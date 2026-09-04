//! Testing-environment lifecycle endpoints.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::ActorRef,
    error::AppError,
    features::organizations,
    infrastructure::postgres::context,
};

use super::{
    key::EnvironmentKeyHolder,
    model::{
        CleaningResult, EnvironmentCreate, EnvironmentKey, EnvironmentPage, EnvironmentPatch,
        EnvironmentResponse, EnvironmentSelfView, EnvironmentWithKey, PageInfo, PageQuery,
    },
    support::{self, Claim, StoredKey},
    validation,
};

const CREATE_ROUTE: &str = "POST /api/v1/organizations/{org_id}/testing-environments";
const UPDATE_ROUTE: &str =
    "PATCH /api/v1/organizations/{org_id}/testing-environments/{environment_id}";
const DELETE_ROUTE: &str =
    "DELETE /api/v1/organizations/{org_id}/testing-environments/{environment_id}";
const RESTORE_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/testing-environments/{environment_id}/restorations";
const ROTATE_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/testing-environments/{environment_id}/key-rotations";
const CLEAN_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/testing-environments/{environment_id}/cleanings";
const SELF_CLEAN_ROUTE: &str = "POST /api/v1/testing-environment/cleanings";

// sqlx accepts only literal query strings, so the three readers below spell
// out the same projection rather than composing it. That is the better trade
// here anyway: every statement this feature executes is greppable in full.
const LIST_ENVIRONMENTS_QUERY: &str = r"
    SELECT
        environment.id,
        organization.org_id,
        environment.name,
        environment.description,
        environment.status,
        environment.created_by_membership_id,
        environment.key_generation,
        environment.key_rotated_at,
        environment.last_activity_at,
        environment.cleaned_at,
        environment.deleted_at,
        environment.purge_after,
        environment.version,
        environment.created_at,
        environment.updated_at
    FROM iam.testing_environments AS environment
    JOIN iam.organizations AS organization
      ON organization.id = environment.organization_id
    WHERE environment.organization_id = $1
      AND ($2::text IS NULL OR environment.status = $2)
      AND ($3::uuid IS NULL OR environment.id > $3)
    ORDER BY environment.id
    LIMIT $4
";

const GET_ENVIRONMENT_QUERY: &str = r"
    SELECT
        environment.id,
        organization.org_id,
        environment.name,
        environment.description,
        environment.status,
        environment.created_by_membership_id,
        environment.key_generation,
        environment.key_rotated_at,
        environment.last_activity_at,
        environment.cleaned_at,
        environment.deleted_at,
        environment.purge_after,
        environment.version,
        environment.created_at,
        environment.updated_at
    FROM iam.testing_environments AS environment
    JOIN iam.organizations AS organization
      ON organization.id = environment.organization_id
    WHERE environment.id = $1
";

const GET_ORGANIZATION_ENVIRONMENT_QUERY: &str = r"
    SELECT
        environment.id,
        organization.org_id,
        environment.name,
        environment.description,
        environment.status,
        environment.created_by_membership_id,
        environment.key_generation,
        environment.key_rotated_at,
        environment.last_activity_at,
        environment.cleaned_at,
        environment.deleted_at,
        environment.purge_after,
        environment.version,
        environment.created_at,
        environment.updated_at
    FROM iam.testing_environments AS environment
    JOIN iam.organizations AS organization
      ON organization.id = environment.organization_id
    WHERE environment.id = $1 AND environment.organization_id = $2
";

#[derive(sqlx::FromRow)]
struct DescribedEnvironment {
    #[sqlx(rename = "testing_environment_id")]
    id: Uuid,
    name: String,
    description: Option<String>,
    key_generation: i32,
    version: i64,
    created_at: time::OffsetDateTime,
}

pub(super) async fn list_environments(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    let (cursor, limit, status) = validation::page(&query)?;
    let mut scope = organizations::begin_organization(&state, &authenticated, &org_id).await?;

    let mut environments = sqlx::query_as::<_, EnvironmentResponse>(LIST_ENVIRONMENTS_QUERY)
        .bind(scope.access.organization_id)
        .bind(status)
        .bind(cursor)
        .bind(limit + 1)
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;

    let has_more = environments.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        environments.pop();
    }
    let next_cursor = has_more
        .then(|| environments.last().map(|last| last.id))
        .flatten();
    support::json(
        StatusCode::OK,
        &EnvironmentPage {
            items: environments,
            page: PageInfo {
                next_cursor,
                has_more,
            },
        },
        None,
    )
}

/// Creates an environment and hands back its key.
///
/// Any active member may do this, Carbon or Silicon, and becomes the
/// environment's creator with permanent administrative authority over it. The
/// key is returned exactly once here as a convenience; it stays retrievable,
/// so losing this response is not losing the environment.
#[allow(
    clippy::too_many_lines,
    reason = "one mutation: claim, authorize, write, audit and record the replay in a single transaction"
)]
pub(super) async fn create_environment(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<EnvironmentCreate>,
) -> Result<Response, AppError> {
    let plane = support::plane(&state)?;
    let max_per_organization = i64::from(plane.settings.max_per_organization);
    validation::create(&mut input)?;

    let mut scope = organizations::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        CREATE_ROUTE,
        "collection",
        &input,
        true,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };

    let live = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM iam.testing_environments
        WHERE organization_id = $1 AND status = 'active'
        ",
    )
    .bind(scope.access.organization_id)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if live >= max_per_organization {
        return Err(AppError::Conflict {
            code: "testing_environment_limit_reached".into(),
        });
    }

    let environment_id = Uuid::now_v7();
    let key = state
        .crypto
        .generate_testing_environment_key()
        .map_err(|_| AppError::Internal {
            category: "testing_environment_key_generate",
        })?;
    let stored = support::store_key(&state, scope.access.organization_id, environment_id, &key)?;

    sqlx::query(
        r"
        INSERT INTO iam.testing_environments (
            id, organization_id, created_by_membership_id, name, description,
            key_digest, key_digest_key_version,
            key_ciphertext, key_nonce, key_encryption_key_version
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ",
    )
    .bind(environment_id)
    .bind(scope.access.organization_id)
    .bind(scope.access.membership_id)
    .bind(&input.name)
    .bind(&input.description)
    .bind(&stored.digest)
    .bind(stored.digest_key_version)
    .bind(&stored.ciphertext)
    .bind(&stored.nonce)
    .bind(stored.encryption_key_version)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "testing_environment_name_taken"))?;

    let environment = fetch(&mut scope.transaction, environment_id).await?;
    support::record_audit(
        &mut scope.transaction,
        support::AuditEvent {
            actor: Some(actor(&authenticated)),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: scope.access.organization_id,
            action: "testing_environment.created",
            environment_id,
            version: environment.version,
            before_state: None,
            after_state: redacted(&environment)?,
            metadata: &json!({ "name": environment.name }),
        },
    )
    .await?;

    let response = EnvironmentWithKey {
        environment,
        key: support::read_key(
            &state,
            scope.access.organization_id,
            environment_id,
            &stored,
        )?,
    };
    let body = support::finish(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &response,
        true,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(
        StatusCode::CREATED,
        body,
        Some(response.environment.version),
        true,
    )
}

pub(super) async fn get_environment(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, environment_id)): Path<(String, Uuid)>,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    let mut scope = organizations::begin_organization(&state, &authenticated, &org_id).await?;
    let environment = fetch_in_organization(
        &mut scope.transaction,
        scope.access.organization_id,
        environment_id,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &environment, Some(environment.version))
}

pub(super) async fn update_environment(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, environment_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(mut input): Json<EnvironmentPatch>,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    validation::patch(&mut input)?;
    let expected_version = support::expected_version(&headers)?;

    let mut scope = organizations::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        UPDATE_ROUTE,
        &environment_id.to_string(),
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };

    let before = fetch_in_organization(
        &mut scope.transaction,
        scope.access.organization_id,
        environment_id,
    )
    .await?;
    require_live(&before)?;
    if before.version != expected_version {
        return Err(AppError::PreconditionFailed {
            code: "etag_mismatch".into(),
        });
    }
    let affected = sqlx::query(
        r"
        UPDATE iam.testing_environments
        SET name = COALESCE($2, name),
            description = CASE WHEN $3 THEN $4 ELSE description END
        WHERE id = $1 AND status = 'active' AND version = $5
          AND (
              ($2::text IS NOT NULL AND name IS DISTINCT FROM $2)
              OR ($3 AND description IS DISTINCT FROM $4)
          )
        ",
    )
    .bind(environment_id)
    .bind(input.name.as_ref())
    .bind(input.description.is_some())
    .bind(input.description.clone().flatten())
    .bind(expected_version)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "testing_environment_name_taken"))?
    .rows_affected();
    ensure_environment_updated(
        &mut scope.transaction,
        scope.access.organization_id,
        environment_id,
        expected_version,
        affected,
    )
    .await?;

    let after = fetch(&mut scope.transaction, environment_id).await?;
    support::record_audit(
        &mut scope.transaction,
        support::AuditEvent {
            actor: Some(actor(&authenticated)),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: scope.access.organization_id,
            action: "testing_environment.updated",
            environment_id,
            version: after.version,
            before_state: redacted(&before)?,
            after_state: redacted(&after)?,
            metadata: &json!({}),
        },
    )
    .await?;

    let body = support::finish(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &after,
        false,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(after.version), false)
}

async fn ensure_environment_updated(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    environment_id: Uuid,
    expected_version: i64,
    affected: u64,
) -> Result<(), AppError> {
    if affected == 1 {
        return Ok(());
    }
    let current = fetch_in_organization(transaction, organization_id, environment_id).await?;
    if current.version != expected_version {
        return Err(AppError::PreconditionFailed {
            code: "etag_mismatch".into(),
        });
    }
    Err(AppError::Conflict {
        code: "testing_environment_unchanged".into(),
    })
}

/// Retires an environment, keeping it recoverable for the configured window.
///
/// Nothing is erased here. The row survives with a purge deadline, and the
/// worker destroys the data only once that deadline passes, which is what makes
/// an accidental deletion something an operator can undo rather than a support
/// ticket.
pub(super) async fn delete_environment(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, environment_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let plane = support::plane(&state)?;
    let recovery_days = i32::from(plane.settings.recovery_days);
    let mut scope = organizations::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        DELETE_ROUTE,
        &environment_id.to_string(),
        &json!({}),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };

    let before = fetch_in_organization(
        &mut scope.transaction,
        scope.access.organization_id,
        environment_id,
    )
    .await?;
    require_live(&before)?;

    let affected = sqlx::query(
        r"
        UPDATE iam.testing_environments
        SET status = 'deleted',
            deleted_at = transaction_timestamp(),
            purge_after = transaction_timestamp() + make_interval(days => $2)
        WHERE id = $1 AND status = 'active'
        ",
    )
    .bind(environment_id)
    .bind(recovery_days)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?
    .rows_affected();
    if affected != 1 {
        return Err(AppError::Forbidden);
    }

    let after = fetch(&mut scope.transaction, environment_id).await?;
    support::record_audit(
        &mut scope.transaction,
        support::AuditEvent {
            actor: Some(actor(&authenticated)),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: scope.access.organization_id,
            action: "testing_environment.deleted",
            environment_id,
            version: after.version,
            before_state: redacted(&before)?,
            after_state: redacted(&after)?,
            metadata: &json!({ "recovery_days": recovery_days }),
        },
    )
    .await?;

    let body = support::finish(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &after,
        false,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(after.version), false)
}

/// Brings a deleted environment back inside its recovery window.
pub(super) async fn restore_environment(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, environment_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    let mut scope = organizations::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        RESTORE_ROUTE,
        &environment_id.to_string(),
        &json!({}),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };

    let before = fetch_in_organization(
        &mut scope.transaction,
        scope.access.organization_id,
        environment_id,
    )
    .await?;
    if before.status != "deleted" {
        return Err(AppError::Conflict {
            code: "testing_environment_not_deleted".into(),
        });
    }

    // The name was released when the environment was deleted, so another one
    // may have taken it in the meantime. Surfacing that as a conflict is
    // honest; silently renaming somebody's environment would not be.
    let affected = sqlx::query(
        r"
        UPDATE iam.testing_environments
        SET status = 'active',
            deleted_at = NULL,
            purge_after = NULL,
            last_activity_at = transaction_timestamp()
        WHERE id = $1
          AND status = 'deleted'
          AND purge_after > transaction_timestamp()
        ",
    )
    .bind(environment_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "testing_environment_name_taken"))?
    .rows_affected();
    if affected != 1 {
        return Err(AppError::Conflict {
            code: "testing_environment_not_recoverable".into(),
        });
    }

    let after = fetch(&mut scope.transaction, environment_id).await?;
    support::record_audit(
        &mut scope.transaction,
        support::AuditEvent {
            actor: Some(actor(&authenticated)),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: scope.access.organization_id,
            action: "testing_environment.restored",
            environment_id,
            version: after.version,
            before_state: redacted(&before)?,
            after_state: redacted(&after)?,
            metadata: &json!({}),
        },
    )
    .await?;

    let body = support::finish(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &after,
        false,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(after.version), false)
}

/// Reads the environment key back.
///
/// Restricted to environment administrators and audited on every read, because
/// this is the one route that turns membership into unrestricted authority
/// inside an environment.
pub(super) async fn get_environment_key(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, environment_id)): Path<(String, Uuid)>,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    let mut scope = organizations::begin_organization(&state, &authenticated, &org_id).await?;
    let environment = fetch_in_organization(
        &mut scope.transaction,
        scope.access.organization_id,
        environment_id,
    )
    .await?;
    require_live(&environment)?;
    support::require_administrator(
        &mut scope.transaction,
        scope.access.organization_id,
        environment.created_by_membership_id,
        authenticated.0.subject.id,
    )
    .await?;

    let stored = fetch_key(&mut scope.transaction, environment_id).await?;
    let key = support::read_key(
        &state,
        scope.access.organization_id,
        environment_id,
        &stored,
    )?;
    support::record_audit(
        &mut scope.transaction,
        support::AuditEvent {
            actor: Some(actor(&authenticated)),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: scope.access.organization_id,
            action: "testing_environment.key_read",
            environment_id,
            version: environment.version,
            before_state: None,
            after_state: None,
            metadata: &json!({ "key_generation": environment.key_generation }),
        },
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;

    let body = serde_json::to_vec(&EnvironmentKey {
        environment_id,
        key_generation: environment.key_generation,
        key_rotated_at: environment.key_rotated_at,
        key,
    })
    .map_err(|_| AppError::Internal {
        category: "testing_environment_response_serialize",
    })?;
    support::json_response(StatusCode::OK, body, None, true)
}

/// Replaces the environment key, invalidating the previous one immediately.
#[allow(
    clippy::too_many_lines,
    reason = "one mutation: claim, authorize, write, audit and record the replay in a single transaction"
)]
pub(super) async fn rotate_environment_key(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, environment_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    let mut scope = organizations::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        ROTATE_ROUTE,
        &environment_id.to_string(),
        &json!({}),
        true,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };

    let before = fetch_in_organization(
        &mut scope.transaction,
        scope.access.organization_id,
        environment_id,
    )
    .await?;
    require_live(&before)?;
    support::require_administrator(
        &mut scope.transaction,
        scope.access.organization_id,
        before.created_by_membership_id,
        authenticated.0.subject.id,
    )
    .await?;

    let key = state
        .crypto
        .generate_testing_environment_key()
        .map_err(|_| AppError::Internal {
            category: "testing_environment_key_generate",
        })?;
    let stored = support::store_key(&state, scope.access.organization_id, environment_id, &key)?;
    let affected = sqlx::query(
        r"
        UPDATE iam.testing_environments
        SET key_digest = $2,
            key_digest_key_version = $3,
            key_ciphertext = $4,
            key_nonce = $5,
            key_encryption_key_version = $6,
            key_generation = key_generation + 1,
            key_rotated_at = transaction_timestamp()
        WHERE id = $1 AND status = 'active'
        ",
    )
    .bind(environment_id)
    .bind(&stored.digest)
    .bind(stored.digest_key_version)
    .bind(&stored.ciphertext)
    .bind(&stored.nonce)
    .bind(stored.encryption_key_version)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?
    .rows_affected();
    if affected != 1 {
        return Err(AppError::Forbidden);
    }

    let after = fetch(&mut scope.transaction, environment_id).await?;
    support::record_audit(
        &mut scope.transaction,
        support::AuditEvent {
            actor: Some(actor(&authenticated)),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: scope.access.organization_id,
            action: "testing_environment.key_rotated",
            environment_id,
            version: after.version,
            before_state: None,
            after_state: None,
            metadata: &json!({ "key_generation": after.key_generation }),
        },
    )
    .await?;

    let response = EnvironmentWithKey {
        environment: after,
        key: support::read_key(
            &state,
            scope.access.organization_id,
            environment_id,
            &stored,
        )?,
    };
    let body = support::finish(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &response,
        true,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(
        StatusCode::OK,
        body,
        Some(response.environment.version),
        true,
    )
}

/// Empties an environment without retiring it, for an administrator.
pub(super) async fn clean_environment(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, environment_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    let mut scope = organizations::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        CLEAN_ROUTE,
        &environment_id.to_string(),
        &json!({}),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };

    let environment = fetch_in_organization(
        &mut scope.transaction,
        scope.access.organization_id,
        environment_id,
    )
    .await?;
    require_live(&environment)?;
    support::require_administrator(
        &mut scope.transaction,
        scope.access.organization_id,
        environment.created_by_membership_id,
        authenticated.0.subject.id,
    )
    .await?;

    let result = erase(&state, environment_id).await?;
    support::record_audit(
        &mut scope.transaction,
        support::AuditEvent {
            actor: Some(actor(&authenticated)),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: scope.access.organization_id,
            action: "testing_environment.cleaned",
            environment_id,
            version: environment.version,
            before_state: None,
            after_state: None,
            metadata: &json!({ "erased_rows": result.erased_rows }),
        },
    )
    .await?;
    mark_cleaned(&mut scope.transaction, environment_id).await?;

    let body = support::finish(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &result,
        false,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, None, false)
}

/// Describes the environment whose key was presented.
pub(super) async fn describe_current_environment(
    State(state): State<ApiState>,
    holder: EnvironmentKeyHolder,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    let mut transaction = context::begin(&state.pool, context::DatabaseContext::anonymous())
        .await
        .map_err(support::database)?;
    let described = describe(&mut transaction, holder.environment.id).await?;
    transaction.commit().await.map_err(support::database)?;

    support::json(
        StatusCode::OK,
        &EnvironmentSelfView {
            id: described.id,
            name: described.name,
            description: described.description,
            key_generation: described.key_generation,
            created_at: described.created_at,
        },
        None,
    )
}

/// Empties the environment whose key was presented.
///
/// The specification puts this in the hands of anyone holding the key, and it
/// stays that way: the key is the environment's root authority, and erasing
/// disposable test data is well within it.
pub(super) async fn clean_current_environment(
    State(state): State<ApiState>,
    holder: EnvironmentKeyHolder,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    let environment_id = holder.environment.id;
    let mut transaction = context::begin(&state.pool, context::DatabaseContext::anonymous())
        .await
        .map_err(support::database)?;
    let lease = match super::key::claim_for_key_holder(
        &mut transaction,
        &state,
        &holder,
        &headers,
        SELF_CLEAN_ROUTE,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };

    let version = describe(&mut transaction, environment_id).await?.version;

    let result = erase(&state, environment_id).await?;
    support::record_audit(
        &mut transaction,
        support::AuditEvent {
            actor: None,
            authentication_session_id: None,
            organization_id: holder.environment.organization_id,
            action: "testing_environment.cleaned",
            environment_id,
            version,
            before_state: None,
            after_state: None,
            metadata: &json!({ "erased_rows": result.erased_rows, "actor": "environment_key" }),
        },
    )
    .await?;
    mark_cleaned(&mut transaction, environment_id).await?;

    let body = support::finish(
        &mut transaction,
        &state,
        lease,
        StatusCode::OK,
        &result,
        false,
    )
    .await?;
    transaction.commit().await.map_err(support::database)?;
    support::json_response(StatusCode::OK, body, None, false)
}

/// Destroys one environment's rows in the testing database.
///
/// Deliberately outside the control-plane transaction: the two databases
/// cannot commit together, and erasing first means a failure afterwards leaves
/// an environment that is empty but still recorded, which the caller can retry.
/// The reverse order would leave orphaned data no one can reach.
async fn erase(state: &ApiState, environment_id: Uuid) -> Result<CleaningResult, AppError> {
    let plane = support::plane(state)?;
    let erased_rows =
        sqlx::query_scalar::<_, i64>("SELECT iam_private.erase_testing_environment($1)")
            .bind(environment_id)
            .fetch_one(&plane.pool)
            .await
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    testing_environment.id = %environment_id,
                    "could not erase testing environment data"
                );
                AppError::Internal {
                    category: "testing_environment_erase",
                }
            })?;
    Ok(CleaningResult {
        environment_id,
        erased_rows,
        cleaned_at: time::OffsetDateTime::now_utc(),
    })
}

/// Describes one live environment regardless of who is asking.
///
/// A key holder has no IAM principal, so row security hides every environment
/// from them -- correctly, since membership is what makes an environment
/// visible to a person. This is the narrow, secret-free read for the credential
/// that is the environment's own authority. Authority is settled before it is
/// called.
async fn describe(
    transaction: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
) -> Result<DescribedEnvironment, AppError> {
    sqlx::query_as::<_, DescribedEnvironment>(
        "SELECT * FROM iam_private.describe_testing_environment($1)",
    )
    .bind(environment_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

/// Stamps the cleaning outcome once authority has been established.
///
/// Goes through the same boundary as the read above, because cleaning is
/// authorized either by organization administration or by the key alone, and
/// the update policy cannot recognize the second caller.
async fn mark_cleaned(
    transaction: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT iam_private.record_testing_environment_cleaning($1)")
        .bind(environment_id)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(support::database)
}

async fn fetch(
    transaction: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
) -> Result<EnvironmentResponse, AppError> {
    sqlx::query_as::<_, EnvironmentResponse>(GET_ENVIRONMENT_QUERY)
        .bind(environment_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)
}

async fn fetch_in_organization(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    environment_id: Uuid,
) -> Result<EnvironmentResponse, AppError> {
    sqlx::query_as::<_, EnvironmentResponse>(GET_ORGANIZATION_ENVIRONMENT_QUERY)
        .bind(environment_id)
        .bind(organization_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)
}

async fn fetch_key(
    transaction: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
) -> Result<StoredKey, AppError> {
    let row = sqlx::query_as::<_, (Vec<u8>, i16, Vec<u8>, Vec<u8>, i16)>(
        r"
        SELECT
            key_digest, key_digest_key_version,
            key_ciphertext, key_nonce, key_encryption_key_version
        FROM iam.testing_environments
        WHERE id = $1
        ",
    )
    .bind(environment_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    Ok(StoredKey {
        digest: row.0,
        digest_key_version: row.1,
        ciphertext: row.2,
        nonce: row.3,
        encryption_key_version: row.4,
    })
}

fn require_live(environment: &EnvironmentResponse) -> Result<(), AppError> {
    if environment.status == "active" {
        Ok(())
    } else {
        Err(AppError::Conflict {
            code: "testing_environment_deleted".into(),
        })
    }
}

fn actor(authenticated: &Authenticated) -> ActorRef {
    ActorRef {
        actor_type: authenticated.0.subject.actor_type,
        id: authenticated.0.subject.id,
    }
}

fn redacted(environment: &EnvironmentResponse) -> Result<Option<serde_json::Value>, AppError> {
    serde_json::to_value(environment)
        .map(Some)
        .map_err(|_| AppError::Internal {
            category: "testing_environment_audit_state",
        })
}
