#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use secrecy::ExposeSecret as _;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::actor::ActorType,
    infrastructure::{
        crypto::{DigestPurpose, EncryptionContext, ProtectedField, SecretKind},
        postgres::{
            context::{self, DatabaseContext},
            step_up::RequiredAssurance,
        },
    },
};

use super::{
    cursor,
    error::ApiError,
    events::{self, Mutation},
    idempotency::{self, Claim},
    model::{
        AppPath, ApplicationAdminDecision, ApplicationCreate, ApplicationCreated,
        ApplicationDetail, ApplicationDirectoryEntry, ApplicationOboEndpoint, ApplicationPage,
        ApplicationPatch, ApplicationSecretRotated, ApplicationView, PageInfo, PageQuery,
        PublicActor,
    },
    security::{
        ApplicationClient, Bearer, expected_version, lock_step_up_actor, require_carbon,
        require_platform_capability, require_step_up,
    },
    validation,
};

pub(super) const REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY: &str = r"
    UPDATE iam.access_tokens AS token
    SET revoked_at = transaction_timestamp(),
        revocation_reason = 'application_scope_revoked'
    WHERE token.client_application_id = $1
      AND token.token_class = 'application_access'
      AND token.revoked_at IS NULL
      AND token.expires_at > transaction_timestamp()
      AND EXISTS (
          SELECT 1
          FROM iam.access_token_scopes AS token_scope
          WHERE token_scope.access_token_id = token.id
            AND token_scope.scope = ANY($2::text[])
      )
    ";

const CLIENT_SECRET_ROTATION_STEP_UP_ACTION: &str = "application.client_secret.rotate";

async fn resolve_creation_organization(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    organization_handle: &str,
) -> Result<Uuid, ApiError> {
    // Resolved through an owner-rights function on purpose.
    //
    // The lock is the point of this lookup — the authority check and the insert
    // must see the same membership — but PostgreSQL applies a table's UPDATE
    // policy to a locking read, and `organizations_authorized_update` requires
    // `current_organization_id()`. That setting is chosen from this query's own
    // result, so run inline the statement had to know its answer to produce it:
    // it matched nothing and every registration reported the organization
    // missing. The predicate is unchanged and still evaluated inside the
    // function, so this narrows nothing.
    // `SELECT f(...)` always yields a row, so the absent case arrives as a NULL
    // inside it rather than as no row at all. Decoded as `Option` so a caller
    // without the authority still receives the not-found this returns, not a
    // decode failure reported as an internal error.
    sqlx::query_scalar::<_, Option<Uuid>>(
        r"
        SELECT iam_private.lock_application_creation_organization($1, $2)
        ",
    )
    .bind(organization_handle)
    .bind(carbon_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_creation_organization"))?
    .ok_or_else(ApiError::not_found)
}

pub(super) async fn lock_current_application_manager(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    carbon_id: Uuid,
) -> Result<(), ApiError> {
    let current = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT membership.id
        FROM iam.organizations AS organization
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.principal_id = $2
         AND membership.principal_kind = 'carbon'
         AND membership.org_role IN ('owner', 'admin')
         AND membership.status = 'active'
        JOIN iam.principals AS principal
          ON principal.id = membership.principal_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE organization.id = $1
          AND organization.status = 'active'
        FOR SHARE OF organization, membership, principal
        ",
    )
    .bind(organization_id)
    .bind(carbon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_manager_lock"))?;
    if current.is_none() {
        return Err(ApiError::not_found());
    }
    Ok(())
}

pub(super) async fn list(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApplicationPage>, ApiError> {
    let carbon_id = require_carbon(&access)?;
    let cursor = cursor::decode(query.cursor.as_deref())?;
    let limit = cursor::limit(query.limit);
    if query.status.as_deref().is_some_and(|status| {
        !matches!(
            status,
            "under_review" | "verified" | "rejected" | "suspended" | "deleted"
        )
    }) {
        return Err(ApiError::validation("status", "contains an invalid status"));
    }
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_list_context"))?;
    let (cursor_at, cursor_id) =
        cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)));
    let mut rows = sqlx::query_as::<_, ApplicationView>(
        r"
        SELECT
            application.id, application.app_id, application.organization_id,
            organization.org_id, application.created_by_carbon_id,
            application.app_name, application.app_logo_uri, application.base_url,
            application.review_status, application.version,
            application.created_at, application.updated_at
        FROM iam.applications AS application
        JOIN LATERAL iam_private.resolve_authorized_application_organization(
            application.id
        ) AS organization ON TRUE
        WHERE application.deleted_at IS NULL
          AND iam_private.can_read_application(application.id, $1)
          AND ($2::text IS NULL OR application.review_status = $2)
          AND (
              $3::timestamptz IS NULL
              OR (application.created_at, application.id) < ($3, $4)
          )
        ORDER BY application.created_at DESC, application.id DESC
        LIMIT $5
        ",
    )
    .bind(carbon_id)
    .bind(query.status)
    .bind(cursor_at)
    .bind(cursor_id)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_list"))?;
    let next_cursor = if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
        rows.pop();
        rows.last()
            .map(|item| cursor::encode(item.created_at, item.id))
            .transpose()?
    } else {
        None
    };
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        // The authorized projection above can identify every Application the
        // Carbon manages without a tenant selected. The tables read by the
        // detail projection are tenant-scoped, though, and the authority lock
        // itself is intentionally subject to RLS. Select the row's tenant
        // before either operation. Without this, the first real Application
        // made an otherwise valid list fail as a misleading 404.
        context::select_organization(&mut transaction, row.organization_id)
            .await
            .map_err(|_| ApiError::internal("application_list_organization_context"))?;
        lock_current_application_manager(&mut transaction, row.organization_id, carbon_id).await?;
        select_application_context(&mut transaction, row.id, row.organization_id).await?;
        items.push(load_detail(&mut transaction, &state, row.id, false).await?);
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_list_commit"))?;
    Ok(Json(ApplicationPage {
        items,
        page: PageInfo::from_next_cursor(next_cursor),
    }))
}

pub(super) async fn create(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    headers: HeaderMap,
    Json(input): Json<ApplicationCreate>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::application_create(&input)?;
    let qualified_app_id = validation::qualify_app_id(&input.org_id, &input.app_id)?;
    let canonical = serde_json::to_vec(&json!({
        "app_id": input.app_id,
        "org_id": input.org_id,
        "base_url": input.base_url,
        "app_name": input.app_name,
        "app_logo_uri": input.app_logo_uri,
        "webhook_url": input.webhook_url,
        "webhook_secret": input.webhook_secret.expose_secret(),
        "obo_endpoints": input.obo_endpoints,
    }))
    .map_err(|_| ApiError::internal("application_create_canonical"))?;
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_create_context"))?;
    let organization_id =
        resolve_creation_organization(&mut transaction, carbon_id, &input.org_id).await?;
    context::select_organization(&mut transaction, organization_id)
        .await
        .map_err(|_| ApiError::internal("application_create_organization_context"))?;
    let caller_scope = format!("carbon:{carbon_id}:organization:{organization_id}");
    let claim = idempotency::claim::<ApplicationCreated>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/applications",
        &canonical,
        true,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("application_replay_commit"))?;
        let status = StatusCode::from_u16(status)
            .map_err(|_| ApiError::internal("application_replay_status"))?;
        return Ok(created_secret_response(status, response, true));
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("application_idempotency_state"));
    };

    ensure_application_id_available_for_testing(&state.pool, &qualified_app_id).await?;

    let application_id = Uuid::now_v7();
    let webhook_endpoint_id = Uuid::now_v7();
    let webhook_key_id = Uuid::now_v7();
    let client_secret_id = Uuid::now_v7();
    let client_secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)
        .map_err(|_| ApiError::internal("application_secret_generate"))?;
    let client_digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationSecret, &client_secret)
        .map_err(|_| ApiError::internal("application_secret_digest"))?;
    let encrypted_webhook = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookUrl,
                application_id,
                webhook_endpoint_id,
            ),
            input.webhook_url.as_bytes(),
        )
        .map_err(|_| ApiError::internal("webhook_url_encrypt"))?;
    let encrypted_webhook_secret = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                application_id,
                webhook_key_id,
            ),
            input.webhook_secret.expose_secret().as_bytes(),
        )
        .map_err(|_| ApiError::internal("webhook_secret_encrypt"))?;
    let webhook_digest = Sha256::digest(input.webhook_url.as_bytes());
    // A testing environment has no platform-operator review authority of its
    // own. Keeping its endpoint pending would make the otherwise complete
    // replica unable to emit a webhook at all, so test-plane endpoints become
    // usable in the same transaction that creates them. Production retains
    // the operator-review lifecycle.
    let activate_webhook_immediately = crate::infrastructure::testing_plane::is_active();

    sqlx::query(
        r"
        INSERT INTO iam.principals (id, kind, status, activated_at)
        VALUES ($1, 'application', 'active', transaction_timestamp())
        ",
    )
    .bind(application_id)
    .execute(&mut *transaction)
    .await
    .map_err(map_application_write)?;
    sqlx::query(
        r"
        INSERT INTO iam.applications (
            id, app_id, organization_id, created_by_carbon_id,
            app_name, app_logo_uri, base_url, review_status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'verified')
        ",
    )
    .bind(application_id)
    .bind(&qualified_app_id)
    .bind(organization_id)
    .bind(carbon_id)
    .bind(&input.app_name)
    .bind(&input.app_logo_uri)
    .bind(&input.base_url)
    .execute(&mut *transaction)
    .await
    .map_err(map_application_write)?;
    // The login carries the whole catalogue -- "scope of the login is always
    // everything" -- and a login's request-scope rows are foreign-keyed to the
    // approved set, so "everything" has to exist as rows rather than as a
    // special case at authorization time. Approving scopes is a platform
    // authority the organization owner deliberately does not hold, so the grant
    // goes through an owner-rights function that checks the caller can manage
    // this application before it writes. `scope` on the create input is the
    // webhook's scope and is applied to the webhook, not here.
    sqlx::query("SELECT iam_private.grant_application_scope_catalogue($1, $2)")
        .bind(application_id)
        .bind(carbon_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("application_scope_catalogue"))?;
    replace_obo_endpoints(&mut transaction, application_id, &input.obo_endpoints).await?;
    sqlx::query(
        r"
        INSERT INTO iam.application_secrets (
            id, application_id, secret_version, secret_prefix, secret_digest,
            pepper_key_version, created_by_carbon_id
        ) VALUES ($1, $2, 1, $3, $4, $5, $6)
        ",
    )
    .bind(client_secret_id)
    .bind(application_id)
    .bind(secret_prefix(client_secret.expose_secret()))
    .bind(client_digest.as_bytes().as_slice())
    .bind(client_digest.key_version())
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_secret_insert"))?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_endpoints (
            id, application_id, url_ciphertext, url_nonce,
            encryption_key_version, url_digest, status, activated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            CASE WHEN $7 THEN 'active' ELSE 'pending_review' END,
            CASE WHEN $7 THEN transaction_timestamp() END
        )
        ",
    )
    .bind(webhook_endpoint_id)
    .bind(application_id)
    .bind(encrypted_webhook.ciphertext)
    .bind(encrypted_webhook.nonce.as_slice())
    .bind(encrypted_webhook.key_version)
    .bind(webhook_digest.as_slice())
    .bind(activate_webhook_immediately)
    .execute(&mut *transaction)
    .await
    .map_err(map_application_write)?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES ($1, $2, $3, 1, $4, $5, $6, $7)
        ",
    )
    .bind(webhook_key_id)
    .bind(application_id)
    .bind(webhook_endpoint_id)
    .bind(webhook_secret_fingerprint(
        input.webhook_secret.expose_secret(),
    ))
    .bind(encrypted_webhook_secret.ciphertext)
    .bind(encrypted_webhook_secret.nonce.as_slice())
    .bind(encrypted_webhook_secret.key_version)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_secret_insert"))?;

    let detail = load_detail(&mut transaction, &state, application_id, false).await?;
    let secret_replay_expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT transaction_timestamp() + interval '10 minutes'",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_secret_replay_expiry"))?;
    let response = ApplicationCreated {
        application: detail,
        app_secret: client_secret.expose_secret().to_owned(),
        app_secret_version: 1,
        webhook_signing_secret: input.webhook_secret.expose_secret().to_owned(),
        webhook_secret_version: 1,
        secret_replay_expires_at,
    };
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            organization_id,
            application_id,
            action: "application.create",
            target_type: "application",
            target_id: Some(application_id),
            aggregate_type: "application",
            aggregate_id: application_id,
            aggregate_version: 1,
            before: None,
            after: Some(json!({
                "app_id": qualified_app_id,
                "base_url": input.base_url,
                "review_status": "verified",
            })),
            metadata: json!({
                "application_id": application_id,
                "organization_id": organization_id,
                "org_id": input.org_id,
                "obo_endpoint_count": input.obo_endpoints.len(),
            }),
            event_type: "application.created",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        201,
        &response,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_create_commit"))?;
    Ok(created_secret_response(
        StatusCode::CREATED,
        response,
        false,
    ))
}

pub(super) async fn ensure_application_id_available_for_testing(
    production_pool: &PgPool,
    qualified_app_id: &str,
) -> Result<(), ApiError> {
    if !crate::infrastructure::testing_plane::is_active() {
        return Ok(());
    }
    let reserved = sqlx::query_scalar::<_, bool>(
        "SELECT iam_private.production_application_id_is_reserved($1)",
    )
    .bind(qualified_app_id)
    .fetch_one(production_pool)
    .await
    .map_err(|_| ApiError::internal("production_application_id_reservation"))?;
    if reserved {
        return Err(ApiError::conflict("application_id_reserved_in_production"));
    }
    Ok(())
}

pub(super) async fn get(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_get_context"))?;
    let application =
        resolve_readable_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let detail = load_detail(&mut transaction, &state, application.id, false).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_get_commit"))?;
    json_with_etag(StatusCode::OK, &detail, detail.version)
}

/// Resolves one configured backend location for an authenticated Application.
///
/// Application credentials establish the caller, but deliberately do not
/// constrain the target to the caller's organization: qualified identifiers
/// are global and the directory exists specifically for cross-Application
/// discovery. Only a currently usable target is visible.
pub(super) async fn discover(
    State(state): State<ApiState>,
    client: ApplicationClient,
    Path(path): Path<AppPath>,
) -> Result<Json<ApplicationDirectoryEntry>, ApiError> {
    validation::app_id(&path.app_id)?;
    let mut transaction = context::begin(
        state.db(),
        DatabaseContext::application(client.application_id, client.application_id),
    )
    .await
    .map_err(|_| ApiError::internal("application_directory_context"))?;
    let entry = sqlx::query_as::<_, ApplicationDirectoryEntry>(
        r"
        SELECT application.app_id, application.base_url
        FROM iam.applications AS application
        JOIN iam.principals AS principal
          ON principal.id = application.id
         AND principal.kind = 'application'
         AND principal.status = 'active'
        WHERE application.app_id = $1
          AND application.review_status = 'verified'
          AND application.deleted_at IS NULL
        ",
    )
    .bind(&path.app_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_directory_read"))?
    .ok_or_else(ApiError::not_found)?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_directory_commit"))?;
    Ok(Json(entry))
}

pub(super) async fn rotate_client_secret(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let canonical = b"{}";
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_secret_rotation_context"))?;
    lock_step_up_actor(&mut transaction, carbon_id).await?;
    let app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", app.id);
    let claim = idempotency::claim::<ApplicationSecretRotated>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/applications/{app_id}/client-secret-rotations",
        canonical,
        true,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("application_secret_rotation_replay_commit"))?;
        let status = StatusCode::from_u16(status)
            .map_err(|_| ApiError::internal("application_secret_rotation_replay_status"))?;
        return secret_json_with_etag(status, &response, response.application_version, true);
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal(
            "application_secret_rotation_idempotency",
        ));
    };
    let expected = expected_version(&headers)?;
    let app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, true).await?;
    if app.version != expected {
        return Err(ApiError::precondition_failed());
    }
    require_step_up(
        &mut transaction,
        &state.crypto,
        &headers,
        &access,
        CLIENT_SECRET_ROTATION_STEP_UP_ACTION,
        app.id,
        RequiredAssurance::VerifiedChannel,
    )
    .await?;

    let secret_version = sqlx::query_scalar::<_, i64>(
        r"
        SELECT COALESCE(MAX(secret_version), 0) + 1
        FROM iam.application_secrets
        WHERE application_id = $1
        ",
    )
    .bind(app.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_secret_rotation_version"))?;
    let secret_id = Uuid::now_v7();
    let secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)
        .map_err(|_| ApiError::internal("application_secret_rotation_generate"))?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationSecret, &secret)
        .map_err(|_| ApiError::internal("application_secret_rotation_digest"))?;

    sqlx::query(
        r"
        UPDATE iam.application_secrets
        SET status = 'retired', retired_at = transaction_timestamp(), retires_at = NULL
        WHERE application_id = $1 AND status IN ('active', 'retiring')
        ",
    )
    .bind(app.id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_secret_rotation_retire"))?;
    sqlx::query(
        r"
        INSERT INTO iam.application_secrets (
            id, application_id, secret_version, secret_prefix, secret_digest,
            pepper_key_version, created_by_carbon_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(secret_id)
    .bind(app.id)
    .bind(secret_version)
    .bind(secret_prefix(secret.expose_secret()))
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_secret_rotation_insert"))?;
    let application_version = bump_application(&mut transaction, app.id).await?;
    let secret_replay_expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT transaction_timestamp() + interval '10 minutes'",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_secret_rotation_replay_expiry"))?;
    let response = ApplicationSecretRotated {
        app_id: app.app_id,
        app_secret: secret.expose_secret().to_owned(),
        app_secret_version: secret_version,
        application_version,
        secret_replay_expires_at,
    };
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            organization_id: app.organization_id,
            application_id: app.id,
            action: "application.client_secret.rotate",
            target_type: "application_secret",
            target_id: Some(secret_id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: application_version,
            before: None,
            after: Some(json!({ "secret_version": secret_version, "status": "active" })),
            metadata: json!({ "secret_version": secret_version }),
            event_type: "application.client_secret_rotated",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        200,
        &response,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_secret_rotation_commit"))?;
    secret_json_with_etag(
        StatusCode::OK,
        &response,
        response.application_version,
        false,
    )
}

pub(super) async fn patch(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
    Json(input): Json<ApplicationPatch>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    validation::application_patch(&input)?;
    let canonical = serde_json::to_vec(&input_as_json(&input))
        .map_err(|_| ApiError::internal("application_patch_canonical"))?;
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("application_patch_context"))?;
    let claim_app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", claim_app.id);
    let claim = idempotency::claim::<ApplicationDetail>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "PATCH /api/v1/applications/{app_id}",
        &canonical,
        false,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("application_patch_replay_commit"))?;
        let status = StatusCode::from_u16(status)
            .map_err(|_| ApiError::internal("application_patch_replay_status"))?;
        return json_with_etag_replayed(status, &response, response.version);
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("application_patch_idempotency"));
    };
    let version = expected_version(&headers)?;
    let before = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, true).await?;
    if before.version != version {
        return Err(ApiError::precondition_failed());
    }
    let current_endpoints = if input.obo_endpoints.is_some() {
        load_detail(&mut transaction, &state, before.id, false)
            .await?
            .obo_endpoints
    } else {
        Vec::new()
    };
    let changes_application = input
        .base_url
        .as_deref()
        .is_some_and(|value| value != before.base_url.as_str())
        || input
            .app_name
            .as_ref()
            .is_some_and(|value| value != &before.app_name)
        || input
            .app_logo_uri
            .as_ref()
            .is_some_and(|value| value != &before.app_logo_uri)
        || input.obo_endpoints.as_ref().is_some_and(|values| {
            let mut values = values.clone();
            values.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
            values != current_endpoints
        });
    if !changes_application {
        return Err(ApiError::conflict("application_unchanged"));
    }
    if input.base_url.is_some() || input.app_name.is_some() || input.app_logo_uri.is_some() {
        sqlx::query(
            r"
            UPDATE iam.applications
            SET app_name = CASE WHEN $2 THEN $3 ELSE app_name END,
                app_logo_uri = CASE WHEN $4 THEN $5 ELSE app_logo_uri END,
                base_url = COALESCE($6, base_url)
            WHERE id = $1 AND version = $7
            ",
        )
        .bind(before.id)
        .bind(input.app_name.is_some())
        .bind(input.app_name.clone().flatten())
        .bind(input.app_logo_uri.is_some())
        .bind(input.app_logo_uri.clone().flatten())
        .bind(&input.base_url)
        .bind(version)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("application_patch_metadata"))?;
    }
    if let Some(endpoints) = &input.obo_endpoints {
        replace_obo_endpoints(&mut transaction, before.id, endpoints).await?;
    }
    let updated_version =
        if input.base_url.is_some() || input.app_name.is_some() || input.app_logo_uri.is_some() {
            version + 1
        } else {
            bump_application(&mut transaction, before.id).await?
        };
    let response = load_detail(&mut transaction, &state, before.id, false).await?;
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            organization_id: before.organization_id,
            application_id: before.id,
            action: "application.update",
            target_type: "application",
            target_id: Some(before.id),
            aggregate_type: "application",
            aggregate_id: before.id,
            aggregate_version: updated_version,
            before: Some(json!({
                "app_name": before.app_name,
                "app_logo_uri": before.app_logo_uri,
                "base_url": before.base_url,
                "review_status": before.review_status,
            })),
            after: Some(json!({
                "app_name": response.app_name,
                "app_logo_uri": response.app_logo,
                "base_url": response.base_url,
                "review_status": response.status,
            })),
            metadata: json!({ "pending_configuration_review": true }),
            event_type: "application.updated",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        200,
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("application_patch_commit"))?;
    json_with_etag(StatusCode::OK, &response, response.version)
}

pub(super) async fn admin_list(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApplicationPage>, ApiError> {
    let carbon_id = require_carbon(&access)?;
    let cursor = cursor::decode(query.cursor.as_deref())?;
    let limit = cursor::limit(query.limit);
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("admin_application_list_context"))?;
    require_platform_capability(&mut transaction, carbon_id, "applications.review").await?;
    let (at, id) = cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)));
    let mut rows = sqlx::query_as::<_, ApplicationView>(
        r"
        SELECT application.id, application.app_id, application.organization_id,
               organization.org_id, application.created_by_carbon_id,
               application.app_name, application.app_logo_uri, application.base_url,
               application.review_status, application.version,
               application.created_at, application.updated_at
        FROM iam.applications AS application
        JOIN LATERAL iam_private.resolve_authorized_application_organization(
            application.id
        ) AS organization ON TRUE
        WHERE ($1::text IS NULL OR application.review_status = $1)
          AND ($2::timestamptz IS NULL
               OR (application.created_at, application.id) < ($2, $3))
        ORDER BY application.created_at DESC, application.id DESC
        LIMIT $4
        ",
    )
    .bind(query.status)
    .bind(at)
    .bind(id)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("admin_application_list"))?;
    let next_cursor = if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
        rows.pop();
        rows.last()
            .map(|item| cursor::encode(item.created_at, item.id))
            .transpose()?
    } else {
        None
    };
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(load_detail(&mut transaction, &state, row.id, true).await?);
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("admin_application_list_commit"))?;
    Ok(Json(ApplicationPage {
        items,
        page: PageInfo::from_next_cursor(next_cursor),
    }))
}

pub(super) async fn admin_decide(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
    Json(input): Json<ApplicationAdminDecision>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    validate_admin_decision(&input)?;
    let canonical = serde_json::to_vec(&json!({
        "decision": input.decision,
        "reason": input.reason,
        "approved_scopes": input.approved_scopes,
    }))
    .map_err(|_| ApiError::internal("admin_decision_canonical"))?;
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("admin_decision_context"))?;
    lock_step_up_actor(&mut transaction, carbon_id).await?;
    if input.decision == "delete" {
        for capability in [
            "applications.review",
            "applications.suspend",
            "applications.policy",
        ] {
            require_platform_capability(&mut transaction, carbon_id, capability).await?;
        }
    } else {
        let capability = match input.decision.as_str() {
            "suspend" | "reactivate" => "applications.suspend",
            _ => "applications.review",
        };
        require_platform_capability(&mut transaction, carbon_id, capability).await?;
    }
    let claim_app = resolve_admin_app_for_claim(&mut transaction, &path.app_id).await?;
    let caller_scope = format!("platform-admin:{carbon_id}:application:{}", claim_app.id);
    let claim = idempotency::claim::<ApplicationDetail>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/admin/applications/{app_id}/decisions",
        &canonical,
        false,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("admin_decision_replay"))?;
        let status = StatusCode::from_u16(status)
            .map_err(|_| ApiError::internal("admin_decision_replay_status"))?;
        return json_with_etag_replayed(status, &response, response.version);
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("admin_decision_idempotency"));
    };
    let expected = expected_version(&headers)?;
    let app = resolve_admin_app(&mut transaction, &path.app_id, true).await?;
    validate_admin_transition(&input, &app.review_status)?;
    if app.version != expected {
        return Err(ApiError::precondition_failed());
    }
    require_step_up(
        &mut transaction,
        &state.crypto,
        &headers,
        &access,
        "platform_admin.application_review",
        app.id,
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    apply_admin_decision(&mut transaction, carbon_id, app.id, &input).await?;
    let next_status = match input.decision.as_str() {
        "approve" | "reactivate" => Some("verified"),
        "reject" => Some("rejected"),
        "suspend" => Some("suspended"),
        "delete" => Some("deleted"),
        _ => None,
    };
    sqlx::query(
        r"
        UPDATE iam.applications
        SET review_status = COALESCE($2, review_status),
            deleted_at = CASE
                WHEN $2 = 'deleted' THEN transaction_timestamp()
                ELSE deleted_at
            END
        WHERE id = $1 AND version = $3
        ",
    )
    .bind(app.id)
    .bind(next_status)
    .bind(expected)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("admin_decision_application"))?;
    if let Some(status) = next_status {
        if status == "deleted" {
            sqlx::query(
                r"
                UPDATE iam.principals
                SET status = 'deleted', deleted_at = transaction_timestamp(),
                    suspended_at = NULL, auth_epoch = auth_epoch + 1
                WHERE id = $1 AND kind = 'application' AND status <> 'deleted'
                ",
            )
            .bind(app.id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("admin_delete_application_principal"))?;
            retire_application_credentials(&mut transaction, carbon_id, app.id).await?;
            revoke_application_authority(&mut transaction, app.id, "application_deleted").await?;
        } else if status == "suspended" {
            sqlx::query(
                r"
                UPDATE iam.principals
                SET status = 'suspended', suspended_at = transaction_timestamp(),
                    auth_epoch = auth_epoch + 1
                WHERE id = $1 AND kind = 'application'
                ",
            )
            .bind(app.id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("admin_suspend_principal"))?;
            revoke_application_authority(&mut transaction, app.id, "application_suspended").await?;
        } else if status == "verified" {
            sqlx::query(
                r"
                UPDATE iam.principals
                SET status = 'active', activated_at = COALESCE(activated_at, transaction_timestamp()),
                    suspended_at = NULL
                WHERE id = $1 AND kind = 'application' AND status <> 'deleted'
                ",
            )
            .bind(app.id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("admin_restore_principal"))?;
        }
    }
    let version =
        sqlx::query_scalar::<_, i64>("SELECT version FROM iam.applications WHERE id = $1")
            .bind(app.id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("admin_decision_version"))?;
    sqlx::query(
        r"
        INSERT INTO iam.application_reviews (
            id, application_id, reviewer_carbon_id, decision, reason, application_version
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(app.id)
    .bind(carbon_id)
    .bind(review_decision_name(&input.decision))
    .bind(&input.reason)
    .bind(version)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("application_review_insert"))?;
    let response = load_detail(&mut transaction, &state, app.id, true).await?;
    let deleted = input.decision == "delete";
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            organization_id: app.organization_id,
            application_id: app.id,
            action: if deleted {
                "application.delete"
            } else {
                "application.review.decide"
            },
            target_type: "application",
            target_id: Some(app.id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: version,
            before: Some(json!({ "review_status": app.review_status })),
            after: Some(json!({ "review_status": response.status })),
            metadata: json!({
                "decision": input.decision,
                "reason_present": input.reason.is_some(),
                "authority_revoked": deleted,
            }),
            event_type: if deleted {
                "application.deleted"
            } else {
                "application.review_decided"
            },
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        200,
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("admin_decision_commit"))?;
    json_with_etag(StatusCode::OK, &response, response.version)
}

pub(super) async fn resolve_technical_app(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    app_id: &str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    resolve_app(
        transaction,
        Some(carbon_id),
        app_id,
        "technical",
        for_update,
    )
    .await
}

pub(super) async fn resolve_readable_app(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    app_id: &str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    resolve_app(transaction, Some(carbon_id), app_id, "read", for_update).await
}

/// Resolves only the webhook review surface: organization managers and current
/// platform application reviewers share this narrow authority. The privileged
/// grant is locked by an owner-rights helper because runtime roles deliberately
/// cannot update (or issue locking reads against) platform role grants.
pub(super) async fn resolve_webhook_review_app(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    app_id: &str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    let platform_reviewer =
        sqlx::query_scalar::<_, bool>("SELECT iam_private.lock_application_webhook_reviewer($1)")
            .bind(carbon_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("application_webhook_reviewer_lock"))?;
    if platform_reviewer {
        resolve_admin_app(transaction, app_id, for_update).await
    } else {
        resolve_technical_app(transaction, carbon_id, app_id, for_update).await
    }
}

async fn resolve_admin_app_for_claim(
    transaction: &mut Transaction<'_, Postgres>,
    app_id: &str,
) -> Result<ApplicationView, ApiError> {
    let app = sqlx::query_as::<_, ApplicationView>(
        r"
        SELECT application.id, application.app_id, application.organization_id,
               organization.org_id, application.created_by_carbon_id,
               application.app_name, application.app_logo_uri, application.base_url,
               application.review_status, application.version,
               application.created_at, application.updated_at
        FROM iam.applications AS application
        JOIN LATERAL iam_private.resolve_authorized_application_organization(
            application.id
        ) AS organization ON TRUE
        WHERE application.app_id = $1
        ",
    )
    .bind(app_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("admin_application_claim_resolve"))?
    .ok_or_else(ApiError::not_found)?;
    sqlx::query(
        r"
        SELECT set_config('iam.application_id', $1, true),
               set_config('iam.organization_id', $2, true)
        ",
    )
    .bind(app.id.to_string())
    .bind(app.organization_id.to_string())
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("admin_application_claim_context"))?;
    Ok(app)
}

async fn resolve_admin_app(
    transaction: &mut Transaction<'_, Postgres>,
    app_id: &str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    resolve_app(transaction, None, app_id, "admin", for_update).await
}

async fn resolve_app(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Option<Uuid>,
    app_id: &str,
    access: &'static str,
    for_update: bool,
) -> Result<ApplicationView, ApiError> {
    let app = if for_update {
        sqlx::query_as::<_, ApplicationView>(
            r"
            SELECT application.id, application.app_id, application.organization_id,
                   organization.org_id, application.created_by_carbon_id,
                   application.app_name, application.app_logo_uri, application.base_url,
                   application.review_status, application.version,
                   application.created_at, application.updated_at
            FROM iam.applications AS application
            JOIN LATERAL iam_private.resolve_authorized_application_organization(
                application.id
            ) AS organization ON TRUE
            WHERE application.app_id = $1 AND application.deleted_at IS NULL
              AND CASE $3::text
                    WHEN 'read' THEN iam_private.can_read_application(application.id, $2)
                    WHEN 'technical' THEN iam_private.can_manage_application_technical(application.id, $2)
                    WHEN 'manage' THEN iam_private.can_manage_application(application.id, $2)
                    WHEN 'admin' THEN TRUE
                    ELSE FALSE
                  END
            FOR UPDATE OF application
            ",
        )
        .bind(app_id)
        .bind(carbon_id)
        .bind(access)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as::<_, ApplicationView>(
            r"
            SELECT application.id, application.app_id, application.organization_id,
                   organization.org_id, application.created_by_carbon_id,
                   application.app_name, application.app_logo_uri, application.base_url,
                   application.review_status, application.version,
                   application.created_at, application.updated_at
            FROM iam.applications AS application
            JOIN LATERAL iam_private.resolve_authorized_application_organization(
                application.id
            ) AS organization ON TRUE
            WHERE application.app_id = $1 AND application.deleted_at IS NULL
              AND CASE $3::text
                    WHEN 'read' THEN iam_private.can_read_application(application.id, $2)
                    WHEN 'technical' THEN iam_private.can_manage_application_technical(application.id, $2)
                    WHEN 'manage' THEN iam_private.can_manage_application(application.id, $2)
                    WHEN 'admin' THEN TRUE
                    ELSE FALSE
                  END
            ",
        )
        .bind(app_id)
        .bind(carbon_id)
        .bind(access)
        .fetch_optional(&mut **transaction)
        .await
    }
    .map_err(|_| ApiError::internal("application_resolve"))?
    .ok_or_else(ApiError::not_found)?;
    context::select_organization(transaction, app.organization_id)
        .await
        .map_err(|_| ApiError::internal("application_organization_context_select"))?;
    if let Some(carbon_id) = carbon_id {
        lock_current_application_manager(transaction, app.organization_id, carbon_id).await?;
    }
    select_application_context(transaction, app.id, app.organization_id).await?;
    Ok(app)
}

async fn select_application_context(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    organization_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        r"
        SELECT set_config('iam.application_id', $1, true),
               set_config('iam.organization_id', $2, true)
        ",
    )
    .bind(application_id.to_string())
    .bind(organization_id.to_string())
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_context_select"))?;
    Ok(())
}

pub(crate) async fn load_detail(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    application_id: Uuid,
    _include_admin_policy: bool,
) -> Result<ApplicationDetail, ApiError> {
    let application = sqlx::query_as::<_, ApplicationView>(
        r"
        SELECT application.id, application.app_id, application.organization_id,
               organization.org_id, application.created_by_carbon_id,
               application.app_name, application.app_logo_uri, application.base_url,
               application.review_status, application.version,
               application.created_at, application.updated_at
        FROM iam.applications AS application
        JOIN LATERAL iam_private.resolve_authorized_application_organization(
            application.id
        ) AS organization ON TRUE
        WHERE application.id = $1
        ",
    )
    .bind(application_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_detail"))?;
    let creator_public_id =
        sqlx::query_scalar::<_, String>("SELECT carbon_id FROM iam.carbons WHERE id = $1")
            .bind(application.created_by_carbon_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("application_creator_public_id"))?;
    let requested_scopes = sqlx::query_scalar::<_, String>(
        r"
        SELECT scope FROM iam.application_requested_scopes
        WHERE application_id = $1 ORDER BY scope
        ",
    )
    .bind(application_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_requested_scopes"))?;
    let approved_scopes = sqlx::query_scalar::<_, String>(
        r"
        SELECT scope FROM iam.application_approved_scopes
        WHERE application_id = $1 AND revoked_at IS NULL ORDER BY scope
        ",
    )
    .bind(application_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_approved_scopes"))?;
    let obo_endpoints = sqlx::query_as::<_, ApplicationOboEndpoint>(
        r"
        SELECT endpoint_id, path, metadata_definition AS metadata
        FROM iam.application_obo_endpoints
        WHERE application_id = $1 AND status = 'active'
        ORDER BY endpoint_id
        ",
    )
    .bind(application_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_obo_endpoints"))?;
    let has_pending_changes = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1 FROM iam.applications
            WHERE id = $1 AND deleted_at IS NULL
        ) AND (
            EXISTS (
                SELECT 1 FROM iam.application_webhook_endpoints
                WHERE application_id = $1 AND status = 'pending_review'
            )
            OR EXISTS (
                SELECT 1
                FROM iam.application_requested_scopes AS requested
                WHERE requested.application_id = $1
                  AND NOT EXISTS (
                      SELECT 1 FROM iam.application_approved_scopes AS approved
                      WHERE approved.application_id = requested.application_id
                        AND approved.scope = requested.scope
                        AND approved.revoked_at IS NULL
                )
            )
        )
        ",
    )
    .bind(application_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_pending_changes"))?;
    let webhook =
        super::webhooks::load_webhook(transaction, state, application_id, application.version)
            .await?;
    Ok(ApplicationDetail {
        id: application.id,
        app_id: application.app_id,
        org_id: application.org_id,
        created_by: PublicActor {
            principal_id: application.created_by_carbon_id,
            actor_type: ActorType::Carbon.as_str().to_owned(),
            public_id: creator_public_id,
        },
        app_name: application.app_name,
        app_logo: application.app_logo_uri,
        base_url: application.base_url,
        requested_scopes,
        approved_scopes,
        obo_endpoints,
        status: application.review_status,
        webhook,
        has_pending_changes,
        version: application.version,
        created_at: application.created_at,
        updated_at: application.updated_at,
    })
}

pub(super) async fn bump_application(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
) -> Result<i64, ApiError> {
    sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.applications
        SET updated_at = transaction_timestamp()
        WHERE id = $1
        RETURNING version
        ",
    )
    .bind(application_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_version_bump"))
}

pub(super) async fn revoke_application_authority(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    reason: &'static str,
) -> Result<(), ApiError> {
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'revoked', revoked_at = transaction_timestamp(), revocation_reason = $2
        WHERE client_application_id = $1 AND status = 'active'
        ",
    )
    .bind(application_id)
    .bind(reason)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_refresh_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.refresh_tokens AS token
        SET revoked_at = transaction_timestamp()
        FROM iam.refresh_token_families AS family
        WHERE token.family_id = family.id
          AND family.client_application_id = $1
          AND token.revoked_at IS NULL
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_refresh_token_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.access_tokens
        SET revoked_at = transaction_timestamp(), revocation_reason = $2
        WHERE (client_application_id = $1 OR audience_application_id = $1)
          AND revoked_at IS NULL
        ",
    )
    .bind(application_id)
    .bind(reason)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_access_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.oauth_consent_grants
        SET status = 'revoked', revoked_at = transaction_timestamp()
        WHERE application_id = $1 AND status = 'active'
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_consent_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.obo_proofs
        SET revoked_at = transaction_timestamp()
        WHERE (issuer_application_id = $1 OR audience_application_id = $1)
          AND consumed_at IS NULL AND revoked_at IS NULL
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_obo_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.webhook_deliveries AS delivery
        SET status = 'cancelled', lease_owner = NULL, lease_expires_at = NULL
        FROM iam.outbox_event_recipients AS recipient
        JOIN iam.application_webhook_endpoints AS endpoint
          ON endpoint.id = recipient.application_webhook_endpoint_id
        WHERE delivery.recipient_id = recipient.id
          AND endpoint.application_id = $1
          AND delivery.status IN ('pending', 'processing')
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_delivery_cancel"))?;
    Ok(())
}

pub(super) async fn retire_application_credentials(
    transaction: &mut Transaction<'_, Postgres>,
    reviewer: Uuid,
    application_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        r"
        UPDATE iam.application_secrets
        SET status = 'compromised', retired_at = transaction_timestamp(), retires_at = NULL
        WHERE application_id = $1 AND status IN ('active', 'retiring')
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("deleted_application_secret_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.application_webhook_signing_keys
        SET status = 'compromised', retired_at = transaction_timestamp(), retires_at = NULL
        WHERE application_id = $1 AND status IN ('active', 'retiring')
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("deleted_application_webhook_secret_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.application_webhook_endpoints
        SET status = 'disabled'
        WHERE application_id = $1 AND status IN ('active', 'pending_review')
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("deleted_application_webhook_disable"))?;
    sqlx::query(
        r"
        UPDATE iam.application_obo_endpoints
        SET status = 'retired', retired_at = transaction_timestamp()
        WHERE application_id = $1 AND status = 'active'
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("deleted_application_obo_retire"))?;
    sqlx::query(
        r"
        UPDATE iam.application_approved_scopes
        SET revoked_by_carbon_id = $2, revoked_at = transaction_timestamp()
        WHERE application_id = $1 AND revoked_at IS NULL
        ",
    )
    .bind(application_id)
    .bind(reviewer)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("deleted_application_scope_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.oauth_authorization_codes
        SET consumed_at = transaction_timestamp()
        WHERE application_id = $1 AND consumed_at IS NULL
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("deleted_application_code_consume"))?;
    sqlx::query(
        r"
        UPDATE iam.oauth_authorization_requests
        SET status = 'denied', decided_at = COALESCE(decided_at, transaction_timestamp())
        WHERE application_id = $1 AND status IN ('pending', 'approved')
        ",
    )
    .bind(application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("deleted_application_authorization_deny"))?;
    Ok(())
}

async fn apply_admin_decision(
    transaction: &mut Transaction<'_, Postgres>,
    reviewer: Uuid,
    application_id: Uuid,
    input: &ApplicationAdminDecision,
) -> Result<(), ApiError> {
    let effective_scopes = if let Some(scopes) = &input.approved_scopes {
        Some(scopes.clone())
    } else if matches!(
        input.decision.as_str(),
        "approve" | "approve_pending_changes"
    ) {
        Some(
            sqlx::query_scalar::<_, String>(
                r"
                SELECT scope FROM iam.application_requested_scopes
                WHERE application_id = $1 ORDER BY scope
                ",
            )
            .bind(application_id)
            .fetch_all(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("requested_scope_review"))?,
        )
    } else {
        None
    };
    if let Some(scopes) = &effective_scopes {
        let removed_scopes = sqlx::query_scalar::<_, String>(
            r"
            UPDATE iam.application_approved_scopes
            SET revoked_by_carbon_id = $2, revoked_at = transaction_timestamp()
            WHERE application_id = $1 AND revoked_at IS NULL
              AND NOT (scope = ANY($3::text[]))
            RETURNING scope
            ",
        )
        .bind(application_id)
        .bind(reviewer)
        .bind(scopes)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("approved_scope_revoke"))?;
        if !removed_scopes.is_empty() {
            sqlx::query(REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY)
                .bind(application_id)
                .bind(&removed_scopes)
                .execute(&mut **transaction)
                .await
                .map_err(|_| ApiError::internal("approved_scope_access_revoke"))?;
        }
        for scope in scopes {
            let inserted = sqlx::query(
                r"
                INSERT INTO iam.application_approved_scopes (
                    application_id, scope, approved_by_carbon_id
                )
                SELECT requested.application_id, requested.scope, $3
                FROM iam.application_requested_scopes AS requested
                WHERE requested.application_id = $1 AND requested.scope = $2
                  AND NOT EXISTS (
                      SELECT 1 FROM iam.application_approved_scopes AS approved
                      WHERE approved.application_id = requested.application_id
                        AND approved.scope = requested.scope AND approved.revoked_at IS NULL
                  )
                ",
            )
            .bind(application_id)
            .bind(scope)
            .bind(reviewer)
            .execute(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("approved_scope_insert"))?;
            if inserted.rows_affected() == 0 {
                let active = sqlx::query_scalar::<_, bool>(
                    r"
                    SELECT EXISTS (
                        SELECT 1 FROM iam.application_approved_scopes
                        WHERE application_id = $1 AND scope = $2 AND revoked_at IS NULL
                    )
                    ",
                )
                .bind(application_id)
                .bind(scope)
                .fetch_one(&mut **transaction)
                .await
                .map_err(|_| ApiError::internal("approved_scope_check"))?;
                if !active {
                    return Err(ApiError::validation(
                        "approved_scopes",
                        format!("scope was not requested: {scope}"),
                    ));
                }
            }
        }
    }
    let endpoint_id = if matches!(
        input.decision.as_str(),
        "approve" | "approve_pending_changes"
    ) {
        sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id FROM iam.application_webhook_endpoints
            WHERE application_id = $1 AND status = 'pending_review'
            ORDER BY created_at DESC, id DESC LIMIT 1
            ",
        )
        .bind(application_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_pending_review"))?
    } else {
        None
    };
    if let Some(endpoint_id) = endpoint_id {
        sqlx::query(
            r"
            UPDATE iam.application_webhook_endpoints
            SET status = 'retired', retired_at = transaction_timestamp()
            WHERE application_id = $1 AND status = 'active' AND id <> $2
            ",
        )
        .bind(application_id)
        .bind(endpoint_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_previous_retire"))?;
        let result = sqlx::query(
            r"
            UPDATE iam.application_webhook_endpoints
            SET status = 'active', activated_at = transaction_timestamp()
            WHERE application_id = $1 AND id = $2 AND status = 'pending_review'
            ",
        )
        .bind(application_id)
        .bind(endpoint_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_activate"))?;
        if result.rows_affected() != 1 {
            return Err(ApiError::validation(
                "webhook_endpoint_id",
                "must identify a pending endpoint",
            ));
        }
        sqlx::query(
            r"
            UPDATE iam.application_webhook_endpoints
            SET status = 'retired', retired_at = transaction_timestamp()
            WHERE application_id = $1 AND status = 'pending_review' AND id <> $2
            ",
        )
        .bind(application_id)
        .bind(endpoint_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_pending_retire"))?;
    }
    if input.decision == "reject_pending_changes" {
        sqlx::query(
            r"
            UPDATE iam.application_webhook_endpoints
            SET status = 'retired', retired_at = transaction_timestamp()
            WHERE application_id = $1 AND status = 'pending_review'
            ",
        )
        .bind(application_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_reject_pending"))?;
        sqlx::query(
            r"
            DELETE FROM iam.application_requested_scopes AS requested
            WHERE requested.application_id = $1
              AND NOT EXISTS (
                  SELECT 1 FROM iam.application_approved_scopes AS approved
                  WHERE approved.application_id = requested.application_id
                    AND approved.scope = requested.scope
                    AND approved.revoked_at IS NULL
              )
            ",
        )
        .bind(application_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("scope_reject_pending"))?;
    }
    Ok(())
}

fn validate_admin_decision(input: &ApplicationAdminDecision) -> Result<(), ApiError> {
    if !matches!(
        input.decision.as_str(),
        "approve"
            | "reject"
            | "suspend"
            | "reactivate"
            | "delete"
            | "approve_pending_changes"
            | "reject_pending_changes"
    ) {
        return Err(ApiError::validation(
            "decision",
            "contains an invalid decision",
        ));
    }
    if input
        .reason
        .as_deref()
        .is_some_and(|reason| reason.is_empty() || reason.chars().count() > 2_000)
    {
        return Err(ApiError::validation(
            "reason",
            "must contain 1 to 2000 characters",
        ));
    }
    if let Some(scopes) = &input.approved_scopes {
        validation::scopes(scopes)?;
    }
    let approves_changes = matches!(
        input.decision.as_str(),
        "approve" | "approve_pending_changes"
    );
    if !approves_changes && input.approved_scopes.is_some() {
        return Err(ApiError::validation(
            "decision",
            "review approvals are only valid with an approving decision",
        ));
    }
    Ok(())
}

fn validate_admin_transition(
    input: &ApplicationAdminDecision,
    current_status: &str,
) -> Result<(), ApiError> {
    let allowed = match input.decision.as_str() {
        "approve" | "reject" => current_status == "under_review",
        "suspend" | "approve_pending_changes" | "reject_pending_changes" => {
            current_status == "verified"
        }
        "reactivate" => current_status == "suspended",
        "delete" => current_status != "deleted",
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(ApiError::conflict("application_review_state_conflict"))
    }
}

fn review_decision_name(decision: &str) -> &'static str {
    match decision {
        "approve" | "approve_pending_changes" => "approve",
        "suspend" => "suspend",
        "reactivate" => "restore",
        "delete" => "delete",
        _ => "reject",
    }
}

fn input_as_json(input: &ApplicationPatch) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    if let Some(value) = &input.base_url {
        object.insert("base_url".to_owned(), json!(value));
    }
    if let Some(value) = &input.app_name {
        object.insert("app_name".to_owned(), json!(value));
    }
    if let Some(value) = &input.app_logo_uri {
        object.insert("app_logo_uri".to_owned(), json!(value));
    }
    if let Some(value) = &input.obo_endpoints {
        object.insert("obo_endpoints".to_owned(), json!(value));
    }
    serde_json::Value::Object(object)
}

async fn replace_obo_endpoints(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    endpoints: &[ApplicationOboEndpoint],
) -> Result<(), ApiError> {
    for endpoint in endpoints {
        let result = sqlx::query(
            r"
            INSERT INTO iam.application_obo_endpoints (
                organization_id, application_id, endpoint_id, path, metadata_definition
            )
            SELECT application.organization_id, application.id, $2, $3, $4
            FROM iam.applications AS application
            WHERE application.id = $1
            ON CONFLICT (application_id, endpoint_id) DO UPDATE
            SET metadata_definition = EXCLUDED.metadata_definition,
                status = 'active',
                retired_at = NULL
            WHERE application_obo_endpoints.path = EXCLUDED.path
            ",
        )
        .bind(application_id)
        .bind(&endpoint.endpoint_id)
        .bind(&endpoint.path)
        .bind(sqlx::types::Json(&endpoint.metadata))
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_obo_endpoint_write(&error))?;
        if result.rows_affected() != 1 {
            return Err(ApiError::conflict("obo_endpoint_path_immutable"));
        }
    }
    let endpoint_ids = endpoints
        .iter()
        .map(|endpoint| endpoint.endpoint_id.as_str())
        .collect::<Vec<_>>();
    sqlx::query(
        r"
        UPDATE iam.application_obo_endpoints
        SET status = 'retired', retired_at = transaction_timestamp()
        WHERE application_id = $1
          AND status = 'active'
          AND NOT (endpoint_id = ANY($2::text[]))
        ",
    )
    .bind(application_id)
    .bind(endpoint_ids)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("application_obo_endpoint_retire"))?;
    Ok(())
}

fn map_obo_endpoint_write(error: &sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database) = error
        && (database.is_unique_violation() || database.is_check_violation())
    {
        return ApiError::conflict("obo_endpoint_conflict");
    }
    ApiError::internal("application_obo_endpoint_write")
}

pub(super) fn secret_prefix(secret: &str) -> String {
    secret.chars().take(12).collect()
}

pub(crate) fn webhook_secret_fingerprint(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    format!("whs_{}", hex::encode(&digest[..4]))
}

fn created_secret_response(
    status: StatusCode,
    response: ApplicationCreated,
    replayed: bool,
) -> Response {
    let mut response = (status, Json(response)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    response
}

pub(super) fn secret_json_with_etag<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
    version: i64,
    replayed: bool,
) -> Result<Response, ApiError> {
    let mut response = json_with_etag(status, body, version)?;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    Ok(response)
}

pub(super) fn json_with_etag<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
    version: i64,
) -> Result<Response, ApiError> {
    let mut response = (status, Json(body)).into_response();
    let etag = HeaderValue::from_str(&format!("\"{version}\""))
        .map_err(|_| ApiError::internal("etag_encode"))?;
    response.headers_mut().insert(header::ETAG, etag);
    Ok(response)
}

pub(super) fn json_with_etag_replayed<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
    version: i64,
) -> Result<Response, ApiError> {
    let mut response = json_with_etag(status, body, version)?;
    response.headers_mut().insert(
        http::HeaderName::from_static("idempotency-replayed"),
        HeaderValue::from_static("true"),
    );
    Ok(response)
}

#[allow(clippy::needless_pass_by_value)]
fn map_application_write(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database) = &error
        && database.is_unique_violation()
    {
        return ApiError::conflict("application_conflict");
    }
    ApiError::internal("application_write")
}

#[cfg(test)]
mod tests {
    use super::{
        REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY, json_with_etag_replayed,
        validate_admin_decision, validate_admin_transition, webhook_secret_fingerprint,
    };
    use crate::features::applications::model::ApplicationAdminDecision;
    use axum::http::{HeaderValue, StatusCode, header};

    fn admin_decision(decision: &str) -> ApplicationAdminDecision {
        ApplicationAdminDecision {
            decision: decision.to_owned(),
            reason: Some("operator request".to_owned()),
            approved_scopes: None,
        }
    }

    #[test]
    fn backend_delete_is_a_terminal_admin_review_transition() {
        let input = admin_decision("delete");
        assert!(validate_admin_decision(&input).is_ok());
        for status in ["under_review", "verified", "rejected", "suspended"] {
            assert!(
                validate_admin_transition(&input, status).is_ok(),
                "backend deletion must accept {status} applications"
            );
        }
        assert!(validate_admin_transition(&input, "deleted").is_err());
    }

    #[test]
    fn replayed_versioned_response_preserves_status_and_etag() {
        let Ok(response) = json_with_etag_replayed(
            StatusCode::ACCEPTED,
            &serde_json::json!({ "version": 17 }),
            17,
        ) else {
            panic!("a valid aggregate version must produce an ETag");
        };

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response.headers().get(header::ETAG),
            Some(&HeaderValue::from_static("\"17\""))
        );
        assert_eq!(
            response.headers().get("idempotency-replayed"),
            Some(&HeaderValue::from_static("true"))
        );
    }

    #[test]
    fn backend_delete_rejects_unrelated_policy_mutation() {
        let mut input = admin_decision("delete");
        input.approved_scopes = Some(vec!["organizations.read".to_owned()]);
        assert!(validate_admin_decision(&input).is_err());
    }

    #[test]
    fn webhook_secret_fingerprint_keeps_the_database_identifier_non_secret() {
        let first = webhook_secret_fingerprint("caller-owned-webhook-secret-00001");
        let second = webhook_secret_fingerprint("caller-owned-webhook-secret-00002");
        assert_eq!(first.len(), 12);
        assert!(first.starts_with("whs_"));
        assert_ne!(first, second);
        assert!(!first.contains("caller"));
    }

    #[test]
    fn removed_scopes_revoke_only_intersecting_active_client_access_tokens() {
        for required_fragment in [
            "token.client_application_id = $1",
            "token.token_class = 'application_access'",
            "token.revoked_at IS NULL",
            "token.expires_at > transaction_timestamp()",
            "FROM iam.access_token_scopes AS token_scope",
            "token_scope.access_token_id = token.id",
            "token_scope.scope = ANY($2::text[])",
            "revocation_reason = 'application_scope_revoked'",
        ] {
            assert!(
                REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY.contains(required_fragment),
                "scope-removal containment is missing `{required_fragment}`"
            );
        }
        assert!(!REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY.contains("refresh_tokens"));
        assert!(!REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY.contains("authentication_sessions"));
    }

    /// Resolves the owning organization as the restricted API role.
    ///
    /// Registering an application always answered 404. The lookup share-locks
    /// the organization and the caller's membership, PostgreSQL applies a
    /// table's UPDATE policy to a locking read, and
    /// `organizations_authorized_update` requires `current_organization_id()` —
    /// a setting chosen from this lookup's own result. The statement therefore
    /// had to know its answer before it could produce it.
    ///
    /// Every other Docker-backed test connects as the schema owner, where row
    /// security does not apply and the fault is invisible. This one provisions
    /// the restricted roles so the lookup runs exactly as production runs it.
    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    #[allow(
        clippy::too_many_lines,
        reason = "the roles, grants and organization fixture form one end-to-end contract"
    )]
    async fn the_owning_organization_resolves_for_the_restricted_api_role() -> anyhow::Result<()> {
        use anyhow::ensure;
        use sqlx::postgres::PgPoolOptions;
        use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
        use testcontainers_modules::postgres::Postgres as TestPostgres;
        use uuid::Uuid;

        const RUNTIME_ROLES: &str = "
            CREATE ROLE silicon_iam_api NOLOGIN NOSUPERUSER NOBYPASSRLS;
            CREATE ROLE silicon_iam_worker NOLOGIN NOSUPERUSER NOBYPASSRLS;
            CREATE ROLE silicon_iam_key_operator NOLOGIN NOSUPERUSER NOBYPASSRLS;
            CREATE ROLE silicon_iam_api_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS
                IN ROLE silicon_iam_api;
        ";
        let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");

        let container = TestPostgres::default()
            .with_tag("16-alpine")
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        crate::infrastructure::postgres::migrate(&pool).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(RUNTIME_ROLES))
            .execute(&pool)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
            .execute(&pool)
            .await?;

        let carbon_id = Uuid::from_u128(0x51_01);
        let organization_id = Uuid::from_u128(0x51_02);
        let membership_id = Uuid::from_u128(0x51_03);

        let mut fixture = pool.begin().await?;
        sqlx::query(
            r"
            INSERT INTO iam.principals (id, kind, status, activated_at)
            VALUES ($1, 'carbon', 'active', transaction_timestamp())
            ",
        )
        .bind(carbon_id)
        .execute(&mut *fixture)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.carbons (id, carbon_id, display_name)
            VALUES ($1, 'owner-under-rls', 'Owner Under Row Security')
            ",
        )
        .bind(carbon_id)
        .execute(&mut *fixture)
        .await?;
        // An active Carbon must hold one verified primary contact of each kind;
        // a deferred assertion enforces it at commit.
        sqlx::query(
            r"
            INSERT INTO iam.cryptographic_key_versions (purpose, key_version)
            VALUES ('contact_aead', 1)
            ",
        )
        .execute(&mut *fixture)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.carbon_contacts (
                id, carbon_id, kind, ciphertext, nonce, encryption_key_version, verified_at
            ) VALUES
                ($1, $3, 'email', decode(repeat('11', 17), 'hex'),
                    decode(repeat('12', 12), 'hex'), 1, transaction_timestamp()),
                ($2, $3, 'phone', decode(repeat('21', 17), 'hex'),
                    decode(repeat('22', 12), 'hex'), 1, transaction_timestamp())
            ",
        )
        .bind(Uuid::from_u128(0x51_05))
        .bind(Uuid::from_u128(0x51_06))
        .bind(carbon_id)
        .execute(&mut *fixture)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
            VALUES ($1, 'tos', $2, 'Team of Silicons')
            ",
        )
        .bind(organization_id)
        .bind(carbon_id)
        .execute(&mut *fixture)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role
            ) VALUES ($1, $2, $3, 'carbon', 'owner')
            ",
        )
        .bind(membership_id)
        .bind(organization_id)
        .bind(carbon_id)
        .execute(&mut *fixture)
        .await?;
        fixture.commit().await?;

        // Exactly the context the handler has at this point: the principal is
        // known, the organization is not — that is what the lookup decides.
        let mut resolving = pool.begin().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(
            "SET LOCAL ROLE silicon_iam_api_runtime",
        ))
        .execute(&mut *resolving)
        .await?;
        sqlx::query("SELECT set_config('iam.principal_id', $1::text, true)")
            .bind(carbon_id)
            .execute(&mut *resolving)
            .await?;

        let resolved = super::resolve_creation_organization(&mut resolving, carbon_id, "tos")
            .await
            .map_err(|_| anyhow::anyhow!("the owning organization did not resolve"))?;

        ensure!(
            resolved == organization_id,
            "resolved {resolved} instead of {organization_id}"
        );

        // A Carbon with no membership must still be refused.
        let stranger = Uuid::from_u128(0x51_04);
        ensure!(
            super::resolve_creation_organization(&mut resolving, stranger, "tos")
                .await
                .is_err(),
            "a Carbon outside the organization must not resolve it"
        );

        Ok(())
    }
}
