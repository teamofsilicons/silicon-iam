#![allow(clippy::too_many_lines)]

use std::borrow::Cow;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use secrecy::ExposeSecret as _;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::organization::Capability,
    error::AppError,
    infrastructure::{crypto::DigestPurpose, postgres::step_up::RequiredAssurance},
};

use super::{
    model::{
        PageInfo, RemovalQuery, SiliconCreate, SiliconCreatedResponse, SiliconHookResponse,
        SiliconPage, SiliconPatch, SiliconQuery, SiliconResponse,
    },
    support::{self, Claim, MutationEvent},
    validation,
};

const SILICON_CREATE_ROUTE: &str = "/api/v1/organizations/{org_id}/silicons";
const SILICON_UPDATE_ROUTE: &str = "/api/v1/organizations/{org_id}/silicons/{silicon_id}";
const SILICON_HOOK_ROUTE: &str = "/api/v1/organizations/{org_id}/silicons/{silicon_id}/iam-hook";

#[derive(Clone, Debug, sqlx::FromRow)]
struct SiliconIdentity {
    principal_id: Uuid,
    membership_id: Uuid,
    version: i64,
    membership_version: i64,
    status: String,
}

pub(super) async fn list_silicons(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<SiliconQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (cursor, limit) = validation::page_parts(query.cursor.as_deref(), query.limit)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let profile_base = silicon_profile_base(&state)?;
    let mut items = sqlx::query_as::<_, SiliconResponse>(SILICON_LIST_SQL)
        .bind(scope.access.organization_id)
        .bind(cursor)
        .bind(limit + 1)
        .bind(query.tag_id)
        .bind(profile_base)
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_page(&mut items, limit)?;
    support::json(StatusCode::OK, &SiliconPage { items, page }, None)
}

pub(super) async fn create_silicon(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<SiliconCreate>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validation::silicon_create(&mut input, state.settings.environment)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::SiliconsCreate)?;
    if !input.tag_ids.is_empty() {
        support::require_capability(&scope.access, Capability::TagsManage)?;
    }
    if !input.machine_capabilities.is_empty() {
        support::require_capability(&scope.access, Capability::AdminsManage)?;
    }
    validate_references(
        &mut scope.transaction,
        scope.access.organization_id,
        &input.tag_ids,
        input.reports_to_membership_id,
    )
    .await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        SILICON_CREATE_ROUTE,
        &input,
        true,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let token = state
        .crypto
        .generate_silicon_token()
        .map_err(|_| AppError::Internal {
            category: "silicon_token_generate",
        })?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::SiliconCredential, &token)
        .map_err(|_| AppError::Internal {
            category: "silicon_token_digest",
        })?;
    let principal_id = Uuid::now_v7();
    let membership_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.principals (id, kind, status, activated_at)
        VALUES ($1, 'silicon', 'active', transaction_timestamp())
        ",
    )
    .bind(principal_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.organization_memberships (
            id, organization_id, principal_id, principal_kind, job_role
        ) VALUES ($1, $2, $3, 'silicon', $4)
        ",
    )
    .bind(membership_id)
    .bind(scope.access.organization_id)
    .bind(principal_id)
    .bind(&input.job_role)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "silicon_id_unavailable"))?;
    sqlx::query(
        r"
        INSERT INTO iam.silicons (
            id, organization_id, membership_id, organization_handle,
            local_silicon_id, profile_photo_override_uri, reports_to_membership_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(principal_id)
    .bind(scope.access.organization_id)
    .bind(membership_id)
    .bind(&org_id)
    .bind(&input.silicon_id)
    .bind(&input.profile_photo)
    .bind(input.reports_to_membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "silicon_id_unavailable"))?;
    let prefix = token.expose_secret().get(..12).ok_or(AppError::Internal {
        category: "silicon_token_prefix",
    })?;
    sqlx::query(
        r"
        INSERT INTO iam.silicon_credentials (
            id, organization_id, silicon_id, credential_prefix, secret_digest,
            pepper_key_version, created_by_membership_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(scope.access.organization_id)
    .bind(principal_id)
    .bind(prefix)
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        "INSERT INTO iam.silicon_hooks (id, organization_id, silicon_id) VALUES ($1, $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(scope.access.organization_id)
    .bind(principal_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    assign_tags(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        scope.access.membership_id,
        &input.tag_ids,
    )
    .await?;
    grant_machine_capabilities(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        scope.access.membership_id,
        &input.machine_capabilities,
    )
    .await?;
    let silicon = fetch_silicon(
        &mut scope.transaction,
        scope.access.organization_id,
        &format!("{}:{org_id}", input.silicon_id),
        &silicon_profile_base(&state)?,
    )
    .await?;
    let secret_replay_expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
    let response = SiliconCreatedResponse {
        silicon,
        silicon_token: token.expose_secret().to_owned(),
        secret_replay_expires_at,
    };
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "silicon.created",
            target_type: "silicon",
            target_id: principal_id,
            aggregate_type: "silicon",
            aggregate_id: principal_id,
            aggregate_version: response.silicon.version,
            event_type: "organization.silicon.created.v1",
            before_state: None,
            after_state: Some(json!({
                "principal_id": principal_id,
                "membership_id": membership_id,
                "silicon_id": response.silicon.silicon_id,
                "version": response.silicon.version,
            })),
            metadata: json!({
                "silicon_id": principal_id,
                "membership_id": membership_id,
                "subject_principal_id": principal_id,
            }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, None, true)
}

pub(super) async fn get_silicon(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon_id(&silicon_id, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let silicon = fetch_silicon(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
        &silicon_profile_base(&state)?,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &silicon, Some(silicon.version))
}

pub(super) async fn update_silicon(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(mut input): Json<SiliconPatch>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon_id(&silicon_id, &org_id)?;
    validation::silicon_patch(&mut input, state.settings.environment)?;
    let expected_version = validation::expected_version(&headers)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    if input.profile_photo.is_some() || input.tag_ids.is_some() {
        support::require_capability(&scope.access, Capability::SiliconsUpdateDirectory)?;
    }
    if input.reports_to_membership_id.is_some() {
        support::require_capability(&scope.access, Capability::SiliconsManageHierarchy)?;
    }
    if input.tag_ids.is_some() {
        support::require_capability(&scope.access, Capability::TagsManage)?;
    }
    let identity = fetch_identity(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    require_active_version(&identity, expected_version)?;
    validate_references(
        &mut scope.transaction,
        scope.access.organization_id,
        input.tag_ids.as_deref().unwrap_or(&[]),
        input.reports_to_membership_id.flatten(),
    )
    .await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        SILICON_UPDATE_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let before = fetch_silicon(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
        &silicon_profile_base(&state)?,
    )
    .await?;
    if let Some(tag_ids) = input.tag_ids.as_deref() {
        replace_tags(
            &mut scope.transaction,
            scope.access.organization_id,
            identity.membership_id,
            scope.access.membership_id,
            tag_ids,
        )
        .await?;
    }
    let result = sqlx::query(
        r"
        UPDATE iam.silicons
        SET profile_photo_override_uri = CASE WHEN $4 THEN $5 ELSE profile_photo_override_uri END,
            reports_to_membership_id = CASE WHEN $6 THEN $7 ELSE reports_to_membership_id END,
            updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND id = $2 AND version = $3
          AND provisioning_status <> 'deleted'
        ",
    )
    .bind(scope.access.organization_id)
    .bind(identity.principal_id)
    .bind(expected_version)
    .bind(input.profile_photo.is_some())
    .bind(input.profile_photo.as_ref().and_then(Clone::clone))
    .bind(input.reports_to_membership_id.is_some())
    .bind(input.reports_to_membership_id.flatten())
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "invalid_reporting_hierarchy"))?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    sqlx::query(
        "UPDATE iam.organization_memberships SET authz_epoch = authz_epoch + 1 WHERE organization_id = $1 AND id = $2 AND status = 'active'",
    )
    .bind(scope.access.organization_id)
    .bind(identity.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    let silicon = fetch_silicon(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
        &silicon_profile_base(&state)?,
    )
    .await?;
    record_silicon_change(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        "silicon.directory_updated",
        "organization.silicon.updated.v1",
        &before,
        &silicon,
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &silicon,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(silicon.version), false)
}

pub(super) async fn remove_silicon(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    Query(query): Query<RemovalQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon_id(&silicon_id, &org_id)?;
    let expected_version = validation::expected_version(&headers)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::SiliconsRemove)?;
    let identity = fetch_identity(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    require_active_version(&identity, expected_version)?;
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.authorization_change",
        Some(identity.membership_id),
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        SILICON_UPDATE_ROUTE,
        &query,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let resulting_version = sqlx::query_scalar::<_, i64>(
        r"
        SELECT silicon_version
        FROM iam_private.remove_organization_membership($1, $2, $3, $4, $5)
        ",
    )
    .bind(scope.access.organization_id)
    .bind(identity.membership_id)
    .bind(identity.membership_version)
    .bind(Some(expected_version))
    .bind(query.reassign_reports_to)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(support::transition_database)?
    .ok_or(AppError::NotFound)?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "silicon.removed",
            target_type: "silicon",
            target_id: identity.principal_id,
            aggregate_type: "silicon",
            aggregate_id: identity.principal_id,
            aggregate_version: resulting_version,
            event_type: "organization.silicon.removed.v1",
            before_state: None,
            after_state: Some(json!({ "status": "removed", "version": resulting_version })),
            metadata: json!({
                "silicon_id": identity.principal_id,
                "membership_id": identity.membership_id,
                "subject_principal_id": identity.principal_id,
            }),
        },
    )
    .await?;
    support::finish_empty(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::NO_CONTENT,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    Ok(support::empty(StatusCode::NO_CONTENT))
}

pub(super) async fn get_silicon_hook(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon_id(&silicon_id, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let response = fetch_hook(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &response, None)
}

pub(super) async fn retry_silicon_hook(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon_id(&silicon_id, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::SiliconsUpdateDirectory)?;
    let identity = fetch_identity(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    if identity.status != "active" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("silicon_not_active"),
        });
    }
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        SILICON_HOOK_ROUTE,
        &json!({ "silicon_id": silicon_id }),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    sqlx::query(
        r"
        UPDATE iam.silicon_hooks
        SET status = 'pending', last_error_code = NULL,
            next_attempt_at = transaction_timestamp()
        WHERE organization_id = $1 AND silicon_id = $2 AND status IN ('pending', 'failed')
        ",
    )
    .bind(scope.access.organization_id)
    .bind(identity.principal_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    let response = json!({ "queued": true });
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::ACCEPTED,
        &response,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::ACCEPTED, body, None, false)
}

pub(super) async fn fetch_silicon(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: &str,
    profile_base: &str,
) -> Result<SiliconResponse, AppError> {
    sqlx::query_as::<_, SiliconResponse>(SILICON_BY_ID_SQL)
        .bind(organization_id)
        .bind(silicon_id)
        .bind(profile_base)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)
}

async fn fetch_identity(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: &str,
) -> Result<SiliconIdentity, AppError> {
    sqlx::query_as::<_, SiliconIdentity>(
        r"
        SELECT silicon.id AS principal_id, silicon.membership_id,
               silicon.version,
               membership.version AS membership_version,
               CASE WHEN silicon.provisioning_status <> 'deleted'
                          AND membership.status = 'active'
                    THEN 'active' ELSE 'removed' END AS status
        FROM iam.silicons AS silicon
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id
        WHERE silicon.organization_id = $1 AND silicon.global_silicon_id = $2
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(silicon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

fn require_active_version(identity: &SiliconIdentity, version: i64) -> Result<(), AppError> {
    if identity.status != "active" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("silicon_not_active"),
        });
    }
    if identity.version != version {
        return Err(precondition_failed());
    }
    Ok(())
}

async fn validate_references(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    tag_ids: &[Uuid],
    reports_to: Option<Uuid>,
) -> Result<(), AppError> {
    let tag_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.organization_tags WHERE organization_id = $1 AND id = ANY($2) AND status = 'active'",
    )
    .bind(organization_id)
    .bind(tag_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(tag_count).ok() != Some(tag_ids.len()) {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("directory_reference_inactive"),
        });
    }
    if let Some(reports_to) = reports_to {
        validate_active_silicon(transaction, organization_id, reports_to).await?;
    }
    Ok(())
}

async fn validate_active_silicon(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
) -> Result<(), AppError> {
    let active = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM iam.silicons AS silicon
            JOIN iam.organization_memberships AS membership
              ON membership.organization_id = silicon.organization_id
             AND membership.id = silicon.membership_id
            WHERE silicon.organization_id = $1 AND silicon.membership_id = $2
              AND silicon.provisioning_status <> 'deleted' AND membership.status = 'active'
        )
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if !active {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("directory_reference_inactive"),
        });
    }
    Ok(())
}

async fn assign_tags(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    actor_membership_id: Uuid,
    tag_ids: &[Uuid],
) -> Result<(), AppError> {
    for tag_id in tag_ids {
        sqlx::query(
            r"
            INSERT INTO iam.membership_tags (
                organization_id, membership_id, tag_id, assigned_by_membership_id
            ) VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(organization_id)
        .bind(membership_id)
        .bind(tag_id)
        .bind(actor_membership_id)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    }
    Ok(())
}

async fn replace_tags(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    actor_membership_id: Uuid,
    tag_ids: &[Uuid],
) -> Result<(), AppError> {
    sqlx::query(
        "DELETE FROM iam.membership_tags WHERE organization_id = $1 AND membership_id = $2",
    )
    .bind(organization_id)
    .bind(membership_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    assign_tags(
        transaction,
        organization_id,
        membership_id,
        actor_membership_id,
        tag_ids,
    )
    .await
}

async fn grant_machine_capabilities(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    actor_membership_id: Uuid,
    capabilities: &[String],
) -> Result<(), AppError> {
    for capability in capabilities {
        sqlx::query(
            r"
            INSERT INTO iam.organization_capability_grants (
                id, organization_id, grantee_membership_id, capability,
                granted_by_membership_id, reason
            ) VALUES ($1, $2, $3, $4, $5, 'initial Silicon capability set')
            ",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(membership_id)
        .bind(capability)
        .bind(actor_membership_id)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    }
    Ok(())
}

async fn fetch_hook(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: &str,
) -> Result<SiliconHookResponse, AppError> {
    sqlx::query_as::<_, SiliconHookResponse>(
        r"
        SELECT
            CASE hook.status
                WHEN 'active' THEN 'active'
                WHEN 'failed' THEN 'error'
                WHEN 'disabled' THEN 'error'
                ELSE 'pending'
            END AS status,
            NULL::text AS masked_url,
            CASE hook.status
                WHEN 'active' THEN 'delivered'
                WHEN 'failed' THEN 'error'
                WHEN 'disabled' THEN 'error'
                ELSE 'pending'
            END AS initialized_event_status,
            hook.last_error_code,
            hook.updated_at
        FROM iam.silicon_hooks AS hook
        JOIN iam.silicons AS silicon
          ON silicon.organization_id = hook.organization_id AND silicon.id = hook.silicon_id
        WHERE hook.organization_id = $1 AND silicon.global_silicon_id = $2
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(silicon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn record_silicon_change(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    organization_id: Uuid,
    action: &'static str,
    event_type: &'static str,
    before: &SiliconResponse,
    after: &SiliconResponse,
) -> Result<(), AppError> {
    support::record_mutation(
        transaction,
        authenticated,
        organization_id,
        MutationEvent {
            action,
            target_type: "silicon",
            target_id: after.principal_id,
            aggregate_type: "silicon",
            aggregate_id: after.principal_id,
            aggregate_version: after.version,
            event_type,
            before_state: serde_json::to_value(before).ok(),
            after_state: serde_json::to_value(after).ok(),
            metadata: json!({
                "silicon_id": after.principal_id,
                "membership_id": after.membership_id,
                "subject_principal_id": after.principal_id,
            }),
        },
    )
    .await
}

fn silicon_profile_base(state: &ApiState) -> Result<String, AppError> {
    state
        .settings
        .providers
        .iris_base_url
        .join("pfp/silicon")
        .map(|url| url.to_string())
        .map_err(|_| AppError::Internal {
            category: "silicon_profile_url",
        })
}

fn validate_global_silicon_id(value: &str, org_id: &str) -> Result<(), AppError> {
    let Some((local_id, suffix)) = value.rsplit_once(':') else {
        return Err(validation::field("silicon_id", "has an invalid format"));
    };
    if suffix != org_id {
        return Err(AppError::NotFound);
    }
    let mut synthetic = SiliconCreate {
        silicon_id: local_id.to_owned(),
        profile_photo: None,
        job_role: String::new(),
        reports_to_membership_id: None,
        tag_ids: Vec::new(),
        machine_capabilities: Vec::new(),
    };
    validation::silicon_create(&mut synthetic, crate::config::RuntimeEnvironment::Test).map(|_| ())
}

fn take_page(items: &mut Vec<SiliconResponse>, limit: i64) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "silicon_page_limit",
    })?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_cursor = if has_more {
        items
            .last()
            .map(|item| validation::encode_cursor(item.principal_id))
    } else {
        None
    };
    Ok(PageInfo {
        next_cursor,
        has_more,
    })
}

fn precondition_failed() -> AppError {
    AppError::PreconditionFailed {
        code: Cow::Borrowed("etag_mismatch"),
    }
}

const SILICON_LIST_SQL: &str = concat!(
    "",
    r"
    WITH RECURSIVE hierarchy AS (
        SELECT root.id, root.membership_id, root.reports_to_membership_id, 1::integer AS level
        FROM iam.silicons AS root
        WHERE root.organization_id = $1 AND root.reports_to_membership_id IS NULL
          AND root.provisioning_status <> 'deleted'
        UNION ALL
        SELECT child.id, child.membership_id, child.reports_to_membership_id, hierarchy.level + 1
        FROM iam.silicons AS child
        JOIN hierarchy ON child.reports_to_membership_id = hierarchy.membership_id
        WHERE child.organization_id = $1 AND child.provisioning_status <> 'deleted'
    )
    SELECT silicon.id AS principal_id, silicon.membership_id,
           silicon.global_silicon_id AS silicon_id, silicon.local_silicon_id AS local_id,
           organization.org_id,
           COALESCE(silicon.profile_photo_override_uri,
                    $5 || '?id=' || silicon.global_silicon_id || '&level=' || hierarchy.level::text) AS profile_photo,
           membership.job_role, silicon.reports_to_membership_id,
           COALESCE((SELECT jsonb_agg(jsonb_build_object('id', tag.id, 'name', tag.name) ORDER BY tag.id)
                     FROM iam.membership_tags assignment
                     JOIN iam.organization_tags tag ON tag.organization_id = assignment.organization_id AND tag.id = assignment.tag_id
                     WHERE assignment.organization_id = silicon.organization_id AND assignment.membership_id = silicon.membership_id
                       AND tag.status = 'active'), '[]'::jsonb) AS tags,
           hierarchy.level AS hierarchy_level,
           CASE hook.status WHEN 'active' THEN 'active' WHEN 'failed' THEN 'error' WHEN 'disabled' THEN 'error' ELSE 'pending' END AS hook_status,
           'active'::text AS status, silicon.version, silicon.created_at, silicon.updated_at
    FROM iam.silicons silicon
    JOIN iam.organizations organization ON organization.id = silicon.organization_id
    JOIN iam.organization_memberships membership ON membership.organization_id = silicon.organization_id AND membership.id = silicon.membership_id
    JOIN hierarchy ON hierarchy.id = silicon.id
    LEFT JOIN iam.silicon_hooks hook ON hook.organization_id = silicon.organization_id AND hook.silicon_id = silicon.id
    WHERE silicon.organization_id = $1 AND membership.status = 'active' AND silicon.provisioning_status <> 'deleted'
      AND ($2::uuid IS NULL OR silicon.id > $2)
      AND ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM iam.membership_tags filter_tag
          WHERE filter_tag.organization_id = silicon.organization_id AND filter_tag.membership_id = silicon.membership_id AND filter_tag.tag_id = $4))
    ORDER BY silicon.id
    LIMIT $3
    "
);

const SILICON_BY_ID_SQL: &str = r"
    WITH RECURSIVE hierarchy AS (
        SELECT root.id, root.membership_id, root.reports_to_membership_id, 1::integer AS level
        FROM iam.silicons AS root
        WHERE root.organization_id = $1 AND root.reports_to_membership_id IS NULL
        UNION ALL
        SELECT child.id, child.membership_id, child.reports_to_membership_id, hierarchy.level + 1
        FROM iam.silicons AS child
        JOIN hierarchy ON child.reports_to_membership_id = hierarchy.membership_id
        WHERE child.organization_id = $1
    )
    SELECT silicon.id AS principal_id, silicon.membership_id,
           silicon.global_silicon_id AS silicon_id, silicon.local_silicon_id AS local_id,
           organization.org_id,
           COALESCE(silicon.profile_photo_override_uri,
                    $3 || '?id=' || silicon.global_silicon_id || '&level=' || hierarchy.level::text) AS profile_photo,
           membership.job_role, silicon.reports_to_membership_id,
           COALESCE((SELECT jsonb_agg(jsonb_build_object('id', tag.id, 'name', tag.name) ORDER BY tag.id)
                     FROM iam.membership_tags assignment
                     JOIN iam.organization_tags tag ON tag.organization_id = assignment.organization_id AND tag.id = assignment.tag_id
                     WHERE assignment.organization_id = silicon.organization_id AND assignment.membership_id = silicon.membership_id
                       AND tag.status = 'active'), '[]'::jsonb) AS tags,
           hierarchy.level AS hierarchy_level,
           CASE hook.status WHEN 'active' THEN 'active' WHEN 'failed' THEN 'error' WHEN 'disabled' THEN 'error' ELSE 'pending' END AS hook_status,
           CASE WHEN membership.status = 'active' AND silicon.provisioning_status <> 'deleted' THEN 'active' ELSE 'removed' END AS status,
           silicon.version, silicon.created_at, silicon.updated_at
    FROM iam.silicons silicon
    JOIN iam.organizations organization ON organization.id = silicon.organization_id
    JOIN iam.organization_memberships membership ON membership.organization_id = silicon.organization_id AND membership.id = silicon.membership_id
    JOIN hierarchy ON hierarchy.id = silicon.id
    LEFT JOIN iam.silicon_hooks hook ON hook.organization_id = silicon.organization_id AND hook.silicon_id = silicon.id
    WHERE silicon.organization_id = $1 AND silicon.global_silicon_id = $2
    LIMIT 1
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_silicon_ids_are_bound_to_the_route_organization() {
        assert!(validate_global_silicon_id("worker:acme", "acme").is_ok());
        assert!(matches!(
            validate_global_silicon_id("worker:other", "acme"),
            Err(AppError::NotFound)
        ));
        assert!(validate_global_silicon_id("worker", "acme").is_err());
    }
}
