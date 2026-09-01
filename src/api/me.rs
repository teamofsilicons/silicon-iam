//! Current Carbon profile and account-lifecycle endpoints.

use std::borrow::Cow;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    domain::actor::{ActorRef, ActorType},
    error::AppError,
    infrastructure::{
        crypto::{EncryptedValue, EncryptionContext, ProtectedField},
        postgres::{
            context::{self, DatabaseContext},
            events::{self, AggregateVersion, AuditRecord, OutboxRecord},
            idempotency::{
                self, IdempotencyClaim, IdempotencyKey, IdempotencyLease, IdempotencyRequest,
                ReplayResponse,
            },
            step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
        },
    },
};

use super::{ApiState, authentication::Authenticated};

const ME_ROUTE: &str = "/api/v1/me";
const DELETION_GRACE_DAYS: i64 = 30;

#[derive(Clone, Debug, Deserialize, FromRow, Serialize)]
pub(crate) struct CarbonProfileResponse {
    principal_id: Uuid,
    carbon_id: String,
    display_name: String,
    description: Option<String>,
    profile_photo: String,
    email: String,
    phone_number: String,
    status: String,
    pub(crate) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch must distinguish omitted fields from explicit null"
)]
pub(super) struct CarbonProfilePatch {
    display_name: Option<String>,
    #[serde(default, with = "serde_with::rust::double_option")]
    description: Option<Option<String>>,
    #[serde(default, with = "serde_with::rust::double_option")]
    profile_photo: Option<Option<String>>,
}

#[derive(FromRow)]
struct CarbonRow {
    principal_id: Uuid,
    carbon_id: String,
    display_name: String,
    description: Option<String>,
    profile_photo_uri: Option<String>,
    status: String,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct ContactRow {
    id: Uuid,
    kind: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
}

enum Claim {
    Acquired(IdempotencyLease),
    Replay(Response),
}

/// Returns the authenticated Carbon's current account including self-only contacts.
pub(super) async fn get(
    State(state): State<ApiState>,
    authenticated: Authenticated,
) -> Result<Response, AppError> {
    let carbon_id = require_self_service(&authenticated)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| internal("carbon_profile_context"))?;
    let profile = read_profile(&mut transaction, &state, carbon_id, false).await?;
    transaction
        .commit()
        .await
        .map_err(|_| internal("carbon_profile_commit"))?;
    json_with_etag(StatusCode::OK, &profile, profile.version)
}

#[allow(
    clippy::too_many_lines,
    reason = "profile validation, concurrency, idempotency, mutation, audit, and response are one compact self-service workflow"
)]
pub(super) async fn patch(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
    payload: Result<Json<CarbonProfilePatch>, JsonRejection>,
) -> Result<Response, AppError> {
    let carbon_id = require_self_service(&authenticated)?;
    let input = validate_patch(json_body(payload)?, &state)?;
    let expected_version = expected_version(&headers)?;
    let mut transaction = serializable(&state).await?;
    set_principal_context(&mut transaction, carbon_id).await?;
    let lease = match claim(&mut transaction, &state, &headers, &authenticated, &input).await? {
        Claim::Replay(response) => {
            transaction
                .commit()
                .await
                .map_err(|_| internal("carbon_profile_replay_commit"))?;
            return Ok(response);
        }
        Claim::Acquired(lease) => lease,
    };
    let before = read_profile(&mut transaction, &state, carbon_id, true).await?;
    if before.version != expected_version {
        return Err(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_mismatch"),
        });
    }
    let description_present = input.description.is_some();
    let description = input.description.as_ref().and_then(Clone::clone);
    let photo_present = input.profile_photo.is_some();
    let profile_photo = input.profile_photo.as_ref().and_then(Clone::clone);
    sqlx::query(
        r"
        UPDATE iam.carbons
        SET display_name = COALESCE($2, display_name),
            description = CASE WHEN $3 THEN $4 ELSE description END,
            profile_photo_uri = CASE WHEN $5 THEN $6 ELSE profile_photo_uri END
        WHERE id = $1 AND version = $7 AND deleted_at IS NULL
        ",
    )
    .bind(carbon_id)
    .bind(input.display_name.as_deref())
    .bind(description_present)
    .bind(description.as_deref())
    .bind(photo_present)
    .bind(profile_photo.as_deref())
    .bind(expected_version)
    .execute(&mut *transaction)
    .await
    .map_err(|_| internal("carbon_profile_update"))?;
    let after = read_profile(&mut transaction, &state, carbon_id, false).await?;
    if after.version != expected_version.saturating_add(1) {
        return Err(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_mismatch"),
        });
    }
    record_mutation(
        &mut transaction,
        &authenticated,
        "carbon.profile_update",
        "carbon.updated.v1",
        after.version,
        Some(json!({
            "display_name": before.display_name,
            "description": before.description,
            "profile_photo": before.profile_photo,
        })),
        Some(json!({
            "display_name": after.display_name,
            "description": after.description,
            "profile_photo": after.profile_photo,
        })),
    )
    .await?;
    let body = serde_json::to_vec(&after).map_err(|_| internal("carbon_profile_encode"))?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        lease,
        StatusCode::OK.as_u16(),
        &body,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| internal("carbon_profile_update_commit"))?;
    raw_json_with_etag(StatusCode::OK, body, after.version, false)
}

#[allow(
    clippy::too_many_lines,
    reason = "deletion atomically disables authority, revokes credentials, schedules bounded finalization, and emits security records"
)]
pub(super) async fn delete(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let carbon_id = require_self_service(&authenticated)?;
    let expected_version = expected_version(&headers)?;
    let mut transaction = serializable(&state).await?;
    set_principal_context(&mut transaction, carbon_id).await?;
    let lease = match claim(
        &mut transaction,
        &state,
        &headers,
        &authenticated,
        &json!({ "expected_version": expected_version }),
    )
    .await?
    {
        Claim::Replay(response) => {
            transaction
                .commit()
                .await
                .map_err(|_| internal("carbon_delete_replay_commit"))?;
            return Ok(response);
        }
        Claim::Acquired(lease) => lease,
    };
    consume_delete_step_up(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        carbon_id,
    )
    .await?;
    let before = read_profile(&mut transaction, &state, carbon_id, true).await?;
    if before.version != expected_version {
        return Err(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_mismatch"),
        });
    }
    enforce_deletion_preconditions(&mut transaction, carbon_id).await?;
    let request_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.account_deletion_requests (
            id, carbon_id, requested_from_session_id, scheduled_for
        ) VALUES (
            $1, $2, $3,
            transaction_timestamp() + ($4::bigint * interval '1 day')
        )
        ",
    )
    .bind(request_id)
    .bind(carbon_id)
    .bind(authenticated.0.authentication_session_id)
    .bind(DELETION_GRACE_DAYS)
    .execute(&mut *transaction)
    .await
    .map_err(|error| database_conflict(&error, "account_deletion_already_pending"))?;
    sqlx::query(
        r"
        UPDATE iam.principals
        SET status = 'deletion_pending', auth_epoch = auth_epoch + 1
        WHERE id = $1 AND kind = 'carbon' AND status = 'active'
        ",
    )
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| internal("carbon_delete_disable"))?;
    sqlx::query("UPDATE iam.carbons SET updated_at = transaction_timestamp() WHERE id = $1")
        .bind(carbon_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| internal("carbon_delete_version"))?;
    revoke_all_authority(&mut transaction, carbon_id).await?;
    let aggregate_version = expected_version.saturating_add(1);
    record_mutation(
        &mut transaction,
        &authenticated,
        "carbon.deletion_request",
        "carbon.deletion_requested.v1",
        aggregate_version,
        Some(json!({ "status": before.status })),
        Some(json!({ "status": "deletion_pending" })),
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        lease,
        StatusCode::ACCEPTED.as_u16(),
        &[],
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| account_deletion_commit_error(&error))?;
    Ok(StatusCode::ACCEPTED.into_response())
}

fn require_self_service(authenticated: &Authenticated) -> Result<Uuid, AppError> {
    let access = &authenticated.0;
    if access.subject.actor_type == ActorType::Carbon
        && access.audience == "silicon-iam"
        && access.client_application_id.is_none()
        && access.organization_id.is_none()
        && access.membership_id.is_none()
        && access.scopes.iter().any(|scope| scope == "iam.self")
    {
        Ok(access.subject.id)
    } else {
        Err(AppError::Forbidden)
    }
}

pub(crate) async fn read_profile(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    carbon_id: Uuid,
    lock: bool,
) -> Result<CarbonProfileResponse, AppError> {
    let sql = if lock {
        r"
        SELECT carbon.id AS principal_id, carbon.carbon_id, carbon.display_name,
               carbon.description, carbon.profile_photo_uri, principal.status,
               carbon.version, carbon.created_at, carbon.updated_at
        FROM iam.carbons AS carbon
        JOIN iam.principals AS principal
          ON principal.id = carbon.id AND principal.kind = 'carbon'
        WHERE carbon.id = $1 AND carbon.deleted_at IS NULL
        FOR UPDATE OF carbon, principal
        "
    } else {
        r"
        SELECT carbon.id AS principal_id, carbon.carbon_id, carbon.display_name,
               carbon.description, carbon.profile_photo_uri, principal.status,
               carbon.version, carbon.created_at, carbon.updated_at
        FROM iam.carbons AS carbon
        JOIN iam.principals AS principal
          ON principal.id = carbon.id AND principal.kind = 'carbon'
        WHERE carbon.id = $1 AND carbon.deleted_at IS NULL
        "
    };
    let carbon = sqlx::query_as::<_, CarbonRow>(sql)
        .bind(carbon_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| internal("carbon_profile_read"))?
        .ok_or(AppError::Unauthenticated)?;
    let contacts = sqlx::query_as::<_, ContactRow>(
        r"
        SELECT id, kind::text AS kind, ciphertext, nonce, encryption_key_version
        FROM iam.carbon_contacts
        WHERE carbon_id = $1 AND status = 'active' AND is_primary
        ORDER BY kind
        ",
    )
    .bind(carbon_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_profile_contacts"))?;
    let email = decrypt_contact(state, contacts.iter().find(|row| row.kind == "email"))?;
    let phone = decrypt_contact(state, contacts.iter().find(|row| row.kind == "phone"))?;
    let profile_photo = match carbon.profile_photo_uri {
        Some(value) => value,
        None => default_profile_photo(state, &carbon.carbon_id)?,
    };
    Ok(CarbonProfileResponse {
        principal_id: carbon.principal_id,
        carbon_id: carbon.carbon_id,
        display_name: carbon.display_name,
        description: carbon.description,
        profile_photo,
        email,
        phone_number: phone,
        status: match carbon.status.as_str() {
            "active" | "suspended" | "deletion_pending" => carbon.status,
            _ => return Err(internal("carbon_profile_status")),
        },
        version: carbon.version,
        created_at: carbon.created_at,
        updated_at: carbon.updated_at,
    })
}

fn decrypt_contact(state: &ApiState, row: Option<&ContactRow>) -> Result<String, AppError> {
    let row = row.ok_or_else(|| internal("carbon_profile_contact_invariant"))?;
    let field = match row.kind.as_str() {
        "email" => ProtectedField::CarbonEmail,
        "phone" => ProtectedField::CarbonPhone,
        _ => return Err(internal("carbon_profile_contact_kind")),
    };
    let nonce: [u8; 12] = row
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| internal("carbon_profile_contact_nonce"))?;
    let plaintext = state
        .crypto
        .decrypt(
            EncryptionContext::global(field, row.id),
            &EncryptedValue {
                key_version: row.encryption_key_version,
                nonce,
                ciphertext: row.ciphertext.clone(),
            },
        )
        .map_err(|_| internal("carbon_profile_contact_decrypt"))?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| internal("carbon_profile_contact_plaintext"))
}

fn default_profile_photo(state: &ApiState, carbon_id: &str) -> Result<String, AppError> {
    let mut url = state
        .settings
        .providers
        .iris_base_url
        .join("pfp/carbon")
        .map_err(|_| internal("carbon_profile_photo_url"))?;
    url.query_pairs_mut().append_pair("id", carbon_id);
    Ok(url.to_string())
}

fn validate_patch(
    mut input: CarbonProfilePatch,
    state: &ApiState,
) -> Result<CarbonProfilePatch, AppError> {
    if input.display_name.is_none() && input.description.is_none() && input.profile_photo.is_none()
    {
        return Err(validation(
            "body",
            "must contain at least one profile field",
        ));
    }
    if let Some(value) = input.display_name.take() {
        input.display_name = Some(bounded_text("display_name", value, 1, 200, false)?);
    }
    if let Some(Some(value)) = input.description.take() {
        input.description = Some(Some(bounded_text("description", value, 0, 5_000, true)?));
    }
    if let Some(Some(value)) = input.profile_photo.take() {
        input.profile_photo = Some(Some(validate_profile_photo(
            &value,
            state.settings.environment == crate::config::RuntimeEnvironment::Production,
        )?));
    }
    Ok(input)
}

fn bounded_text(
    field: &'static str,
    value: String,
    minimum: usize,
    maximum: usize,
    allow_blank: bool,
) -> Result<String, AppError> {
    let length = value.chars().count();
    if !(minimum..=maximum).contains(&length)
        || value.chars().any(char::is_control)
        || (!allow_blank && value.trim().is_empty())
    {
        Err(validation(field, "has an invalid length or characters"))
    } else {
        Ok(value)
    }
}

fn validate_profile_photo(value: &str, production: bool) -> Result<String, AppError> {
    if value.len() > 2_048 {
        return Err(validation("profile_photo", "must be a safe HTTP URL"));
    }
    let url =
        Url::parse(value).map_err(|_| validation("profile_photo", "must be a safe HTTP URL"))?;
    let valid_scheme = if production {
        url.scheme() == "https"
    } else {
        matches!(url.scheme(), "http" | "https")
    };
    if !valid_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(validation("profile_photo", "must be a safe HTTP URL"));
    }
    Ok(url.to_string())
}

pub(crate) fn expected_version(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::PreconditionRequired {
            code: Cow::Borrowed("if_match_required"),
        })?;
    if raw.starts_with("W/") || raw.contains(',') {
        return Err(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_invalid"),
        });
    }
    raw.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_invalid"),
        })
}

async fn serializable(state: &ApiState) -> Result<Transaction<'_, Postgres>, AppError> {
    let mut transaction = state
        .pool
        .begin()
        .await
        .map_err(|_| internal("carbon_account_transaction"))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await
        .map_err(|_| internal("carbon_account_transaction"))?;
    Ok(transaction)
}

async fn set_principal_context(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT set_config('iam.principal_id', $1, true)")
        .bind(carbon_id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(|_| internal("carbon_account_context"))?;
    Ok(())
}

async fn claim<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    headers: &HeaderMap,
    authenticated: &Authenticated,
    request: &T,
) -> Result<Claim, AppError> {
    let raw = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::PreconditionRequired {
            code: Cow::Borrowed("idempotency_key_required"),
        })?;
    let key = IdempotencyKey::parse(raw).map_err(|_| {
        validation(
            "Idempotency-Key",
            "must contain 16 to 255 visible ASCII characters",
        )
    })?;
    let caller = SecretString::from(format!("carbon:{}", authenticated.0.subject.id));
    let payload = SecretString::from(
        serde_json::to_string(request).map_err(|_| internal("carbon_account_request_encode"))?,
    );
    match idempotency::claim(
        transaction,
        &state.crypto,
        IdempotencyRequest {
            route: ME_ROUTE,
            caller_scope: &caller,
            key: &key,
            request_payload: &payload,
            contains_one_time_secret: false,
        },
    )
    .await?
    {
        IdempotencyClaim::Acquired(lease) => Ok(Claim::Acquired(lease)),
        IdempotencyClaim::Replay(replay) => Ok(Claim::Replay(replay_response(replay)?)),
    }
}

fn replay_response(replay: ReplayResponse) -> Result<Response, AppError> {
    let status = StatusCode::from_u16(replay.status)
        .map_err(|_| internal("carbon_account_replay_status"))?;
    if replay.body.is_empty() {
        return Ok(status.into_response());
    }
    let version = serde_json::from_slice::<serde_json::Value>(&replay.body)
        .ok()
        .and_then(|value| value.get("version").and_then(serde_json::Value::as_i64))
        .ok_or_else(|| internal("carbon_account_replay_version"))?;
    raw_json_with_etag(status, replay.body, version, true)
}

async fn consume_delete_step_up(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    carbon_id: Uuid,
) -> Result<(), AppError> {
    let raw = headers
        .get("x-step-up-token")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::PreconditionRequired {
            code: Cow::Borrowed("step_up_required"),
        })?;
    let token = StepUpToken::parse(raw).map_err(|_| AppError::PreconditionFailed {
        code: Cow::Borrowed("step_up_invalid"),
    })?;
    step_up::consume(
        transaction,
        &state.crypto,
        &token,
        StepUpExpectation {
            carbon_id,
            authentication_session_id: authenticated.0.authentication_session_id,
            action: "account.delete",
            resource_id: Some(carbon_id),
            required_assurance: RequiredAssurance::PhishingResistant,
        },
    )
    .await
    .map(|_| ())
}

async fn enforce_deletion_preconditions(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
) -> Result<(), AppError> {
    let owns_organization = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM iam.organizations AS organization
            LEFT JOIN iam.organization_memberships AS membership
              ON membership.organization_id = organization.id
             AND membership.principal_id = $1
             AND membership.principal_kind = 'carbon'
             AND membership.org_role = 'owner'
             AND membership.status = 'active'
            WHERE organization.status = 'active'
              AND (organization.created_by_carbon_id = $1 OR membership.id IS NOT NULL)
        )
        ",
    )
    .bind(carbon_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_delete_ownership_check"))?;
    if owns_organization {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("organization_ownership_transfer_required"),
        });
    }
    let owns_application = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1 FROM iam.applications
            WHERE owner_carbon_id = $1
              AND review_status NOT IN ('deleted', 'rejected')
              AND deleted_at IS NULL
        )
        ",
    )
    .bind(carbon_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_delete_application_ownership_check"))?;
    if owns_application {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("application_ownership_transfer_required"),
        });
    }
    let is_last_platform_administrator = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM iam.platform_role_grants AS own_grant
            WHERE own_grant.carbon_id = $1
              AND own_grant.role = 'platform_administrator'
              AND own_grant.revoked_at IS NULL
        ) AND NOT EXISTS (
            SELECT 1
            FROM iam.platform_role_grants AS other_grant
            JOIN iam.principals AS other_principal
              ON other_principal.id = other_grant.carbon_id
             AND other_principal.kind = 'carbon'
             AND other_principal.status = 'active'
            WHERE other_grant.carbon_id <> $1
              AND other_grant.role = 'platform_administrator'
              AND other_grant.revoked_at IS NULL
        )
        ",
    )
    .bind(carbon_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_delete_last_platform_administrator_check"))?;
    if is_last_platform_administrator {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("last_platform_administrator"),
        });
    }
    let has_platform_role = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM iam.platform_role_grants WHERE carbon_id = $1 AND revoked_at IS NULL)",
    )
    .bind(carbon_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_delete_platform_role_check"))?;
    if has_platform_role {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("platform_role_revocation_required"),
        });
    }
    Ok(())
}

async fn revoke_all_authority(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.authentication_sessions
        SET status = 'revoked', revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = 'account_deletion_requested', version = version + 1
        WHERE subject_principal_id = $1 AND status = 'active'
        ",
    )
    .bind(carbon_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_delete_sessions_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'revoked', revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = 'account_deletion_requested'
        WHERE subject_principal_id = $1 AND status = 'active'
        ",
    )
    .bind(carbon_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_delete_refresh_families_revoke"))?;
    sqlx::query(
        "UPDATE iam.refresh_tokens SET revoked_at = COALESCE(revoked_at, transaction_timestamp()) WHERE family_id IN (SELECT id FROM iam.refresh_token_families WHERE subject_principal_id = $1)",
    )
    .bind(carbon_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_delete_refresh_tokens_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.access_tokens
        SET revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = COALESCE(revocation_reason, 'account_deletion_requested')
        WHERE subject_principal_id = $1 AND revoked_at IS NULL
        ",
    )
    .bind(carbon_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_delete_access_tokens_revoke"))?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "audit and outbox share one explicit aggregate transition"
)]
async fn record_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    action: &'static str,
    event_type: &'static str,
    version: i64,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
) -> Result<(), AppError> {
    let aggregate = AggregateVersion {
        aggregate_type: "carbon",
        aggregate_id: authenticated.0.subject.id,
        version,
    };
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: ActorType::Carbon,
                id: authenticated.0.subject.id,
            }),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: None,
            application_id: None,
            action,
            target_type: "carbon",
            target_id: Some(authenticated.0.subject.id),
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state: before,
            after_state: after,
            metadata: json!({}),
        },
    )
    .await
    .map_err(|_| internal("carbon_account_audit"))?;
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: None,
            aggregate,
            event_ordinal: 1,
            event_type,
            schema_version: 1,
            payload: json!({ "carbon_id": authenticated.0.subject.id }),
        },
    )
    .await
    .map_err(|_| internal("carbon_account_outbox"))?;
    Ok(())
}

fn json_with_etag<T: Serialize>(
    status: StatusCode,
    value: &T,
    version: i64,
) -> Result<Response, AppError> {
    let body = serde_json::to_vec(value).map_err(|_| internal("carbon_profile_encode"))?;
    raw_json_with_etag(status, body, version, false)
}

fn raw_json_with_etag(
    status: StatusCode,
    body: Vec<u8>,
    version: i64,
    replayed: bool,
) -> Result<Response, AppError> {
    let etag = HeaderValue::from_str(&format!("\"{version}\""))
        .map_err(|_| internal("carbon_profile_etag"))?;
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ETAG, etag)
        .body(axum::body::Body::from(body))
        .map_err(|_| internal("carbon_profile_response"))?;
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    Ok(response)
}

fn json_body<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, AppError> {
    payload
        .map(|Json(value)| value)
        .map_err(|_| validation("body", "must be valid JSON matching the schema"))
}

fn validation(field: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: json!({ "fields": [{ "field": field, "message": message }] }),
    }
}

fn database_conflict(error: &sqlx::Error, code: &'static str) -> AppError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|value| matches!(value.as_ref(), "23505" | "40001" | "40P01"))
    {
        AppError::Conflict {
            code: Cow::Borrowed(code),
        }
    } else {
        internal("carbon_account_database")
    }
}

fn account_deletion_commit_error(error: &sqlx::Error) -> AppError {
    if let Some(database_error) = error.as_database_error()
        && database_error.code().as_deref() == Some("23514")
    {
        let message = database_error.message();
        if message.contains("final active platform administrator") {
            return AppError::Conflict {
                code: Cow::Borrowed("last_platform_administrator"),
            };
        }
        if message.contains("must have exactly one active owner") {
            return AppError::Conflict {
                code: Cow::Borrowed("organization_ownership_transfer_required"),
            };
        }
    }
    database_conflict(error, "account_deletion_conflict")
}

const fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{bounded_text, expected_version};

    #[test]
    fn profile_text_rejects_controls_and_blank_display_names() {
        assert!(bounded_text("display_name", "Carbon".to_owned(), 1, 200, false).is_ok());
        assert!(bounded_text("display_name", "  ".to_owned(), 1, 200, false).is_err());
        assert!(bounded_text("description", "bad\ntext".to_owned(), 0, 5_000, true).is_err());
    }

    #[test]
    fn profile_etag_is_one_strong_positive_version() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"4\""));
        assert_eq!(expected_version(&headers).ok(), Some(4));
        headers.insert(header::IF_MATCH, HeaderValue::from_static("W/\"4\""));
        assert!(expected_version(&headers).is_err());
    }
}
