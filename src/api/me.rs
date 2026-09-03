//! Current Carbon profile and account-lifecycle endpoints.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

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
    features::organizations::{
        capture_carbon_profile_silicon_routes, enqueue_carbon_profile_silicon_events,
    },
    infrastructure::{
        crypto::{CryptoService, EncryptedValue, EncryptionContext, ProtectedField},
        postgres::{
            context::{self, DatabaseContext},
            events::{self, AggregateVersion, AuditRecord, OutboxRecord},
            idempotency::{
                self, IdempotencyClaim, IdempotencyKey, IdempotencyLease, IdempotencyRequest,
                ReplayResponse,
            },
        },
    },
};

use super::{ApiState, authentication::Authenticated};

const ME_ROUTE: &str = "PATCH /api/v1/me";

#[derive(Clone, Debug, Deserialize, FromRow, Serialize)]
pub(crate) struct CarbonProfileResponse {
    principal_id: Uuid,
    carbon_id: String,
    display_name: String,
    timezone: String,
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
    timezone: Option<String>,
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
    timezone: String,
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
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
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
    let expected_version = expected_version(&headers)?;
    let before = read_profile(&mut transaction, &state, carbon_id, true).await?;
    if before.version != expected_version {
        return Err(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_mismatch"),
        });
    }
    let authorizations_before = profile_webhook_authorizations(&mut transaction, carbon_id).await?;
    let silicon_routes = capture_carbon_profile_silicon_routes(&mut transaction, carbon_id).await?;
    let description_present = input.description.is_some();
    let description = input.description.as_ref().and_then(Clone::clone);
    let photo_present = input.profile_photo.is_some();
    let profile_photo = input.profile_photo.as_ref().and_then(Clone::clone);
    sqlx::query(
        r"
        UPDATE iam.carbons
        SET display_name = COALESCE($2, display_name),
            timezone_id = COALESCE($3, timezone_id),
            description = CASE WHEN $4 THEN $5 ELSE description END,
            profile_photo_uri = CASE WHEN $6 THEN $7 ELSE profile_photo_uri END
        WHERE id = $1 AND version = $8 AND deleted_at IS NULL
        ",
    )
    .bind(carbon_id)
    .bind(input.display_name.as_deref())
    .bind(input.timezone.as_deref())
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
    let authorizations_after = profile_webhook_authorizations(&mut transaction, carbon_id).await?;
    let outbox_event_id = record_mutation(
        &mut transaction,
        &authenticated,
        "carbon.profile_update",
        "carbon.updated.v1",
        after.version,
        Some(json!({
            "display_name": before.display_name,
            "timezone": before.timezone,
            "description": before.description,
            "profile_photo": before.profile_photo,
        })),
        Some(json!({
            "display_name": after.display_name,
            "timezone": after.timezone,
            "description": after.description,
            "profile_photo": after.profile_photo,
        })),
    )
    .await?;
    capture_profile_webhook_projections(
        &mut transaction,
        &state.crypto,
        outbox_event_id,
        &before,
        &after,
        &authorizations_before,
        &authorizations_after,
    )
    .await?;
    let before_profile = serde_json::to_value(&before)
        .map_err(|_| internal("carbon_profile_silicon_webhook_encode"))?;
    let after_profile = serde_json::to_value(&after)
        .map_err(|_| internal("carbon_profile_silicon_webhook_encode"))?;
    enqueue_carbon_profile_silicon_events(
        &mut transaction,
        after.version,
        &changed_profile_fields(&before, &after),
        &before_profile,
        &after_profile,
        &silicon_routes,
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
               carbon.timezone_id AS timezone,
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
               carbon.timezone_id AS timezone,
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
        timezone: carbon.timezone,
        description: carbon.description,
        profile_photo,
        email,
        phone_number: phone,
        status: match carbon.status.as_str() {
            "active" | "suspended" => carbon.status,
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
    if input.display_name.is_none()
        && input.timezone.is_none()
        && input.description.is_none()
        && input.profile_photo.is_none()
    {
        return Err(validation(
            "body",
            "must contain at least one profile field",
        ));
    }
    if let Some(value) = input.display_name.take() {
        input.display_name = Some(bounded_text("display_name", value, 1, 200, false)?);
    }
    if input
        .timezone
        .as_deref()
        .is_some_and(|value| !crate::domain::timezone::is_valid_identifier(value))
    {
        return Err(validation("timezone", "must be a valid IANA TZ identifier"));
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
) -> Result<Uuid, AppError> {
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
    let outbox_event_id = events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: None,
            aggregate,
            event_ordinal: 1,
            event_type,
            schema_version: 1,
            payload: json!({ "carbon_id": authenticated.0.subject.id }),
            silicon_webhook_routing: None,
        },
    )
    .await
    .map_err(|_| internal("carbon_account_outbox"))?;
    Ok(outbox_event_id)
}

async fn profile_webhook_authorizations(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
) -> Result<BTreeMap<Uuid, BTreeSet<String>>, AppError> {
    let rows = sqlx::query_as::<_, (Uuid, String)>(
        r"
        SELECT application_id, scope
        FROM iam_private.list_profile_webhook_authorization_scopes($1)
        ",
    )
    .bind(carbon_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| internal("carbon_profile_webhook_authorizations"))?;
    let mut authorizations = BTreeMap::<Uuid, BTreeSet<String>>::new();
    for (application_id, scope) in rows {
        authorizations
            .entry(application_id)
            .or_default()
            .insert(scope);
    }
    Ok(authorizations)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the two authorization snapshots and exact profile versions define one immutable delivery projection"
)]
async fn capture_profile_webhook_projections(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    outbox_event_id: Uuid,
    before: &CarbonProfileResponse,
    after: &CarbonProfileResponse,
    authorizations_before: &BTreeMap<Uuid, BTreeSet<String>>,
    authorizations_after: &BTreeMap<Uuid, BTreeSet<String>>,
) -> Result<(), AppError> {
    let recipient_application_ids =
        profile_webhook_recipient_application_ids(authorizations_before, authorizations_after);
    for application_id in recipient_application_ids {
        let effective_scopes = authorizations_after
            .get(&application_id)
            .cloned()
            .unwrap_or_default();
        let payload = profile_webhook_payload(before, after, &effective_scopes)?;
        let plaintext =
            serde_json::to_vec(&payload).map_err(|_| internal("carbon_profile_webhook_encode"))?;
        let projection_id = Uuid::now_v7();
        let encrypted = crypto
            .encrypt(
                EncryptionContext::tenant(
                    ProtectedField::ApplicationWebhookEventPayload,
                    application_id,
                    projection_id,
                ),
                &plaintext,
            )
            .map_err(|_| internal("carbon_profile_webhook_encrypt"))?;
        sqlx::query(
            r"
            INSERT INTO iam.application_webhook_event_projections (
                id, outbox_event_id, application_id,
                payload_ciphertext, payload_nonce, encryption_key_version
            ) VALUES ($1, $2, $3, $4, $5, $6)
            ",
        )
        .bind(projection_id)
        .bind(outbox_event_id)
        .bind(application_id)
        .bind(encrypted.ciphertext)
        .bind(encrypted.nonce.as_slice())
        .bind(encrypted.key_version)
        .execute(&mut **transaction)
        .await
        .map_err(|_| internal("carbon_profile_webhook_projection_insert"))?;
    }
    Ok(())
}

fn profile_webhook_recipient_application_ids(
    authorizations_before: &BTreeMap<Uuid, BTreeSet<String>>,
    authorizations_after: &BTreeMap<Uuid, BTreeSet<String>>,
) -> BTreeSet<Uuid> {
    authorizations_before
        .keys()
        .chain(authorizations_after.keys())
        .copied()
        .collect()
}

fn profile_webhook_payload(
    before: &CarbonProfileResponse,
    after: &CarbonProfileResponse,
    effective_scopes: &BTreeSet<String>,
) -> Result<serde_json::Value, AppError> {
    let serialized =
        serde_json::to_value(after).map_err(|_| internal("carbon_profile_webhook_projection"))?;
    let source = serialized
        .as_object()
        .ok_or_else(|| internal("carbon_profile_webhook_projection"))?;
    let mut current = serde_json::Map::new();
    for field in ["principal_id", "version"] {
        if let Some(value) = source.get(field) {
            current.insert(field.to_owned(), value.clone());
        }
    }

    let has_profile = effective_scopes.contains("profile");
    if has_profile {
        for field in [
            "carbon_id",
            "display_name",
            "timezone",
            "description",
            "profile_photo",
            "status",
            "created_at",
            "updated_at",
        ] {
            if let Some(value) = source.get(field) {
                current.insert(field.to_owned(), value.clone());
            }
        }
    }
    if effective_scopes.contains("email")
        && let Some(value) = source.get("email")
    {
        current.insert("email".to_owned(), value.clone());
    }
    if effective_scopes.contains("phone")
        && let Some(value) = source.get("phone_number")
    {
        current.insert("phone_number".to_owned(), value.clone());
    }

    let changed_fields = if has_profile {
        changed_profile_fields(before, after)
    } else {
        Vec::new()
    };

    Ok(json!({
        "changed_fields": changed_fields,
        "current": current,
    }))
}

fn changed_profile_fields(
    before: &CarbonProfileResponse,
    after: &CarbonProfileResponse,
) -> Vec<&'static str> {
    let mut changed_fields = Vec::new();
    if before.display_name != after.display_name {
        changed_fields.push("display_name");
    }
    if before.timezone != after.timezone {
        changed_fields.push("timezone");
    }
    if before.description != after.description {
        changed_fields.push("description");
    }
    if before.profile_photo != after.profile_photo {
        changed_fields.push("profile_photo");
    }
    changed_fields
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
        .map_err(|rejection| AppError::from_json_rejection(&rejection))
}

fn validation(field: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: json!({ "fields": [{ "field": field, "message": message }] }),
    }
}

const fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use anyhow::{Context as _, ensure};
    use axum::http::{HeaderMap, HeaderValue, header};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use secrecy::SecretString;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres as TestPostgres;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::{
        config::{KeyringSettings, SecuritySettings},
        infrastructure::{
            crypto::{CryptoService, EncryptedValue, EncryptionContext, ProtectedField},
            postgres,
        },
    };

    use super::{
        CarbonProfileResponse, bounded_text, capture_carbon_profile_silicon_routes,
        capture_profile_webhook_projections, changed_profile_fields,
        enqueue_carbon_profile_silicon_events, expected_version, profile_webhook_authorizations,
        profile_webhook_payload, profile_webhook_recipient_application_ids,
    };

    fn profile(version: i64, display_name: &str, email: &str) -> CarbonProfileResponse {
        CarbonProfileResponse {
            principal_id: Uuid::from_u128(1),
            carbon_id: "carbon-one".to_owned(),
            display_name: display_name.to_owned(),
            timezone: "UTC".to_owned(),
            description: Some("Platform engineer".to_owned()),
            profile_photo: "https://iris.example/pfp/carbon?id=carbon-one".to_owned(),
            email: email.to_owned(),
            phone_number: "+15555550100".to_owned(),
            status: "active".to_owned(),
            version,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn projection_crypto() -> Result<CryptoService, crate::infrastructure::crypto::CryptoError> {
        let key = URL_SAFE_NO_PAD.encode([17_u8; 32]);
        let keyring = || KeyringSettings {
            current_version: 1,
            keys: BTreeMap::from([(1, SecretString::from(key.clone()))]),
        };
        CryptoService::from_settings(&SecuritySettings {
            token_peppers: keyring(),
            blind_index_keys: keyring(),
            encryption_keys: keyring(),
            cookie_key: SecretString::from(key),
            access_token_ttl: std::time::Duration::from_mins(30),
            refresh_family_ttl: std::time::Duration::from_hours(21_600),
            authorization_code_ttl: std::time::Duration::from_secs(120),
            otp_ttl: std::time::Duration::from_secs(600),
            otp_max_attempts: 10,
        })
    }

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

    #[test]
    fn webhook_projection_discloses_only_effectively_scoped_fields() {
        let before = profile(4, "Before", "before@example.test");
        let after = profile(5, "After", "after@example.test");

        let Ok(unscoped) = profile_webhook_payload(
            &before,
            &after,
            &BTreeSet::from(["organizations.read".to_owned()]),
        ) else {
            panic!("valid profiles must project");
        };
        let Some(unscoped_current) = unscoped["current"].as_object() else {
            panic!("current state must be an object");
        };
        assert_eq!(unscoped["changed_fields"], serde_json::json!([]));
        assert_eq!(unscoped_current.len(), 2);
        assert!(unscoped_current.contains_key("principal_id"));
        assert!(unscoped_current.contains_key("version"));
        for forbidden in [
            "carbon_id",
            "display_name",
            "timezone",
            "description",
            "profile_photo",
            "email",
            "phone_number",
        ] {
            assert!(!unscoped_current.contains_key(forbidden));
        }

        let Ok(profile_and_email) = profile_webhook_payload(
            &before,
            &after,
            &BTreeSet::from(["profile".to_owned(), "email".to_owned()]),
        ) else {
            panic!("valid profiles must project");
        };
        assert_eq!(
            profile_and_email["changed_fields"],
            serde_json::json!(["display_name"])
        );
        assert_eq!(profile_and_email["current"]["display_name"], "After");
        assert_eq!(profile_and_email["current"]["email"], "after@example.test");
        assert!(profile_and_email["current"].get("phone_number").is_none());
    }

    #[test]
    fn webhook_projection_is_a_frozen_version_and_routes_before_only_grants() {
        let before = profile(7, "Before", "before@example.test");
        let mut after = profile(8, "Captured", "captured@example.test");
        let Ok(payload) = profile_webhook_payload(
            &before,
            &after,
            &BTreeSet::from(["profile".to_owned(), "email".to_owned()]),
        ) else {
            panic!("valid profiles must project");
        };
        after.display_name = "Later".to_owned();
        after.email = "later@example.test".to_owned();
        after.version = 9;
        assert_eq!(payload["current"]["display_name"], "Captured");
        assert_eq!(payload["current"]["email"], "captured@example.test");
        assert_eq!(payload["current"]["version"], 8);

        let before_only_application = Uuid::from_u128(2);
        let after_only_application = Uuid::from_u128(3);
        let before_authorizations = BTreeMap::from([(
            before_only_application,
            BTreeSet::from(["profile".to_owned()]),
        )]);
        let after_authorizations =
            BTreeMap::from([(after_only_application, BTreeSet::from(["email".to_owned()]))]);
        assert_eq!(
            profile_webhook_recipient_application_ids(
                &before_authorizations,
                &after_authorizations,
            ),
            BTreeSet::from([before_only_application, after_only_application])
        );
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    #[allow(
        clippy::too_many_lines,
        reason = "the isolated live fixture, transaction, ciphertext inspection, and assertions form one end-to-end invariant test"
    )]
    async fn live_profile_projection_freezes_scoped_state_and_before_only_recipient()
    -> anyhow::Result<()> {
        let container = TestPostgres::default()
            .with_tag("16-alpine")
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        postgres::migrate(&pool).await?;

        let carbon_id = Uuid::from_u128(0x301);
        let retained_application_id = Uuid::from_u128(0x302);
        let before_only_application_id = Uuid::from_u128(0x303);
        let session_id = Uuid::from_u128(0x304);
        let retained_consent_id = Uuid::from_u128(0x305);
        let before_only_consent_id = Uuid::from_u128(0x306);
        let organization_id = Uuid::from_u128(0x320);
        let carbon_membership_id = Uuid::from_u128(0x321);
        let shared_tag_id = Uuid::from_u128(0x322);
        let silicon_id = Uuid::from_u128(0x323);
        let silicon_membership_id = Uuid::from_u128(0x324);
        let silicon_endpoint_id = Uuid::from_u128(0x325);
        let silicon_signing_key_id = Uuid::from_u128(0x326);
        let silicon_subscription_id = Uuid::from_u128(0x327);
        let full_silicon_id = Uuid::from_u128(0x328);
        let full_silicon_membership_id = Uuid::from_u128(0x329);
        let full_silicon_endpoint_id = Uuid::from_u128(0x32a);
        let full_silicon_signing_key_id = Uuid::from_u128(0x32b);
        let full_silicon_subscription_id = Uuid::from_u128(0x32c);
        sqlx::query(
            r"
            INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status)
            VALUES ('contact_aead', 1, 'active');
            ",
        )
        .execute(&pool)
        .await?;
        let seed_sql = format!(
            r"
            BEGIN;
            INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
              ('{carbon_id}', 'carbon', 'active', transaction_timestamp()),
              ('{retained_application_id}', 'application', 'active', transaction_timestamp()),
              ('{before_only_application_id}', 'application', 'active', transaction_timestamp()),
              ('{silicon_id}', 'silicon', 'active', transaction_timestamp()),
              ('{full_silicon_id}', 'silicon', 'active', transaction_timestamp());
            INSERT INTO iam.carbons (id, carbon_id, display_name)
            VALUES ('{carbon_id}', 'projection-carbon', 'Captured');
            INSERT INTO iam.carbon_contacts (
                id, carbon_id, kind, ciphertext, nonce, encryption_key_version, verified_at
            ) VALUES
              ('00000000-0000-0000-0000-000000000311', '{carbon_id}', 'email',
               decode(repeat('11', 17), 'hex'), decode(repeat('12', 12), 'hex'), 1,
               transaction_timestamp()),
              ('00000000-0000-0000-0000-000000000312', '{carbon_id}', 'phone',
               decode(repeat('13', 17), 'hex'), decode(repeat('14', 12), 'hex'), 1,
               transaction_timestamp());
            INSERT INTO iam.authentication_sessions (
                id, subject_principal_id, subject_kind, authentication_method,
                subject_auth_epoch, idle_expires_at, absolute_expires_at
            ) VALUES (
                '{session_id}', '{carbon_id}', 'carbon', 'email_otp', 1,
                transaction_timestamp() + interval '1 day',
                transaction_timestamp() + interval '2 days'
            );
            INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
            VALUES ('{organization_id}', 'projection-org', '{carbon_id}', 'Projection Org');
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role, job_role
            ) VALUES
              ('{carbon_membership_id}', '{organization_id}', '{carbon_id}', 'carbon',
               'owner', 'Platform engineer'),
              ('{silicon_membership_id}', '{organization_id}', '{silicon_id}', 'silicon',
               'member', 'Profile subscriber'),
              ('{full_silicon_membership_id}', '{organization_id}', '{full_silicon_id}',
               'silicon', 'member', 'Full subscriber');
            INSERT INTO iam.applications (
                id, app_id, organization_id, created_by_carbon_id, review_status
            ) VALUES
              ('{retained_application_id}', 'projection-retained', '{organization_id}',
               '{carbon_id}', 'verified'),
              ('{before_only_application_id}', 'projection-before', '{organization_id}',
               '{carbon_id}', 'verified');
            INSERT INTO iam.application_requested_scopes (application_id, scope) VALUES
              ('{retained_application_id}', 'profile'),
              ('{retained_application_id}', 'email'),
              ('{before_only_application_id}', 'phone');
            INSERT INTO iam.application_approved_scopes (
                application_id, scope, approved_by_carbon_id
            ) VALUES
              ('{retained_application_id}', 'profile', '{carbon_id}'),
              ('{retained_application_id}', 'email', '{carbon_id}'),
              ('{before_only_application_id}', 'phone', '{carbon_id}');
            INSERT INTO iam.oauth_consent_grants (
                id, application_id, subject_principal_id, subject_kind,
                parent_authentication_session_id
            ) VALUES
              ('{retained_consent_id}', '{retained_application_id}', '{carbon_id}', 'carbon',
               '{session_id}'),
              ('{before_only_consent_id}', '{before_only_application_id}', '{carbon_id}', 'carbon',
               '{session_id}');
            INSERT INTO iam.oauth_consent_grant_scopes (consent_grant_id, scope) VALUES
              ('{retained_consent_id}', 'profile'),
              ('{retained_consent_id}', 'email'),
              ('{before_only_consent_id}', 'phone');
            INSERT INTO iam.carbon_membership_settings (
                organization_id, membership_id, carbon_id
            ) VALUES ('{organization_id}', '{carbon_membership_id}', '{carbon_id}');
            INSERT INTO iam.silicons (
                id, organization_id, membership_id, organization_handle,
                silicon_handle, display_name, provisioning_status
            ) VALUES
              (
                '{silicon_id}', '{organization_id}', '{silicon_membership_id}',
                'projection-org', 'subscriber', 'Profile subscriber', 'active'
              ),
              (
                '{full_silicon_id}', '{organization_id}', '{full_silicon_membership_id}',
                'projection-org', 'full-subscriber', 'Full subscriber', 'active'
              );
            INSERT INTO iam.organization_tags (
                id, organization_id, name, normalized_name, created_by_membership_id
            ) VALUES (
                '{shared_tag_id}', '{organization_id}', 'Engineering', 'engineering',
                '{carbon_membership_id}'
            );
            INSERT INTO iam.membership_tags (
                organization_id, membership_id, tag_id, assigned_by_membership_id
            ) VALUES
              ('{organization_id}', '{carbon_membership_id}', '{shared_tag_id}',
               '{carbon_membership_id}'),
              ('{organization_id}', '{silicon_membership_id}', '{shared_tag_id}',
               '{carbon_membership_id}');
            INSERT INTO iam.silicon_webhook_endpoints (
                id, organization_id, silicon_id, url_ciphertext, url_nonce,
                encryption_key_version, url_digest
            ) VALUES
              (
                '{silicon_endpoint_id}', '{organization_id}', '{silicon_id}',
                decode(repeat('21', 17), 'hex'), decode(repeat('22', 12), 'hex'), 1,
                decode(repeat('23', 32), 'hex')
              ),
              (
                '{full_silicon_endpoint_id}', '{organization_id}', '{full_silicon_id}',
                decode(repeat('26', 17), 'hex'), decode(repeat('27', 12), 'hex'), 1,
                decode(repeat('28', 32), 'hex')
              );
            INSERT INTO iam.silicon_webhook_signing_keys (
                id, organization_id, silicon_id, endpoint_id, secret_version,
                key_prefix, secret_ciphertext, secret_nonce, encryption_key_version
            ) VALUES
              (
                '{silicon_signing_key_id}', '{organization_id}', '{silicon_id}',
                '{silicon_endpoint_id}', 1, 'swhs_1234567',
                decode(repeat('24', 17), 'hex'), decode(repeat('25', 12), 'hex'), 1
              ),
              (
                '{full_silicon_signing_key_id}', '{organization_id}', '{full_silicon_id}',
                '{full_silicon_endpoint_id}', 1, 'swhs_7654321',
                decode(repeat('29', 17), 'hex'), decode(repeat('2a', 12), 'hex'), 1
              );
            INSERT INTO iam.silicon_webhook_subscriptions (
                id, organization_id, silicon_id, endpoint_id, mode, tag_filter_enabled
            ) VALUES
              (
                '{silicon_subscription_id}', '{organization_id}', '{silicon_id}',
                '{silicon_endpoint_id}', 'selected', true
              ),
              (
                '{full_silicon_subscription_id}', '{organization_id}', '{full_silicon_id}',
                '{full_silicon_endpoint_id}', 'all', false
              );
            INSERT INTO iam.silicon_webhook_subscription_topics (subscription_id, topic)
            VALUES ('{silicon_subscription_id}', 'member_updates');
            COMMIT;
            "
        );
        // Every interpolated value above is a test-owned UUID rendered by
        // `Uuid::Display`; no external input can enter this fixture statement.
        sqlx::raw_sql(sqlx::AssertSqlSafe(seed_sql))
            .execute(&pool)
            .await
            .context("seed profile projection live test")?;

        let crypto = projection_crypto()?;
        let before = profile(1, "Before", "before@example.test");
        let after = profile(2, "Captured", "captured@example.test");
        let outbox_event_id = Uuid::now_v7();
        let mut transaction = pool.begin().await?;
        sqlx::query("SELECT set_config('iam.principal_id', $1, true)")
            .bind(carbon_id.to_string())
            .execute(&mut *transaction)
            .await?;
        let authorizations_before =
            profile_webhook_authorizations(&mut transaction, carbon_id).await?;
        let silicon_routes =
            capture_carbon_profile_silicon_routes(&mut transaction, carbon_id).await?;
        sqlx::query(
            r"
            UPDATE iam.oauth_consent_grants
            SET status = 'revoked', revoked_at = transaction_timestamp()
            WHERE id = $1
            ",
        )
        .bind(before_only_consent_id)
        .execute(&mut *transaction)
        .await?;
        let authorizations_after =
            profile_webhook_authorizations(&mut transaction, carbon_id).await?;
        sqlx::query(
            r"
            INSERT INTO iam.outbox_events (
                id, aggregate_type, aggregate_id, aggregate_version,
                event_type, schema_version, payload
            ) VALUES ($1, 'carbon', $2, 2, 'carbon.updated.v1', 1, $3)
            ",
        )
        .bind(outbox_event_id)
        .bind(carbon_id)
        .bind(serde_json::json!({ "carbon_id": carbon_id }))
        .execute(&mut *transaction)
        .await?;
        capture_profile_webhook_projections(
            &mut transaction,
            &crypto,
            outbox_event_id,
            &before,
            &after,
            &authorizations_before,
            &authorizations_after,
        )
        .await?;
        let before_profile = serde_json::to_value(&before)?;
        let after_profile = serde_json::to_value(&after)?;
        enqueue_carbon_profile_silicon_events(
            &mut transaction,
            after.version,
            &changed_profile_fields(&before, &after),
            &before_profile,
            &after_profile,
            &silicon_routes,
        )
        .await?;
        let full_only_event_id = postgres::events::enqueue_outbox(
            &mut transaction,
            postgres::events::OutboxRecord {
                organization_id: Some(organization_id),
                aggregate: postgres::events::AggregateVersion {
                    aggregate_type: "organization",
                    aggregate_id: organization_id,
                    version: 1,
                },
                event_ordinal: 1,
                event_type: "organization.updated.v1",
                schema_version: 1,
                payload: serde_json::json!({ "change": "organization.updated" }),
                silicon_webhook_routing: Some(postgres::events::SiliconWebhookRouting {
                    topics: Vec::new(),
                    affected_membership_id: None,
                    affected_tag_ids: Vec::new(),
                    before_tag_membership_ids: Vec::new(),
                    organization_wide: true,
                }),
            },
        )
        .await?;
        let mixed_topic_event_id = postgres::events::enqueue_outbox(
            &mut transaction,
            postgres::events::OutboxRecord {
                organization_id: Some(organization_id),
                aggregate: postgres::events::AggregateVersion {
                    aggregate_type: "membership_topic_test",
                    aggregate_id: carbon_membership_id,
                    version: 2,
                },
                event_ordinal: 1,
                event_type: "organization.membership.updated.v1",
                schema_version: 1,
                payload: serde_json::json!({ "change": "membership.mixed_update" }),
                silicon_webhook_routing: Some(postgres::events::SiliconWebhookRouting {
                    topics: vec![
                        postgres::events::SiliconWebhookTopic::MemberUpdates,
                        postgres::events::SiliconWebhookTopic::TrustUpdates,
                    ],
                    affected_membership_id: Some(carbon_membership_id),
                    affected_tag_ids: vec![shared_tag_id],
                    before_tag_membership_ids: Vec::new(),
                    organization_wide: false,
                }),
            },
        )
        .await?;
        let unrouted_event_id = postgres::events::enqueue_outbox(
            &mut transaction,
            postgres::events::OutboxRecord {
                organization_id: Some(organization_id),
                aggregate: postgres::events::AggregateVersion {
                    aggregate_type: "organization_internal",
                    aggregate_id: organization_id,
                    version: 1,
                },
                event_ordinal: 1,
                event_type: "organization.internal.v1",
                schema_version: 1,
                payload: serde_json::json!({ "change": "organization.internal" }),
                silicon_webhook_routing: None,
            },
        )
        .await?;
        transaction.commit().await?;

        sqlx::query("UPDATE iam.carbons SET display_name = 'Later' WHERE id = $1")
            .bind(carbon_id)
            .execute(&pool)
            .await?;
        let rows = sqlx::query_as::<_, (Uuid, Uuid, Vec<u8>, Vec<u8>, i16)>(
            r"
            SELECT id, application_id, payload_ciphertext, payload_nonce,
                   encryption_key_version
            FROM iam.application_webhook_event_projections
            WHERE outbox_event_id = $1
            ORDER BY application_id
            ",
        )
        .bind(outbox_event_id)
        .fetch_all(&pool)
        .await?;
        ensure!(rows.len() == 2, "before-only Application was not retained");
        let mut payloads = BTreeMap::new();
        for (projection_id, application_id, ciphertext, nonce, key_version) in rows {
            let nonce: [u8; 12] = nonce
                .try_into()
                .map_err(|_| anyhow::anyhow!("projection nonce length changed"))?;
            let plaintext = crypto.decrypt(
                EncryptionContext::tenant(
                    ProtectedField::ApplicationWebhookEventPayload,
                    application_id,
                    projection_id,
                ),
                &EncryptedValue {
                    key_version,
                    nonce,
                    ciphertext,
                },
            )?;
            payloads.insert(
                application_id,
                serde_json::from_slice::<serde_json::Value>(&plaintext)?,
            );
        }
        let retained = &payloads[&retained_application_id];
        ensure!(retained["current"]["display_name"] == "Captured");
        ensure!(retained["current"]["email"] == "captured@example.test");
        ensure!(retained["current"].get("phone_number").is_none());
        let before_only = &payloads[&before_only_application_id];
        ensure!(before_only["current"].get("phone_number").is_none());
        ensure!(before_only["current"].get("display_name").is_none());
        ensure!(before_only["changed_fields"] == serde_json::json!([]));

        let (silicon_event_id, silicon_payload) = sqlx::query_as::<_, (Uuid, serde_json::Value)>(
            r"
                SELECT id, payload
                FROM iam.outbox_events
                WHERE organization_id = $1
                  AND aggregate_type = 'organization_membership_profile'
                  AND aggregate_id = $2
                  AND aggregate_version = 2
                  AND event_ordinal = 1
                  AND event_type = 'organization.membership.profile_updated.v1'
                ",
        )
        .bind(organization_id)
        .bind(carbon_membership_id)
        .fetch_one(&pool)
        .await?;
        ensure!(silicon_payload["changed_fields"] == serde_json::json!(["display_name"]));
        ensure!(silicon_payload["before"]["profile"]["display_name"] == "Before");
        ensure!(silicon_payload["current"]["profile"]["display_name"] == "Captured");
        ensure!(silicon_payload["current"]["membership"]["job_role"] == "Platform engineer");
        ensure!(silicon_payload["current"]["profile"].get("email").is_none());
        ensure!(
            silicon_payload["current"]["profile"]
                .get("phone_number")
                .is_none()
        );
        ensure!(silicon_payload.get("principal_id").is_none());
        ensure!(silicon_payload.get("carbon_id").is_none());
        let routed_topic = sqlx::query_scalar::<_, String>(
            "SELECT topic FROM iam.outbox_event_topics WHERE outbox_event_id = $1",
        )
        .bind(silicon_event_id)
        .fetch_one(&pool)
        .await?;
        ensure!(routed_topic == "member_updates");
        let routed_tags = sqlx::query_scalar::<_, Uuid>(
            "SELECT tag_id FROM iam.outbox_event_affected_tags WHERE outbox_event_id = $1",
        )
        .bind(silicon_event_id)
        .fetch_all(&pool)
        .await?;
        ensure!(routed_tags == vec![shared_tag_id]);
        let own_tag_snapshot = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT membership_id
            FROM iam.outbox_event_own_tag_memberships
            WHERE outbox_event_id = $1
            ORDER BY membership_id
            ",
        )
        .bind(silicon_event_id)
        .fetch_all(&pool)
        .await?;
        ensure!(
            own_tag_snapshot == vec![silicon_membership_id],
            "profile routing did not freeze the exact event-time own-tag audience"
        );
        let silicon_recipients = sqlx::query_as::<_, (Uuid, Uuid)>(
            r"
            SELECT endpoint_id, signing_key_id
            FROM iam_private.list_worker_silicon_webhook_recipients($1)
            ",
        )
        .bind(silicon_event_id)
        .fetch_all(&pool)
        .await?;
        ensure!(
            silicon_recipients
                == vec![
                    (silicon_endpoint_id, silicon_signing_key_id),
                    (full_silicon_endpoint_id, full_silicon_signing_key_id),
                ],
            "member_updates selected and Full subscribers did not receive the profile event"
        );
        let full_only_recipients = sqlx::query_as::<_, (Uuid, Uuid)>(
            r"
            SELECT endpoint_id, signing_key_id
            FROM iam_private.list_worker_silicon_webhook_recipients($1)
            ",
        )
        .bind(full_only_event_id)
        .fetch_all(&pool)
        .await?;
        ensure!(
            full_only_recipients == vec![(full_silicon_endpoint_id, full_silicon_signing_key_id)],
            "selected member_updates subscriber received a Full-only event"
        );
        let mixed_topic_recipients = sqlx::query_as::<_, (Uuid, Uuid)>(
            r"
            SELECT endpoint_id, signing_key_id
            FROM iam_private.list_worker_silicon_webhook_recipients($1)
            ",
        )
        .bind(mixed_topic_event_id)
        .fetch_all(&pool)
        .await?;
        ensure!(
            mixed_topic_recipients
                == vec![
                    (silicon_endpoint_id, silicon_signing_key_id),
                    (full_silicon_endpoint_id, full_silicon_signing_key_id),
                ],
            "a subscriber matching multiple event topics was duplicated or omitted"
        );
        let unrouted_recipients = sqlx::query_as::<_, (Uuid, Uuid)>(
            r"
            SELECT endpoint_id, signing_key_id
            FROM iam_private.list_worker_silicon_webhook_recipients($1)
            ",
        )
        .bind(unrouted_event_id)
        .fetch_all(&pool)
        .await?;
        ensure!(
            unrouted_recipients.is_empty(),
            "Full subscription received an event without a Silicon routing decision"
        );
        let route_markers = sqlx::query_as::<_, (Uuid, bool)>(
            r"
            SELECT id, silicon_webhook_routable
            FROM iam.outbox_events
            WHERE id = ANY($1)
            ORDER BY id
            ",
        )
        .bind(vec![full_only_event_id, unrouted_event_id])
        .fetch_all(&pool)
        .await?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
        ensure!(route_markers[&full_only_event_id]);
        ensure!(!route_markers[&unrouted_event_id]);

        let mut tag_change = pool.begin().await?;
        sqlx::query(
            r"
            DELETE FROM iam.membership_tags
            WHERE organization_id = $1 AND membership_id = $2 AND tag_id = $3
            ",
        )
        .bind(organization_id)
        .bind(silicon_membership_id)
        .bind(shared_tag_id)
        .execute(&mut *tag_change)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.membership_tags (
                organization_id, membership_id, tag_id, assigned_by_membership_id
            ) VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(organization_id)
        .bind(full_silicon_membership_id)
        .bind(shared_tag_id)
        .bind(carbon_membership_id)
        .execute(&mut *tag_change)
        .await?;
        sqlx::query(
            r"
            UPDATE iam.silicon_webhook_subscriptions
            SET mode = 'selected', tag_filter_enabled = true
            WHERE id = $1
            ",
        )
        .bind(full_silicon_subscription_id)
        .execute(&mut *tag_change)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.silicon_webhook_subscription_topics (subscription_id, topic)
            VALUES ($1, 'member_updates')
            ",
        )
        .bind(full_silicon_subscription_id)
        .execute(&mut *tag_change)
        .await?;
        tag_change.commit().await?;

        let recipients_after_later_tag_change = sqlx::query_as::<_, (Uuid, Uuid)>(
            r"
            SELECT endpoint_id, signing_key_id
            FROM iam_private.list_worker_silicon_webhook_recipients($1)
            ",
        )
        .bind(silicon_event_id)
        .fetch_all(&pool)
        .await?;
        ensure!(
            recipients_after_later_tag_change
                == vec![(silicon_endpoint_id, silicon_signing_key_id)],
            "own-tag routing hydrated a later tag gain or forgot an event-time tag loss"
        );

        sqlx::query(
            r"
            UPDATE iam.outbox_events
            SET status = 'completed', completed_at = transaction_timestamp()
            WHERE id = $1
            ",
        )
        .bind(outbox_event_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            UPDATE iam.application_webhook_event_projections
            SET created_at = transaction_timestamp() - interval '46 days'
            WHERE outbox_event_id = $1
            ",
        )
        .bind(outbox_event_id)
        .execute(&pool)
        .await?;
        sqlx::raw_sql(
            "CREATE ROLE silicon_iam_worker NOLOGIN; GRANT silicon_iam_worker TO postgres;",
        )
        .execute(&pool)
        .await?;
        let purged = sqlx::query_scalar::<_, i64>(
            r"
            SELECT affected_rows
            FROM iam_private.run_worker_retention_maintenance(
                'webhook_delivery_attempts', 365, 30, 90, 365, 45, 2555, 100
            )
            ",
        )
        .fetch_one(&pool)
        .await?;
        ensure!(purged == 2, "retention did not purge both old projections");
        let remaining = sqlx::query_scalar::<_, i64>(
            r"
            SELECT count(*)
            FROM iam.application_webhook_event_projections
            WHERE outbox_event_id = $1
            ",
        )
        .bind(outbox_event_id)
        .fetch_one(&pool)
        .await?;
        ensure!(remaining == 0, "retention left expired projections behind");
        Ok(())
    }
}
