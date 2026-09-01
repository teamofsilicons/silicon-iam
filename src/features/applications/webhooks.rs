#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::ApiState,
    infrastructure::{
        crypto::{EncryptedValue, EncryptionContext, ProtectedField},
        postgres::context::{self, DatabaseContext},
    },
};

use super::{
    applications::{
        bump_application, json_with_etag, json_with_etag_replayed, resolve_readable_app,
        resolve_technical_app,
    },
    cursor,
    error::ApiError,
    events::{self, Mutation},
    idempotency::{self, Claim},
    model::{
        AppPath, LoginEventPage, LoginEventView, PageInfo, PageQuery, WebhookEndpointView,
        WebhookReplace, WebhookView,
    },
    security::{Bearer, expected_version, require_carbon},
    validation,
};

#[derive(FromRow)]
struct EncryptedEndpointRow {
    id: Uuid,
    application_id: Uuid,
    url_ciphertext: Vec<u8>,
    url_nonce: Vec<u8>,
    encryption_key_version: i16,
    status: String,
}

#[derive(FromRow)]
struct EncryptedSigningKeyRow {
    id: Uuid,
    secret_ciphertext: Vec<u8>,
    secret_nonce: Vec<u8>,
    encryption_key_version: i16,
}

pub(super) async fn get(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("webhook_get_context"))?;
    let app = resolve_readable_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let webhook = load_webhook(&mut transaction, &state, app.id, app.version).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("webhook_get_commit"))?;
    json_with_etag(StatusCode::OK, &webhook, webhook.version)
}

pub(super) async fn replace(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
    Json(input): Json<WebhookReplace>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let url = validation::webhook_url(&input.url)?;
    let canonical = input.url.as_bytes();
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("webhook_replace_context"))?;
    let app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", app.id);
    if let Some(replay) = idempotency::replay_if_present::<WebhookView>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "PUT /api/v1/applications/{app_id}/webhook",
        canonical,
    )
    .await?
    {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("webhook_replace_replay"))?;
        let status = StatusCode::from_u16(replay.status)
            .map_err(|_| ApiError::internal("webhook_replace_replay_status"))?;
        return json_with_etag_replayed(status, &replay.response, replay.response.version);
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("webhook_replace_preflight_commit"))?;
    crate::features::webhook_url::validate_resolved_target(&url)
        .await
        .map_err(|message| ApiError::validation("webhook_url", message))?;

    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("webhook_replace_context"))?;
    let app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", app.id);
    let claim = idempotency::claim::<WebhookView>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "PUT /api/v1/applications/{app_id}/webhook",
        canonical,
        false,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("webhook_replace_replay"))?;
        let status = StatusCode::from_u16(status)
            .map_err(|_| ApiError::internal("webhook_replace_replay_status"))?;
        return json_with_etag_replayed(status, &response, response.version);
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("webhook_replace_idempotency"));
    };
    let expected = expected_version(&headers)?;
    let app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, true).await?;
    if app.version != expected {
        return Err(ApiError::precondition_failed());
    }
    let old_key = sqlx::query_as::<_, EncryptedSigningKeyRow>(
        r"
        SELECT signing.id, signing.secret_ciphertext,
               signing.secret_nonce, signing.encryption_key_version
        FROM iam.application_webhook_signing_keys AS signing
        JOIN iam.application_webhook_endpoints AS endpoint
          ON endpoint.id = signing.endpoint_id
        WHERE signing.application_id = $1
          AND signing.status IN ('active', 'retiring')
          AND endpoint.status IN ('active', 'pending_review')
        ORDER BY (endpoint.status = 'active') DESC, signing.created_at DESC
        LIMIT 1
        ",
    )
    .bind(app.id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_signing_key_read"))?
    .ok_or_else(|| ApiError::internal("webhook_signing_key_missing"))?;
    let secret = decrypt_signing_secret(&state, app.id, &old_key)?;
    sqlx::query(
        r"
        UPDATE iam.application_webhook_endpoints
        SET status = 'retired', retired_at = transaction_timestamp()
        WHERE application_id = $1 AND status = 'pending_review'
        ",
    )
    .bind(app.id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_pending_retire"))?;
    let endpoint_id = Uuid::now_v7();
    let signing_key_id = Uuid::now_v7();
    let signing_secret_version = next_signing_secret_version(&mut transaction, app.id).await?;
    let encrypted_url = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(ProtectedField::ApplicationWebhookUrl, app.id, endpoint_id),
            input.url.as_bytes(),
        )
        .map_err(|_| ApiError::internal("webhook_url_encrypt"))?;
    let encrypted_secret = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                app.id,
                signing_key_id,
            ),
            &secret,
        )
        .map_err(|_| ApiError::internal("webhook_secret_rebind"))?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_endpoints (
            id, application_id, url_ciphertext, url_nonce,
            encryption_key_version, url_digest
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(endpoint_id)
    .bind(app.id)
    .bind(encrypted_url.ciphertext)
    .bind(encrypted_url.nonce.as_slice())
    .bind(encrypted_url.key_version)
    .bind(Sha256::digest(input.url.as_bytes()).as_slice())
    .execute(&mut *transaction)
    .await
    .map_err(map_webhook_write)?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(signing_key_id)
    .bind(app.id)
    .bind(endpoint_id)
    .bind(signing_secret_version)
    .bind("whs_migrated")
    .bind(encrypted_secret.ciphertext)
    .bind(encrypted_secret.nonce.as_slice())
    .bind(encrypted_secret.key_version)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_signing_key_rebind"))?;
    let version = bump_application(&mut transaction, app.id).await?;
    let response = load_webhook(&mut transaction, &state, app.id, version).await?;
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: app.id,
            action: "application.webhook.propose",
            target_type: "application_webhook",
            target_id: Some(endpoint_id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: version,
            before: None,
            after: Some(json!({ "endpoint_id": endpoint_id, "status": "pending_review" })),
            metadata: json!({ "dns_validated_at_submission": true }),
            event_type: "application.webhook_proposed",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        202,
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("webhook_replace_commit"))?;
    json_with_etag(StatusCode::ACCEPTED, &response, response.version)
}

pub(super) async fn login_history(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    Query(query): Query<PageQuery>,
) -> Result<Json<LoginEventPage>, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let cursor = cursor::decode(query.cursor.as_deref())?;
    let limit = cursor::limit(query.limit);
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("login_history_context"))?;
    let app = resolve_readable_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let (at, id) = cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)));
    let mut items = sqlx::query_as::<_, LoginEventView>(
        r"
        SELECT event.id,
               event.subject_principal_id AS principal_id,
               event.subject_kind::text AS actor_type,
               COALESCE(carbon.carbon_id, silicon.global_silicon_id) AS public_id,
               application.app_id AS app_id,
               organization.org_id,
               CASE event.event_type
                   WHEN 'login.challenge' THEN 'login_challenge'
                   WHEN 'login.success' THEN 'login_success'
                   WHEN 'login.failure' THEN 'login_failure'
                   WHEN 'oauth.authorization' THEN 'oauth_authorization'
                   WHEN 'oauth.token_exchange' THEN 'oauth_token_exchange'
                   WHEN 'logout.success' THEN 'logout'
                   WHEN 'refresh.replay' THEN 'refresh_replay'
               END AS event_type,
               event.outcome = 'success' AS success,
               NULL::text AS ip_prefix,
               NULL::text AS user_agent_summary,
               event.request_id::text AS request_id,
               event.occurred_at
        FROM iam.authentication_events AS event
        JOIN iam.applications AS application ON application.id = event.application_id
        LEFT JOIN iam.organizations AS organization ON organization.id = event.organization_id
        LEFT JOIN iam.carbons AS carbon
          ON carbon.id = event.subject_principal_id AND event.subject_kind = 'carbon'
        LEFT JOIN iam.silicons AS silicon
          ON silicon.id = event.subject_principal_id AND event.subject_kind = 'silicon'
        WHERE event.application_id = $1
          AND event.subject_principal_id IS NOT NULL
          AND event.subject_kind IN ('carbon', 'silicon')
          AND event.event_type = ANY(ARRAY[
              'login.challenge', 'login.success', 'login.failure',
              'oauth.authorization', 'oauth.token_exchange',
              'logout.success', 'refresh.replay'
          ]::text[])
          AND ($2::timestamptz IS NULL OR (event.occurred_at, event.id) < ($2, $3))
        ORDER BY event.occurred_at DESC, event.id DESC
        LIMIT $4
        ",
    )
    .bind(app.id)
    .bind(at)
    .bind(id)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("login_history"))?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("login_history_commit"))?;
    let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
        items.pop();
        items
            .last()
            .map(|item| cursor::encode(item.occurred_at, item.id))
            .transpose()?
    } else {
        None
    };
    Ok(Json(LoginEventPage {
        items,
        page: PageInfo::from_next_cursor(next_cursor),
    }))
}

pub(super) async fn load_webhook(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    application_id: Uuid,
    application_version: i64,
) -> Result<WebhookView, ApiError> {
    let rows = sqlx::query_as::<_, EncryptedEndpointRow>(
        r"
        SELECT id, application_id, url_ciphertext, url_nonce,
               encryption_key_version, status
        FROM iam.application_webhook_endpoints
        WHERE application_id = $1
          AND status IN ('active', 'pending_review', 'disabled', 'retired')
        ORDER BY created_at DESC
        ",
    )
    .bind(application_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_load"))?;
    let mut active = None;
    let mut pending = None;
    let mut disabled = None;
    let mut retired = None;
    for row in rows {
        let endpoint = decrypt_endpoint(state, row)?;
        if endpoint.status == "active" && active.is_none() {
            active = Some(endpoint);
        } else if endpoint.status == "pending_review" && pending.is_none() {
            pending = Some(endpoint);
        } else if endpoint.status == "disabled" && disabled.is_none() {
            disabled = Some(endpoint);
        } else if endpoint.status == "retired" && retired.is_none() {
            retired = Some(endpoint);
        }
    }
    let secret_version = sqlx::query_scalar::<_, i64>(
        r"
        SELECT COALESCE(MAX(secret_version), 0)
        FROM iam.application_webhook_signing_keys
        WHERE application_id = $1
        ",
    )
    .bind(application_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_secret_version_read"))?;
    webhook_projection(
        active.as_ref(),
        pending.as_ref(),
        disabled.as_ref(),
        retired.as_ref(),
        secret_version,
        application_version,
    )
}

fn webhook_projection(
    active: Option<&WebhookEndpointView>,
    pending: Option<&WebhookEndpointView>,
    disabled: Option<&WebhookEndpointView>,
    retired: Option<&WebhookEndpointView>,
    secret_version: i64,
    application_version: i64,
) -> Result<WebhookView, ApiError> {
    if active.is_none() && pending.is_none() && disabled.is_none() && retired.is_none() {
        return Err(ApiError::internal("webhook_endpoint_missing"));
    }
    let status = if active.is_none() && pending.is_none() {
        "disabled"
    } else if active.is_none() && pending.is_some() {
        "pending_review"
    } else if pending.is_some() {
        "replacement_under_review"
    } else {
        "active"
    };
    Ok(WebhookView {
        active_url: active.map(|endpoint| endpoint.url.clone()),
        pending_url: pending.map(|endpoint| endpoint.url.clone()),
        status: status.to_owned(),
        secret_version,
        version: application_version,
    })
}

fn decrypt_endpoint(
    state: &ApiState,
    row: EncryptedEndpointRow,
) -> Result<WebhookEndpointView, ApiError> {
    let nonce = <[u8; 12]>::try_from(row.url_nonce.as_slice())
        .map_err(|_| ApiError::internal("webhook_url_nonce"))?;
    let encrypted = EncryptedValue {
        key_version: row.encryption_key_version,
        nonce,
        ciphertext: row.url_ciphertext,
    };
    let plaintext = state
        .crypto
        .decrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookUrl,
                row.application_id,
                row.id,
            ),
            &encrypted,
        )
        .map_err(|_| ApiError::internal("webhook_url_decrypt"))?;
    let url = String::from_utf8(plaintext.to_vec())
        .map_err(|_| ApiError::internal("webhook_url_utf8"))?;
    Ok(WebhookEndpointView {
        url,
        status: row.status,
    })
}

fn decrypt_signing_secret(
    state: &ApiState,
    application_id: Uuid,
    row: &EncryptedSigningKeyRow,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ApiError> {
    let nonce = <[u8; 12]>::try_from(row.secret_nonce.as_slice())
        .map_err(|_| ApiError::internal("webhook_secret_nonce"))?;
    state
        .crypto
        .decrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                application_id,
                row.id,
            ),
            &EncryptedValue {
                key_version: row.encryption_key_version,
                nonce,
                ciphertext: row.secret_ciphertext.clone(),
            },
        )
        .map_err(|_| ApiError::internal("webhook_secret_decrypt"))
}

async fn next_signing_secret_version(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
) -> Result<i64, ApiError> {
    sqlx::query_scalar(
        "SELECT COALESCE(MAX(secret_version), 0) + 1 FROM iam.application_webhook_signing_keys WHERE application_id = $1",
    )
    .bind(application_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_secret_version"))
}

#[allow(clippy::needless_pass_by_value)]
fn map_webhook_write(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database) = &error
        && database.is_unique_violation()
    {
        return ApiError::conflict("webhook_url_conflict");
    }
    ApiError::internal("webhook_write")
}

#[cfg(test)]
mod tests {
    use super::{WebhookEndpointView, webhook_projection};

    fn endpoint(url: &str, status: &str) -> WebhookEndpointView {
        WebhookEndpointView {
            url: url.to_owned(),
            status: status.to_owned(),
        }
    }

    #[test]
    fn projection_uses_the_application_aggregate_version() {
        let active = endpoint("https://active.example.test/webhook", "active");
        let pending = endpoint("https://replacement.example.test/webhook", "pending_review");
        let Ok(projection) = webhook_projection(Some(&active), Some(&pending), None, None, 4, 19)
        else {
            panic!("a valid active and pending webhook must project");
        };

        assert_eq!(projection.status, "replacement_under_review");
        assert_eq!(projection.secret_version, 4);
        assert_eq!(projection.version, 19);
        assert_eq!(projection.active_url.as_deref(), Some(active.url.as_str()));
        assert_eq!(
            projection.pending_url.as_deref(),
            Some(pending.url.as_str())
        );
    }

    #[test]
    fn projection_preserves_pending_and_disabled_statuses() {
        let pending = endpoint("https://pending.example.test/webhook", "pending_review");
        let disabled = endpoint("https://disabled.example.test/webhook", "disabled");
        let Ok(pending_projection) = webhook_projection(None, Some(&pending), None, None, 2, 7)
        else {
            panic!("an initial pending webhook must project");
        };
        let Ok(disabled_projection) = webhook_projection(None, None, Some(&disabled), None, 2, 8)
        else {
            panic!("a disabled webhook must project");
        };

        assert_eq!(pending_projection.status, "pending_review");
        assert_eq!(pending_projection.secret_version, 2);
        assert_eq!(pending_projection.version, 7);
        assert_eq!(disabled_projection.status, "disabled");
        assert_eq!(disabled_projection.secret_version, 2);
        assert_eq!(disabled_projection.version, 8);
    }
}
