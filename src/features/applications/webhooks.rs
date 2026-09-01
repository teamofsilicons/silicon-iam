#![allow(clippy::too_many_lines)]

use std::{collections::HashMap, net::IpAddr};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use secrecy::ExposeSecret as _;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    api::ApiState,
    infrastructure::{
        crypto::{EncryptedValue, EncryptionContext, ProtectedField, SecretKind},
        postgres::{
            context::{self, DatabaseContext},
            step_up::RequiredAssurance,
        },
    },
};

use super::{
    applications::{bump_application, json_with_etag, resolve_readable_app, resolve_technical_app},
    cursor,
    error::ApiError,
    events::{self, Mutation},
    idempotency::{self, Claim},
    model::{
        AppPath, DeliveryAttemptView, DeliveryPage, DeliveryPath, DeliveryView, LoginEventPage,
        LoginEventView, PageInfo, PageQuery, SecretRotationRequest, WebhookEndpointView,
        WebhookReplace, WebhookSecretRotated, WebhookView,
    },
    security::{Bearer, expected_version, require_carbon, require_step_up},
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
    version: i64,
}

#[derive(FromRow)]
struct EncryptedSigningKeyRow {
    id: Uuid,
    secret_ciphertext: Vec<u8>,
    secret_nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(FromRow)]
struct DeliveryRow {
    id: Uuid,
    destination_type: String,
    destination_id: Uuid,
    event_id: Uuid,
    event_type: String,
    aggregate_id: Uuid,
    aggregate_version: i64,
    status: String,
    next_attempt_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl DeliveryRow {
    fn into_public(self, attempts: Vec<DeliveryAttemptView>) -> DeliveryView {
        DeliveryView {
            id: self.id,
            destination_type: self.destination_type,
            destination_id: self.destination_id,
            event_id: self.event_id,
            event_type: self.event_type,
            aggregate_id: self.aggregate_id,
            aggregate_version: self.aggregate_version,
            status: self.status,
            attempts,
            next_attempt_at: self.next_attempt_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(FromRow)]
struct DeliveryAttemptRow {
    delivery_id: Uuid,
    attempt: i32,
    started_at: OffsetDateTime,
    duration_ms: Option<i32>,
    outcome: String,
    response_status: Option<i16>,
    response_digest: Option<Vec<u8>>,
}

impl DeliveryAttemptRow {
    fn into_public(self) -> DeliveryAttemptView {
        DeliveryAttemptView {
            attempt: self.attempt,
            started_at: self.started_at,
            duration_ms: self.duration_ms,
            outcome: self.outcome,
            response_status: self.response_status,
            response_body_digest: self
                .response_digest
                .map(|digest| format!("sha256:{}", hex::encode(digest))),
        }
    }
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
    let webhook = load_webhook(&mut transaction, &state, app.id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("webhook_get_commit"))?;
    json_with_etag(StatusCode::OK, &webhook, app.version)
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
    validate_dns_target(&url).await?;
    let expected = expected_version(&headers)?;
    let canonical = input.url.as_bytes();
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("webhook_replace_context"))?;
    let app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, true).await?;
    if app.version != expected {
        return Err(ApiError::precondition_failed());
    }
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
    if let Claim::Replay { response, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("webhook_replace_replay"))?;
        return json_with_etag(StatusCode::ACCEPTED, &response, app.version + 1);
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("webhook_replace_idempotency"));
    };
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
    let response = load_webhook(&mut transaction, &state, app.id).await?;
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
    json_with_etag(StatusCode::ACCEPTED, &response, version)
}

pub(super) async fn rotate_secret(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
    input: Option<Json<SecretRotationRequest>>,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let input = input.map_or_else(SecretRotationRequest::default, |Json(value)| value);
    validation::overlap(input.overlap_seconds)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("webhook_secret_rotate_context"))?;
    let app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, true).await?;
    require_step_up(
        &mut transaction,
        &state.crypto,
        &headers,
        &access,
        "application.rotate_secret",
        app.id,
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", app.id);
    let claim = idempotency::claim::<WebhookSecretRotated>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/applications/{app_id}/webhook/secret-rotations",
        &input.overlap_seconds.to_be_bytes(),
        true,
    )
    .await?;
    if let Claim::Replay { response, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("webhook_secret_replay"))?;
        return Ok(signing_secret_response(response, true));
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("webhook_secret_idempotency"));
    };
    let endpoint_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id FROM iam.application_webhook_endpoints
        WHERE application_id = $1 AND status IN ('active', 'pending_review')
        ORDER BY (status = 'active') DESC, created_at DESC LIMIT 1
        FOR UPDATE
        ",
    )
    .bind(app.id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_endpoint_for_rotation"))?
    .ok_or_else(ApiError::not_found)?;
    let previous_valid_until = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT transaction_timestamp() + ($1::bigint * interval '1 second')",
    )
    .bind(i64::from(input.overlap_seconds))
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_secret_validity"))?;
    if input.overlap_seconds == 0 {
        sqlx::query(
            r"
            UPDATE iam.application_webhook_signing_keys
            SET status = 'retired', retired_at = transaction_timestamp(), retires_at = NULL
            WHERE endpoint_id = $1 AND status IN ('active', 'retiring')
            ",
        )
        .bind(endpoint_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_secret_retire"))?;
    } else {
        sqlx::query(
            r"
            UPDATE iam.application_webhook_signing_keys
            SET status = 'retiring', retires_at = $2
            WHERE endpoint_id = $1 AND status = 'active'
            ",
        )
        .bind(endpoint_id)
        .bind(previous_valid_until)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("webhook_secret_overlap"))?;
    }
    let key_id = Uuid::now_v7();
    let raw = state
        .crypto
        .generate_secret(SecretKind::WebhookSigningSecret)
        .map_err(|_| ApiError::internal("webhook_secret_generate"))?;
    let encrypted = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                app.id,
                key_id,
            ),
            raw.expose_secret().as_bytes(),
        )
        .map_err(|_| ApiError::internal("webhook_secret_encrypt"))?;
    let prefix = raw.expose_secret().chars().take(12).collect::<String>();
    let secret_version = next_signing_secret_version(&mut transaction, app.id).await?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(key_id)
    .bind(app.id)
    .bind(endpoint_id)
    .bind(secret_version)
    .bind(&prefix)
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce.as_slice())
    .bind(encrypted.key_version)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_secret_insert"))?;
    let version = bump_application(&mut transaction, app.id).await?;
    let secret_replay_expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT transaction_timestamp() + interval '10 minutes'",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_secret_replay_expiry"))?;
    let response = WebhookSecretRotated {
        app_id: app.app_id.clone(),
        webhook_signing_secret: raw.expose_secret().to_owned(),
        secret_version,
        previous_valid_until,
        secret_replay_expires_at,
    };
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: app.id,
            action: "application.webhook_secret.rotate",
            target_type: "webhook_signing_key",
            target_id: Some(key_id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: version,
            before: None,
            after: Some(json!({
                "key_id": key_id,
                "prefix": prefix,
                "secret_version": secret_version,
            })),
            metadata: json!({ "overlap_seconds": input.overlap_seconds }),
            event_type: "application.webhook_secret_rotated",
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
        .map_err(|_| ApiError::internal("webhook_secret_commit"))?;
    Ok(signing_secret_response(response, false))
}

pub(super) async fn list_deliveries(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    Query(query): Query<PageQuery>,
) -> Result<Json<DeliveryPage>, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let cursor = cursor::decode(query.cursor.as_deref())?;
    let limit = cursor::limit(query.limit);
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("delivery_list_context"))?;
    let app = resolve_readable_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let (at, id) = cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)));
    let mut rows = sqlx::query_as::<_, DeliveryRow>(
        r"
        SELECT delivery.id,
               'application'::text AS destination_type,
               endpoint.application_id AS destination_id,
               event.id AS event_id, event.event_type,
               event.aggregate_id, event.aggregate_version,
               CASE
                   WHEN delivery.status = 'processing' THEN 'delivering'
                   WHEN delivery.status = 'pending' AND delivery.last_error_code IS NOT NULL
                       THEN 'retry_wait'
                   ELSE delivery.status
               END AS status,
               CASE
                   WHEN delivery.status IN ('pending', 'processing')
                       THEN delivery.next_attempt_at
                   ELSE NULL
               END AS next_attempt_at,
               delivery.created_at, delivery.updated_at
        FROM iam.webhook_deliveries AS delivery
        JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.id = delivery.recipient_id
         AND recipient.outbox_event_id = delivery.outbox_event_id
        JOIN iam.application_webhook_endpoints AS endpoint
          ON endpoint.id = recipient.application_webhook_endpoint_id
        WHERE endpoint.application_id = $1
          AND (
              $2::text IS NULL
              OR CASE
                  WHEN delivery.status = 'processing' THEN 'delivering'
                  WHEN delivery.status = 'pending' AND delivery.last_error_code IS NOT NULL
                      THEN 'retry_wait'
                  ELSE delivery.status
              END = $2
          )
          AND ($3::timestamptz IS NULL OR (delivery.created_at, delivery.id) < ($3, $4))
        ORDER BY delivery.created_at DESC, delivery.id DESC
        LIMIT $5
        ",
    )
    .bind(app.id)
    .bind(query.status)
    .bind(at)
    .bind(id)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("delivery_list"))?;
    let next_cursor = if i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit {
        rows.pop();
        rows.last()
            .map(|item| cursor::encode(item.created_at, item.id))
            .transpose()?
    } else {
        None
    };
    let delivery_ids = rows.iter().map(|row| row.id).collect::<Vec<_>>();
    let attempts = fetch_attempts(&mut transaction, &delivery_ids).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("delivery_list_commit"))?;
    let mut attempts_by_delivery = attempts.into_iter().fold(
        HashMap::<Uuid, Vec<DeliveryAttemptView>>::new(),
        |mut grouped, row| {
            grouped
                .entry(row.delivery_id)
                .or_default()
                .push(row.into_public());
            grouped
        },
    );
    Ok(Json(DeliveryPage {
        items: rows
            .into_iter()
            .map(|row| {
                let attempts = attempts_by_delivery.remove(&row.id).unwrap_or_default();
                row.into_public(attempts)
            })
            .collect(),
        page: PageInfo::from_next_cursor(next_cursor),
    }))
}

pub(super) async fn get_delivery(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<DeliveryPath>,
) -> Result<Json<DeliveryView>, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("delivery_get_context"))?;
    let app = resolve_readable_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let delivery = delivery_for_application(&mut transaction, app.id, path.delivery_id, false)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let attempts = fetch_attempts(&mut transaction, &[path.delivery_id])
        .await?
        .into_iter()
        .map(DeliveryAttemptRow::into_public)
        .collect();
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("delivery_get_commit"))?;
    Ok(Json(delivery.into_public(attempts)))
}

pub(super) async fn replay_delivery(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<DeliveryPath>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    validation::app_id(&path.app_id)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("delivery_replay_context"))?;
    let app = resolve_technical_app(&mut transaction, carbon_id, &path.app_id, false).await?;
    let caller_scope = format!("carbon:{carbon_id}:application:{}", app.id);
    let claim = idempotency::claim::<serde_json::Value>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/applications/{app_id}/webhook-deliveries/{delivery_id}/replays",
        path.delivery_id.as_bytes(),
        false,
    )
    .await?;
    if matches!(claim, Claim::Replay { .. }) {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("delivery_replay_replayed"))?;
        return Ok(StatusCode::ACCEPTED.into_response());
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("delivery_replay_idempotency"));
    };
    if delivery_for_application(&mut transaction, app.id, path.delivery_id, true)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found());
    }
    let result = sqlx::query(
        r"
        UPDATE iam.webhook_deliveries
        SET status = 'pending', next_attempt_at = transaction_timestamp(),
            cycle_attempt_count = 0,
            manual_replay_count = manual_replay_count + 1,
            lease_owner = NULL, lease_expires_at = NULL,
            delivered_at = NULL, dead_lettered_at = NULL,
            last_http_status = NULL, last_error_code = NULL
        WHERE id = $1 AND status = 'dead_letter'
        ",
    )
    .bind(path.delivery_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("delivery_replay_update"))?;
    if result.rows_affected() != 1 {
        return Err(ApiError::conflict("delivery_not_replayable"));
    }
    let version = bump_application(&mut transaction, app.id).await?;
    events::record(
        &mut transaction,
        Mutation {
            actor_id: Some(carbon_id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: app.id,
            action: "application.webhook_delivery.replay",
            target_type: "webhook_delivery",
            target_id: Some(path.delivery_id),
            aggregate_type: "application",
            aggregate_id: app.id,
            aggregate_version: version,
            before: Some(json!({ "status": "dead_letter" })),
            after: Some(json!({ "status": "pending" })),
            metadata: json!({ "delivery_id": path.delivery_id }),
            event_type: "application.webhook_delivery_replayed",
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        202,
        &serde_json::Value::Null,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("delivery_replay_commit"))?;
    Ok(StatusCode::ACCEPTED.into_response())
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
) -> Result<WebhookView, ApiError> {
    let rows = sqlx::query_as::<_, EncryptedEndpointRow>(
        r"
        SELECT id, application_id, url_ciphertext, url_nonce,
               encryption_key_version, status, version
        FROM iam.application_webhook_endpoints
        WHERE application_id = $1 AND status IN ('active', 'pending_review', 'disabled')
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
    for row in rows {
        let endpoint = decrypt_endpoint(state, row)?;
        if endpoint.status == "active" && active.is_none() {
            active = Some(endpoint);
        } else if endpoint.status == "pending_review" && pending.is_none() {
            pending = Some(endpoint);
        } else if endpoint.status == "disabled" && disabled.is_none() {
            disabled = Some(endpoint);
        }
    }
    let representative = active
        .as_ref()
        .or(pending.as_ref())
        .or(disabled.as_ref())
        .ok_or_else(|| ApiError::internal("webhook_endpoint_missing"))?;
    let secret_version = sqlx::query_scalar::<_, i64>(
        r"
        SELECT secret_version
        FROM iam.application_webhook_signing_keys
        WHERE application_id = $1 AND status IN ('active', 'retiring')
        ORDER BY secret_version DESC LIMIT 1
        ",
    )
    .bind(application_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("webhook_secret_version_read"))?;
    let status = if disabled.is_some() && active.is_none() && pending.is_none() {
        "disabled"
    } else if active.is_none() && pending.is_some() {
        "pending_review"
    } else if pending.is_some() {
        "replacement_under_review"
    } else {
        "active"
    };
    Ok(WebhookView {
        active_url: active.as_ref().map(|endpoint| endpoint.url.clone()),
        pending_url: pending.as_ref().map(|endpoint| endpoint.url.clone()),
        status: status.to_owned(),
        secret_version,
        version: representative.version,
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
        version: row.version,
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

async fn delivery_for_application(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    delivery_id: Uuid,
    for_update: bool,
) -> Result<Option<DeliveryRow>, ApiError> {
    let result = if for_update {
        sqlx::query_as::<_, DeliveryRow>(
            r"
            SELECT delivery.id,
                   'application'::text AS destination_type,
                   endpoint.application_id AS destination_id,
                   event.id AS event_id, event.event_type,
                   event.aggregate_id, event.aggregate_version,
                   CASE
                       WHEN delivery.status = 'processing' THEN 'delivering'
                       WHEN delivery.status = 'pending' AND delivery.last_error_code IS NOT NULL
                           THEN 'retry_wait'
                       ELSE delivery.status
                   END AS status,
                   CASE
                       WHEN delivery.status IN ('pending', 'processing')
                           THEN delivery.next_attempt_at
                       ELSE NULL
                   END AS next_attempt_at,
                   delivery.created_at, delivery.updated_at
            FROM iam.webhook_deliveries AS delivery
            JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
            JOIN iam.outbox_event_recipients AS recipient
              ON recipient.id = delivery.recipient_id
             AND recipient.outbox_event_id = delivery.outbox_event_id
            JOIN iam.application_webhook_endpoints AS endpoint
              ON endpoint.id = recipient.application_webhook_endpoint_id
            WHERE endpoint.application_id = $1 AND delivery.id = $2
            FOR UPDATE OF delivery
            ",
        )
        .bind(application_id)
        .bind(delivery_id)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as::<_, DeliveryRow>(
            r"
            SELECT delivery.id,
                   'application'::text AS destination_type,
                   endpoint.application_id AS destination_id,
                   event.id AS event_id, event.event_type,
                   event.aggregate_id, event.aggregate_version,
                   CASE
                       WHEN delivery.status = 'processing' THEN 'delivering'
                       WHEN delivery.status = 'pending' AND delivery.last_error_code IS NOT NULL
                           THEN 'retry_wait'
                       ELSE delivery.status
                   END AS status,
                   CASE
                       WHEN delivery.status IN ('pending', 'processing')
                           THEN delivery.next_attempt_at
                       ELSE NULL
                   END AS next_attempt_at,
                   delivery.created_at, delivery.updated_at
            FROM iam.webhook_deliveries AS delivery
            JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
            JOIN iam.outbox_event_recipients AS recipient
              ON recipient.id = delivery.recipient_id
             AND recipient.outbox_event_id = delivery.outbox_event_id
            JOIN iam.application_webhook_endpoints AS endpoint
              ON endpoint.id = recipient.application_webhook_endpoint_id
            WHERE endpoint.application_id = $1 AND delivery.id = $2
            ",
        )
        .bind(application_id)
        .bind(delivery_id)
        .fetch_optional(&mut **transaction)
        .await
    };
    result.map_err(|_| ApiError::internal("delivery_resolve"))
}

async fn fetch_attempts(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_ids: &[Uuid],
) -> Result<Vec<DeliveryAttemptRow>, ApiError> {
    if delivery_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, DeliveryAttemptRow>(
        r"
        WITH ranked AS (
            SELECT
                attempt.delivery_id,
                attempt.attempt_number AS attempt,
                attempt.started_at,
                attempt.duration_ms,
                CASE
                    WHEN attempt.finished_at IS NULL THEN 'rejected'
                    WHEN attempt.http_status BETWEEN 200 AND 299 THEN 'success'
                    WHEN attempt.http_status IS NOT NULL THEN 'http_error'
                    WHEN attempt.error_code ILIKE '%timeout%' THEN 'timeout'
                    WHEN attempt.error_code = ANY(ARRAY[
                        'dns_resolution', 'connection', 'request', 'network'
                    ]::text[]) THEN 'network_error'
                    ELSE 'rejected'
                END AS outcome,
                attempt.http_status AS response_status,
                attempt.response_digest,
                row_number() OVER (
                    PARTITION BY attempt.delivery_id
                    ORDER BY attempt.attempt_number DESC
                ) AS history_rank
            FROM iam.webhook_delivery_attempts AS attempt
            WHERE attempt.delivery_id = ANY($1::uuid[])
        )
        SELECT delivery_id, attempt, started_at, duration_ms, outcome,
               response_status, response_digest
        FROM ranked
        WHERE history_rank <= 100
        ORDER BY delivery_id, attempt
        ",
    )
    .bind(delivery_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("delivery_attempts"))
}

async fn validate_dns_target(url: &Url) -> Result<(), ApiError> {
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::validation("webhook_url", "must contain a host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| ApiError::validation("webhook_url", "host cannot be resolved"))?
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().copied().any(is_non_public_ip) {
        return Err(ApiError::validation(
            "webhook_url",
            "every resolved address must be public",
        ));
    }
    Ok(())
}

fn is_non_public_ip(address: IpAddr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || match address {
            IpAddr::V4(address) => {
                address.is_private()
                    || address.is_link_local()
                    || address.is_broadcast()
                    || address.is_documentation()
            }
            IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local(),
        }
}

fn signing_secret_response(response: WebhookSecretRotated, replayed: bool) -> Response {
    let mut response = (StatusCode::CREATED, Json(response)).into_response();
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::is_non_public_ip;

    #[test]
    fn ssrf_policy_rejects_private_and_link_local_addresses() {
        assert!(is_non_public_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_non_public_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_non_public_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_non_public_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
