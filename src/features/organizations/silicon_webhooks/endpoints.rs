#![allow(clippy::too_many_lines)]

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use secrecy::ExposeSecret as _;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    error::AppError,
    infrastructure::crypto::{EncryptedValue, EncryptionContext, ProtectedField, SecretKind},
};

use super::{
    super::{
        model::{SiliconWebhookConfiguredResponse, SiliconWebhookReplace, SiliconWebhookResponse},
        silicons,
        support::{self, Claim, MutationEvent},
        validation,
    },
    shared::{self, TargetSilicon},
};

const WEBHOOK_REPLACE_ROUTE: &str =
    "PUT /api/v1/organizations/{org_id}/silicons/{silicon_id}/webhook";
const WEBHOOK_DELETE_ROUTE: &str =
    "DELETE /api/v1/organizations/{org_id}/silicons/{silicon_id}/webhook";
#[derive(Clone, Debug, FromRow)]
struct EndpointIdentity {
    id: Uuid,
    status: String,
    version: i64,
}

#[derive(Clone, Debug)]
struct SubscriptionSnapshot {
    id: Uuid,
    mode: String,
    topics: Vec<String>,
    tag_filter_enabled: bool,
    additional_tag_ids: Vec<Uuid>,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct SubscriptionBaseSnapshot {
    id: Uuid,
    mode: String,
    tag_filter_enabled: bool,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct SubscriptionBeforeState {
    silicon_id: String,
    mode: String,
    topics: Vec<String>,
    tag_filter: Option<SubscriptionTagFilterBeforeState>,
    version: i64,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct SubscriptionTagFilterBeforeState {
    additional_tag_ids: Vec<Uuid>,
}

#[derive(Debug, FromRow)]
struct EncryptedEndpointRow {
    id: Uuid,
    silicon_id: String,
    url_ciphertext: Vec<u8>,
    url_nonce: Vec<u8>,
    encryption_key_version: i16,
    status: String,
    secret_version: i64,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

pub(in crate::features::organizations) async fn get_webhook(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    silicons::validate_global_silicon_id(&silicon_id, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let target = shared::load_target(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize(&authenticated, &scope.access, &target)?;
    let response = load_webhook(
        &mut scope.transaction,
        &state,
        scope.access.organization_id,
        &target,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &response, Some(response.version))
}

pub(in crate::features::organizations) async fn replace_webhook(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<SiliconWebhookReplace>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    silicons::validate_global_silicon_id(&silicon_id, &org_id)?;
    let url = crate::features::webhook_url::parse(&input.url)
        .map_err(|message| validation::field("webhook_url", message))?;

    let mut preflight = support::begin_organization(&state, &authenticated, &org_id).await?;
    let target = shared::load_target(
        &mut preflight.transaction,
        preflight.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize_identity(&authenticated, &preflight.access, &target)?;
    let claim_request = replace_claim_request(
        preflight.access.organization_id,
        target.principal_id,
        &input,
    );
    let replay = support::replay_resource_if_present(
        &mut preflight.transaction,
        &state,
        &authenticated,
        &headers,
        WEBHOOK_REPLACE_ROUTE,
        &silicon_id,
        &claim_request,
        true,
    )
    .await?;
    preflight
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    if let Some(response) = replay {
        return Ok(response);
    }
    crate::features::webhook_url::validate_resolved_target(&url)
        .await
        .map_err(|message| validation::field("webhook_url", message))?;

    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let target = shared::load_target(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize_identity(&authenticated, &scope.access, &target)?;
    let claim_request =
        replace_claim_request(scope.access.organization_id, target.principal_id, &input);
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        WEBHOOK_REPLACE_ROUTE,
        &silicon_id,
        &claim_request,
        true,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let target = shared::load_target_for_update(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize(&authenticated, &scope.access, &target)?;
    shared::consume_carbon_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.silicon_webhook.redirect",
        &target,
    )
    .await?;

    let current = lock_endpoint(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
    )
    .await?;
    if let Some(endpoint) = current.as_ref() {
        shared::lock_delivery_scope(&mut scope.transaction, endpoint.id).await?;
    }
    enforce_existing_version(
        &headers,
        current
            .as_ref()
            .filter(|endpoint| endpoint.status == "active")
            .map(|endpoint| endpoint.version),
    )?;
    let endpoint_id = current
        .as_ref()
        .map_or_else(Uuid::now_v7, |endpoint| endpoint.id);
    let key_id = Uuid::now_v7();
    let secret_version = next_secret_version(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
    )
    .await?;
    let secret = state
        .crypto
        .generate_secret(SecretKind::SiliconWebhookSigningSecret)
        .map_err(|_| AppError::Internal {
            category: "silicon_webhook_secret_generate",
        })?;
    let encrypted_url = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::SiliconWebhookUrl,
                scope.access.organization_id,
                endpoint_id,
            ),
            url.as_str().as_bytes(),
        )
        .map_err(|_| AppError::Internal {
            category: "silicon_webhook_url_encrypt",
        })?;
    let encrypted_secret = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::SiliconWebhookSigningSecret,
                scope.access.organization_id,
                key_id,
            ),
            secret.expose_secret().as_bytes(),
        )
        .map_err(|_| AppError::Internal {
            category: "silicon_webhook_secret_encrypt",
        })?;

    if current.is_some() {
        shared::cancel_deliveries(
            &mut scope.transaction,
            scope.access.organization_id,
            endpoint_id,
            "silicon_webhook_reconfigured",
        )
        .await?;
    }
    retire_keys_immediately(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
    )
    .await?;
    let endpoint_version = persist_endpoint(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
        endpoint_id,
        &encrypted_url,
        url.as_str(),
        current.is_some(),
    )
    .await?;
    insert_signing_key(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
        endpoint_id,
        key_id,
        secret_version,
        &encrypted_secret,
        secret.expose_secret(),
    )
    .await?;
    let webhook = load_webhook(
        &mut scope.transaction,
        &state,
        scope.access.organization_id,
        &target,
    )
    .await?;
    let secret_replay_expires_at = secret_replay_expiry(&mut scope.transaction).await?;
    let response = SiliconWebhookConfiguredResponse {
        webhook,
        webhook_signing_secret: secret.expose_secret().to_owned(),
        secret_replay_expires_at,
    };
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "silicon.webhook.configure",
            target_type: "silicon_webhook",
            target_id: endpoint_id,
            aggregate_type: "silicon_webhook",
            aggregate_id: endpoint_id,
            aggregate_version: endpoint_version,
            event_type: "organization.silicon.webhook.configured.v1",
            before_state: current
                .as_ref()
                .map(|endpoint| json!({ "status": endpoint.status, "endpoint_id": endpoint.id })),
            after_state: Some(json!({
                "status": "active",
                "endpoint_id": endpoint_id,
                "secret_version": secret_version,
            })),
            metadata: json!({
                "silicon_id": target.principal_id,
                "membership_id": target.membership_id,
                "endpoint_id": endpoint_id,
            }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &response,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(endpoint_version), true)
}

pub(in crate::features::organizations) async fn delete_webhook(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    silicons::validate_global_silicon_id(&silicon_id, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let target = shared::load_target(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize_identity(&authenticated, &scope.access, &target)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        WEBHOOK_DELETE_ROUTE,
        &silicon_id,
        &json!({ "operation": "delete" }),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let target = shared::load_target_for_update(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    shared::authorize(&authenticated, &scope.access, &target)?;
    shared::consume_carbon_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.silicon_webhook.redirect",
        &target,
    )
    .await?;
    let endpoint = lock_endpoint(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
    )
    .await?
    .filter(|endpoint| endpoint.status == "active")
    .ok_or(AppError::NotFound)?;
    shared::lock_delivery_scope(&mut scope.transaction, endpoint.id).await?;
    enforce_existing_version(&headers, Some(endpoint.version))?;
    let subscription = lock_subscription_snapshot(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
        endpoint.id,
    )
    .await?;
    if let Some(subscription) = subscription.as_ref() {
        sqlx::query(
            "DELETE FROM iam.silicon_webhook_subscription_topics WHERE subscription_id = $1",
        )
        .bind(subscription.id)
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
        let deleted_id = sqlx::query_scalar::<_, Uuid>(
            r"
            DELETE FROM iam.silicon_webhook_subscriptions
            WHERE organization_id = $1 AND silicon_id = $2
              AND endpoint_id = $3 AND id = $4
            RETURNING id
            ",
        )
        .bind(scope.access.organization_id)
        .bind(target.principal_id)
        .bind(endpoint.id)
        .bind(subscription.id)
        .fetch_optional(&mut *scope.transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::Internal {
            category: "silicon_webhook_subscription_delete",
        })?;
        if deleted_id != subscription.id {
            return Err(AppError::Internal {
                category: "silicon_webhook_subscription_delete_identity",
            });
        }
    }
    shared::cancel_deliveries(
        &mut scope.transaction,
        scope.access.organization_id,
        endpoint.id,
        "silicon_webhook_disabled",
    )
    .await?;
    retire_keys_immediately(
        &mut scope.transaction,
        scope.access.organization_id,
        target.principal_id,
    )
    .await?;
    let version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.silicon_webhook_endpoints
        SET status = 'disabled', disabled_at = transaction_timestamp(),
            updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND silicon_id = $2 AND status = 'active'
        RETURNING version
        ",
    )
    .bind(scope.access.organization_id)
    .bind(target.principal_id)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    if let Some(event) = subscription_deleted_event(
        subscription.as_ref(),
        &silicon_id,
        target.principal_id,
        target.membership_id,
        endpoint.id,
    )? {
        support::record_mutation(
            &mut scope.transaction,
            &authenticated,
            scope.access.organization_id,
            event,
        )
        .await?;
    }
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "silicon.webhook.delete",
            target_type: "silicon_webhook",
            target_id: endpoint.id,
            aggregate_type: "silicon_webhook",
            aggregate_id: endpoint.id,
            aggregate_version: version,
            event_type: "organization.silicon.webhook.deleted.v1",
            before_state: Some(json!({ "status": "active" })),
            after_state: Some(json!({ "status": "disabled" })),
            metadata: json!({
                "silicon_id": target.principal_id,
                "membership_id": target.membership_id,
                "endpoint_id": endpoint.id,
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

async fn lock_subscription_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
    endpoint_id: Uuid,
) -> Result<Option<SubscriptionSnapshot>, AppError> {
    let Some(subscription) = sqlx::query_as::<_, SubscriptionBaseSnapshot>(
        r"
        SELECT subscription.id, subscription.mode, subscription.tag_filter_enabled,
               subscription.version, subscription.created_at, subscription.updated_at
        FROM iam.silicon_webhook_subscriptions AS subscription
        WHERE subscription.organization_id = $1
          AND subscription.silicon_id = $2
          AND subscription.endpoint_id = $3
        FOR UPDATE OF subscription
        ",
    )
    .bind(organization_id)
    .bind(silicon_id)
    .bind(endpoint_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    else {
        return Ok(None);
    };

    let topics = if subscription.mode == "all" {
        vec![
            "membership_lifecycle".to_owned(),
            "member_updates".to_owned(),
            "trust_updates".to_owned(),
        ]
    } else {
        sqlx::query_scalar::<_, String>(
            r"
            SELECT topic::text
            FROM iam.silicon_webhook_subscription_topics
            WHERE subscription_id = $1
            ORDER BY topic
            ",
        )
        .bind(subscription.id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(support::database)?
    };
    let additional_tag_ids = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT tag_id
        FROM iam.silicon_webhook_subscription_extra_tags
        WHERE subscription_id = $1
        ORDER BY tag_id
        ",
    )
    .bind(subscription.id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)?;

    Ok(Some(SubscriptionSnapshot {
        id: subscription.id,
        mode: subscription.mode,
        topics,
        tag_filter_enabled: subscription.tag_filter_enabled,
        additional_tag_ids,
        version: subscription.version,
        created_at: subscription.created_at,
        updated_at: subscription.updated_at,
    }))
}

fn subscription_deleted_event(
    subscription: Option<&SubscriptionSnapshot>,
    global_silicon_id: &str,
    silicon_id: Uuid,
    membership_id: Uuid,
    endpoint_id: Uuid,
) -> Result<Option<MutationEvent<'static>>, AppError> {
    let Some(subscription) = subscription else {
        return Ok(None);
    };
    let before_state = serde_json::to_value(SubscriptionBeforeState {
        silicon_id: global_silicon_id.to_owned(),
        mode: subscription.mode.clone(),
        topics: subscription.topics.clone(),
        tag_filter: subscription
            .tag_filter_enabled
            .then(|| SubscriptionTagFilterBeforeState {
                additional_tag_ids: subscription.additional_tag_ids.clone(),
            }),
        version: subscription.version,
        created_at: subscription.created_at,
        updated_at: subscription.updated_at,
    })
    .map_err(|_| AppError::Internal {
        category: "silicon_webhook_subscription_delete_before_state",
    })?;
    Ok(Some(MutationEvent {
        action: "silicon.webhook_subscription.delete",
        target_type: "silicon_webhook_subscription",
        target_id: subscription.id,
        aggregate_type: "silicon_webhook_subscription",
        aggregate_id: subscription.id,
        aggregate_version: subscription.version + 1,
        event_type: "organization.silicon.webhook_subscription.deleted.v1",
        before_state: Some(before_state),
        after_state: None,
        metadata: json!({
            "silicon_id": silicon_id,
            "membership_id": membership_id,
            "subscription_id": subscription.id,
            "endpoint_id": endpoint_id,
            "deletion_source": "endpoint_delete",
        }),
    }))
}

async fn lock_endpoint(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
) -> Result<Option<EndpointIdentity>, AppError> {
    sqlx::query_as::<_, EndpointIdentity>(
        r"
        SELECT id, status, version
        FROM iam.silicon_webhook_endpoints
        WHERE organization_id = $1 AND silicon_id = $2
        FOR UPDATE
        ",
    )
    .bind(organization_id)
    .bind(silicon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)
}

#[allow(clippy::too_many_arguments)]
async fn persist_endpoint(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
    endpoint_id: Uuid,
    encrypted_url: &EncryptedValue,
    canonical_url: &str,
    exists: bool,
) -> Result<i64, AppError> {
    let digest = Sha256::digest(canonical_url.as_bytes());
    let version = if exists {
        sqlx::query_scalar::<_, i64>(
            r"
            UPDATE iam.silicon_webhook_endpoints
            SET url_ciphertext = $4, url_nonce = $5, encryption_key_version = $6,
                url_digest = $7, status = 'active', disabled_at = NULL,
                updated_at = transaction_timestamp()
            WHERE organization_id = $1 AND silicon_id = $2 AND id = $3
            RETURNING version
            ",
        )
        .bind(organization_id)
        .bind(silicon_id)
        .bind(endpoint_id)
        .bind(&encrypted_url.ciphertext)
        .bind(encrypted_url.nonce.as_slice())
        .bind(encrypted_url.key_version)
        .bind(digest.as_slice())
        .fetch_one(&mut **transaction)
        .await
    } else {
        sqlx::query_scalar::<_, i64>(
            r"
            INSERT INTO iam.silicon_webhook_endpoints (
                id, organization_id, silicon_id, url_ciphertext, url_nonce,
                encryption_key_version, url_digest
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING version
            ",
        )
        .bind(endpoint_id)
        .bind(organization_id)
        .bind(silicon_id)
        .bind(&encrypted_url.ciphertext)
        .bind(encrypted_url.nonce.as_slice())
        .bind(encrypted_url.key_version)
        .bind(digest.as_slice())
        .fetch_one(&mut **transaction)
        .await
    };
    version.map_err(support::database)
}

#[allow(clippy::too_many_arguments)]
async fn insert_signing_key(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
    endpoint_id: Uuid,
    key_id: Uuid,
    secret_version: i64,
    encrypted_secret: &EncryptedValue,
    raw_secret: &str,
) -> Result<(), AppError> {
    let key_prefix = raw_secret.get(..12).ok_or(AppError::Internal {
        category: "silicon_webhook_secret_prefix",
    })?;
    sqlx::query(
        r"
        INSERT INTO iam.silicon_webhook_signing_keys (
            id, organization_id, silicon_id, endpoint_id, secret_version,
            key_prefix, secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ",
    )
    .bind(key_id)
    .bind(organization_id)
    .bind(silicon_id)
    .bind(endpoint_id)
    .bind(secret_version)
    .bind(key_prefix)
    .bind(&encrypted_secret.ciphertext)
    .bind(encrypted_secret.nonce.as_slice())
    .bind(encrypted_secret.key_version)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    Ok(())
}

async fn retire_keys_immediately(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.silicon_webhook_signing_keys
        SET status = 'retired', retires_at = NULL,
            retired_at = transaction_timestamp()
        WHERE organization_id = $1 AND silicon_id = $2
          AND status IN ('active', 'retiring')
        ",
    )
    .bind(organization_id)
    .bind(silicon_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    Ok(())
}

fn enforce_existing_version(
    headers: &HeaderMap,
    existing_version: Option<i64>,
) -> Result<(), AppError> {
    let Some(existing_version) = existing_version else {
        return Ok(());
    };
    if validation::expected_version(headers)? != existing_version {
        return Err(AppError::PreconditionFailed {
            code: "etag_mismatch".into(),
        });
    }
    Ok(())
}

async fn next_secret_version(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
) -> Result<i64, AppError> {
    sqlx::query_scalar::<_, i64>(
        r"
        SELECT COALESCE(MAX(secret_version), 0) + 1
        FROM iam.silicon_webhook_signing_keys
        WHERE organization_id = $1 AND silicon_id = $2
        ",
    )
    .bind(organization_id)
    .bind(silicon_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)
}

async fn secret_replay_expiry(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<OffsetDateTime, AppError> {
    sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT transaction_timestamp() + interval '10 minutes'",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)
}

async fn load_webhook(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    organization_id: Uuid,
    target: &TargetSilicon,
) -> Result<SiliconWebhookResponse, AppError> {
    let row = sqlx::query_as::<_, EncryptedEndpointRow>(
        r"
        SELECT endpoint.id, silicon.global_silicon_id AS silicon_id,
               endpoint.url_ciphertext, endpoint.url_nonce,
               endpoint.encryption_key_version, endpoint.status,
               signing.secret_version, endpoint.version,
               endpoint.created_at, endpoint.updated_at
        FROM iam.silicon_webhook_endpoints AS endpoint
        JOIN iam.silicons AS silicon
          ON silicon.organization_id = endpoint.organization_id
         AND silicon.id = endpoint.silicon_id
        JOIN iam.silicon_webhook_signing_keys AS signing
          ON signing.organization_id = endpoint.organization_id
         AND signing.silicon_id = endpoint.silicon_id
         AND signing.endpoint_id = endpoint.id
         AND signing.status = 'active'
        WHERE endpoint.organization_id = $1
          AND endpoint.silicon_id = $2
          AND endpoint.status = 'active'
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(target.principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    let nonce = <[u8; 12]>::try_from(row.url_nonce.as_slice()).map_err(|_| AppError::Internal {
        category: "silicon_webhook_url_nonce",
    })?;
    let plaintext = state
        .crypto
        .decrypt(
            EncryptionContext::tenant(ProtectedField::SiliconWebhookUrl, organization_id, row.id),
            &EncryptedValue {
                key_version: row.encryption_key_version,
                nonce,
                ciphertext: row.url_ciphertext,
            },
        )
        .map_err(|_| AppError::Internal {
            category: "silicon_webhook_url_decrypt",
        })?;
    let url = String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Internal {
        category: "silicon_webhook_url_utf8",
    })?;
    Ok(SiliconWebhookResponse {
        silicon_id: row.silicon_id,
        url,
        status: row.status,
        secret_version: row.secret_version,
        version: row.version,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn replace_claim_request(
    organization_id: Uuid,
    silicon_id: Uuid,
    input: &SiliconWebhookReplace,
) -> serde_json::Value {
    json!({
        "organization_id": organization_id,
        "silicon_id": silicon_id,
        "request": input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_idempotency_is_bound_to_the_target_silicon() {
        let organization_id = Uuid::now_v7();
        let input = SiliconWebhookReplace {
            url: "https://hooks.example/events".to_owned(),
        };
        let first = replace_claim_request(organization_id, Uuid::now_v7(), &input);
        let second = replace_claim_request(organization_id, Uuid::now_v7(), &input);
        assert_ne!(first, second);
    }

    #[test]
    fn endpoint_delete_emits_the_actual_subscription_snapshot() {
        let subscription_id = Uuid::from_u128(1);
        let silicon_id = Uuid::from_u128(2);
        let membership_id = Uuid::from_u128(3);
        let endpoint_id = Uuid::from_u128(4);
        let additional_tag_id = Uuid::from_u128(5);
        let snapshot = SubscriptionSnapshot {
            id: subscription_id,
            mode: "selected".to_owned(),
            topics: vec!["member_updates".to_owned()],
            tag_filter_enabled: true,
            additional_tag_ids: vec![additional_tag_id],
            version: 7,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };

        let Ok(Some(event)) = subscription_deleted_event(
            Some(&snapshot),
            "bot:acme",
            silicon_id,
            membership_id,
            endpoint_id,
        ) else {
            panic!("an existing subscription snapshot must produce an event");
        };

        assert_eq!(event.target_id, subscription_id);
        assert_eq!(event.aggregate_id, subscription_id);
        assert_eq!(event.aggregate_version, 8);
        assert_eq!(
            event.event_type,
            "organization.silicon.webhook_subscription.deleted.v1"
        );
        assert_eq!(
            event.before_state,
            Some(json!({
                "silicon_id": "bot:acme",
                "mode": "selected",
                "topics": ["member_updates"],
                "tag_filter": { "additional_tag_ids": [additional_tag_id] },
                "version": 7,
                "created_at": "1970-01-01T00:00:00Z",
                "updated_at": "1970-01-01T00:00:00Z",
            }))
        );
        assert_eq!(
            event.metadata,
            json!({
                "silicon_id": silicon_id,
                "membership_id": membership_id,
                "subscription_id": subscription_id,
                "endpoint_id": endpoint_id,
                "deletion_source": "endpoint_delete",
            })
        );
        assert!(event.after_state.is_none());
    }

    #[test]
    fn endpoint_delete_does_not_emit_a_phantom_subscription_event() {
        let Ok(event) = subscription_deleted_event(
            None,
            "bot:acme",
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
        ) else {
            panic!("absence must not fail event construction");
        };

        assert!(event.is_none());
    }
}
