//! At-least-once application and Silicon webhook event delivery.

use std::{borrow::Cow, time::Instant};

use futures::{StreamExt as _, stream};
use secrecy::SecretString;
use serde::Serialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;

use crate::{
    error::AppError,
    infrastructure::{
        crypto::{EncryptedValue, EncryptionContext, ProtectedField},
        postgres::events::uses_captured_application_webhook_projection,
        providers::webhook::{self as transport, WebhookError, WebhookReceipt, WebhookRequest},
    },
};

use super::{WorkerContext, delivery_claim_limit, retry_delay_seconds};

#[derive(sqlx::FromRow)]
struct ClaimedDelivery {
    delivery_id: Uuid,
    cycle_attempt_count: i32,
    outbox_event_id: Uuid,
    recipient_kind: String,
    application_webhook_endpoint_id: Option<Uuid>,
    silicon_webhook_endpoint_id: Option<Uuid>,
    signing_key_id: Option<Uuid>,
    silicon_webhook_signing_key_id: Option<Uuid>,
    organization_id: Option<Uuid>,
    aggregate_type: String,
    aggregate_id: Uuid,
    aggregate_version: i64,
    event_type: String,
    schema_version: i16,
    payload: Value,
    created_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct ApplicationMaterial {
    application_id: Uuid,
    url_ciphertext: Vec<u8>,
    url_nonce: Vec<u8>,
    url_encryption_key_version: i16,
    secret_ciphertext: Vec<u8>,
    secret_nonce: Vec<u8>,
    secret_encryption_key_version: i16,
    secret_version: i64,
}

#[derive(sqlx::FromRow)]
struct SiliconMaterial {
    organization_id: Uuid,
    url_ciphertext: Vec<u8>,
    url_nonce: Vec<u8>,
    url_encryption_key_version: i16,
    secret_ciphertext: Vec<u8>,
    secret_nonce: Vec<u8>,
    secret_encryption_key_version: i16,
    secret_version: i64,
}

#[derive(sqlx::FromRow)]
struct ApplicationEventProjection {
    projection_id: Uuid,
    payload_ciphertext: Vec<u8>,
    payload_nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(Serialize)]
struct EventEnvelope<'a> {
    spec_version: &'static str,
    event_id: Uuid,
    event_type: &'a str,
    occurred_at: &'a str,
    organization_id: Option<Uuid>,
    aggregate: AggregateEnvelope<'a>,
    data: &'a Value,
}

#[derive(Serialize)]
struct AggregateEnvelope<'a> {
    #[serde(rename = "type")]
    aggregate_type: &'a str,
    id: Uuid,
    version: i64,
}

struct DeliveryMaterial {
    application_id: Option<Uuid>,
    destination: Url,
    signing_secret: SecretString,
    signing_key_version: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecipientType {
    Application,
    SiliconWebhook,
}

impl TryFrom<&str> for RecipientType {
    type Error = WebhookError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "application" => Ok(Self::Application),
            "silicon_webhook" => Ok(Self::SiliconWebhook),
            _ => Err(WebhookError::DestinationRejected),
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the lease-safe claim query and its typed projection are one auditable operation"
)]
pub(super) async fn process_batch(context: &WorkerContext) -> Result<(), AppError> {
    let _outbound_stage = context.outbound_stage_lock.lock().await;
    let claim_limit = delivery_claim_limit(context)?;
    let lease_seconds =
        i64::try_from(context.settings.worker.lease_duration.as_secs()).map_err(|_| {
            AppError::Internal {
                category: "worker_lease_duration",
            }
        })?;
    let deliveries = sqlx::query_as::<_, ClaimedDelivery>(
        r"
        WITH candidates AS (
            SELECT delivery.id
            FROM iam.webhook_deliveries AS delivery
            JOIN iam.outbox_event_recipients AS recipient
              ON recipient.id = delivery.recipient_id
             AND recipient.outbox_event_id = delivery.outbox_event_id
            JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
            WHERE (
                (
                    delivery.status = 'pending'
                    AND delivery.next_attempt_at <= transaction_timestamp()
                ) OR (
                    delivery.status = 'processing'
                    AND delivery.lease_expires_at <= transaction_timestamp()
                )
            )
              AND NOT EXISTS (
                  SELECT 1
                  FROM iam.outbox_events AS prior_unexpanded_event
                  WHERE prior_unexpanded_event.organization_id
                        IS NOT DISTINCT FROM event.organization_id
                    AND prior_unexpanded_event.aggregate_type = event.aggregate_type
                    AND prior_unexpanded_event.aggregate_id = event.aggregate_id
                    AND prior_unexpanded_event.global_sequence < event.global_sequence
                    AND prior_unexpanded_event.status IN ('pending', 'processing')
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM iam.webhook_deliveries AS prior_delivery
                  JOIN iam.outbox_event_recipients AS prior_recipient
                    ON prior_recipient.id = prior_delivery.recipient_id
                   AND prior_recipient.outbox_event_id = prior_delivery.outbox_event_id
                  JOIN iam.outbox_events AS prior_event
                    ON prior_event.id = prior_delivery.outbox_event_id
                  WHERE prior_recipient.ordering_key = recipient.ordering_key
                    AND prior_event.global_sequence < event.global_sequence
                    AND prior_delivery.status IN ('pending', 'processing')
              )
            ORDER BY delivery.next_attempt_at, event.global_sequence, delivery.id
            FOR UPDATE OF delivery SKIP LOCKED
            LIMIT $1
        ), claimed AS (
            UPDATE iam.webhook_deliveries AS delivery
            SET status = 'processing',
                lease_owner = $2,
                lease_expires_at = transaction_timestamp()
                    + ($3::bigint * interval '1 second'),
                attempt_count = delivery.attempt_count + 1,
                cycle_attempt_count = delivery.cycle_attempt_count + 1,
                last_error_code = NULL
            FROM candidates
            WHERE delivery.id = candidates.id
            RETURNING delivery.*
        )
        SELECT
            claimed.id AS delivery_id,
            claimed.cycle_attempt_count,
            claimed.outbox_event_id,
            recipient.recipient_kind,
            recipient.application_webhook_endpoint_id,
            recipient.silicon_webhook_endpoint_id,
            claimed.signing_key_id,
            claimed.silicon_webhook_signing_key_id,
            event.organization_id,
            event.aggregate_type,
            event.aggregate_id,
            event.aggregate_version,
            event.event_type,
            event.schema_version,
            event.payload,
            event.created_at
        FROM claimed
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.id = claimed.recipient_id
         AND recipient.outbox_event_id = claimed.outbox_event_id
        JOIN iam.outbox_events AS event ON event.id = claimed.outbox_event_id
        ORDER BY event.global_sequence, claimed.id
        ",
    )
    .bind(claim_limit)
    .bind(&context.instance_id)
    .bind(lease_seconds)
    .fetch_all(&context.pool)
    .await?;

    let results = stream::iter(deliveries)
        .map(|delivery| async move { process_delivery(context, &delivery).await })
        .buffer_unordered(context.settings.worker.delivery_concurrency.get())
        .collect::<Vec<_>>()
        .await;
    for result in results {
        result?;
    }
    Ok(())
}

async fn process_delivery(
    context: &WorkerContext,
    delivery: &ClaimedDelivery,
) -> Result<(), AppError> {
    let material = match load_material(context, delivery).await {
        Ok(material) => material,
        Err(error) => {
            finish_failure(context, delivery, error.code(), error.retryable(), None).await?;
            return Ok(());
        }
    };
    let data = match load_event_data(context, delivery, material.application_id).await {
        Ok(data) => data,
        Err(error) => {
            finish_failure(context, delivery, error.code(), error.retryable(), None).await?;
            return Ok(());
        }
    };
    let occurred_at = delivery
        .created_at
        .format(&Rfc3339)
        .map_err(|_| AppError::Internal {
            category: "webhook_event_timestamp",
        })?;
    let wire_event_type = wire_event_type(&delivery.event_type, delivery.schema_version)?;
    let body = serde_json::to_vec(&EventEnvelope {
        spec_version: "1.0",
        event_id: delivery.outbox_event_id,
        event_type: wire_event_type.as_ref(),
        occurred_at: &occurred_at,
        organization_id: delivery.organization_id,
        aggregate: AggregateEnvelope {
            aggregate_type: &delivery.aggregate_type,
            id: delivery.aggregate_id,
            version: delivery.aggregate_version,
        },
        data: &data,
    })
    .map_err(|_| AppError::Internal {
        category: "webhook_event_serialization",
    })?;
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let Some(attempt_id) = begin_attempt(context, delivery).await? else {
        return Ok(());
    };
    let started = Instant::now();
    let result = transport::deliver(WebhookRequest {
        environment: context.settings.environment,
        destination: &material.destination,
        signing_secret: &material.signing_secret,
        signing_key_version: material.signing_key_version,
        event_id: delivery.outbox_event_id,
        timestamp,
        body: &body,
    })
    .await;
    let duration_ms = i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);
    match result {
        Ok(receipt) => {
            finish_success(context, delivery, attempt_id, duration_ms, receipt).await?;
        }
        Err(error) => {
            let http_status = error
                .http_status()
                .map(i16::try_from)
                .transpose()
                .map_err(|_| AppError::Internal {
                    category: "webhook_http_status",
                })?;
            finish_attempt_error(context, attempt_id, duration_ms, http_status, error).await?;
            finish_failure(
                context,
                delivery,
                error.code(),
                error.retryable(),
                http_status,
            )
            .await?;
        }
    }
    Ok(())
}

async fn load_material(
    context: &WorkerContext,
    delivery: &ClaimedDelivery,
) -> Result<DeliveryMaterial, WebhookError> {
    match RecipientType::try_from(delivery.recipient_kind.as_str())? {
        RecipientType::Application => load_application_material(context, delivery).await,
        RecipientType::SiliconWebhook => load_silicon_material(context, delivery).await,
    }
}

async fn load_application_material(
    context: &WorkerContext,
    delivery: &ClaimedDelivery,
) -> Result<DeliveryMaterial, WebhookError> {
    let endpoint_id = delivery
        .application_webhook_endpoint_id
        .ok_or(WebhookError::DestinationRejected)?;
    let signing_key_id = delivery.signing_key_id.ok_or(WebhookError::SigningFailed)?;
    let material = sqlx::query_as::<_, ApplicationMaterial>(
        r"
        SELECT *
        FROM iam_private.get_worker_application_webhook_material($1, $2)
        ",
    )
    .bind(endpoint_id)
    .bind(signing_key_id)
    .fetch_optional(&context.pool)
    .await
    .map_err(|_| WebhookError::Unavailable)?
    .ok_or(WebhookError::DestinationRejected)?;
    let destination = decrypt_url(
        context,
        EncryptionContext::tenant(
            ProtectedField::ApplicationWebhookUrl,
            material.application_id,
            endpoint_id,
        ),
        material.url_encryption_key_version,
        material.url_nonce,
        material.url_ciphertext,
    )?;
    let signing_secret = decrypt_secret(
        context,
        EncryptionContext::tenant(
            ProtectedField::ApplicationWebhookSigningSecret,
            material.application_id,
            signing_key_id,
        ),
        material.secret_encryption_key_version,
        material.secret_nonce,
        material.secret_ciphertext,
    )?;
    Ok(DeliveryMaterial {
        application_id: Some(material.application_id),
        destination,
        signing_secret,
        signing_key_version: material.secret_version,
    })
}

async fn load_silicon_material(
    context: &WorkerContext,
    delivery: &ClaimedDelivery,
) -> Result<DeliveryMaterial, WebhookError> {
    let endpoint_id = delivery
        .silicon_webhook_endpoint_id
        .ok_or(WebhookError::DestinationRejected)?;
    let signing_key_id = delivery
        .silicon_webhook_signing_key_id
        .ok_or(WebhookError::SigningFailed)?;
    let material = sqlx::query_as::<_, SiliconMaterial>(
        r"
        SELECT *
        FROM iam_private.get_worker_silicon_webhook_material($1, $2)
        ",
    )
    .bind(endpoint_id)
    .bind(signing_key_id)
    .fetch_optional(&context.pool)
    .await
    .map_err(|_| WebhookError::Unavailable)?
    .ok_or(WebhookError::DestinationRejected)?;
    let destination = decrypt_url(
        context,
        EncryptionContext::tenant(
            ProtectedField::SiliconWebhookUrl,
            material.organization_id,
            endpoint_id,
        ),
        material.url_encryption_key_version,
        material.url_nonce,
        material.url_ciphertext,
    )?;
    let signing_secret = decrypt_secret(
        context,
        EncryptionContext::tenant(
            ProtectedField::SiliconWebhookSigningSecret,
            material.organization_id,
            signing_key_id,
        ),
        material.secret_encryption_key_version,
        material.secret_nonce,
        material.secret_ciphertext,
    )?;
    Ok(DeliveryMaterial {
        application_id: None,
        destination,
        signing_secret,
        signing_key_version: material.secret_version,
    })
}

async fn load_event_data(
    context: &WorkerContext,
    delivery: &ClaimedDelivery,
    application_id: Option<Uuid>,
) -> Result<Value, WebhookError> {
    let Some(application_id) = application_id else {
        return Ok(delivery.payload.clone());
    };
    if !uses_captured_application_webhook_projection(&delivery.event_type) {
        return Ok(delivery.payload.clone());
    }
    let projection = sqlx::query_as::<_, ApplicationEventProjection>(
        r"
        SELECT
            projection_id,
            payload_ciphertext,
            payload_nonce,
            encryption_key_version
        FROM iam_private.get_worker_application_webhook_event_projection($1, $2)
        ",
    )
    .bind(delivery.outbox_event_id)
    .bind(application_id)
    .fetch_optional(&context.pool)
    .await
    .map_err(|_| WebhookError::Unavailable)?
    .ok_or(WebhookError::Unavailable)?;
    let plaintext = context
        .encryption
        .decrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookEventPayload,
                application_id,
                projection.projection_id,
            ),
            &encrypted_value(
                projection.encryption_key_version,
                projection.payload_nonce,
                projection.payload_ciphertext,
            )?,
        )
        .map_err(|_| WebhookError::Unavailable)?;
    let payload = serde_json::from_slice::<Value>(&plaintext)
        .map_err(|_| WebhookError::DestinationRejected)?;
    if !payload.is_object() {
        return Err(WebhookError::DestinationRejected);
    }
    Ok(payload)
}

fn wire_event_type(event_type: &str, schema_version: i16) -> Result<Cow<'_, str>, AppError> {
    if schema_version <= 0 {
        return Err(AppError::Internal {
            category: "webhook_event_schema_version",
        });
    }
    let suffix = format!(".v{schema_version}");
    if event_type.ends_with(&suffix) {
        return Ok(Cow::Borrowed(event_type));
    }
    if event_type.rsplit_once(".v").is_some_and(|(_, version)| {
        !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err(AppError::Internal {
            category: "webhook_event_schema_mismatch",
        });
    }
    Ok(Cow::Owned(format!("{event_type}{suffix}")))
}

fn decrypt_url(
    context: &WorkerContext,
    encryption_context: EncryptionContext,
    key_version: i16,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Url, WebhookError> {
    let plaintext = context
        .encryption
        .decrypt(
            encryption_context,
            &encrypted_value(key_version, nonce, ciphertext)?,
        )
        .map_err(|_| WebhookError::Unavailable)?;
    let value = std::str::from_utf8(&plaintext).map_err(|_| WebhookError::DestinationRejected)?;
    Url::parse(value).map_err(|_| WebhookError::DestinationRejected)
}

fn decrypt_secret(
    context: &WorkerContext,
    encryption_context: EncryptionContext,
    key_version: i16,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<SecretString, WebhookError> {
    let plaintext = context
        .encryption
        .decrypt(
            encryption_context,
            &encrypted_value(key_version, nonce, ciphertext)?,
        )
        .map_err(|_| WebhookError::Unavailable)?;
    let value = std::str::from_utf8(&plaintext).map_err(|_| WebhookError::SigningFailed)?;
    Ok(SecretString::from(value.to_owned()))
}

fn encrypted_value(
    key_version: i16,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<EncryptedValue, WebhookError> {
    Ok(EncryptedValue {
        key_version,
        nonce: nonce
            .try_into()
            .map_err(|_| WebhookError::DestinationRejected)?,
        ciphertext,
    })
}

async fn begin_attempt(
    context: &WorkerContext,
    delivery: &ClaimedDelivery,
) -> Result<Option<Uuid>, AppError> {
    let lease_seconds =
        i64::try_from(context.settings.worker.lease_duration.as_secs()).map_err(|_| {
            AppError::Internal {
                category: "worker_lease_duration",
            }
        })?;
    let attempt_id = Uuid::now_v7();
    let mut transaction = context.pool.begin().await?;
    let attempt_number = sqlx::query_scalar::<_, i32>(
        r"
        UPDATE iam.webhook_deliveries
        SET lease_expires_at = transaction_timestamp()
            + ($3::bigint * interval '1 second')
        WHERE id = $1
          AND status = 'processing'
          AND lease_owner = $2
          AND lease_expires_at > transaction_timestamp()
        RETURNING attempt_count
        ",
    )
    .bind(delivery.delivery_id)
    .bind(&context.instance_id)
    .bind(lease_seconds)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(attempt_number) = attempt_number else {
        transaction.rollback().await?;
        return Ok(None);
    };
    sqlx::query(
        r"
        INSERT INTO iam.webhook_delivery_attempts (
            id, delivery_id, attempt_number
        )
        VALUES ($1, $2, $3)
        ",
    )
    .bind(attempt_id)
    .bind(delivery.delivery_id)
    .bind(attempt_number)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(attempt_id))
}

async fn finish_success(
    context: &WorkerContext,
    delivery: &ClaimedDelivery,
    attempt_id: Uuid,
    duration_ms: i32,
    receipt: WebhookReceipt,
) -> Result<(), AppError> {
    let mut transaction = context.pool.begin().await?;
    sqlx::query(
        r"
        UPDATE iam.webhook_delivery_attempts
        SET finished_at = clock_timestamp(),
            http_status = $2,
            duration_ms = $3,
            response_digest = $4
        WHERE id = $1
        ",
    )
    .bind(attempt_id)
    .bind(
        i16::try_from(receipt.http_status).map_err(|_| AppError::Internal {
            category: "webhook_http_status",
        })?,
    )
    .bind(duration_ms)
    .bind(receipt.response_digest.as_slice())
    .execute(&mut *transaction)
    .await?;
    let result = sqlx::query(
        r"
        UPDATE iam.webhook_deliveries
        SET status = 'delivered',
            lease_owner = NULL,
            lease_expires_at = NULL,
            delivered_at = transaction_timestamp(),
            last_http_status = $3,
            last_error_code = NULL
        WHERE id = $1
          AND status = 'processing'
          AND lease_owner = $2
        ",
    )
    .bind(delivery.delivery_id)
    .bind(&context.instance_id)
    .bind(
        i16::try_from(receipt.http_status).map_err(|_| AppError::Internal {
            category: "webhook_http_status",
        })?,
    )
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::Internal {
            category: "webhook_lease_lost",
        });
    }
    transaction.commit().await?;
    Ok(())
}

async fn finish_attempt_error(
    context: &WorkerContext,
    attempt_id: Uuid,
    duration_ms: i32,
    http_status: Option<i16>,
    error: WebhookError,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.webhook_delivery_attempts
        SET finished_at = clock_timestamp(),
            duration_ms = $2,
            http_status = $3,
            error_code = $4
        WHERE id = $1
        ",
    )
    .bind(attempt_id)
    .bind(duration_ms)
    .bind(http_status)
    .bind(error.code())
    .execute(&context.pool)
    .await?;
    Ok(())
}

async fn finish_failure(
    context: &WorkerContext,
    delivery: &ClaimedDelivery,
    error_code: &'static str,
    retryable: bool,
    http_status: Option<i16>,
) -> Result<(), AppError> {
    let attempts_exhausted =
        delivery.cycle_attempt_count >= i32::from(context.settings.worker.max_attempts);
    let dead_letter = attempts_exhausted || !retryable;
    let delay = retry_delay_seconds(
        u32::try_from(delivery.cycle_attempt_count).unwrap_or(u32::MAX),
        context.settings.worker.max_retry_delay,
        delivery.delivery_id,
    );
    sqlx::query(
        r"
        UPDATE iam.webhook_deliveries
        SET status = CASE WHEN $3 THEN 'dead_letter' ELSE 'pending' END,
            lease_owner = NULL,
            lease_expires_at = NULL,
            next_attempt_at = CASE
                WHEN $3 THEN next_attempt_at
                ELSE transaction_timestamp() + ($4::bigint * interval '1 second')
            END,
            dead_lettered_at = CASE WHEN $3 THEN transaction_timestamp() ELSE NULL END,
            last_http_status = $5,
            last_error_code = $6
        WHERE id = $1
          AND status = 'processing'
          AND lease_owner = $2
        ",
    )
    .bind(delivery.delivery_id)
    .bind(&context.instance_id)
    .bind(dead_letter)
    .bind(delay)
    .bind(http_status)
    .bind(error_code)
    .execute(&context.pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RecipientType, wire_event_type};

    #[test]
    fn wire_event_names_have_exactly_one_matching_schema_suffix() {
        assert_eq!(
            wire_event_type("organization.updated.v1", 1)
                .ok()
                .as_deref(),
            Some("organization.updated.v1")
        );
        assert_eq!(
            wire_event_type("session.logout", 1).ok().as_deref(),
            Some("session.logout.v1")
        );
        assert!(wire_event_type("organization.updated.v2", 1).is_err());
        assert!(wire_event_type("organization.updated", 0).is_err());
    }

    #[test]
    fn recipient_types_fail_closed_after_legacy_hook_retirement() {
        assert_eq!(
            RecipientType::try_from("application"),
            Ok(RecipientType::Application)
        );
        assert_eq!(
            RecipientType::try_from("silicon_webhook"),
            Ok(RecipientType::SiliconWebhook)
        );
        assert!(RecipientType::try_from("silicon_hook").is_err());
        assert!(RecipientType::try_from("unknown").is_err());
    }

    #[test]
    fn claim_waits_for_prior_aggregate_expansion_before_destination_ordering() {
        let source = include_str!("webhook.rs")
            .split_once("#[cfg(test)]")
            .map_or(include_str!("webhook.rs"), |(production, _)| production);

        for predicate in [
            "FROM iam.outbox_events AS prior_unexpanded_event",
            "prior_unexpanded_event.organization_id\n                        IS NOT DISTINCT FROM event.organization_id",
            "prior_unexpanded_event.aggregate_type = event.aggregate_type",
            "prior_unexpanded_event.aggregate_id = event.aggregate_id",
            "prior_unexpanded_event.global_sequence < event.global_sequence",
            "prior_unexpanded_event.status IN ('pending', 'processing')",
            "prior_recipient.ordering_key = recipient.ordering_key",
        ] {
            assert!(
                source.contains(predicate),
                "missing claim guard: {predicate}"
            );
        }
    }
}
