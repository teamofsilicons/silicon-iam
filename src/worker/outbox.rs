//! Expands committed domain events into immutable recipient deliveries.

use futures::{StreamExt as _, stream};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::error::AppError;

use super::{WorkerContext, delivery_claim_limit, retry_delay_seconds};

#[derive(sqlx::FromRow)]
struct ClaimedEvent {
    id: Uuid,
    organization_id: Option<Uuid>,
    aggregate_type: String,
    aggregate_id: Uuid,
    payload: Value,
    attempt_count: i32,
    created_at: time::OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct ApplicationRecipient {
    endpoint_id: Uuid,
    signing_key_id: Uuid,
}

#[derive(sqlx::FromRow)]
struct SiliconRecipient {
    hook_id: Uuid,
}

pub(super) async fn process_batch(context: &WorkerContext) -> Result<(), AppError> {
    let claim_limit = delivery_claim_limit(context)?;
    let lease_seconds =
        i64::try_from(context.settings.worker.lease_duration.as_secs()).map_err(|_| {
            AppError::Internal {
                category: "worker_lease_duration",
            }
        })?;
    let events = sqlx::query_as::<_, ClaimedEvent>(
        r"
        WITH candidates AS (
            SELECT event.id
            FROM iam.outbox_events AS event
            WHERE (
                    event.status = 'pending'
                    AND event.available_at <= transaction_timestamp()
                ) OR (
                    event.status = 'processing'
                    AND event.lease_expires_at <= transaction_timestamp()
                )
            ORDER BY event.available_at, event.global_sequence
            FOR UPDATE SKIP LOCKED
            LIMIT $1
        )
        UPDATE iam.outbox_events AS event
        SET status = 'processing',
            lease_owner = $2,
            lease_expires_at = transaction_timestamp()
                + ($3::bigint * interval '1 second'),
            attempt_count = event.attempt_count + 1,
            last_error_code = NULL
        FROM candidates
        WHERE event.id = candidates.id
        RETURNING
            event.id,
            event.organization_id,
            event.aggregate_type,
            event.aggregate_id,
            event.payload,
            event.attempt_count,
            event.created_at
        ",
    )
    .bind(claim_limit)
    .bind(&context.instance_id)
    .bind(lease_seconds)
    .fetch_all(&context.pool)
    .await?;

    let results = stream::iter(events)
        .map(|event| async move { process_event(context, &event).await })
        .buffer_unordered(context.settings.worker.delivery_concurrency.get())
        .collect::<Vec<_>>()
        .await;
    for result in results {
        result?;
    }
    Ok(())
}

async fn process_event(context: &WorkerContext, event: &ClaimedEvent) -> Result<(), AppError> {
    if let Err(error) = expand_event(context, event).await {
        let code = match error {
            AppError::Internal { category } => category,
            _ => "outbox_expansion",
        };
        mark_failure(context, event, code).await?;
    }
    Ok(())
}

async fn expand_event(context: &WorkerContext, event: &ClaimedEvent) -> Result<(), AppError> {
    let mut transaction = context.pool.begin().await?;
    let owns_lease = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM iam.outbox_events
            WHERE id = $1
              AND status = 'processing'
              AND lease_owner = $2
              AND lease_expires_at > transaction_timestamp()
            FOR UPDATE
        )
        ",
    )
    .bind(event.id)
    .bind(&context.instance_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !owns_lease {
        transaction.rollback().await?;
        return Ok(());
    }

    expand_application_recipients(&mut transaction, event).await?;
    expand_silicon_recipients(&mut transaction, event).await?;

    let result = sqlx::query(
        r"
        UPDATE iam.outbox_events
        SET status = 'completed',
            lease_owner = NULL,
            lease_expires_at = NULL,
            completed_at = transaction_timestamp(),
            last_error_code = NULL
        WHERE id = $1
          AND status = 'processing'
          AND lease_owner = $2
        ",
    )
    .bind(event.id)
    .bind(&context.instance_id)
    .execute(&mut *transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::Internal {
            category: "outbox_lease_lost",
        });
    }
    transaction.commit().await?;
    Ok(())
}

async fn expand_application_recipients(
    transaction: &mut Transaction<'_, Postgres>,
    event: &ClaimedEvent,
) -> Result<(), sqlx::Error> {
    let subject_id = payload_uuid(
        &event.payload,
        &[
            "subject_principal_id",
            "principal_id",
            "carbon_id",
            "silicon_id",
        ],
    );
    let application_id = payload_uuid(&event.payload, &["application_id"]);
    if subject_id.is_none() && application_id.is_none() {
        return Ok(());
    }

    let recipients = sqlx::query_as::<_, ApplicationRecipient>(
        r"
        SELECT endpoint_id, signing_key_id
        FROM iam_private.list_worker_application_webhook_recipients($1, $2, $3, $4)
        ",
    )
    .bind(event.organization_id)
    .bind(subject_id)
    .bind(application_id)
    .bind(event.created_at)
    .fetch_all(&mut **transaction)
    .await?;
    for recipient in recipients {
        insert_application_recipient(
            transaction,
            event,
            recipient.endpoint_id,
            recipient.signing_key_id,
        )
        .await?;
    }
    Ok(())
}

async fn expand_silicon_recipients(
    transaction: &mut Transaction<'_, Postgres>,
    event: &ClaimedEvent,
) -> Result<(), sqlx::Error> {
    let Some(organization_id) = event.organization_id else {
        return Ok(());
    };
    let recipients = sqlx::query_as::<_, SiliconRecipient>(
        r"
        SELECT hook.id AS hook_id
        FROM iam.silicon_hooks AS hook
        JOIN iam.silicons AS silicon
          ON silicon.organization_id = hook.organization_id
         AND silicon.id = hook.silicon_id
        JOIN iam.principals AS principal
          ON principal.id = silicon.id
         AND principal.kind = 'silicon'
        WHERE hook.organization_id = $1
          AND hook.status = 'active'
          AND principal.status = 'active'
        ORDER BY hook.id
        ",
    )
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?;
    for recipient in recipients {
        insert_silicon_recipient(transaction, event, recipient.hook_id).await?;
    }
    Ok(())
}

async fn insert_application_recipient(
    transaction: &mut Transaction<'_, Postgres>,
    event: &ClaimedEvent,
    endpoint_id: Uuid,
    signing_key_id: Uuid,
) -> Result<(), sqlx::Error> {
    let recipient_id = Uuid::now_v7();
    let ordering_key = format!("{}:{}", event.aggregate_type, event.aggregate_id);
    let insert_result = sqlx::query(
        r"
        INSERT INTO iam.outbox_event_recipients (
            id, outbox_event_id, recipient_kind,
            application_webhook_endpoint_id, ordering_key
        ) VALUES ($1, $2, 'application', $3, $4)
        ON CONFLICT (outbox_event_id, application_webhook_endpoint_id)
            WHERE recipient_kind = 'application'
        DO NOTHING
        ",
    )
    .bind(recipient_id)
    .bind(event.id)
    .bind(endpoint_id)
    .bind(&ordering_key)
    .execute(&mut **transaction)
    .await?;
    let persisted_recipient_id = if insert_result.rows_affected() == 1 {
        recipient_id
    } else {
        sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id
            FROM iam.outbox_event_recipients
            WHERE outbox_event_id = $1
              AND recipient_kind = 'application'
              AND application_webhook_endpoint_id = $2
              AND ordering_key = $3
            ",
        )
        .bind(event.id)
        .bind(endpoint_id)
        .bind(&ordering_key)
        .fetch_one(&mut **transaction)
        .await?
    };

    sqlx::query(
        r"
        INSERT INTO iam.webhook_deliveries (
            id, outbox_event_id, recipient_id, signing_key_id
        ) VALUES ($1, $2, $3, $4)
        ON CONFLICT (outbox_event_id, recipient_id) DO NOTHING
        ",
    )
    .bind(Uuid::now_v7())
    .bind(event.id)
    .bind(persisted_recipient_id)
    .bind(signing_key_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_silicon_recipient(
    transaction: &mut Transaction<'_, Postgres>,
    event: &ClaimedEvent,
    hook_id: Uuid,
) -> Result<(), sqlx::Error> {
    let recipient_id = Uuid::now_v7();
    let ordering_key = format!("{}:{}", event.aggregate_type, event.aggregate_id);
    let insert_result = sqlx::query(
        r"
        INSERT INTO iam.outbox_event_recipients (
            id, outbox_event_id, recipient_kind, silicon_hook_id, ordering_key
        ) VALUES ($1, $2, 'silicon_hook', $3, $4)
        ON CONFLICT (outbox_event_id, silicon_hook_id)
            WHERE recipient_kind = 'silicon_hook'
        DO NOTHING
        ",
    )
    .bind(recipient_id)
    .bind(event.id)
    .bind(hook_id)
    .bind(&ordering_key)
    .execute(&mut **transaction)
    .await?;
    let persisted_recipient_id = if insert_result.rows_affected() == 1 {
        recipient_id
    } else {
        sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id
            FROM iam.outbox_event_recipients
            WHERE outbox_event_id = $1
              AND recipient_kind = 'silicon_hook'
              AND silicon_hook_id = $2
              AND ordering_key = $3
            ",
        )
        .bind(event.id)
        .bind(hook_id)
        .bind(&ordering_key)
        .fetch_one(&mut **transaction)
        .await?
    };

    sqlx::query(
        r"
        INSERT INTO iam.webhook_deliveries (
            id, outbox_event_id, recipient_id
        ) VALUES ($1, $2, $3)
        ON CONFLICT (outbox_event_id, recipient_id) DO NOTHING
        ",
    )
    .bind(Uuid::now_v7())
    .bind(event.id)
    .bind(persisted_recipient_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn mark_failure(
    context: &WorkerContext,
    event: &ClaimedEvent,
    error_code: &'static str,
) -> Result<(), sqlx::Error> {
    let dead_letter = event.attempt_count >= i32::from(context.settings.worker.max_attempts);
    let delay = retry_delay_seconds(
        u32::try_from(event.attempt_count).unwrap_or(u32::MAX),
        context.settings.worker.max_retry_delay,
        event.id,
    );
    sqlx::query(
        r"
        UPDATE iam.outbox_events
        SET status = CASE WHEN $3 THEN 'dead_letter' ELSE 'pending' END,
            lease_owner = NULL,
            lease_expires_at = NULL,
            available_at = CASE
                WHEN $3 THEN available_at
                ELSE transaction_timestamp() + ($4::bigint * interval '1 second')
            END,
            last_error_code = $5,
            dead_lettered_at = CASE WHEN $3 THEN transaction_timestamp() ELSE NULL END
        WHERE id = $1
          AND status = 'processing'
          AND lease_owner = $2
        ",
    )
    .bind(event.id)
    .bind(&context.instance_id)
    .bind(dead_letter)
    .bind(delay)
    .bind(error_code)
    .execute(&context.pool)
    .await?;
    Ok(())
}

fn payload_uuid(payload: &Value, keys: &[&str]) -> Option<Uuid> {
    keys.iter().find_map(|key| {
        payload
            .get(*key)
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
    })
}
