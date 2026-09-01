//! Redacted failed-delivery inspection and dead-letter replay.

use std::{borrow::Cow, collections::HashMap};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Serialize;
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::{ActorRef, ActorType},
    error::AppError,
    infrastructure::postgres::{
        events::{self, AggregateVersion, AuditRecord},
        idempotency::{self, IdempotencyClaim},
        tokens::AccessContext,
    },
};

use super::{
    access,
    model::{DeliveryQuery, WebhookDelivery, WebhookDeliveryAttempt, WebhookDeliveryPage},
    pagination::{self, Cursor},
};

const CAPABILITY: &str = "deliveries.manage";
const ACTION: &str = "platform_admin.manage";
const REPLAY_ROUTE: &str = "/api/v1/admin/delivery-failures/{delivery_id}/replays";
const ATTEMPT_HISTORY_LIMIT: i64 = 20;

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
    fn into_public(self, attempts: Vec<WebhookDeliveryAttempt>) -> WebhookDelivery {
        WebhookDelivery {
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
struct AttemptRow {
    delivery_id: Uuid,
    attempt: i32,
    started_at: OffsetDateTime,
    duration_ms: Option<i32>,
    outcome: String,
    response_status: Option<i16>,
    response_digest: Option<Vec<u8>>,
}

impl AttemptRow {
    fn into_public(self) -> WebhookDeliveryAttempt {
        WebhookDeliveryAttempt {
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

#[derive(FromRow)]
struct ReplayRow {
    id: Uuid,
    outbox_event_id: Uuid,
    manual_replay_count: i32,
}

#[derive(Serialize)]
struct ReplayRequest {
    delivery_id: Uuid,
}

pub(super) async fn list_failures(
    State(state): State<ApiState>,
    Authenticated(access_context): Authenticated,
    Query(query): Query<DeliveryQuery>,
) -> Result<Json<WebhookDeliveryPage>, AppError> {
    validate_destination_type(query.destination_type.as_deref())?;
    let carbon_id = access::require_carbon(&access_context)?;
    let limit = pagination::limit(query.limit)?;
    let cursor = pagination::decode(query.cursor.as_deref())?;
    let mut transaction = access::begin_serializable(&state, carbon_id).await?;
    access::require_platform_capability(&mut transaction, carbon_id, CAPABILITY).await?;

    let mut builder = QueryBuilder::<Postgres>::new(
        r"
        SELECT
            delivery.id,
            recipient.recipient_kind AS destination_type,
            COALESCE(endpoint.application_id, hook.silicon_id) AS destination_id,
            event.id AS event_id,
            event.event_type,
            event.aggregate_id,
            event.aggregate_version,
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
            delivery.created_at,
            delivery.updated_at
        FROM iam.webhook_deliveries AS delivery
        JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.outbox_event_id = delivery.outbox_event_id
         AND recipient.id = delivery.recipient_id
        LEFT JOIN iam.application_webhook_endpoints AS endpoint
          ON endpoint.id = recipient.application_webhook_endpoint_id
        LEFT JOIN iam.silicon_hooks AS hook
          ON hook.id = recipient.silicon_hook_id
        WHERE (
            delivery.status = 'dead_letter'
            OR (delivery.status = 'pending' AND delivery.last_error_code IS NOT NULL)
        )
        ",
    );
    if let Some(destination_type) = query.destination_type {
        builder.push(" AND recipient.recipient_kind = ");
        builder.push_bind(destination_type);
    }
    if let Some(cursor) = cursor {
        builder.push(" AND (delivery.created_at, delivery.id) < (");
        builder.push_bind(cursor.at);
        builder.push(", ");
        builder.push_bind(cursor.id);
        builder.push(")");
    }
    builder.push(" ORDER BY delivery.created_at DESC, delivery.id DESC LIMIT ");
    builder.push_bind(limit + 1);
    let mut rows = builder
        .build_query_as::<DeliveryRow>()
        .fetch_all(&mut *transaction)
        .await?;
    let page = pagination::page(&mut rows, limit, |row| Cursor {
        at: row.created_at,
        id: row.id,
    })?;
    let delivery_ids = rows.iter().map(|row| row.id).collect::<Vec<_>>();
    let attempts = fetch_attempts(&mut transaction, &delivery_ids).await?;
    transaction.commit().await?;

    let mut attempts_by_delivery = attempts.into_iter().fold(
        HashMap::<Uuid, Vec<WebhookDeliveryAttempt>>::new(),
        |mut grouped, row| {
            grouped
                .entry(row.delivery_id)
                .or_default()
                .push(row.into_public());
            grouped
        },
    );
    Ok(Json(WebhookDeliveryPage {
        items: rows
            .into_iter()
            .map(|row| {
                let attempts = attempts_by_delivery.remove(&row.id).unwrap_or_default();
                row.into_public(attempts)
            })
            .collect(),
        page,
    }))
}

pub(super) async fn replay(
    State(state): State<ApiState>,
    Authenticated(access_context): Authenticated,
    Path(delivery_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let carbon_id = access::require_carbon(&access_context)?;
    let request = ReplayRequest { delivery_id };
    let mut transaction = access::begin_serializable(&state, carbon_id).await?;
    access::require_platform_capability(&mut transaction, carbon_id, CAPABILITY).await?;
    let claim = access::claim(
        &mut transaction,
        &state,
        &headers,
        carbon_id,
        REPLAY_ROUTE,
        &request,
    )
    .await?;
    if let IdempotencyClaim::Replay(_) = claim {
        transaction.commit().await?;
        return access::empty(StatusCode::ACCEPTED, true);
    }
    let IdempotencyClaim::Acquired(lease) = claim else {
        return Err(AppError::Internal {
            category: "delivery_replay_claim",
        });
    };
    access::consume_step_up(
        &mut transaction,
        &state,
        &headers,
        &access_context,
        ACTION,
        Some(delivery_id),
    )
    .await?;
    requeue_delivery(&mut transaction, &access_context, delivery_id).await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        lease,
        StatusCode::ACCEPTED.as_u16(),
        &[],
    )
    .await?;
    transaction.commit().await?;
    access::empty(StatusCode::ACCEPTED, false)
}

async fn requeue_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    access_context: &AccessContext,
    delivery_id: Uuid,
) -> Result<(), AppError> {
    let current_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM iam.webhook_deliveries WHERE id = $1 FOR UPDATE",
    )
    .bind(delivery_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AppError::NotFound)?;
    if current_status != "dead_letter" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("delivery_not_dead_lettered"),
        });
    }
    let row = sqlx::query_as::<_, ReplayRow>(
        r"
        UPDATE iam.webhook_deliveries
        SET status = 'pending',
            cycle_attempt_count = 0,
            manual_replay_count = manual_replay_count + 1,
            next_attempt_at = transaction_timestamp(),
            lease_owner = NULL,
            lease_expires_at = NULL,
            delivered_at = NULL,
            dead_lettered_at = NULL,
            last_http_status = NULL,
            last_error_code = NULL
        WHERE id = $1 AND status = 'dead_letter'
        RETURNING id, outbox_event_id, manual_replay_count
        ",
    )
    .bind(delivery_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AppError::Internal {
        category: "delivery_replay_transition",
    })?;
    let aggregate = AggregateVersion {
        aggregate_type: "webhook_delivery",
        aggregate_id: row.id,
        version: i64::from(row.manual_replay_count),
    };
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: ActorType::Carbon,
                id: access_context.subject.id,
            }),
            authentication_session_id: Some(access_context.authentication_session_id),
            organization_id: None,
            application_id: access_context.client_application_id,
            action: "platform.delivery.replayed",
            target_type: "webhook_delivery",
            target_id: Some(row.id),
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state: Some(serde_json::json!({ "status": "dead_letter" })),
            after_state: Some(serde_json::json!({ "status": "pending" })),
            metadata: serde_json::json!({
                "event_id": row.outbox_event_id,
                "manual_replay_count": row.manual_replay_count
            }),
        },
    )
    .await?;
    Ok(())
}

async fn fetch_attempts(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    delivery_ids: &[Uuid],
) -> Result<Vec<AttemptRow>, AppError> {
    if delivery_ids.is_empty() {
        return Ok(Vec::new());
    }
    Ok(sqlx::query_as::<_, AttemptRow>(
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
        SELECT
            delivery_id, attempt, started_at, duration_ms, outcome,
            response_status, response_digest
        FROM ranked
        WHERE history_rank <= $2
        ORDER BY delivery_id, attempt
        ",
    )
    .bind(delivery_ids)
    .bind(ATTEMPT_HISTORY_LIMIT)
    .fetch_all(&mut **transaction)
    .await?)
}

fn validate_destination_type(value: Option<&str>) -> Result<(), AppError> {
    if value.is_some_and(|value| !matches!(value, "application" | "silicon_hook")) {
        return Err(AppError::Validation {
            details: serde_json::json!({
                "field": "destination_type",
                "message": "must be application or silicon_hook"
            }),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_type_is_deny_by_default() {
        assert!(validate_destination_type(Some("application")).is_ok());
        assert!(validate_destination_type(Some("silicon_hook")).is_ok());
        assert!(matches!(
            validate_destination_type(Some("notification")),
            Err(AppError::Validation { .. })
        ));
    }

    #[test]
    fn response_digests_are_algorithm_labeled() {
        let attempt = AttemptRow {
            delivery_id: Uuid::nil(),
            attempt: 1,
            started_at: OffsetDateTime::UNIX_EPOCH,
            duration_ms: Some(1),
            outcome: "success".to_owned(),
            response_status: Some(200),
            response_digest: Some(vec![0xab; 32]),
        }
        .into_public();
        assert_eq!(
            attempt.response_body_digest.as_deref(),
            Some("sha256:abababababababababababababababababababababababababababababababab")
        );
    }

    #[test]
    fn replay_idempotency_route_follows_the_shared_contract() {
        assert!(crate::infrastructure::postgres::idempotency::validate_route(REPLAY_ROUTE).is_ok());
    }
}
