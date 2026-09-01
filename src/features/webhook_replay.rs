//! Shared persistence primitives for recipient-safe webhook dead-letter replay.

use serde_json::Value;
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, FromRow)]
pub(crate) struct DeadLetterRecord {
    pub(crate) delivery_id: Uuid,
    pub(crate) recipient_id: Uuid,
    pub(crate) event_id: Uuid,
    pub(crate) organization_id: Option<Uuid>,
    pub(crate) event_type: String,
    pub(crate) payload: Value,
    pub(crate) occurred_at: OffsetDateTime,
    pub(crate) aggregate_type: String,
    pub(crate) aggregate_id: Uuid,
    pub(crate) aggregate_version: i64,
    pub(crate) status: String,
    pub(crate) attempt_count: i32,
    pub(crate) cycle_attempt_count: i32,
    pub(crate) manual_replay_count: i32,
    pub(crate) last_http_status: Option<i16>,
    pub(crate) last_error_code: Option<String>,
    pub(crate) dead_lettered_at: Option<OffsetDateTime>,
    pub(crate) version: i64,
}

const RECORD_PROJECTION: &str = r"
    delivery.id AS delivery_id,
    recipient.id AS recipient_id,
    event.id AS event_id,
    event.organization_id,
    event.event_type,
    event.payload,
    event.created_at AS occurred_at,
    event.aggregate_type,
    event.aggregate_id,
    event.aggregate_version,
    delivery.status,
    delivery.attempt_count,
    delivery.cycle_attempt_count,
    delivery.manual_replay_count,
    delivery.last_http_status,
    delivery.last_error_code,
    delivery.dead_lettered_at,
    delivery.version
";

pub(crate) async fn list_application_dead_letters(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    cursor_at: Option<OffsetDateTime>,
    cursor_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<DeadLetterRecord>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new("SELECT ");
    query.push(RECORD_PROJECTION).push(
        r"
        FROM iam.webhook_deliveries AS delivery
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.id = delivery.recipient_id
         AND recipient.outbox_event_id = delivery.outbox_event_id
         AND recipient.recipient_kind = 'application'
        JOIN iam.application_webhook_endpoints AS endpoint
          ON endpoint.id = recipient.application_webhook_endpoint_id
         AND endpoint.application_id = ",
    );
    query.push_bind(application_id).push(
        r"
        JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
        WHERE delivery.status = 'dead_letter'
        ",
    );
    if let (Some(cursor_at), Some(cursor_id)) = (cursor_at, cursor_id) {
        query
            .push(" AND (delivery.dead_lettered_at, delivery.id) < (")
            .push_bind(cursor_at)
            .push(", ")
            .push_bind(cursor_id)
            .push(")");
    }
    query
        .push(" ORDER BY delivery.dead_lettered_at DESC, delivery.id DESC LIMIT ")
        .push_bind(limit);
    query
        .build_query_as::<DeadLetterRecord>()
        .fetch_all(&mut **transaction)
        .await
}

pub(crate) async fn lock_application_dead_letters(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    delivery_ids: &[Uuid],
) -> Result<Vec<DeadLetterRecord>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new("SELECT ");
    query.push(RECORD_PROJECTION).push(
        r"
        FROM iam.webhook_deliveries AS delivery
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.id = delivery.recipient_id
         AND recipient.outbox_event_id = delivery.outbox_event_id
         AND recipient.recipient_kind = 'application'
        JOIN iam.application_webhook_endpoints AS endpoint
          ON endpoint.id = recipient.application_webhook_endpoint_id
         AND endpoint.application_id = ",
    );
    query.push_bind(application_id).push(
        r"
        JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
        WHERE delivery.id = ANY(",
    );
    query.push_bind(delivery_ids).push(
        r"::uuid[])
          AND delivery.status = 'dead_letter'
        ORDER BY event.global_sequence, delivery.id
        FOR UPDATE OF delivery, recipient
        ",
    );
    query
        .build_query_as::<DeadLetterRecord>()
        .fetch_all(&mut **transaction)
        .await
}

pub(crate) async fn list_silicon_dead_letters(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
    cursor_at: Option<OffsetDateTime>,
    cursor_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<DeadLetterRecord>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new("SELECT ");
    query.push(RECORD_PROJECTION).push(
        r"
        FROM iam.webhook_deliveries AS delivery
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.id = delivery.recipient_id
         AND recipient.outbox_event_id = delivery.outbox_event_id
         AND recipient.recipient_kind = 'silicon_webhook'
        JOIN iam.silicon_webhook_endpoints AS endpoint
          ON endpoint.id = recipient.silicon_webhook_endpoint_id
         AND endpoint.organization_id = ",
    );
    query
        .push_bind(organization_id)
        .push(" AND endpoint.silicon_id = ")
        .push_bind(silicon_id)
        .push(
            r"
        JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
        WHERE delivery.status = 'dead_letter'
        ",
        );
    if let (Some(cursor_at), Some(cursor_id)) = (cursor_at, cursor_id) {
        query
            .push(" AND (delivery.dead_lettered_at, delivery.id) < (")
            .push_bind(cursor_at)
            .push(", ")
            .push_bind(cursor_id)
            .push(")");
    }
    query
        .push(" ORDER BY delivery.dead_lettered_at DESC, delivery.id DESC LIMIT ")
        .push_bind(limit);
    query
        .build_query_as::<DeadLetterRecord>()
        .fetch_all(&mut **transaction)
        .await
}

pub(crate) async fn lock_silicon_dead_letters(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: Uuid,
    delivery_ids: &[Uuid],
) -> Result<Vec<DeadLetterRecord>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new("SELECT ");
    query.push(RECORD_PROJECTION).push(
        r"
        FROM iam.webhook_deliveries AS delivery
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.id = delivery.recipient_id
         AND recipient.outbox_event_id = delivery.outbox_event_id
         AND recipient.recipient_kind = 'silicon_webhook'
        JOIN iam.silicon_webhook_endpoints AS endpoint
          ON endpoint.id = recipient.silicon_webhook_endpoint_id
         AND endpoint.organization_id = ",
    );
    query
        .push_bind(organization_id)
        .push(" AND endpoint.silicon_id = ")
        .push_bind(silicon_id)
        .push(
            r"
        JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
        WHERE delivery.id = ANY(",
        )
        .push_bind(delivery_ids)
        .push(
            r"::uuid[])
          AND delivery.status = 'dead_letter'
        ORDER BY event.global_sequence, delivery.id
        FOR UPDATE OF delivery, recipient
        ",
        );
    query
        .build_query_as::<DeadLetterRecord>()
        .fetch_all(&mut **transaction)
        .await
}

pub(crate) async fn replay_application_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &DeadLetterRecord,
    endpoint_id: Uuid,
    signing_key_id: Uuid,
    replay_batch_id: Uuid,
) -> Result<DeadLetterRecord, sqlx::Error> {
    let ordering_key = manual_replay_ordering_key("application", endpoint_id, replay_batch_id);
    sqlx::query(
        r"
        UPDATE iam.outbox_event_recipients
        SET application_webhook_endpoint_id = $2, ordering_key = $3
        WHERE id = $1 AND outbox_event_id = $4 AND recipient_kind = 'application'
        ",
    )
    .bind(delivery.recipient_id)
    .bind(endpoint_id)
    .bind(ordering_key)
    .bind(delivery.event_id)
    .execute(&mut **transaction)
    .await?;
    reset_delivery(transaction, delivery, Some(signing_key_id), None).await
}

pub(crate) async fn replay_silicon_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &DeadLetterRecord,
    endpoint_id: Uuid,
    signing_key_id: Uuid,
    replay_batch_id: Uuid,
) -> Result<DeadLetterRecord, sqlx::Error> {
    let ordering_key = manual_replay_ordering_key("silicon_webhook", endpoint_id, replay_batch_id);
    sqlx::query(
        r"
        UPDATE iam.outbox_event_recipients
        SET silicon_webhook_endpoint_id = $2, ordering_key = $3
        WHERE id = $1 AND outbox_event_id = $4 AND recipient_kind = 'silicon_webhook'
        ",
    )
    .bind(delivery.recipient_id)
    .bind(endpoint_id)
    .bind(ordering_key)
    .bind(delivery.event_id)
    .execute(&mut **transaction)
    .await?;
    reset_delivery(transaction, delivery, None, Some(signing_key_id)).await
}

async fn reset_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &DeadLetterRecord,
    application_signing_key_id: Option<Uuid>,
    silicon_signing_key_id: Option<Uuid>,
) -> Result<DeadLetterRecord, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        r"
        WITH reset AS (
            UPDATE iam.webhook_deliveries
            SET signing_key_id = ",
    );
    query
        .push_bind(application_signing_key_id)
        .push(", silicon_webhook_signing_key_id = ")
        .push_bind(silicon_signing_key_id)
        .push(
            r",
                status = 'pending',
                cycle_attempt_count = 0,
                manual_replay_count = manual_replay_count + 1,
                next_attempt_at = transaction_timestamp(),
                lease_owner = NULL,
                lease_expires_at = NULL,
                delivered_at = NULL,
                dead_lettered_at = NULL,
                last_http_status = NULL,
                last_error_code = NULL
            WHERE id = ",
        )
        .push_bind(delivery.delivery_id)
        .push(
            r" AND status = 'dead_letter'
            RETURNING *
        )
        SELECT ",
        )
        .push(RECORD_PROJECTION)
        .push(
            r"
        FROM reset AS delivery
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.id = delivery.recipient_id
         AND recipient.outbox_event_id = delivery.outbox_event_id
        JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
        ",
        );
    query
        .build_query_as::<DeadLetterRecord>()
        .fetch_one(&mut **transaction)
        .await
}

fn manual_replay_ordering_key(kind: &str, endpoint_id: Uuid, replay_batch_id: Uuid) -> String {
    format!("manual-replay:{kind}:{endpoint_id}:{replay_batch_id}")
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{DeadLetterRecord, manual_replay_ordering_key};

    #[test]
    fn manual_replay_batch_has_one_destination_bound_ordering_lane() {
        let _delivery = DeadLetterRecord {
            delivery_id: Uuid::from_u128(1),
            recipient_id: Uuid::from_u128(2),
            event_id: Uuid::from_u128(3),
            organization_id: None,
            event_type: "application.updated".to_owned(),
            payload: json!({}),
            occurred_at: OffsetDateTime::UNIX_EPOCH,
            aggregate_type: "application".to_owned(),
            aggregate_id: Uuid::from_u128(4),
            aggregate_version: 2,
            status: "dead_letter".to_owned(),
            attempt_count: 5,
            cycle_attempt_count: 5,
            manual_replay_count: 0,
            last_http_status: Some(503),
            last_error_code: Some("remote_server_error".to_owned()),
            dead_lettered_at: Some(OffsetDateTime::UNIX_EPOCH),
            version: 3,
        };
        let endpoint_id = Uuid::from_u128(5);
        let other_endpoint_id = Uuid::from_u128(6);
        let replay_batch_id = Uuid::from_u128(7);
        let other_batch_id = Uuid::from_u128(8);
        let expected = format!("manual-replay:application:{endpoint_id}:{replay_batch_id}");
        assert_eq!(
            manual_replay_ordering_key("application", endpoint_id, replay_batch_id),
            expected
        );
        assert_eq!(
            manual_replay_ordering_key("application", endpoint_id, replay_batch_id),
            manual_replay_ordering_key("application", endpoint_id, replay_batch_id),
        );
        assert_ne!(
            manual_replay_ordering_key("application", endpoint_id, replay_batch_id),
            manual_replay_ordering_key("application", endpoint_id, other_batch_id),
        );
        assert_ne!(
            manual_replay_ordering_key("application", endpoint_id, replay_batch_id),
            manual_replay_ordering_key("application", other_endpoint_id, replay_batch_id),
        );
    }
}
