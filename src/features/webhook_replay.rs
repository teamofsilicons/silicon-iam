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

/// Rechecks the persisted recipient binding for a logout control event.
///
/// Logout revokes the delegated authority that normally protects historical
/// Application event replay. The original dead-letter recipient remains the
/// sole authority for replaying this secret-free revocation notification.
pub(crate) async fn application_logout_dead_letter_is_bound_to(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    delivery: &DeadLetterRecord,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM iam.webhook_deliveries AS persisted_delivery
            JOIN iam.outbox_event_recipients AS recipient
              ON recipient.id = persisted_delivery.recipient_id
             AND recipient.outbox_event_id = persisted_delivery.outbox_event_id
             AND recipient.recipient_kind = 'application'
            JOIN iam.application_webhook_endpoints AS endpoint
              ON endpoint.id = recipient.application_webhook_endpoint_id
            JOIN iam.outbox_events AS event
              ON event.id = persisted_delivery.outbox_event_id
            WHERE persisted_delivery.id = $1
              AND persisted_delivery.recipient_id = $2
              AND persisted_delivery.outbox_event_id = $3
              AND persisted_delivery.status = 'dead_letter'
              AND endpoint.application_id = $4
              AND event.event_type = 'session.logout'
              AND event.aggregate_type = 'authentication_session'
        )
        ",
    )
    .bind(delivery.delivery_id)
    .bind(delivery.recipient_id)
    .bind(delivery.event_id)
    .bind(application_id)
    .fetch_one(&mut **transaction)
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
    let updated = sqlx::query(
        r"
        UPDATE iam.outbox_event_recipients AS recipient
        SET application_webhook_endpoint_id = $2, ordering_key = $3
        FROM iam.application_webhook_endpoints AS previous_endpoint,
             iam.application_webhook_endpoints AS replay_endpoint
        WHERE recipient.id = $1
          AND recipient.outbox_event_id = $4
          AND recipient.recipient_kind = 'application'
          AND previous_endpoint.id = recipient.application_webhook_endpoint_id
          AND replay_endpoint.id = $2
          AND replay_endpoint.application_id = previous_endpoint.application_id
        ",
    )
    .bind(delivery.recipient_id)
    .bind(endpoint_id)
    .bind(ordering_key)
    .bind(delivery.event_id)
    .execute(&mut **transaction)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }
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

    use super::{
        DeadLetterRecord, application_logout_dead_letter_is_bound_to,
        lock_application_dead_letters, manual_replay_ordering_key, replay_application_delivery,
    };

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

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    #[allow(
        clippy::too_many_lines,
        reason = "one fresh-database fixture proves the complete immutable recipient boundary"
    )]
    async fn logout_replay_requires_exact_persisted_application_recipient() -> anyhow::Result<()> {
        use anyhow::ensure;
        use sqlx::postgres::PgPoolOptions;
        use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
        use testcontainers_modules::postgres::Postgres;

        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        crate::infrastructure::postgres::migrate(&pool).await?;

        let application_id = Uuid::from_u128(0x44_01);
        let other_application_id = Uuid::from_u128(0x44_02);
        let endpoint_id = Uuid::from_u128(0x44_03);
        let other_endpoint_id = Uuid::from_u128(0x44_04);
        let logout_event_id = Uuid::from_u128(0x44_05);
        let profile_event_id = Uuid::from_u128(0x44_06);
        let logout_recipient_id = Uuid::from_u128(0x44_07);
        let profile_recipient_id = Uuid::from_u128(0x44_08);
        let logout_delivery_id = Uuid::from_u128(0x44_09);
        let profile_delivery_id = Uuid::from_u128(0x44_0a);
        let subject_id = Uuid::from_u128(0x44_0b);

        let mut transaction = pool.begin().await?;
        // This routing-boundary test bypasses unrelated Application and key
        // fixtures while retaining every CHECK constraint used by replay.
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            r"
            INSERT INTO iam.application_webhook_endpoints (
                id, application_id, url_ciphertext, url_nonce,
                encryption_key_version, url_digest, status, activated_at
            ) VALUES
                ($1, $2, decode(repeat('41', 17), 'hex'),
                 decode(repeat('41', 12), 'hex'), 1,
                 decode(repeat('41', 32), 'hex'), 'active', transaction_timestamp()),
                ($3, $4, decode(repeat('42', 17), 'hex'),
                 decode(repeat('42', 12), 'hex'), 1,
                 decode(repeat('42', 32), 'hex'), 'active', transaction_timestamp())
            ",
        )
        .bind(endpoint_id)
        .bind(application_id)
        .bind(other_endpoint_id)
        .bind(other_application_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.outbox_events (
                id, aggregate_type, aggregate_id, aggregate_version,
                event_type, payload, status, completed_at
            ) VALUES
                ($1, 'authentication_session', $2, 1, 'session.logout',
                 jsonb_build_object('subject_principal_id', $2),
                 'completed', transaction_timestamp()),
                ($3, 'carbon', $2, 1, 'carbon.updated', '{}',
                 'completed', transaction_timestamp())
            ",
        )
        .bind(logout_event_id)
        .bind(subject_id)
        .bind(profile_event_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.outbox_event_recipients (
                id, outbox_event_id, recipient_kind,
                application_webhook_endpoint_id, ordering_key
            ) VALUES
                ($1, $2, 'application', $3, 'logout-recipient'),
                ($4, $5, 'application', $3, 'profile-recipient')
            ",
        )
        .bind(logout_recipient_id)
        .bind(logout_event_id)
        .bind(endpoint_id)
        .bind(profile_recipient_id)
        .bind(profile_event_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.webhook_deliveries (
                id, outbox_event_id, recipient_id, status,
                attempt_count, cycle_attempt_count, dead_lettered_at
            ) VALUES
                ($1, $2, $3, 'dead_letter', 5, 5, transaction_timestamp()),
                ($4, $5, $6, 'dead_letter', 5, 5, transaction_timestamp())
            ",
        )
        .bind(logout_delivery_id)
        .bind(logout_event_id)
        .bind(logout_recipient_id)
        .bind(profile_delivery_id)
        .bind(profile_event_id)
        .bind(profile_recipient_id)
        .execute(&mut *transaction)
        .await?;

        let deliveries = lock_application_dead_letters(
            &mut transaction,
            application_id,
            &[logout_delivery_id, profile_delivery_id],
        )
        .await?;
        let logout = deliveries
            .iter()
            .find(|delivery| delivery.delivery_id == logout_delivery_id)
            .ok_or_else(|| anyhow::anyhow!("logout dead letter was not locked"))?;
        let profile = deliveries
            .iter()
            .find(|delivery| delivery.delivery_id == profile_delivery_id)
            .ok_or_else(|| anyhow::anyhow!("profile dead letter was not locked"))?;

        ensure!(
            application_logout_dead_letter_is_bound_to(&mut transaction, application_id, logout,)
                .await?,
            "the exact original logout recipient was rejected"
        );
        ensure!(
            !application_logout_dead_letter_is_bound_to(
                &mut transaction,
                other_application_id,
                logout,
            )
            .await?,
            "a different Application inherited logout replay authority"
        );
        ensure!(
            !application_logout_dead_letter_is_bound_to(&mut transaction, application_id, profile,)
                .await?,
            "recipient binding broadened a non-logout historical replay"
        );
        let mut mismatched = logout.clone();
        mismatched.event_id = profile_event_id;
        ensure!(
            !application_logout_dead_letter_is_bound_to(
                &mut transaction,
                application_id,
                &mismatched,
            )
            .await?,
            "a mismatched delivery/event tuple was authorized"
        );

        let cross_application_retarget = replay_application_delivery(
            &mut transaction,
            logout,
            other_endpoint_id,
            Uuid::from_u128(0x44_0c),
            Uuid::from_u128(0x44_0d),
        )
        .await;
        ensure!(
            matches!(cross_application_retarget, Err(sqlx::Error::RowNotFound)),
            "a replay recipient was retargeted across Application boundaries"
        );
        let persisted_endpoint = sqlx::query_scalar::<_, Uuid>(
            "SELECT application_webhook_endpoint_id FROM iam.outbox_event_recipients WHERE id = $1",
        )
        .bind(logout_recipient_id)
        .fetch_one(&mut *transaction)
        .await?;
        ensure!(
            persisted_endpoint == endpoint_id,
            "failed cross-Application replay changed the recipient binding"
        );

        transaction.rollback().await?;
        Ok(())
    }
}
