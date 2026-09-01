use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::error::AppError;

use super::idempotency::request_uuid;

pub(super) struct SecurityMutation<'a> {
    pub(super) authentication_event: &'a str,
    pub(super) authentication_outcome: &'a str,
    pub(super) audit_action: &'a str,
    pub(super) audit_result: &'a str,
    pub(super) outbox_event: &'a str,
    pub(super) subject_id: Option<Uuid>,
    pub(super) actor_id: Option<Uuid>,
    pub(super) authentication_session_id: Option<Uuid>,
    pub(super) application_id: Option<Uuid>,
    pub(super) aggregate_type: &'a str,
    pub(super) aggregate_id: Uuid,
    pub(super) aggregate_version: i64,
    pub(super) failure_code: Option<&'a str>,
    pub(super) metadata: Value,
}

/// Allocates the next outbox-backed version while the caller holds the
/// aggregate's state lock. Reusable OTP challenges can span more than one
/// failed-attempt window, so an attempt counter is not a durable version.
pub(super) async fn next_aggregate_version(
    transaction: &mut Transaction<'_, Postgres>,
    aggregate_type: &'static str,
    aggregate_id: Uuid,
) -> Result<i64, AppError> {
    sqlx::query_scalar::<_, i64>(
        r"
        SELECT COALESCE(MAX(aggregate_version), 0) + 1
        FROM iam.outbox_events
        WHERE aggregate_type = $1
          AND aggregate_id = $2
        ",
    )
    .bind(aggregate_type)
    .bind(aggregate_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "authentication_aggregate_version",
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the immutable authentication and outbox evidence writes share one atomic operation"
)]
pub(super) async fn record(
    transaction: &mut Transaction<'_, Postgres>,
    mutation: SecurityMutation<'_>,
) -> Result<(), AppError> {
    let request_id = request_uuid();
    sqlx::query(
        r"
        INSERT INTO iam.authentication_events (
            id,
            event_type,
            outcome,
            subject_principal_id,
            subject_kind,
            authentication_session_id,
            application_id,
            request_id,
            failure_code,
            metadata
        )
        VALUES (
            $1, $2, $3, $4,
            (SELECT principal.kind FROM iam.principals AS principal WHERE principal.id = $4),
            $5, $6, $7, $8, $9
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(mutation.authentication_event)
    .bind(mutation.authentication_outcome)
    .bind(mutation.subject_id)
    .bind(mutation.authentication_session_id)
    .bind(mutation.application_id)
    .bind(request_id)
    .bind(mutation.failure_code)
    .bind(&mutation.metadata)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "authentication_event_write",
    })?;

    sqlx::query(
        r"
        INSERT INTO iam.audit_events (
            occurred_at,
            id,
            request_id,
            actor_principal_id,
            actor_kind,
            actor_authentication_session_id,
            application_id,
            action,
            target_type,
            target_id,
            result,
            aggregate_type,
            aggregate_id,
            aggregate_version,
            metadata
        )
        VALUES (
            transaction_timestamp(), $1, $2, $3,
            (SELECT principal.kind FROM iam.principals AS principal WHERE principal.id = $3),
            $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(request_id)
    .bind(mutation.actor_id)
    .bind(mutation.actor_id.and(mutation.authentication_session_id))
    .bind(mutation.application_id)
    .bind(mutation.audit_action)
    .bind(mutation.aggregate_type)
    .bind(mutation.aggregate_id)
    .bind(mutation.audit_result)
    .bind(mutation.aggregate_type)
    .bind(mutation.aggregate_id)
    .bind(mutation.aggregate_version)
    .bind(&mutation.metadata)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "audit_event_write",
    })?;

    sqlx::query(
        r"
        INSERT INTO iam.outbox_events (
            id,
            aggregate_type,
            aggregate_id,
            aggregate_version,
            event_type,
            payload
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(mutation.aggregate_type)
    .bind(mutation.aggregate_id)
    .bind(mutation.aggregate_version)
    .bind(mutation.outbox_event)
    .bind(mutation.metadata)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "outbox_event_write",
    })?;
    Ok(())
}
