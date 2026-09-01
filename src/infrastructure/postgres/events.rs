//! Transactional audit and outbox persistence primitives.

use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{domain::actor::ActorRef, request_context};

/// Redacted security audit record committed with a domain mutation.
pub struct AuditRecord<'a> {
    /// Actor responsible for the mutation; absent only for system maintenance.
    pub actor: Option<ActorRef>,
    /// Parent authentication session when the actor is interactive.
    pub authentication_session_id: Option<Uuid>,
    /// Organization boundary, when applicable.
    pub organization_id: Option<Uuid>,
    /// Application boundary, when applicable.
    pub application_id: Option<Uuid>,
    /// Stable dotted action vocabulary.
    pub action: &'static str,
    /// Stable target type.
    pub target_type: &'static str,
    /// Target UUID, when the target already exists.
    pub target_id: Option<Uuid>,
    /// Authentication method used for the request.
    pub authentication_method: Option<&'static str>,
    /// Aggregate identity and new exact version.
    pub aggregate: Option<AggregateVersion<'a>>,
    /// Redacted externally visible prior state.
    pub before_state: Option<Value>,
    /// Redacted externally visible new state.
    pub after_state: Option<Value>,
    /// Redacted supplemental metadata.
    pub metadata: Value,
}

/// Aggregate identity captured by audit and outbox ordering.
#[derive(Clone, Copy)]
pub struct AggregateVersion<'a> {
    /// Stable aggregate type.
    pub aggregate_type: &'a str,
    /// Aggregate UUID.
    pub aggregate_id: Uuid,
    /// Exact version after the mutation.
    pub version: i64,
}

/// Minimal versioned integration event committed with a domain mutation.
pub struct OutboxRecord<'a> {
    /// Optional organization boundary.
    pub organization_id: Option<Uuid>,
    /// Aggregate ordering identity.
    pub aggregate: AggregateVersion<'a>,
    /// Ordinal when one mutation emits multiple events at one version.
    pub event_ordinal: i16,
    /// Stable dotted event name.
    pub event_type: &'a str,
    /// Event schema version.
    pub schema_version: i16,
    /// Minimal secret-free object payload.
    pub payload: Value,
}

/// Inserts an append-only audit event in the caller's transaction.
///
/// # Errors
///
/// Returns an error if PostgreSQL rejects the redacted event or any reference.
pub async fn record_audit(
    transaction: &mut Transaction<'_, Postgres>,
    record: AuditRecord<'_>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    let request_id = request_context::current_request_uuid().unwrap_or_else(Uuid::now_v7);
    let (actor_id, actor_kind) = record.actor.map_or((None, None), |actor| {
        (Some(actor.id), Some(actor.actor_type.as_str()))
    });
    let (aggregate_type, aggregate_id, aggregate_version) =
        record.aggregate.map_or((None, None, None), |aggregate| {
            (
                Some(aggregate.aggregate_type),
                Some(aggregate.aggregate_id),
                Some(aggregate.version),
            )
        });

    sqlx::query(
        r"
        INSERT INTO iam.audit_events (
            occurred_at, id, request_id, actor_principal_id, actor_kind,
            actor_authentication_session_id, organization_id, application_id,
            action, target_type, target_id, authentication_method,
            aggregate_type, aggregate_id, aggregate_version,
            before_state, after_state, metadata
        ) VALUES (
            transaction_timestamp(), $1, $2, $3, $4::iam.principal_kind,
            $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
        )
        ",
    )
    .bind(id)
    .bind(request_id)
    .bind(actor_id)
    .bind(actor_kind)
    .bind(record.authentication_session_id)
    .bind(record.organization_id)
    .bind(record.application_id)
    .bind(record.action)
    .bind(record.target_type)
    .bind(record.target_id)
    .bind(record.authentication_method)
    .bind(aggregate_type)
    .bind(aggregate_id)
    .bind(aggregate_version)
    .bind(record.before_state)
    .bind(record.after_state)
    .bind(record.metadata)
    .execute(&mut **transaction)
    .await?;
    Ok(id)
}

/// Inserts one durable integration event in the caller's transaction.
///
/// # Errors
///
/// Returns an error if PostgreSQL rejects the event shape, ordering identity,
/// or organization reference.
pub async fn enqueue_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    record: OutboxRecord<'_>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.outbox_events (
            id, organization_id, aggregate_type, aggregate_id,
            aggregate_version, event_ordinal, event_type, schema_version,
            payload
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ",
    )
    .bind(id)
    .bind(record.organization_id)
    .bind(record.aggregate.aggregate_type)
    .bind(record.aggregate.aggregate_id)
    .bind(record.aggregate.version)
    .bind(record.event_ordinal)
    .bind(record.event_type)
    .bind(record.schema_version)
    .bind(record.payload)
    .execute(&mut **transaction)
    .await?;
    Ok(id)
}
