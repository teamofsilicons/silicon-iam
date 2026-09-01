use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    domain::actor::{ActorRef, ActorType},
    infrastructure::postgres::events::{self, AggregateVersion, AuditRecord, OutboxRecord},
};

use super::error::ApiError;

pub(super) struct Mutation {
    pub(super) actor_id: Option<Uuid>,
    pub(super) authentication_session_id: Option<Uuid>,
    pub(super) application_id: Uuid,
    pub(super) action: &'static str,
    pub(super) target_type: &'static str,
    pub(super) target_id: Option<Uuid>,
    pub(super) aggregate_type: &'static str,
    pub(super) aggregate_id: Uuid,
    pub(super) aggregate_version: i64,
    pub(super) before: Option<Value>,
    pub(super) after: Option<Value>,
    pub(super) metadata: Value,
    pub(super) event_type: &'static str,
}

pub(super) async fn record(
    transaction: &mut Transaction<'_, Postgres>,
    mutation: Mutation,
) -> Result<(), ApiError> {
    let aggregate = AggregateVersion {
        aggregate_type: mutation.aggregate_type,
        aggregate_id: mutation.aggregate_id,
        version: mutation.aggregate_version,
    };
    events::record_audit(
        transaction,
        AuditRecord {
            actor: mutation.actor_id.map(|id| ActorRef {
                actor_type: ActorType::Carbon,
                id,
            }),
            authentication_session_id: mutation.authentication_session_id,
            organization_id: None,
            application_id: Some(mutation.application_id),
            action: mutation.action,
            target_type: mutation.target_type,
            target_id: mutation.target_id,
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state: mutation.before,
            after_state: mutation.after,
            metadata: mutation.metadata.clone(),
        },
    )
    .await
    .map_err(|_| ApiError::internal("application_audit"))?;
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: None,
            aggregate,
            event_ordinal: 1,
            event_type: mutation.event_type,
            schema_version: 1,
            payload: mutation.metadata,
        },
    )
    .await
    .map_err(|_| ApiError::internal("application_outbox"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn authentication_event(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    subject_id: Option<Uuid>,
    subject_kind: Option<&str>,
    session_id: Option<Uuid>,
    event_type: &'static str,
    outcome: &'static str,
    failure_code: Option<&'static str>,
    metadata: Value,
) -> Result<(), ApiError> {
    let request_id = crate::request_context::current_request_uuid().unwrap_or_else(Uuid::now_v7);
    sqlx::query(
        r"
        INSERT INTO iam.authentication_events (
            id, event_type, outcome, subject_principal_id, subject_kind,
            application_id, authentication_session_id, request_id,
            failure_code, metadata
        ) VALUES ($1, $2, $3, $4, $5::iam.principal_kind, $6, $7, $8, $9, $10)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(event_type)
    .bind(outcome)
    .bind(subject_id)
    .bind(subject_kind)
    .bind(application_id)
    .bind(session_id)
    .bind(request_id)
    .bind(failure_code)
    .bind(metadata)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("oauth_authentication_event"))?;
    Ok(())
}
