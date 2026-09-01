use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use sha2::{Digest as _, Sha256};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{api::ApiState, error::AppError};

use super::{
    model::{ProviderConnectionTransition, WorkOsConnectionData, WorkOsWebhookEnvelope},
    support::{self, MutationEvent},
};

const SIGNATURE_HEADER: &str = "workos-signature";
const MAX_WEBHOOK_BODY_BYTES: usize = 64 * 1024;
const MAX_TOP_LEVEL_PROPERTIES: usize = 100;

#[derive(FromRow)]
struct TransitionRow {
    organization_id: Uuid,
    connection_id: Uuid,
    config_version: i64,
    changed: bool,
    status: String,
}

pub(super) async fn receive(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    if body.len() > MAX_WEBHOOK_BODY_BYTES {
        return Err(AppError::PayloadTooLarge);
    }
    let signature = exactly_one_signature(&headers)?;
    let now_milliseconds = now_milliseconds()?;
    let verified = support::workos(&state)?
        .verify_webhook(signature, &body, now_milliseconds)
        .map_err(support::map_workos)?;
    let signature_timestamp = timestamp_from_milliseconds(verified.issued_at_milliseconds)?;
    let payload_digest: [u8; 32] = Sha256::digest(&body).into();
    let envelope = parse_envelope(&body)?;
    validate_provider_id(&envelope.id, "event_", 512)?;
    let transition = transition(&envelope.event);

    let mut transaction = state.pool.begin().await.map_err(support::database)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await
        .map_err(support::database)?;
    if let Some(transition) = transition {
        let data: WorkOsConnectionData =
            serde_json::from_value(envelope.data).map_err(|_| invalid_webhook("data"))?;
        validate_connection_data(&data, transition)?;
        let receipt_id = Uuid::now_v7();
        let row = sqlx::query_as::<_, TransitionRow>(
            r"
            SELECT organization_id, connection_id, config_version, changed, status
            FROM iam_private.apply_workos_connection_event(
                $1, $2, $3, $4, $5, $6, $7, $8, $9
            )
            ",
        )
        .bind(receipt_id)
        .bind(&envelope.id)
        .bind(transition.event_name())
        .bind(&data.organization_id)
        .bind(Uuid::now_v7())
        .bind(&data.id)
        .bind(data.connection_type.as_deref())
        .bind(payload_digest.as_slice())
        .bind(signature_timestamp)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_transition_error)?
        .ok_or_else(|| AppError::Conflict {
            code: "workos_event_unknown_organization".into(),
        })?;
        if row.changed {
            support::record_system_mutation(
                &mut transaction,
                row.organization_id,
                MutationEvent {
                    action: transition_audit_action(transition),
                    target_type: "sso_connection",
                    target_id: Some(row.connection_id),
                    aggregate_type: "organization_sso_config",
                    aggregate_id: row.organization_id,
                    aggregate_version: row.config_version,
                    event_type: transition_outbox_event(transition),
                    before_state: None,
                    after_state: Some(serde_json::json!({ "status": row.status })),
                    metadata: serde_json::json!({ "provider_event_id": envelope.id }),
                },
            )
            .await?;
        }
    } else {
        record_ignored_receipt(
            &mut transaction,
            &envelope.id,
            &payload_digest,
            signature_timestamp,
        )
        .await?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| support::database_conflict(error, "workos_event_conflict"))?;
    Ok(StatusCode::ACCEPTED)
}

fn parse_envelope(body: &[u8]) -> Result<WorkOsWebhookEnvelope, AppError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| invalid_webhook("body"))?;
    let object = value.as_object().ok_or_else(|| invalid_webhook("body"))?;
    if object.len() > MAX_TOP_LEVEL_PROPERTIES {
        return Err(invalid_webhook("body"));
    }
    serde_json::from_value(value).map_err(|_| invalid_webhook("body"))
}

fn exactly_one_signature(headers: &HeaderMap) -> Result<&str, AppError> {
    let mut values = headers.get_all(SIGNATURE_HEADER).iter();
    let value = values.next().ok_or(AppError::Unauthenticated)?;
    if values.next().is_some() {
        return Err(AppError::Unauthenticated);
    }
    value.to_str().map_err(|_| AppError::Unauthenticated)
}

fn transition(value: &str) -> Option<ProviderConnectionTransition> {
    match value {
        "connection.activated" => Some(ProviderConnectionTransition::Activated),
        "connection.deactivated" => Some(ProviderConnectionTransition::Deactivated),
        "connection.deleted" => Some(ProviderConnectionTransition::Deleted),
        _ => None,
    }
}

fn validate_connection_data(
    data: &WorkOsConnectionData,
    transition: ProviderConnectionTransition,
) -> Result<(), AppError> {
    if data.object != "connection" {
        return Err(invalid_webhook("data.object"));
    }
    validate_provider_id(&data.id, "conn_", 255)?;
    validate_provider_id(&data.organization_id, "org_", 255)?;
    if data
        .connection_type
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > 100)
    {
        return Err(invalid_webhook("data.connection_type"));
    }
    let state_matches = match transition {
        ProviderConnectionTransition::Activated => data.state.as_deref() == Some("active"),
        ProviderConnectionTransition::Deactivated => data.state.as_deref() == Some("inactive"),
        ProviderConnectionTransition::Deleted => true,
    };
    if !state_matches {
        return Err(invalid_webhook("data.state"));
    }
    Ok(())
}

fn validate_provider_id(value: &str, prefix: &'static str, maximum: usize) -> Result<(), AppError> {
    if !value.starts_with(prefix)
        || value.len() <= prefix.len()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(invalid_webhook("provider_id"));
    }
    Ok(())
}

async fn record_ignored_receipt(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    provider_event_id: &str,
    payload_digest: &[u8; 32],
    signature_timestamp: OffsetDateTime,
) -> Result<(), AppError> {
    let _inserted = sqlx::query_scalar::<_, bool>(
        r"
        SELECT iam_private.record_ignored_workos_event($1, $2, $3, $4)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(provider_event_id)
    .bind(payload_digest.as_slice())
    .bind(signature_timestamp)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_transition_error)?;
    Ok(())
}

fn now_milliseconds() -> Result<i64, AppError> {
    i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| internal("workos_webhook_clock"))
}

fn timestamp_from_milliseconds(value: i64) -> Result<OffsetDateTime, AppError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000)
        .map_err(|_| internal("workos_webhook_timestamp"))
}

const fn transition_audit_action(value: ProviderConnectionTransition) -> &'static str {
    match value {
        ProviderConnectionTransition::Activated => "sso.connection.activate",
        ProviderConnectionTransition::Deactivated => "sso.connection.deactivate",
        ProviderConnectionTransition::Deleted => "sso.connection.delete",
    }
}

const fn transition_outbox_event(value: ProviderConnectionTransition) -> &'static str {
    match value {
        ProviderConnectionTransition::Activated => "sso.connection.activated.v1",
        ProviderConnectionTransition::Deactivated => "sso.connection.deactivated.v1",
        ProviderConnectionTransition::Deleted => "sso.connection.deleted.v1",
    }
}

fn map_transition_error(error: sqlx::Error) -> AppError {
    let message = error
        .as_database_error()
        .map(sqlx::error::DatabaseError::message);
    match message {
        Some("workos_event_payload_conflict" | "workos_event_metadata_conflict") => {
            AppError::Conflict {
                code: "workos_event_conflict".into(),
            }
        }
        Some("workos_event_invalid") => invalid_webhook("event"),
        _ => support::database(error),
    }
}

fn invalid_webhook(field: &'static str) -> AppError {
    AppError::Validation {
        details: serde_json::json!({
            "field": field,
            "message": "has an invalid WorkOS event shape"
        }),
    }
}

const fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{exactly_one_signature, transition};
    use crate::features::sso::model::ProviderConnectionTransition;

    #[test]
    fn signature_header_must_be_unique() {
        let mut headers = HeaderMap::new();
        headers.append("workos-signature", HeaderValue::from_static("t=1,v1=aa"));
        assert!(exactly_one_signature(&headers).is_ok());
        headers.append("workos-signature", HeaderValue::from_static("t=1,v1=bb"));
        assert!(exactly_one_signature(&headers).is_err());
    }

    #[test]
    fn only_connection_lifecycle_events_mutate_sso() {
        assert_eq!(
            transition("connection.activated"),
            Some(ProviderConnectionTransition::Activated)
        );
        assert_eq!(transition("organization.updated"), None);
    }
}
