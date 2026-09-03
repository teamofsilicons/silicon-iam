use std::{borrow::Cow, num::NonZeroU32, time::Duration};

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use secrecy::SecretString;
use serde::Serialize;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{
        actor::{ActorRef, ActorType},
        directory::OrganizationId,
        organization::Capability,
    },
    error::AppError,
    infrastructure::{
        postgres::{
            authorization::{self, AuthorizationError, OrganizationAccess},
            context::{self, DatabaseContext},
            events::{self, AggregateVersion, AuditRecord, OutboxRecord, SiliconWebhookRouting},
            idempotency::{
                self, IdempotencyClaim, IdempotencyKey, IdempotencyLease, IdempotencyRequest,
                OneTimeResponseReplayTtl, ReplayResponse,
            },
            rate_limit::{self, RateLimitPolicy},
            step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
        },
        providers::workos::{WorkOsClient, WorkOsError},
    },
};

use super::security;
use super::security::BrowserSession;

pub(super) const SSO_CHANGE_ACTION: &str = "organization.sso_change";
pub(super) const PLATFORM_ADMIN_ACTION: &str = "platform_admin.sso_entitlement";

pub(super) struct OrganizationScope<'a> {
    pub(super) transaction: Transaction<'a, Postgres>,
    pub(super) access: OrganizationAccess,
}

pub(super) enum Claim {
    Acquired(IdempotencyLease),
    Replay(Response),
}

pub(super) struct MutationEvent<'a> {
    pub(super) action: &'static str,
    pub(super) target_type: &'static str,
    pub(super) target_id: Option<Uuid>,
    pub(super) aggregate_type: &'a str,
    pub(super) aggregate_id: Uuid,
    pub(super) aggregate_version: i64,
    pub(super) event_type: &'a str,
    pub(super) before_state: Option<serde_json::Value>,
    pub(super) after_state: Option<serde_json::Value>,
    pub(super) metadata: serde_json::Value,
}

pub(super) async fn begin_organization<'a>(
    state: &'a ApiState,
    authenticated: &Authenticated,
    organization_handle: &OrganizationId,
    serializable: bool,
) -> Result<OrganizationScope<'a>, AppError> {
    let carbon_id = security::require_first_party_carbon(&authenticated.0)?;
    let mut transaction = if serializable {
        begin_serializable(state, Some(carbon_id), None).await?
    } else {
        context::begin(state.db(), DatabaseContext::principal(carbon_id))
            .await
            .map_err(database)?
    };
    let access = authorization::resolve_organization_access(
        &mut transaction,
        carbon_id,
        organization_handle.as_str(),
    )
    .await
    .map_err(map_authorization)?
    .ok_or(AppError::NotFound)?;
    context::select_organization(&mut transaction, access.organization_id)
        .await
        .map_err(database)?;
    Ok(OrganizationScope {
        transaction,
        access,
    })
}

pub(super) async fn begin_platform<'a>(
    state: &'a ApiState,
    authenticated: &Authenticated,
) -> Result<(Transaction<'a, Postgres>, Uuid), AppError> {
    let carbon_id = security::require_first_party_carbon(&authenticated.0)?;
    let mut transaction = begin_serializable(state, Some(carbon_id), None).await?;
    let allowed = sqlx::query_scalar::<_, bool>(
        "SELECT iam_private.has_platform_capability($1, 'organizations.sso_feature')",
    )
    .bind(carbon_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(database)?;
    if !allowed {
        return Err(AppError::Forbidden);
    }
    Ok((transaction, carbon_id))
}

pub(super) fn require_manage(access: &OrganizationAccess) -> Result<(), AppError> {
    if access.authority.allows(Capability::SsoManage) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(super) async fn consume_step_up(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    action: &'static str,
    resource_id: Uuid,
) -> Result<Uuid, AppError> {
    let carbon_id = security::require_first_party_carbon(&authenticated.0)?;
    let raw = headers
        .get("x-step-up-token")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::PreconditionRequired {
            code: Cow::Borrowed("step_up_required"),
        })?;
    let token = StepUpToken::parse(raw).map_err(|_| AppError::PreconditionFailed {
        code: Cow::Borrowed("step_up_invalid"),
    })?;
    step_up::consume(
        transaction,
        &state.crypto,
        &token,
        StepUpExpectation {
            carbon_id,
            authentication_session_id: authenticated.0.authentication_session_id,
            action,
            resource_id: Some(resource_id),
            required_assurance: RequiredAssurance::VerifiedChannel,
        },
    )
    .await
}

pub(super) fn expected_version(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::PreconditionRequired {
            code: Cow::Borrowed("if_match_required"),
        })?;
    if raw.starts_with("W/") || raw.contains(',') {
        return Err(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_invalid"),
        });
    }
    raw.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|version| *version > 0)
        .ok_or(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_invalid"),
        })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the transaction, authenticated caller, concrete resource, and exact request form one auditable claim boundary"
)]
pub(super) async fn claim<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    route: &'static str,
    resource_scope: &str,
    request: &T,
    contains_one_time_secret: bool,
) -> Result<Claim, AppError> {
    let key = idempotency_key(headers)?;
    let caller_scope = SecretString::from(idempotency_caller_scope(
        authenticated.0.subject.id,
        resource_scope,
    ));
    let request_payload = SecretString::from(
        serde_json::to_string(request).map_err(|_| internal("sso_idempotency_serialize"))?,
    );
    match idempotency::claim(
        transaction,
        &state.crypto,
        IdempotencyRequest {
            route,
            caller_scope: &caller_scope,
            key: &key,
            request_payload: &request_payload,
            contains_one_time_secret,
        },
    )
    .await?
    {
        IdempotencyClaim::Acquired(lease) => Ok(Claim::Acquired(lease)),
        IdempotencyClaim::Replay(replay) => Ok(Claim::Replay(replay_response(replay)?)),
    }
}

fn idempotency_caller_scope(carbon_id: Uuid, resource_scope: &str) -> String {
    format!("carbon:{carbon_id}:resource:{resource_scope}")
}

pub(super) async fn complete_json<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    lease: IdempotencyLease,
    status: StatusCode,
    value: &T,
    replay_ttl: Option<OneTimeResponseReplayTtl>,
) -> Result<Vec<u8>, AppError> {
    let bytes = serde_json::to_vec(value).map_err(|_| internal("sso_response_serialize"))?;
    if let Some(replay_ttl) = replay_ttl {
        idempotency::complete_with_replay_ttl(
            transaction,
            &state.crypto,
            lease,
            status.as_u16(),
            &bytes,
            replay_ttl,
        )
        .await?;
    } else {
        idempotency::complete(transaction, &state.crypto, lease, status.as_u16(), &bytes).await?;
    }
    Ok(bytes)
}

pub(super) async fn complete_empty(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    lease: IdempotencyLease,
) -> Result<(), AppError> {
    idempotency::complete(transaction, &state.crypto, lease, 204, &[]).await
}

pub(super) async fn record_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    organization_id: Option<Uuid>,
    event: MutationEvent<'_>,
) -> Result<(), AppError> {
    let aggregate = AggregateVersion {
        aggregate_type: event.aggregate_type,
        aggregate_id: event.aggregate_id,
        version: event.aggregate_version,
    };
    let webhook_payload = webhook_payload(&event);
    let silicon_webhook_routing = silicon_webhook_routing(event.event_type);
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: authenticated.0.subject.actor_type,
                id: authenticated.0.subject.id,
            }),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id,
            application_id: authenticated.0.client_application_id,
            action: event.action,
            target_type: event.target_type,
            target_id: event.target_id,
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state: event.before_state,
            after_state: event.after_state,
            metadata: event.metadata.clone(),
        },
    )
    .await
    .map_err(database)?;
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id,
            aggregate,
            event_ordinal: 1,
            event_type: event.event_type,
            schema_version: 1,
            payload: webhook_payload,
            silicon_webhook_routing,
        },
    )
    .await
    .map_err(database)?;
    Ok(())
}

pub(super) async fn record_system_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    event: MutationEvent<'_>,
) -> Result<(), AppError> {
    let aggregate = AggregateVersion {
        aggregate_type: event.aggregate_type,
        aggregate_id: event.aggregate_id,
        version: event.aggregate_version,
    };
    let webhook_payload = webhook_payload(&event);
    let silicon_webhook_routing = silicon_webhook_routing(event.event_type);
    events::record_audit(
        transaction,
        AuditRecord {
            actor: None,
            authentication_session_id: None,
            organization_id: Some(organization_id),
            application_id: None,
            action: event.action,
            target_type: event.target_type,
            target_id: event.target_id,
            authentication_method: Some("workos_webhook"),
            aggregate: Some(aggregate),
            before_state: event.before_state,
            after_state: event.after_state,
            metadata: event.metadata.clone(),
        },
    )
    .await
    .map_err(database)?;
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: Some(organization_id),
            aggregate,
            event_ordinal: 1,
            event_type: event.event_type,
            schema_version: 1,
            payload: webhook_payload,
            silicon_webhook_routing,
        },
    )
    .await
    .map_err(database)?;
    Ok(())
}

pub(super) async fn record_browser_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    browser_session: BrowserSession,
    organization_id: Uuid,
    event: MutationEvent<'_>,
) -> Result<(), AppError> {
    let aggregate = AggregateVersion {
        aggregate_type: event.aggregate_type,
        aggregate_id: event.aggregate_id,
        version: event.aggregate_version,
    };
    let webhook_payload = webhook_payload(&event);
    let silicon_webhook_routing = silicon_webhook_routing(event.event_type);
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: ActorType::Carbon,
                id: browser_session.carbon_id,
            }),
            authentication_session_id: Some(browser_session.session_id),
            organization_id: Some(organization_id),
            application_id: None,
            action: event.action,
            target_type: event.target_type,
            target_id: event.target_id,
            authentication_method: Some("workos_sso"),
            aggregate: Some(aggregate),
            before_state: event.before_state,
            after_state: event.after_state,
            metadata: event.metadata.clone(),
        },
    )
    .await
    .map_err(database)?;
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: Some(organization_id),
            aggregate,
            event_ordinal: 1,
            event_type: event.event_type,
            schema_version: 1,
            payload: webhook_payload,
            silicon_webhook_routing,
        },
    )
    .await
    .map_err(database)?;
    Ok(())
}

fn silicon_webhook_routing(event_type: &str) -> Option<SiliconWebhookRouting> {
    match event_type {
        "sso.setup_link.created.v1"
        | "sso.configuration.disabled.v1"
        | "sso.entitlement.replaced.v1"
        | "sso.connection.activated.v1"
        | "sso.connection.deactivated.v1"
        | "sso.connection.deleted.v1" => Some(SiliconWebhookRouting {
            topics: Vec::new(),
            affected_membership_id: None,
            affected_tag_ids: Vec::new(),
            before_tag_membership_ids: Vec::new(),
            organization_wide: true,
        }),
        _ => None,
    }
}

fn webhook_payload(event: &MutationEvent<'_>) -> serde_json::Value {
    let mut payload = event.metadata.as_object().cloned().unwrap_or_default();
    payload.insert("change".to_owned(), json!(event.action));
    payload.insert(
        "target".to_owned(),
        json!({ "type": event.target_type, "id": event.target_id }),
    );
    payload.insert(
        "before".to_owned(),
        event
            .before_state
            .clone()
            .unwrap_or(serde_json::Value::Null),
    );
    payload.insert(
        "after".to_owned(),
        event.after_state.clone().unwrap_or(serde_json::Value::Null),
    );
    serde_json::Value::Object(payload)
}

pub(super) fn workos(state: &ApiState) -> Result<&WorkOsClient, AppError> {
    state
        .workos
        .as_deref()
        .ok_or_else(|| internal("workos_not_configured"))
}

pub(super) fn map_workos(error: WorkOsError) -> AppError {
    match error {
        WorkOsError::InvalidSignature | WorkOsError::StaleSignature => AppError::Unauthenticated,
        WorkOsError::Rejected | WorkOsError::NotFound | WorkOsError::Conflict => {
            AppError::Conflict {
                code: Cow::Borrowed("workos_request_rejected"),
            }
        }
        WorkOsError::NotConfigured => internal("workos_not_configured"),
        WorkOsError::Unavailable | WorkOsError::InvalidResponse => AppError::ProviderUnavailable,
    }
}

pub(super) async fn enforce_rate_limit(
    state: &ApiState,
    name: &'static str,
    raw_scope: SecretString,
    maximum: u32,
    window: Duration,
) -> Result<(), AppError> {
    let maximum = NonZeroU32::new(maximum).ok_or_else(|| internal("sso_rate_limit_policy"))?;
    let policy = RateLimitPolicy::new(maximum, window, window)
        .map_err(|_| internal("sso_rate_limit_policy"))?;
    rate_limit::enforce(state.db(), &state.crypto, name, &raw_scope, policy).await?;
    Ok(())
}

pub(super) fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
    version: Option<i64>,
    contains_secret: bool,
) -> Result<Response, AppError> {
    let body = serde_json::to_vec(value).map_err(|_| internal("sso_response_serialize"))?;
    raw_json_response(status, body, version, contains_secret, false)
}

pub(super) fn stored_json_response(
    status: StatusCode,
    body: Vec<u8>,
    version: Option<i64>,
    contains_secret: bool,
) -> Result<Response, AppError> {
    raw_json_response(status, body, version, contains_secret, false)
}

pub(super) fn empty_response() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

fn replay_response(replay: ReplayResponse) -> Result<Response, AppError> {
    let status = StatusCode::from_u16(replay.status)
        .map_err(|_| internal("sso_idempotency_replay_status"))?;
    if status == StatusCode::NO_CONTENT {
        let mut response = status.into_response();
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
        return Ok(response);
    }
    let version = serde_json::from_slice::<serde_json::Value>(&replay.body)
        .ok()
        .and_then(|value| value.get("version").and_then(serde_json::Value::as_i64))
        .filter(|value| *value > 0);
    raw_json_response(status, replay.body, version, true, true)
}

fn raw_json_response(
    status: StatusCode,
    body: Vec<u8>,
    version: Option<i64>,
    contains_secret: bool,
    replayed: bool,
) -> Result<Response, AppError> {
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| internal("sso_response_build"))?;
    if let Some(version) = version {
        let etag =
            HeaderValue::from_str(&format!("\"{version}\"")).map_err(|_| internal("sso_etag"))?;
        response.headers_mut().insert(header::ETAG, etag);
    }
    if contains_secret {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    Ok(response)
}

async fn begin_serializable(
    state: &ApiState,
    principal_id: Option<Uuid>,
    organization_id: Option<Uuid>,
) -> Result<Transaction<'_, Postgres>, AppError> {
    let mut transaction = context::begin_scoped(state.db()).await.map_err(database)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
    sqlx::query(
        r"
        SELECT
            set_config('iam.principal_id', $1, true),
            set_config('iam.organization_id', $2, true),
            set_config('iam.application_id', '', true),
            set_config('iam.signup_session_id', '', true)
        ",
    )
    .bind(principal_id.map_or_else(String::new, |value| value.to_string()))
    .bind(organization_id.map_or_else(String::new, |value| value.to_string()))
    .execute(&mut *transaction)
    .await
    .map_err(database)?;
    Ok(transaction)
}

fn idempotency_key(headers: &HeaderMap) -> Result<IdempotencyKey, AppError> {
    let raw = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::PreconditionRequired {
            code: Cow::Borrowed("idempotency_key_required"),
        })?;
    IdempotencyKey::parse(raw).map_err(|_| AppError::Validation {
        details: json!({
            "field": "Idempotency-Key",
            "message": "must contain 16 to 255 visible ASCII characters"
        }),
    })
}

fn map_authorization(error: AuthorizationError) -> AppError {
    match error {
        AuthorizationError::Database(error) => database(error),
        AuthorizationError::InvalidStoredValue => internal("sso_authorization_value"),
    }
}

pub(super) fn database(_error: sqlx::Error) -> AppError {
    internal("sso_database")
}

pub(super) fn database_conflict(error: sqlx::Error, code: &'static str) -> AppError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|value| matches!(value.as_ref(), "23505" | "23514" | "23P01" | "40001"))
    {
        AppError::Conflict {
            code: Cow::Borrowed(code),
        }
    } else {
        database(error)
    }
}

const fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{expected_version, idempotency_caller_scope, silicon_webhook_routing};

    #[test]
    fn etag_requires_one_strong_positive_integer() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"7\""));
        assert_eq!(expected_version(&headers).ok(), Some(7));
        headers.insert(header::IF_MATCH, HeaderValue::from_static("W/\"7\""));
        assert!(expected_version(&headers).is_err());
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"7\", \"8\""));
        assert!(expected_version(&headers).is_err());
    }

    #[test]
    fn only_external_sso_configuration_events_enter_silicon_routing() {
        assert!(
            silicon_webhook_routing("sso.setup_link.created.v1")
                .is_some_and(|routing| routing.topics.is_empty())
        );
        assert!(
            silicon_webhook_routing("sso.connection.activated.v1")
                .is_some_and(|routing| routing.topics.is_empty())
        );
        assert!(silicon_webhook_routing("sso.authorization.started.v1").is_none());
        assert!(silicon_webhook_routing("sso.authorization.completed.v1").is_none());
    }

    #[test]
    fn every_sso_event_in_the_full_catalog_has_explicit_routing() {
        for event_type in crate::domain::events::SILICON_FULL_EVENT_TYPES
            .iter()
            .filter(|event_type| event_type.starts_with("sso."))
        {
            assert!(
                silicon_webhook_routing(event_type).is_some(),
                "missing explicit Silicon Full routing for {event_type}"
            );
        }
    }

    #[test]
    fn idempotency_caller_scope_is_resource_qualified() {
        let carbon_id = uuid::Uuid::from_u128(1);
        let first = idempotency_caller_scope(carbon_id, "first-org");
        assert_eq!(first, idempotency_caller_scope(carbon_id, "first-org"));
        assert_ne!(first, idempotency_caller_scope(carbon_id, "second-org"));
        assert_ne!(
            first,
            idempotency_caller_scope(uuid::Uuid::from_u128(2), "first-org")
        );
    }
}
