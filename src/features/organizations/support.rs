use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse as _, Response},
};
use secrecy::SecretString;
use serde::Serialize;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{
        actor::{ActorRef, ActorType},
        organization::Capability,
    },
    error::AppError,
    infrastructure::postgres::{
        authorization::{self, AuthorizationError, OrganizationAccess},
        context::{self, DatabaseContext},
        events::{self, AggregateVersion, AuditRecord, OutboxRecord},
        idempotency::{self, IdempotencyClaim, IdempotencyKey, IdempotencyLease},
        step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
    },
};

pub(super) struct OrganizationTransaction<'a> {
    pub(super) transaction: Transaction<'a, Postgres>,
    pub(super) access: OrganizationAccess,
}

pub(super) struct MutationEvent<'a> {
    pub(super) action: &'static str,
    pub(super) target_type: &'static str,
    pub(super) target_id: Uuid,
    pub(super) aggregate_type: &'a str,
    pub(super) aggregate_id: Uuid,
    pub(super) aggregate_version: i64,
    pub(super) event_type: &'a str,
    pub(super) before_state: Option<serde_json::Value>,
    pub(super) after_state: Option<serde_json::Value>,
    pub(super) metadata: serde_json::Value,
}

pub(super) enum Claim {
    Acquired(IdempotencyLease),
    Replay(Response),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectIamBinding {
    Carbon,
    Silicon {
        organization_id: Uuid,
        membership_id: Uuid,
    },
}

pub(super) async fn begin_organization<'a>(
    state: &'a ApiState,
    authenticated: &Authenticated,
    organization_handle: &str,
) -> Result<OrganizationTransaction<'a>, AppError> {
    let credential_binding = direct_iam_binding(authenticated)?;
    let principal_id = authenticated.0.subject.id;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(principal_id))
        .await
        .map_err(database)?;
    let access = authorization::resolve_organization_access(
        &mut transaction,
        principal_id,
        organization_handle,
    )
    .await
    .map_err(map_authorization)?
    .ok_or(AppError::NotFound)?;
    context::select_organization(&mut transaction, access.organization_id)
        .await
        .map_err(database)?;
    if let DirectIamBinding::Silicon {
        organization_id,
        membership_id,
    } = credential_binding
        && (organization_id != access.organization_id || membership_id != access.membership_id)
    {
        return Err(AppError::Forbidden);
    }
    Ok(OrganizationTransaction {
        transaction,
        access,
    })
}

pub(super) fn require_carbon(authenticated: &Authenticated) -> Result<Uuid, AppError> {
    if authenticated.0.subject.actor_type != ActorType::Carbon
        || direct_iam_binding(authenticated)? != DirectIamBinding::Carbon
    {
        return Err(AppError::Forbidden);
    }
    Ok(authenticated.0.subject.id)
}

fn direct_iam_binding(authenticated: &Authenticated) -> Result<DirectIamBinding, AppError> {
    let access = &authenticated.0;
    if access.audience != "silicon-iam"
        || access.client_application_id.is_some()
        || !access.scopes.iter().any(|scope| scope == "iam.self")
    {
        return Err(AppError::Forbidden);
    }

    match (
        access.subject.actor_type,
        access.organization_id,
        access.membership_id,
    ) {
        (ActorType::Carbon, None, None) => Ok(DirectIamBinding::Carbon),
        (ActorType::Silicon, Some(organization_id), Some(membership_id)) => {
            Ok(DirectIamBinding::Silicon {
                organization_id,
                membership_id,
            })
        }
        _ => Err(AppError::Forbidden),
    }
}

pub(super) fn require_capability(
    access: &OrganizationAccess,
    capability: Capability,
) -> Result<(), AppError> {
    if access.authority.allows(capability) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(super) async fn claim<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    route: &'static str,
    request: &T,
    contains_one_time_secret: bool,
) -> Result<Claim, AppError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            crate::features::organizations::validation::field("idempotency_key", "is required")
        })?;
    let key = IdempotencyKey::parse(key).map_err(|_| {
        crate::features::organizations::validation::field(
            "idempotency_key",
            "must contain 16 to 255 visible ASCII characters",
        )
    })?;
    let caller_scope = SecretString::from(format!(
        "{}:{}",
        authenticated.0.subject.actor_type.as_str(),
        authenticated.0.subject.id
    ));
    let request_payload =
        SecretString::from(
            serde_json::to_string(request).map_err(|_| AppError::Internal {
                category: "organization_request_serialize",
            })?,
        );
    match idempotency::claim(
        transaction,
        &state.crypto,
        idempotency::IdempotencyRequest {
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
        IdempotencyClaim::Replay(replay) => Ok(Claim::Replay(replay_response(
            replay,
            contains_one_time_secret,
        )?)),
    }
}

pub(super) async fn consume_step_up(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    action: &'static str,
    resource_id: Option<Uuid>,
    assurance: RequiredAssurance,
) -> Result<Uuid, AppError> {
    let carbon_id = require_carbon(authenticated)?;
    let token = headers
        .get("x-step-up-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::PreconditionRequired {
            code: "step_up_required".into(),
        })?;
    let token = StepUpToken::parse(token).map_err(|_| AppError::PreconditionFailed {
        code: "step_up_invalid".into(),
    })?;
    step_up::consume(
        transaction,
        &state.crypto,
        &token,
        StepUpExpectation {
            carbon_id,
            authentication_session_id: authenticated.0.authentication_session_id,
            action,
            resource_id,
            required_assurance: assurance,
        },
    )
    .await
}

pub(super) async fn record_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    organization_id: Uuid,
    event: MutationEvent<'_>,
) -> Result<(), AppError> {
    let aggregate = AggregateVersion {
        aggregate_type: event.aggregate_type,
        aggregate_id: event.aggregate_id,
        version: event.aggregate_version,
    };
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: authenticated.0.subject.actor_type,
                id: authenticated.0.subject.id,
            }),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: Some(organization_id),
            application_id: authenticated.0.client_application_id,
            action: event.action,
            target_type: event.target_type,
            target_id: Some(event.target_id),
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
            organization_id: Some(organization_id),
            aggregate,
            event_ordinal: 1,
            event_type: event.event_type,
            schema_version: 1,
            payload: event.metadata,
        },
    )
    .await
    .map_err(database)?;
    Ok(())
}

pub(super) async fn finish_json<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    lease: IdempotencyLease,
    status: StatusCode,
    value: &T,
) -> Result<Vec<u8>, AppError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AppError::Internal {
        category: "organization_response_serialize",
    })?;
    idempotency::complete(transaction, &state.crypto, lease, status.as_u16(), &bytes).await?;
    Ok(bytes)
}

pub(super) async fn finish_empty(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    lease: IdempotencyLease,
    status: StatusCode,
) -> Result<(), AppError> {
    idempotency::complete(transaction, &state.crypto, lease, status.as_u16(), &[]).await
}

pub(super) fn json_response(
    status: StatusCode,
    body: Vec<u8>,
    version: Option<i64>,
    contains_secret: bool,
) -> Result<Response, AppError> {
    let mut response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| AppError::Internal {
            category: "organization_response_build",
        })?;
    if let Some(version) = version {
        let etag =
            HeaderValue::from_str(&format!("\"{version}\"")).map_err(|_| AppError::Internal {
                category: "organization_etag",
            })?;
        response.headers_mut().insert(http::header::ETAG, etag);
    }
    if contains_secret {
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        response
            .headers_mut()
            .insert(http::header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    Ok(response)
}

pub(super) fn json<T: Serialize>(
    status: StatusCode,
    value: &T,
    version: Option<i64>,
) -> Result<Response, AppError> {
    let body = serde_json::to_vec(value).map_err(|_| AppError::Internal {
        category: "organization_response_serialize",
    })?;
    json_response(status, body, version, false)
}

pub(super) fn empty(status: StatusCode) -> Response {
    status.into_response()
}

pub(super) fn database(_error: sqlx::Error) -> AppError {
    AppError::Internal {
        category: "organization_database",
    }
}

pub(super) fn conflict_from_database(error: sqlx::Error, code: &'static str) -> AppError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|database_code| matches!(database_code.as_ref(), "23505" | "23514" | "23P01"))
    {
        AppError::Conflict { code: code.into() }
    } else {
        database(error)
    }
}

pub(super) fn transition_database(error: sqlx::Error) -> AppError {
    let message = error
        .as_database_error()
        .map(sqlx::error::DatabaseError::message);

    match message {
        Some(
            "membership_version_mismatch" | "silicon_version_mismatch" | "tag_version_mismatch",
        ) => AppError::PreconditionFailed {
            code: "etag_mismatch".into(),
        },
        Some("owner_cannot_be_removed") => AppError::Conflict {
            code: "owner_cannot_be_removed".into(),
        },
        Some("reassign_reports_to_required") => AppError::Conflict {
            code: "reassign_reports_to_required".into(),
        },
        Some("invalid_reporting_hierarchy") => AppError::Conflict {
            code: "invalid_reporting_hierarchy".into(),
        },
        Some("membership_role_transition_invalid") => AppError::Conflict {
            code: "membership_role_transition_invalid".into(),
        },
        Some("tag_in_use") => AppError::Conflict {
            code: "tag_in_use".into(),
        },
        Some(
            "membership_removal_forbidden"
            | "admin_role_transition_forbidden"
            | "tag_archive_forbidden",
        ) => AppError::Forbidden,
        _ => database(error),
    }
}

fn replay_response(
    replay: idempotency::ReplayResponse,
    contains_one_time_secret: bool,
) -> Result<Response, AppError> {
    let status = StatusCode::from_u16(replay.status).map_err(|_| AppError::Internal {
        category: "organization_replay_status",
    })?;
    let mut response = json_response(status, replay.body, None, contains_one_time_secret)?;
    response.headers_mut().insert(
        HeaderNameExt::idempotency_replayed(),
        HeaderValue::from_static("true"),
    );
    Ok(response)
}

fn map_authorization(error: AuthorizationError) -> AppError {
    match error {
        AuthorizationError::Database(error) => database(error),
        AuthorizationError::InvalidStoredValue => AppError::Internal {
            category: "organization_authorization_value",
        },
    }
}

struct HeaderNameExt;

impl HeaderNameExt {
    fn idempotency_replayed() -> http::HeaderName {
        http::HeaderName::from_static("idempotency-replayed")
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        api::authentication::Authenticated,
        domain::actor::{ActorRef, ActorType},
        infrastructure::postgres::tokens::AccessContext,
    };

    use super::{DirectIamBinding, direct_iam_binding, require_carbon};
    use uuid::Uuid;

    fn direct_carbon() -> Authenticated {
        Authenticated(AccessContext {
            token_id: Uuid::from_u128(1),
            authentication_session_id: Uuid::from_u128(2),
            subject: ActorRef {
                actor_type: ActorType::Carbon,
                id: Uuid::from_u128(3),
            },
            client_application_id: None,
            audience: "silicon-iam".to_owned(),
            organization_id: None,
            membership_id: None,
            scopes: vec!["iam.self".to_owned()],
            assurance_level: 2,
        })
    }

    #[test]
    fn organization_access_rejects_delegated_carbon_oauth_tokens() {
        let direct = direct_carbon();
        assert!(matches!(
            direct_iam_binding(&direct),
            Ok(DirectIamBinding::Carbon)
        ));
        assert!(require_carbon(&direct).is_ok());

        let mut delegated = direct;
        delegated.0.client_application_id = Some(Uuid::from_u128(4));
        delegated.0.audience = "third-party-app".to_owned();
        assert!(direct_iam_binding(&delegated).is_err());
        assert!(require_carbon(&delegated).is_err());
    }

    #[test]
    fn silicon_iam_tokens_require_exact_tenant_binding() {
        let organization_id = Uuid::from_u128(5);
        let membership_id = Uuid::from_u128(6);
        let mut authenticated = direct_carbon();
        authenticated.0.subject.actor_type = ActorType::Silicon;
        authenticated.0.organization_id = Some(organization_id);
        authenticated.0.membership_id = Some(membership_id);

        assert!(matches!(
            direct_iam_binding(&authenticated),
            Ok(DirectIamBinding::Silicon {
                organization_id: bound_organization_id,
                membership_id: bound_membership_id,
            }) if bound_organization_id == organization_id && bound_membership_id == membership_id
        ));

        authenticated.0.membership_id = None;
        assert!(direct_iam_binding(&authenticated).is_err());
    }
}
