//! Shared platform authorization, precondition, and response helpers.

use std::borrow::Cow;

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use secrecy::SecretString;
use serde::Serialize;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::actor::ActorType,
    error::AppError,
    infrastructure::postgres::{
        idempotency::{self, IdempotencyClaim, IdempotencyKey, IdempotencyRequest, ReplayResponse},
        step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
        tokens::AccessContext,
    },
};

pub(super) fn require_carbon(access: &AccessContext) -> Result<Uuid, AppError> {
    if access.subject.actor_type != ActorType::Carbon
        || access.audience != "silicon-iam"
        || access.client_application_id.is_some()
        || access.organization_id.is_some()
        || access.membership_id.is_some()
        || !access.scopes.iter().any(|scope| scope == "iam.self")
    {
        return Err(AppError::Forbidden);
    }
    Ok(access.subject.id)
}

pub(super) async fn begin_serializable(
    state: &ApiState,
    principal_id: Uuid,
) -> Result<Transaction<'_, Postgres>, AppError> {
    let mut transaction = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        r"
        SELECT
            set_config('iam.principal_id', $1, true),
            set_config('iam.organization_id', '', true),
            set_config('iam.application_id', '', true),
            set_config('iam.signup_session_id', '', true)
        ",
    )
    .bind(principal_id.to_string())
    .execute(&mut *transaction)
    .await?;
    Ok(transaction)
}

pub(super) async fn require_platform_capability(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    capability: &'static str,
) -> Result<(), AppError> {
    let allowed =
        sqlx::query_scalar::<_, bool>("SELECT iam_private.has_platform_capability($1, $2)")
            .bind(carbon_id)
            .bind(capability)
            .fetch_one(&mut **transaction)
            .await?;
    if allowed {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(super) async fn consume_step_up(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    headers: &HeaderMap,
    access: &AccessContext,
    action: &'static str,
    resource_id: Option<Uuid>,
) -> Result<(), AppError> {
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
            carbon_id: access.subject.id,
            authentication_session_id: access.authentication_session_id,
            action,
            resource_id,
            required_assurance: RequiredAssurance::PhishingResistant,
        },
    )
    .await?;
    Ok(())
}

pub(super) async fn claim<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    headers: &HeaderMap,
    caller_id: Uuid,
    route: &'static str,
    request: &T,
) -> Result<IdempotencyClaim, AppError> {
    let raw_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::PreconditionRequired {
            code: Cow::Borrowed("idempotency_key_required"),
        })?;
    let key = IdempotencyKey::parse(raw_key).map_err(|_| AppError::Validation {
        details: serde_json::json!({
            "field": "Idempotency-Key",
            "message": "must contain 16 to 255 visible ASCII characters"
        }),
    })?;
    let payload = serde_json::to_string(request).map_err(|_| AppError::Internal {
        category: "administration_idempotency_serialize",
    })?;
    let caller_scope = SecretString::from(format!("platform-admin:{caller_id}"));
    let request_payload = SecretString::from(payload);
    idempotency::claim(
        transaction,
        &state.crypto,
        IdempotencyRequest {
            route,
            caller_scope: &caller_scope,
            key: &key,
            request_payload: &request_payload,
            contains_one_time_secret: false,
        },
    )
    .await
}

pub(super) fn expected_version(headers: &HeaderMap) -> Result<i64, AppError> {
    let value = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::PreconditionRequired {
            code: Cow::Borrowed("if_match_required"),
        })?;
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|version| *version > 0)
        .ok_or(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_invalid"),
        })
}

pub(super) fn json<T: Serialize>(
    status: StatusCode,
    value: &T,
    version: Option<i64>,
) -> Result<(Vec<u8>, Response), AppError> {
    let body = serde_json::to_vec(value).map_err(|_| AppError::Internal {
        category: "administration_response_serialize",
    })?;
    let response = raw_json(status, body.clone(), version, false)?;
    Ok((body, response))
}

pub(super) fn replay(response: ReplayResponse, version: Option<i64>) -> Result<Response, AppError> {
    raw_json(
        StatusCode::from_u16(response.status).map_err(|_| AppError::Internal {
            category: "administration_replay_status",
        })?,
        response.body,
        version,
        true,
    )
}

pub(super) fn empty(status: StatusCode, replayed: bool) -> Result<Response, AppError> {
    let mut response = Response::builder()
        .status(status)
        .body(Body::empty())
        .map_err(|_| AppError::Internal {
            category: "administration_response_build",
        })?;
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    Ok(response)
}

fn raw_json(
    status: StatusCode,
    body: Vec<u8>,
    version: Option<i64>,
    replayed: bool,
) -> Result<Response, AppError> {
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| AppError::Internal {
            category: "administration_response_build",
        })?;
    if let Some(version) = version {
        let etag =
            HeaderValue::try_from(format!("\"{version}\"")).map_err(|_| AppError::Internal {
                category: "administration_etag",
            })?;
        response.headers_mut().insert(header::ETAG, etag);
    }
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::require_carbon;
    use crate::{
        domain::actor::{ActorRef, ActorType},
        infrastructure::postgres::tokens::AccessContext,
    };
    use uuid::Uuid;

    fn direct_access() -> AccessContext {
        AccessContext {
            token_id: Uuid::now_v7(),
            authentication_session_id: Uuid::now_v7(),
            subject: ActorRef {
                actor_type: ActorType::Carbon,
                id: Uuid::now_v7(),
            },
            client_application_id: None,
            audience: "silicon-iam".to_owned(),
            organization_id: None,
            membership_id: None,
            scopes: vec!["iam.self".to_owned()],
            assurance_level: 1,
        }
    }

    #[test]
    fn delegated_carbon_tokens_cannot_administer_the_platform() {
        let direct = direct_access();
        assert!(require_carbon(&direct).is_ok());

        let mut delegated = direct_access();
        delegated.client_application_id = Some(Uuid::now_v7());
        delegated.audience = "third_party_app".to_owned();
        assert!(require_carbon(&delegated).is_err());
    }
}
