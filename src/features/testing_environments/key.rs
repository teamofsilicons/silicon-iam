//! Authority carried by a testing environment key.
//!
//! The key is the root credential of one environment. Presenting it on an
//! ordinary API request moves that whole request onto the testing plane; a
//! request that reaches this module without one is untouched and stays on
//! production.

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use secrecy::SecretString;
use sqlx::{Postgres, Transaction};

use crate::{
    api::ApiState,
    error::AppError,
    infrastructure::{
        postgres::idempotency::{self, IdempotencyClaim, IdempotencyKey},
        testing_plane::{self, SelectedEnvironment},
    },
};

use super::{
    support::{self, AdministeredEnvironment, Claim},
    validation,
};

/// Request header naming the environment a request should execute inside.
pub(crate) const ENVIRONMENT_KEY_HEADER: &str = "x-testing-environment-key";

/// A verified environment key and the environment it opens.
pub(super) struct EnvironmentKeyHolder {
    pub(super) environment: AdministeredEnvironment,
}

impl FromRequestParts<ApiState> for EnvironmentKeyHolder {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        support::plane(state)?;
        let presented = presented_key(&parts.headers)?.ok_or(AppError::Unauthenticated)?;
        let environment = support::resolve_key(&state.pool, state, &presented)
            .await?
            .ok_or(AppError::Unauthenticated)?;
        Ok(Self { environment })
    }
}

/// Moves a request onto the testing plane when it presents a valid key.
///
/// Applied to the feature routers rather than to the whole API, so the
/// control-plane routes -- which read and write production, and are what mints
/// these keys in the first place -- are structurally outside its reach rather
/// than relying on each handler to opt out.
pub(crate) async fn select_plane(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    let presented = match presented_key(request.headers()) {
        Ok(None) => return next.run(request).await,
        Ok(Some(presented)) => presented,
        Err(error) => return error.into_response(),
    };

    // The header is only meaningful where a testing database exists. Answering
    // "unauthenticated" instead would send an operator hunting for a bad key.
    let Some(plane) = state.testing.as_ref() else {
        return AppError::ServiceUnavailable.into_response();
    };
    let _ = plane;

    let resolved = match support::resolve_key(&state.pool, &state, &presented).await {
        Ok(Some(environment)) => environment,
        Ok(None) => return AppError::Unauthenticated.into_response(),
        Err(error) => return error.into_response(),
    };
    let selected = SelectedEnvironment {
        id: resolved.id,
        organization_id: resolved.organization_id,
    };
    support::touch(&state.pool, selected.id).await;

    testing_plane::scope(selected, next.run(request)).await
}

/// Reserves an idempotency key for a mutation authorized by the environment
/// key alone.
///
/// The caller boundary is the environment itself: two holders of the same key
/// are the same caller here, which is exactly the semantics that makes a
/// retried clean idempotent no matter who retries it.
pub(super) async fn claim_for_key_holder(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    holder: &EnvironmentKeyHolder,
    headers: &HeaderMap,
    route: &'static str,
) -> Result<Claim, AppError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| validation::field("idempotency_key", "is required"))?;
    let key = IdempotencyKey::parse(key).map_err(|_| {
        validation::field(
            "idempotency_key",
            "must contain 16 to 255 visible ASCII characters",
        )
    })?;
    let caller_scope =
        SecretString::from(format!("testing_environment_key:{}", holder.environment.id));
    let request_payload = SecretString::from("{}".to_owned());

    match idempotency::claim(
        transaction,
        &state.crypto,
        idempotency::IdempotencyRequest {
            route,
            caller_scope: &caller_scope,
            key: &key,
            request_payload: &request_payload,
            contains_one_time_secret: false,
        },
    )
    .await?
    {
        IdempotencyClaim::Acquired(lease) => Ok(Claim::Acquired(lease)),
        IdempotencyClaim::Replay(replay) => {
            let status = StatusCode::from_u16(replay.status).map_err(|_| AppError::Internal {
                category: "testing_environment_replay_status",
            })?;
            let mut response = support::json_response(status, replay.body, None, false)?;
            response.headers_mut().insert(
                http::HeaderName::from_static("idempotency-replayed"),
                http::HeaderValue::from_static("true"),
            );
            Ok(Claim::Replay(response))
        }
    }
}

/// Extracts a syntactically valid key, refusing anything ambiguous.
///
/// A repeated header is rejected rather than resolved to its first value: two
/// environment keys on one request has no correct interpretation.
fn presented_key(headers: &HeaderMap) -> Result<Option<String>, AppError> {
    let mut values = headers
        .get_all(http::HeaderName::from_static(ENVIRONMENT_KEY_HEADER))
        .iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AppError::Unauthenticated);
    }
    let value = value.to_str().map_err(|_| AppError::Unauthenticated)?;
    validation::key_shape(value)
        .map(|value| Some(value.to_owned()))
        .ok_or(AppError::Unauthenticated)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{ENVIRONMENT_KEY_HEADER, presented_key};

    #[test]
    fn an_absent_header_leaves_the_request_on_production() {
        let Ok(presented) = presented_key(&HeaderMap::new()) else {
            panic!("an absent header is not an error");
        };
        assert_eq!(presented, None);
    }

    #[test]
    fn a_repeated_or_malformed_key_is_refused() {
        let mut headers = HeaderMap::new();
        let valid = "a".repeat(32);
        let Ok(value) = HeaderValue::from_str(&valid) else {
            panic!("a 32-character key must encode as a header value");
        };
        headers.insert(ENVIRONMENT_KEY_HEADER, value.clone());
        assert!(matches!(presented_key(&headers), Ok(Some(_))));

        headers.append(ENVIRONMENT_KEY_HEADER, value);
        assert!(presented_key(&headers).is_err());

        let mut short = HeaderMap::new();
        short.insert(ENVIRONMENT_KEY_HEADER, HeaderValue::from_static("abc"));
        assert!(presented_key(&short).is_err());
    }
}
