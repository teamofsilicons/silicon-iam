//! The scoped service completes its own `tos>iam` login without distributing
//! the application's secret. Only this router can create its internal identity;
//! the public main-IAM protocol still requires `ApplicationClient` Basic auth.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, header},
    middleware::{self, Next},
    response::Response,
    routing::post,
};
use secrecy::SecretString;
use serde::Deserialize;
use tower_http::limit::RequestBodyLimitLayer;

use crate::{
    api::ApiState,
    domain::actor::ActorType,
    infrastructure::{
        postgres::{
            context::{self, DatabaseContext},
            tokens::{self, AccessContext},
        },
        testing_plane,
    },
};

use super::{
    error::ApiError,
    model::{AppTokenForm, IntrospectionResponse, TokenInput},
    oauth,
    security::{ApplicationIdentity, enforce_request_rate_limit},
};

const APP_ID: &str = "tos>iam";
const MAX_BODY_BYTES: usize = 4_096;

pub(crate) fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/introspect", post(introspect))
        .route_layer(middleware::from_fn(request_boundary))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    slt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refresh {
    refresh_token: String,
}

async fn request_boundary(request: Request, next: Next) -> Result<Response, ApiError> {
    // No query token, app selector or destination override can turn this fixed
    // service into a general relay. Testing plane selection occurs separately.
    if request.uri().query().is_some() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "Query parameters are not accepted.",
        ));
    }
    if request.uri().path() != "/api/v1/auth/introspect"
        && request.headers().contains_key(header::AUTHORIZATION)
    {
        return Err(ApiError::bad_request(
            "invalid_request",
            "Present the login or refresh credential in the JSON body.",
        ));
    }
    for name in ["idempotency-key", "x-org-id"] {
        if request.headers().get_all(name).iter().count() > 1 {
            return Err(ApiError::bad_request(
                "invalid_request",
                "A request header was repeated.",
            ));
        }
    }
    Ok(next.run(request).await)
}

async fn login(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> Result<Response, ApiError> {
    if !testing_plane::is_active() {
        require_credential(&input.slt, "oac_")?;
    } else if input.slt.is_empty() || input.slt.len() > 101 {
        return Err(ApiError::bad_request(
            "invalid_grant",
            "The testing actor is invalid.",
        ));
    }
    let client = service_identity(&state, "login", &input.slt).await?;
    let form = AppTokenForm {
        app_id: Some(APP_ID.into()),
        slt: Some(input.slt),
        refresh_token: None,
    };
    oauth::tokens_for_application(state, client, headers, form).await
}

async fn refresh(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<Refresh>,
) -> Result<Response, ApiError> {
    require_credential(&input.refresh_token, "ort_")?;
    let client = service_identity(&state, "refresh", &input.refresh_token).await?;
    let form = AppTokenForm {
        app_id: Some(APP_ID.into()),
        slt: None,
        refresh_token: Some(input.refresh_token),
    };
    oauth::tokens_for_application(state, client, headers, form).await
}

async fn logout(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<Refresh>,
) -> Result<Response, ApiError> {
    require_credential(&input.refresh_token, "ort_")?;
    let client = service_identity(&state, "logout", &input.refresh_token).await?;
    // The existing revoke machinery looks up a digest only within this exact
    // application. Unknown/other-app/already-revoked tokens are harmless no-ops.
    let input = TokenInput {
        token: input.refresh_token,
        token_type_hint: Some("refresh_token".into()),
    };
    oauth::revoke_for_application(state, client, headers, input).await
}

async fn introspect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<IntrospectionResponse>, ApiError> {
    if !body.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "Introspection accepts only the bearer header and no body.",
        ));
    }
    let token = bearer(&headers)?;
    let client = service_identity(&state, "introspect", &token).await?;
    let access = tokens::authenticate(
        state.db(),
        &state.crypto,
        &SecretString::from(token.clone()),
    )
    .await
    .map_err(|error| match error {
        tokens::AccessTokenError::InvalidFormat => ApiError::unauthenticated(),
        _ => ApiError::internal("scoped_auth_bearer"),
    })?
    .ok_or_else(ApiError::unauthenticated)?;
    if !is_service_session(&access, &client) {
        return Err(ApiError::forbidden("scoped_auth_application_mismatch"));
    }
    oauth::introspect_for_application(
        state,
        client,
        headers,
        TokenInput {
            token,
            token_type_hint: Some("access_token".into()),
        },
    )
    .await
}

fn is_service_session(access: &AccessContext, client: &ApplicationIdentity) -> bool {
    matches!(
        access.subject.actor_type,
        ActorType::Carbon | ActorType::Silicon
    ) && access.client_application_id == Some(client.application_id)
        && access.audience_application_id == Some(client.application_id)
        && access.audience == APP_ID
}

fn require_credential(value: &str, prefix: &str) -> Result<(), ApiError> {
    if !value.strip_prefix(prefix).is_some_and(|value| {
        value.len() == 43
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }) {
        return Err(ApiError::bad_request(
            "invalid_grant",
            "The credential is invalid.",
        ));
    }
    Ok(())
}

fn bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthenticated)?;
    if values.next().is_some() {
        return Err(ApiError::unauthenticated());
    }
    let (scheme, token) = value
        .split_once(' ')
        .ok_or_else(ApiError::unauthenticated)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || require_credential(token, "oat_").is_err() {
        return Err(ApiError::unauthenticated());
    }
    Ok(token.into())
}

async fn service_identity(
    state: &ApiState,
    route: &'static str,
    credential: &str,
) -> Result<ApplicationIdentity, ApiError> {
    // Public garbage credentials cannot exhaust a single shared app bucket.
    // The rate limiter persists only an HMAC digest of this credential scope.
    enforce_request_rate_limit(
        state,
        "scoped_application_auth",
        SecretString::from(format!(
            "application:{APP_ID}:{route}:credential:{credential}"
        )),
        120,
    )
    .await?;
    let mut tx = context::begin(state.db(), DatabaseContext::anonymous())
        .await
        .map_err(|_| ApiError::internal("scoped_auth_context"))?;
    // This private, argument-free database helper discloses only the identity
    // bound to this service. It never reads, decrypts, or returns an app secret.
    let query = if testing_plane::is_active() {
        "SELECT application_id, app_id, organization_id, auth_epoch FROM iam_private.resolve_testing_scoped_iam_application()"
    } else {
        "SELECT application_id, app_id, organization_id, auth_epoch FROM iam_private.resolve_scoped_iam_application()"
    };
    let identity =
        sqlx::query_as::<_, (crate::domain::id::Id, String, crate::domain::id::Id, i64)>(query)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| ApiError::internal("scoped_auth_registration"))?
            .ok_or_else(|| ApiError::forbidden("scoped_auth_application_unavailable"))?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("scoped_auth_context_commit"))?;
    if identity.1 != APP_ID {
        return Err(ApiError::internal("scoped_auth_registration_binding"));
    }
    Ok(ApplicationIdentity {
        application_id: identity.0,
        app_id: identity.1,
        organization_id: identity.2,
        auth_epoch: identity.3,
    })
}

#[cfg(test)]
#[path = "scoped_auth_tests.rs"]
mod tests;
