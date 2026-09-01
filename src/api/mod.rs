//! HTTP composition root and process lifecycle.

pub(crate) mod authentication;
pub(crate) mod me;

use std::{future::IntoFuture as _, sync::Arc, time::Instant};

use axum::{
    Json, Router,
    extract::{MatchedPath, Request, State},
    http::{HeaderMap, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse as _, Response},
    routing::get,
};
use serde::Serialize;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    sensitive_headers::{SetSensitiveRequestHeadersLayer, SetSensitiveResponseHeadersLayer},
    set_header::SetResponseHeaderLayer,
};
use tracing::{Instrument as _, info, info_span};
use uuid::Uuid;

use crate::{
    config::Settings,
    error::AppError,
    infrastructure::{
        crypto::CryptoService,
        postgres,
        providers::{NotificationProviders, workos::WorkOsClient},
    },
    request_context, shutdown,
};

#[derive(Clone)]
pub(crate) struct ApiState {
    pub(crate) pool: PgPool,
    pub(crate) settings: Arc<Settings>,
    pub(crate) crypto: Arc<CryptoService>,
    pub(crate) notifications: NotificationProviders,
    pub(crate) workos: Option<Arc<WorkOsClient>>,
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Serialize)]
struct VersionResponse {
    service: &'static str,
    api_version: &'static str,
    build: &'static str,
    commit: &'static str,
}

#[derive(Serialize)]
struct NegotiatedVersionResponse {
    service: &'static str,
    selected_api_version: &'static str,
    supported_api_versions: &'static [&'static str],
    build: &'static str,
    commit: &'static str,
}

const SUPPORTED_API_VERSIONS: &[&str] = &["v1"];
const SUPPORTED_API_VERSIONS_HEADER: &str = "silicon-iam-supported-api-versions";
const SELECTED_API_VERSION_HEADER: &str = "silicon-iam-api-version";

/// Connects dependencies and serves the HTTP API until graceful shutdown.
///
/// # Errors
///
/// Returns an error when PostgreSQL or the listener cannot be initialized, or
/// when the HTTP server exits unexpectedly.
pub async fn serve(settings: Settings) -> anyhow::Result<()> {
    let pool = postgres::connect(&settings.database, "iam-api").await?;
    postgres::register_runtime_key_versions(&pool, &settings.security).await?;
    let bind_addr = settings.server.bind_addr;
    let crypto = CryptoService::from_settings(&settings.security)?;
    let notifications = NotificationProviders::from_settings(&settings.providers)?;
    let workos = WorkOsClient::from_settings(&settings.providers)?.map(Arc::new);
    let state = ApiState {
        pool,
        settings: Arc::new(settings),
        crypto: Arc::new(crypto),
        notifications,
        workos,
    };
    let app = router(state.clone())?;
    let listener = TcpListener::bind(bind_addr).await?;
    let shutdown_timeout = state.settings.server.shutdown_timeout;
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();

    info!(%bind_addr, "Silicon IAM API listening");
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_receiver.await;
        })
        .into_future();
    tokio::pin!(server);

    tokio::select! {
        result = &mut server => result?,
        result = shutdown::signal() => {
            result?;
            let _ = shutdown_sender.send(());
            if let Ok(result) = tokio::time::timeout(shutdown_timeout, &mut server).await {
                result?;
            } else {
                tracing::error!("API graceful-shutdown deadline elapsed");
            }
        }
    }
    if tokio::time::timeout(shutdown_timeout, state.pool.close())
        .await
        .is_err()
    {
        tracing::error!("API database-pool shutdown deadline elapsed");
    }
    Ok(())
}

fn router(state: ApiState) -> anyhow::Result<Router> {
    let max_body_bytes = state.settings.server.max_body_bytes;
    let request_timeout = state.settings.server.request_timeout;
    let admission = Arc::new(Semaphore::new(
        state.settings.server.max_concurrent_requests,
    ));
    let sensitive_request_headers = [
        http::header::AUTHORIZATION,
        http::header::COOKIE,
        http::HeaderName::from_static("idempotency-key"),
        http::HeaderName::from_static("x-csrf-token"),
        http::HeaderName::from_static("x-step-up-token"),
        http::HeaderName::from_static("workos-signature"),
    ];
    let sensitive_response_headers = [http::header::SET_COOKIE, http::header::LOCATION];

    let allowed_origins = state
        .settings
        .server
        .cors_allowed_origins
        .iter()
        .map(|origin| origin.origin().ascii_serialization().parse())
        .collect::<Result<Vec<http::HeaderValue>, _>>()?;
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_credentials(true)
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::PUT,
            http::Method::PATCH,
            http::Method::DELETE,
            http::Method::OPTIONS,
        ])
        .allow_headers([
            http::header::ACCEPT,
            http::header::AUTHORIZATION,
            http::header::CONTENT_TYPE,
            http::HeaderName::from_static("idempotency-key"),
            http::header::IF_MATCH,
            http::HeaderName::from_static("x-csrf-token"),
            http::HeaderName::from_static("x-org-id"),
            http::HeaderName::from_static("x-request-id"),
            http::HeaderName::from_static("x-step-up-token"),
            http::HeaderName::from_static(SUPPORTED_API_VERSIONS_HEADER),
        ])
        .expose_headers([
            http::header::ETAG,
            http::header::LOCATION,
            http::header::RETRY_AFTER,
            http::HeaderName::from_static("idempotency-replayed"),
            http::HeaderName::from_static("ratelimit-limit"),
            http::HeaderName::from_static("ratelimit-remaining"),
            http::HeaderName::from_static("ratelimit-reset"),
            http::HeaderName::from_static("x-request-id"),
            http::HeaderName::from_static(SELECTED_API_VERSION_HEADER),
        ])
        .max_age(std::time::Duration::from_mins(10));

    // The JSON contract. Everything under this router answers with the error
    // envelope and is never cached.
    let api = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/api/version", get(negotiate_api_version))
        .route("/api/v1/version", get(version))
        .route("/api/v1/me", get(me::get).patch(me::patch))
        .merge(crate::features::authentication::router())
        .merge(crate::features::organizations::router())
        .merge(crate::features::applications::router())
        .merge(crate::features::sso::router())
        .layer(middleware::from_fn(normalize_errors))
        .layer(SetResponseHeaderLayer::if_not_present(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        ));

    /*
     * The HTML surfaces: /admin and /docs/api/.
     *
     * Merged as a sibling rather than nested, so they sit OUTSIDE the JSON
     * router's own layers. Two of those layers would actively break them:
     * `normalize_errors` rewrites any non-JSON 4xx into the error envelope,
     * which would turn the documentation's 404 page into a machine-readable
     * blob; and the `no-store` default would make every static asset
     * uncacheable. Both surfaces set their own Content-Type, Cache-Control
     * and Content-Security-Policy.
     *
     * They still share the request-scope, timeout, admission and panic layers
     * applied to the whole application below, because those are process
     * protections rather than contract behaviour.
     */
    let router = api
        .merge(crate::web::router())
        /*
         * A path that matches no route at all.
         *
         * `normalize_errors` sits on the API router, so it never sees a request
         * that failed to match anything — that lands on the composed router's
         * fallback instead. Without this, an unknown path would answer with
         * Axum's bare empty 404 and break the contract's promise that every
         * JSON error looks the same. The HTML surfaces are unaffected: their
         * own handlers own their 404s.
         */
        .fallback(|| async { AppError::NotFound })
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(SetSensitiveRequestHeadersLayer::new(
                    sensitive_request_headers,
                ))
                .layer(SetSensitiveResponseHeadersLayer::new(
                    sensitive_response_headers,
                ))
                .layer(RequestBodyLimitLayer::new(max_body_bytes))
                .layer(CatchPanicLayer::custom(handle_panic)),
        )
        .layer(middleware::from_fn_with_state(
            request_timeout,
            enforce_timeout,
        ))
        .layer(middleware::from_fn_with_state(admission, enforce_admission))
        .layer(cors)
        .layer(middleware::from_fn(request_scope))
        .layer(SetResponseHeaderLayer::if_not_present(
            http::HeaderName::from_static("x-content-type-options"),
            http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            http::HeaderName::from_static("referrer-policy"),
            http::HeaderValue::from_static("no-referrer"),
        ));
    Ok(router)
}

/// Rewrites a non-JSON error into the contract's error envelope.
///
/// Applied only to the JSON router. Axum's own rejections — an unmatched
/// route, a method mismatch, a body that exceeded the limit — are plain text,
/// and a client that has been promised one error shape everywhere should get
/// it here too.
async fn normalize_errors(request: Request, next: Next) -> Response {
    normalize_error_response(next.run(request).await)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

async fn readiness(
    axum::extract::State(state): axum::extract::State<ApiState>,
) -> Result<Json<HealthResponse>, AppError> {
    if postgres::ready(&state.pool).await {
        Ok(Json(HealthResponse { ok: true }))
    } else {
        Err(AppError::ServiceUnavailable)
    }
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        service: "silicon-iam",
        api_version: "v1",
        build: env!("CARGO_PKG_VERSION"),
        commit: option_env!("SILICON_IAM_GIT_COMMIT").unwrap_or("unknown"),
    })
}

async fn negotiate_api_version(headers: HeaderMap) -> Result<Response, AppError> {
    let advertised = supported_versions_header(&headers)?;
    let selected = select_api_version(&advertised).ok_or(AppError::ApiVersionNotAcceptable {
        supported_versions: SUPPORTED_API_VERSIONS,
    })?;
    let mut response = Json(NegotiatedVersionResponse {
        service: "silicon-iam",
        selected_api_version: selected,
        supported_api_versions: SUPPORTED_API_VERSIONS,
        build: env!("CARGO_PKG_VERSION"),
        commit: option_env!("SILICON_IAM_GIT_COMMIT").unwrap_or("unknown"),
    })
    .into_response();
    response.headers_mut().insert(
        http::HeaderName::from_static(SELECTED_API_VERSION_HEADER),
        HeaderValue::from_static(selected),
    );
    response.headers_mut().insert(
        http::header::VARY,
        HeaderValue::from_static("Silicon-IAM-Supported-API-Versions"),
    );
    Ok(response)
}

fn select_api_version(advertised: &[&str]) -> Option<&'static str> {
    SUPPORTED_API_VERSIONS
        .iter()
        .copied()
        .find(|version| advertised.iter().any(|candidate| candidate == version))
}

fn supported_versions_header(headers: &HeaderMap) -> Result<Vec<&str>, AppError> {
    let mut values = headers
        .get_all(http::HeaderName::from_static(SUPPORTED_API_VERSIONS_HEADER))
        .iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 255)
        .ok_or_else(|| AppError::Validation {
            details: serde_json::json!({
                "silicon_iam_supported_api_versions": "must be supplied exactly once",
            }),
        })?;
    if values.next().is_some() {
        return Err(AppError::Validation {
            details: serde_json::json!({
                "silicon_iam_supported_api_versions": "must be supplied exactly once",
            }),
        });
    }

    let versions = value.split(',').map(str::trim).collect::<Vec<_>>();
    if versions.is_empty()
        || versions.len() > 16
        || versions
            .iter()
            .any(|version| !is_valid_api_version(version))
        || versions
            .iter()
            .enumerate()
            .any(|(index, version)| versions[..index].contains(version))
    {
        return Err(AppError::Validation {
            details: serde_json::json!({
                "silicon_iam_supported_api_versions":
                    "must contain 1 to 16 comma-separated versions such as v1",
            }),
        });
    }
    Ok(versions)
}

fn is_valid_api_version(version: &str) -> bool {
    version.strip_prefix('v').is_some_and(|major| {
        !major.is_empty()
            && major.len() <= 9
            && !major.starts_with('0')
            && major.bytes().all(|byte| byte.is_ascii_digit())
    })
}

async fn request_scope(mut request: Request, next: Next) -> Response {
    let request_id = validated_request_id(&request).unwrap_or_else(|| Uuid::now_v7().to_string());
    if let Ok(header_value) = request_id.parse() {
        request
            .headers_mut()
            .insert(http::HeaderName::from_static("x-request-id"), header_value);
    }

    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("<unmatched>", MatchedPath::as_str);
    let started_at = Instant::now();
    let span = info_span!(
        "http.request",
        request_id = %request_id,
        method = %method,
        route = %route,
        status = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
    );

    let future = next.run(request);
    let mut response = request_context::scope(request_id.clone(), future)
        .instrument(span.clone())
        .await;
    span.record("status", response.status().as_u16());
    let latency_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    span.record("latency_ms", latency_ms);
    info!(parent: &span, "HTTP request completed");

    if let Ok(header_value) = request_id.parse() {
        response
            .headers_mut()
            .insert(http::HeaderName::from_static("x-request-id"), header_value);
    }
    response
}

async fn enforce_timeout(
    State(request_timeout): State<std::time::Duration>,
    request: Request,
    next: Next,
) -> Response {
    match tokio::time::timeout(request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => AppError::Timeout.into_response(),
    }
}

async fn enforce_admission(
    State(admission): State<Arc<Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = admission.try_acquire_owned() else {
        return AppError::Overloaded.into_response();
    };
    next.run(request).await
}

fn validated_request_id(request: &Request) -> Option<String> {
    let value = request
        .headers()
        .get(http::HeaderName::from_static("x-request-id"))?
        .to_str()
        .ok()?;
    Uuid::parse_str(value).ok().map(|id| id.to_string())
}

fn normalize_error_response(response: Response) -> Response {
    if !response.status().is_client_error() && !response.status().is_server_error() {
        return response;
    }
    let is_json = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if is_json {
        return response;
    }

    let replacement = match response.status() {
        http::StatusCode::NOT_FOUND => AppError::NotFound.into_response(),
        http::StatusCode::METHOD_NOT_ALLOWED => AppError::MethodNotAllowed.into_response(),
        http::StatusCode::PAYLOAD_TOO_LARGE => AppError::PayloadTooLarge.into_response(),
        http::StatusCode::REQUEST_TIMEOUT | http::StatusCode::GATEWAY_TIMEOUT => {
            AppError::Timeout.into_response()
        }
        status => AppError::TransportRejected { status }.into_response(),
    };

    let (original_parts, _) = response.into_parts();
    let (mut replacement_parts, replacement_body) = replacement.into_parts();
    replacement_parts.status = original_parts.status;
    for (name, value) in &original_parts.headers {
        if name != http::header::CONTENT_TYPE && name != http::header::CONTENT_LENGTH {
            replacement_parts
                .headers
                .append(name.clone(), value.clone());
        }
    }
    Response::from_parts(replacement_parts, replacement_body)
}

fn handle_panic(_panic: Box<dyn std::any::Any + Send + 'static>) -> Response {
    AppError::Internal {
        category: "request_handler_panic",
    }
    .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        http::{HeaderMap, HeaderValue, StatusCode, header},
        response::{IntoResponse as _, Response},
    };

    use super::{
        SELECTED_API_VERSION_HEADER, SUPPORTED_API_VERSIONS_HEADER, is_valid_api_version,
        negotiate_api_version, normalize_error_response, select_api_version,
        supported_versions_header,
    };

    fn plain(status: StatusCode, body: &'static str) -> Response {
        (status, body).into_response()
    }

    #[test]
    fn a_non_json_client_error_is_rewritten_into_the_envelope() {
        // Axum's own rejections are plain text. A client promised one error
        // shape everywhere should get it for those too.
        let response = normalize_error_response(plain(StatusCode::NOT_FOUND, "not found"));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("application/json"),
            "{content_type}"
        );
    }

    #[test]
    fn a_json_error_is_left_alone() {
        let mut response = plain(StatusCode::CONFLICT, "{}");
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        let normalized = normalize_error_response(response);
        assert_eq!(normalized.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn a_success_is_never_rewritten() {
        // The HTML surfaces answer 200 with text/html and must survive intact.
        let mut response = plain(StatusCode::OK, "<!doctype html>");
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/html; charset=utf-8"),
        );
        let normalized = normalize_error_response(response);
        let content_type = normalized
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(content_type.starts_with("text/html"), "{content_type}");
    }

    #[test]
    fn api_version_syntax_is_strict_and_future_compatible() {
        assert!(is_valid_api_version("v1"));
        assert!(is_valid_api_version("v27"));
        for invalid in ["", "1", "v0", "v01", "V1", "v1.1", "v1234567890"] {
            assert!(!is_valid_api_version(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn supported_versions_are_trimmed_and_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(
            SUPPORTED_API_VERSIONS_HEADER,
            HeaderValue::from_static("v3, v2,v1"),
        );
        let Ok(versions) = supported_versions_header(&headers) else {
            panic!("a valid version advertisement must parse");
        };
        assert_eq!(versions, vec!["v3", "v2", "v1"]);

        headers.insert(
            SUPPORTED_API_VERSIONS_HEADER,
            HeaderValue::from_static("v0"),
        );
        assert!(supported_versions_header(&headers).is_err());

        headers.insert(
            SUPPORTED_API_VERSIONS_HEADER,
            HeaderValue::from_static("v1,"),
        );
        assert!(supported_versions_header(&headers).is_err());

        headers.insert(
            SUPPORTED_API_VERSIONS_HEADER,
            HeaderValue::from_static("v1,v1"),
        );
        assert!(supported_versions_header(&headers).is_err());
    }

    #[test]
    fn server_selects_only_the_highest_mutually_supported_version() {
        assert_eq!(select_api_version(&["v3", "v1"]), Some("v1"));
        assert_eq!(select_api_version(&["v3", "v2"]), None);
    }

    #[tokio::test]
    async fn negotiation_response_identifies_its_selected_varying_version() {
        let mut headers = HeaderMap::new();
        headers.insert(
            SUPPORTED_API_VERSIONS_HEADER,
            HeaderValue::from_static("v2,v1"),
        );
        let Ok(response) = negotiate_api_version(headers).await else {
            panic!("v1 must be mutually supported");
        };
        assert_eq!(
            response
                .headers()
                .get(SELECTED_API_VERSION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("v1")
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::VARY)
                .and_then(|value| value.to_str().ok()),
            Some("Silicon-IAM-Supported-API-Versions")
        );
    }
}
