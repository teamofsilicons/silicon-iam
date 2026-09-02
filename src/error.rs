//! Stable application errors and public HTTP error representation.

use std::borrow::Cow;

use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use tracing::error;

/// Error returned by an IAM use case.
#[derive(Debug, Error)]
pub enum AppError {
    /// Request input is invalid.
    #[error("request validation failed")]
    Validation {
        /// Machine-readable validation details.
        details: Value,
    },
    /// Credential is absent, invalid, expired, or revoked.
    #[error("authentication is required")]
    Unauthenticated,
    /// Authenticated actor lacks required authority.
    #[error("the actor is not authorized for this action")]
    Forbidden,
    /// Requested resource does not exist or is not visible.
    #[error("resource was not found")]
    NotFound,
    /// Authenticated Carbon has no matching usable organization invitation.
    #[error("the authenticated Carbon is not invited")]
    NotInvited,
    /// Mutation conflicts with current state or a unique invariant.
    #[error("request conflicts with current state")]
    Conflict {
        /// Stable conflict code.
        code: Cow<'static, str>,
    },
    /// A resource or one-time credential existed but is no longer usable.
    #[error("the requested resource is no longer available")]
    Gone {
        /// Stable expiration or consumption code.
        code: Cow<'static, str>,
    },
    /// A required optimistic-concurrency or step-up precondition was omitted.
    #[error("a required request precondition is missing")]
    PreconditionRequired {
        /// Stable missing-precondition code.
        code: Cow<'static, str>,
    },
    /// A supplied optimistic-concurrency or step-up precondition did not hold.
    #[error("a request precondition failed")]
    PreconditionFailed {
        /// Stable failed-precondition code.
        code: Cow<'static, str>,
    },
    /// A distributed abuse-control limit was exceeded.
    #[error("rate limit exceeded")]
    RateLimited {
        /// Effective request or verification-attempt limit.
        limit: u64,
        /// Requests or verification attempts remaining in the active bucket.
        remaining: u64,
        /// Seconds until the active bucket resets.
        reset_after_seconds: u64,
        /// Seconds until another attempt may be made.
        retry_after_seconds: u64,
    },
    /// Request processing exceeded the server deadline.
    #[error("request processing deadline exceeded")]
    Timeout,
    /// Request body exceeds the configured maximum.
    #[error("request body is too large")]
    PayloadTooLarge,
    /// The route exists but not for the requested method.
    #[error("method is not allowed for this route")]
    MethodNotAllowed,
    /// External provider is temporarily unavailable.
    #[error("an external provider is unavailable")]
    ProviderUnavailable,
    /// A required service dependency is temporarily unavailable.
    #[error("the service is temporarily unavailable")]
    ServiceUnavailable,
    /// The client and server do not support a common public API version.
    #[error("the client and server do not support a common API version")]
    ApiVersionNotAcceptable {
        /// Server API versions in descending preference order.
        supported_versions: &'static [&'static str],
    },
    /// Server admission is at its configured concurrency capacity.
    #[error("server admission capacity is exhausted")]
    Overloaded,
    /// A transport layer rejected a request before a typed extractor ran.
    #[error("request was rejected with HTTP status {status}")]
    TransportRejected {
        /// Original transport status, preserved in the response.
        status: StatusCode,
    },
    /// Unexpected internal failure whose detail must not cross the API boundary.
    #[error("internal service error in {category}")]
    Internal {
        /// Static subsystem label safe for production logs.
        category: &'static str,
    },
}

/// Public structured error envelope.
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    error: PublicError,
}

#[derive(Debug, Serialize)]
struct PublicError {
    code: Cow<'static, str>,
    message: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Value>,
    request_id: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let rate_limit = match &self {
            Self::RateLimited {
                limit,
                remaining,
                reset_after_seconds,
                retry_after_seconds,
            } => Some((
                *limit,
                *remaining,
                *reset_after_seconds,
                *retry_after_seconds,
            )),
            _ => None,
        };
        let unauthenticated = matches!(self, Self::Unauthenticated);
        let service_unavailable = matches!(
            self,
            Self::ProviderUnavailable | Self::ServiceUnavailable | Self::Overloaded
        );
        let (status, code, message, details) = self.public_parts();
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: PublicError {
                    code,
                    message,
                    details,
                    request_id: request_id(),
                },
            }),
        )
            .into_response();
        if let Some((limit, remaining, reset_after_seconds, retry_after_seconds)) = rate_limit {
            insert_numeric_header(
                response.headers_mut(),
                header::RETRY_AFTER,
                retry_after_seconds,
            );
            insert_numeric_header(
                response.headers_mut(),
                HeaderName::from_static("ratelimit-limit"),
                limit,
            );
            insert_numeric_header(
                response.headers_mut(),
                HeaderName::from_static("ratelimit-remaining"),
                remaining,
            );
            insert_numeric_header(
                response.headers_mut(),
                HeaderName::from_static("ratelimit-reset"),
                reset_after_seconds,
            );
        }
        if unauthenticated {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        if service_unavailable {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        }
        response
    }
}

impl AppError {
    /// Validation failure describing exactly one offending request field.
    pub(crate) fn invalid_field(field: impl Into<String>, message: &'static str) -> Self {
        Self::Validation {
            details: serde_json::json!({
                "fields": [{ "field": field.into(), "message": message }],
            }),
        }
    }

    /// Maps a rejected JSON body onto a validation error that names the
    /// offending field.
    ///
    /// Serde knows precisely why deserialization failed, but its message can
    /// embed the submitted value, so only the field name is surfaced, and only
    /// when it is a plain identifier. Every other shape stays generic.
    pub(crate) fn from_json_rejection(rejection: &JsonRejection) -> Self {
        match rejection {
            JsonRejection::MissingJsonContentType(_) => {
                Self::invalid_field("content-type", "must be application/json")
            }
            JsonRejection::JsonSyntaxError(_) => Self::invalid_field("body", "must be valid JSON"),
            JsonRejection::JsonDataError(error) => json_data_error(&error.body_text()),
            _ => Self::invalid_field("body", "must match the documented JSON schema"),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive mapping keeps every public status, code, and message auditable"
    )]
    fn public_parts(
        self,
    ) -> (
        StatusCode,
        Cow<'static, str>,
        Cow<'static, str>,
        Option<Value>,
    ) {
        match self {
            Self::Validation { details } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Cow::Borrowed("validation_failed"),
                Cow::Borrowed("The request contains invalid data."),
                Some(details),
            ),
            Self::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                Cow::Borrowed("unauthenticated"),
                Cow::Borrowed("Authentication is required."),
                None,
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                Cow::Borrowed("forbidden"),
                Cow::Borrowed("The actor is not authorized for this action."),
                None,
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                Cow::Borrowed("not_found"),
                Cow::Borrowed("The requested resource was not found."),
                None,
            ),
            Self::NotInvited => (
                StatusCode::NOT_FOUND,
                Cow::Borrowed("not_invited"),
                Cow::Borrowed("The authenticated Carbon is not invited."),
                None,
            ),
            Self::Conflict { code } => (
                StatusCode::CONFLICT,
                code,
                Cow::Borrowed("The request conflicts with the current resource state."),
                None,
            ),
            Self::Gone { code } => (
                StatusCode::GONE,
                code,
                Cow::Borrowed("The requested resource is no longer available."),
                None,
            ),
            Self::PreconditionRequired { code } => (
                StatusCode::PRECONDITION_REQUIRED,
                code,
                Cow::Borrowed("A required request precondition is missing."),
                None,
            ),
            Self::PreconditionFailed { code } => (
                StatusCode::PRECONDITION_FAILED,
                code,
                Cow::Borrowed("A supplied request precondition did not hold."),
                None,
            ),
            Self::RateLimited {
                limit,
                remaining,
                reset_after_seconds,
                retry_after_seconds,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                Cow::Borrowed("rate_limited"),
                Cow::Borrowed("Too many requests. Retry later."),
                Some(serde_json::json!({
                    "limit": limit,
                    "remaining": remaining,
                    "reset_after_seconds": reset_after_seconds,
                    "retry_after_seconds": retry_after_seconds,
                })),
            ),
            Self::Timeout => (
                StatusCode::GATEWAY_TIMEOUT,
                Cow::Borrowed("request_timeout"),
                Cow::Borrowed("The request exceeded its processing deadline."),
                None,
            ),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Cow::Borrowed("payload_too_large"),
                Cow::Borrowed("The request body exceeds the allowed size."),
                None,
            ),
            Self::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                Cow::Borrowed("method_not_allowed"),
                Cow::Borrowed("The HTTP method is not allowed for this route."),
                None,
            ),
            Self::ProviderUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                Cow::Borrowed("provider_unavailable"),
                Cow::Borrowed("A required provider is temporarily unavailable."),
                None,
            ),
            Self::ServiceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                Cow::Borrowed("service_unavailable"),
                Cow::Borrowed("The service is temporarily unavailable."),
                None,
            ),
            Self::ApiVersionNotAcceptable { supported_versions } => (
                StatusCode::NOT_ACCEPTABLE,
                Cow::Borrowed("api_version_not_acceptable"),
                Cow::Borrowed("The client and server do not support a common API version."),
                Some(serde_json::json!({
                    "supported_api_versions": supported_versions,
                })),
            ),
            Self::Overloaded => (
                StatusCode::SERVICE_UNAVAILABLE,
                Cow::Borrowed("server_overloaded"),
                Cow::Borrowed("The service is temporarily at capacity."),
                None,
            ),
            Self::TransportRejected { status } => (
                status,
                Cow::Borrowed("request_rejected"),
                Cow::Borrowed("The HTTP request was rejected."),
                None,
            ),
            Self::Internal { category } => {
                error!(error.category = category, "internal application failure");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Cow::Borrowed("internal_error"),
                    Cow::Borrowed("An internal service error occurred."),
                    None,
                )
            }
        }
    }
}

fn insert_numeric_header(headers: &mut http::HeaderMap, name: HeaderName, value: u64) {
    if let Ok(value) = HeaderValue::from_str(&value.to_string()) {
        headers.insert(name, value);
    }
}

fn request_id() -> String {
    crate::request_context::current_request_id().unwrap_or_else(|| "unavailable".to_owned())
}

/// Longest field name reflected back to a caller.
const MAX_REFLECTED_FIELD_BYTES: usize = 64;

/// Names the field serde rejected, falling back to the generic body message.
fn json_data_error(detail: &str) -> AppError {
    if let Some(field) = plain_identifier_after(detail, "unknown field ") {
        return AppError::invalid_field(field, "is not a recognized field");
    }
    if let Some(field) = plain_identifier_after(detail, "missing field ") {
        return AppError::invalid_field(field, "is required");
    }
    AppError::invalid_field("body", "must match the documented JSON schema")
}

/// Extracts the backtick-quoted identifier following `needle`.
///
/// An unknown field name originates in the request body, so anything that is
/// not a bounded plain identifier is discarded rather than reflected.
fn plain_identifier_after(haystack: &str, needle: &str) -> Option<String> {
    let start = haystack.find(needle)? + needle.len();
    let rest = haystack.get(start..)?.strip_prefix('`')?;
    let name = rest.get(..rest.find('`')?)?;
    let plain = !name.is_empty()
        && name.len() <= MAX_REFLECTED_FIELD_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    plain.then(|| name.to_owned())
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        let category = match error {
            sqlx::Error::PoolTimedOut => "database_pool_timeout",
            sqlx::Error::PoolClosed => "database_pool_closed",
            sqlx::Error::RowNotFound => "database_row_not_found",
            _ => "database_operation",
        };
        Self::Internal { category }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{HeaderValue, Method, Request, header},
        response::IntoResponse as _,
    };

    use super::AppError;

    #[test]
    fn rate_limit_error_emits_the_complete_contract_header_set() {
        let response = AppError::RateLimited {
            limit: 5,
            remaining: 0,
            reset_after_seconds: 600,
            retry_after_seconds: 600,
        }
        .into_response();
        let headers = response.headers();

        assert_eq!(
            headers
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("600")
        );
        assert_eq!(
            headers
                .get("ratelimit-limit")
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
        assert_eq!(
            headers
                .get("ratelimit-remaining")
                .and_then(|value| value.to_str().ok()),
            Some("0")
        );
        assert_eq!(
            headers
                .get("ratelimit-reset")
                .and_then(|value| value.to_str().ok()),
            Some("600")
        );
    }

    #[test]
    fn shared_unauthorized_response_advertises_bearer_authentication() {
        let response = AppError::Unauthenticated.into_response();

        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );
    }

    #[test]
    fn not_invited_is_a_non_disclosing_not_found_error() {
        let (status, code, message, details) = AppError::NotInvited.public_parts();

        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(code, "not_invited");
        assert_eq!(message, "The authenticated Carbon is not invited.");
        assert!(details.is_none());
    }

    #[test]
    fn every_typed_service_unavailable_response_has_retry_after() {
        for error in [
            AppError::ProviderUnavailable,
            AppError::ServiceUnavailable,
            AppError::Overloaded,
        ] {
            let response = error.into_response();
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
                Some("5")
            );
        }
    }

    fn field_details(error: AppError) -> serde_json::Value {
        match error {
            AppError::Validation { details } => details,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_body_field_is_named_in_the_validation_details() {
        let details = field_details(super::json_data_error(
            "Failed to deserialize the JSON body into the target type: unknown field `timezone`, expected one of `carbon_id`, `display_name` at line 1 column 63",
        ));

        assert_eq!(
            details,
            serde_json::json!({
                "fields": [{ "field": "timezone", "message": "is not a recognized field" }],
            })
        );
    }

    #[test]
    fn missing_body_field_is_named_in_the_validation_details() {
        let details = field_details(super::json_data_error(
            "Failed to deserialize the JSON body into the target type: missing field `display_name` at line 1 column 30",
        ));

        assert_eq!(
            details,
            serde_json::json!({
                "fields": [{ "field": "display_name", "message": "is required" }],
            })
        );
    }

    #[test]
    fn a_submitted_value_is_never_reflected_back_to_the_caller() {
        let details = field_details(super::json_data_error(
            "Failed to deserialize the JSON body into the target type: invalid type: string \"664503\", expected a u64 at line 1 column 20",
        ));

        assert_eq!(
            details,
            serde_json::json!({
                "fields": [{ "field": "body", "message": "must match the documented JSON schema" }],
            })
        );
    }

    #[test]
    fn an_unknown_field_name_that_is_not_a_plain_identifier_stays_generic() {
        for detail in [
            "unknown field `<script>alert(1)</script>`, expected one of `carbon_id`",
            "unknown field `a.b`, expected one of `carbon_id`",
            "unknown field ``, expected one of `carbon_id`",
        ] {
            let details = field_details(super::json_data_error(detail));
            assert_eq!(
                details,
                serde_json::json!({
                    "fields": [{ "field": "body", "message": "must match the documented JSON schema" }],
                }),
                "reflected an unsafe field name from {detail}"
            );
        }
    }

    #[test]
    fn an_over_long_unknown_field_name_stays_generic() {
        let name = "f".repeat(super::MAX_REFLECTED_FIELD_BYTES + 1);
        let details = field_details(super::json_data_error(&format!(
            "unknown field `{name}`, expected one of `carbon_id`"
        )));

        assert_eq!(
            details,
            serde_json::json!({
                "fields": [{ "field": "body", "message": "must match the documented JSON schema" }],
            })
        );
    }

    #[test]
    fn an_unknown_field_name_at_the_maximum_length_is_still_named() {
        let name = "f".repeat(super::MAX_REFLECTED_FIELD_BYTES);
        let details = field_details(super::json_data_error(&format!(
            "unknown field `{name}`, expected one of `carbon_id`"
        )));

        assert_eq!(
            details,
            serde_json::json!({
                "fields": [{ "field": name, "message": "is not a recognized field" }],
            })
        );
    }

    /// Guards the parser against a change in axum's or serde's rejection text:
    /// these drive a real extractor rather than a hand-written message.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(
        dead_code,
        reason = "the fields exist to give the extractor a realistic shape to reject"
    )]
    struct Completion {
        carbon_id: String,
        display_name: String,
        timezone: Option<String>,
    }

    fn json_post(body: &'static str, content_type: Option<&'static str>) -> Request<Body> {
        let mut request = Request::new(Body::from(body));
        *request.method_mut() = Method::POST;
        if let Some(content_type) = content_type {
            request
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        request
    }

    async fn rejection_of(request: Request<Body>) -> AppError {
        use axum::extract::FromRequest as _;

        match axum::Json::<Completion>::from_request(request, &()).await {
            Ok(_) => panic!("the extractor was expected to reject this body"),
            Err(rejection) => AppError::from_json_rejection(&rejection),
        }
    }

    #[tokio::test]
    async fn a_real_unknown_field_rejection_names_that_field() {
        let request = json_post(
            r#"{"carbon_id":"a-b","display_name":"A","time_zone":"Asia/Kolkata"}"#,
            Some("application/json"),
        );

        assert_eq!(
            field_details(rejection_of(request).await),
            serde_json::json!({
                "fields": [{ "field": "time_zone", "message": "is not a recognized field" }],
            })
        );
    }

    #[tokio::test]
    async fn a_real_missing_field_rejection_names_that_field() {
        let request = json_post(r#"{"carbon_id":"a-b"}"#, Some("application/json"));

        assert_eq!(
            field_details(rejection_of(request).await),
            serde_json::json!({
                "fields": [{ "field": "display_name", "message": "is required" }],
            })
        );
    }

    #[tokio::test]
    async fn a_missing_json_content_type_is_reported_as_such() {
        let request = json_post("{}", None);

        assert_eq!(
            field_details(rejection_of(request).await),
            serde_json::json!({
                "fields": [{ "field": "content-type", "message": "must be application/json" }],
            })
        );
    }

    #[tokio::test]
    async fn malformed_json_is_reported_as_invalid_json() {
        let request = json_post("{not json", Some("application/json"));

        assert_eq!(
            field_details(rejection_of(request).await),
            serde_json::json!({
                "fields": [{ "field": "body", "message": "must be valid JSON" }],
            })
        );
    }
}
