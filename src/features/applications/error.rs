use axum::{
    Json,
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;

/// Feature-local errors include protocol statuses that the shared error type
/// does not yet represent (notably 400, 410, 412, and 428).
#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    details: Option<Box<Value>>,
    retry_after: Option<u64>,
    rate_limit: Option<RateLimitMetadata>,
    www_authenticate: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
struct RateLimitMetadata {
    limit: u64,
    remaining: u64,
    reset_after_seconds: u64,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: PublicError,
}

#[derive(Serialize)]
struct PublicError {
    code: &'static str,
    message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Box<Value>>,
    request_id: String,
}

impl ApiError {
    pub(super) fn bad_request(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub(super) fn validation(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "validation_failed",
            message: "The request contains invalid data.",
            details: Some(Box::new(serde_json::json!({
                "fields": [{ "field": field, "message": message.into() }]
            }))),
            retry_after: None,
            rate_limit: None,
            www_authenticate: None,
        }
    }

    /// Whether this is the "nobody is signed in" rejection.
    ///
    /// The login route treats that as a state to act on rather than a failure
    /// to report, and must not confuse it with any other error.
    pub(super) const fn is_unauthenticated(&self) -> bool {
        matches!(self.status, StatusCode::UNAUTHORIZED)
    }

    pub(super) fn unauthenticated() -> Self {
        let mut error = Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Authentication is required.",
        );
        error.www_authenticate = Some("Bearer");
        error
    }

    pub(super) fn invalid_client() -> Self {
        let mut error = Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Application authentication failed.",
        );
        error.www_authenticate = Some("Basic realm=\"silicon-iam\"");
        error
    }

    pub(super) fn forbidden(code: &'static str) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            code,
            "The actor is not authorized for this action.",
        )
    }

    pub(super) fn not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "The requested resource was not found.",
        )
    }

    pub(super) fn conflict(code: &'static str) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            code,
            "The request conflicts with the current resource state.",
        )
    }

    pub(super) fn gone(code: &'static str) -> Self {
        Self::new(
            StatusCode::GONE,
            code,
            "The credential is no longer usable.",
        )
    }

    pub(super) fn precondition_failed() -> Self {
        Self::new(
            StatusCode::PRECONDITION_FAILED,
            "version_mismatch",
            "The resource version does not match If-Match.",
        )
    }

    pub(super) fn precondition(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::PRECONDITION_FAILED, code, message)
    }

    pub(super) fn precondition_required(precondition: &'static str) -> Self {
        Self {
            status: StatusCode::PRECONDITION_REQUIRED,
            code: "precondition_required",
            message: "A required request precondition is missing.",
            details: Some(Box::new(
                serde_json::json!({ "precondition": precondition }),
            )),
            retry_after: None,
            rate_limit: None,
            www_authenticate: None,
        }
    }

    pub(super) fn rate_limited(
        limit: u64,
        remaining: u64,
        reset_after_seconds: u64,
        retry_after_seconds: u64,
    ) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: "Too many requests. Retry later.",
            details: Some(Box::new(serde_json::json!({
                "limit": limit,
                "remaining": remaining,
                "reset_after_seconds": reset_after_seconds,
                "retry_after_seconds": retry_after_seconds,
            }))),
            retry_after: Some(retry_after_seconds),
            rate_limit: Some(RateLimitMetadata {
                limit,
                remaining,
                reset_after_seconds,
            }),
            www_authenticate: None,
        }
    }

    pub(super) fn internal(category: &'static str) -> Self {
        tracing::error!(error.category = category, "applications feature failure");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "An internal service error occurred.",
        )
    }

    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            details: None,
            retry_after: None,
            rate_limit: None,
            www_authenticate: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorEnvelope {
                error: PublicError {
                    code: self.code,
                    message: self.message,
                    details: self.details,
                    request_id: crate::request_context::current_request_id()
                        .unwrap_or_else(|| "unavailable".to_owned()),
                },
            }),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        if let Some(seconds) = self.retry_after
            && let Ok(value) = seconds.to_string().parse()
        {
            response
                .headers_mut()
                .insert(http::header::RETRY_AFTER, value);
        }
        if let Some(rate_limit) = self.rate_limit {
            insert_numeric_header(
                response.headers_mut(),
                HeaderName::from_static("ratelimit-limit"),
                rate_limit.limit,
            );
            insert_numeric_header(
                response.headers_mut(),
                HeaderName::from_static("ratelimit-remaining"),
                rate_limit.remaining,
            );
            insert_numeric_header(
                response.headers_mut(),
                HeaderName::from_static("ratelimit-reset"),
                rate_limit.reset_after_seconds,
            );
        }
        if let Some(challenge) = self.www_authenticate {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        response
    }
}

fn insert_numeric_header(headers: &mut http::HeaderMap, name: HeaderName, value: u64) {
    if let Ok(value) = HeaderValue::from_str(&value.to_string()) {
        headers.insert(name, value);
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(database) = &error
            && database.is_unique_violation()
        {
            return Self::conflict("unique_conflict");
        }
        Self::internal("applications_database")
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse as _;

    use super::ApiError;

    #[test]
    fn rate_limit_errors_emit_the_shared_header_set() {
        let response = ApiError::rate_limited(120, 0, 58, 58).into_response();
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
        for (name, expected) in [
            ("retry-after", "58"),
            ("ratelimit-limit", "120"),
            ("ratelimit-remaining", "0"),
            ("ratelimit-reset", "58"),
        ] {
            assert_eq!(
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok()),
                Some(expected)
            );
        }
    }

    #[test]
    fn application_client_errors_advertise_basic_authentication() {
        let response = ApiError::invalid_client().into_response();
        assert_eq!(
            response
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Basic realm=\"silicon-iam\"")
        );
    }
}
