//! Request-local correlation data shared across transport-independent errors.

use std::future::Future;
use uuid::Uuid;

tokio::task_local! {
    static REQUEST_ID: String;
}

/// Runs a request future with its validated correlation identifier.
pub async fn scope<T>(request_id: String, future: impl Future<Output = T>) -> T {
    REQUEST_ID.scope(request_id, future).await
}

/// Returns the correlation identifier for the current request, when available.
#[must_use]
pub fn current_request_id() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// Returns the current request ID as a UUID.
#[must_use]
pub fn current_request_uuid() -> Option<Uuid> {
    current_request_id().and_then(|value| Uuid::parse_str(&value).ok())
}
