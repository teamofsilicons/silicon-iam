//! Shared bounded HTTP response handling for provider adapters.

use bytes::BytesMut;
use futures::StreamExt as _;
use serde::de::DeserializeOwned;

use crate::application::ports::DeliveryError;

const MAX_PROVIDER_RESPONSE_BYTES: usize = 64 * 1024;

pub(super) async fn decode_json<T>(response: reqwest::Response) -> Result<T, DeliveryError>
where
    T: DeserializeOwned,
{
    let mut stream = response.bytes_stream();
    let mut body = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| DeliveryError::Unavailable)?;
        if body.len().saturating_add(chunk.len()) > MAX_PROVIDER_RESPONSE_BYTES {
            // A success response means the provider may already have accepted
            // the message. Failure to consume its receipt is outcome-unknown,
            // never a definitive rejection that is safe to resend.
            return Err(DeliveryError::Unavailable);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| DeliveryError::Unavailable)
}

pub(super) fn classify_status(status: reqwest::StatusCode) -> DeliveryError {
    if status_is_retryable(status) {
        DeliveryError::Unavailable
    } else {
        DeliveryError::Rejected
    }
}

pub(super) fn status_is_retryable(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_EARLY
            | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_provider_statuses_are_retryable() {
        for status in [
            reqwest::StatusCode::REQUEST_TIMEOUT,
            reqwest::StatusCode::TOO_EARLY,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert_eq!(classify_status(status), DeliveryError::Unavailable);
        }
        for status in [
            reqwest::StatusCode::BAD_REQUEST,
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::FORBIDDEN,
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert_eq!(classify_status(status), DeliveryError::Rejected);
        }
    }
}
