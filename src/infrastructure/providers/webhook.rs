//! SSRF-resistant, DNS-pinned webhook delivery transport.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use bytes::BytesMut;
use futures::StreamExt as _;
use hmac::{Hmac, Mac as _};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::{Host, Url};
use uuid::Uuid;

use crate::config::RuntimeEnvironment;

use super::http;

type HmacSha256 = Hmac<Sha256>;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Successful, body-free webhook delivery evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WebhookReceipt {
    pub(crate) http_status: u16,
    pub(crate) response_digest: [u8; 32],
}

/// Fully bound transport input for one outbound webhook attempt.
pub(crate) struct WebhookRequest<'a> {
    pub(crate) environment: RuntimeEnvironment,
    pub(crate) destination: &'a Url,
    pub(crate) signing_secret: Option<&'a SecretString>,
    pub(crate) service_bearer: Option<&'a SecretString>,
    pub(crate) signing_key_version: Option<i64>,
    pub(crate) event_id: Uuid,
    pub(crate) timestamp: i64,
    pub(crate) body: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseBodyError {
    Unavailable,
    TooLarge,
}

/// Classified webhook transport failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum WebhookError {
    #[error("webhook destination is not permitted")]
    DestinationRejected,
    #[error("webhook destination resolution failed")]
    ResolutionFailed,
    #[error("webhook request failed transiently")]
    Unavailable,
    #[error("webhook endpoint rejected the event")]
    HttpStatus(u16),
    #[error("webhook response exceeded the permitted size")]
    ResponseTooLarge(u16),
    #[error("webhook signing failed")]
    SigningFailed,
}

impl WebhookError {
    pub(crate) fn retryable(self) -> bool {
        match self {
            Self::ResolutionFailed | Self::Unavailable => true,
            Self::HttpStatus(status) | Self::ResponseTooLarge(status) => {
                reqwest::StatusCode::from_u16(status).is_ok_and(http::status_is_retryable)
            }
            Self::DestinationRejected | Self::SigningFailed => false,
        }
    }

    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::DestinationRejected => "destination_rejected",
            Self::ResolutionFailed => "dns_resolution_failed",
            Self::Unavailable => "transport_unavailable",
            Self::HttpStatus(status) if status_is_retryable(status) => "endpoint_unavailable",
            Self::HttpStatus(_) => "endpoint_rejected",
            Self::ResponseTooLarge(_) => "response_too_large",
            Self::SigningFailed => "signing_failed",
        }
    }

    pub(crate) const fn http_status(self) -> Option<u16> {
        match self {
            Self::HttpStatus(status) | Self::ResponseTooLarge(status) => Some(status),
            Self::DestinationRejected
            | Self::ResolutionFailed
            | Self::Unavailable
            | Self::SigningFailed => None,
        }
    }
}

fn status_is_retryable(status: u16) -> bool {
    reqwest::StatusCode::from_u16(status).is_ok_and(http::status_is_retryable)
}

/// Sends one HMAC-signed event after resolving and pinning its public IPs.
pub(crate) async fn deliver(request: WebhookRequest<'_>) -> Result<WebhookReceipt, WebhookError> {
    let WebhookRequest {
        environment,
        destination,
        signing_secret,
        service_bearer,
        signing_key_version,
        event_id,
        timestamp,
        body,
    } = request;
    validate_url(environment, destination)?;
    let host = destination
        .host()
        .ok_or(WebhookError::DestinationRejected)?;
    let port = destination
        .port_or_known_default()
        .ok_or(WebhookError::DestinationRejected)?;
    let (host_name, addresses) = resolve_public_addresses(host, port).await?;

    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(environment == RuntimeEnvironment::Production)
        .user_agent(concat!("silicon-iam/", env!("CARGO_PKG_VERSION")));
    if let Some(host_name) = host_name {
        builder = builder.resolve_to_addrs(&host_name, &addresses);
    }
    let client = builder.build().map_err(|_| WebhookError::Unavailable)?;

    let mut request = client
        .post(destination.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Silicon-IAM-Event-ID", event_id.to_string())
        .header("X-Silicon-IAM-Timestamp", timestamp.to_string())
        .body(body.to_vec());
    if let Some(version) = signing_key_version {
        request = request.header("X-Silicon-IAM-Key-Version", version.to_string());
    }
    if let Some(secret) = signing_secret {
        request = request.header(
            "X-Silicon-IAM-Signature",
            signature(secret, timestamp, body)?,
        );
    }
    if let Some(token) = service_bearer {
        request = request.bearer_auth(token.expose_secret());
    }

    let response = request
        .send()
        .await
        .map_err(|_| WebhookError::Unavailable)?;
    let status = response.status();
    let response_digest = digest_bounded_response(response)
        .await
        .map_err(|error| classify_response_body_error(status, error))?;
    if status.is_success() {
        return Ok(WebhookReceipt {
            http_status: status.as_u16(),
            response_digest,
        });
    }
    Err(WebhookError::HttpStatus(status.as_u16()))
}

fn classify_response_body_error(
    status: reqwest::StatusCode,
    error: ResponseBodyError,
) -> WebhookError {
    match error {
        ResponseBodyError::TooLarge => WebhookError::ResponseTooLarge(status.as_u16()),
        ResponseBodyError::Unavailable if !status.is_success() => {
            WebhookError::HttpStatus(status.as_u16())
        }
        ResponseBodyError::Unavailable => WebhookError::Unavailable,
    }
}

fn validate_url(environment: RuntimeEnvironment, destination: &Url) -> Result<(), WebhookError> {
    let allowed_scheme = destination.scheme() == "https"
        || (environment != RuntimeEnvironment::Production && destination.scheme() == "http");
    if !allowed_scheme
        || !destination.username().is_empty()
        || destination.password().is_some()
        || destination.fragment().is_some()
        || destination.host().is_none()
        || matches!(destination.host(), Some(Host::Domain(domain)) if domain.ends_with('.'))
    {
        return Err(WebhookError::DestinationRejected);
    }
    Ok(())
}

async fn resolve_public_addresses(
    host: Host<&str>,
    port: u16,
) -> Result<(Option<String>, Vec<SocketAddr>), WebhookError> {
    match host {
        Host::Ipv4(address) => {
            let ip = IpAddr::V4(address);
            if is_public_destination(ip) {
                Ok((None, vec![SocketAddr::new(ip, port)]))
            } else {
                Err(WebhookError::DestinationRejected)
            }
        }
        Host::Ipv6(address) => {
            let ip = IpAddr::V6(address);
            if is_public_destination(ip) {
                Ok((None, vec![SocketAddr::new(ip, port)]))
            } else {
                Err(WebhookError::DestinationRejected)
            }
        }
        Host::Domain(domain) => {
            if domain.ends_with('.') {
                return Err(WebhookError::DestinationRejected);
            }
            let normalized = domain.to_ascii_lowercase();
            if normalized.is_empty()
                || normalized == "localhost"
                || normalized.ends_with(".localhost")
                || has_final_label(&normalized, "local")
                || has_final_label(&normalized, "internal")
            {
                return Err(WebhookError::DestinationRejected);
            }
            let resolved = tokio::time::timeout(
                CONNECT_TIMEOUT,
                tokio::net::lookup_host((normalized.as_str(), port)),
            )
            .await
            .map_err(|_| WebhookError::ResolutionFailed)?
            .map_err(|_| WebhookError::ResolutionFailed)?;
            let mut addresses = resolved.collect::<Vec<_>>();
            addresses.sort_unstable();
            addresses.dedup();
            if addresses.is_empty()
                || addresses
                    .iter()
                    .any(|address| !is_public_destination(address.ip()))
            {
                return Err(WebhookError::DestinationRejected);
            }
            Ok((Some(normalized), addresses))
        }
    }
}

fn has_final_label(domain: &str, label: &str) -> bool {
    domain
        .rsplit_once('.')
        .is_some_and(|(_, final_label)| final_label == label)
}

fn is_public_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or_else(|| is_public_ipv6(address), is_public_ipv4),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, _fourth] = address.octets();
    !matches!(
        (first, second, third),
        (0 | 10 | 127 | 224..=255, _, _)
            | (100, 64..=127, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0 | 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18 | 19, _)
            | (198, 51, 100)
            | (203, 0, 113)
    )
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let ipv4_compatible = segments[..6].iter().all(|segment| *segment == 0);
    let well_known_nat64 = segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2..6].iter().all(|segment| *segment == 0);
    let local_nat64 = segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001;
    let discard_only = segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0);
    let ietf_protocol_assignment = segments[0] == 0x2001 && (segments[1] & 0xfe00) == 0;
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let extended_documentation = segments[0] == 0x3fff && segments[1] <= 0x0fff;
    let unique_local = (segments[0] & 0xfe00) == 0xfc00;
    let link_local = (segments[0] & 0xffc0) == 0xfe80;
    let deprecated_site_local = (segments[0] & 0xffc0) == 0xfec0;
    let multicast = (segments[0] & 0xff00) == 0xff00;

    !(ipv4_compatible
        || well_known_nat64
        || local_nat64
        || discard_only
        || ietf_protocol_assignment
        || documentation
        || extended_documentation
        || segments[0] == 0x2002
        || segments[0] == 0x5f00
        || unique_local
        || link_local
        || deprecated_site_local
        || multicast)
}

fn signature(secret: &SecretString, timestamp: i64, body: &[u8]) -> Result<String, WebhookError> {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(secret.expose_secret().as_bytes())
        .map_err(|_| WebhookError::SigningFailed)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!("v1={}", hex::encode(mac.finalize().into_bytes())))
}

async fn digest_bounded_response(
    response: reqwest::Response,
) -> Result<[u8; 32], ResponseBodyError> {
    let mut stream = response.bytes_stream();
    let mut body = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ResponseBodyError::Unavailable)?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ResponseBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Sha256::digest(&body).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_every_common_non_public_ipv4_range() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
        ] {
            let parsed = address.parse::<IpAddr>();
            assert!(parsed.is_ok());
            if let Ok(parsed) = parsed {
                assert!(!is_public_destination(parsed), "accepted {address}");
            }
        }
        let public = "8.8.8.8".parse::<IpAddr>();
        assert!(public.is_ok_and(is_public_destination));
    }

    #[test]
    fn rejects_non_public_ipv6_ranges_and_mapped_addresses() {
        for address in [
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b:1::1",
            "::ffff:127.0.0.1",
        ] {
            let parsed = address.parse::<IpAddr>();
            assert!(parsed.is_ok());
            if let Ok(parsed) = parsed {
                assert!(!is_public_destination(parsed), "accepted {address}");
            }
        }
        let public = "2606:4700:4700::1111".parse::<IpAddr>();
        assert!(public.is_ok_and(is_public_destination));
    }

    #[test]
    fn signature_is_deterministic_and_versioned() {
        let secret = SecretString::from("a sufficiently long signing key".to_owned());
        let first = signature(&secret, 1_700_000_000, br#"{"ok":true}"#);
        let second = signature(&secret, 1_700_000_000, br#"{"ok":true}"#);
        assert!(first.is_ok());
        assert_eq!(first, second);
        assert!(first.is_ok_and(|value| value.starts_with("v1=")));
    }

    #[tokio::test]
    async fn rejects_trailing_dot_domains_before_dns_pinning() {
        let destination = Url::parse("https://hooks.example./events");
        assert!(destination.is_ok());
        let Ok(destination) = destination else {
            unreachable!("the URL crate accepts a DNS root-label suffix");
        };
        assert_eq!(
            validate_url(RuntimeEnvironment::Production, &destination),
            Err(WebhookError::DestinationRejected)
        );
        assert_eq!(
            resolve_public_addresses(Host::Domain("hooks.example."), 443).await,
            Err(WebhookError::DestinationRejected)
        );
    }

    #[test]
    fn oversized_transient_responses_remain_retryable() {
        for status in [
            reqwest::StatusCode::REQUEST_TIMEOUT,
            reqwest::StatusCode::TOO_EARLY,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert_eq!(
                classify_response_body_error(status, ResponseBodyError::TooLarge),
                WebhookError::ResponseTooLarge(status.as_u16())
            );
        }
        assert_eq!(
            classify_response_body_error(
                reqwest::StatusCode::BAD_REQUEST,
                ResponseBodyError::TooLarge,
            ),
            WebhookError::ResponseTooLarge(reqwest::StatusCode::BAD_REQUEST.as_u16())
        );
        assert_eq!(
            classify_response_body_error(
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                ResponseBodyError::Unavailable,
            ),
            WebhookError::HttpStatus(reqwest::StatusCode::SERVICE_UNAVAILABLE.as_u16())
        );
    }
}
