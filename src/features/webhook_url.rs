//! Shared webhook-destination validation.
//!
//! Submission-time validation is deliberately paired with delivery-time DNS
//! pinning. The former gives callers useful feedback, while the latter remains
//! the authoritative SSRF boundary when a delivery is made.

use std::{net::IpAddr, time::Duration};

use url::Url;

use crate::infrastructure::providers::webhook::is_public_destination;

const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(2);

/// Parses a canonical, public HTTPS webhook URL.
pub(crate) fn parse(value: &str) -> Result<Url, &'static str> {
    let parsed = Url::parse(value).map_err(|_| "must be a valid HTTPS URL")?;
    if value.len() > 2_048
        || parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || matches!(parsed.host(), Some(url::Host::Domain(domain)) if domain.ends_with('.'))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || is_local_host(parsed.host_str().unwrap_or_default())
        || parsed.as_str() != value
    {
        return Err("must be a canonical public HTTPS URL without credentials or fragments");
    }
    Ok(parsed)
}

/// Resolves a webhook host and rejects it if any current address is non-public.
pub(crate) async fn validate_resolved_target(url: &Url) -> Result<(), &'static str> {
    let host = url.host_str().ok_or("must contain a host")?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = tokio::time::timeout(RESOLUTION_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| "host resolution timed out")?
        .map_err(|_| "host cannot be resolved")?
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .copied()
            .any(|address| !is_public_destination(address))
    {
        return Err("every resolved address must be public");
    }
    Ok(())
}

fn is_local_host(host: &str) -> bool {
    let normalized = host.to_ascii_lowercase();
    normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized
            .rsplit_once('.')
            .is_some_and(|(_, suffix)| matches!(suffix, "local" | "internal"))
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| !is_public_destination(address))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{is_local_host, parse};

    #[test]
    fn webhook_urls_must_be_canonical_public_https_urls() {
        assert!(parse("https://hooks.example/events").is_ok());
        assert!(parse("https://hooks.example./events").is_err());
        assert!(parse("https://127.0.0.1/events").is_err());
        assert!(parse("http://hooks.example/events").is_err());
        assert!(parse("https://user@hooks.example/events").is_err());
    }

    #[test]
    fn non_public_networks_are_rejected() {
        assert!(is_local_host(&Ipv4Addr::LOCALHOST.to_string()));
        assert!(is_local_host(&Ipv4Addr::new(10, 0, 0, 1).to_string()));
        assert!(is_local_host(&Ipv6Addr::LOCALHOST.to_string()));
        assert!(!is_local_host(&Ipv4Addr::new(1, 1, 1, 1).to_string()));
        assert!(is_local_host("service.internal"));
        assert!(is_local_host("printer.local"));
    }
}
