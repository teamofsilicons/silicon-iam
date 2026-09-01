use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use url::Url;

use super::{error::ApiError, model};

const MAX_REDIRECT_URIS: usize = 20;
const MAX_SCOPES: usize = 100;
pub(super) const OBO_ACTIONS: [&str; 17] = [
    "organization.update",
    "members.invite",
    "members.update_directory",
    "members.remove",
    "silicons.create",
    "silicons.update_directory",
    "silicons.manage_hierarchy",
    "silicons.remove",
    "silicons.rotate_token",
    "tags.manage",
    "trust.manage",
    "roles.request",
    "roles.approve",
    "admins.create",
    "admins.manage",
    "sso.manage",
    "audit.read",
];

pub(super) fn app_id(value: &str) -> Result<(), ApiError> {
    if !(3..=80).contains(&value.len())
        || !value.bytes().enumerate().all(|(index, byte)| {
            (index != 0 && (byte.is_ascii_digit() || matches!(byte, b'_' | b'-')))
                || byte.is_ascii_lowercase()
        })
    {
        return Err(ApiError::validation(
            "app_id",
            "must be 3-80 lowercase ASCII characters, start with a letter, and contain only letters, digits, '_' or '-'",
        ));
    }
    Ok(())
}

pub(super) fn application_create(input: &model::ApplicationCreate) -> Result<(), ApiError> {
    app_id(&input.app_id)?;
    optional_text("app_name", input.app_name.as_deref(), 1, 200)?;
    optional_https_uri("app_logo_uri", input.app_logo_uri.as_deref(), 2_048)?;
    redirect_uris(&input.redirect_uris)?;
    webhook_url(&input.webhook_url)?;
    scopes(&input.requested_scopes)?;
    Ok(())
}

pub(super) fn application_patch(input: &model::ApplicationPatch) -> Result<(), ApiError> {
    if input.app_name.is_none()
        && input.app_logo_uri.is_none()
        && input.redirect_uris.is_none()
        && input.requested_scopes.is_none()
    {
        return Err(ApiError::validation(
            "body",
            "must change at least one field",
        ));
    }
    if let Some(value) = input.app_name.as_ref().and_then(|value| value.as_deref()) {
        optional_text("app_name", Some(value), 1, 200)?;
    }
    if let Some(value) = input
        .app_logo_uri
        .as_ref()
        .and_then(|value| value.as_deref())
    {
        optional_https_uri("app_logo_uri", Some(value), 2_048)?;
    }
    if let Some(values) = &input.redirect_uris {
        redirect_uris(values)?;
    }
    if let Some(values) = &input.requested_scopes {
        scopes(values)?;
    }
    Ok(())
}

pub(super) fn collaborator_role(value: &str) -> Result<(), ApiError> {
    if matches!(value, "owner_delegate" | "developer" | "viewer") {
        Ok(())
    } else {
        Err(ApiError::validation(
            "role",
            "must be owner_delegate, developer, or viewer",
        ))
    }
}

pub(super) fn overlap(seconds: u16) -> Result<(), ApiError> {
    if seconds <= 3_600 {
        Ok(())
    } else {
        Err(ApiError::validation(
            "overlap_seconds",
            "must be between 0 and 3600",
        ))
    }
}

pub(super) fn redirect_uris(values: &[String]) -> Result<(), ApiError> {
    if !(1..=MAX_REDIRECT_URIS).contains(&values.len()) {
        return Err(ApiError::validation(
            "redirect_uris",
            "must contain 1 to 20 exact URIs",
        ));
    }
    let mut unique = BTreeSet::<&str>::new();
    for value in values {
        let parsed = Url::parse(value)
            .map_err(|_| ApiError::validation("redirect_uris", "contains an invalid URI"))?;
        if value.len() > 2_048
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.host_str().is_none()
            || !matches!(parsed.scheme(), "https" | "http")
            || (parsed.scheme() == "http"
                && !matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1")))
            || parsed.as_str() != value
        {
            return Err(ApiError::validation(
                "redirect_uris",
                "must contain canonical exact HTTPS URIs (HTTP is limited to loopback development)",
            ));
        }
        if !unique.insert(value.as_str()) {
            return Err(ApiError::validation(
                "redirect_uris",
                "must not contain duplicates",
            ));
        }
    }
    Ok(())
}

pub(super) fn webhook_url(value: &str) -> Result<Url, ApiError> {
    let parsed = Url::parse(value)
        .map_err(|_| ApiError::validation("webhook_url", "must be a valid HTTPS URL"))?;
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
        return Err(ApiError::validation(
            "webhook_url",
            "must be a canonical public HTTPS URL without credentials or fragments",
        ));
    }
    Ok(parsed)
}

pub(super) fn scopes(values: &[String]) -> Result<(), ApiError> {
    if values.is_empty() || values.len() > MAX_SCOPES {
        return Err(ApiError::validation(
            "requested_scopes",
            "must contain 1 to 100 scopes",
        ));
    }
    let mut unique = BTreeSet::<&str>::new();
    for value in values {
        if !(2..=128).contains(&value.len())
            || !value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || (index != 0
                        && (byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b':' | b'-')))
            })
        {
            return Err(ApiError::validation(
                "requested_scopes",
                "contains an invalid scope",
            ));
        }
        if !unique.insert(value.as_str()) {
            return Err(ApiError::validation(
                "requested_scopes",
                "must not contain duplicates",
            ));
        }
    }
    if !unique.contains("openid") {
        return Err(ApiError::validation(
            "requested_scopes",
            "must include openid",
        ));
    }
    Ok(())
}

pub(super) fn authorize(query: &model::AuthorizeQuery) -> Result<Vec<String>, ApiError> {
    app_id(&query.client_id)?;
    if query.response_type != "code" {
        return Err(ApiError::bad_request(
            "unsupported_response_type",
            "Only response_type=code is supported.",
        ));
    }
    if query.code_challenge_method != "S256" || !pkce_challenge(&query.code_challenge) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "PKCE-S256 is required.",
        ));
    }
    bounded_protocol_secret("state", &query.state)?;
    bounded_protocol_secret("nonce", &query.nonce)?;
    let requested_scopes = query
        .scope
        .split(' ')
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    scopes(&requested_scopes)?;
    Ok(requested_scopes)
}

fn pkce_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn pkce_value(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

pub(super) fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    if !pkce_value(verifier) {
        return false;
    }
    let calculated = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    subtle::ConstantTimeEq::ct_eq(calculated.as_bytes(), challenge.as_bytes()).into()
}

pub(super) fn action(value: &str) -> Result<(), ApiError> {
    if OBO_ACTIONS.contains(&value) {
        Ok(())
    } else {
        Err(ApiError::validation(
            "action",
            "must be a supported organization capability",
        ))
    }
}

pub(super) fn resource(value: Option<&str>) -> Result<(), ApiError> {
    if value.is_some_and(|value| value.is_empty() || value.len() > 1_024) {
        return Err(ApiError::validation(
            "resource",
            "must contain 1 to 1024 characters",
        ));
    }
    Ok(())
}

pub(super) fn org_id(value: &str) -> Result<(), ApiError> {
    if !(3..=50).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(ApiError::validation("org_id", "has an invalid format"));
    }
    Ok(())
}

fn optional_text(
    field: &'static str,
    value: Option<&str>,
    min: usize,
    max: usize,
) -> Result<(), ApiError> {
    if value.is_some_and(|value| !(min..=max).contains(&value.chars().count())) {
        return Err(ApiError::validation(
            field,
            format!("must contain {min} to {max} characters"),
        ));
    }
    Ok(())
}

fn optional_https_uri(
    field: &'static str,
    value: Option<&str>,
    max: usize,
) -> Result<(), ApiError> {
    let Some(value) = value else { return Ok(()) };
    let parsed = Url::parse(value).map_err(|_| ApiError::validation(field, "must be a URI"))?;
    if value.len() > max || parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err(ApiError::validation(field, "must be a valid HTTPS URI"));
    }
    Ok(())
}

fn bounded_protocol_secret(field: &'static str, value: &str) -> Result<(), ApiError> {
    if !(16..=512).contains(&value.len()) || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ApiError::bad_request(
            "invalid_request",
            match field {
                "state" => "state must contain 16 to 512 characters.",
                _ => "nonce must contain 16 to 512 characters.",
            },
        ));
    }
    Ok(())
}

fn is_local_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(|address| {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || match address {
                    std::net::IpAddr::V4(address) => {
                        address.is_private() || address.is_link_local() || address.is_broadcast()
                    }
                    std::net::IpAddr::V6(address) => address.is_unique_local(),
                }
        })
}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::{OBO_ACTIONS, action, app_id, pkce_matches, redirect_uris, webhook_url};

    #[test]
    fn application_identifiers_match_database_constraints() {
        assert!(app_id("good_app-1").is_ok());
        assert!(app_id("1bad").is_err());
        assert!(app_id(&format!("a{}", "b".repeat(79))).is_ok());
        assert!(app_id(&format!("a{}", "b".repeat(80))).is_err());
    }

    #[test]
    fn redirect_matching_remains_exact() {
        let values = vec!["https://client.example/callback".to_owned()];
        assert!(redirect_uris(&values).is_ok());
        assert!(redirect_uris(&["https://client.example/callback#fragment".to_owned()]).is_err());
    }

    #[test]
    fn webhook_validation_rejects_obvious_ssrf_targets() {
        assert!(webhook_url("https://hooks.example/events").is_ok());
        assert!(webhook_url("https://hooks.example./events").is_err());
        assert!(webhook_url("https://127.0.0.1/events").is_err());
        assert!(webhook_url("http://hooks.example/events").is_err());
    }

    #[test]
    fn pkce_is_s256_and_constant_time_compared() {
        let verifier = "A".repeat(43);
        let challenge = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            sha2::Sha256::digest(verifier.as_bytes()),
        );
        assert!(pkce_matches(&verifier, &challenge));
        assert!(!pkce_matches(&verifier, &"B".repeat(43)));
    }

    #[test]
    fn obo_actions_are_a_closed_capability_vocabulary() {
        assert!(OBO_ACTIONS.iter().all(|value| action(value).is_ok()));
        assert!(action("documents.read").is_err());
        assert!(action("owner-only-action").is_err());
    }
}
