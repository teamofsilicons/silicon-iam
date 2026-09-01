use std::{collections::HashSet, str::FromStr as _};

use garde::rules::email::parse_email;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use url::Url;

use crate::{
    config::RuntimeEnvironment,
    domain::directory::{JobRole, OrganizationId},
    error::AppError,
};

use super::model::{
    AdmissionMode, AuthorizeQuery, CallbackQuery, CorrelationSecret, SsoAdmissionPolicy,
};

const MAX_POLICY_TAGS: usize = 500;
const MAX_PROVIDER_ID_BYTES: usize = 512;

pub(super) fn organization_id(value: &str) -> Result<OrganizationId, AppError> {
    OrganizationId::from_str(value).map_err(|_| field("org_id", "has an invalid format"))
}

pub(super) fn policy(mut value: SsoAdmissionPolicy) -> Result<SsoAdmissionPolicy, AppError> {
    value.default_job_role = JobRole::try_from(value.default_job_role)
        .map(String::from)
        .map_err(|_| field("default_job_role", "must contain at most 5000 characters"))?;
    validate_unique_ids(
        "default_tag_ids",
        &mut value.default_tag_ids,
        MAX_POLICY_TAGS,
    )?;

    let mut domains = HashSet::with_capacity(value.allowed_email_domains.len());
    for domain in &mut value.allowed_email_domains {
        *domain = normalized_domain(domain)?;
        if !domains.insert(domain.clone()) {
            return Err(field("allowed_email_domains", "must contain unique values"));
        }
    }
    value.allowed_email_domains.sort_unstable();

    let mut groups = HashSet::with_capacity(value.allowed_groups.len());
    if value.allowed_groups.len() > 500 {
        return Err(field("allowed_groups", "must contain at most 500 values"));
    }
    for group in &value.allowed_groups {
        if group.is_empty()
            || group.len() > MAX_PROVIDER_ID_BYTES
            || !group.bytes().all(|byte| byte.is_ascii_graphic())
            || !groups.insert(group.clone())
        {
            return Err(field(
                "allowed_groups",
                "must contain unique exact WorkOS group strings of 1 to 512 visible ASCII bytes",
            ));
        }
    }
    value.allowed_groups.sort_unstable();

    match value.mode {
        AdmissionMode::InvitationRequired
            if !value.allowed_email_domains.is_empty() || !value.allowed_groups.is_empty() =>
        {
            Err(field(
                "mode",
                "invitation_required cannot include identity admission rules",
            ))
        }
        AdmissionMode::VerifiedIdentityPolicy
            if value.allowed_email_domains.is_empty() && value.allowed_groups.is_empty() =>
        {
            Err(field(
                "mode",
                "verified_identity_policy requires an email domain or group",
            ))
        }
        _ => Ok(value),
    }
}

pub(super) fn entitlement_reason(value: Option<String>) -> Result<Option<String>, AppError> {
    value
        .map(|reason| {
            if reason.trim() != reason || reason.is_empty() || reason.chars().count() > 2_000 {
                Err(field(
                    "reason",
                    "must contain 1 to 2000 unpadded characters",
                ))
            } else {
                Ok(reason)
            }
        })
        .transpose()
}

pub(super) fn authorize(
    query: AuthorizeQuery,
    auth_base_url: &Url,
    environment: RuntimeEnvironment,
) -> Result<super::model::ValidatedAuthorize, AppError> {
    let return_to = query
        .return_to
        .map(|value| Url::parse(&value).map_err(|_| field("return_to", "must be an absolute URL")))
        .transpose()?
        .unwrap_or_else(|| auth_base_url.clone());
    validate_return_to(&return_to, auth_base_url, environment)?;
    Ok(super::model::ValidatedAuthorize { return_to })
}

pub(super) fn callback(query: CallbackQuery) -> Result<CallbackQuery, AppError> {
    if query.code.is_empty()
        || query.code.len() > 2_048
        || query.code.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(field("code", "has an invalid format"));
    }
    if query.state.len() < 16 || query.state.len() > 512 {
        return Err(field("state", "has an invalid format"));
    }
    correlation_from_wire(&query.state)?;
    Ok(query)
}

pub(super) fn provider_email(value: &str) -> Result<String, AppError> {
    if value != value.trim() || value.len() > 320 || parse_email(value).is_err() {
        return Err(AppError::Conflict {
            code: "sso_identity_invalid".into(),
        });
    }
    Ok(crate::domain::auth::normalize_email(value))
}

pub(super) fn correlation_from_wire(value: &str) -> Result<CorrelationSecret, AppError> {
    let (state, nonce) = value
        .split_once('.')
        .ok_or_else(|| field("state", "has an invalid format"))?;
    if state.len() != 47
        || nonce.len() != 47
        || !state.starts_with("sss_")
        || !nonce.starts_with("ssn_")
        || !state[4..]
            .bytes()
            .chain(nonce[4..].bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(field("state", "has an invalid format"));
    }
    Ok(CorrelationSecret {
        state: SecretString::from(state.to_owned()),
        nonce: SecretString::from(nonce.to_owned()),
        wire_state: SecretString::from(value.to_owned()),
    })
}

pub(super) fn validate_correlation_parts(value: &CorrelationSecret) -> Result<(), AppError> {
    let expected = format!(
        "{}.{}",
        value.state.expose_secret(),
        value.nonce.expose_secret()
    );
    if expected == *value.wire_state.expose_secret() {
        Ok(())
    } else {
        Err(field("state", "has an invalid format"))
    }
}

fn validate_return_to(
    value: &Url,
    auth_base_url: &Url,
    environment: RuntimeEnvironment,
) -> Result<(), AppError> {
    let valid_scheme = value.scheme() == "https"
        || (environment != RuntimeEnvironment::Production && value.scheme() == "http");
    if !valid_scheme
        || value.origin() != auth_base_url.origin()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.fragment().is_some()
        || value.as_str().len() > 2_048
    {
        return Err(field(
            "return_to",
            "must be a fragment-free URL on the configured authentication origin",
        ));
    }
    Ok(())
}

fn normalized_domain(value: &str) -> Result<String, AppError> {
    let domain = value.to_ascii_lowercase();
    if value != domain
        || domain.is_empty()
        || domain.len() > 253
        || domain.ends_with('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || !domain.contains('.')
    {
        return Err(field(
            "allowed_email_domains",
            "must contain canonical lowercase DNS hostnames",
        ));
    }
    Ok(domain)
}

fn validate_unique_ids(
    name: &'static str,
    values: &mut [uuid::Uuid],
    maximum: usize,
) -> Result<(), AppError> {
    values.sort_unstable();
    if values.len() > maximum || values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(field(name, "must contain unique values within the limit"));
    }
    Ok(())
}

pub(super) fn field(name: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: json!({ "field": name, "message": message }),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;
    use url::Url;

    use super::{authorize, correlation_from_wire, normalized_domain};
    use crate::{config::RuntimeEnvironment, features::sso::model::AuthorizeQuery};

    #[test]
    fn return_uri_is_restricted_to_configured_frontend_origin() {
        let base = Url::parse("https://auth.example.com/").unwrap_or_else(|_| unreachable!());
        let valid = authorize(
            AuthorizeQuery {
                return_to: Some("https://auth.example.com/organizations/acme".to_owned()),
            },
            &base,
            RuntimeEnvironment::Production,
        );
        assert!(valid.is_ok());
        let cross_origin = authorize(
            AuthorizeQuery {
                return_to: Some("https://attacker.example/callback".to_owned()),
            },
            &base,
            RuntimeEnvironment::Production,
        );
        assert!(cross_origin.is_err());
    }

    #[test]
    fn correlation_wire_has_two_typed_components() {
        let state = format!("sss_{}.ssn_{}", "A".repeat(43), "B".repeat(43));
        let parsed = correlation_from_wire(&state);
        assert!(parsed.is_ok());
        if let Ok(parsed) = parsed {
            assert_eq!(parsed.wire_state.expose_secret(), &state);
        }
        assert!(correlation_from_wire(&format!("sss_{}", "A".repeat(43))).is_err());
    }

    #[test]
    fn domains_are_canonical_and_not_wildcards() {
        assert_eq!(
            normalized_domain("example.com").ok().as_deref(),
            Some("example.com")
        );
        assert!(normalized_domain("Example.com").is_err());
        assert!(normalized_domain("*.example.com").is_err());
        assert!(normalized_domain("localhost").is_err());
    }
}
