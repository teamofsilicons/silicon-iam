use std::str::FromStr as _;

use garde::rules::email::parse_email;
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use url::Url;

use crate::{config::RuntimeEnvironment, domain::directory::OrganizationId, error::AppError};

use super::model::{AuthorizeQuery, CallbackQuery, CorrelationSecret};

pub(super) fn organization_id(value: &str) -> Result<OrganizationId, AppError> {
    OrganizationId::from_str(value).map_err(|_| field("org_id", "has an invalid format"))
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

pub(super) fn field(name: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: json!({ "field": name, "message": message }),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;
    use url::Url;

    use super::{authorize, correlation_from_wire};
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
}
