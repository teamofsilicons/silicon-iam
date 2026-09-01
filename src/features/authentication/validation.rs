use std::str::FromStr as _;

use garde::rules::email::parse_email;
use secrecy::SecretString;
use serde_json::json;
use url::Url;

use crate::{domain::auth::CarbonId, error::AppError};

use super::model::{
    ContactChannel, LoginChallengeInput, PageQuery, SignupCompletionInput, ValidatedContact,
    ValidatedLoginIdentifier, ValidatedSignupCompletion,
};

const MAX_EMAIL_BYTES: usize = 320;
const MAX_CURSOR_BYTES: usize = 2_048;
const MAX_PAGE_SIZE: u16 = 100;

pub(super) fn email(value: String) -> Result<ValidatedContact, AppError> {
    if value != value.trim() || value.len() > MAX_EMAIL_BYTES || parse_email(&value).is_err() {
        return Err(validation("email", "must be a valid email address"));
    }
    let normalized = crate::domain::auth::normalize_email(&value);
    Ok(ValidatedContact {
        channel: ContactChannel::Email,
        normalized,
        presentation: SecretString::from(value),
    })
}

pub(super) fn phone(value: String) -> Result<ValidatedContact, AppError> {
    let valid = (9..=16).contains(&value.len())
        && value.starts_with('+')
        && value.get(1..).is_some_and(|digits| {
            digits.len() >= 8 && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
        && value.as_bytes().get(1).is_some_and(|byte| *byte != b'0');
    if !valid {
        return Err(validation("phone_number", "must be an E.164 phone number"));
    }
    Ok(ValidatedContact {
        channel: ContactChannel::Phone,
        normalized: value.clone(),
        presentation: SecretString::from(value),
    })
}

pub(super) fn verification_code(value: String) -> Result<SecretString, AppError> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(validation("code", "must contain exactly six digits"));
    }
    Ok(SecretString::from(value))
}

pub(super) fn refresh_token(value: String) -> Result<SecretString, AppError> {
    if value.len() != 47
        || !value.starts_with("rft_")
        || !value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AppError::Unauthenticated);
    }
    Ok(SecretString::from(value))
}

pub(super) fn login_identifier(
    input: LoginChallengeInput,
) -> Result<ValidatedLoginIdentifier, AppError> {
    match (input.email, input.phone_number, input.carbon_id) {
        (Some(value), None, None) => email(value).map(ValidatedLoginIdentifier::Contact),
        (None, Some(value), None) => phone(value).map(ValidatedLoginIdentifier::Contact),
        (None, None, Some(value)) => CarbonId::from_lookup_str(&value)
            .map(ValidatedLoginIdentifier::CarbonId)
            .map_err(|_| validation("carbon_id", "has an invalid format")),
        _ => Err(validation(
            "identifier",
            "exactly one of email, phone_number, or carbon_id is required",
        )),
    }
}

pub(super) fn signup_completion(
    input: SignupCompletionInput,
    production: bool,
) -> Result<ValidatedSignupCompletion, AppError> {
    let carbon_id = CarbonId::from_str(&input.carbon_id)
        .map_err(|_| validation("carbon_id", "has an invalid format"))?;
    let display_name = bounded_text("display_name", input.display_name, 1, 200, false)?;
    let timezone = input.time_zone.unwrap_or_else(|| "UTC".to_owned());
    if !crate::domain::timezone::is_valid_identifier(&timezone) {
        return Err(validation(
            "time_zone",
            "must be a valid IANA TZ identifier",
        ));
    }
    let description = input
        .description
        .map(|value| bounded_text("description", value, 0, 5_000, true))
        .transpose()?;
    let profile_photo = input
        .profile_photo
        .map(|value| profile_photo(&value, production))
        .transpose()?;
    Ok(ValidatedSignupCompletion {
        carbon_id,
        display_name,
        timezone,
        description,
        profile_photo,
    })
}

pub(super) fn page(query: PageQuery) -> Result<(Option<String>, i64), AppError> {
    let cursor = query
        .cursor
        .map(|value| {
            if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
                Err(validation("cursor", "has an invalid length"))
            } else {
                Ok(value)
            }
        })
        .transpose()?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(validation("limit", "must be between 1 and 100"));
    }
    Ok((cursor, i64::from(limit)))
}

fn bounded_text(
    field: &'static str,
    value: String,
    min_chars: usize,
    max_chars: usize,
    allow_blank: bool,
) -> Result<String, AppError> {
    let length = value.chars().count();
    let contains_control = value.chars().any(char::is_control);
    if !(min_chars..=max_chars).contains(&length)
        || contains_control
        || (!allow_blank && value.trim().is_empty())
    {
        return Err(validation(field, "has an invalid length or characters"));
    }
    Ok(value)
}

fn profile_photo(value: &str, production: bool) -> Result<Url, AppError> {
    if value.len() > 2_048 {
        return Err(validation("profile_photo", "must be a valid URL"));
    }
    let url = Url::parse(value).map_err(|_| validation("profile_photo", "must be a valid URL"))?;
    let valid_scheme = if production {
        url.scheme() == "https"
    } else {
        matches!(url.scheme(), "http" | "https")
    };
    if !valid_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(validation("profile_photo", "must be a safe HTTP URL"));
    }
    Ok(url)
}

pub(super) fn validation(field: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: json!({
            "fields": [{ "field": field, "message": message }],
        }),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::{email, phone, refresh_token, signup_completion, verification_code};
    use crate::features::authentication::model::SignupCompletionInput;

    #[test]
    fn contacts_are_exactly_validated_and_normalized() {
        let parsed_email = email("User@Example.COM".to_owned());
        assert!(matches!(parsed_email, Ok(value) if value.normalized == "user@example.com"));
        assert!(email(" user@example.com".to_owned()).is_err());

        let parsed_phone = phone("+919876543210".to_owned());
        assert!(matches!(parsed_phone, Ok(value) if value.normalized == "+919876543210"));
        assert!(phone("+012345678".to_owned()).is_err());
    }

    #[test]
    fn codes_and_refresh_tokens_have_closed_wire_shapes() {
        let code = verification_code("000042".to_owned());
        assert!(matches!(code, Ok(value) if value.expose_secret() == "000042"));
        assert!(verification_code("42".to_owned()).is_err());

        assert!(refresh_token(format!("rft_{}", "A".repeat(43))).is_ok());
        assert!(refresh_token(format!("cat_{}", "A".repeat(43))).is_err());
    }

    #[test]
    fn signup_profiles_require_a_real_tzdb_identifier() {
        let valid = SignupCompletionInput {
            carbon_id: "timezone_test".to_owned(),
            display_name: "Time Zone Test".to_owned(),
            time_zone: Some("Asia/Kolkata".to_owned()),
            description: None,
            profile_photo: None,
        };
        assert!(matches!(
            signup_completion(valid, false),
            Ok(profile) if profile.timezone == "Asia/Kolkata"
        ));

        let invalid = SignupCompletionInput {
            carbon_id: "timezone_test".to_owned(),
            display_name: "Time Zone Test".to_owned(),
            time_zone: Some("Mars/Olympus_Mons".to_owned()),
            description: None,
            profile_photo: None,
        };
        assert!(signup_completion(invalid, false).is_err());

        let defaulted = SignupCompletionInput {
            carbon_id: "timezone_test".to_owned(),
            display_name: "Time Zone Test".to_owned(),
            time_zone: None,
            description: None,
            profile_photo: None,
        };
        assert!(matches!(
            signup_completion(defaulted, false),
            Ok(profile) if profile.timezone == "UTC"
        ));
    }
}
