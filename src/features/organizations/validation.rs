use std::{collections::HashSet, str::FromStr as _};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderMap;
use serde_json::json;
use url::Url;
use uuid::Uuid;

use crate::{
    config::RuntimeEnvironment,
    domain::{
        directory::{JobRole, OrganizationId, SiliconLocalId},
        organization::Capability,
    },
    error::AppError,
};

use super::model::{
    CapabilitiesReplace, MachineCapabilitiesReplace, MembershipDirectoryPatch, OrganizationCreate,
    OrganizationPatch, PageQuery, SiliconCreate, SiliconPatch, TagInput, TrustRulePatch,
};

const MAX_CURSOR_BYTES: usize = 128;
const DEFAULT_PAGE_SIZE: u16 = 50;
const MAX_PAGE_SIZE: u16 = 100;

pub(super) fn organization_id(value: &str) -> Result<OrganizationId, AppError> {
    OrganizationId::from_str(value).map_err(|_| field("org_id", "has an invalid format"))
}

pub(super) fn organization_create(
    input: &mut OrganizationCreate,
    environment: RuntimeEnvironment,
) -> Result<OrganizationId, AppError> {
    let organization_id = organization_id(&input.org_id)?;
    input.org_id = organization_id.to_string();
    input.name = bounded_text("name", std::mem::take(&mut input.name), 1, 200, false)?;
    input.description = optional_text("description", input.description.take(), 5_000)?;
    input.logo = optional_url("logo", input.logo.take(), environment)?;
    Ok(organization_id)
}

pub(super) fn organization_patch(
    input: &mut OrganizationPatch,
    environment: RuntimeEnvironment,
) -> Result<(), AppError> {
    if input.name.is_none()
        && input.logo.is_none()
        && input.description.is_none()
        && input.join_method.is_none()
    {
        return Err(field("body", "must contain at least one mutable field"));
    }
    if let Some(name) = input.name.take() {
        input.name = Some(bounded_text("name", name, 1, 200, false)?);
    }
    if let Some(logo) = input.logo.take() {
        input.logo = Some(optional_url("logo", logo, environment)?);
    }
    if let Some(description) = input.description.take() {
        input.description = Some(optional_text("description", description, 5_000)?);
    }
    if let Some(join_method) = input.join_method.as_deref()
        && !matches!(join_method, "email" | "sso")
    {
        return Err(field("join_method", "must be email or sso"));
    }
    Ok(())
}

pub(super) fn member_patch(
    input: &mut MembershipDirectoryPatch,
    environment: RuntimeEnvironment,
) -> Result<(), AppError> {
    if input.tag_ids.is_none()
        && input.first_silicon_membership_id.is_none()
        && input.extra_silicon_membership_ids.is_none()
        && input.reports_to_membership_id.is_none()
        && input.profile_photo.is_none()
    {
        return Err(field("body", "must contain at least one mutable field"));
    }
    if let Some(tag_ids) = input.tag_ids.as_mut() {
        validate_unique_ids("tag_ids", tag_ids, 100)?;
    }
    if let Some(extra_ids) = input.extra_silicon_membership_ids.as_mut() {
        validate_unique_ids("extra_silicon_membership_ids", extra_ids, 500)?;
    }
    if let Some(profile_photo) = input.profile_photo.take() {
        input.profile_photo = Some(optional_url("profile_photo", profile_photo, environment)?);
    }
    Ok(())
}

pub(super) fn silicon_create(
    input: &mut SiliconCreate,
    environment: RuntimeEnvironment,
) -> Result<SiliconLocalId, AppError> {
    let local_id = SiliconLocalId::from_str(&input.silicon_id)
        .map_err(|_| field("silicon_id", "has an invalid format"))?;
    input.silicon_id = local_id.to_string();
    input.job_role = job_role(std::mem::take(&mut input.job_role))?;
    input.profile_photo = optional_url("profile_photo", input.profile_photo.take(), environment)?;
    validate_unique_ids("tag_ids", &mut input.tag_ids, 100)?;
    input.machine_capabilities = machine_capabilities(&MachineCapabilitiesReplace {
        machine_capabilities: std::mem::take(&mut input.machine_capabilities),
    })?;
    Ok(local_id)
}

pub(super) fn silicon_patch(
    input: &mut SiliconPatch,
    environment: RuntimeEnvironment,
) -> Result<(), AppError> {
    if input.profile_photo.is_none()
        && input.reports_to_membership_id.is_none()
        && input.tag_ids.is_none()
    {
        return Err(field("body", "must contain at least one mutable field"));
    }
    if let Some(profile_photo) = input.profile_photo.take() {
        input.profile_photo = Some(optional_url("profile_photo", profile_photo, environment)?);
    }
    if let Some(tag_ids) = input.tag_ids.as_mut() {
        validate_unique_ids("tag_ids", tag_ids, 100)?;
    }
    Ok(())
}

pub(super) fn tag(input: &mut TagInput) -> Result<String, AppError> {
    input.name = bounded_text("name", std::mem::take(&mut input.name), 1, 100, false)?;
    let normalized = input
        .name
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");
    if normalized.is_empty()
        || normalized.len() > 100
        || !normalized.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(field(
            "name",
            "must normalize to lowercase letters, digits, hyphens, or underscores",
        ));
    }
    Ok(normalized)
}

pub(super) fn capabilities(input: &CapabilitiesReplace) -> Result<Vec<String>, AppError> {
    let mut seen = HashSet::with_capacity(input.capabilities.len());
    let mut capabilities = Vec::with_capacity(input.capabilities.len());
    for value in &input.capabilities {
        let capability = Capability::from_str(value)
            .map_err(|_| field("capabilities", "contains an unsupported capability"))?;
        if !seen.insert(capability) {
            return Err(field("capabilities", "must contain unique values"));
        }
        capabilities.push(capability.as_str().to_owned());
    }
    capabilities.sort_unstable();
    Ok(capabilities)
}

pub(super) fn machine_capabilities(
    input: &MachineCapabilitiesReplace,
) -> Result<Vec<String>, AppError> {
    const ALLOWED: [&str; 5] = [
        "members.update_directory",
        "roles.request",
        "silicons.manage_hierarchy",
        "silicons.update_directory",
        "trust.manage",
    ];
    let mut values = input.machine_capabilities.clone();
    values.sort_unstable();
    if values.len() > ALLOWED.len()
        || values.windows(2).any(|pair| pair[0] == pair[1])
        || values
            .iter()
            .any(|value| ALLOWED.binary_search(&value.as_str()).is_err())
    {
        return Err(field(
            "machine_capabilities",
            "contains a duplicate or capability not allowed for Silicons",
        ));
    }
    Ok(values)
}

pub(super) fn trust_rule_patch(input: &TrustRulePatch) -> Result<(), AppError> {
    if input.subject.is_none() && input.target.is_none() && input.trust.is_none() {
        return Err(field("body", "must contain at least one mutable field"));
    }
    Ok(())
}

pub(super) fn job_role(value: String) -> Result<String, AppError> {
    JobRole::try_from(value)
        .map(String::from)
        .map_err(|_| field("job_role", "must contain at most 5000 characters"))
}

pub(super) fn page(query: &PageQuery) -> Result<(Option<Uuid>, i64), AppError> {
    page_parts(query.cursor.as_deref(), query.limit)
}

pub(super) fn page_parts(
    cursor: Option<&str>,
    limit: Option<u16>,
) -> Result<(Option<Uuid>, i64), AppError> {
    let cursor = cursor.map(decode_cursor).transpose()?;
    let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(field("limit", "must be between 1 and 100"));
    }
    Ok((cursor, i64::from(limit)))
}

pub(super) fn encode_cursor(id: Uuid) -> String {
    URL_SAFE_NO_PAD.encode(id.as_bytes())
}

pub(super) fn expected_version(headers: &HeaderMap) -> Result<i64, AppError> {
    let value = headers
        .get(http::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::PreconditionRequired {
            code: "if_match_required".into(),
        })?;
    let digits = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| AppError::PreconditionFailed {
            code: "etag_invalid".into(),
        })?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::PreconditionFailed {
            code: "etag_invalid".into(),
        });
    }
    digits
        .parse::<i64>()
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| AppError::PreconditionFailed {
            code: "etag_invalid".into(),
        })
}

pub(super) fn bounded_text(
    name: &'static str,
    value: String,
    minimum: usize,
    maximum: usize,
    allow_blank: bool,
) -> Result<String, AppError> {
    let characters = value.chars().count();
    if !(minimum..=maximum).contains(&characters)
        || value.chars().any(char::is_control)
        || (!allow_blank && value.trim().is_empty())
    {
        return Err(field(name, "has an invalid length or characters"));
    }
    Ok(value)
}

pub(super) fn field(field_name: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: json!({ "fields": [{ "field": field_name, "message": message }] }),
    }
}

fn optional_text(
    name: &'static str,
    value: Option<String>,
    maximum: usize,
) -> Result<Option<String>, AppError> {
    value
        .map(|value| bounded_text(name, value, 0, maximum, true))
        .transpose()
}

fn optional_url(
    name: &'static str,
    value: Option<String>,
    environment: RuntimeEnvironment,
) -> Result<Option<String>, AppError> {
    value
        .map(|value| safe_url(name, &value, environment))
        .transpose()
}

fn safe_url(
    name: &'static str,
    value: &str,
    environment: RuntimeEnvironment,
) -> Result<String, AppError> {
    if value.len() > 2_048 {
        return Err(field(name, "must be a safe HTTP URL"));
    }
    let parsed = Url::parse(value).map_err(|_| field(name, "must be a safe HTTP URL"))?;
    let valid_scheme = match environment {
        RuntimeEnvironment::Production => parsed.scheme() == "https",
        RuntimeEnvironment::Development | RuntimeEnvironment::Test => {
            matches!(parsed.scheme(), "http" | "https")
        }
    };
    if !valid_scheme
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(field(name, "must be a safe HTTP URL"));
    }
    Ok(parsed.to_string())
}

fn validate_unique_ids(
    name: &'static str,
    values: &mut [Uuid],
    maximum: usize,
) -> Result<(), AppError> {
    values.sort_unstable();
    if values.len() > maximum || values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(field(name, "must be unique and within the item limit"));
    }
    Ok(())
}

fn decode_cursor(value: &str) -> Result<Uuid, AppError> {
    if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
        return Err(field("cursor", "has an invalid format"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| field("cursor", "has an invalid format"))?;
    Uuid::from_slice(&bytes).map_err(|_| field("cursor", "has an invalid format"))
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn cursor_round_trips_without_exposing_query_state() {
        let id = Uuid::now_v7();
        assert!(matches!(decode_cursor(&encode_cursor(id)), Ok(decoded) if decoded == id));
    }

    #[test]
    fn if_match_requires_a_positive_strong_version() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::IF_MATCH, HeaderValue::from_static("\"42\""));
        assert!(matches!(expected_version(&headers), Ok(42)));

        headers.insert(http::header::IF_MATCH, HeaderValue::from_static("W/\"42\""));
        assert!(expected_version(&headers).is_err());
    }

    #[test]
    fn machine_capabilities_are_a_closed_silicon_subset() {
        let valid = MachineCapabilitiesReplace {
            machine_capabilities: vec!["trust.manage".to_owned()],
        };
        assert!(matches!(
            machine_capabilities(&valid),
            Ok(values) if values == ["trust.manage"]
        ));

        let invalid = MachineCapabilitiesReplace {
            machine_capabilities: vec!["admins.manage".to_owned()],
        };
        assert!(machine_capabilities(&invalid).is_err());
    }
}
