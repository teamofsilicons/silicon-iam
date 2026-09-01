use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use url::Url;

use super::{error::ApiError, model};

const MAX_REDIRECT_URIS: usize = 20;
const MAX_SCOPES: usize = 100;
const MAX_OBO_ENDPOINTS: usize = 50;
const MAX_OBO_METADATA_BYTES: usize = 16_384;
const MAX_OBO_METADATA_DEPTH: usize = 8;
const MAX_OBO_METADATA_NODES: usize = 512;

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
    obo_endpoints(&input.obo_endpoints)?;
    Ok(())
}

pub(super) fn application_patch(input: &model::ApplicationPatch) -> Result<(), ApiError> {
    if input.app_name.is_none()
        && input.app_logo_uri.is_none()
        && input.redirect_uris.is_none()
        && input.requested_scopes.is_none()
        && input.obo_endpoints.is_none()
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
    if let Some(values) = &input.obo_endpoints {
        obo_endpoints(values)?;
    }
    Ok(())
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
    crate::features::webhook_url::parse(value)
        .map_err(|message| ApiError::validation("webhook_url", message))
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
    bounded_oauth_state(&query.state)?;
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

pub(super) fn obo_endpoint_id(value: &str) -> Result<(), ApiError> {
    if !(3..=128).contains(&value.len())
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0
                    && (byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b':' | b'-')))
        })
    {
        return Err(ApiError::validation(
            "endpoint_id",
            "must be 3-128 characters, start with a lowercase letter, and contain only lowercase ASCII letters, digits, '_', '.', ':', or '-'",
        ));
    }
    Ok(())
}

pub(super) fn obo_metadata(field: &'static str, value: &serde_json::Value) -> Result<(), ApiError> {
    if !value.is_object() {
        return Err(ApiError::validation(field, "must be a JSON object"));
    }
    let encoded =
        serde_json::to_vec(value).map_err(|_| ApiError::validation(field, "must be valid JSON"))?;
    if encoded.len() > MAX_OBO_METADATA_BYTES {
        return Err(ApiError::validation(
            field,
            "must serialize to at most 16384 bytes",
        ));
    }
    let mut nodes = 0;
    validate_json_shape(value, 0, &mut nodes, field)
}

fn obo_endpoints(values: &[model::ApplicationOboEndpoint]) -> Result<(), ApiError> {
    if values.len() > MAX_OBO_ENDPOINTS {
        return Err(ApiError::validation(
            "obo_endpoints",
            "must contain at most 50 endpoints",
        ));
    }
    let mut identifiers = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for endpoint in values {
        obo_endpoint_id(&endpoint.endpoint_id)?;
        if !identifiers.insert(endpoint.endpoint_id.as_str()) {
            return Err(ApiError::validation(
                "obo_endpoints",
                "contains duplicate endpoint_id values",
            ));
        }
        if endpoint.path.len() > 2_048
            || !endpoint.path.starts_with('/')
            || endpoint.path.starts_with("//")
            || endpoint.path.contains(['?', '#'])
            || endpoint
                .path
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || endpoint
                .path
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
        {
            return Err(ApiError::validation(
                "obo_endpoints",
                "contains an invalid absolute endpoint path",
            ));
        }
        if !paths.insert(endpoint.path.as_str()) {
            return Err(ApiError::validation(
                "obo_endpoints",
                "contains duplicate endpoint paths",
            ));
        }
        obo_metadata("obo_endpoints.metadata", &endpoint.metadata)?;
        validate_obo_metadata_definition(&endpoint.metadata)?;
    }
    Ok(())
}

fn validate_obo_metadata_definition(definition: &serde_json::Value) -> Result<(), ApiError> {
    let Some(properties) = definition.as_object() else {
        return Err(ApiError::validation(
            "obo_endpoints.metadata",
            "must be a JSON object",
        ));
    };
    for descriptor in properties.values() {
        let Some(descriptor) = descriptor.as_object() else {
            continue;
        };
        let Some(declared_type) = descriptor.get("type") else {
            continue;
        };
        let Some(declared_type) = declared_type.as_str() else {
            return Err(ApiError::validation(
                "obo_endpoints.metadata",
                "contains a metadata type that is not a string",
            ));
        };
        if !matches!(
            declared_type,
            "string" | "number" | "integer" | "boolean" | "object" | "array" | "null"
        ) {
            return Err(ApiError::validation(
                "obo_endpoints.metadata",
                "contains an unsupported metadata type",
            ));
        }
    }
    Ok(())
}

pub(super) fn obo_request_metadata(
    definition: &serde_json::Value,
    request: &serde_json::Value,
) -> Result<(), ApiError> {
    obo_metadata("metadata", request)?;
    let Some(definition) = definition.as_object() else {
        return Err(ApiError::internal("obo_endpoint_metadata_definition"));
    };
    let Some(request) = request.as_object() else {
        return Err(ApiError::validation("metadata", "must be a JSON object"));
    };
    if let Some(key) = definition.keys().find(|key| !request.contains_key(*key)) {
        return Err(ApiError::validation(
            "metadata",
            format!("is missing the required '{key}' property"),
        ));
    }
    if let Some(key) = request.keys().find(|key| !definition.contains_key(*key)) {
        return Err(ApiError::validation(
            "metadata",
            format!("contains the unregistered '{key}' property"),
        ));
    }
    for (key, descriptor) in definition {
        let Some(declared_type) = descriptor
            .as_object()
            .and_then(|descriptor| descriptor.get("type"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let Some(value) = request.get(key) else {
            return Err(ApiError::validation(
                "metadata",
                "is missing a required property",
            ));
        };
        let matches = match declared_type {
            "string" => value.is_string(),
            "number" => value.is_number(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "boolean" => value.is_boolean(),
            "object" => value.is_object(),
            "array" => value.is_array(),
            "null" => value.is_null(),
            _ => return Err(ApiError::internal("obo_endpoint_metadata_type")),
        };
        if !matches {
            return Err(ApiError::validation(
                "metadata",
                format!("property '{key}' must have type '{declared_type}'"),
            ));
        }
    }
    Ok(())
}

fn validate_json_shape(
    value: &serde_json::Value,
    depth: usize,
    nodes: &mut usize,
    field: &'static str,
) -> Result<(), ApiError> {
    *nodes += 1;
    if depth > MAX_OBO_METADATA_DEPTH || *nodes > MAX_OBO_METADATA_NODES {
        return Err(ApiError::validation(
            field,
            "is too deeply nested or complex",
        ));
    }
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                if key.is_empty()
                    || key.len() > 128
                    || key.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(ApiError::validation(
                        field,
                        "contains an invalid object key",
                    ));
                }
                validate_json_shape(child, depth + 1, nodes, field)?;
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                validate_json_shape(child, depth + 1, nodes, field)?;
            }
        }
        _ => {}
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

fn bounded_oauth_state(value: &str) -> Result<(), ApiError> {
    if !(16..=512).contains(&value.len()) || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "state must contain 16 to 512 characters.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sha2::Digest as _;

    use super::{
        app_id, obo_endpoint_id, obo_endpoints, obo_metadata, obo_request_metadata, pkce_matches,
        redirect_uris, webhook_url,
    };
    use crate::features::applications::model::ApplicationOboEndpoint;

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
    fn obo_endpoints_accept_application_owned_identifiers_and_bounded_objects() {
        assert!(obo_endpoint_id("documents.read").is_ok());
        assert!(obo_endpoint_id("Owner.read").is_err());
        assert!(obo_metadata("metadata", &json!({ "document_id": "doc_123" })).is_ok());
        assert!(obo_metadata("metadata", &json!(["not", "an", "object"])).is_err());
        assert!(obo_metadata("metadata", &json!({ "value": "x".repeat(16_384) })).is_err());
    }

    #[test]
    fn obo_endpoint_registry_requires_unique_stable_absolute_paths() {
        let endpoint = ApplicationOboEndpoint {
            endpoint_id: "documents.read".to_owned(),
            path: "/v1/documents/read".to_owned(),
            metadata: json!({ "document_id": { "type": "string" } }),
        };
        assert!(obo_endpoints(std::slice::from_ref(&endpoint)).is_ok());
        assert!(obo_endpoints(&[endpoint.clone(), endpoint.clone()]).is_err());
        assert!(
            obo_endpoints(&[ApplicationOboEndpoint {
                path: "/v1/../admin".to_owned(),
                ..endpoint
            }])
            .is_err()
        );
    }

    #[test]
    fn obo_request_metadata_matches_the_registered_contract_exactly() {
        let definition = json!({
            "reason": { "type": "string" },
            "attempt": { "type": "integer" },
            "flags": { "type": "array" },
            "context": { "type": "object" },
            "approved": { "type": "boolean" },
            "weight": { "type": "number" },
            "empty": { "type": "null" },
        });
        assert!(
            obo_request_metadata(
                &definition,
                &json!({
                    "reason": "support",
                    "attempt": 2,
                    "flags": ["urgent"],
                    "context": { "ticket": "SUP-1" },
                    "approved": true,
                    "weight": 1.5,
                    "empty": null,
                }),
            )
            .is_ok()
        );
        assert!(obo_request_metadata(&definition, &json!({})).is_err());
        assert!(
            obo_request_metadata(
                &definition,
                &json!({
                    "reason": 7,
                    "attempt": 2,
                    "flags": [],
                    "context": {},
                    "approved": true,
                    "weight": 1,
                    "empty": null,
                }),
            )
            .is_err()
        );
        assert!(
            obo_request_metadata(
                &json!({ "reason": { "type": "string" } }),
                &json!({ "reason": "support", "unregistered": true }),
            )
            .is_err()
        );
    }

    #[test]
    fn obo_endpoint_registry_rejects_invalid_declared_types() {
        let endpoint = ApplicationOboEndpoint {
            endpoint_id: "documents.read".to_owned(),
            path: "/v1/documents/read".to_owned(),
            metadata: json!({ "document_id": { "type": "uuid" } }),
        };
        assert!(obo_endpoints(&[endpoint]).is_err());
    }
}
