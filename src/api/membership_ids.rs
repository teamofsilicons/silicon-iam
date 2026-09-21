//! Translate canonical public membership IDs at the transport boundary.
//!
//! UUID keys remain private to storage and authorization. Translation never
//! authorizes a resource; handlers continue to enforce their existing checks.

use std::collections::{BTreeMap, BTreeSet};

use crate::domain::id::Id;
use axum::{
    body::{Body, to_bytes},
    extract::{FromRequestParts, Path, Request, State},
    http::{header, request::Parts},
    middleware::Next,
    response::Response,
};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};

use super::ApiState;
use crate::{error::AppError, infrastructure::postgres::context};

pub(crate) struct MembershipPath(pub(crate) (String, Id));

impl FromRequestParts<ApiState> for MembershipPath {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &ApiState) -> Result<Self, AppError> {
        let Path((org, id)) = Path::<(String, String)>::from_request_parts(parts, state)
            .await
            .map_err(|_| invalid_id())?;
        if legacy_client(&parts.headers)
            && let Ok(key) = Id::parse_str(&id)
        {
            return Ok(Self((org, key)));
        }
        if membership_org(&id) != Some(org.as_str()) {
            return Err(invalid_id());
        }
        let mut transaction = context::begin_scoped(state.db()).await?;
        let rows = resolve(&mut transaction, &[id], &[]).await?;
        transaction.commit().await?;
        let (key, _) = rows.into_iter().next().ok_or(AppError::NotFound)?;
        Ok(Self((org, key)))
    }
}

fn invalid_id() -> AppError {
    AppError::Validation {
        details: json!({"membership_id": ["must be carbon_id[org_id] or silicon_id[org_id]"]}),
    }
}

fn handle(value: &str, max: usize) -> bool {
    (3..=max).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
}

fn membership_org(id: &str) -> Option<&str> {
    let (actor, org) = id.strip_suffix(']')?.split_once('[')?;
    if !handle(org, 50) {
        return None;
    }
    let valid = actor.split_once(':').map_or_else(
        || handle(actor, 30),
        |(silicon, owner)| handle(silicon, 50) && owner == org,
    );
    valid.then_some(org)
}

fn membership_field(key: &str) -> bool {
    key == "membership_id"
        || key.ends_with("_membership_id")
        || key.ends_with("_membership_ids")
        || key == "extra_silicons"
        || key == "reassign_reports_to"
}

fn identifier_field(key: &str) -> bool {
    membership_field(key) || key == "id" || key.ends_with("_id") || key.ends_with("_ids")
}

fn visit_ids(
    value: &mut Value,
    key: &str,
    visit: &mut impl FnMut(&mut Value, &str) -> Result<(), AppError>,
) -> Result<(), AppError> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                visit_ids(value, key, visit)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                visit_ids(value, key, visit)?;
            }
        }
        _ if identifier_field(key) => visit(value, key)?,
        _ => {}
    }
    Ok(())
}

fn needs_translation(value: &Value, key: &str, input: bool) -> bool {
    match value {
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| needs_translation(value, key, input)),
        Value::Array(values) => values
            .iter()
            .any(|value| needs_translation(value, key, input)),
        Value::String(id) if identifier_field(key) => {
            if input {
                membership_field(key) || membership_org(id).is_some()
            } else {
                Id::parse_str(id).is_ok()
            }
        }
        _ => false,
    }
}

async fn resolve(
    transaction: &mut Transaction<'_, Postgres>,
    ids: &[String],
    keys: &[Id],
) -> Result<Vec<(Id, String)>, AppError> {
    Ok(
        sqlx::query_as("SELECT * FROM iam_private.resolve_membership_identifiers($1, $2)")
            .bind(ids)
            .bind(keys)
            .fetch_all(&mut **transaction)
            .await?,
    )
}

async fn decode(
    transaction: &mut Transaction<'_, Postgres>,
    value: &mut Value,
) -> Result<(), AppError> {
    let mut ids = BTreeSet::new();
    visit_ids(value, "", &mut |value, key| {
        if value.is_null() {
            return Ok(());
        }
        if let Some(id) = value.as_str() {
            if membership_org(id).is_some() {
                ids.insert(id.to_owned());
            } else if membership_field(key) {
                return Err(invalid_id());
            }
        } else if membership_field(key) {
            return Err(invalid_id());
        }
        Ok(())
    })?;
    if ids.is_empty() {
        return Ok(());
    }
    let ids: Vec<_> = ids.into_iter().collect();
    let mapping: BTreeMap<_, _> = resolve(transaction, &ids, &[])
        .await?
        .into_iter()
        .map(|(key, id)| (id, key.to_string()))
        .collect();
    if mapping.len() != ids.len() {
        return Err(AppError::NotFound);
    }
    visit_ids(value, "", &mut |value, _| {
        if let Some(key) = value.as_str().and_then(|id| mapping.get(id)) {
            *value = Value::String(key.clone());
        }
        Ok(())
    })
}

pub(crate) async fn encode(
    transaction: &mut Transaction<'_, Postgres>,
    value: &mut Value,
) -> Result<(), AppError> {
    let mut keys = BTreeSet::new();
    visit_ids(value, "", &mut |value, _| {
        if let Some(key) = value.as_str().and_then(|id| Id::parse_str(id).ok()) {
            keys.insert(key);
        }
        Ok(())
    })?;
    if keys.is_empty() {
        return Ok(());
    }
    let mapping: BTreeMap<_, _> = resolve(transaction, &[], &keys.into_iter().collect::<Vec<_>>())
        .await?
        .into_iter()
        .map(|(key, id)| (key.to_string(), id))
        .collect();
    visit_ids(value, "", &mut |value, key| {
        if let Some(id) = value.as_str().and_then(|key| mapping.get(key)) {
            *value = Value::String(id.clone());
        } else if membership_field(key)
            && value.as_str().is_some_and(|id| Id::parse_str(id).is_ok())
        {
            return Err(AppError::Internal {
                category: "membership_identifier_missing",
            });
        }
        Ok(())
    })
}

// Existing 1.x clients deserialize membership references as UUIDs, including
// authorization snapshots used by other live services. Keep their established
// representation until they upgrade; this does not bypass handler authorization.
fn legacy_client(headers: &http::HeaderMap) -> bool {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.strip_prefix("silicon-iam-client/"))
        .is_some_and(|version| {
            let parts: Vec<_> = version.split('.').collect();
            parts.len() == 3
                && parts[0] == "1"
                && parts[1..]
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
}

pub(crate) async fn transport(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    if legacy_client(request.headers()) {
        let mut response = encode_response(&state, next.run(request).await, false).await?;
        response.headers_mut().insert(
            "silicon-iam-membership-format",
            http::HeaderValue::from_static("uuid-legacy"),
        );
        return Ok(response);
    }
    let (mut parts, body) = request.into_parts();
    // These are the authenticated request contracts accepting membership refs.
    // Preserve unrelated bodies byte-for-byte (including signed callbacks).
    let accepts_memberships = parts.uri.path().starts_with("/api/v1/organizations/")
        || parts.uri.path() == "/api/v1/step-up/challenges";
    if let Some(query) = parts.uri.query()
        && accepts_memberships
        && query.contains("reassign_reports_to")
    {
        let mut values = Value::Object(
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
                .collect(),
        );
        let authenticated =
            super::authentication::Authenticated::from_request_parts(&mut parts, &state).await?;
        parts.extensions.insert(authenticated);
        let before = values.clone();
        let mut transaction = context::begin_scoped(state.db()).await?;
        decode(&mut transaction, &mut values).await?;
        transaction.commit().await?;
        if values != before {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            if let Some(values) = values.as_object() {
                for (key, value) in values {
                    if let Some(value) = value.as_str() {
                        query.append_pair(key, value);
                    }
                }
            }
            let path = format!("{}?{}", parts.uri.path(), query.finish());
            let mut uri = parts.uri.into_parts();
            uri.path_and_query = Some(path.parse().map_err(|_| invalid_id())?);
            parts.uri = http::Uri::from_parts(uri).map_err(|_| invalid_id())?;
        }
    }
    let request = if is_json(&parts.headers) {
        let bytes = to_bytes(body, state.settings.server.max_body_bytes)
            .await
            .map_err(|_| AppError::Validation {
                details: json!({"body": ["request body is too large"]}),
            })?;
        // Leave malformed JSON to the handler's ordinary JSON rejection.
        if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes)
            && accepts_memberships
            && needs_translation(&value, "", true)
        {
            let authenticated =
                super::authentication::Authenticated::from_request_parts(&mut parts, &state)
                    .await?;
            parts.extensions.insert(authenticated);
            let before = value.clone();
            let mut transaction = context::begin_scoped(state.db()).await?;
            decode(&mut transaction, &mut value).await?;
            transaction.commit().await?;
            if value == before {
                Request::from_parts(parts, Body::from(bytes))
            } else {
                parts.headers.remove(header::CONTENT_LENGTH);
                Request::from_parts(parts, Body::from(value.to_string()))
            }
        } else {
            Request::from_parts(parts, Body::from(bytes))
        }
    } else {
        Request::from_parts(parts, body)
    };
    let response = next.run(request).await;
    encode_response(&state, response, true).await
}

/// Internal record field names never become duplicate public identity keys.
/// This also covers JSON returned by privileged SQL readers and replay caches.
pub(crate) fn remove_principal_ids(value: &mut Value) -> bool {
    match value {
        Value::Object(object) => {
            let principal = object.remove("principal_id");
            let mut changed = principal.is_some();
            if let Some(identity) = principal
                && !["id", "carbon_id", "silicon_id", "app_id", "public_id"]
                    .iter()
                    .any(|key| object.contains_key(*key))
            {
                object.insert("id".to_owned(), identity);
            }
            let redundant_keys: Vec<_> = object
                .keys()
                .filter(|key| key.ends_with("_principal_id"))
                .cloned()
                .collect();
            for key in redundant_keys {
                if let Some(value) = object.remove(&key) {
                    object
                        .entry(key.replace("_principal_id", "_id"))
                        .or_insert(value);
                    changed = true;
                }
            }
            for value in object.values_mut() {
                changed |= remove_principal_ids(value);
            }
            changed
        }
        Value::Array(values) => {
            let mut changed = false;
            for value in values {
                changed |= remove_principal_ids(value);
            }
            changed
        }
        _ => false,
    }
}

async fn encode_response(
    state: &ApiState,
    response: Response,
    translate_memberships: bool,
) -> Result<Response, AppError> {
    if !is_json(response.headers()) {
        return Ok(response);
    }
    let (mut parts, body) = response.into_parts();
    let bytes = to_bytes(body, usize::MAX)
        .await
        .map_err(|_| AppError::Internal {
            category: "membership_response_body",
        })?;
    let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    };
    let identities_changed = remove_principal_ids(&mut value);
    let memberships_changed = translate_memberships && needs_translation(&value, "", false);
    if !identities_changed && !memberships_changed {
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    }
    if memberships_changed {
        let mut transaction = context::begin_scoped(state.db()).await?;
        encode(&mut transaction, &mut value).await?;
        transaction.commit().await?;
    }
    parts.headers.remove(header::CONTENT_LENGTH);
    Ok(Response::from_parts(parts, Body::from(value.to_string())))
}

fn is_json(headers: &http::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|mime| {
                mime.trim() == "application/json" || mime.trim().ends_with("+json")
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_responses_remove_redundant_principal_keys_recursively() {
        let mut value = json!({"principal_id":"saket","carbon_id":"saket","items":[{"actor":{"principal_id":"chef:bricks","public_id":"chef:bricks","type":"silicon"}}]});
        assert!(remove_principal_ids(&mut value));
        assert_eq!(
            value,
            json!({"carbon_id":"saket","items":[{"actor":{"public_id":"chef:bricks","type":"silicon"}}]})
        );
        assert!(!remove_principal_ids(&mut value));
    }

    #[test]
    fn generic_webhook_actors_keep_their_canonical_identity() {
        let mut value = json!({"actor":{"type":"carbon","principal_id":"saket"},"subject_principal_id":"chef:bricks"});
        assert!(remove_principal_ids(&mut value));
        assert_eq!(
            value,
            json!({"actor":{"type":"carbon","id":"saket"},"subject_id":"chef:bricks"})
        );
    }

    #[test]
    fn only_existing_official_clients_receive_legacy_memberships() {
        for (agent, expected) in [
            ("silicon-iam-client/1.8.0 silicon-briefcase/0.5.0", true),
            ("silicon-iam-client/1.11.0", true),
            ("silicon-iam-client/2.0.0", false),
            ("silicon-iam-client/1.bad.0", false),
            ("browser silicon-iam-client/1.11.0", false),
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert(header::USER_AGENT, http::HeaderValue::from_static(agent));
            assert_eq!(legacy_client(&headers), expected);
        }
        assert!(!legacy_client(&http::HeaderMap::new()));
    }

    #[test]
    fn canonical_ids_distinguish_carbons_and_full_silicon_ids() {
        assert_eq!(membership_org("saket[tos]"), Some("tos"));
        assert_eq!(membership_org("head_of_growth:tos[tos]"), Some("tos"));
        for invalid in [
            "saket",
            "saket[]",
            "saket[tos][tos]",
            "head:acme[tos]",
            "Saket[tos]",
            "00000000-0000-0000-0000-000000000001",
        ] {
            assert_eq!(membership_org(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn identifiers_are_visited_without_rewriting_profile_text() -> Result<(), AppError> {
        let mut value = json!({"display_name": "saket[tos]", "first_silicon_membership_id": null,
            "extra_silicon_membership_ids": ["head:tos[tos]"], "nested": {"membership_id": "saket[tos]"}});
        visit_ids(&mut value, "", &mut |v, _| {
            if v.is_string() {
                *v = json!("changed");
            }
            Ok(())
        })?;
        assert_eq!(value["display_name"], "saket[tos]");
        assert_eq!(value["extra_silicon_membership_ids"][0], "changed");
        assert!(value["first_silicon_membership_id"].is_null());
        Ok(())
    }
}

#[cfg(test)]
#[path = "membership_ids_tests.rs"]
mod integration_tests;
