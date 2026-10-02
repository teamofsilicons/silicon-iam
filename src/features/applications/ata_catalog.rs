//! Application delegation endpoint definitions, separate from user delegation.
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Transaction};

use super::{error::ApiError, security::ApplicationClient, validation, verification};
use crate::{
    api::ApiState,
    domain::id::Id,
    infrastructure::postgres::context::{self, DatabaseContext},
};

pub(super) const WARNINGS: &[&str] = &[
    "uses_credits",
    "incurs_cost",
    "stores_data",
    "shares_data",
    "deletes_data",
    "external_service",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dependency {
    pub(super) audience: String,
    pub(super) endpoint_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_field_names,
    reason = "endpoint_id is the documented wire field"
)]
pub(super) struct Endpoint {
    pub(super) endpoint_id: String,
    pub(super) name: String,
    pub(super) path: String,
    pub(super) critical: bool,
    pub(super) description: String,
    #[serde(default = "empty_object")]
    pub(super) metadata: Value,
    #[serde(default)]
    pub(super) note_to_user: Option<String>,
    #[serde(default)]
    pub(super) additional_warnings: Vec<String>,
    #[serde(default)]
    pub(super) downstream: Vec<Dependency>,
    #[serde(default = "enabled")]
    pub(super) enabled: bool,
}
fn empty_object() -> Value {
    serde_json::json!({})
}
const fn enabled() -> bool {
    true
}

pub(super) fn validate(endpoints: &[Endpoint]) -> Result<(), ApiError> {
    if endpoints.len() > 100 {
        return Err(ApiError::validation(
            "ata_endpoints",
            "at most 100 endpoints may be configured",
        ));
    }
    let mut ids = std::collections::HashSet::new();
    let mut paths = std::collections::HashSet::new();
    for endpoint in endpoints {
        if !valid_local_id(&endpoint.endpoint_id) || !ids.insert(&endpoint.endpoint_id) {
            return Err(ApiError::validation(
                "ata_endpoints.endpoint_id",
                "use a unique lowercase local endpoint ID, 1–128 characters",
            ));
        }
        validation::optional_text("ata_endpoints.name", Some(&endpoint.name), 1, 160)?;
        validation::optional_text(
            "ata_endpoints.description",
            Some(&endpoint.description),
            1,
            4000,
        )?;
        validation::optional_text(
            "ata_endpoints.note_to_user",
            endpoint.note_to_user.as_deref(),
            1,
            2000,
        )?;
        if !valid_path(&endpoint.path) || !paths.insert(&endpoint.path) {
            return Err(ApiError::validation(
                "ata_endpoints.path",
                "use a unique absolute API path without query, fragment or traversal",
            ));
        }
        if !endpoint.metadata.is_object() || endpoint.metadata.to_string().len() > 16384 {
            return Err(ApiError::validation(
                "ata_endpoints.metadata",
                "must be an object up to 16 KiB",
            ));
        }
        let warnings: std::collections::HashSet<_> = endpoint.additional_warnings.iter().collect();
        if warnings.len() != endpoint.additional_warnings.len()
            || warnings.iter().any(|v| !WARNINGS.contains(&v.as_str()))
        {
            return Err(ApiError::validation(
                "ata_endpoints.additional_warnings",
                "select distinct warnings from the IAM warning catalog",
            ));
        }
        if endpoint.downstream.len() > 16 {
            return Err(ApiError::validation(
                "ata_endpoints.downstream",
                "at most 16 direct dependencies may be configured",
            ));
        }
        let mut deps = std::collections::HashSet::new();
        for dependency in &endpoint.downstream {
            validation::app_id(&dependency.audience)?;
            if !valid_local_id(&dependency.endpoint_id)
                || !deps.insert((&dependency.audience, &dependency.endpoint_id))
            {
                return Err(ApiError::validation(
                    "ata_endpoints.downstream",
                    "use distinct application and local ATA endpoint IDs",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn valid_local_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
fn valid_path(value: &str) -> bool {
    (1..=2048).contains(&value.len())
        && value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains(['?', '#', '\\', '%'])
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
        && !value.split('/').any(|s| s == "." || s == "..")
}

pub(super) async fn replace(
    tx: &mut Transaction<'_, Postgres>,
    app: Id,
    endpoints: &[Endpoint],
) -> Result<(), ApiError> {
    validate(endpoints)?;
    sqlx::query("SELECT iam_private.configure_application_ata_endpoints($1,$2)")
        .bind(app)
        .bind(sqlx::types::Json(endpoints))
        .execute(&mut **tx)
        .await
        .map_err(|_| {
            ApiError::validation(
                "ata_endpoints",
                "endpoint configuration conflicts with the existing catalog",
            )
        })?;
    Ok(())
}

pub(super) async fn discover(
    State(state): State<ApiState>,
    client: ApplicationClient,
    Path(app_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validation::app_id(&app_id)?;
    let mut tx = context::begin(
        state.db(),
        DatabaseContext::application(client.application_id, client.application_id),
    )
    .await
    .map_err(|_| ApiError::internal("ata_discovery_context"))?;
    verification::lock_client(&mut tx, &state, &client).await?;
    let catalog = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.discover_application_ata_endpoints($1)",
    )
    .bind(app_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError::internal("ata_discovery"))?
    .ok_or_else(ApiError::not_found)?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("ata_discovery_commit"))?;
    Ok(Json(catalog.0))
}

pub(super) async fn warning_catalog() -> Json<Value> {
    Json(serde_json::json!({"warnings":[
        {"id":"uses_credits","name":"Uses credits"}, {"id":"incurs_cost","name":"May incur charges"},
        {"id":"stores_data","name":"Stores data"}, {"id":"shares_data","name":"Shares data"},
        {"id":"deletes_data","name":"Can delete data"}, {"id":"external_service","name":"Uses an external service"}
    ]}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_authority_confusion_and_unsafe_paths() {
        for value in [
            "[app:obo:read]",
            "[app:ata:read]",
            "read:private",
            "READ",
            "",
            "<script>",
        ] {
            assert!(!valid_local_id(value));
        }
        for path in [
            "//evil.example/a",
            "/a/../b",
            "/a%2fb",
            "/a?b",
            "/a#b",
            "/a\\b",
            "/a\nb",
        ] {
            assert!(!valid_path(path));
        }
        assert!(valid_local_id("read_private"));
        assert!(valid_path("/api/v1/files/{id}"));
    }
}
