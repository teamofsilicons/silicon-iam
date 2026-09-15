//! Dedicated service authority and reconciliation for Honeycomb.
mod events;
#[cfg(test)]
#[path = "honeycomb/tests.rs"]
mod live_tests;
pub(crate) mod operations;

use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, State},
    http::{header, request::Parts},
    routing::get,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use super::{error::ApiError, validation};
use crate::{
    api::ApiState,
    domain::actor::ActorType,
    infrastructure::{postgres::tokens, testing_plane},
};

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/honeycomb/scope-catalog", get(catalog))
        .route("/api/v1/honeycomb/bundles/{bundle_id}", get(bundle))
        .route("/api/v1/honeycomb/inventory", get(inventory))
        .route("/api/v1/honeycomb/applications/{app_id}", get(application))
        .route(
            "/api/v1/honeycomb/operations/{operation_id}",
            get(operation),
        )
        .merge(operations::router())
        .merge(events::router())
        .merge(crate::features::testing_environments::honeycomb::router())
        .layer(axum::middleware::from_fn(no_store))
}

async fn no_store(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

/// This is separate from `ApplicationClient` and cannot be obtained with app credentials.
pub(crate) struct Service {
    pub(crate) application_id: Uuid,
}

fn valid_service_credential(value: &str, expected_hex: &str) -> bool {
    let Some(secret) = value.strip_prefix("Bearer hck_") else {
        return false;
    };
    if secret.len() != 43
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return false;
    }
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let actual = Sha256::digest(format!("hck_{secret}").as_bytes());
    bool::from(actual.as_slice().ct_eq(&expected))
}

impl FromRequestParts<ApiState> for Service {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        // Management addresses environments explicitly. A test root key must never
        // switch the database in which service authority is evaluated.
        if testing_plane::is_active() || parts.headers.contains_key("x-testing-environment-key") {
            return Err(ApiError::forbidden("management_test_header_forbidden"));
        }
        let settings = state
            .settings
            .honeycomb
            .as_ref()
            .ok_or_else(|| ApiError::forbidden("honeycomb_not_configured"))?;
        if parts.headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
            return Err(ApiError::unauthenticated());
        }
        let value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(ApiError::unauthenticated)?;
        if !valid_service_credential(value, settings.credential_sha256.expose_secret()) {
            return Err(ApiError::unauthenticated());
        }
        let application_id = sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT iam_private.resolve_honeycomb_application($1)",
        )
        .bind(&settings.app_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| ApiError::internal("honeycomb_identity"))?
        .ok_or_else(|| ApiError::forbidden("honeycomb_identity_unavailable"))?;
        Ok(Self { application_id })
    }
}

impl Service {
    pub(crate) async fn actor(
        &self,
        state: &ApiState,
        headers: &axum::http::HeaderMap,
    ) -> Result<tokens::AccessContext, ApiError> {
        if headers.get_all("x-honeycomb-actor-token").iter().count() != 1 {
            return Err(ApiError::unauthenticated());
        }
        let token = headers
            .get("x-honeycomb-actor-token")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(ApiError::unauthenticated)?;
        let access = tokens::authenticate(
            &state.pool,
            &state.crypto,
            &SecretString::from(token.to_owned()),
        )
        .await
        .map_err(|error| match error {
            tokens::AccessTokenError::InvalidFormat => ApiError::unauthenticated(),
            _ => ApiError::internal("honeycomb_actor_authentication"),
        })?
        .ok_or_else(ApiError::unauthenticated)?;
        if access.subject.actor_type != ActorType::Carbon
            || access.client_application_id != Some(self.application_id)
            || access.audience_application_id != Some(self.application_id)
        {
            return Err(ApiError::forbidden("honeycomb_actor_required"));
        }
        Ok(access)
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFilter {
    app_id: Option<String>,
    org_id: Option<String>,
}
async fn catalog(
    State(state): State<ApiState>,
    service: Service,
    axum::extract::Query(filter): axum::extract::Query<CatalogFilter>,
) -> Result<Json<Value>, ApiError> {
    if let Some(app) = &filter.app_id {
        validation::app_id(app)?;
    }
    if let Some(org) = &filter.org_id {
        validation::org_id(org)?;
    }
    let result: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_scope_catalog($1,$2,$3)")
            .bind(service.application_id)
            .bind(filter.app_id)
            .bind(filter.org_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|_| ApiError::internal("honeycomb_scope_catalog"))?;
    Ok(Json(result.0))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFilter {
    kind: String,
    after: Option<Uuid>,
}
async fn inventory(
    State(state): State<ApiState>,
    service: Service,
    axum::extract::Query(filter): axum::extract::Query<InventoryFilter>,
) -> Result<Json<Value>, ApiError> {
    if !matches!(
        filter.kind.as_str(),
        "applications" | "bundles" | "testing-environments"
    ) {
        return Err(ApiError::validation(
            "kind",
            "select applications, bundles or testing-environments",
        ));
    }
    let value: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_inventory($1,$2,$3)")
            .bind(service.application_id)
            .bind(filter.kind)
            .bind(filter.after)
            .fetch_one(&state.pool)
            .await
            .map_err(|_| ApiError::internal("honeycomb_inventory"))?;
    Ok(Json(value.0))
}
async fn bundle(
    State(state): State<ApiState>,
    service: Service,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validation::app_id(&id)?;
    let value: Option<sqlx::types::Json<Value>> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_bundle_record($1,$2)")
            .bind(service.application_id)
            .bind(id)
            .fetch_one(&state.pool)
            .await
            .map_err(|_| ApiError::internal("honeycomb_bundle_record"))?;
    Ok(Json(value.ok_or_else(ApiError::not_found)?.0))
}

async fn application(
    State(state): State<ApiState>,
    service: Service,
    Path(app_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validation::app_id(&app_id)?;
    let value = sqlx::query_scalar::<_, Option<sqlx::types::Json<Value>>>(
        "SELECT iam_private.honeycomb_application_record($1,$2)",
    )
    .bind(service.application_id)
    .bind(&app_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| ApiError::internal("honeycomb_application_record"))?
    .ok_or_else(ApiError::not_found)?;
    Ok(Json(value.0))
}

async fn operation(
    State(state): State<ApiState>,
    service: Service,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let value = sqlx::query_scalar::<_, Option<sqlx::types::Json<Value>>>(
        "SELECT iam_private.honeycomb_operation_status($1,$2)",
    )
    .bind(service.application_id)
    .bind(id)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| ApiError::internal("honeycomb_operation_status"))?
    .ok_or_else(ApiError::not_found)?;
    Ok(Json(value.0))
}

/// Explicit writer cutover, independent of provisioned service API credentials.
pub(crate) async fn legacy_writer_guard(
    State(state): State<ApiState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    if state
        .settings
        .honeycomb
        .as_ref()
        .is_some_and(|settings| settings.retire_legacy_writers)
        && request.method() == axum::http::Method::POST
        && request
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .is_some_and(|path| path.as_str() == "/api/v1/testing-environment/applications/imports")
    {
        return ApiError::management_moved().into_response();
    }
    if state
        .settings
        .honeycomb
        .as_ref()
        .is_some_and(|settings| settings.retire_legacy_writers)
        && !testing_plane::is_active()
        && !matches!(
            *request.method(),
            axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
        )
    {
        let route = request
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .map_or("", axum::extract::MatchedPath::as_str);
        if !route.starts_with("/api/v1/honeycomb/")
            && (matches!(
                route,
                "/api/v1/applications"
                    | "/api/v1/applications/{app_id}"
                    | "/api/v1/applications/{app_id}/client-secret-rotations"
                    | "/api/v1/applications/{app_id}/webhook-secret-rotations"
                    | "/api/v1/applications/{app_id}/webhook"
                    | "/api/v1/applications/{app_id}/webhook/approvals"
                    | "/api/v1/admin/applications/{app_id}/decisions"
                    | "/api/v1/applications/{app_id}/scope-requests"
                    | "/api/v1/application-scope-requests/{request_id}/messages"
                    | "/api/v1/application-scope-requests/{request_id}/decisions"
                    | "/api/v1/application-bundles"
                    | "/api/v1/application-bundles/{bundle_id}"
            ) || route.contains("testing-environments")
                || route == "/api/v1/testing-environment/cleanings")
        {
            return ApiError::management_moved().into_response();
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_application_or_user_credentials_never_grant_service_authority() {
        let secret = format!("hck_{}", "a".repeat(43));
        let digest = hex::encode(Sha256::digest(secret.as_bytes()));
        assert!(valid_service_credential(
            &format!("Bearer {secret}"),
            &digest
        ));
        for prefix in ["ask_", "oat_", "cat_", "sat_"] {
            assert!(!valid_service_credential(
                &format!("Bearer {prefix}{}", "a".repeat(43)),
                &digest
            ));
        }
        assert!(!valid_service_credential(
            &format!("Bearer hck_{}", "b".repeat(43)),
            &digest
        ));
    }
}
