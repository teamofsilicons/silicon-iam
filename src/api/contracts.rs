//! First official contract lifecycle and explicit major-version negotiation.
use super::ApiState;
use crate::error::AppError;
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use serde_json::{Value, json};
pub(super) async fn list(State(state): State<ApiState>) -> Result<Json<Value>, AppError> {
    let value = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.list_contract_versions()",
    )
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(value.0))
}
pub(super) async fn govern(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    let version = request
        .uri()
        .path()
        .strip_prefix("/api/")
        .and_then(|path| path.split('/').next())
        .filter(|version| super::is_valid_api_version(version));
    let Some(version) = version.map(str::to_owned) else {
        return next.run(request).await;
    };
    if let Some(advertised) = request.headers().get(super::SUPPORTED_API_VERSIONS_HEADER)
        && (advertised.to_str().is_err()
            || super::supported_versions_header(request.headers()).is_err()
            || !advertised
                .to_str()
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == version))
    {
        return (StatusCode::NOT_ACCEPTABLE,Json(json!({"error":{"code":"api_version_not_supported","message":"The path version must be included in Silicon-IAM-Supported-API-Versions."}}))).into_response();
    }
    let status = match sqlx::query_scalar::<_, Option<String>>(
        "SELECT iam_private.record_contract_request($1)",
    )
    .bind(&version)
    .fetch_one(&state.pool)
    .await
    {
        Ok(Some(status)) => status,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(json!({"error":{"code":"unknown_api_version","message":"Unknown API contract."}})),
        )
            .into_response(),
        Err(_) => {
            return AppError::Internal {
                category: "contract_registry",
            }
            .into_response();
        }
    };
    if status == "sunset" {
        return (StatusCode::GONE,Json(json!({"error":{"code":"api_version_sunset","message":"This contract has been retired. Negotiate a supported version at /api/version."}}))).into_response();
    }
    let mut response = next.run(request).await;
    if let Ok(header) = HeaderValue::from_str(&version) {
        response
            .headers_mut()
            .insert(super::SELECTED_API_VERSION_HEADER, header);
    }
    if status == "deprecated" {
        response
            .headers_mut()
            .insert("deprecation", HeaderValue::from_static("true"));
    }
    response
}
