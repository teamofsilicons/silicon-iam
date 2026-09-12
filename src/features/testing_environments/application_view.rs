//! Authenticate the selected test application without returning credentials.

use super::support;
use crate::{
    api::ApiState,
    error::AppError,
    features::applications::security::ApplicationClient,
    infrastructure::{
        postgres::context::{self, DatabaseContext},
        testing_plane,
    },
};
use axum::{extract::State, http::StatusCode, response::Response};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Serialize, sqlx::FromRow)]
struct ApplicationView {
    app_id: String,
    app_name: Option<String>,
    app_logo: Option<String>,
    base_url: String,
    app_scope: Value,
    webhook_scope: Vec<String>,
    testing_idle_days: i32,
}

#[derive(Serialize)]
struct TestingContext {
    environment_id: Uuid,
    application: ApplicationView,
}

pub(super) async fn get(
    State(state): State<ApiState>,
    client: ApplicationClient,
) -> Result<Response, AppError> {
    let environment_id = testing_plane::current_id().ok_or(AppError::Forbidden)?;
    let mut transaction = context::begin(
        state.db(),
        DatabaseContext {
            principal_id: Some(client.application_id),
            application_id: Some(client.application_id),
            organization_id: Some(client.organization_id),
            signup_session_id: None,
        },
    )
    .await
    .map_err(support::database)?;
    let application = sqlx::query_as::<_, ApplicationView>(
        "SELECT app_id, app_name, app_logo_uri AS app_logo, base_url, app_scope, webhook_scope, testing_idle_days FROM iam.applications WHERE id = $1 AND deleted_at IS NULL AND review_status = 'verified'"
    ).bind(client.application_id).fetch_optional(&mut *transaction).await.map_err(support::database)?.ok_or(AppError::NotFound)?;
    transaction.commit().await.map_err(support::database)?;
    support::json(
        StatusCode::OK,
        &TestingContext {
            environment_id,
            application,
        },
        None,
    )
}
