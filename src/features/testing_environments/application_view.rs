//! Authenticate the selected test application without returning credentials.
use sha2::Digest as _;

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
    environment: EnvironmentView,
    environment_id: Uuid,
    application: ApplicationView,
    webhook_key_digest: String,
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
    let environment = sqlx::query_as::<_, EnvironmentView>(
        "SELECT * FROM iam_private.test_application_environment($1)",
    )
    .bind(environment_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(support::database)?
    .ok_or(AppError::Unauthenticated)?;
    let key = sqlx::query_as::<_, (Uuid, Vec<u8>, Vec<u8>, i16)>(
        "SELECT * FROM iam_private.get_testing_environment_obo_key($1)",
    )
    .bind(environment_id)
    .fetch_one(&state.pool)
    .await
    .map_err(support::database)?;
    let root = state
        .crypto
        .decrypt(
            crate::infrastructure::crypto::EncryptionContext::tenant(
                crate::infrastructure::crypto::ProtectedField::TestingEnvironmentKey,
                key.0,
                environment_id,
            ),
            &super::graph::encrypted(key.3, &key.2, key.1)?,
        )
        .map_err(|_| AppError::Internal {
            category: "testing_webhook_digest",
        })?;
    let webhook_key_digest = hex::encode(sha2::Sha256::digest(root.as_slice()));
    support::json(
        StatusCode::OK,
        &TestingContext {
            environment,
            environment_id,
            application,
            webhook_key_digest,
        },
        None,
    )
}

#[derive(Serialize, sqlx::FromRow)]
struct EnvironmentView {
    environment_id: Uuid,
    #[serde(skip)]
    #[sqlx(rename = "organization_id")]
    _organization_id: Uuid,
    org_id: String,
    name: String,
    description: Option<String>,
    version: i64,
    key_generation: i32,
    #[serde(with = "time::serde::rfc3339::option")]
    cleaned_at: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
    creator_type: String,
    creator_id: String,
}
