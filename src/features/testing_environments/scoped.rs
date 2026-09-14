//! Explicit delegation to create a test world, never to administer production IAM.

use super::{handlers, model::EnvironmentCreate, support, validation};
use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::ActorType,
    error::AppError,
    features::organizations::support as organizations,
    infrastructure::testing_plane,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    routing::post,
};

pub(super) const CREATE_SCOPE: &str = "organization.testing_environments.create";

pub(crate) fn router() -> Router<ApiState> {
    Router::new().route(
        "/api/v1/organizations/{org_id}/testing-environments",
        post(create),
    )
}

async fn create(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<EnvironmentCreate>,
) -> Result<Response, AppError> {
    validate_boundary(&authenticated, &org_id, &headers)?;
    support::plane(&state)?;
    validation::create(&mut input)?;
    let application_id = authenticated
        .0
        .client_application_id
        .ok_or(AppError::Forbidden)?;
    let mut scope =
        organizations::begin_scoped_organization(&state, &authenticated, &org_id, CREATE_SCOPE)
            .await?;
    // The token was authenticated normally. Install only its server-derived
    // application identity, then lock/recheck its exact live grant chain before
    // either a new mutation or recovery of an encrypted key-bearing receipt.
    sqlx::query("SELECT set_config('iam.application_id', $1, true)")
        .bind(application_id.to_string())
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let allowed = sqlx::query_scalar::<_, bool>(
        "SELECT iam_private.authorize_scoped_testing_environment_creation($1, $2)",
    )
    .bind(authenticated.0.token_id)
    .bind(scope.access.membership_id)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if !allowed {
        return Err(AppError::Forbidden);
    }
    let replay_scope = format!(
        "scoped:{}:membership:{}:app:{}:session:{}",
        scope.access.organization_id,
        scope.access.membership_id,
        application_id,
        authenticated.0.authentication_session_id,
    );
    handlers::create_in_scope(
        &state,
        &authenticated,
        &headers,
        input,
        scope,
        &replay_scope,
    )
    .await
}

pub(super) fn validate_boundary(
    actor: &Authenticated,
    org_id: &str,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    if testing_plane::is_active()
        || headers.contains_key(super::ENVIRONMENT_KEY_HEADER)
        || headers.contains_key(super::APPLICATION_HEADER)
        || actor.0.subject.actor_type != ActorType::Carbon
        || actor.0.client_application_id.is_none()
    {
        return Err(AppError::Forbidden);
    }
    organizations::require_application_scope(actor, CREATE_SCOPE)?;
    for name in ["idempotency-key", "x-org-id"] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(validation::field(
                "headers",
                "must not repeat security headers",
            ));
        }
    }
    if headers
        .get("x-org-id")
        .is_some_and(|value| value.to_str().ok() != Some(org_id))
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}
