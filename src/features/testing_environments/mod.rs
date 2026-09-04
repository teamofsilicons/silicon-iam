//! Testing environments: disposable replicas of Silicon IAM.
//!
//! An environment is an organization-owned copy of this service running against
//! a separate database, starting completely empty. Everything the product does
//! -- organizations, Carbons, Silicons, applications, tokens -- works inside
//! one, through the same routes, because an environment is a change of
//! database rather than a second implementation.
//!
//! This module owns the control plane: creating environments, holding their
//! keys, retiring and reviving them. It runs against production and is
//! deliberately not reachable from inside an environment, so an environment
//! cannot create or destroy environments.

mod handlers;
mod imports;
mod key;
mod model;
mod support;
mod validation;

pub(crate) use key::{ENVIRONMENT_KEY_HEADER, select_plane};

use axum::{
    Router,
    routing::{get, post},
};

use crate::api::ApiState;

/// Builds the testing-environment control-plane router.
pub fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/organizations/{org_id}/testing-environments",
            get(handlers::list_environments).post(handlers::create_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/testing-environments/{environment_id}",
            get(handlers::get_environment)
                .patch(handlers::update_environment)
                .delete(handlers::delete_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/testing-environments/{environment_id}/key",
            get(handlers::get_environment_key),
        )
        .route(
            "/api/v1/organizations/{org_id}/testing-environments/{environment_id}/key-rotations",
            post(handlers::rotate_environment_key),
        )
        .route(
            "/api/v1/organizations/{org_id}/testing-environments/{environment_id}/cleanings",
            post(handlers::clean_environment),
        )
        .route(
            "/api/v1/organizations/{org_id}/testing-environments/{environment_id}/restorations",
            post(handlers::restore_environment),
        )
        .route(
            "/api/v1/testing-environment",
            get(handlers::describe_current_environment),
        )
        .route(
            "/api/v1/testing-environment/cleanings",
            post(handlers::clean_current_environment),
        )
}

/// Builds routes that exist only inside an already-selected testing plane.
pub fn data_plane_router() -> Router<ApiState> {
    Router::new().route(
        "/api/v1/testing-environment/applications/imports",
        post(imports::import_application),
    )
}
