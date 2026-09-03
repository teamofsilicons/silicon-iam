//! Organization-owned applications, authorization-code login, webhooks, and delegated OBO access.
#![allow(clippy::module_inception)]

mod applications;
mod cursor;
mod error;
mod events;
mod idempotency;
mod model;
mod oauth;
mod obo;
pub(crate) mod security;
mod validation;
mod webhooks;

#[cfg(test)]
mod live_tests;

use axum::{
    Router,
    routing::{get, post},
};

use crate::api::ApiState;

/// Builds the complete application, authorization-code, and OBO HTTP surface.
///
/// The root API router should merge this router so its absolute contract paths
/// remain unchanged.
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/login", get(oauth::login))
        .route("/api/v1/login/status", get(oauth::login_status))
        .route("/api/v1/app-auth/tokens", post(oauth::app_tokens))
        .route("/api/v1/oauth/introspect", post(oauth::introspect))
        .route("/api/v1/oauth/revoke", post(oauth::revoke))
        .route("/api/v1/obo-access/exchanges", post(obo::exchange))
        .route("/api/v1/obo-access/verify", post(obo::verify))
        .route(
            "/api/v1/obo-access/applications/{app_id}/endpoints",
            get(obo::discover_endpoints),
        )
        .route(
            "/api/v1/applications",
            get(applications::list).post(applications::create),
        )
        .route(
            "/api/v1/applications/{app_id}",
            get(applications::get).patch(applications::patch),
        )
        .route(
            "/api/v1/applications/{app_id}/client-secret-rotations",
            post(applications::rotate_client_secret),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook",
            get(webhooks::get).put(webhooks::replace),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook/dead-letters",
            get(webhooks::list_dead_letters),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook/dead-letters/replays",
            post(webhooks::replay_dead_letters),
        )
        .route("/api/v1/admin/applications", get(applications::admin_list))
        .route(
            "/api/v1/admin/applications/{app_id}/decisions",
            post(applications::admin_decide),
        )
        .route(
            "/api/v1/applications/{app_id}/login-history",
            get(webhooks::login_history),
        )
}
