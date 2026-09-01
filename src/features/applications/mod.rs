//! Carbon-owned applications, OAuth/OIDC, webhooks, and delegated OBO access.
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
pub(crate) mod signing;
mod validation;
mod webhooks;

#[cfg(test)]
mod live_tests;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::api::ApiState;

/// Builds the complete application, OAuth/OIDC, and OBO HTTP surface.
///
/// The root API router should merge this router so its absolute contract paths
/// remain unchanged.
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(oauth::discovery))
        .route("/.well-known/jwks.json", get(oauth::jwks))
        .route("/api/v1/oauth/authorize", get(oauth::authorize))
        .route(
            "/api/v1/oauth/authorize/decisions",
            post(oauth::decide_consent),
        )
        .route("/api/v1/oauth/token", post(oauth::token))
        .route("/api/v1/oauth/introspect", post(oauth::introspect))
        .route("/api/v1/oauth/revoke", post(oauth::revoke))
        .route("/api/v1/oauth/userinfo", get(oauth::userinfo))
        .route("/api/v1/obo-access/exchanges", post(obo::exchange))
        .route("/api/v1/obo-access/verify", post(obo::verify))
        .route("/api/v1/me/application-grants", get(oauth::list_grants))
        .route(
            "/api/v1/me/application-grants/{grant_id}",
            delete(oauth::revoke_grant),
        )
        .route(
            "/api/v1/application-ids/{app_id}/availability",
            get(applications::availability),
        )
        .route(
            "/api/v1/applications",
            get(applications::list).post(applications::create),
        )
        .route(
            "/api/v1/applications/{app_id}",
            get(applications::get)
                .patch(applications::patch)
                .delete(applications::delete),
        )
        .route(
            "/api/v1/applications/{app_id}/collaborators",
            get(applications::list_collaborators).post(applications::add_collaborator),
        )
        .route(
            "/api/v1/applications/{app_id}/collaborators/{principal_id}",
            delete(applications::remove_collaborator),
        )
        .route(
            "/api/v1/applications/{app_id}/secret-rotations",
            post(applications::rotate_secret),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook",
            get(webhooks::get).put(webhooks::replace),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook/secret-rotations",
            post(webhooks::rotate_secret),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook-deliveries",
            get(webhooks::list_deliveries),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook-deliveries/{delivery_id}",
            get(webhooks::get_delivery),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook-deliveries/{delivery_id}/replays",
            post(webhooks::replay_delivery),
        )
        .route(
            "/api/v1/applications/{app_id}/login-history",
            get(webhooks::login_history),
        )
        .route("/api/v1/admin/applications", get(applications::admin_list))
        .route(
            "/api/v1/admin/applications/{app_id}/decisions",
            post(applications::admin_decide),
        )
}
