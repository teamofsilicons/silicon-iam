//! Carbon-owned applications, authorization-code login, webhooks, and delegated OBO access.
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
        .route("/api/v1/oauth/authorize", get(oauth::authorize))
        .route(
            "/api/v1/oauth/authorize/decisions",
            post(oauth::decide_consent),
        )
        .route("/api/v1/oauth/token", post(oauth::token))
        .route("/api/v1/oauth/introspect", post(oauth::introspect))
        .route("/api/v1/oauth/revoke", post(oauth::revoke))
        .route("/api/v1/obo-access/exchanges", post(obo::exchange))
        .route("/api/v1/obo-access/verify", post(obo::verify))
        .route(
            "/api/v1/applications",
            get(applications::list).post(applications::create),
        )
        .route(
            "/api/v1/applications/{app_id}",
            get(applications::get).patch(applications::patch),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook",
            get(webhooks::get).put(webhooks::replace),
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
