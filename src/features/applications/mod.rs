//! Organization-owned applications, authorization-code login, webhooks, and delegated OBO access.
#![allow(clippy::module_inception)]

mod applications;
mod authorization;
mod batch_login;
mod bundles;
mod cursor;
mod error;
mod events;
mod idempotency;
mod model;
mod oauth;
mod obo;
mod scope_reviews;
mod scopes;
pub(crate) mod security;
mod validation;
mod webhooks;

pub(crate) use applications::{load_detail, webhook_secret_fingerprint};
pub(crate) use model::ApplicationDetail;
pub(crate) use scopes::scoped_router;

#[cfg(test)]
mod bundle_availability_tests;
#[cfg(test)]
pub(crate) mod live_tests;
#[cfg(test)]
mod login_history_tests;
#[cfg(test)]
mod scope_catalog_tests;
#[cfg(test)]
mod scope_tests;

use axum::{
    Router,
    routing::{get, post},
};

use crate::api::ApiState;

/// Builds the complete application, authorization-code, and OBO HTTP surface.
///
/// The root API router should merge this router so its absolute contract paths
/// remain unchanged.
#[allow(
    clippy::too_many_lines,
    reason = "declarative route composition keeps the complete application contract together"
)]
pub fn router() -> Router<ApiState> {
    Router::new()
        .merge(bundle_router())
        .route("/api/v1/application-scopes", get(scopes::catalog))
        .route(
            "/api/v1/application-scope-requests",
            get(scope_reviews::list),
        )
        .route(
            "/api/v1/applications/{app_id}/scope-requests",
            post(scope_reviews::submit),
        )
        .route(
            "/api/v1/application-scope-requests/{request_id}",
            get(scope_reviews::get),
        )
        .route(
            "/api/v1/application-scope-requests/{request_id}/messages",
            post(scope_reviews::reply),
        )
        .route(
            "/api/v1/application-scope-requests/{request_id}/decisions",
            post(scope_reviews::decide),
        )
        .route("/api/v1/login", get(oauth::login))
        .route("/api/v1/login/status", get(oauth::login_status))
        .route(
            "/api/v1/app-auth/organizations",
            get(oauth::login_organizations),
        )
        .route(
            "/api/v1/app-auth/batch/organizations",
            get(batch_login::organizations),
        )
        .route(
            "/api/v1/app-auth/batch/short-lived-tokens",
            post(batch_login::issue),
        )
        .route("/api/v1/app-auth/tokens", post(oauth::app_tokens))
        .route(
            "/api/v1/app-auth/short-lived-tokens",
            post(oauth::issue_short_lived_token),
        )
        .route("/api/v1/oauth/introspect", post(oauth::introspect))
        .route("/api/v1/oauth/revoke", post(oauth::revoke))
        .route(
            "/api/v1/application-directory/{app_id}",
            get(applications::discover),
        )
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
            "/api/v1/applications/{app_id}/webhook-secret-rotations",
            post(webhooks::rotate_secret),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook",
            get(webhooks::get).put(webhooks::replace),
        )
        .route(
            "/api/v1/applications/{app_id}/webhook/approvals",
            post(webhooks::approve),
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

fn bundle_router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/organizations/{org_id}/application-bundle-availability",
            get(bundles::availability),
        )
        .route(
            "/api/v1/application-bundles",
            get(bundles::list).post(bundles::create),
        )
        .route(
            "/api/v1/application-bundles/{bundle_id}",
            get(bundles::get)
                .patch(bundles::patch)
                .delete(bundles::delete),
        )
        .route(
            "/api/v1/app-auth/bundles/{bundle_id}/organizations",
            get(bundles::organizations),
        )
        .route(
            "/api/v1/app-auth/bundles/{bundle_id}/short-lived-tokens",
            post(bundles::issue),
        )
}
