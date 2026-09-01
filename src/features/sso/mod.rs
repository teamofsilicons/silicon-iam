//! WorkOS-backed organization SSO configuration and existing-Carbon admission.

mod authorization;
mod configuration;
mod model;
mod security;
mod support;
mod validation;
mod webhook;

use axum::{
    Router,
    routing::{get, post, put},
};

use crate::api::ApiState;

/// Builds the `WorkOS` SSO feature router.
pub(crate) fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/organizations/{org_id}/sso",
            get(configuration::get).delete(configuration::disable),
        )
        .route(
            "/api/v1/organizations/{org_id}/sso/setup-link",
            post(configuration::create_setup_link),
        )
        .route(
            "/api/v1/organizations/{org_id}/sso/policy",
            put(configuration::replace_policy),
        )
        .route(
            "/api/v1/organizations/{org_id}/sso/authorize",
            get(authorization::authorize),
        )
        .route("/api/v1/sso/callback", get(authorization::callback))
        .route(
            "/api/v1/organizations/{org_id}/sso/test",
            post(configuration::test),
        )
        .route("/api/v1/provider-webhooks/workos", post(webhook::receive))
        .route(
            "/api/v1/admin/organizations/{org_id}/sso-entitlement",
            put(configuration::replace_entitlement),
        )
}

#[cfg(test)]
mod tests {
    #[test]
    fn route_constants_are_absolute_and_versioned() {
        for route in [
            "/api/v1/organizations/{org_id}/sso",
            "/api/v1/organizations/{org_id}/sso/setup-link",
            "/api/v1/organizations/{org_id}/sso/policy",
            "/api/v1/provider-webhooks/workos",
        ] {
            assert!(route.starts_with("/api/v1/"));
        }
    }
}
