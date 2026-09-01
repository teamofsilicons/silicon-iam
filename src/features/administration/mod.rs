//! Platform administration and redacted audit APIs.

mod access;
mod audit;
mod carbons;
mod deliveries;
mod model;
mod pagination;
mod platform_admins;

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::api::ApiState;

/// Builds the platform administration and audit router.
pub(crate) fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/organizations/{org_id}/audit-events",
            get(audit::list_organization),
        )
        .route("/api/v1/admin/audit-events", get(audit::list_global))
        .route(
            "/api/v1/admin/platform-administrators",
            get(platform_admins::list).post(platform_admins::create),
        )
        .route(
            "/api/v1/admin/platform-administrators/{principal_id}",
            delete(platform_admins::remove),
        )
        .route(
            "/api/v1/admin/carbons/{carbon_id}/status",
            put(carbons::replace_status),
        )
        .route(
            "/api/v1/admin/delivery-failures",
            get(deliveries::list_failures),
        )
        .route(
            "/api/v1/admin/delivery-failures/{delivery_id}/replays",
            post(deliveries::replay),
        )
}
