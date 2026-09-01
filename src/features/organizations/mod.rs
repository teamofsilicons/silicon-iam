//! Organization tenancy, directory, Silicon, and governance HTTP slice.

mod directory;
mod governance;
mod handlers;
mod invitations;
mod model;
mod silicons;
mod support;
mod trust;
mod validation;

use axum::{
    Router,
    routing::{get, post, put},
};

use crate::api::ApiState;

/// Builds the organization and directory feature router.
#[allow(clippy::too_many_lines)]
pub fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/organization-ids/{org_id}/availability",
            get(handlers::organization_id_availability),
        )
        .route(
            "/api/v1/organizations",
            get(handlers::list_organizations).post(handlers::create_organization),
        )
        .route(
            "/api/v1/organizations/{org_id}",
            get(handlers::get_organization).patch(handlers::update_organization),
        )
        .route(
            "/api/v1/organizations/{org_id}/ownership-transfers",
            post(handlers::transfer_ownership),
        )
        .route(
            "/api/v1/organizations/{org_id}/members",
            get(directory::list_members),
        )
        .route(
            "/api/v1/organizations/{org_id}/members/{membership_id}",
            get(directory::get_member)
                .patch(directory::update_member_directory)
                .delete(directory::remove_member),
        )
        .route(
            "/api/v1/organizations/{org_id}/members/{membership_id}/authorization",
            get(directory::get_member_authorization),
        )
        .route(
            "/api/v1/organizations/{org_id}/members/{membership_id}/admin-promotions",
            post(directory::promote_admin),
        )
        .route(
            "/api/v1/organizations/{org_id}/members/{membership_id}/admin-demotions",
            post(directory::demote_admin),
        )
        .route(
            "/api/v1/organizations/{org_id}/members/{membership_id}/capabilities",
            put(directory::replace_member_capabilities),
        )
        .route(
            "/api/v1/organizations/{org_id}/members/{membership_id}/machine-capabilities",
            put(directory::replace_machine_capabilities),
        )
        .route(
            "/api/v1/organizations/{org_id}/carbon-invites",
            get(invitations::list_invitations).post(invitations::create_invitation),
        )
        .route(
            "/api/v1/organizations/{org_id}/carbon-invites/{invite_id}",
            get(invitations::get_invitation).delete(invitations::revoke_invitation),
        )
        .route(
            "/api/v1/organizations/{org_id}/carbon-invites/{invite_id}/verification-code",
            post(invitations::send_invitation_code),
        )
        .route(
            "/api/v1/organizations/{org_id}/join",
            post(invitations::join_organization),
        )
        .route(
            "/api/v1/organizations/{org_id}/silicons",
            get(silicons::list_silicons).post(silicons::create_silicon),
        )
        .route(
            "/api/v1/organizations/{org_id}/silicons/{silicon_id}",
            get(silicons::get_silicon)
                .patch(silicons::update_silicon)
                .delete(silicons::remove_silicon),
        )
        .route(
            "/api/v1/organizations/{org_id}/silicons/{silicon_id}/iam-hook",
            get(silicons::get_silicon_hook).post(silicons::retry_silicon_hook),
        )
        .route(
            "/api/v1/organizations/{org_id}/silicons/{silicon_id}/token-rotation-requests",
            post(governance::request_silicon_token_rotation),
        )
        .route(
            "/api/v1/organizations/{org_id}/silicons/{silicon_id}/token-rotation-requests/{request_id}/complete",
            post(governance::complete_silicon_token_rotation),
        )
        .route(
            "/api/v1/organizations/{org_id}/tags",
            get(handlers::list_tags).post(handlers::create_tag),
        )
        .route(
            "/api/v1/organizations/{org_id}/tags/{tag_id}",
            get(handlers::get_tag)
                .patch(handlers::update_tag)
                .delete(handlers::delete_tag),
        )
        .route(
            "/api/v1/organizations/{org_id}/tags/{tag_id}/members",
            get(handlers::list_tag_members),
        )
        .route(
            "/api/v1/organizations/{org_id}/trust/default",
            get(trust::get_default_trust).put(trust::replace_default_trust),
        )
        .route(
            "/api/v1/organizations/{org_id}/trust/rules",
            get(trust::list_trust_rules).post(trust::create_trust_rule),
        )
        .route(
            "/api/v1/organizations/{org_id}/trust/rules/{rule_id}",
            get(trust::get_trust_rule)
                .patch(trust::update_trust_rule)
                .delete(trust::delete_trust_rule),
        )
        .route(
            "/api/v1/organizations/{org_id}/trust/effective",
            post(trust::evaluate_trust),
        )
        .route(
            "/api/v1/organizations/{org_id}/role-change-requests",
            post(governance::create_role_change_request),
        )
        .route(
            "/api/v1/organizations/{org_id}/approval-requests",
            get(governance::list_approval_requests),
        )
        .route(
            "/api/v1/organizations/{org_id}/approval-requests/{request_id}",
            get(governance::get_approval_request),
        )
        .route(
            "/api/v1/organizations/{org_id}/approval-requests/{request_id}/decisions",
            post(governance::decide_approval_request),
        )
        .route(
            "/api/v1/organizations/{org_id}/members/{membership_id}/job-role-history",
            get(governance::list_job_role_history),
        )
}
