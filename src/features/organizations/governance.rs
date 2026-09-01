#![allow(clippy::too_many_lines)]

use std::{borrow::Cow, collections::BTreeSet, str::FromStr as _};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use secrecy::ExposeSecret as _;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{
        actor::ActorType,
        organization::{Capability, OrgRole},
    },
    error::AppError,
    infrastructure::{crypto::DigestPurpose, postgres::step_up::RequiredAssurance},
};

use super::{
    model::{
        ActorResponse, ApprovalDecisionCreate, ApprovalDecisionResponse, ApprovalQuery,
        ApprovalRequestPage, ApprovalRequestResponse, ApprovalRequirementsResponse,
        DirectJobRoleReplace, DirectTagSetReplace, MembershipResponse, PageInfo, PageQuery,
        RoleChangeRequestCreate, RoleHistoryPage, RoleHistoryResponse, SiliconResponse,
        SiliconTokenRotatedResponse, TagChangeRequestCreate, TagHistoryPage, TagHistoryResponse,
    },
    support::{self, Claim, MutationEvent},
    validation,
};

const ROLE_REQUEST_ROUTE: &str = "POST /api/v1/organizations/{org_id}/role-change-requests";
const TAG_REQUEST_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/members/{membership_id}/tag-change-requests";
const DIRECT_ROLE_REPLACE_ROUTE: &str =
    "PUT /api/v1/organizations/{org_id}/members/{membership_id}/job-role";
const DIRECT_TAGS_REPLACE_ROUTE: &str =
    "PUT /api/v1/organizations/{org_id}/members/{membership_id}/tags";
const APPROVAL_DECISION_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/approval-requests/{request_id}/decisions";
const ROTATION_REQUEST_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/silicons/{silicon_id}/token-rotation-requests";
const ROTATION_COMPLETE_ROUTE: &str = "POST /api/v1/organizations/{org_id}/silicons/{silicon_id}/token-rotation-requests/{request_id}/complete";

#[derive(Clone, Debug, sqlx::FromRow)]
struct ApprovalRow {
    id: Uuid,
    org_id: String,
    kind: String,
    status: String,
    requested_by_principal_id: Uuid,
    requested_by_type: String,
    requested_by_public_id: String,
    target_membership_id: Uuid,
    previous_job_role: Option<String>,
    proposed_job_role: Option<String>,
    previous_tag_ids: Option<Vec<Uuid>>,
    added_tag_ids: Option<Vec<Uuid>>,
    removed_tag_ids: Option<Vec<Uuid>>,
    proposed_tag_ids: Option<Vec<Uuid>>,
    tag_change_reason: Option<String>,
    silicon_id: Option<Uuid>,
    completed_at: Option<OffsetDateTime>,
    version: i64,
    created_at: OffsetDateTime,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct DecisionRow {
    id: Uuid,
    principal_id: Uuid,
    actor_type: String,
    public_id: String,
    decision: String,
    comment: Option<String>,
    decided_at: OffsetDateTime,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct TargetMembership {
    id: Uuid,
    principal_kind: String,
    job_role: String,
    status: String,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct DirectTargetMembership {
    principal_kind: String,
    job_role: String,
    status: String,
    version: i64,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct RequirementRow {
    id: Uuid,
    requirement_kind: String,
    specific_membership_id: Option<Uuid>,
    required_capability: Option<String>,
    quorum: i16,
}

#[derive(Clone, Debug, sqlx::FromRow)]
#[allow(clippy::struct_field_names)]
struct RotationTarget {
    silicon_id: Uuid,
    membership_id: Uuid,
    global_silicon_id: String,
    credential_id: Uuid,
}

struct RotationInvalidation {
    membership_id: Uuid,
    before_member: MembershipResponse,
    before_silicon: SiliconResponse,
}

struct AppliedSiliconProjection {
    membership_id: Uuid,
    before: SiliconResponse,
    action: &'static str,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct RoleHistoryRow {
    id: Uuid,
    membership_id: Uuid,
    old_job_role: String,
    new_job_role: String,
    approval_request_id: Option<Uuid>,
    requested_by_principal_id: Uuid,
    requested_by_type: String,
    requested_by_public_id: String,
    applied_at: OffsetDateTime,
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct TagHistoryRow {
    id: Uuid,
    membership_id: Uuid,
    previous_tag_ids: Vec<Uuid>,
    applied_tag_ids: Vec<Uuid>,
    approval_request_id: Option<Uuid>,
    membership_version: i64,
    requested_by_principal_id: Uuid,
    requested_by_type: String,
    requested_by_public_id: String,
    applied_at: OffsetDateTime,
}

#[derive(Debug, sqlx::FromRow)]
struct AppliedTagChange {
    applied_membership_id: Uuid,
    previous_tags: Vec<Uuid>,
    applied_tags: Vec<Uuid>,
    resulting_membership_version: i64,
}

#[derive(Serialize)]
struct TagChangeClaim<'a> {
    target_membership_id: Uuid,
    add_tag_ids: &'a [Uuid],
    remove_tag_ids: &'a [Uuid],
    reason: Option<&'a str>,
}

pub(super) async fn create_role_change_request(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<RoleChangeRequestCreate>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    input.proposed_job_role = validation::job_role(std::mem::take(&mut input.proposed_job_role))?;
    input.reason = input
        .reason
        .take()
        .map(|value| validation::bounded_text("reason", value, 0, 2_000, true))
        .transpose()?;
    require_silicon_governance_request(authenticated.0.subject.actor_type)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        ROLE_REQUEST_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let target = fetch_target(
        &mut scope.transaction,
        scope.access.organization_id,
        input.target_membership_id,
    )
    .await?;
    if target.status != "active" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("membership_not_active"),
        });
    }
    if target.job_role == input.proposed_job_role {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("job_role_unchanged"),
        });
    }
    let request_id = Uuid::now_v7();
    let is_carbon = target.principal_kind == "carbon";
    sqlx::query(
        r"
        INSERT INTO iam.approval_requests (
            id, organization_id, request_kind, requested_by_membership_id,
            minimum_distinct_approvers
        ) VALUES ($1, $2, $3, $4, $5)
        ",
    )
    .bind(request_id)
    .bind(scope.access.organization_id)
    .bind(if is_carbon {
        "carbon_job_role_change"
    } else {
        "silicon_job_role_change"
    })
    .bind(scope.access.membership_id)
    .bind(if is_carbon { 2_i16 } else { 1_i16 })
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.job_role_change_requests (
            approval_request_id, organization_id, target_membership_id,
            target_principal_kind, previous_job_role, proposed_job_role
        ) VALUES ($1, $2, $3, $4::iam.principal_kind, $5, $6)
        ",
    )
    .bind(request_id)
    .bind(scope.access.organization_id)
    .bind(target.id)
    .bind(&target.principal_kind)
    .bind(&target.job_role)
    .bind(&input.proposed_job_role)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if is_carbon {
        insert_requirement(
            &mut scope.transaction,
            scope.access.organization_id,
            request_id,
            "specific_membership",
            Some(target.id),
            None,
        )
        .await?;
    }
    insert_requirement(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
        "current_owner_or_admin",
        None,
        Some("roles.approve"),
    )
    .await?;
    let approval = fetch_approval(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
    )
    .await?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "role_change.requested",
            target_type: "approval_request",
            target_id: request_id,
            aggregate_type: "approval_request",
            aggregate_id: request_id,
            aggregate_version: approval.version,
            event_type: "organization.role_change.requested.v1",
            before_state: None,
            after_state: Some(approval.immutable_payload.clone()),
            metadata: json!({
                "approval_request_id": request_id,
                "target_membership_id": target.id,
                "reason_present": input.reason.is_some(),
            }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &approval,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, Some(approval.version), false)
}

fn require_silicon_governance_request(actor_type: ActorType) -> Result<(), AppError> {
    if actor_type == ActorType::Silicon {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub(super) async fn replace_member_job_role(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(mut input): Json<DirectJobRoleReplace>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    input.job_role = validation::job_role(std::mem::take(&mut input.job_role))?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    require_direct_governance_control(&authenticated, &scope.access, Capability::RolesApprove)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        DIRECT_ROLE_REPLACE_ROUTE,
        &membership_id.to_string(),
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let target = lock_direct_target(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    require_direct_target_version(&target, expected_version)?;
    if target.job_role == input.job_role {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("job_role_unchanged"),
        });
    }
    if target.principal_kind == "silicon" {
        lock_silicon_projection(
            &mut scope.transaction,
            scope.access.organization_id,
            membership_id,
        )
        .await?;
    }
    let before_member = super::directory::fetch_member(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    let before_silicon = fetch_silicon_projection(
        &mut scope.transaction,
        &state,
        scope.access.organization_id,
        membership_id,
        target.principal_kind == "silicon",
    )
    .await?;
    let _membership_version = sqlx::query_scalar::<_, i64>(
        r"
        SELECT iam_private.replace_membership_job_role_direct(
            $1, $2, $3, $4, $5, $6
        )
        ",
    )
    .bind(scope.access.organization_id)
    .bind(membership_id)
    .bind(scope.access.membership_id)
    .bind(Uuid::now_v7())
    .bind(expected_version)
    .bind(&input.job_role)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    touch_direct_silicon_projection(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        target.principal_kind == "silicon",
    )
    .await?;
    let member = super::directory::fetch_member(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    super::directory::record_member_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        "membership.job_role_replaced",
        "organization.membership.updated.v1",
        &before_member,
        &member,
    )
    .await?;
    record_direct_silicon_projection(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        membership_id,
        before_silicon,
        "silicon.job_role_replaced",
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &member,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(member.version), false)
}

pub(super) async fn replace_member_tags(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(mut input): Json<DirectTagSetReplace>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validation::direct_tag_set(&mut input)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    require_direct_governance_control(&authenticated, &scope.access, Capability::TagsManage)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        DIRECT_TAGS_REPLACE_ROUTE,
        &membership_id.to_string(),
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let target = lock_direct_target(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    require_direct_target_version(&target, expected_version)?;
    let previous_tag_ids = membership_tag_ids(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    if previous_tag_ids == input.tag_ids {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("tag_set_unchanged"),
        });
    }
    validate_active_tag_ids(
        &mut scope.transaction,
        scope.access.organization_id,
        &input.tag_ids,
    )
    .await?;
    if target.principal_kind == "silicon" {
        lock_silicon_projection(
            &mut scope.transaction,
            scope.access.organization_id,
            membership_id,
        )
        .await?;
    }
    let before_member = super::directory::fetch_member(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    let before_silicon = fetch_silicon_projection(
        &mut scope.transaction,
        &state,
        scope.access.organization_id,
        membership_id,
        target.principal_kind == "silicon",
    )
    .await?;
    let _membership_version = sqlx::query_scalar::<_, i64>(
        r"
        SELECT iam_private.replace_membership_tags_direct(
            $1, $2, $3, $4, $5, $6
        )
        ",
    )
    .bind(scope.access.organization_id)
    .bind(membership_id)
    .bind(scope.access.membership_id)
    .bind(Uuid::now_v7())
    .bind(expected_version)
    .bind(&input.tag_ids)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    touch_direct_silicon_projection(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        target.principal_kind == "silicon",
    )
    .await?;
    let member = super::directory::fetch_member(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    super::directory::record_member_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        "membership.tags_replaced",
        "organization.membership.updated.v1",
        &before_member,
        &member,
    )
    .await?;
    record_direct_silicon_projection(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        membership_id,
        before_silicon,
        "silicon.tags_replaced",
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &member,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(member.version), false)
}

fn require_direct_governance_control(
    authenticated: &Authenticated,
    access: &crate::infrastructure::postgres::authorization::OrganizationAccess,
    capability: Capability,
) -> Result<(), AppError> {
    support::require_carbon(authenticated)?;
    if !matches!(access.authority.org_role, OrgRole::Owner | OrgRole::Admin) {
        return Err(AppError::Forbidden);
    }
    support::require_capability(access, capability)
}

pub(super) async fn create_tag_change_request(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(mut input): Json<TagChangeRequestCreate>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validation::tag_change_request(&mut input)?;
    require_silicon_governance_request(authenticated.0.subject.actor_type)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let claim = TagChangeClaim {
        target_membership_id: membership_id,
        add_tag_ids: &input.add_tag_ids,
        remove_tag_ids: &input.remove_tag_ids,
        reason: input.reason.as_deref(),
    };
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        TAG_REQUEST_ROUTE,
        &membership_id.to_string(),
        &claim,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let target = fetch_target(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    if target.status != "active" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("membership_not_active"),
        });
    }
    if !matches!(target.principal_kind.as_str(), "carbon" | "silicon") {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("tag_change_target_ineligible"),
        });
    }

    let previous_tag_ids = membership_tag_ids(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    let mut proposed_tag_ids = previous_tag_ids.iter().copied().collect::<BTreeSet<_>>();
    for tag_id in &input.remove_tag_ids {
        if !proposed_tag_ids.remove(tag_id) {
            return Err(AppError::Conflict {
                code: Cow::Borrowed("tag_change_not_applicable"),
            });
        }
    }
    for tag_id in &input.add_tag_ids {
        if !proposed_tag_ids.insert(*tag_id) {
            return Err(AppError::Conflict {
                code: Cow::Borrowed("tag_change_not_applicable"),
            });
        }
    }
    if proposed_tag_ids.len() > 100 {
        return Err(validation::field(
            "add_tag_ids",
            "would exceed the membership tag limit",
        ));
    }
    let proposed_tag_ids = proposed_tag_ids.into_iter().collect::<Vec<_>>();
    validate_active_tag_ids(
        &mut scope.transaction,
        scope.access.organization_id,
        &proposed_tag_ids,
    )
    .await?;

    let request_id = Uuid::now_v7();
    let is_carbon = target.principal_kind == "carbon";
    sqlx::query(
        r"
        INSERT INTO iam.approval_requests (
            id, organization_id, request_kind, requested_by_membership_id,
            minimum_distinct_approvers
        ) VALUES ($1, $2, $3, $4, $5)
        ",
    )
    .bind(request_id)
    .bind(scope.access.organization_id)
    .bind(if is_carbon {
        "carbon_tag_change"
    } else {
        "silicon_tag_change"
    })
    .bind(scope.access.membership_id)
    .bind(if is_carbon { 2_i16 } else { 1_i16 })
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.tag_change_requests (
            approval_request_id, organization_id, target_membership_id,
            target_principal_kind, previous_tag_ids, added_tag_ids,
            removed_tag_ids, proposed_tag_ids, reason
        ) VALUES ($1, $2, $3, $4::iam.principal_kind, $5, $6, $7, $8, $9)
        ",
    )
    .bind(request_id)
    .bind(scope.access.organization_id)
    .bind(membership_id)
    .bind(&target.principal_kind)
    .bind(&previous_tag_ids)
    .bind(&input.add_tag_ids)
    .bind(&input.remove_tag_ids)
    .bind(&proposed_tag_ids)
    .bind(&input.reason)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if is_carbon {
        insert_requirement(
            &mut scope.transaction,
            scope.access.organization_id,
            request_id,
            "specific_membership",
            Some(membership_id),
            None,
        )
        .await?;
    }
    insert_requirement(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
        "current_owner_or_admin",
        None,
        Some("tags.manage"),
    )
    .await?;
    let approval = fetch_approval(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
    )
    .await?;
    let affected_tag_ids = previous_tag_ids
        .iter()
        .chain(&proposed_tag_ids)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "tag_change.requested",
            target_type: "approval_request",
            target_id: request_id,
            aggregate_type: "approval_request",
            aggregate_id: request_id,
            aggregate_version: approval.version,
            event_type: "organization.tag_change.requested.v1",
            before_state: None,
            after_state: Some(approval.immutable_payload.clone()),
            metadata: json!({
                "approval_request_id": request_id,
                "target_membership_id": membership_id,
                "tag_ids": affected_tag_ids,
                "reason_present": input.reason.is_some(),
            }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &approval,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, Some(approval.version), false)
}

pub(super) async fn list_approval_requests(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<ApprovalQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_approval_filters(&query)?;
    let (cursor, limit) = validation::page_parts(query.cursor.as_deref(), query.limit)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let rows = sqlx::query_as::<_, ApprovalRow>(APPROVAL_LIST_SQL)
        .bind(scope.access.organization_id)
        .bind(cursor)
        .bind(limit + 1)
        .bind(query.status.as_deref())
        .bind(query.kind.as_deref())
        .bind(query.actionable_by_me.unwrap_or(false))
        .bind(scope.access.membership_id)
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let mut items = materialize_approvals(&mut scope.transaction, rows).await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_approval_page(&mut items, limit)?;
    support::json(StatusCode::OK, &ApprovalRequestPage { items, page }, None)
}

pub(super) async fn get_approval_request(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, request_id)): Path<(String, Uuid)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let approval = fetch_approval(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &approval, Some(approval.version))
}

pub(super) async fn decide_approval_request(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, request_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(mut input): Json<ApprovalDecisionCreate>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    if !matches!(input.decision.as_str(), "approve" | "reject") {
        return Err(validation::field("decision", "must be approve or reject"));
    }
    input.comment = input
        .comment
        .take()
        .map(|value| validation::bounded_text("comment", value, 0, 2_000, true))
        .transpose()?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        APPROVAL_DECISION_ROUTE,
        &request_id.to_string(),
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let approval = fetch_approval(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
    )
    .await?;
    if approval.version != expected_version {
        return Err(precondition_failed());
    }
    if approval.status != "pending" {
        return Err(AppError::Gone {
            code: Cow::Borrowed("approval_request_closed"),
        });
    }
    let requirement = eligible_requirement(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
        scope.access.membership_id,
        &scope.access.authority,
    )
    .await?;
    let step_up_assertion_id = if approval.kind == "silicon_token_rotation" {
        let silicon_id = approval
            .immutable_payload
            .get("silicon_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(AppError::Internal {
                category: "rotation_approval_payload",
            })?;
        Some(
            support::consume_step_up(
                &mut scope.transaction,
                &state,
                &authenticated,
                &headers,
                "silicon.rotate_token",
                Some(silicon_id),
                RequiredAssurance::VerifiedChannel,
            )
            .await?,
        )
    } else {
        None
    };
    sqlx::query(
        r"
        INSERT INTO iam.approval_decisions (
            id, organization_id, approval_request_id, approval_requirement_id,
            decided_by_membership_id, decision, eligibility_snapshot, step_up_assertion_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(scope.access.organization_id)
    .bind(request_id)
    .bind(requirement.id)
    .bind(scope.access.membership_id)
    .bind(&input.decision)
    .bind(json!({
        "org_role": format!("{:?}", scope.access.authority.org_role).to_ascii_lowercase(),
        "requirement_kind": requirement.requirement_kind,
        "required_capability": requirement.required_capability,
        "comment": input.comment,
    }))
    .bind(step_up_assertion_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "approval_already_decided"))?;

    let mut applied_role_change = None;
    let mut applied_tag_change = None;
    let mut applied_silicon_projection = None;
    let mut invalidated_rotation = None;
    if input.decision == "reject" {
        update_approval_status(
            &mut scope.transaction,
            scope.access.organization_id,
            request_id,
            expected_version,
            "rejected",
        )
        .await?;
    } else if requirements_satisfied(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
    )
    .await?
    {
        match approval.kind.as_str() {
            "carbon_job_role_change" | "silicon_job_role_change" => {
                let target_membership_id = approval.target_membership_id;
                let before_silicon = capture_approved_silicon_projection(
                    &mut scope.transaction,
                    &state,
                    scope.access.organization_id,
                    target_membership_id,
                    &approval.kind,
                )
                .await?;
                let applied = apply_job_role_change(
                    &mut scope.transaction,
                    scope.access.organization_id,
                    request_id,
                    expected_version,
                )
                .await?;
                if applied.0 != target_membership_id {
                    return Err(AppError::Internal {
                        category: "role_change_target",
                    });
                }
                if let Some((before, action)) = before_silicon {
                    touch_direct_silicon_projection(
                        &mut scope.transaction,
                        scope.access.organization_id,
                        target_membership_id,
                        true,
                    )
                    .await?;
                    applied_silicon_projection = Some(AppliedSiliconProjection {
                        membership_id: target_membership_id,
                        before,
                        action,
                    });
                }
                applied_role_change = Some(applied);
            }
            "carbon_tag_change" | "silicon_tag_change" => {
                let target_membership_id = approval.target_membership_id;
                let before_silicon = capture_approved_silicon_projection(
                    &mut scope.transaction,
                    &state,
                    scope.access.organization_id,
                    target_membership_id,
                    &approval.kind,
                )
                .await?;
                let applied = sqlx::query_as::<_, AppliedTagChange>(
                    "SELECT * FROM iam_private.apply_approved_tag_change($1, $2, $3)",
                )
                .bind(scope.access.organization_id)
                .bind(request_id)
                .bind(expected_version)
                .fetch_one(&mut *scope.transaction)
                .await
                .map_err(map_tag_change_apply_error)?;
                if applied.applied_membership_id != target_membership_id {
                    return Err(AppError::Internal {
                        category: "tag_change_target",
                    });
                }
                if let Some((before, action)) = before_silicon {
                    touch_direct_silicon_projection(
                        &mut scope.transaction,
                        scope.access.organization_id,
                        target_membership_id,
                        true,
                    )
                    .await?;
                    applied_silicon_projection = Some(AppliedSiliconProjection {
                        membership_id: target_membership_id,
                        before,
                        action,
                    });
                }
                applied_tag_change = Some(applied);
            }
            "silicon_token_rotation" => {
                let target = lock_rotation_target_for_approval(
                    &mut scope.transaction,
                    scope.access.organization_id,
                    request_id,
                )
                .await?;
                let before_member = super::directory::fetch_member(
                    &mut scope.transaction,
                    scope.access.organization_id,
                    target.membership_id,
                )
                .await?;
                let before_silicon = fetch_silicon_projection(
                    &mut scope.transaction,
                    &state,
                    scope.access.organization_id,
                    target.membership_id,
                    true,
                )
                .await?
                .ok_or(AppError::NotFound)?;
                update_approval_status(
                    &mut scope.transaction,
                    scope.access.organization_id,
                    request_id,
                    expected_version,
                    "approved",
                )
                .await?;
                invalidate_rotation_credential(
                    &mut scope.transaction,
                    scope.access.organization_id,
                    request_id,
                    &target,
                )
                .await?;
                invalidated_rotation = Some(RotationInvalidation {
                    membership_id: target.membership_id,
                    before_member,
                    before_silicon,
                });
            }
            _ => {
                update_approval_status(
                    &mut scope.transaction,
                    scope.access.organization_id,
                    request_id,
                    expected_version,
                    "approved",
                )
                .await?;
            }
        }
    } else {
        let bumped = sqlx::query(
            "UPDATE iam.approval_requests SET updated_at = transaction_timestamp() WHERE organization_id = $1 AND id = $2 AND version = $3 AND status = 'pending'",
        )
        .bind(scope.access.organization_id)
        .bind(request_id)
        .bind(expected_version)
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
        if bumped.rows_affected() != 1 {
            return Err(precondition_failed());
        }
    }
    let result = fetch_approval(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
    )
    .await?;
    if let Some((membership_id, previous_job_role, job_role, membership_version)) =
        applied_role_change
    {
        support::record_application_mutation(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            MutationEvent {
                action: "membership.job_role_updated",
                target_type: "organization_membership",
                target_id: membership_id,
                aggregate_type: "organization_membership",
                aggregate_id: membership_id,
                aggregate_version: membership_version,
                event_type: "organization.membership.updated.v1",
                before_state: Some(json!({
                    "job_role": previous_job_role,
                    "version": membership_version - 1,
                })),
                after_state: Some(json!({
                    "job_role": job_role,
                    "version": membership_version,
                })),
                metadata: json!({
                    "membership_id": membership_id,
                    "approval_request_id": request_id,
                    "changed_fields": ["job_role"],
                }),
            },
        )
        .await?;
    }
    if let Some(applied) = applied_tag_change {
        support::record_application_mutation(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            MutationEvent {
                action: "membership.tags_updated",
                target_type: "organization_membership",
                target_id: applied.applied_membership_id,
                aggregate_type: "organization_membership",
                aggregate_id: applied.applied_membership_id,
                aggregate_version: applied.resulting_membership_version,
                event_type: "organization.membership.updated.v1",
                before_state: Some(json!({
                    "tag_ids": applied.previous_tags,
                    "version": applied.resulting_membership_version - 1,
                })),
                after_state: Some(json!({
                    "tag_ids": applied.applied_tags,
                    "version": applied.resulting_membership_version,
                })),
                metadata: json!({
                    "membership_id": applied.applied_membership_id,
                    "approval_request_id": request_id,
                    "changed_fields": ["tags"],
                }),
            },
        )
        .await?;
    }
    if let Some(projection) = applied_silicon_projection {
        record_direct_silicon_projection(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            projection.membership_id,
            Some(projection.before),
            projection.action,
        )
        .await?;
    }
    if let Some(invalidation) = invalidated_rotation {
        let after_member = super::directory::fetch_member(
            &mut scope.transaction,
            scope.access.organization_id,
            invalidation.membership_id,
        )
        .await?;
        super::directory::record_member_mutation(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            "membership.silicon_credential_invalidated",
            "organization.membership.updated.v1",
            &invalidation.before_member,
            &after_member,
        )
        .await?;
        record_direct_silicon_projection(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            invalidation.membership_id,
            Some(invalidation.before_silicon),
            "silicon.credential_invalidated",
        )
        .await?;
    }
    let approval_tag_ids = approval_payload_tag_ids(&approval.immutable_payload);
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "approval.decided",
            target_type: "approval_request",
            target_id: request_id,
            aggregate_type: "approval_request",
            aggregate_id: request_id,
            aggregate_version: result.version,
            event_type: "organization.approval.decided.v1",
            before_state: Some(json!({ "status": approval.status, "version": approval.version })),
            after_state: Some(json!({ "status": result.status, "version": result.version })),
            metadata: json!({
                "approval_request_id": request_id,
                "decision": input.decision,
                "target_membership_id": approval.target_membership_id,
                "tag_ids": approval_tag_ids,
            }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &result,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(result.version), false)
}

pub(super) async fn list_job_role_history(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (cursor, limit) = validation::page(&query)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    fetch_target(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    let rows = sqlx::query_as::<_, RoleHistoryRow>(ROLE_HISTORY_SQL)
        .bind(scope.access.organization_id)
        .bind(membership_id)
        .bind(cursor)
        .bind(limit + 1)
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let approvers = match row.approval_request_id {
            Some(request_id) => decision_actors(&mut scope.transaction, request_id).await?,
            None => Vec::new(),
        };
        items.push(RoleHistoryResponse {
            id: row.id,
            membership_id: row.membership_id,
            old_job_role: row.old_job_role,
            new_job_role: row.new_job_role,
            requested_by: ActorResponse {
                principal_id: row.requested_by_principal_id,
                actor_type: row.requested_by_type,
                public_id: row.requested_by_public_id,
            },
            approvers,
            approval_request_id: row.approval_request_id,
            applied_at: row.applied_at,
        });
    }
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_history_page(&mut items, limit)?;
    support::json(StatusCode::OK, &RoleHistoryPage { items, page }, None)
}

pub(super) async fn list_tag_history(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (cursor, limit) = validation::page(&query)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let target = fetch_target(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    if !matches!(target.principal_kind.as_str(), "carbon" | "silicon") {
        return Err(AppError::NotFound);
    }
    let rows = sqlx::query_as::<_, TagHistoryRow>(TAG_HISTORY_SQL)
        .bind(scope.access.organization_id)
        .bind(membership_id)
        .bind(cursor)
        .bind(limit + 1)
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let approvers = match row.approval_request_id {
            Some(request_id) => decision_actors(&mut scope.transaction, request_id).await?,
            None => Vec::new(),
        };
        items.push(TagHistoryResponse {
            id: row.id,
            membership_id: row.membership_id,
            previous_tag_ids: row.previous_tag_ids,
            applied_tag_ids: row.applied_tag_ids,
            requested_by: ActorResponse {
                principal_id: row.requested_by_principal_id,
                actor_type: row.requested_by_type,
                public_id: row.requested_by_public_id,
            },
            approvers,
            approval_request_id: row.approval_request_id,
            membership_version: row.membership_version,
            applied_at: row.applied_at,
        });
    }
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_tag_history_page(&mut items, limit)?;
    support::json(StatusCode::OK, &TagHistoryPage { items, page }, None)
}

pub(super) async fn request_silicon_token_rotation(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_handle)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon(&silicon_handle, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::SiliconsRotateToken)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        ROTATION_REQUEST_ROUTE,
        &silicon_handle,
        &json!({ "operation": "request" }),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let target = fetch_rotation_target(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_handle,
    )
    .await?;
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "silicon.rotate_token",
        Some(target.silicon_id),
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let pending = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1 FROM iam.silicon_token_rotation_requests rotation
            JOIN iam.approval_requests request ON request.id = rotation.approval_request_id
            WHERE rotation.organization_id = $1 AND rotation.silicon_id = $2
              AND request.status IN ('pending', 'approved')
        )
        ",
    )
    .bind(scope.access.organization_id)
    .bind(target.silicon_id)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if pending {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("rotation_already_pending"),
        });
    }
    let request_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.approval_requests (
            id, organization_id, request_kind, requested_by_membership_id,
            minimum_distinct_approvers
        ) VALUES ($1, $2, 'silicon_token_rotation', $3, 1)
        ",
    )
    .bind(request_id)
    .bind(scope.access.organization_id)
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.silicon_token_rotation_requests (
            approval_request_id, organization_id, silicon_id, previous_credential_id
        ) VALUES ($1, $2, $3, $4)
        ",
    )
    .bind(request_id)
    .bind(scope.access.organization_id)
    .bind(target.silicon_id)
    .bind(target.credential_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    insert_requirement(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
        "current_owner",
        None,
        None,
    )
    .await?;
    let approval = fetch_approval(
        &mut scope.transaction,
        scope.access.organization_id,
        request_id,
    )
    .await?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "silicon.rotation_requested",
            target_type: "approval_request",
            target_id: request_id,
            aggregate_type: "approval_request",
            aggregate_id: request_id,
            aggregate_version: approval.version,
            event_type: "organization.silicon.rotation_requested.v1",
            before_state: None,
            after_state: Some(json!({ "silicon_id": target.silicon_id })),
            metadata: json!({
                "approval_request_id": request_id,
                "silicon_id": target.silicon_id,
                "target_membership_id": target.membership_id,
            }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &approval,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, Some(approval.version), false)
}

pub(super) async fn complete_silicon_token_rotation(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_handle, request_id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon(&silicon_handle, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::SiliconsRotateToken)?;
    let resource_scope = format!("{silicon_handle}:{request_id}");
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        ROTATION_COMPLETE_ROUTE,
        &resource_scope,
        &json!({ "operation": "complete" }),
        true,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let target = fetch_rotation_target_for_request(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_handle,
        request_id,
    )
    .await?;
    super::silicons::lock_hierarchy_subtree(
        &mut scope.transaction,
        scope.access.organization_id,
        target.membership_id,
        false,
    )
    .await?;
    let before_member = super::directory::fetch_member(
        &mut scope.transaction,
        scope.access.organization_id,
        target.membership_id,
    )
    .await?;
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "silicon.rotate_token",
        Some(target.silicon_id),
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let ready = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1 FROM iam.silicon_token_rotation_requests rotation
            JOIN iam.approval_requests request ON request.id = rotation.approval_request_id
            WHERE rotation.organization_id = $1 AND rotation.approval_request_id = $2
              AND rotation.silicon_id = $3 AND rotation.fulfillment_status = 'ready'
              AND request.status = 'approved'
        )
        ",
    )
    .bind(scope.access.organization_id)
    .bind(request_id)
    .bind(target.silicon_id)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if !ready {
        return Err(AppError::Gone {
            code: Cow::Borrowed("rotation_not_ready"),
        });
    }
    let token = state
        .crypto
        .generate_silicon_token()
        .map_err(|_| AppError::Internal {
            category: "silicon_rotation_token_generate",
        })?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::SiliconCredential, &token)
        .map_err(|_| AppError::Internal {
            category: "silicon_rotation_token_digest",
        })?;
    let replacement_id = Uuid::now_v7();
    let prefix = token.expose_secret().get(..12).ok_or(AppError::Internal {
        category: "silicon_rotation_prefix",
    })?;
    sqlx::query(
        "UPDATE iam.silicon_credentials SET status = 'retired', retired_at = transaction_timestamp() WHERE id = $1 AND silicon_id = $2 AND status = 'active'",
    )
    .bind(target.credential_id)
    .bind(target.silicon_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.silicon_credentials (
            id, organization_id, silicon_id, credential_prefix, secret_digest,
            pepper_key_version, created_by_membership_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(replacement_id)
    .bind(scope.access.organization_id)
    .bind(target.silicon_id)
    .bind(prefix)
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        UPDATE iam.silicon_token_rotation_requests
        SET replacement_credential_id = $3, fulfillment_status = 'completed',
            fulfilled_at = transaction_timestamp()
        WHERE organization_id = $1 AND approval_request_id = $2 AND fulfillment_status = 'ready'
        ",
    )
    .bind(scope.access.organization_id)
    .bind(request_id)
    .bind(replacement_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        UPDATE iam.approval_requests
        SET status = 'applied', applied_at = transaction_timestamp()
        WHERE organization_id = $1 AND id = $2 AND status = 'approved'
        ",
    )
    .bind(scope.access.organization_id)
    .bind(request_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.silicon_credential_history (
            id, organization_id, silicon_id, approval_request_id,
            previous_credential_id, replacement_credential_id
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(scope.access.organization_id)
    .bind(target.silicon_id)
    .bind(request_id)
    .bind(target.credential_id)
    .bind(replacement_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query("UPDATE iam.principals SET auth_epoch = auth_epoch + 1 WHERE id = $1")
        .bind(target.silicon_id)
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    sqlx::query(
        "UPDATE iam.organization_memberships SET authz_epoch = authz_epoch + 1 WHERE organization_id = $1 AND id = $2 AND status = 'active'",
    )
    .bind(scope.access.organization_id)
    .bind(target.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    let silicon_version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.silicons
        SET updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND id = $2 AND provisioning_status <> 'deleted'
        RETURNING version
        ",
    )
    .bind(scope.access.organization_id)
    .bind(target.silicon_id)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    revoke_silicon_sessions(&mut scope.transaction, target.silicon_id).await?;
    let credential_version = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.silicon_credentials WHERE silicon_id = $1",
    )
    .bind(target.silicon_id)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    let response = SiliconTokenRotatedResponse {
        silicon_id: target.global_silicon_id,
        credential_version,
        silicon_token: token.expose_secret().to_owned(),
        secret_replay_expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
    };
    support::record_application_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "silicon.credential_rotated",
            target_type: "silicon",
            target_id: target.silicon_id,
            aggregate_type: "silicon",
            aggregate_id: target.silicon_id,
            aggregate_version: silicon_version,
            event_type: "organization.silicon.credential_rotated.v1",
            before_state: None,
            after_state: Some(json!({
                "credential_version": credential_version,
                "version": silicon_version,
            })),
            metadata: json!({
                "silicon_id": target.silicon_id,
                "target_membership_id": target.membership_id,
                "approval_request_id": request_id,
            }),
        },
    )
    .await?;
    let after_member = super::directory::fetch_member(
        &mut scope.transaction,
        scope.access.organization_id,
        target.membership_id,
    )
    .await?;
    super::directory::record_member_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        "membership.silicon_credential_rotated",
        "organization.membership.updated.v1",
        &before_member,
        &after_member,
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &response,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, None, true)
}

async fn lock_direct_target(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
) -> Result<DirectTargetMembership, AppError> {
    sqlx::query_as::<_, DirectTargetMembership>(
        r"
        SELECT principal_kind::text AS principal_kind, job_role, status, version
        FROM iam.organization_memberships
        WHERE organization_id = $1 AND id = $2
        FOR UPDATE
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

fn require_direct_target_version(
    target: &DirectTargetMembership,
    expected_version: i64,
) -> Result<(), AppError> {
    if target.status != "active" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("membership_not_active"),
        });
    }
    if target.version != expected_version {
        return Err(precondition_failed());
    }
    Ok(())
}

async fn lock_silicon_projection(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM iam.silicons
        WHERE organization_id = $1 AND membership_id = $2
          AND provisioning_status <> 'deleted'
        FOR UPDATE
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    Ok(())
}

async fn capture_approved_silicon_projection(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    organization_id: Uuid,
    membership_id: Uuid,
    approval_kind: &str,
) -> Result<Option<(SiliconResponse, &'static str)>, AppError> {
    let Some(action) = approved_silicon_projection_action(approval_kind) else {
        return Ok(None);
    };
    let target = lock_direct_target(transaction, organization_id, membership_id).await?;
    if target.principal_kind != "silicon" {
        return Err(AppError::Internal {
            category: "silicon_approval_target_kind",
        });
    }
    lock_silicon_projection(transaction, organization_id, membership_id).await?;
    let before = fetch_silicon_projection(transaction, state, organization_id, membership_id, true)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Some((before, action)))
}

fn approved_silicon_projection_action(approval_kind: &str) -> Option<&'static str> {
    match approval_kind {
        "silicon_job_role_change" => Some("silicon.job_role_change_approved"),
        "silicon_tag_change" => Some("silicon.tag_change_approved"),
        _ => None,
    }
}

async fn fetch_silicon_projection(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    organization_id: Uuid,
    membership_id: Uuid,
    enabled: bool,
) -> Result<Option<SiliconResponse>, AppError> {
    if !enabled {
        return Ok(None);
    }
    let profile_base = super::silicons::silicon_profile_base(state)?;
    let mut silicons = super::silicons::fetch_silicons(
        transaction,
        organization_id,
        &[membership_id],
        &profile_base,
    )
    .await?;
    silicons.pop().map(Some).ok_or(AppError::NotFound)
}

async fn touch_direct_silicon_projection(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    enabled: bool,
) -> Result<(), AppError> {
    if !enabled {
        return Ok(());
    }
    let result = sqlx::query(
        r"
        UPDATE iam.silicons
        SET updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND membership_id = $2
          AND provisioning_status <> 'deleted'
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    if result.rows_affected() != 1 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the direct control event keeps its exact actor, tenant, and projection explicit"
)]
async fn record_direct_silicon_projection(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    organization_id: Uuid,
    membership_id: Uuid,
    before: Option<SiliconResponse>,
    action: &'static str,
) -> Result<(), AppError> {
    let Some(before) = before else {
        return Ok(());
    };
    let after = fetch_silicon_projection(transaction, state, organization_id, membership_id, true)
        .await?
        .ok_or(AppError::NotFound)?;
    super::silicons::record_silicon_change(
        transaction,
        state,
        authenticated,
        organization_id,
        action,
        "organization.silicon.updated.v1",
        &before,
        &after,
    )
    .await
}

async fn fetch_target(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
) -> Result<TargetMembership, AppError> {
    sqlx::query_as::<_, TargetMembership>(
        "SELECT id, principal_kind::text AS principal_kind, job_role, status FROM iam.organization_memberships WHERE organization_id = $1 AND id = $2 LIMIT 1",
    )
    .bind(organization_id)
    .bind(membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn membership_tag_ids(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT assignment.tag_id
        FROM iam.membership_tags AS assignment
        WHERE assignment.organization_id = $1 AND assignment.membership_id = $2
        ORDER BY assignment.tag_id
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)
}

async fn validate_active_tag_ids(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    tag_ids: &[Uuid],
) -> Result<(), AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM iam.organization_tags AS tag
        WHERE tag.organization_id = $1 AND tag.id = ANY($2) AND tag.status = 'active'
        ",
    )
    .bind(organization_id)
    .bind(tag_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(count).ok() != Some(tag_ids.len()) {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("directory_reference_inactive"),
        });
    }
    Ok(())
}

async fn insert_requirement(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    request_id: Uuid,
    kind: &'static str,
    specific_membership_id: Option<Uuid>,
    required_capability: Option<&'static str>,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        INSERT INTO iam.approval_requirements (
            id, organization_id, approval_request_id, requirement_kind,
            specific_membership_id, required_capability
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(request_id)
    .bind(kind)
    .bind(specific_membership_id)
    .bind(required_capability)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    Ok(())
}

async fn eligible_requirement(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    request_id: Uuid,
    caller_membership_id: Uuid,
    authority: &crate::domain::organization::OrganizationAuthority,
) -> Result<RequirementRow, AppError> {
    let requirements = sqlx::query_as::<_, RequirementRow>(
        r"
        SELECT requirement.id, requirement.requirement_kind,
               requirement.specific_membership_id, requirement.required_capability,
               requirement.quorum
        FROM iam.approval_requirements AS requirement
        WHERE requirement.organization_id = $1 AND requirement.approval_request_id = $2
          AND NOT EXISTS (
              SELECT 1 FROM iam.approval_decisions AS decision
              WHERE decision.approval_request_id = requirement.approval_request_id
                AND decision.decided_by_membership_id = $3
          )
        ORDER BY requirement.id
        ",
    )
    .bind(organization_id)
    .bind(request_id)
    .bind(caller_membership_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)?;
    for requirement in requirements {
        let eligible = match requirement.requirement_kind.as_str() {
            "specific_membership" => {
                requirement.specific_membership_id == Some(caller_membership_id)
            }
            "current_owner" => authority.org_role == OrgRole::Owner,
            "current_owner_or_admin" => {
                authority.org_role == OrgRole::Owner
                    || (authority.org_role == OrgRole::Admin
                        && requirement
                            .required_capability
                            .as_deref()
                            .and_then(|capability| Capability::from_str(capability).ok())
                            .is_some_and(|capability| authority.allows(capability)))
            }
            _ => false,
        };
        if eligible {
            return Ok(requirement);
        }
    }
    Err(AppError::Forbidden)
}

async fn requirements_satisfied(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    request_id: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT NOT EXISTS (
            SELECT 1
            FROM iam.approval_requirements AS requirement
            WHERE requirement.organization_id = $1
              AND requirement.approval_request_id = $2
              AND (
                  SELECT count(*)
                  FROM iam.approval_decisions AS decision
                  WHERE decision.approval_request_id = requirement.approval_request_id
                    AND decision.approval_requirement_id = requirement.id
                    AND decision.decision = 'approve'
              ) < requirement.quorum
        )
        ",
    )
    .bind(organization_id)
    .bind(request_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)
}

async fn update_approval_status(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    request_id: Uuid,
    expected_version: i64,
    status: &'static str,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r"
        UPDATE iam.approval_requests
        SET status = $4,
            rejected_at = CASE WHEN $4 = 'rejected' THEN transaction_timestamp() ELSE rejected_at END,
            approved_at = CASE WHEN $4 = 'approved' THEN transaction_timestamp() ELSE approved_at END
        WHERE organization_id = $1 AND id = $2 AND version = $3 AND status = 'pending'
        ",
    )
    .bind(organization_id)
    .bind(request_id)
    .bind(expected_version)
    .bind(status)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    Ok(())
}

async fn apply_job_role_change(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    request_id: Uuid,
    expected_version: i64,
) -> Result<(Uuid, String, String, i64), AppError> {
    let payload = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT target_membership_id, previous_job_role, proposed_job_role FROM iam.job_role_change_requests WHERE organization_id = $1 AND approval_request_id = $2",
    )
    .bind(organization_id)
    .bind(request_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    let membership_version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.organization_memberships
        SET job_role = $3
        WHERE organization_id = $1 AND id = $2 AND status = 'active' AND job_role = $4
        RETURNING version
        ",
    )
    .bind(organization_id)
    .bind(payload.0)
    .bind(&payload.2)
    .bind(&payload.1)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::Conflict {
        code: Cow::Borrowed("job_role_changed_since_request"),
    })?;
    sqlx::query(
        r"
        INSERT INTO iam.job_role_history (
            id, organization_id, membership_id, approval_request_id,
            previous_job_role, applied_job_role, membership_version
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(organization_id)
    .bind(payload.0)
    .bind(request_id)
    .bind(&payload.1)
    .bind(&payload.2)
    .bind(membership_version)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    let result = sqlx::query(
        r"
        UPDATE iam.approval_requests
        SET status = 'applied', approved_at = transaction_timestamp(),
            applied_at = transaction_timestamp()
        WHERE organization_id = $1 AND id = $2 AND version = $3 AND status = 'pending'
        ",
    )
    .bind(organization_id)
    .bind(request_id)
    .bind(expected_version)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    Ok((payload.0, payload.1, payload.2, membership_version))
}

async fn fetch_approval(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    request_id: Uuid,
) -> Result<ApprovalRequestResponse, AppError> {
    let row = sqlx::query_as::<_, ApprovalRow>(APPROVAL_BY_ID_SQL)
        .bind(organization_id)
        .bind(request_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)?;
    materialize_approval(transaction, row).await
}

async fn materialize_approvals(
    transaction: &mut Transaction<'_, Postgres>,
    rows: Vec<ApprovalRow>,
) -> Result<Vec<ApprovalRequestResponse>, AppError> {
    let mut output = Vec::with_capacity(rows.len());
    for row in rows {
        output.push(materialize_approval(transaction, row).await?);
    }
    Ok(output)
}

async fn materialize_approval(
    transaction: &mut Transaction<'_, Postgres>,
    row: ApprovalRow,
) -> Result<ApprovalRequestResponse, AppError> {
    let requirements = sqlx::query_as::<_, RequirementRow>(
        "SELECT id, requirement_kind, specific_membership_id, required_capability, quorum FROM iam.approval_requirements WHERE approval_request_id = $1 ORDER BY id",
    )
    .bind(row.id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)?;
    let decisions = decision_rows(transaction, row.id)
        .await?
        .into_iter()
        .map(|decision| ApprovalDecisionResponse {
            id: decision.id,
            approver: ActorResponse {
                principal_id: decision.principal_id,
                actor_type: decision.actor_type,
                public_id: decision.public_id,
            },
            decision: decision.decision,
            comment: decision.comment,
            decided_at: decision.decided_at,
        })
        .collect();
    let target_carbon = requirements
        .iter()
        .filter(|requirement| requirement.requirement_kind == "specific_membership")
        .map(|requirement| requirement.quorum)
        .sum();
    let eligible_owner_or_admin = requirements
        .iter()
        .filter(|requirement| {
            matches!(
                requirement.requirement_kind.as_str(),
                "current_owner" | "current_owner_or_admin"
            )
        })
        .map(|requirement| requirement.quorum)
        .sum();
    let immutable_payload = match row.kind.as_str() {
        "carbon_job_role_change" | "silicon_job_role_change" => json!({
            "previous_job_role": row.previous_job_role,
            "proposed_job_role": row.proposed_job_role,
        }),
        "carbon_tag_change" | "silicon_tag_change" => json!({
            "previous_tag_ids": row.previous_tag_ids,
            "added_tag_ids": row.added_tag_ids,
            "removed_tag_ids": row.removed_tag_ids,
            "proposed_tag_ids": row.proposed_tag_ids,
            "reason": row.tag_change_reason,
        }),
        "silicon_token_rotation" => json!({
            "silicon_id": row.silicon_id,
        }),
        _ => json!({}),
    };
    Ok(ApprovalRequestResponse {
        id: row.id,
        org_id: row.org_id,
        kind: row.kind,
        status: public_approval_status(&row.status),
        requested_by: ActorResponse {
            principal_id: row.requested_by_principal_id,
            actor_type: row.requested_by_type,
            public_id: row.requested_by_public_id,
        },
        target_membership_id: row.target_membership_id,
        immutable_payload,
        required_approvals: ApprovalRequirementsResponse {
            target_carbon,
            eligible_owner_or_admin,
        },
        decisions,
        completed_at: row.completed_at,
        version: row.version,
        created_at: row.created_at,
    })
}

async fn decision_rows(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<Vec<DecisionRow>, AppError> {
    sqlx::query_as::<_, DecisionRow>(DECISIONS_SQL)
        .bind(request_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(support::database)
}

async fn decision_actors(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<Vec<ActorResponse>, AppError> {
    Ok(decision_rows(transaction, request_id)
        .await?
        .into_iter()
        .filter(|row| row.decision == "approve")
        .map(|row| ActorResponse {
            principal_id: row.principal_id,
            actor_type: row.actor_type,
            public_id: row.public_id,
        })
        .collect())
}

async fn fetch_rotation_target(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_handle: &str,
) -> Result<RotationTarget, AppError> {
    sqlx::query_as::<_, RotationTarget>(
        r"
        SELECT silicon.id AS silicon_id, silicon.membership_id,
               silicon.global_silicon_id, credential.id AS credential_id
        FROM iam.silicons AS silicon
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id AND membership.status = 'active'
        JOIN iam.silicon_credentials AS credential
          ON credential.organization_id = silicon.organization_id
         AND credential.silicon_id = silicon.id AND credential.status = 'active'
        WHERE silicon.organization_id = $1 AND silicon.global_silicon_id = $2
          AND silicon.provisioning_status <> 'deleted'
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(silicon_handle)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn lock_rotation_target_for_approval(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    request_id: Uuid,
) -> Result<RotationTarget, AppError> {
    sqlx::query_as::<_, RotationTarget>(
        r"
        SELECT silicon.id AS silicon_id, silicon.membership_id,
               silicon.global_silicon_id,
               rotation.previous_credential_id AS credential_id
        FROM iam.silicon_token_rotation_requests AS rotation
        JOIN iam.silicons AS silicon
          ON silicon.organization_id = rotation.organization_id
         AND silicon.id = rotation.silicon_id
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id
        JOIN iam.silicon_credentials AS credential
          ON credential.organization_id = rotation.organization_id
         AND credential.silicon_id = rotation.silicon_id
         AND credential.id = rotation.previous_credential_id
        WHERE rotation.organization_id = $1
          AND rotation.approval_request_id = $2
          AND rotation.fulfillment_status = 'awaiting_approval'
          AND silicon.provisioning_status <> 'deleted'
          AND membership.status = 'active'
        FOR UPDATE OF rotation, silicon, membership, credential
        ",
    )
    .bind(organization_id)
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::Gone {
        code: Cow::Borrowed("rotation_not_ready"),
    })
}

async fn invalidate_rotation_credential(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    request_id: Uuid,
    target: &RotationTarget,
) -> Result<(), AppError> {
    let active_credential_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM iam.silicon_credentials
        WHERE organization_id = $1 AND silicon_id = $2 AND status = 'active'
        FOR UPDATE
        ",
    )
    .bind(organization_id)
    .bind(target.silicon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?;
    if active_credential_id.is_some_and(|credential_id| credential_id != target.credential_id) {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("rotation_credential_changed"),
        });
    }
    sqlx::query(
        r"
        UPDATE iam.silicon_credentials
        SET status = 'retired', retired_at = transaction_timestamp()
        WHERE organization_id = $1 AND silicon_id = $2 AND id = $3 AND status = 'active'
        ",
    )
    .bind(organization_id)
    .bind(target.silicon_id)
    .bind(target.credential_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    let ready = sqlx::query(
        r"
        UPDATE iam.silicon_token_rotation_requests
        SET fulfillment_status = 'ready'
        WHERE organization_id = $1 AND approval_request_id = $2
          AND silicon_id = $3 AND fulfillment_status = 'awaiting_approval'
        ",
    )
    .bind(organization_id)
    .bind(request_id)
    .bind(target.silicon_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    if ready.rows_affected() != 1 {
        return Err(AppError::Gone {
            code: Cow::Borrowed("rotation_not_ready"),
        });
    }
    let principal = sqlx::query("UPDATE iam.principals SET auth_epoch = auth_epoch + 1 WHERE id = $1 AND kind = 'silicon' AND status = 'active'")
        .bind(target.silicon_id)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    let membership = sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET authz_epoch = authz_epoch + 1
        WHERE organization_id = $1 AND id = $2
          AND principal_id = $3 AND principal_kind = 'silicon' AND status = 'active'
        ",
    )
    .bind(organization_id)
    .bind(target.membership_id)
    .bind(target.silicon_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    if principal.rows_affected() != 1 || membership.rows_affected() != 1 {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("membership_not_active"),
        });
    }
    touch_direct_silicon_projection(transaction, organization_id, target.membership_id, true)
        .await?;
    revoke_silicon_sessions(transaction, target.silicon_id).await
}

async fn fetch_rotation_target_for_request(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_handle: &str,
    request_id: Uuid,
) -> Result<RotationTarget, AppError> {
    sqlx::query_as::<_, RotationTarget>(
        r"
        SELECT silicon.id AS silicon_id, silicon.membership_id,
               silicon.global_silicon_id,
               rotation.previous_credential_id AS credential_id
        FROM iam.silicon_token_rotation_requests AS rotation
        JOIN iam.silicons AS silicon
          ON silicon.organization_id = rotation.organization_id
         AND silicon.id = rotation.silicon_id
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id AND membership.status = 'active'
        WHERE rotation.organization_id = $1
          AND rotation.approval_request_id = $2
          AND silicon.global_silicon_id = $3
          AND silicon.provisioning_status <> 'deleted'
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(request_id)
    .bind(silicon_handle)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn revoke_silicon_sessions(
    transaction: &mut Transaction<'_, Postgres>,
    silicon_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE iam.authentication_sessions SET status = 'revoked', revoked_at = transaction_timestamp(), revocation_reason = 'Silicon credential rotated', version = version + 1 WHERE subject_principal_id = $1 AND status = 'active'",
    )
    .bind(silicon_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'revoked', revoked_at = transaction_timestamp(),
            revocation_reason = 'Silicon credential rotated'
        WHERE subject_principal_id = $1 AND status = 'active'
        ",
    )
    .bind(silicon_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        UPDATE iam.refresh_tokens AS token
        SET revoked_at = COALESCE(token.revoked_at, transaction_timestamp())
        FROM iam.refresh_token_families AS family
        WHERE token.family_id = family.id
          AND family.subject_principal_id = $1
        ",
    )
    .bind(silicon_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        "UPDATE iam.access_tokens SET revoked_at = transaction_timestamp(), revocation_reason = 'Silicon credential rotated' WHERE subject_principal_id = $1 AND revoked_at IS NULL",
    )
    .bind(silicon_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    Ok(())
}

fn validate_global_silicon(value: &str, org_id: &str) -> Result<(), AppError> {
    let Some((local, suffix)) = value.rsplit_once(':') else {
        return Err(validation::field("silicon_id", "has an invalid format"));
    };
    if suffix != org_id
        || local.len() < 3
        || local.len() > 50
        || !local.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(AppError::NotFound);
    }
    Ok(())
}

fn validate_approval_filters(query: &ApprovalQuery) -> Result<(), AppError> {
    if query
        .status
        .as_deref()
        .is_some_and(|value| !matches!(value, "pending" | "approved" | "rejected" | "completed"))
    {
        return Err(validation::field("status", "has an unsupported value"));
    }
    if query.kind.as_deref().is_some_and(|value| {
        !matches!(
            value,
            "carbon_job_role_change"
                | "silicon_job_role_change"
                | "carbon_tag_change"
                | "silicon_tag_change"
                | "silicon_token_rotation"
        )
    }) {
        return Err(validation::field("kind", "has an unsupported value"));
    }
    Ok(())
}

fn public_approval_status(value: &str) -> String {
    match value {
        "applied" => "completed".to_owned(),
        other => other.to_owned(),
    }
}

fn take_approval_page(
    items: &mut Vec<ApprovalRequestResponse>,
    limit: i64,
) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "approval_page_limit",
    })?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    Ok(PageInfo {
        next_cursor: if has_more {
            items.last().map(|item| validation::encode_cursor(item.id))
        } else {
            None
        },
        has_more,
    })
}

fn take_history_page(
    items: &mut Vec<RoleHistoryResponse>,
    limit: i64,
) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "role_history_page_limit",
    })?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    Ok(PageInfo {
        next_cursor: if has_more {
            items.last().map(|item| validation::encode_cursor(item.id))
        } else {
            None
        },
        has_more,
    })
}

fn take_tag_history_page(
    items: &mut Vec<TagHistoryResponse>,
    limit: i64,
) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "tag_history_page_limit",
    })?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    Ok(PageInfo {
        next_cursor: if has_more {
            items.last().map(|item| validation::encode_cursor(item.id))
        } else {
            None
        },
        has_more,
    })
}

fn approval_payload_tag_ids(payload: &Value) -> Vec<Uuid> {
    ["previous_tag_ids", "proposed_tag_ids"]
        .into_iter()
        .filter_map(|field| payload.get(field).and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|value| Uuid::parse_str(value).ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn map_tag_change_apply_error(error: sqlx::Error) -> AppError {
    let message = error
        .as_database_error()
        .map(sqlx::error::DatabaseError::message);
    match message {
        Some("tag_change_approval_version_mismatch") => precondition_failed(),
        Some("tag_change_approval_closed") => AppError::Gone {
            code: Cow::Borrowed("approval_request_closed"),
        },
        Some("tag_change_snapshot_changed") => AppError::Conflict {
            code: Cow::Borrowed("tag_change_snapshot_changed"),
        },
        Some("tag_change_target_inactive") => AppError::Conflict {
            code: Cow::Borrowed("membership_not_active"),
        },
        Some("tag_change_tag_inactive") => AppError::Conflict {
            code: Cow::Borrowed("directory_reference_inactive"),
        },
        Some("tag_change_apply_forbidden" | "tag_change_requirements_unsatisfied") => {
            AppError::Forbidden
        }
        _ => support::database(error),
    }
}

fn precondition_failed() -> AppError {
    AppError::PreconditionFailed {
        code: Cow::Borrowed("etag_mismatch"),
    }
}

const APPROVAL_LIST_SQL: &str = r"
    SELECT request.id, organization.org_id, request.request_kind AS kind,
           request.status,
           requester.principal_id AS requested_by_principal_id, requester.principal_kind::text AS requested_by_type,
           CASE WHEN requester.principal_kind = 'carbon' THEN requester_carbon.carbon_id ELSE requester_silicon.global_silicon_id END AS requested_by_public_id,
           COALESCE(role_change.target_membership_id, tag_change.target_membership_id, rotation_silicon.membership_id) AS target_membership_id,
           role_change.previous_job_role, role_change.proposed_job_role,
           tag_change.previous_tag_ids, tag_change.added_tag_ids,
           tag_change.removed_tag_ids, tag_change.proposed_tag_ids,
           tag_change.reason AS tag_change_reason, rotation.silicon_id,
           COALESCE(request.applied_at, request.rejected_at, request.cancelled_at) AS completed_at,
           request.version, request.created_at
    FROM iam.approval_requests request
    JOIN iam.organizations organization ON organization.id = request.organization_id
    JOIN iam.organization_memberships requester ON requester.organization_id = request.organization_id AND requester.id = request.requested_by_membership_id
    LEFT JOIN iam.carbons requester_carbon ON requester_carbon.id = requester.principal_id AND requester.principal_kind = 'carbon'
    LEFT JOIN iam.silicons requester_silicon ON requester_silicon.id = requester.principal_id AND requester.principal_kind = 'silicon'
    LEFT JOIN iam.job_role_change_requests role_change ON role_change.organization_id = request.organization_id AND role_change.approval_request_id = request.id
    LEFT JOIN iam.tag_change_requests tag_change ON tag_change.organization_id = request.organization_id AND tag_change.approval_request_id = request.id
    LEFT JOIN iam.silicon_token_rotation_requests rotation ON rotation.organization_id = request.organization_id AND rotation.approval_request_id = request.id
    LEFT JOIN iam.silicons rotation_silicon ON rotation_silicon.organization_id = rotation.organization_id AND rotation_silicon.id = rotation.silicon_id
    WHERE request.organization_id = $1 AND ($2::uuid IS NULL OR request.id > $2)
      AND ($4::text IS NULL OR CASE WHEN request.status = 'applied' THEN 'completed' ELSE request.status END = $4)
      AND ($5::text IS NULL OR request.request_kind = $5)
      AND (NOT $6 OR EXISTS (
          SELECT 1 FROM iam.approval_requirements requirement
          WHERE requirement.approval_request_id = request.id
            AND NOT EXISTS (SELECT 1 FROM iam.approval_decisions decision WHERE decision.approval_request_id = request.id AND decision.decided_by_membership_id = $7)
            AND (requirement.specific_membership_id = $7
                 OR (requirement.requirement_kind = 'current_owner' AND EXISTS (SELECT 1 FROM iam.organization_memberships caller WHERE caller.id = $7 AND caller.org_role = 'owner' AND caller.status = 'active'))
                 OR (requirement.requirement_kind = 'current_owner_or_admin' AND iam_private.has_organization_capability(request.organization_id, iam_private.current_principal_id(), requirement.required_capability)))
      ))
    ORDER BY request.id LIMIT $3
";

const APPROVAL_BY_ID_SQL: &str = r"
    SELECT request.id, organization.org_id, request.request_kind AS kind,
           request.status,
           requester.principal_id AS requested_by_principal_id, requester.principal_kind::text AS requested_by_type,
           CASE WHEN requester.principal_kind = 'carbon' THEN requester_carbon.carbon_id ELSE requester_silicon.global_silicon_id END AS requested_by_public_id,
           COALESCE(role_change.target_membership_id, tag_change.target_membership_id, rotation_silicon.membership_id) AS target_membership_id,
           role_change.previous_job_role, role_change.proposed_job_role,
           tag_change.previous_tag_ids, tag_change.added_tag_ids,
           tag_change.removed_tag_ids, tag_change.proposed_tag_ids,
           tag_change.reason AS tag_change_reason, rotation.silicon_id,
           COALESCE(request.applied_at, request.rejected_at, request.cancelled_at) AS completed_at,
           request.version, request.created_at
    FROM iam.approval_requests request
    JOIN iam.organizations organization ON organization.id = request.organization_id
    JOIN iam.organization_memberships requester ON requester.organization_id = request.organization_id AND requester.id = request.requested_by_membership_id
    LEFT JOIN iam.carbons requester_carbon ON requester_carbon.id = requester.principal_id AND requester.principal_kind = 'carbon'
    LEFT JOIN iam.silicons requester_silicon ON requester_silicon.id = requester.principal_id AND requester.principal_kind = 'silicon'
    LEFT JOIN iam.job_role_change_requests role_change ON role_change.organization_id = request.organization_id AND role_change.approval_request_id = request.id
    LEFT JOIN iam.tag_change_requests tag_change ON tag_change.organization_id = request.organization_id AND tag_change.approval_request_id = request.id
    LEFT JOIN iam.silicon_token_rotation_requests rotation ON rotation.organization_id = request.organization_id AND rotation.approval_request_id = request.id
    LEFT JOIN iam.silicons rotation_silicon ON rotation_silicon.organization_id = rotation.organization_id AND rotation_silicon.id = rotation.silicon_id
    WHERE request.organization_id = $1 AND request.id = $2 LIMIT 1
";

const DECISIONS_SQL: &str = r"
    SELECT decision.id, membership.principal_id,
           membership.principal_kind::text AS actor_type,
           CASE WHEN membership.principal_kind = 'carbon' THEN carbon.carbon_id ELSE silicon.global_silicon_id END AS public_id,
           decision.decision,
           decision.eligibility_snapshot ->> 'comment' AS comment,
           decision.decided_at
    FROM iam.approval_decisions decision
    JOIN iam.organization_memberships membership
      ON membership.organization_id = decision.organization_id
     AND membership.id = decision.decided_by_membership_id
    LEFT JOIN iam.carbons carbon ON carbon.id = membership.principal_id AND membership.principal_kind = 'carbon'
    LEFT JOIN iam.silicons silicon ON silicon.id = membership.principal_id AND membership.principal_kind = 'silicon'
    WHERE decision.approval_request_id = $1 ORDER BY decision.decided_at, decision.id
";

const ROLE_HISTORY_SQL: &str = r"
    SELECT history.id, history.membership_id,
           history.previous_job_role AS old_job_role,
           history.applied_job_role AS new_job_role,
           history.approval_request_id,
           requester.principal_id AS requested_by_principal_id,
           requester.principal_kind::text AS requested_by_type,
           CASE WHEN requester.principal_kind = 'carbon' THEN carbon.carbon_id ELSE silicon.global_silicon_id END AS requested_by_public_id,
           history.applied_at
    FROM iam.job_role_history history
    LEFT JOIN iam.approval_requests request
      ON request.organization_id = history.organization_id AND request.id = history.approval_request_id
    JOIN iam.organization_memberships requester
      ON requester.organization_id = history.organization_id
     AND requester.id = COALESCE(request.requested_by_membership_id, history.applied_by_membership_id)
    LEFT JOIN iam.carbons carbon ON carbon.id = requester.principal_id AND requester.principal_kind = 'carbon'
    LEFT JOIN iam.silicons silicon ON silicon.id = requester.principal_id AND requester.principal_kind = 'silicon'
    WHERE history.organization_id = $1 AND history.membership_id = $2
      AND ($3::uuid IS NULL OR history.id > $3)
    ORDER BY history.id LIMIT $4
";

const TAG_HISTORY_SQL: &str = r"
    SELECT history.id, history.membership_id,
           history.previous_tag_ids, history.applied_tag_ids,
           history.approval_request_id, history.membership_version,
           requester.principal_id AS requested_by_principal_id,
           requester.principal_kind::text AS requested_by_type,
           CASE WHEN requester.principal_kind = 'carbon' THEN carbon.carbon_id ELSE silicon.global_silicon_id END AS requested_by_public_id,
           history.applied_at
    FROM iam.membership_tag_change_history history
    LEFT JOIN iam.approval_requests request
      ON request.organization_id = history.organization_id AND request.id = history.approval_request_id
    JOIN iam.organization_memberships requester
      ON requester.organization_id = history.organization_id
     AND requester.id = COALESCE(request.requested_by_membership_id, history.applied_by_membership_id)
    LEFT JOIN iam.carbons carbon ON carbon.id = requester.principal_id AND requester.principal_kind = 'carbon'
    LEFT JOIN iam.silicons silicon ON silicon.id = requester.principal_id AND requester.principal_kind = 'silicon'
    WHERE history.organization_id = $1 AND history.membership_id = $2
      AND ($3::uuid IS NULL OR history.id > $3)
    ORDER BY history.id LIMIT $4
";

#[cfg(test)]
mod tests {
    use anyhow::ensure;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres;
    use uuid::Uuid;

    use super::{
        APPROVAL_BY_ID_SQL, APPROVAL_LIST_SQL, approved_silicon_projection_action,
        require_silicon_governance_request,
    };
    use crate::domain::actor::ActorType;

    #[test]
    fn only_silicons_can_create_governance_requests() {
        assert!(require_silicon_governance_request(ActorType::Silicon).is_ok());
        assert!(require_silicon_governance_request(ActorType::Carbon).is_err());
        assert!(require_silicon_governance_request(ActorType::Application).is_err());
    }

    #[test]
    fn approved_silicon_directory_changes_emit_the_silicon_projection() {
        assert_eq!(
            approved_silicon_projection_action("silicon_job_role_change"),
            Some("silicon.job_role_change_approved")
        );
        assert_eq!(
            approved_silicon_projection_action("silicon_tag_change"),
            Some("silicon.tag_change_approved")
        );
        assert_eq!(
            approved_silicon_projection_action("carbon_job_role_change"),
            None
        );
        assert_eq!(
            approved_silicon_projection_action("carbon_tag_change"),
            None
        );
    }

    #[test]
    fn governance_requests_have_no_invented_expiry_contract() {
        let migration =
            include_str!("../../../migrations/0034_exact_membership_events_and_scope_cleanup.sql");
        assert!(migration.contains("ALTER COLUMN expires_at DROP NOT NULL"));
        assert!(migration.contains("WHERE status IN ('pending', 'approved')"));
        assert!(!APPROVAL_LIST_SQL.contains("expires_at"));
        assert!(!APPROVAL_BY_ID_SQL.contains("expires_at"));
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture and both fixed-path direct governance transitions form one database contract test"
    )]
    async fn direct_admin_role_and_tag_control_is_atomic_and_historical() -> anyhow::Result<()> {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        crate::infrastructure::postgres::migrate(&pool).await?;

        let owner_id = Uuid::from_u128(0x401);
        let admin_id = Uuid::from_u128(0x402);
        let target_id = Uuid::from_u128(0x403);
        let organization_id = Uuid::from_u128(0x404);
        let owner_membership_id = Uuid::from_u128(0x405);
        let admin_membership_id = Uuid::from_u128(0x406);
        let target_membership_id = Uuid::from_u128(0x407);
        let tag_id = Uuid::from_u128(0x408);
        let role_history_id = Uuid::from_u128(0x409);
        let tag_history_id = Uuid::from_u128(0x40a);

        let mut seed = pool.begin().await?;
        sqlx::query(
            r"
            INSERT INTO iam.principals (id, kind, status, activated_at)
            VALUES
                ($1, 'carbon', 'active', transaction_timestamp()),
                ($2, 'carbon', 'active', transaction_timestamp()),
                ($3, 'carbon', 'active', transaction_timestamp())
            ",
        )
        .bind(owner_id)
        .bind(admin_id)
        .bind(target_id)
        .execute(&mut *seed)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.carbons (id, carbon_id, display_name)
            VALUES
                ($1, 'direct-owner', 'Direct Owner'),
                ($2, 'direct-admin', 'Direct Admin'),
                ($3, 'direct-target', 'Direct Target')
            ",
        )
        .bind(owner_id)
        .bind(admin_id)
        .bind(target_id)
        .execute(&mut *seed)
        .await?;
        sqlx::query(
            "INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status) VALUES ('contact_aead', 1, 'active')",
        )
        .execute(&mut *seed)
        .await?;
        for (contact_index, carbon_id) in [owner_id, admin_id, target_id].into_iter().enumerate() {
            for (kind_index, kind) in ["email", "phone"].into_iter().enumerate() {
                let discriminator = u8::try_from(contact_index * 2 + kind_index + 1)?;
                sqlx::query(
                    r"
                    INSERT INTO iam.carbon_contacts (
                        id, carbon_id, kind, ciphertext, nonce,
                        encryption_key_version, verified_at
                    ) VALUES ($1, $2, $3::iam.contact_kind, $4, $5, 1, transaction_timestamp())
                    ",
                )
                .bind(Uuid::from_u128(0x410 + u128::from(discriminator)))
                .bind(carbon_id)
                .bind(kind)
                .bind(vec![discriminator; 17])
                .bind(vec![discriminator; 12])
                .execute(&mut *seed)
                .await?;
            }
        }
        sqlx::query(
            "INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name) VALUES ($1, 'direct-controls', $2, 'Direct Controls')",
        )
        .bind(organization_id)
        .bind(owner_id)
        .execute(&mut *seed)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role,
                job_role, role_granted_by_membership_id
            ) VALUES
                ($1, $4, $5, 'carbon', 'owner', 'Owner', NULL),
                ($2, $4, $6, 'carbon', 'admin', 'Administrator', $1),
                ($3, $4, $7, 'carbon', 'member', 'Engineer', NULL)
            ",
        )
        .bind(owner_membership_id)
        .bind(admin_membership_id)
        .bind(target_membership_id)
        .bind(organization_id)
        .bind(owner_id)
        .bind(admin_id)
        .bind(target_id)
        .execute(&mut *seed)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_capability_grants (
                id, organization_id, grantee_membership_id, capability,
                granted_by_membership_id
            ) VALUES
                ($1, $3, $4, 'roles.approve', $5),
                ($2, $3, $4, 'tags.manage', $5)
            ",
        )
        .bind(Uuid::from_u128(0x40b))
        .bind(Uuid::from_u128(0x40c))
        .bind(organization_id)
        .bind(admin_membership_id)
        .bind(owner_membership_id)
        .execute(&mut *seed)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_tags (
                id, organization_id, name, normalized_name,
                created_by_membership_id
            ) VALUES ($1, $2, 'Platform', 'platform', $3)
            ",
        )
        .bind(tag_id)
        .bind(organization_id)
        .bind(owner_membership_id)
        .execute(&mut *seed)
        .await?;
        seed.commit().await?;

        let mut transaction = crate::infrastructure::postgres::context::begin(
            &pool,
            crate::infrastructure::postgres::context::DatabaseContext::organization(
                admin_id,
                organization_id,
            ),
        )
        .await?;
        let role_version = sqlx::query_scalar::<_, i64>(
            "SELECT iam_private.replace_membership_job_role_direct($1, $2, $3, $4, 1, 'Staff Engineer')",
        )
        .bind(organization_id)
        .bind(target_membership_id)
        .bind(admin_membership_id)
        .bind(role_history_id)
        .fetch_one(&mut *transaction)
        .await?;
        let tag_version = sqlx::query_scalar::<_, i64>(
            "SELECT iam_private.replace_membership_tags_direct($1, $2, $3, $4, $5, $6)",
        )
        .bind(organization_id)
        .bind(target_membership_id)
        .bind(admin_membership_id)
        .bind(tag_history_id)
        .bind(role_version)
        .bind(vec![tag_id])
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;

        let membership = sqlx::query_as::<_, (String, i64, i64)>(
            "SELECT job_role, authz_epoch, version FROM iam.organization_memberships WHERE id = $1",
        )
        .bind(target_membership_id)
        .fetch_one(&pool)
        .await?;
        let role_history = sqlx::query_as::<_, (Option<Uuid>, Option<Uuid>)>(
            "SELECT approval_request_id, applied_by_membership_id FROM iam.job_role_history WHERE id = $1",
        )
        .bind(role_history_id)
        .fetch_one(&pool)
        .await?;
        let tag_history = sqlx::query_as::<_, (Option<Uuid>, Option<Uuid>, Vec<Uuid>)>(
            "SELECT approval_request_id, applied_by_membership_id, applied_tag_ids FROM iam.membership_tag_change_history WHERE id = $1",
        )
        .bind(tag_history_id)
        .fetch_one(&pool)
        .await?;
        ensure!(role_version == 2 && tag_version == 3);
        ensure!(membership == ("Staff Engineer".to_owned(), 2, 3));
        ensure!(role_history == (None, Some(admin_membership_id)));
        ensure!(tag_history == (None, Some(admin_membership_id), vec![tag_id]));
        Ok(())
    }
}
