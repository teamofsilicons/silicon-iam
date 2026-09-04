#![allow(clippy::too_many_lines)]

use std::{borrow::Cow, collections::BTreeMap};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Serialize;
use serde_json::json;
use sqlx::{Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::organization::{Capability, OrgRole},
    error::AppError,
    infrastructure::postgres::step_up::RequiredAssurance,
};

use super::{
    model::{
        CapabilitiesReplace, MemberQuery, MembershipAuthorizationResponse,
        MembershipDirectoryPatch, MembershipPage, MembershipResponse, PageInfo, RemovalQuery,
    },
    support::{self, Claim, MutationEvent},
    validation,
};

const MEMBER_UPDATE_ROUTE: &str = "PATCH /api/v1/organizations/{org_id}/members/{membership_id}";
const MEMBER_REMOVE_ROUTE: &str = "DELETE /api/v1/organizations/{org_id}/members/{membership_id}";
const MEMBER_PROMOTE_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/members/{membership_id}/admin-promotions";
const MEMBER_DEMOTE_ROUTE: &str =
    "POST /api/v1/organizations/{org_id}/members/{membership_id}/admin-demotions";
const MEMBER_CAPABILITIES_ROUTE: &str =
    "PUT /api/v1/organizations/{org_id}/members/{membership_id}/capabilities";

#[derive(Clone, Debug, sqlx::FromRow)]
struct MembershipIdentity {
    principal_kind: String,
    org_role: String,
    status: String,
    version: i64,
}

pub(super) async fn list_members(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<MemberQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (cursor, limit) = validation::page_parts(query.cursor.as_deref(), query.limit)?;
    validate_member_filters(&query)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let mut items = list_members_query(
        &mut scope.transaction,
        scope.access.organization_id,
        cursor,
        limit + 1,
        query.principal_type.as_deref(),
        query.tag_id,
        query.status.as_deref(),
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_page(&mut items, limit)?;
    support::json(StatusCode::OK, &MembershipPage { items, page }, None)
}

pub(super) async fn get_member(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let member = fetch_member(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &member, Some(member.version))
}

pub(super) async fn update_member_directory(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(mut input): Json<MembershipDirectoryPatch>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validation::member_patch(&mut input, state.settings.environment)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        MEMBER_UPDATE_ROUTE,
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
    let identity = fetch_membership_identity(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    require_active_version(&identity, expected_version)?;
    authorize_directory_patch(&scope.access, &identity, &input)?;

    let silicon_member = identity.principal_kind == "silicon";
    let hierarchy_change = silicon_member && input.reports_to_membership_id.is_some();
    let affected_membership_ids = if silicon_member {
        super::silicons::lock_hierarchy_subtree(
            &mut scope.transaction,
            scope.access.organization_id,
            membership_id,
            hierarchy_change,
        )
        .await?
    } else {
        vec![membership_id]
    };
    let before_members = fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &affected_membership_ids,
    )
    .await?
    .into_iter()
    .map(|member| (member.id, member))
    .collect::<BTreeMap<_, _>>();
    let profile_base = silicon_member
        .then(|| super::silicons::silicon_profile_base(&state))
        .transpose()?;
    let before_silicons = if let Some(profile_base) = profile_base.as_deref() {
        super::silicons::fetch_silicons(
            &mut scope.transaction,
            scope.access.organization_id,
            &affected_membership_ids,
            profile_base,
        )
        .await?
        .into_iter()
        .map(|silicon| (silicon.membership_id, silicon))
        .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };

    match identity.principal_kind.as_str() {
        "carbon" => {
            update_carbon_directory(
                &mut scope.transaction,
                scope.access.organization_id,
                membership_id,
                scope.access.membership_id,
                &input,
            )
            .await?;
        }
        "silicon" => {
            update_silicon_directory(
                &mut scope.transaction,
                scope.access.organization_id,
                membership_id,
                &input,
            )
            .await?;
        }
        _ => {
            return Err(AppError::Internal {
                category: "membership_kind",
            });
        }
    }
    bump_membership(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        expected_version,
        identity.principal_kind == "carbon" || input.reports_to_membership_id.is_some(),
    )
    .await?;
    let changed_membership_ids = if let Some(profile_base) = profile_base.as_deref() {
        let provisional = super::silicons::fetch_silicons(
            &mut scope.transaction,
            scope.access.organization_id,
            &affected_membership_ids,
            profile_base,
        )
        .await?;
        provisional
            .iter()
            .filter_map(|after| {
                let before = before_silicons.get(&after.membership_id)?;
                (after.membership_id == membership_id
                    || super::silicons::hierarchy_projection_changed(before, after))
                .then_some(after.membership_id)
            })
            .collect::<Vec<_>>()
    } else {
        vec![membership_id]
    };
    if silicon_member {
        super::silicons::touch_silicon_descendants(
            &mut scope.transaction,
            scope.access.organization_id,
            membership_id,
            &changed_membership_ids,
        )
        .await?;
        let descendants = changed_membership_ids
            .iter()
            .copied()
            .filter(|affected_id| *affected_id != membership_id)
            .collect::<Vec<_>>();
        super::silicons::touch_membership_projections(
            &mut scope.transaction,
            scope.access.organization_id,
            &descendants,
            None,
        )
        .await?;
    }
    let after_members = fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &changed_membership_ids,
    )
    .await?
    .into_iter()
    .map(|member| (member.id, member))
    .collect::<BTreeMap<_, _>>();
    let after_silicons = if let Some(profile_base) = profile_base.as_deref() {
        super::silicons::fetch_silicons(
            &mut scope.transaction,
            scope.access.organization_id,
            &changed_membership_ids,
            profile_base,
        )
        .await?
        .into_iter()
        .map(|silicon| (silicon.membership_id, silicon))
        .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };
    for affected_id in &changed_membership_ids {
        record_member_mutation(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            if *affected_id == membership_id {
                "membership.directory_updated"
            } else {
                "membership.hierarchy_projection_updated"
            },
            "organization.membership.updated.v1",
            before_members.get(affected_id).ok_or(AppError::Internal {
                category: "directory_membership_before_state",
            })?,
            after_members.get(affected_id).ok_or(AppError::Internal {
                category: "directory_membership_after_state",
            })?,
        )
        .await?;
        if silicon_member {
            super::silicons::record_silicon_change(
                &mut scope.transaction,
                &state,
                &authenticated,
                scope.access.organization_id,
                if *affected_id == membership_id {
                    "silicon.directory_updated"
                } else {
                    "silicon.hierarchy_projection_updated"
                },
                "organization.silicon.updated.v1",
                before_silicons.get(affected_id).ok_or(AppError::Internal {
                    category: "directory_silicon_before_state",
                })?,
                after_silicons.get(affected_id).ok_or(AppError::Internal {
                    category: "directory_silicon_after_state",
                })?,
            )
            .await?;
        }
    }
    let member = after_members
        .get(&membership_id)
        .cloned()
        .ok_or(AppError::Internal {
            category: "directory_member_response",
        })?;
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

pub(super) async fn remove_member(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    Query(query): Query<RemovalQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        MEMBER_REMOVE_ROUTE,
        &membership_id.to_string(),
        &query,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let identity = fetch_membership_identity(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    require_active_version(&identity, expected_version)?;
    require_carbon_removal(&identity)?;
    if identity.org_role == "owner" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("owner_cannot_be_removed"),
        });
    }
    support::require_capability(&scope.access, Capability::MembersRemove)?;
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.authorization_change",
        Some(membership_id),
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let affected_membership_ids = support::lock_membership_removal_event_scope(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        query.reassign_reports_to,
    )
    .await?;
    let before_members = fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &affected_membership_ids,
    )
    .await?;
    let before = before_members
        .iter()
        .find(|member| member.id == membership_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let before_by_id = before_members
        .into_iter()
        .map(|member| (member.id, member))
        .collect::<BTreeMap<_, _>>();
    let version = sqlx::query_scalar::<_, i64>(
        r"
        SELECT membership_version
        FROM iam_private.remove_organization_membership($1, $2, $3, $4, $5)
        ",
    )
    .bind(scope.access.organization_id)
    .bind(membership_id)
    .bind(expected_version)
    .bind(None::<i64>)
    .bind(query.reassign_reports_to)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(support::transition_database)?
    .ok_or(AppError::NotFound)?;
    support::record_application_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "membership.removed",
            target_type: "organization_membership",
            target_id: membership_id,
            aggregate_type: "organization_membership",
            aggregate_id: membership_id,
            aggregate_version: version,
            event_type: "organization.membership.removed.v1",
            before_state: redacted(&before)?,
            after_state: Some(json!({ "status": "removed", "version": version })),
            metadata: json!({
                "membership_id": membership_id,
                "principal_kind": identity.principal_kind,
                "reassign_reports_to": query.reassign_reports_to,
            }),
        },
    )
    .await?;
    let surviving_membership_ids = affected_membership_ids
        .into_iter()
        .filter(|affected_id| *affected_id != membership_id)
        .collect::<Vec<_>>();
    let surviving_members = fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &surviving_membership_ids,
    )
    .await?;
    for member in &surviving_members {
        let before_member = before_by_id.get(&member.id).ok_or(AppError::Internal {
            category: "membership_removal_before_state",
        })?;
        record_member_mutation(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            "membership.removal_side_effect_applied",
            "organization.membership.updated.v1",
            before_member,
            member,
        )
        .await?;
    }
    support::finish_empty(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::NO_CONTENT,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    Ok(support::empty(StatusCode::NO_CONTENT))
}

fn require_carbon_removal(identity: &MembershipIdentity) -> Result<(), AppError> {
    match identity.principal_kind.as_str() {
        "carbon" => Ok(()),
        "silicon" => Err(AppError::Conflict {
            code: Cow::Borrowed("silicon_requires_silicon_endpoint"),
        }),
        _ => Err(AppError::Internal {
            category: "membership_kind",
        }),
    }
}

pub(super) async fn get_member_authorization(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let authorization = fetch_authorization(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &authorization, Some(authorization.version))
}

pub(super) async fn promote_admin(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    change_admin_role(state, authenticated, org_id, membership_id, headers, true).await
}

pub(super) async fn demote_admin(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    change_admin_role(state, authenticated, org_id, membership_id, headers, false).await
}

pub(super) async fn replace_member_capabilities(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, membership_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<CapabilitiesReplace>,
) -> Result<Response, AppError> {
    let capabilities = validation::capabilities(&input)?;
    replace_capabilities(
        state,
        authenticated,
        org_id,
        membership_id,
        headers,
        &input,
        capabilities,
    )
    .await
}

pub(super) async fn list_members_query(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    cursor: Option<Uuid>,
    limit: i64,
    principal_type: Option<&str>,
    tag_id: Option<Uuid>,
    status: Option<&str>,
) -> Result<Vec<MembershipResponse>, AppError> {
    let mut statement = QueryBuilder::<Postgres>::new(MEMBERSHIP_PROJECTION);
    statement
        .push(" WHERE membership.organization_id = ")
        .push_bind(organization_id);
    if let Some(cursor) = cursor {
        statement.push(" AND membership.id > ").push_bind(cursor);
    }
    if let Some(principal_type) = principal_type {
        statement
            .push(" AND membership.principal_kind::text = ")
            .push_bind(principal_type.to_owned());
    }
    if let Some(tag_id) = tag_id {
        statement
            .push(" AND EXISTS (SELECT 1 FROM iam.membership_tags AS filter_tag WHERE filter_tag.organization_id = membership.organization_id AND filter_tag.membership_id = membership.id AND filter_tag.tag_id = ")
            .push_bind(tag_id)
            .push(")");
    }
    if let Some(status) = status {
        statement
            .push(" AND CASE WHEN membership.status = 'active' THEN 'active' ELSE 'removed' END = ")
            .push_bind(status.to_owned());
    }
    statement
        .push(" ORDER BY membership.id LIMIT ")
        .push_bind(limit);
    statement
        .build_query_as::<MembershipResponse>()
        .fetch_all(&mut **transaction)
        .await
        .map_err(support::database)
}

pub(super) async fn fetch_member(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
) -> Result<MembershipResponse, AppError> {
    let mut statement = QueryBuilder::<Postgres>::new(MEMBERSHIP_PROJECTION);
    statement
        .push(" WHERE membership.organization_id = ")
        .push_bind(organization_id)
        .push(" AND membership.id = ")
        .push_bind(membership_id)
        .push(" LIMIT 1");
    statement
        .build_query_as::<MembershipResponse>()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)
}

pub(super) async fn fetch_members(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_ids: &[Uuid],
) -> Result<Vec<MembershipResponse>, AppError> {
    if membership_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut statement = QueryBuilder::<Postgres>::new(MEMBERSHIP_PROJECTION);
    statement
        .push(" WHERE membership.organization_id = ")
        .push_bind(organization_id)
        .push(" AND membership.id = ANY(")
        .push_bind(membership_ids.to_vec())
        .push(") ORDER BY membership.id");
    statement
        .build_query_as::<MembershipResponse>()
        .fetch_all(&mut **transaction)
        .await
        .map_err(support::database)
}

async fn change_admin_role(
    state: ApiState,
    authenticated: Authenticated,
    org_id: String,
    membership_id: Uuid,
    headers: HeaderMap,
    promote: bool,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(
        &scope.access,
        if promote {
            Capability::AdminsCreate
        } else {
            Capability::AdminsManage
        },
    )?;
    let route = if promote {
        MEMBER_PROMOTE_ROUTE
    } else {
        MEMBER_DEMOTE_ROUTE
    };
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        route,
        &membership_id.to_string(),
        &json!({ "promote": promote }),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let identity = fetch_membership_identity(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    require_active_version(&identity, expected_version)?;
    if identity.principal_kind != "carbon"
        || (promote && identity.org_role != "member")
        || (!promote && identity.org_role != "admin")
    {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("membership_role_transition_invalid"),
        });
    }
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.authorization_change",
        Some(membership_id),
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let before = fetch_authorization(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    let resulting_version = sqlx::query_scalar::<_, Option<i64>>(
        r"
        SELECT iam_private.set_organization_admin_role($1, $2, $3, $4)
        ",
    )
    .bind(scope.access.organization_id)
    .bind(membership_id)
    .bind(expected_version)
    .bind(promote)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::transition_database)?
    .ok_or(AppError::NotFound)?;
    if promote {
        grant_default_administrator_capabilities(
            &mut scope.transaction,
            scope.access.organization_id,
            membership_id,
            scope.access.membership_id,
            "administrator promoted",
        )
        .await?;
    }
    let authorization = fetch_authorization(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    debug_assert_eq!(authorization.version, resulting_version);
    record_authorization_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        if promote {
            "admin.promoted"
        } else {
            "admin.demoted"
        },
        if promote {
            "organization.admin.promoted.v1"
        } else {
            "organization.admin.demoted.v1"
        },
        &before,
        &authorization,
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &authorization,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(authorization.version), false)
}

#[allow(clippy::too_many_arguments)]
async fn replace_capabilities(
    state: ApiState,
    authenticated: Authenticated,
    org_id: String,
    membership_id: Uuid,
    headers: HeaderMap,
    request: &CapabilitiesReplace,
    capabilities: Vec<String>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::AdminsManage)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        MEMBER_CAPABILITIES_ROUTE,
        &membership_id.to_string(),
        request,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let identity = fetch_membership_identity(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    require_active_version(&identity, expected_version)?;
    if identity.principal_kind != "carbon" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("capability_principal_type_mismatch"),
        });
    }
    if identity.org_role == "owner" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("owner_capabilities_are_intrinsic"),
        });
    }
    validate_delegation(&mut scope.transaction, &scope.access, &capabilities).await?;
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.authorization_change",
        Some(membership_id),
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let before = fetch_authorization(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    replace_grants(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        scope.access.membership_id,
        &capabilities,
    )
    .await?;
    bump_membership(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        expected_version,
        true,
    )
    .await?;
    let authorization = fetch_authorization(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
    )
    .await?;
    record_authorization_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        "membership.capabilities_replaced",
        "organization.membership.authorization_updated.v1",
        &before,
        &authorization,
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &authorization,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(authorization.version), false)
}

fn authorize_directory_patch(
    access: &crate::infrastructure::postgres::authorization::OrganizationAccess,
    identity: &MembershipIdentity,
    input: &MembershipDirectoryPatch,
) -> Result<(), AppError> {
    match identity.principal_kind.as_str() {
        "carbon" => {
            if input.reports_to_membership_id.is_some() || input.profile_photo.is_some() {
                return Err(validation::field(
                    "body",
                    "contains Silicon-only directory fields",
                ));
            }
            if input.first_silicon_membership_id.is_some()
                || input.extra_silicon_membership_ids.is_some()
            {
                support::require_capability(access, Capability::MembersUpdateDirectory)?;
            }
            if input.default_trust.is_some() {
                support::require_capability(access, Capability::TrustManage)?;
            }
        }
        "silicon" => {
            if input.first_silicon_membership_id.is_some()
                || input.extra_silicon_membership_ids.is_some()
                || input.default_trust.is_some()
            {
                return Err(validation::field(
                    "body",
                    "contains Carbon-only directory fields",
                ));
            }
            if input.profile_photo.is_some() {
                support::require_capability(access, Capability::SiliconsUpdateDirectory)?;
            }
            if input.reports_to_membership_id.is_some() {
                support::require_capability(access, Capability::SiliconsManageHierarchy)?;
            }
        }
        _ => {
            return Err(AppError::Internal {
                category: "membership_kind",
            });
        }
    }
    Ok(())
}

async fn update_carbon_directory(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    actor_membership_id: Uuid,
    input: &MembershipDirectoryPatch,
) -> Result<(), AppError> {
    if let Some(first) = input.first_silicon_membership_id {
        validate_active_silicon(transaction, organization_id, first).await?;
        sqlx::query(
            "UPDATE iam.carbon_membership_settings SET first_silicon_membership_id = $3 WHERE organization_id = $1 AND membership_id = $2",
        )
        .bind(organization_id)
        .bind(membership_id)
        .bind(first)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    }
    if let Some(extra) = input.extra_silicon_membership_ids.as_deref() {
        validate_active_silicons(transaction, organization_id, extra).await?;
        sqlx::query(
            r"
            UPDATE iam.extra_silicon_access_grants
            SET revoked_by_membership_id = $3, revoked_at = transaction_timestamp()
            WHERE organization_id = $1 AND carbon_membership_id = $2 AND revoked_at IS NULL
            ",
        )
        .bind(organization_id)
        .bind(membership_id)
        .bind(actor_membership_id)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
        for silicon_membership_id in extra {
            sqlx::query(
                r"
                INSERT INTO iam.extra_silicon_access_grants (
                    organization_id, carbon_membership_id, silicon_membership_id,
                    granted_by_membership_id
                ) VALUES ($1, $2, $3, $4)
                ",
            )
            .bind(organization_id)
            .bind(membership_id)
            .bind(silicon_membership_id)
            .bind(actor_membership_id)
            .execute(&mut **transaction)
            .await
            .map_err(support::database)?;
        }
    }
    if let Some(default_trust) = input.default_trust {
        let result = sqlx::query(
            r"
            UPDATE iam.carbon_membership_settings
            SET default_trust_boundary = $3::iam.trust_boundary,
                default_trust_level = $4::iam.trust_level
            WHERE organization_id = $1 AND membership_id = $2
            ",
        )
        .bind(organization_id)
        .bind(membership_id)
        .bind(default_trust.boundary.as_str())
        .bind(default_trust.level.as_str())
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
        if result.rows_affected() != 1 {
            return Err(AppError::Internal {
                category: "carbon_membership_settings_missing",
            });
        }
    }
    Ok(())
}

async fn update_silicon_directory(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    input: &MembershipDirectoryPatch,
) -> Result<(), AppError> {
    if let Some(reports_to) = input.reports_to_membership_id {
        validate_active_silicon(transaction, organization_id, reports_to).await?;
    }
    if input.profile_photo.is_some() || input.reports_to_membership_id.is_some() {
        sqlx::query(
            r"
            UPDATE iam.silicons
            SET profile_photo_override_uri = CASE WHEN $3 THEN $4 ELSE profile_photo_override_uri END,
                reports_to_membership_id = CASE WHEN $5 THEN $6 ELSE reports_to_membership_id END
            WHERE organization_id = $1 AND membership_id = $2 AND provisioning_status <> 'deleted'
            ",
        )
        .bind(organization_id)
        .bind(membership_id)
        .bind(input.profile_photo.is_some())
        .bind(input.profile_photo.as_ref().and_then(Clone::clone))
        .bind(input.reports_to_membership_id.is_some())
        .bind(input.reports_to_membership_id.flatten())
        .execute(&mut **transaction)
        .await
        .map_err(|error| support::conflict_from_database(error, "invalid_reporting_hierarchy"))?;
    }
    Ok(())
}

async fn validate_active_silicons(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_ids: &[Uuid],
) -> Result<(), AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM iam.silicons AS silicon
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id
        WHERE silicon.organization_id = $1
          AND silicon.membership_id = ANY($2)
          AND silicon.provisioning_status <> 'deleted'
          AND membership.status = 'active'
        ",
    )
    .bind(organization_id)
    .bind(membership_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(count).ok() != Some(membership_ids.len()) {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("directory_reference_inactive"),
        });
    }
    Ok(())
}

async fn validate_active_silicon(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Option<Uuid>,
) -> Result<(), AppError> {
    if let Some(membership_id) = membership_id {
        validate_active_silicons(transaction, organization_id, &[membership_id]).await?;
    }
    Ok(())
}

/// Grants the capabilities an administrator holds by default.
///
/// UNDERSTANDING.md settles the set: an administrator holds every right except
/// creating or removing other administrators. Those two stay with the owner,
/// and with whoever the owner grants them to explicitly.
///
/// Anything already active is skipped, so applying this twice is harmless --
/// which matters because both a promotion and an ownership transfer land here,
/// and a transfer revokes the outgoing owner's grants on its way past.
pub(super) async fn grant_default_administrator_capabilities(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    granted_by_membership_id: Uuid,
    reason: &'static str,
) -> Result<(), AppError> {
    let defaults = sqlx::query_scalar::<_, String>(
        r"
        SELECT capability
        FROM iam.organization_capability_catalog
        WHERE allowed_for_carbon
          AND capability NOT IN ('admins.create', 'admins.manage')
        ORDER BY capability
        ",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)?;
    for capability in &defaults {
        sqlx::query(
            r"
            INSERT INTO iam.organization_capability_grants (
                id, organization_id, grantee_membership_id, capability,
                granted_by_membership_id, reason
            )
            SELECT $1, $2, $3, $4, $5, $6
            WHERE NOT EXISTS (
                SELECT 1 FROM iam.organization_capability_grants
                WHERE organization_id = $2 AND grantee_membership_id = $3
                  AND capability = $4 AND revoked_at IS NULL
            )
            ",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(membership_id)
        .bind(capability)
        .bind(granted_by_membership_id)
        .bind(reason)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    }
    Ok(())
}

async fn fetch_membership_identity(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
) -> Result<MembershipIdentity, AppError> {
    sqlx::query_as::<_, MembershipIdentity>(
        r"
        SELECT principal_kind::text AS principal_kind,
               org_role::text AS org_role, status, version
        FROM iam.organization_memberships
        WHERE organization_id = $1 AND id = $2
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

fn require_active_version(
    identity: &MembershipIdentity,
    expected_version: i64,
) -> Result<(), AppError> {
    if identity.status != "active" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("membership_not_active"),
        });
    }
    if identity.version != expected_version {
        return Err(precondition_failed());
    }
    Ok(())
}

async fn fetch_authorization(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
) -> Result<MembershipAuthorizationResponse, AppError> {
    sqlx::query_as::<_, MembershipAuthorizationResponse>(
        r"
        SELECT
            membership.id AS membership_id,
            membership.org_role::text AS org_role,
            CASE WHEN membership.principal_kind = 'carbon' THEN ARRAY(
                SELECT grant_record.capability
                FROM iam.organization_capability_grants AS grant_record
                WHERE grant_record.organization_id = membership.organization_id
                  AND grant_record.grantee_membership_id = membership.id
                  AND grant_record.revoked_at IS NULL
                  AND grant_record.capability <> 'audit.read'
                ORDER BY grant_record.capability
            ) ELSE ARRAY[]::text[] END AS capabilities,
            membership.authz_epoch AS authorization_epoch,
            membership.version
        FROM iam.organization_memberships AS membership
        WHERE membership.organization_id = $1 AND membership.id = $2
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn validate_delegation(
    transaction: &mut Transaction<'_, Postgres>,
    access: &crate::infrastructure::postgres::authorization::OrganizationAccess,
    capabilities: &[String],
) -> Result<(), AppError> {
    let allowed = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM iam.organization_capability_catalog AS catalog
        WHERE catalog.capability = ANY($1)
          AND catalog.allowed_for_carbon
          AND ($2 OR catalog.delegable)
        ",
    )
    .bind(capabilities)
    .bind(access.authority.org_role == OrgRole::Owner)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(allowed).ok() != Some(capabilities.len()) {
        return Err(AppError::Forbidden);
    }
    if access.authority.org_role != OrgRole::Owner {
        for capability in capabilities {
            let parsed = capability
                .parse::<Capability>()
                .map_err(|_| AppError::Forbidden)?;
            if !access.authority.allows(parsed) {
                return Err(AppError::Forbidden);
            }
        }
    }
    Ok(())
}

async fn replace_grants(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    actor_membership_id: Uuid,
    capabilities: &[String],
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.organization_capability_grants
        SET revoked_by_membership_id = $3, revoked_at = transaction_timestamp(),
            reason = 'capability set replaced'
        WHERE organization_id = $1 AND grantee_membership_id = $2
          AND revoked_at IS NULL AND NOT (capability = ANY($4))
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .bind(actor_membership_id)
    .bind(capabilities)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    for capability in capabilities {
        sqlx::query(
            r"
            INSERT INTO iam.organization_capability_grants (
                id, organization_id, grantee_membership_id, capability,
                granted_by_membership_id, reason
            )
            SELECT $1, $2, $3, $4, $5, 'capability set replaced'
            WHERE NOT EXISTS (
                SELECT 1 FROM iam.organization_capability_grants
                WHERE organization_id = $2 AND grantee_membership_id = $3
                  AND capability = $4 AND revoked_at IS NULL
            )
            ",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(membership_id)
        .bind(capability)
        .bind(actor_membership_id)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    }
    Ok(())
}

async fn bump_membership(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    expected_version: i64,
    bump_authorization: bool,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET authz_epoch = authz_epoch + CASE WHEN $4 THEN 1 ELSE 0 END,
            updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND id = $2 AND version = $3 AND status = 'active'
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .bind(expected_version)
    .bind(bump_authorization)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "transaction context and the exact before/after member event are kept explicit"
)]
pub(super) async fn record_member_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    organization_id: Uuid,
    action: &'static str,
    event_type: &'static str,
    before: &MembershipResponse,
    after: &MembershipResponse,
) -> Result<(), AppError> {
    support::record_application_mutation(
        transaction,
        state,
        authenticated,
        organization_id,
        MutationEvent {
            action,
            target_type: "organization_membership",
            target_id: after.id,
            aggregate_type: "organization_membership",
            aggregate_id: after.id,
            aggregate_version: after.version,
            event_type,
            before_state: redacted(before)?,
            after_state: redacted(after)?,
            metadata: json!({ "membership_id": after.id }),
        },
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "transaction context and the exact before/after authorization event are kept explicit"
)]
async fn record_authorization_mutation(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    organization_id: Uuid,
    action: &'static str,
    event_type: &'static str,
    before: &MembershipAuthorizationResponse,
    after: &MembershipAuthorizationResponse,
) -> Result<(), AppError> {
    support::record_application_mutation(
        transaction,
        state,
        authenticated,
        organization_id,
        MutationEvent {
            action,
            target_type: "organization_membership",
            target_id: after.membership_id,
            aggregate_type: "organization_membership",
            aggregate_id: after.membership_id,
            aggregate_version: after.version,
            event_type,
            before_state: redacted(before)?,
            after_state: redacted(after)?,
            metadata: json!({ "membership_id": after.membership_id }),
        },
    )
    .await
}

fn validate_member_filters(query: &MemberQuery) -> Result<(), AppError> {
    if query
        .principal_type
        .as_deref()
        .is_some_and(|value| !matches!(value, "carbon" | "silicon"))
    {
        return Err(validation::field(
            "principal_type",
            "must be carbon or silicon",
        ));
    }
    if query
        .status
        .as_deref()
        .is_some_and(|value| !matches!(value, "active" | "removed"))
    {
        return Err(validation::field("status", "must be active or removed"));
    }
    Ok(())
}

fn take_page<T: MembershipPageItem>(items: &mut Vec<T>, limit: i64) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "membership_page_limit",
    })?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_cursor = has_more
        .then(|| items.last().map(MembershipPageItem::membership_id))
        .flatten()
        .map(validation::encode_cursor);
    Ok(PageInfo {
        next_cursor,
        has_more,
    })
}

trait MembershipPageItem {
    fn membership_id(&self) -> Uuid;
}

impl MembershipPageItem for MembershipResponse {
    fn membership_id(&self) -> Uuid {
        self.id
    }
}

fn redacted<T: Serialize>(value: &T) -> Result<Option<serde_json::Value>, AppError> {
    serde_json::to_value(value)
        .map(Some)
        .map_err(|_| AppError::Internal {
            category: "membership_audit_serialize",
        })
}

fn precondition_failed() -> AppError {
    AppError::PreconditionFailed {
        code: Cow::Borrowed("etag_mismatch"),
    }
}

const MEMBERSHIP_PROJECTION: &str = r"
    SELECT
        membership.id,
        organization.org_id,
        jsonb_build_object(
            'principal_id', membership.principal_id,
            'type', membership.principal_kind::text,
            'public_id', CASE
                WHEN membership.principal_kind = 'carbon' THEN carbon.carbon_id
                ELSE silicon.global_silicon_id
            END
        ) AS principal,
        CASE WHEN membership.status = 'active' THEN 'active' ELSE 'removed' END AS status,
        membership.org_role::text AS org_role,
        membership.job_role,
        COALESCE((
            SELECT jsonb_agg(jsonb_build_object('id', tag.id, 'name', tag.name) ORDER BY tag.id)
            FROM iam.membership_tags AS assignment
            JOIN iam.organization_tags AS tag
              ON tag.organization_id = assignment.organization_id
             AND tag.id = assignment.tag_id
            WHERE assignment.organization_id = membership.organization_id
              AND assignment.membership_id = membership.id
              AND tag.status = 'active'
        ), '[]'::jsonb) AS tags,
        carbon_settings.first_silicon_membership_id,
        CASE WHEN membership.principal_kind = 'carbon' THEN ARRAY(
            SELECT access_grant.silicon_membership_id
            FROM iam.extra_silicon_access_grants AS access_grant
            WHERE access_grant.organization_id = membership.organization_id
              AND access_grant.carbon_membership_id = membership.id
              AND access_grant.revoked_at IS NULL
            ORDER BY access_grant.silicon_membership_id
        ) ELSE ARRAY[]::uuid[] END AS extra_silicons,
        CASE WHEN carbon_settings.membership_id IS NOT NULL THEN jsonb_build_object(
            'boundary', carbon_settings.default_trust_boundary::text,
            'level', carbon_settings.default_trust_level::text
        ) ELSE NULL END AS default_trust,
        silicon.reports_to_membership_id,
        CASE WHEN silicon.id IS NULL THEN NULL ELSE (
            WITH RECURSIVE ancestors AS (
                SELECT parent.membership_id, parent.reports_to_membership_id
                FROM iam.silicons AS parent
                WHERE parent.organization_id = membership.organization_id
                  AND parent.membership_id = silicon.membership_id
                UNION
                SELECT parent.membership_id, parent.reports_to_membership_id
                FROM iam.silicons AS parent
                JOIN ancestors ON ancestors.reports_to_membership_id = parent.membership_id
                WHERE parent.organization_id = membership.organization_id
            )
            SELECT count(*)::integer FROM ancestors
        ) END AS hierarchy_level,
        membership.authz_epoch AS authorization_epoch,
        membership.removed_at,
        membership.version,
        membership.joined_at AS created_at,
        membership.updated_at
    FROM iam.organization_memberships AS membership
    JOIN iam.organizations AS organization ON organization.id = membership.organization_id
    LEFT JOIN iam.carbons AS carbon
      ON carbon.id = membership.principal_id AND membership.principal_kind = 'carbon'
    LEFT JOIN iam.silicons AS silicon
      ON silicon.id = membership.principal_id AND membership.principal_kind = 'silicon'
    LEFT JOIN iam.carbon_membership_settings AS carbon_settings
      ON carbon_settings.organization_id = membership.organization_id
     AND carbon_settings.membership_id = membership.id
";

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        domain::organization::{OrgRole, OrganizationAuthority},
        infrastructure::postgres::authorization::OrganizationAccess,
    };

    use super::*;
    use crate::features::organizations::model::{TrustBoundary, TrustLevel, TrustValue};

    fn access(capabilities: impl IntoIterator<Item = Capability>) -> OrganizationAccess {
        OrganizationAccess {
            organization_id: Uuid::from_u128(1),
            membership_id: Uuid::from_u128(2),
            authority: OrganizationAuthority {
                org_role: OrgRole::Member,
                capabilities: capabilities.into_iter().collect::<HashSet<_>>(),
            },
        }
    }

    fn default_trust_patch() -> MembershipDirectoryPatch {
        MembershipDirectoryPatch {
            tag_ids: None,
            first_silicon_membership_id: None,
            extra_silicon_membership_ids: None,
            default_trust: Some(TrustValue {
                boundary: TrustBoundary::External,
                level: TrustLevel::NeedsApproval,
            }),
            reports_to_membership_id: None,
            profile_photo: None,
        }
    }

    fn identity(principal_kind: &str) -> MembershipIdentity {
        MembershipIdentity {
            principal_kind: principal_kind.to_owned(),
            org_role: "member".to_owned(),
            status: "active".to_owned(),
            version: 1,
        }
    }

    #[test]
    fn carbon_default_trust_requires_only_trust_manage_for_that_field() {
        assert!(
            authorize_directory_patch(
                &access([Capability::TrustManage]),
                &identity("carbon"),
                &default_trust_patch(),
            )
            .is_ok()
        );
        assert!(matches!(
            authorize_directory_patch(
                &access([Capability::MembersUpdateDirectory]),
                &identity("carbon"),
                &default_trust_patch(),
            ),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn silicon_directory_patch_rejects_carbon_default_trust() {
        assert!(matches!(
            authorize_directory_patch(
                &access([Capability::TrustManage]),
                &identity("silicon"),
                &default_trust_patch(),
            ),
            Err(AppError::Validation { .. })
        ));
    }

    #[test]
    fn generic_member_removal_is_carbon_only() {
        assert!(require_carbon_removal(&identity("carbon")).is_ok());
        assert!(matches!(
            require_carbon_removal(&identity("silicon")),
            Err(AppError::Conflict { code }) if code == "silicon_requires_silicon_endpoint"
        ));
    }
}
