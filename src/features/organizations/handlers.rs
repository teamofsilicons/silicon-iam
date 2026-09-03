#![allow(clippy::too_many_lines)]

use std::{borrow::Cow, collections::BTreeMap, num::NonZeroU32, time::Duration};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use secrecy::SecretString;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::organization::{Capability, OrgRole},
    error::AppError,
    infrastructure::postgres::{
        context::{self, DatabaseContext},
        rate_limit::{self, RateLimitPolicy},
        step_up::RequiredAssurance,
    },
};

use super::{
    model::{
        AvailabilityResponse, MembershipPage, MembershipResponse, OrganizationCreate,
        OrganizationPage, OrganizationPatch, OrganizationResponse, OwnershipTransfer, PageInfo,
        PageQuery, SiliconResponse, TagInput, TagPage, TagResponse,
    },
    support::{self, Claim, MutationEvent},
    validation,
};

const ORGANIZATION_CREATE_ROUTE: &str = "POST /api/v1/organizations";
const ORGANIZATION_UPDATE_ROUTE: &str = "PATCH /api/v1/organizations/{org_id}";
const OWNERSHIP_TRANSFER_ROUTE: &str = "POST /api/v1/organizations/{org_id}/ownership-transfers";
const TAG_CREATE_ROUTE: &str = "POST /api/v1/organizations/{org_id}/tags";
const TAG_UPDATE_ROUTE: &str = "PATCH /api/v1/organizations/{org_id}/tags/{tag_id}";

struct TagWebhookScope {
    assigned_membership_ids: Vec<Uuid>,
}

pub(super) async fn organization_id_availability(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
) -> Result<Response, AppError> {
    support::require_carbon(&authenticated)?;
    let org_id = validation::organization_id(&org_id)?.to_string();
    enforce_actor_rate_limit(&state, &authenticated, "organization_id_availability").await?;

    let mut transaction = context::begin(
        state.db(),
        DatabaseContext::principal(authenticated.0.subject.id),
    )
    .await
    .map_err(support::database)?;
    let available =
        sqlx::query_scalar::<_, bool>("SELECT iam_private.organization_handle_is_available($1)")
            .bind(org_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(support::database)?;
    transaction.commit().await.map_err(support::database)?;
    support::json(StatusCode::OK, &AvailabilityResponse { available }, None)
}

pub(super) async fn list_organizations(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Query(query): Query<PageQuery>,
) -> Result<Response, AppError> {
    let carbon_id = support::require_carbon(&authenticated)?;
    let (cursor, limit) = validation::page(&query)?;
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(support::database)?;
    let mut organizations = sqlx::query_as::<_, OrganizationResponse>(
        r"
        SELECT
            organization.id,
            organization.org_id,
            organization.name,
            organization.logo_uri AS logo,
            organization.description,
            owner.id AS owner_membership_id,
            organization.join_method,
            COALESCE(sso.status, 'disabled') AS sso_status,
            CASE WHEN organization.status = 'active' THEN 'active' ELSE 'disabled' END AS status,
            organization.version,
            organization.created_at,
            organization.updated_at
        FROM iam.organizations AS organization
        JOIN iam.organization_memberships AS owner
          ON owner.organization_id = organization.id
         AND owner.org_role = 'owner'
         AND owner.status = 'active'
        LEFT JOIN iam.organization_sso_configs AS sso
          ON sso.organization_id = organization.id
        JOIN iam.organization_memberships AS caller_membership
          ON caller_membership.organization_id = organization.id
         AND caller_membership.principal_id = $1
        WHERE caller_membership.status = 'active'
          AND ($2::uuid IS NULL OR organization.id > $2)
        ORDER BY organization.id
        LIMIT $3
        ",
    )
    .bind(carbon_id)
    .bind(cursor)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(support::database)?;
    transaction.commit().await.map_err(support::database)?;
    let page = take_page(&mut organizations, limit)?;
    support::json(
        StatusCode::OK,
        &OrganizationPage {
            items: organizations,
            page,
        },
        None,
    )
}

pub(super) async fn create_organization(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
    Json(mut input): Json<OrganizationCreate>,
) -> Result<Response, AppError> {
    let carbon_id = support::require_carbon(&authenticated)?;
    validation::organization_create(&mut input, state.settings.environment)?;

    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(support::database)?;
    let lease = match support::claim(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        ORGANIZATION_CREATE_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    enforce_actor_rate_limit(&state, &authenticated, "organization_create").await?;

    let organization_id = Uuid::now_v7();
    let owner_membership_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.organizations (
            id, org_id, created_by_carbon_id, name, logo_uri, description
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(organization_id)
    .bind(&input.org_id)
    .bind(carbon_id)
    .bind(&input.name)
    .bind(&input.logo)
    .bind(&input.description)
    .execute(&mut *transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "organization_id_unavailable"))?;
    context::select_organization(&mut transaction, organization_id)
        .await
        .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.organization_memberships (
            id, organization_id, principal_id, principal_kind, org_role
        ) VALUES ($1, $2, $3, 'carbon', 'owner')
        ",
    )
    .bind(owner_membership_id)
    .bind(organization_id)
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.carbon_membership_settings (
            organization_id, membership_id, carbon_id
        ) VALUES ($1, $2, $3)
        ",
    )
    .bind(organization_id)
    .bind(owner_membership_id)
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(support::database)?;

    let organization = fetch_organization(&mut transaction, organization_id).await?;
    support::record_mutation(
        &mut transaction,
        &authenticated,
        organization_id,
        MutationEvent {
            action: "organization.created",
            target_type: "organization",
            target_id: organization_id,
            aggregate_type: "organization",
            aggregate_id: organization_id,
            aggregate_version: organization.version,
            event_type: "organization.created.v1",
            before_state: None,
            after_state: redacted_value(&organization)?,
            metadata: json!({ "org_id": organization.org_id }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &organization,
    )
    .await?;
    transaction.commit().await.map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, Some(organization.version), false)
}

pub(super) async fn get_organization(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let organization =
        fetch_organization(&mut scope.transaction, scope.access.organization_id).await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &organization, Some(organization.version))
}

pub(super) async fn update_organization(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<OrganizationPatch>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validation::organization_patch(&mut input, state.settings.environment)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::OrganizationUpdate)?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        ORGANIZATION_UPDATE_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let before = fetch_organization(&mut scope.transaction, scope.access.organization_id).await?;
    if before.version != expected_version {
        return Err(precondition_failed());
    }
    if input.join_method.as_deref() == Some("sso") {
        let ready = sqlx::query_scalar::<_, bool>(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM iam.organization_sso_configs AS config
                JOIN iam.sso_connections AS connection
                  ON connection.organization_id = config.organization_id
                 AND connection.status = 'active'
                WHERE config.organization_id = $1
                  AND config.platform_enabled
                  AND config.status = 'active'
            )
            ",
        )
        .bind(scope.access.organization_id)
        .fetch_one(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
        if !ready {
            return Err(AppError::Conflict {
                code: Cow::Borrowed("sso_not_ready"),
            });
        }
    }
    let result = sqlx::query(
        r"
        UPDATE iam.organizations
        SET name = COALESCE($2, name),
            logo_uri = CASE WHEN $3 THEN $4 ELSE logo_uri END,
            description = CASE WHEN $5 THEN $6 ELSE description END,
            join_method = COALESCE($7, join_method)
        WHERE id = $1 AND version = $8
        ",
    )
    .bind(scope.access.organization_id)
    .bind(&input.name)
    .bind(input.logo.is_some())
    .bind(input.logo.as_ref().and_then(Clone::clone))
    .bind(input.description.is_some())
    .bind(input.description.as_ref().and_then(Clone::clone))
    .bind(&input.join_method)
    .bind(expected_version)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    let organization =
        fetch_organization(&mut scope.transaction, scope.access.organization_id).await?;
    support::record_application_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "organization.updated",
            target_type: "organization",
            target_id: organization.id,
            aggregate_type: "organization",
            aggregate_id: organization.id,
            aggregate_version: organization.version,
            event_type: "organization.updated.v1",
            before_state: redacted_value(&before)?,
            after_state: redacted_value(&organization)?,
            metadata: json!({ "org_id": organization.org_id }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &organization,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(organization.version), false)
}

pub(super) async fn transfer_ownership(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<OwnershipTransfer>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        OWNERSHIP_TRANSFER_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    if scope.access.authority.org_role != OrgRole::Owner {
        return Err(AppError::Forbidden);
    }
    let before = fetch_organization(&mut scope.transaction, scope.access.organization_id).await?;
    if before.version != expected_version {
        return Err(precondition_failed());
    }
    if input.new_owner_membership_id == scope.access.membership_id {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("owner_already_assigned"),
        });
    }
    let eligible = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM iam.organization_memberships
            WHERE organization_id = $1 AND id = $2
              AND principal_kind = 'carbon' AND status = 'active'
              AND org_role IN ('member', 'admin')
        )
        ",
    )
    .bind(scope.access.organization_id)
    .bind(input.new_owner_membership_id)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if !eligible {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("new_owner_ineligible"),
        });
    }
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.transfer_ownership",
        Some(scope.access.organization_id),
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let ownership_membership_ids = [scope.access.membership_id, input.new_owner_membership_id];
    let locked_membership_ids = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT membership.id
        FROM iam.organization_memberships AS membership
        WHERE membership.organization_id = $1
          AND membership.id = ANY($2)
          AND membership.status = 'active'
        ORDER BY membership.id
        FOR UPDATE OF membership
        ",
    )
    .bind(scope.access.organization_id)
    .bind(ownership_membership_ids)
    .fetch_all(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if locked_membership_ids.len() != ownership_membership_ids.len() {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("new_owner_ineligible"),
        });
    }
    let membership_before = super::directory::fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &ownership_membership_ids,
    )
    .await?
    .into_iter()
    .map(|member| (member.id, member))
    .collect::<BTreeMap<_, _>>();

    let bumped = sqlx::query(
        "UPDATE iam.organizations SET updated_at = transaction_timestamp() WHERE id = $1 AND version = $2",
    )
    .bind(scope.access.organization_id)
    .bind(expected_version)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if bumped.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    sqlx::query(
        r"
        UPDATE iam.organization_capability_grants
        SET revoked_by_membership_id = $3, revoked_at = transaction_timestamp(),
            reason = 'ownership transferred'
        WHERE organization_id = $1 AND grantee_membership_id = $2 AND revoked_at IS NULL
        ",
    )
    .bind(scope.access.organization_id)
    .bind(input.new_owner_membership_id)
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.organization_capability_grants (
            id, organization_id, grantee_membership_id, capability,
            granted_by_membership_id, reason
        )
        SELECT $1, $2, $3, 'admins.manage', $3, 'temporary ownership transfer guard'
        WHERE NOT EXISTS (
            SELECT 1 FROM iam.organization_capability_grants
            WHERE organization_id = $2 AND grantee_membership_id = $3
              AND capability = 'admins.manage' AND revoked_at IS NULL
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(scope.access.organization_id)
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET org_role = 'admin', role_granted_by_membership_id = $3,
            authz_epoch = authz_epoch + 1
        WHERE organization_id = $1 AND id = $2 AND org_role = 'owner' AND status = 'active'
        ",
    )
    .bind(scope.access.organization_id)
    .bind(scope.access.membership_id)
    .bind(input.new_owner_membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    let promoted = sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET org_role = 'owner', role_granted_by_membership_id = NULL,
            authz_epoch = authz_epoch + 1
        WHERE organization_id = $1 AND id = $2 AND principal_kind = 'carbon'
          AND status = 'active'
        ",
    )
    .bind(scope.access.organization_id)
    .bind(input.new_owner_membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if promoted.rows_affected() != 1 {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("new_owner_ineligible"),
        });
    }
    sqlx::query(
        r"
        UPDATE iam.organization_capability_grants
        SET revoked_by_membership_id = $4, revoked_at = transaction_timestamp(),
            reason = 'ownership transferred'
        WHERE organization_id = $1
          AND grantee_membership_id IN ($2, $3)
          AND revoked_at IS NULL
        ",
    )
    .bind(scope.access.organization_id)
    .bind(scope.access.membership_id)
    .bind(input.new_owner_membership_id)
    .bind(input.new_owner_membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;

    let membership_after = super::directory::fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &ownership_membership_ids,
    )
    .await?;
    for member in &membership_after {
        let before_member = membership_before
            .get(&member.id)
            .ok_or(AppError::Internal {
                category: "ownership_membership_before_state",
            })?;
        super::directory::record_member_mutation(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            "membership.ownership_role_updated",
            "organization.membership.updated.v1",
            before_member,
            member,
        )
        .await?;
    }

    let organization =
        fetch_organization(&mut scope.transaction, scope.access.organization_id).await?;
    support::record_application_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "organization.ownership_transferred",
            target_type: "organization",
            target_id: organization.id,
            aggregate_type: "organization",
            aggregate_id: organization.id,
            aggregate_version: organization.version,
            event_type: "organization.ownership_transferred.v1",
            before_state: redacted_value(&before)?,
            after_state: redacted_value(&organization)?,
            metadata: json!({
                "previous_owner_membership_id": scope.access.membership_id,
                "new_owner_membership_id": input.new_owner_membership_id,
            }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &organization,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(organization.version), false)
}

pub(super) async fn list_tags(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (cursor, limit) = validation::page(&query)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let mut tags = sqlx::query_as::<_, TagResponse>(
        r"
        SELECT
            tag.id,
            tag.name,
            organization.org_id,
            tag.version,
            tag.created_at,
            tag.updated_at
        FROM iam.organization_tags AS tag
        JOIN iam.organizations AS organization ON organization.id = tag.organization_id
        WHERE tag.organization_id = $1
          AND tag.status = 'active'
          AND ($2::uuid IS NULL OR tag.id > $2)
        ORDER BY tag.id
        LIMIT $3
        ",
    )
    .bind(scope.access.organization_id)
    .bind(cursor)
    .bind(limit + 1)
    .fetch_all(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_page(&mut tags, limit)?;
    support::json(StatusCode::OK, &TagPage { items: tags, page }, None)
}

pub(super) async fn create_tag(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<TagInput>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let normalized_name = validation::tag(&mut input)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::TagsManage)?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        TAG_CREATE_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let tag_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.organization_tags (
            id, organization_id, name, normalized_name, created_by_membership_id
        ) VALUES ($1, $2, $3, $4, $5)
        ",
    )
    .bind(tag_id)
    .bind(scope.access.organization_id)
    .bind(&input.name)
    .bind(normalized_name)
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "tag_name_exists"))?;
    let tag = fetch_tag(&mut scope.transaction, scope.access.organization_id, tag_id).await?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "tag.created",
            target_type: "tag",
            target_id: tag.id,
            aggregate_type: "organization_tag",
            aggregate_id: tag.id,
            aggregate_version: tag.version,
            event_type: "organization.tag_created.v1",
            before_state: None,
            after_state: redacted_value(&tag)?,
            metadata: json!({ "tag_id": tag.id, "name": tag.name }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &tag,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, Some(tag.version), false)
}

pub(super) async fn get_tag(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, tag_id)): Path<(String, Uuid)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let tag = fetch_tag(&mut scope.transaction, scope.access.organization_id, tag_id).await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &tag, Some(tag.version))
}

pub(super) async fn update_tag(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, tag_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(mut input): Json<TagInput>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let normalized_name = validation::tag(&mut input)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::TagsManage)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        TAG_UPDATE_ROUTE,
        &tag_id.to_string(),
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let before = fetch_tag(&mut scope.transaction, scope.access.organization_id, tag_id).await?;
    if before.version != expected_version {
        return Err(precondition_failed());
    }
    let webhook_scope = lock_tag_webhook_scope(
        &mut scope.transaction,
        scope.access.organization_id,
        tag_id,
        expected_version,
    )
    .await?;
    let result = sqlx::query(
        r"
        UPDATE iam.organization_tags
        SET name = $3, normalized_name = $4
        WHERE organization_id = $1 AND id = $2 AND version = $5 AND status = 'active'
        ",
    )
    .bind(scope.access.organization_id)
    .bind(tag_id)
    .bind(&input.name)
    .bind(normalized_name)
    .bind(expected_version)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "tag_name_exists"))?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    let tag = fetch_tag(&mut scope.transaction, scope.access.organization_id, tag_id).await?;
    support::record_application_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "tag.updated",
            target_type: "tag",
            target_id: tag.id,
            aggregate_type: "organization_tag",
            aggregate_id: tag.id,
            aggregate_version: tag.version,
            event_type: "organization.tag_updated.v1",
            before_state: redacted_value(&before)?,
            after_state: redacted_value(&tag)?,
            metadata: json!({
                "tag_id": tag.id,
                "affected_membership_ids": webhook_scope.assigned_membership_ids,
                "tag_assignment_membership_ids": webhook_scope.assigned_membership_ids,
                "before_tag_membership_ids": webhook_scope.assigned_membership_ids,
            }),
        },
    )
    .await?;
    let body =
        support::finish_json(&mut scope.transaction, &state, lease, StatusCode::OK, &tag).await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(tag.version), false)
}

pub(super) async fn list_tag_members(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, tag_id)): Path<(String, Uuid)>,
    Query(query): Query<PageQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (cursor, limit) = validation::page(&query)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    fetch_tag(&mut scope.transaction, scope.access.organization_id, tag_id).await?;
    let mut members = super::directory::list_members_query(
        &mut scope.transaction,
        scope.access.organization_id,
        cursor,
        limit + 1,
        None,
        Some(tag_id),
        Some("active"),
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_page(&mut members, limit)?;
    support::json(
        StatusCode::OK,
        &MembershipPage {
            items: members,
            page,
        },
        None,
    )
}

async fn fetch_tag(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    tag_id: Uuid,
) -> Result<TagResponse, AppError> {
    sqlx::query_as::<_, TagResponse>(
        r"
        SELECT
            tag.id,
            tag.name,
            organization.org_id,
            tag.version,
            tag.created_at,
            tag.updated_at
        FROM iam.organization_tags AS tag
        JOIN iam.organizations AS organization ON organization.id = tag.organization_id
        WHERE tag.organization_id = $1 AND tag.id = $2 AND tag.status = 'active'
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(tag_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn lock_tag_webhook_scope(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    tag_id: Uuid,
    expected_version: i64,
) -> Result<TagWebhookScope, AppError> {
    // Match governed tag-assignment lock order: membership rows first, then
    // tag rows. The second pass captures an assignment that committed before
    // the tag lock was acquired; later additions block on that tag lock.
    let _initial_assigned_membership_ids =
        lock_tag_memberships(transaction, organization_id, tag_id).await?;
    let locked_tag_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT tag.id
        FROM iam.organization_tags AS tag
        WHERE tag.organization_id = $1
          AND tag.id = $2
          AND tag.version = $3
          AND tag.status = 'active'
        FOR UPDATE OF tag
        ",
    )
    .bind(organization_id)
    .bind(tag_id)
    .bind(expected_version)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?;
    if locked_tag_id.is_none() {
        return Err(precondition_failed());
    }

    let assigned_membership_ids =
        lock_tag_memberships(transaction, organization_id, tag_id).await?;
    Ok(TagWebhookScope {
        assigned_membership_ids,
    })
}

async fn lock_tag_memberships(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    tag_id: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT assignment.membership_id
        FROM iam.membership_tags AS assignment
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = assignment.organization_id
         AND membership.id = assignment.membership_id
         AND membership.status = 'active'
        WHERE assignment.organization_id = $1
          AND assignment.tag_id = $2
        ORDER BY assignment.membership_id
        FOR SHARE OF assignment, membership
        ",
    )
    .bind(organization_id)
    .bind(tag_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)
}

async fn fetch_organization(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<OrganizationResponse, AppError> {
    sqlx::query_as::<_, OrganizationResponse>(
        r"
        SELECT
            organization.id,
            organization.org_id,
            organization.name,
            organization.logo_uri AS logo,
            organization.description,
            owner.id AS owner_membership_id,
            organization.join_method,
            COALESCE(sso.status, 'disabled') AS sso_status,
            CASE WHEN organization.status = 'active' THEN 'active' ELSE 'disabled' END AS status,
            organization.version,
            organization.created_at,
            organization.updated_at
        FROM iam.organizations AS organization
        JOIN iam.organization_memberships AS owner
          ON owner.organization_id = organization.id
         AND owner.org_role = 'owner'
         AND owner.status = 'active'
        LEFT JOIN iam.organization_sso_configs AS sso
          ON sso.organization_id = organization.id
        WHERE organization.id = $1
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn enforce_actor_rate_limit(
    state: &ApiState,
    authenticated: &Authenticated,
    name: &'static str,
) -> Result<(), AppError> {
    let maximum = NonZeroU32::new(30).ok_or(AppError::Internal {
        category: "organization_rate_limit_policy",
    })?;
    let policy = RateLimitPolicy::new(maximum, Duration::from_secs(60), Duration::from_secs(60))
        .map_err(|_| AppError::Internal {
            category: "organization_rate_limit_policy",
        })?;
    let scope = SecretString::from(format!(
        "{}:{}",
        authenticated.0.subject.actor_type.as_str(),
        authenticated.0.subject.id
    ));
    rate_limit::enforce(state.db(), &state.crypto, name, &scope, policy).await?;
    Ok(())
}

fn take_page<T: PageItem>(items: &mut Vec<T>, limit: i64) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "organization_page_limit",
    })?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_cursor = if has_more {
        items
            .last()
            .map(|item| validation::encode_cursor(item.id()))
    } else {
        None
    };
    Ok(PageInfo {
        next_cursor,
        has_more,
    })
}

trait PageItem {
    fn id(&self) -> Uuid;
}

impl PageItem for OrganizationResponse {
    fn id(&self) -> Uuid {
        self.id
    }
}

impl PageItem for TagResponse {
    fn id(&self) -> Uuid {
        self.id
    }
}

impl PageItem for MembershipResponse {
    fn id(&self) -> Uuid {
        self.id
    }
}

impl PageItem for SiliconResponse {
    fn id(&self) -> Uuid {
        self.principal_id
    }
}

fn redacted_value<T: Serialize>(value: &T) -> Result<Option<Value>, AppError> {
    serde_json::to_value(value)
        .map(Some)
        .map_err(|_| AppError::Internal {
            category: "organization_audit_serialize",
        })
}

fn precondition_failed() -> AppError {
    AppError::PreconditionFailed {
        code: Cow::Borrowed("etag_mismatch"),
    }
}
