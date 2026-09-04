#![allow(clippy::too_many_lines)]

use std::{borrow::Cow, collections::BTreeMap};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use secrecy::ExposeSecret as _;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::organization::Capability,
    error::AppError,
    infrastructure::{crypto::DigestPurpose, postgres::step_up::RequiredAssurance},
};

use super::{
    model::{
        PageInfo, RemovalQuery, SiliconCreate, SiliconCreatedResponse, SiliconPage, SiliconPatch,
        SiliconQuery, SiliconResponse,
    },
    support::{self, Claim, MutationEvent},
    validation,
};

const SILICON_CREATE_ROUTE: &str = "POST /api/v1/organizations/{org_id}/silicons";
const SILICON_UPDATE_ROUTE: &str = "PATCH /api/v1/organizations/{org_id}/silicons/{silicon_id}";
const SILICON_REMOVE_ROUTE: &str = "DELETE /api/v1/organizations/{org_id}/silicons/{silicon_id}";

#[derive(Clone, Debug, sqlx::FromRow)]
struct SiliconIdentity {
    principal_id: Uuid,
    membership_id: Uuid,
    version: i64,
    membership_version: i64,
    status: String,
}

pub(super) async fn list_silicons(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<SiliconQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (cursor, limit) = validation::page_parts(query.cursor.as_deref(), query.limit)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let profile_base = silicon_profile_base(&state)?;
    let mut items = sqlx::query_as::<_, SiliconResponse>(SILICON_LIST_SQL)
        .bind(scope.access.organization_id)
        .bind(cursor)
        .bind(limit + 1)
        .bind(query.tag_id)
        .bind(profile_base)
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_page(&mut items, limit)?;
    support::json(StatusCode::OK, &SiliconPage { items, page }, None)
}

pub(super) async fn create_silicon(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<SiliconCreate>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validation::silicon_create(&mut input, state.settings.environment)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::SiliconsCreate)?;
    if !input.tag_ids.is_empty() {
        support::require_capability(&scope.access, Capability::TagsManage)?;
    }
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        SILICON_CREATE_ROUTE,
        &input,
        true,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    validate_references(
        &mut scope.transaction,
        scope.access.organization_id,
        &input.tag_ids,
        input.reports_to_membership_id,
    )
    .await?;
    let token = state
        .crypto
        .generate_silicon_token()
        .map_err(|_| AppError::Internal {
            category: "silicon_token_generate",
        })?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::SiliconCredential, &token)
        .map_err(|_| AppError::Internal {
            category: "silicon_token_digest",
        })?;
    let principal_id = Uuid::now_v7();
    let membership_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.principals (id, kind, status, activated_at)
        VALUES ($1, 'silicon', 'active', transaction_timestamp())
        ",
    )
    .bind(principal_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.organization_memberships (
            id, organization_id, principal_id, principal_kind, job_role
        ) VALUES ($1, $2, $3, 'silicon', $4)
        ",
    )
    .bind(membership_id)
    .bind(scope.access.organization_id)
    .bind(principal_id)
    .bind(&input.job_role)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "silicon_id_unavailable"))?;
    sqlx::query(
        r"
        INSERT INTO iam.silicons (
            id, organization_id, membership_id, organization_handle,
            silicon_handle, display_name, timezone_id, description,
            profile_photo_override_uri, reports_to_membership_id, provisioning_status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active')
        ",
    )
    .bind(principal_id)
    .bind(scope.access.organization_id)
    .bind(membership_id)
    .bind(&org_id)
    .bind(&input.silicon_id)
    .bind(input.display_name.as_deref())
    .bind(input.timezone.as_deref())
    .bind(input.description.as_deref())
    .bind(&input.profile_photo)
    .bind(input.reports_to_membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "silicon_id_unavailable"))?;
    let prefix = token.expose_secret().get(..12).ok_or(AppError::Internal {
        category: "silicon_token_prefix",
    })?;
    sqlx::query(
        r"
        INSERT INTO iam.silicon_credentials (
            id, organization_id, silicon_id, credential_prefix, secret_digest,
            pepper_key_version, created_by_membership_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(scope.access.organization_id)
    .bind(principal_id)
    .bind(prefix)
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    assign_tags(
        &mut scope.transaction,
        scope.access.organization_id,
        membership_id,
        scope.access.membership_id,
        &input.tag_ids,
    )
    .await?;
    let silicon = fetch_silicon(
        &mut scope.transaction,
        scope.access.organization_id,
        &format!("{}:{org_id}", input.silicon_id),
        &silicon_profile_base(&state)?,
    )
    .await?;
    let secret_replay_expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
    let response = SiliconCreatedResponse {
        silicon,
        silicon_token: token.expose_secret().to_owned(),
        secret_replay_expires_at,
    };
    let integration_projection =
        serde_json::to_value(&response.silicon).map_err(|_| AppError::Internal {
            category: "silicon_event_serialize",
        })?;
    support::record_application_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "silicon.created",
            target_type: "silicon",
            target_id: principal_id,
            aggregate_type: "silicon",
            aggregate_id: principal_id,
            aggregate_version: response.silicon.version,
            event_type: "organization.silicon.created.v1",
            before_state: None,
            // Serialize only the secret-free directory representation. The
            // one-time Silicon credential exists solely in the HTTP response.
            after_state: Some(integration_projection),
            metadata: json!({
                "silicon_id": principal_id,
                "membership_id": membership_id,
                "subject_principal_id": principal_id,
            }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &response,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, None, true)
}

pub(super) async fn get_silicon(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon_id(&silicon_id, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let silicon = fetch_silicon(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
        &silicon_profile_base(&state)?,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &silicon, Some(silicon.version))
}

pub(super) async fn update_silicon(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(mut input): Json<SiliconPatch>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon_id(&silicon_id, &org_id)?;
    validation::silicon_patch(&mut input, state.settings.environment)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        SILICON_UPDATE_ROUTE,
        &silicon_id,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let identity = fetch_identity(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    require_active_version(&identity, expected_version)?;
    let edits_own_profile = authenticated.0.subject.actor_type
        == crate::domain::actor::ActorType::Silicon
        && authenticated.0.subject.id == identity.principal_id
        && scope.access.membership_id == identity.membership_id;
    if (input.display_name.is_some()
        || input.timezone.is_some()
        || input.description.is_some()
        || input.profile_photo.is_some())
        && !edits_own_profile
    {
        support::require_capability(&scope.access, Capability::SiliconsUpdateDirectory)?;
    }
    if input.reports_to_membership_id.is_some() {
        support::require_capability(&scope.access, Capability::SiliconsManageHierarchy)?;
    }
    let hierarchy_change = input.reports_to_membership_id.is_some();
    let affected_membership_ids = lock_hierarchy_subtree(
        &mut scope.transaction,
        scope.access.organization_id,
        identity.membership_id,
        hierarchy_change,
    )
    .await?;
    validate_references(
        &mut scope.transaction,
        scope.access.organization_id,
        &[],
        input.reports_to_membership_id.flatten(),
    )
    .await?;
    let profile_base = silicon_profile_base(&state)?;
    let before_silicons = fetch_silicons(
        &mut scope.transaction,
        scope.access.organization_id,
        &affected_membership_ids,
        &profile_base,
    )
    .await?;
    let before_silicons = before_silicons
        .into_iter()
        .map(|silicon| (silicon.membership_id, silicon))
        .collect::<BTreeMap<_, _>>();
    let before_members = super::directory::fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &affected_membership_ids,
    )
    .await?
    .into_iter()
    .map(|member| (member.id, member))
    .collect::<BTreeMap<_, _>>();
    let result = sqlx::query(
        r"
        UPDATE iam.silicons
        SET display_name = COALESCE($4, display_name),
            timezone_id = COALESCE($5, timezone_id),
            description = CASE WHEN $6 THEN $7 ELSE description END,
            profile_photo_override_uri = CASE WHEN $8 THEN $9 ELSE profile_photo_override_uri END,
            reports_to_membership_id = CASE WHEN $10 THEN $11 ELSE reports_to_membership_id END,
            updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND id = $2 AND version = $3
          AND provisioning_status <> 'deleted'
          AND (
              ($4::text IS NOT NULL AND display_name IS DISTINCT FROM $4)
              OR ($5::text IS NOT NULL AND timezone_id IS DISTINCT FROM $5)
              OR ($6 AND description IS DISTINCT FROM $7)
              OR ($8 AND profile_photo_override_uri IS DISTINCT FROM $9)
              OR ($10 AND reports_to_membership_id IS DISTINCT FROM $11)
          )
        ",
    )
    .bind(scope.access.organization_id)
    .bind(identity.principal_id)
    .bind(expected_version)
    .bind(input.display_name.as_deref())
    .bind(input.timezone.as_deref())
    .bind(input.description.is_some())
    .bind(input.description.as_ref().and_then(Clone::clone))
    .bind(input.profile_photo.is_some())
    .bind(input.profile_photo.as_ref().and_then(Clone::clone))
    .bind(input.reports_to_membership_id.is_some())
    .bind(input.reports_to_membership_id.flatten())
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "invalid_reporting_hierarchy"))?;
    if result.rows_affected() != 1 {
        let current = fetch_identity(
            &mut scope.transaction,
            scope.access.organization_id,
            &silicon_id,
        )
        .await?;
        require_active_version(&current, expected_version)?;
        return Err(AppError::Conflict {
            code: Cow::Borrowed("silicon_profile_unchanged"),
        });
    }
    let provisional_silicons = fetch_silicons(
        &mut scope.transaction,
        scope.access.organization_id,
        &affected_membership_ids,
        &profile_base,
    )
    .await?;
    let changed_membership_ids = provisional_silicons
        .iter()
        .filter_map(|after| {
            let before = before_silicons.get(&after.membership_id)?;
            (after.membership_id == identity.membership_id
                || hierarchy_projection_changed(before, after))
            .then_some(after.membership_id)
        })
        .collect::<Vec<_>>();
    touch_silicon_descendants(
        &mut scope.transaction,
        scope.access.organization_id,
        identity.membership_id,
        &changed_membership_ids,
    )
    .await?;
    touch_membership_projections(
        &mut scope.transaction,
        scope.access.organization_id,
        &changed_membership_ids,
        hierarchy_change.then_some(identity.membership_id),
    )
    .await?;
    let after_silicons = fetch_silicons(
        &mut scope.transaction,
        scope.access.organization_id,
        &changed_membership_ids,
        &profile_base,
    )
    .await?
    .into_iter()
    .map(|silicon| (silicon.membership_id, silicon))
    .collect::<BTreeMap<_, _>>();
    let after_members = super::directory::fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &changed_membership_ids,
    )
    .await?
    .into_iter()
    .map(|member| (member.id, member))
    .collect::<BTreeMap<_, _>>();
    for membership_id in &changed_membership_ids {
        let before_silicon = before_silicons
            .get(membership_id)
            .ok_or(AppError::Internal {
                category: "silicon_hierarchy_before_state",
            })?;
        let after_silicon = after_silicons
            .get(membership_id)
            .ok_or(AppError::Internal {
                category: "silicon_hierarchy_after_state",
            })?;
        record_silicon_change(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            if *membership_id == identity.membership_id {
                "silicon.directory_updated"
            } else {
                "silicon.hierarchy_projection_updated"
            },
            "organization.silicon.updated.v1",
            before_silicon,
            after_silicon,
        )
        .await?;
        super::directory::record_member_mutation(
            &mut scope.transaction,
            &state,
            &authenticated,
            scope.access.organization_id,
            if *membership_id == identity.membership_id {
                "membership.silicon_profile_updated"
            } else {
                "membership.hierarchy_projection_updated"
            },
            "organization.membership.updated.v1",
            before_members
                .get(membership_id)
                .ok_or(AppError::Internal {
                    category: "silicon_membership_before_state",
                })?,
            after_members.get(membership_id).ok_or(AppError::Internal {
                category: "silicon_membership_after_state",
            })?,
        )
        .await?;
    }
    let silicon =
        after_silicons
            .get(&identity.membership_id)
            .cloned()
            .ok_or(AppError::Internal {
                category: "silicon_update_response",
            })?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &silicon,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(silicon.version), false)
}

pub(super) async fn remove_silicon(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, silicon_id)): Path<(String, String)>,
    Query(query): Query<RemovalQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validate_global_silicon_id(&silicon_id, &org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::SiliconsRemove)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        SILICON_REMOVE_ROUTE,
        &silicon_id,
        &query,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let identity = fetch_identity(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
    )
    .await?;
    require_active_version(&identity, expected_version)?;
    let before = fetch_silicon(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon_id,
        &silicon_profile_base(&state)?,
    )
    .await?;
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        "organization.authorization_change",
        Some(identity.membership_id),
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let affected_membership_ids = support::lock_membership_removal_event_scope(
        &mut scope.transaction,
        scope.access.organization_id,
        identity.membership_id,
        query.reassign_reports_to,
    )
    .await?;
    let before_members = super::directory::fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &affected_membership_ids,
    )
    .await?;
    let before_by_id = before_members
        .into_iter()
        .map(|member| (member.id, member))
        .collect::<BTreeMap<_, _>>();
    sqlx::query_scalar::<_, i64>(
        "SELECT iam_private.deactivate_silicon_webhook_for_removal($1, $2)",
    )
    .bind(scope.access.organization_id)
    .bind(identity.principal_id)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    let resulting_version = sqlx::query_scalar::<_, i64>(
        r"
        SELECT silicon_version
        FROM iam_private.remove_organization_membership($1, $2, $3, $4, $5)
        ",
    )
    .bind(scope.access.organization_id)
    .bind(identity.membership_id)
    .bind(identity.membership_version)
    .bind(Some(expected_version))
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
            action: "silicon.removed",
            target_type: "silicon",
            target_id: identity.principal_id,
            aggregate_type: "silicon",
            aggregate_id: identity.principal_id,
            aggregate_version: resulting_version,
            event_type: "organization.silicon.removed.v1",
            before_state: serde_json::to_value(&before).ok(),
            after_state: Some(json!({ "status": "removed", "version": resulting_version })),
            metadata: json!({
                "silicon_id": identity.principal_id,
                "membership_id": identity.membership_id,
                "subject_principal_id": identity.principal_id,
                "reassign_reports_to": query.reassign_reports_to,
            }),
        },
    )
    .await?;
    let surviving_membership_ids = affected_membership_ids
        .into_iter()
        .filter(|membership_id| *membership_id != identity.membership_id)
        .collect::<Vec<_>>();
    let surviving_members = super::directory::fetch_members(
        &mut scope.transaction,
        scope.access.organization_id,
        &surviving_membership_ids,
    )
    .await?;
    for member in &surviving_members {
        let before_member = before_by_id.get(&member.id).ok_or(AppError::Internal {
            category: "silicon_removal_member_before_state",
        })?;
        super::directory::record_member_mutation(
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

pub(super) async fn fetch_silicon(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: &str,
    profile_base: &str,
) -> Result<SiliconResponse, AppError> {
    sqlx::query_as::<_, SiliconResponse>(SILICON_BY_ID_SQL)
        .bind(organization_id)
        .bind(silicon_id)
        .bind(profile_base)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)
}

pub(super) async fn fetch_silicons(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_ids: &[Uuid],
    profile_base: &str,
) -> Result<Vec<SiliconResponse>, AppError> {
    if membership_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, SiliconResponse>(SILICON_BY_MEMBERSHIPS_SQL)
        .bind(organization_id)
        .bind(membership_ids)
        .bind(profile_base)
        .fetch_all(&mut **transaction)
        .await
        .map_err(support::database)
}

/// Serializes organization hierarchy edits and locks the exact current target
/// subtree in deterministic membership order. Callers may then compare the
/// derived levels before/after and version only projections that changed.
pub(super) async fn lock_hierarchy_subtree(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    root_membership_id: Uuid,
    include_descendants: bool,
) -> Result<Vec<Uuid>, AppError> {
    if include_descendants {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 734921))")
            .bind(organization_id)
            .execute(&mut **transaction)
            .await
            .map_err(support::database)?;
    }
    let ids = sqlx::query_scalar::<_, Uuid>(
        r"
        WITH RECURSIVE subtree AS (
            SELECT silicon.membership_id
            FROM iam.silicons AS silicon
            WHERE silicon.organization_id = $1
              AND silicon.membership_id = $2
              AND silicon.provisioning_status <> 'deleted'
            UNION ALL
            SELECT child.membership_id
            FROM iam.silicons AS child
            JOIN subtree AS parent
              ON child.reports_to_membership_id = parent.membership_id
            WHERE $3
              AND child.organization_id = $1
              AND child.provisioning_status <> 'deleted'
        )
        SELECT membership.id
        FROM subtree
        JOIN iam.silicons AS silicon
          ON silicon.organization_id = $1
         AND silicon.membership_id = subtree.membership_id
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id
        ORDER BY membership.id
        FOR UPDATE OF silicon, membership
        ",
    )
    .bind(organization_id)
    .bind(root_membership_id)
    .bind(include_descendants)
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)?;
    if !ids.contains(&root_membership_id) {
        return Err(AppError::NotFound);
    }
    Ok(ids)
}

pub(super) async fn touch_silicon_descendants(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    target_membership_id: Uuid,
    changed_membership_ids: &[Uuid],
) -> Result<(), AppError> {
    let descendants = changed_membership_ids
        .iter()
        .copied()
        .filter(|membership_id| *membership_id != target_membership_id)
        .collect::<Vec<_>>();
    if descendants.is_empty() {
        return Ok(());
    }
    sqlx::query(
        r"
        UPDATE iam.silicons
        SET updated_at = transaction_timestamp()
        WHERE organization_id = $1
          AND membership_id = ANY($2)
          AND provisioning_status <> 'deleted'
        ",
    )
    .bind(organization_id)
    .bind(&descendants)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    Ok(())
}

pub(super) async fn touch_membership_projections(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_ids: &[Uuid],
    authorization_membership_id: Option<Uuid>,
) -> Result<(), AppError> {
    if membership_ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET authz_epoch = authz_epoch + CASE WHEN id = $3 THEN 1 ELSE 0 END,
            updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND id = ANY($2) AND status = 'active'
        ",
    )
    .bind(organization_id)
    .bind(membership_ids)
    .bind(authorization_membership_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    Ok(())
}

pub(super) fn hierarchy_projection_changed(
    before: &SiliconResponse,
    after: &SiliconResponse,
) -> bool {
    before.hierarchy_level != after.hierarchy_level || before.profile_photo != after.profile_photo
}

async fn fetch_identity(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: &str,
) -> Result<SiliconIdentity, AppError> {
    sqlx::query_as::<_, SiliconIdentity>(
        r"
        SELECT silicon.id AS principal_id, silicon.membership_id,
               silicon.version,
               membership.version AS membership_version,
               CASE WHEN silicon.provisioning_status <> 'deleted'
                          AND membership.status = 'active'
                    THEN 'active' ELSE 'removed' END AS status
        FROM iam.silicons AS silicon
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id
        WHERE silicon.organization_id = $1 AND silicon.global_silicon_id = $2
        LIMIT 1
        ",
    )
    .bind(organization_id)
    .bind(silicon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

fn require_active_version(identity: &SiliconIdentity, version: i64) -> Result<(), AppError> {
    if identity.status != "active" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("silicon_not_active"),
        });
    }
    if identity.version != version {
        return Err(precondition_failed());
    }
    Ok(())
}

async fn validate_references(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    tag_ids: &[Uuid],
    reports_to: Option<Uuid>,
) -> Result<(), AppError> {
    let tag_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.organization_tags WHERE organization_id = $1 AND id = ANY($2) AND status = 'active'",
    )
    .bind(organization_id)
    .bind(tag_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(tag_count).ok() != Some(tag_ids.len()) {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("directory_reference_inactive"),
        });
    }
    if let Some(reports_to) = reports_to {
        validate_active_silicon(transaction, organization_id, reports_to).await?;
    }
    Ok(())
}

async fn validate_active_silicon(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
) -> Result<(), AppError> {
    let active = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM iam.silicons AS silicon
            JOIN iam.organization_memberships AS membership
              ON membership.organization_id = silicon.organization_id
             AND membership.id = silicon.membership_id
            WHERE silicon.organization_id = $1 AND silicon.membership_id = $2
              AND silicon.provisioning_status <> 'deleted' AND membership.status = 'active'
        )
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if !active {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("directory_reference_inactive"),
        });
    }
    Ok(())
}

async fn assign_tags(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    actor_membership_id: Uuid,
    tag_ids: &[Uuid],
) -> Result<(), AppError> {
    let assigned_count = sqlx::query_scalar::<_, i64>(
        "SELECT iam_private.assign_initial_silicon_tags($1, $2, $3, $4)",
    )
    .bind(organization_id)
    .bind(membership_id)
    .bind(actor_membership_id)
    .bind(tag_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(assigned_count).ok() != Some(tag_ids.len()) {
        return Err(AppError::Internal {
            category: "initial_silicon_tag_count",
        });
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "transaction context and the exact before/after Silicon event are kept explicit"
)]
pub(super) async fn record_silicon_change(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    organization_id: Uuid,
    action: &'static str,
    event_type: &'static str,
    before: &SiliconResponse,
    after: &SiliconResponse,
) -> Result<(), AppError> {
    support::record_application_mutation(
        transaction,
        state,
        authenticated,
        organization_id,
        MutationEvent {
            action,
            target_type: "silicon",
            target_id: after.principal_id,
            aggregate_type: "silicon",
            aggregate_id: after.principal_id,
            aggregate_version: after.version,
            event_type,
            before_state: serde_json::to_value(before).ok(),
            after_state: serde_json::to_value(after).ok(),
            metadata: json!({
                "silicon_id": after.principal_id,
                "membership_id": after.membership_id,
                "subject_principal_id": after.principal_id,
            }),
        },
    )
    .await
}

pub(super) fn silicon_profile_base(state: &ApiState) -> Result<String, AppError> {
    state
        .settings
        .providers
        .iris_base_url
        .join("pfp/silicon")
        .map(|url| url.to_string())
        .map_err(|_| AppError::Internal {
            category: "silicon_profile_url",
        })
}

pub(super) fn validate_global_silicon_id(value: &str, org_id: &str) -> Result<(), AppError> {
    let Some((handle, suffix)) = value.rsplit_once(':') else {
        return Err(validation::field("silicon_id", "has an invalid format"));
    };
    if suffix != org_id {
        return Err(AppError::NotFound);
    }
    let mut synthetic = SiliconCreate {
        silicon_id: handle.to_owned(),
        display_name: Some(handle.to_owned()),
        timezone: Some("UTC".to_owned()),
        description: None,
        profile_photo: None,
        job_role: String::new(),
        reports_to_membership_id: None,
        tag_ids: Vec::new(),
    };
    validation::silicon_create(&mut synthetic, crate::config::RuntimeEnvironment::Test).map(|_| ())
}

fn take_page(items: &mut Vec<SiliconResponse>, limit: i64) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "silicon_page_limit",
    })?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_cursor = if has_more {
        items
            .last()
            .map(|item| validation::encode_cursor(item.principal_id))
    } else {
        None
    };
    Ok(PageInfo {
        next_cursor,
        has_more,
    })
}

fn precondition_failed() -> AppError {
    AppError::PreconditionFailed {
        code: Cow::Borrowed("etag_mismatch"),
    }
}

const SILICON_LIST_SQL: &str = concat!(
    "",
    r"
    WITH RECURSIVE hierarchy AS (
        SELECT root.id, root.membership_id, root.reports_to_membership_id, 1::integer AS level
        FROM iam.silicons AS root
        WHERE root.organization_id = $1 AND root.reports_to_membership_id IS NULL
          AND root.provisioning_status <> 'deleted'
        UNION ALL
        SELECT child.id, child.membership_id, child.reports_to_membership_id, hierarchy.level + 1
        FROM iam.silicons AS child
        JOIN hierarchy ON child.reports_to_membership_id = hierarchy.membership_id
        WHERE child.organization_id = $1 AND child.provisioning_status <> 'deleted'
    )
    SELECT silicon.id AS principal_id, silicon.membership_id,
           silicon.global_silicon_id AS silicon_id,
           organization.org_id,
           silicon.display_name, silicon.timezone_id AS timezone, silicon.description,
           COALESCE(silicon.profile_photo_override_uri,
                    $5 || '?id=' || silicon.global_silicon_id || '&level=' || hierarchy.level::text) AS profile_photo,
           membership.job_role, silicon.reports_to_membership_id,
           COALESCE((SELECT jsonb_agg(jsonb_build_object('id', tag.id, 'name', tag.name) ORDER BY tag.id)
                     FROM iam.membership_tags assignment
                     JOIN iam.organization_tags tag ON tag.organization_id = assignment.organization_id AND tag.id = assignment.tag_id
                     WHERE assignment.organization_id = silicon.organization_id AND assignment.membership_id = silicon.membership_id
                       AND tag.status = 'active'), '[]'::jsonb) AS tags,
           hierarchy.level AS hierarchy_level,
           EXISTS (
               SELECT 1
               FROM iam.silicon_webhook_endpoints AS endpoint
               JOIN iam.silicon_webhook_signing_keys AS signing
                 ON signing.organization_id = endpoint.organization_id
                AND signing.silicon_id = endpoint.silicon_id
                AND signing.endpoint_id = endpoint.id
                AND signing.status = 'active'
               WHERE endpoint.organization_id = silicon.organization_id
                 AND endpoint.silicon_id = silicon.id
                 AND endpoint.status = 'active'
           ) AS webhook_configured,
           'active'::text AS status, silicon.version, silicon.created_at, silicon.updated_at
    FROM iam.silicons silicon
    JOIN iam.organizations organization ON organization.id = silicon.organization_id
    JOIN iam.organization_memberships membership ON membership.organization_id = silicon.organization_id AND membership.id = silicon.membership_id
    JOIN hierarchy ON hierarchy.id = silicon.id
    WHERE silicon.organization_id = $1 AND membership.status = 'active' AND silicon.provisioning_status <> 'deleted'
      AND ($2::uuid IS NULL OR silicon.id > $2)
      AND ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM iam.membership_tags filter_tag
          WHERE filter_tag.organization_id = silicon.organization_id AND filter_tag.membership_id = silicon.membership_id AND filter_tag.tag_id = $4))
    ORDER BY silicon.id
    LIMIT $3
    "
);

const SILICON_BY_ID_SQL: &str = r"
    WITH RECURSIVE hierarchy AS (
        SELECT root.id, root.membership_id, root.reports_to_membership_id, 1::integer AS level
        FROM iam.silicons AS root
        WHERE root.organization_id = $1 AND root.reports_to_membership_id IS NULL
        UNION ALL
        SELECT child.id, child.membership_id, child.reports_to_membership_id, hierarchy.level + 1
        FROM iam.silicons AS child
        JOIN hierarchy ON child.reports_to_membership_id = hierarchy.membership_id
        WHERE child.organization_id = $1
    )
    SELECT silicon.id AS principal_id, silicon.membership_id,
           silicon.global_silicon_id AS silicon_id,
           organization.org_id,
           silicon.display_name, silicon.timezone_id AS timezone, silicon.description,
           COALESCE(silicon.profile_photo_override_uri,
                    $3 || '?id=' || silicon.global_silicon_id || '&level=' || hierarchy.level::text) AS profile_photo,
           membership.job_role, silicon.reports_to_membership_id,
           COALESCE((SELECT jsonb_agg(jsonb_build_object('id', tag.id, 'name', tag.name) ORDER BY tag.id)
                     FROM iam.membership_tags assignment
                     JOIN iam.organization_tags tag ON tag.organization_id = assignment.organization_id AND tag.id = assignment.tag_id
                     WHERE assignment.organization_id = silicon.organization_id AND assignment.membership_id = silicon.membership_id
                       AND tag.status = 'active'), '[]'::jsonb) AS tags,
           hierarchy.level AS hierarchy_level,
           EXISTS (
               SELECT 1
               FROM iam.silicon_webhook_endpoints AS endpoint
               JOIN iam.silicon_webhook_signing_keys AS signing
                 ON signing.organization_id = endpoint.organization_id
                AND signing.silicon_id = endpoint.silicon_id
                AND signing.endpoint_id = endpoint.id
                AND signing.status = 'active'
               WHERE endpoint.organization_id = silicon.organization_id
                 AND endpoint.silicon_id = silicon.id
                 AND endpoint.status = 'active'
           ) AS webhook_configured,
           CASE WHEN membership.status = 'active' AND silicon.provisioning_status <> 'deleted' THEN 'active' ELSE 'removed' END AS status,
           silicon.version, silicon.created_at, silicon.updated_at
    FROM iam.silicons silicon
    JOIN iam.organizations organization ON organization.id = silicon.organization_id
    JOIN iam.organization_memberships membership ON membership.organization_id = silicon.organization_id AND membership.id = silicon.membership_id
    JOIN hierarchy ON hierarchy.id = silicon.id
    WHERE silicon.organization_id = $1 AND silicon.global_silicon_id = $2
    LIMIT 1
";

const SILICON_BY_MEMBERSHIPS_SQL: &str = r"
    WITH RECURSIVE hierarchy AS (
        SELECT root.id, root.membership_id, root.reports_to_membership_id, 1::integer AS level
        FROM iam.silicons AS root
        WHERE root.organization_id = $1 AND root.reports_to_membership_id IS NULL
        UNION ALL
        SELECT child.id, child.membership_id, child.reports_to_membership_id, hierarchy.level + 1
        FROM iam.silicons AS child
        JOIN hierarchy ON child.reports_to_membership_id = hierarchy.membership_id
        WHERE child.organization_id = $1
    )
    SELECT silicon.id AS principal_id, silicon.membership_id,
           silicon.global_silicon_id AS silicon_id,
           organization.org_id,
           silicon.display_name, silicon.timezone_id AS timezone, silicon.description,
           COALESCE(silicon.profile_photo_override_uri,
                    $3 || '?id=' || silicon.global_silicon_id || '&level=' || hierarchy.level::text) AS profile_photo,
           membership.job_role, silicon.reports_to_membership_id,
           COALESCE((SELECT jsonb_agg(jsonb_build_object('id', tag.id, 'name', tag.name) ORDER BY tag.id)
                     FROM iam.membership_tags assignment
                     JOIN iam.organization_tags tag ON tag.organization_id = assignment.organization_id AND tag.id = assignment.tag_id
                     WHERE assignment.organization_id = silicon.organization_id AND assignment.membership_id = silicon.membership_id
                       AND tag.status = 'active'), '[]'::jsonb) AS tags,
           hierarchy.level AS hierarchy_level,
           EXISTS (
               SELECT 1
               FROM iam.silicon_webhook_endpoints AS endpoint
               JOIN iam.silicon_webhook_signing_keys AS signing
                 ON signing.organization_id = endpoint.organization_id
                AND signing.silicon_id = endpoint.silicon_id
                AND signing.endpoint_id = endpoint.id
                AND signing.status = 'active'
               WHERE endpoint.organization_id = silicon.organization_id
                 AND endpoint.silicon_id = silicon.id
                 AND endpoint.status = 'active'
           ) AS webhook_configured,
           CASE WHEN membership.status = 'active' AND silicon.provisioning_status <> 'deleted' THEN 'active' ELSE 'removed' END AS status,
           silicon.version, silicon.created_at, silicon.updated_at
    FROM iam.silicons silicon
    JOIN iam.organizations organization ON organization.id = silicon.organization_id
    JOIN iam.organization_memberships membership ON membership.organization_id = silicon.organization_id AND membership.id = silicon.membership_id
    JOIN hierarchy ON hierarchy.id = silicon.id
    WHERE silicon.organization_id = $1 AND silicon.membership_id = ANY($2)
    ORDER BY silicon.membership_id
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_silicon_ids_are_bound_to_the_route_organization() {
        assert!(validate_global_silicon_id("worker:acme", "acme").is_ok());
        assert!(matches!(
            validate_global_silicon_id("worker:other", "acme"),
            Err(AppError::NotFound)
        ));
        assert!(validate_global_silicon_id("worker", "acme").is_err());
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    async fn live_hierarchy_scope_versions_only_changed_subtree_resources() -> anyhow::Result<()> {
        use anyhow::ensure;
        use sqlx::postgres::PgPoolOptions;
        use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
        use testcontainers_modules::postgres::Postgres as TestPostgres;

        let container = TestPostgres::default()
            .with_tag("16-alpine")
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        crate::infrastructure::postgres::migrate(&pool).await?;

        let owner_id = Uuid::from_u128(0xb01);
        let organization_id = Uuid::from_u128(0xb02);
        let owner_membership_id = Uuid::from_u128(0xb03);
        let root_id = Uuid::from_u128(0xb04);
        let root_membership_id = Uuid::from_u128(0xb05);
        let child_id = Uuid::from_u128(0xb06);
        let child_membership_id = Uuid::from_u128(0xb07);
        let grandchild_id = Uuid::from_u128(0xb08);
        let grandchild_membership_id = Uuid::from_u128(0xb09);
        let seed = format!(
            r"
            INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status)
            VALUES ('contact_aead', 1, 'active');
            INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
              ('{owner_id}', 'carbon', 'active', transaction_timestamp()),
              ('{root_id}', 'silicon', 'active', transaction_timestamp()),
              ('{child_id}', 'silicon', 'active', transaction_timestamp()),
              ('{grandchild_id}', 'silicon', 'active', transaction_timestamp());
            INSERT INTO iam.carbons (id, carbon_id, display_name)
            VALUES ('{owner_id}', 'hierarchy-owner', 'Hierarchy Owner');
            INSERT INTO iam.carbon_contacts (
                id, carbon_id, kind, ciphertext, nonce, encryption_key_version, verified_at
            ) VALUES
              ('00000000-0000-0000-0000-000000000b11', '{owner_id}', 'email',
               decode(repeat('51', 17), 'hex'), decode(repeat('52', 12), 'hex'), 1,
               transaction_timestamp()),
              ('00000000-0000-0000-0000-000000000b12', '{owner_id}', 'phone',
               decode(repeat('53', 17), 'hex'), decode(repeat('54', 12), 'hex'), 1,
               transaction_timestamp());
            INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
            VALUES ('{organization_id}', 'hierarchy-org', '{owner_id}', 'Hierarchy Org');
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role, job_role
            ) VALUES
              ('{owner_membership_id}', '{organization_id}', '{owner_id}', 'carbon', 'owner', 'Owner'),
              ('{root_membership_id}', '{organization_id}', '{root_id}', 'silicon', 'member', 'Root'),
              ('{child_membership_id}', '{organization_id}', '{child_id}', 'silicon', 'member', 'Child'),
              ('{grandchild_membership_id}', '{organization_id}', '{grandchild_id}', 'silicon', 'member', 'Grandchild');
            INSERT INTO iam.carbon_membership_settings (organization_id, membership_id, carbon_id)
            VALUES ('{organization_id}', '{owner_membership_id}', '{owner_id}');
            INSERT INTO iam.silicons (
                id, organization_id, membership_id, organization_handle,
                silicon_handle, display_name, reports_to_membership_id, provisioning_status
            ) VALUES
              ('{root_id}', '{organization_id}', '{root_membership_id}', 'hierarchy-org', 'root', 'Root', NULL, 'active'),
              ('{child_id}', '{organization_id}', '{child_membership_id}', 'hierarchy-org', 'child', 'Child', '{root_membership_id}', 'active'),
              ('{grandchild_id}', '{organization_id}', '{grandchild_membership_id}', 'hierarchy-org', 'grandchild', 'Grandchild', '{child_membership_id}', 'active');
            "
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(seed))
            .execute(&pool)
            .await?;

        let mut transaction = pool.begin().await?;
        let affected =
            lock_hierarchy_subtree(&mut transaction, organization_id, child_membership_id, true)
                .await?;
        ensure!(
            affected == vec![child_membership_id, grandchild_membership_id],
            "the locked subtree must be exact and ordered"
        );
        let before = fetch_silicons(
            &mut transaction,
            organization_id,
            &affected,
            "https://iris.teamofsilicons.com/pfp/silicon",
        )
        .await?;
        sqlx::query(
            "UPDATE iam.silicons SET reports_to_membership_id = NULL, updated_at = transaction_timestamp() WHERE organization_id = $1 AND membership_id = $2",
        )
        .bind(organization_id)
        .bind(child_membership_id)
        .execute(&mut *transaction)
        .await?;
        let provisional = fetch_silicons(
            &mut transaction,
            organization_id,
            &affected,
            "https://iris.teamofsilicons.com/pfp/silicon",
        )
        .await?;
        ensure!(
            before
                .iter()
                .zip(&provisional)
                .all(|(old, new)| hierarchy_projection_changed(old, new)),
            "both derived hierarchy projections must change"
        );
        touch_silicon_descendants(
            &mut transaction,
            organization_id,
            child_membership_id,
            &affected,
        )
        .await?;
        touch_membership_projections(
            &mut transaction,
            organization_id,
            &affected,
            Some(child_membership_id),
        )
        .await?;
        let silicon_versions = sqlx::query_as::<_, (Uuid, i64)>(
            "SELECT membership_id, version FROM iam.silicons WHERE organization_id = $1 AND membership_id = ANY($2) ORDER BY membership_id",
        )
        .bind(organization_id)
        .bind(&affected)
        .fetch_all(&mut *transaction)
        .await?;
        ensure!(
            silicon_versions == vec![(child_membership_id, 2), (grandchild_membership_id, 2)],
            "each changed Silicon aggregate must advance exactly once"
        );
        let membership_versions = sqlx::query_as::<_, (Uuid, i64, i64)>(
            "SELECT id, version, authz_epoch FROM iam.organization_memberships WHERE organization_id = $1 AND id = ANY($2) ORDER BY id",
        )
        .bind(organization_id)
        .bind(&affected)
        .fetch_all(&mut *transaction)
        .await?;
        ensure!(
            membership_versions
                == vec![
                    (child_membership_id, 2, 2),
                    (grandchild_membership_id, 2, 1),
                ],
            "each member projection must advance once without inflating descendant authorization"
        );
        Ok(())
    }
}
