use std::{borrow::Cow, collections::BTreeSet};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::organization::Capability,
    error::AppError,
};

use super::{
    model::{
        PageInfo, PageQuery, TrustBoundary, TrustEvaluationInput, TrustEvaluationResponse,
        TrustLevel, TrustRuleInput, TrustRulePage, TrustRulePatch, TrustRuleResponse,
        TrustSelector, TrustValue,
    },
    support::{self, Claim, MutationEvent},
    validation,
};

const TRUST_DEFAULT_ROUTE: &str = "PUT /api/v1/organizations/{org_id}/trust/default";
const TRUST_RULE_CREATE_ROUTE: &str = "POST /api/v1/organizations/{org_id}/trust/rules";
const TRUST_RULE_UPDATE_ROUTE: &str = "PATCH /api/v1/organizations/{org_id}/trust/rules/{rule_id}";
const TRUST_RULE_DELETE_ROUTE: &str = "DELETE /api/v1/organizations/{org_id}/trust/rules/{rule_id}";

#[derive(Clone, Debug, sqlx::FromRow)]
struct TrustRuleRow {
    id: Uuid,
    org_id: String,
    subject_kind: String,
    subject_membership_id: Option<Uuid>,
    subject_tag_id: Option<Uuid>,
    target_kind: String,
    target_silicon_membership_id: Option<Uuid>,
    target_tag_id: Option<Uuid>,
    trust_boundary: String,
    trust_level: String,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub(super) struct MatchRow {
    pub(super) id: Uuid,
    pub(super) subject_kind: String,
    pub(super) target_kind: String,
    pub(super) trust_boundary: String,
    pub(super) trust_level: String,
}

pub(super) async fn get_default_trust(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let (boundary, level, version) = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT default_trust_boundary::text, default_trust_level::text, version FROM iam.organizations WHERE id = $1",
    )
    .bind(scope.access.organization_id)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    let trust = parse_trust(&boundary, &level)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &trust, Some(version))
}

pub(super) async fn replace_default_trust(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<TrustValue>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::TrustManage)?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        TRUST_DEFAULT_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let before = sqlx::query_as::<_, (String, String)>(
        "SELECT default_trust_boundary::text, default_trust_level::text FROM iam.organizations WHERE id = $1 AND version = $2",
    )
    .bind(scope.access.organization_id)
    .bind(expected_version)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(support::database)?
    .ok_or_else(precondition_failed)?;
    if before.0 == input.boundary.as_str() && before.1 == input.level.as_str() {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("trust_default_unchanged"),
        });
    }
    let result = sqlx::query(
        r"
        UPDATE iam.organizations
        SET default_trust_boundary = $2::iam.trust_boundary,
            default_trust_level = $3::iam.trust_level
        WHERE id = $1 AND version = $4
        ",
    )
    .bind(scope.access.organization_id)
    .bind(input.boundary.as_str())
    .bind(input.level.as_str())
    .bind(expected_version)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    let version = expected_version + 1;
    support::record_application_mutation(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        MutationEvent {
            action: "trust.default_replaced",
            target_type: "organization",
            target_id: scope.access.organization_id,
            aggregate_type: "organization",
            aggregate_id: scope.access.organization_id,
            aggregate_version: version,
            event_type: "organization.trust.default_updated.v1",
            before_state: Some(json!({ "boundary": before.0, "level": before.1 })),
            after_state: serde_json::to_value(input).ok(),
            metadata: json!({ "organization_id": scope.access.organization_id }),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &input,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(version), false)
}

pub(super) async fn list_trust_rules(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let (cursor, limit) = validation::page(&query)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let rows = sqlx::query_as::<_, TrustRuleRow>(TRUST_RULE_LIST_SQL)
        .bind(scope.access.organization_id)
        .bind(cursor)
        .bind(limit + 1)
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let mut items = rows
        .into_iter()
        .map(TrustRuleResponse::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let page = take_page(&mut items, limit)?;
    support::json(StatusCode::OK, &TrustRulePage { items, page }, None)
}

pub(super) async fn create_trust_rule(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<TrustRuleInput>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::TrustManage)?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        TRUST_RULE_CREATE_ROUTE,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    validate_selectors(
        &mut scope.transaction,
        scope.access.organization_id,
        &input.subject,
        &input.target,
    )
    .await?;
    let rule_id = Uuid::now_v7();
    let affected_membership_ids = lock_trust_rule_memberships(
        &mut scope.transaction,
        scope.access.organization_id,
        [(&input.subject, true), (&input.target, false)],
    )
    .await?;
    let subject = selector_parts(&input.subject, true);
    let target = selector_parts(&input.target, false);
    sqlx::query(
        r"
        INSERT INTO iam.trust_rules (
            id, organization_id, subject_kind, subject_membership_id, subject_tag_id,
            target_kind, target_silicon_membership_id, target_tag_id,
            trust_boundary, trust_level, created_by_membership_id, updated_by_membership_id
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            $9::iam.trust_boundary, $10::iam.trust_level, $11, $11
        )
        ",
    )
    .bind(rule_id)
    .bind(scope.access.organization_id)
    .bind(subject.kind)
    .bind(subject.membership_id)
    .bind(subject.tag_id)
    .bind(target.kind)
    .bind(target.membership_id)
    .bind(target.tag_id)
    .bind(input.trust.boundary.as_str())
    .bind(input.trust.level.as_str())
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "trust_rule_exists"))?;
    let rule = fetch_rule(
        &mut scope.transaction,
        scope.access.organization_id,
        rule_id,
    )
    .await?;
    record_rule(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        "trust.rule_created",
        "organization.trust.rule_created.v1",
        None,
        Some(&rule),
        &affected_membership_ids,
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &rule,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, Some(rule.version), false)
}

pub(super) async fn get_trust_rule(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, rule_id)): Path<(String, Uuid)>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    let rule = fetch_rule(
        &mut scope.transaction,
        scope.access.organization_id,
        rule_id,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &rule, Some(rule.version))
}

#[allow(
    clippy::too_many_lines,
    reason = "claim ordering, exact selector capture, mutation, and event persistence are one transaction"
)]
pub(super) async fn update_trust_rule(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, rule_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<TrustRulePatch>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    validation::trust_rule_patch(&input)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::TrustManage)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        TRUST_RULE_UPDATE_ROUTE,
        &rule_id.to_string(),
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let before = fetch_rule(
        &mut scope.transaction,
        scope.access.organization_id,
        rule_id,
    )
    .await?;
    if before.version != expected_version {
        return Err(precondition_failed());
    }
    let subject = input.subject.as_ref().unwrap_or(&before.subject);
    let target = input.target.as_ref().unwrap_or(&before.target);
    let trust = input.trust.unwrap_or(before.trust);
    if subject == &before.subject && target == &before.target && trust == before.trust {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("trust_rule_unchanged"),
        });
    }
    validate_selectors(
        &mut scope.transaction,
        scope.access.organization_id,
        subject,
        target,
    )
    .await?;
    let affected_membership_ids = lock_trust_rule_memberships(
        &mut scope.transaction,
        scope.access.organization_id,
        [
            (&before.subject, true),
            (&before.target, false),
            (subject, true),
            (target, false),
        ],
    )
    .await?;
    let subject = selector_parts(subject, true);
    let target = selector_parts(target, false);
    let result = sqlx::query(
        r"
        UPDATE iam.trust_rules
        SET subject_kind = $4, subject_membership_id = $5, subject_tag_id = $6,
            target_kind = $7, target_silicon_membership_id = $8, target_tag_id = $9,
            trust_boundary = $10::iam.trust_boundary,
            trust_level = $11::iam.trust_level,
            updated_by_membership_id = $12
        WHERE organization_id = $1 AND id = $2 AND version = $3 AND archived_at IS NULL
        ",
    )
    .bind(scope.access.organization_id)
    .bind(rule_id)
    .bind(expected_version)
    .bind(subject.kind)
    .bind(subject.membership_id)
    .bind(subject.tag_id)
    .bind(target.kind)
    .bind(target.membership_id)
    .bind(target.tag_id)
    .bind(trust.boundary.as_str())
    .bind(trust.level.as_str())
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::conflict_from_database(error, "trust_rule_exists"))?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    let rule = fetch_rule(
        &mut scope.transaction,
        scope.access.organization_id,
        rule_id,
    )
    .await?;
    record_rule(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        "trust.rule_updated",
        "organization.trust.rule_updated.v1",
        Some(&before),
        Some(&rule),
        &affected_membership_ids,
    )
    .await?;
    let body =
        support::finish_json(&mut scope.transaction, &state, lease, StatusCode::OK, &rule).await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(rule.version), false)
}

pub(super) async fn delete_trust_rule(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path((org_id, rule_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    support::require_capability(&scope.access, Capability::TrustManage)?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        TRUST_RULE_DELETE_ROUTE,
        &rule_id.to_string(),
        &json!({ "operation": "delete" }),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected_version = validation::expected_version(&headers)?;
    let before = fetch_rule(
        &mut scope.transaction,
        scope.access.organization_id,
        rule_id,
    )
    .await?;
    if before.version != expected_version {
        return Err(precondition_failed());
    }
    let affected_membership_ids = lock_trust_rule_memberships(
        &mut scope.transaction,
        scope.access.organization_id,
        [(&before.subject, true), (&before.target, false)],
    )
    .await?;
    let result = sqlx::query(
        "UPDATE iam.trust_rules SET archived_at = transaction_timestamp(), updated_by_membership_id = $4 WHERE organization_id = $1 AND id = $2 AND version = $3 AND archived_at IS NULL",
    )
    .bind(scope.access.organization_id)
    .bind(rule_id)
    .bind(expected_version)
    .bind(scope.access.membership_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if result.rows_affected() != 1 {
        return Err(precondition_failed());
    }
    record_rule(
        &mut scope.transaction,
        &state,
        &authenticated,
        scope.access.organization_id,
        "trust.rule_archived",
        "organization.trust.rule_archived.v1",
        Some(&before),
        None,
        &affected_membership_ids,
    )
    .await?;
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

pub(super) async fn evaluate_trust(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(org_id): Path<String>,
    Json(input): Json<TrustEvaluationInput>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&org_id)?.to_string();
    let mut scope = support::begin_organization(&state, &authenticated, &org_id).await?;
    validate_evaluation(&mut scope.transaction, scope.access.organization_id, &input).await?;
    let (default_boundary, default_level) =
        sqlx::query_as::<_, (String, String)>(TRUST_DEFAULT_FOR_SUBJECT_SQL)
            .bind(scope.access.organization_id)
            .bind(input.subject_membership_id)
            .fetch_one(&mut *scope.transaction)
            .await
            .map_err(support::database)?;
    let matches = sqlx::query_as::<_, MatchRow>(TRUST_MATCH_SQL)
        .bind(scope.access.organization_id)
        .bind(input.subject_membership_id)
        .bind(input.target_silicon_membership_id)
        .fetch_all(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    let response = evaluate_matches(&default_boundary, &default_level, &matches)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &response, None)
}

async fn fetch_rule(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    rule_id: Uuid,
) -> Result<TrustRuleResponse, AppError> {
    let row = sqlx::query_as::<_, TrustRuleRow>(TRUST_RULE_BY_ID_SQL)
        .bind(organization_id)
        .bind(rule_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)?;
    TrustRuleResponse::try_from(row)
}

struct SelectorParts {
    kind: &'static str,
    membership_id: Option<Uuid>,
    tag_id: Option<Uuid>,
}

fn selector_parts(selector: &TrustSelector, subject: bool) -> SelectorParts {
    match selector {
        TrustSelector::Membership { membership_id } => SelectorParts {
            kind: if subject { "membership" } else { "silicon" },
            membership_id: Some(*membership_id),
            tag_id: None,
        },
        TrustSelector::Tag { tag_id } => SelectorParts {
            kind: "tag",
            membership_id: None,
            tag_id: Some(*tag_id),
        },
    }
}

async fn validate_selectors(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    subject: &TrustSelector,
    target: &TrustSelector,
) -> Result<(), AppError> {
    let subject = selector_parts(subject, true);
    let target = selector_parts(target, false);
    if let Some(membership_id) = subject.membership_id {
        validate_active_membership(transaction, organization_id, membership_id, false).await?;
    }
    if let Some(membership_id) = target.membership_id {
        validate_active_membership(transaction, organization_id, membership_id, true).await?;
    }
    for tag_id in [subject.tag_id, target.tag_id].into_iter().flatten() {
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM iam.organization_tags WHERE organization_id = $1 AND id = $2 AND status = 'active')",
        )
        .bind(organization_id)
        .bind(tag_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(support::database)?;
        if !active {
            return Err(AppError::Conflict {
                code: Cow::Borrowed("trust_selector_inactive"),
            });
        }
    }
    Ok(())
}

/// Linearizes a trust-rule mutation with governed tag assignments. The first
/// pass locks every currently selected membership in identifier order. Tag
/// rows are then locked in identifier order, which blocks new assignments
/// because the governed apply function takes a share lock on proposed tags.
/// A second pass observes any assignment that committed while the tag lock was
/// being acquired and returns the exact, stable active membership set.
async fn lock_trust_rule_memberships<'a>(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    selectors: impl IntoIterator<Item = (&'a TrustSelector, bool)>,
) -> Result<Vec<Uuid>, AppError> {
    let mut direct_membership_ids = BTreeSet::new();
    let mut subject_tag_ids = BTreeSet::new();
    let mut target_tag_ids = BTreeSet::new();
    for (selector, subject) in selectors {
        match selector {
            TrustSelector::Membership { membership_id } => {
                direct_membership_ids.insert(*membership_id);
            }
            TrustSelector::Tag { tag_id } if subject => {
                subject_tag_ids.insert(*tag_id);
            }
            TrustSelector::Tag { tag_id } => {
                target_tag_ids.insert(*tag_id);
            }
        }
    }
    let direct_membership_ids = direct_membership_ids.into_iter().collect::<Vec<_>>();
    let subject_tag_ids = subject_tag_ids.into_iter().collect::<Vec<_>>();
    let target_tag_ids = target_tag_ids.into_iter().collect::<Vec<_>>();

    let _initial = lock_selected_memberships(
        transaction,
        organization_id,
        &direct_membership_ids,
        &subject_tag_ids,
        &target_tag_ids,
    )
    .await?;

    let mut tag_ids = subject_tag_ids
        .iter()
        .chain(&target_tag_ids)
        .copied()
        .collect::<Vec<_>>();
    tag_ids.sort_unstable();
    tag_ids.dedup();
    if !tag_ids.is_empty() {
        let locked_tags = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT tag.id
            FROM iam.organization_tags AS tag
            WHERE tag.organization_id = $1
              AND tag.id = ANY($2)
              AND tag.status = 'active'
            ORDER BY tag.id
            FOR UPDATE OF tag
            ",
        )
        .bind(organization_id)
        .bind(&tag_ids)
        .fetch_all(&mut **transaction)
        .await
        .map_err(support::database)?;
        if locked_tags.len() != tag_ids.len() {
            return Err(AppError::Conflict {
                code: Cow::Borrowed("trust_selector_inactive"),
            });
        }
    }

    let affected_membership_ids = lock_selected_memberships(
        transaction,
        organization_id,
        &direct_membership_ids,
        &subject_tag_ids,
        &target_tag_ids,
    )
    .await?;
    if direct_membership_ids
        .iter()
        .any(|membership_id| !affected_membership_ids.contains(membership_id))
    {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("trust_selector_inactive"),
        });
    }
    Ok(affected_membership_ids)
}

async fn lock_selected_memberships(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    direct_membership_ids: &[Uuid],
    subject_tag_ids: &[Uuid],
    target_tag_ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT membership.id
        FROM iam.organization_memberships AS membership
        WHERE membership.organization_id = $1
          AND membership.status = 'active'
          AND (
              membership.id = ANY($2)
              OR EXISTS (
                  SELECT 1
                  FROM iam.membership_tags AS assignment
                  WHERE assignment.organization_id = membership.organization_id
                    AND assignment.membership_id = membership.id
                    AND assignment.tag_id = ANY($3)
              )
              OR (
                  membership.principal_kind = 'silicon'
                  AND EXISTS (
                      SELECT 1
                      FROM iam.membership_tags AS assignment
                      WHERE assignment.organization_id = membership.organization_id
                        AND assignment.membership_id = membership.id
                        AND assignment.tag_id = ANY($4)
                  )
              )
          )
        ORDER BY membership.id
        FOR UPDATE OF membership
        ",
    )
    .bind(organization_id)
    .bind(direct_membership_ids)
    .bind(subject_tag_ids)
    .bind(target_tag_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)
}

async fn validate_evaluation(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    input: &TrustEvaluationInput,
) -> Result<(), AppError> {
    validate_active_membership(
        transaction,
        organization_id,
        input.subject_membership_id,
        false,
    )
    .await?;
    validate_active_membership(
        transaction,
        organization_id,
        input.target_silicon_membership_id,
        true,
    )
    .await
}

async fn validate_active_membership(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    membership_id: Uuid,
    require_silicon: bool,
) -> Result<(), AppError> {
    let active = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1 FROM iam.organization_memberships
            WHERE organization_id = $1 AND id = $2 AND status = 'active'
              AND (NOT $3 OR principal_kind = 'silicon')
        )
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .bind(require_silicon)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if !active {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("trust_selector_inactive"),
        });
    }
    Ok(())
}

pub(super) fn evaluate_matches(
    default_boundary: &str,
    default_level: &str,
    matches: &[MatchRow],
) -> Result<TrustEvaluationResponse, AppError> {
    let Some(max_specificity) = matches.iter().map(specificity).max() else {
        return Ok(TrustEvaluationResponse {
            trust: parse_trust(default_boundary, default_level)?,
            source: "organization_default".to_owned(),
            matching_rule_ids: Vec::new(),
            advisory: true,
        });
    };
    let candidates = matches
        .iter()
        .filter(|row| specificity(row) == max_specificity)
        .collect::<Vec<_>>();
    let selected = candidates
        .iter()
        .copied()
        .min_by_key(|row| {
            (
                level_rank(&row.trust_level),
                boundary_rank(&row.trust_boundary),
            )
        })
        .ok_or(AppError::Internal {
            category: "trust_evaluation",
        })?;
    Ok(TrustEvaluationResponse {
        trust: parse_trust(&selected.trust_boundary, &selected.trust_level)?,
        source: if max_specificity == 2 {
            "exact_rule".to_owned()
        } else {
            "tag_rule".to_owned()
        },
        matching_rule_ids: candidates.iter().map(|row| row.id).collect(),
        advisory: true,
    })
}

fn specificity(row: &MatchRow) -> i16 {
    i16::from(row.subject_kind == "membership") + i16::from(row.target_kind == "silicon")
}

fn level_rank(value: &str) -> u8 {
    match value {
        "not_trusted" => 0,
        "needs_approval" => 1,
        "trusted" => 2,
        _ => u8::MAX,
    }
}

fn boundary_rank(value: &str) -> u8 {
    match value {
        "external" => 0,
        "internal" => 1,
        _ => u8::MAX,
    }
}

fn parse_trust(boundary: &str, level: &str) -> Result<TrustValue, AppError> {
    let boundary = match boundary {
        "internal" => TrustBoundary::Internal,
        "external" => TrustBoundary::External,
        _ => {
            return Err(AppError::Internal {
                category: "trust_boundary",
            });
        }
    };
    let level = match level {
        "not_trusted" => TrustLevel::NotTrusted,
        "needs_approval" => TrustLevel::NeedsApproval,
        "trusted" => TrustLevel::Trusted,
        _ => {
            return Err(AppError::Internal {
                category: "trust_level",
            });
        }
    };
    Ok(TrustValue { boundary, level })
}

impl TryFrom<TrustRuleRow> for TrustRuleResponse {
    type Error = AppError;

    fn try_from(row: TrustRuleRow) -> Result<Self, Self::Error> {
        let subject = match row.subject_kind.as_str() {
            "membership" => TrustSelector::Membership {
                membership_id: row.subject_membership_id.ok_or(AppError::Internal {
                    category: "trust_rule_shape",
                })?,
            },
            "tag" => TrustSelector::Tag {
                tag_id: row.subject_tag_id.ok_or(AppError::Internal {
                    category: "trust_rule_shape",
                })?,
            },
            _ => {
                return Err(AppError::Internal {
                    category: "trust_rule_shape",
                });
            }
        };
        let target = match row.target_kind.as_str() {
            "silicon" => TrustSelector::Membership {
                membership_id: row.target_silicon_membership_id.ok_or(AppError::Internal {
                    category: "trust_rule_shape",
                })?,
            },
            "tag" => TrustSelector::Tag {
                tag_id: row.target_tag_id.ok_or(AppError::Internal {
                    category: "trust_rule_shape",
                })?,
            },
            _ => {
                return Err(AppError::Internal {
                    category: "trust_rule_shape",
                });
            }
        };
        let specificity =
            i16::from(row.subject_kind == "membership") + i16::from(row.target_kind == "silicon");
        Ok(Self {
            id: row.id,
            org_id: row.org_id,
            subject,
            target,
            trust: parse_trust(&row.trust_boundary, &row.trust_level)?,
            specificity,
            version: row.version,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "transaction context and the exact before/after trust-rule event are kept explicit"
)]
async fn record_rule(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    organization_id: Uuid,
    action: &'static str,
    event_type: &'static str,
    before: Option<&TrustRuleResponse>,
    after: Option<&TrustRuleResponse>,
    affected_membership_ids: &[Uuid],
) -> Result<(), AppError> {
    let current = after.or(before).ok_or(AppError::Internal {
        category: "trust_audit_state",
    })?;
    support::record_application_mutation(
        transaction,
        state,
        authenticated,
        organization_id,
        MutationEvent {
            action,
            target_type: "trust_rule",
            target_id: current.id,
            aggregate_type: "trust_rule",
            aggregate_id: current.id,
            aggregate_version: after.map_or(current.version + 1, |value| value.version),
            event_type,
            before_state: before.and_then(|value| serde_json::to_value(value).ok()),
            after_state: after.and_then(|value| serde_json::to_value(value).ok()),
            metadata: rule_event_metadata(current.id, affected_membership_ids),
        },
    )
    .await
}

fn rule_event_metadata(trust_rule_id: Uuid, affected_membership_ids: &[Uuid]) -> serde_json::Value {
    json!({
        "trust_rule_id": trust_rule_id,
        "affected_membership_ids": affected_membership_ids,
    })
}

fn take_page(items: &mut Vec<TrustRuleResponse>, limit: i64) -> Result<PageInfo, AppError> {
    let limit = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "trust_page_limit",
    })?;
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_cursor = if has_more {
        items.last().map(|item| validation::encode_cursor(item.id))
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

const TRUST_RULE_LIST_SQL: &str = r"
    SELECT rule.id, organization.org_id, rule.subject_kind,
           rule.subject_membership_id, rule.subject_tag_id, rule.target_kind,
           rule.target_silicon_membership_id, rule.target_tag_id,
           rule.trust_boundary::text AS trust_boundary,
           rule.trust_level::text AS trust_level,
           rule.version, rule.created_at, rule.updated_at
    FROM iam.trust_rules AS rule
    JOIN iam.organizations AS organization ON organization.id = rule.organization_id
    WHERE rule.organization_id = $1 AND rule.archived_at IS NULL
      AND ($2::uuid IS NULL OR rule.id > $2)
    ORDER BY rule.id LIMIT $3
";

const TRUST_RULE_BY_ID_SQL: &str = r"
    SELECT rule.id, organization.org_id, rule.subject_kind,
           rule.subject_membership_id, rule.subject_tag_id, rule.target_kind,
           rule.target_silicon_membership_id, rule.target_tag_id,
           rule.trust_boundary::text AS trust_boundary,
           rule.trust_level::text AS trust_level,
           rule.version, rule.created_at, rule.updated_at
    FROM iam.trust_rules AS rule
    JOIN iam.organizations AS organization ON organization.id = rule.organization_id
    WHERE rule.organization_id = $1 AND rule.id = $2 AND rule.archived_at IS NULL
    LIMIT 1
";

const TRUST_MATCH_SQL: &str = r"
    SELECT rule.id, rule.subject_kind, rule.target_kind,
           rule.trust_boundary::text AS trust_boundary,
           rule.trust_level::text AS trust_level
    FROM iam.trust_rules AS rule
    WHERE rule.organization_id = $1 AND rule.archived_at IS NULL
      AND (
          (rule.subject_kind = 'membership' AND rule.subject_membership_id = $2)
          OR (rule.subject_kind = 'tag' AND EXISTS (
              SELECT 1 FROM iam.membership_tags AS subject_tag
              WHERE subject_tag.organization_id = rule.organization_id
                AND subject_tag.membership_id = $2 AND subject_tag.tag_id = rule.subject_tag_id
          ))
      )
      AND (
          (rule.target_kind = 'silicon' AND rule.target_silicon_membership_id = $3)
          OR (rule.target_kind = 'tag' AND EXISTS (
              SELECT 1 FROM iam.membership_tags AS target_tag
              WHERE target_tag.organization_id = rule.organization_id
                AND target_tag.membership_id = $3 AND target_tag.tag_id = rule.target_tag_id
          ))
      )
";

const TRUST_DEFAULT_FOR_SUBJECT_SQL: &str = r"
    SELECT
        COALESCE(
            carbon_settings.default_trust_boundary,
            organization.default_trust_boundary
        )::text AS default_trust_boundary,
        COALESCE(
            carbon_settings.default_trust_level,
            organization.default_trust_level
        )::text AS default_trust_level
    FROM iam.organization_memberships AS subject_membership
    JOIN iam.organizations AS organization
      ON organization.id = subject_membership.organization_id
    LEFT JOIN iam.carbon_membership_settings AS carbon_settings
      ON carbon_settings.organization_id = subject_membership.organization_id
     AND carbon_settings.membership_id = subject_membership.id
     AND subject_membership.principal_kind = 'carbon'
    WHERE subject_membership.organization_id = $1
      AND subject_membership.id = $2
      AND subject_membership.status = 'active'
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restrictive_trust_wins_at_equal_specificity() {
        let matches = vec![
            MatchRow {
                id: Uuid::now_v7(),
                subject_kind: "tag".to_owned(),
                target_kind: "tag".to_owned(),
                trust_boundary: "internal".to_owned(),
                trust_level: "trusted".to_owned(),
            },
            MatchRow {
                id: Uuid::now_v7(),
                subject_kind: "tag".to_owned(),
                target_kind: "tag".to_owned(),
                trust_boundary: "external".to_owned(),
                trust_level: "not_trusted".to_owned(),
            },
        ];
        let result = evaluate_matches("internal", "trusted", &matches);
        assert!(matches!(
            result,
            Ok(value) if matches!(value.trust.level, TrustLevel::NotTrusted)
        ));
    }

    #[test]
    fn carbon_evaluation_defaults_are_membership_scoped() {
        assert!(TRUST_DEFAULT_FOR_SUBJECT_SQL.contains("carbon_membership_settings"));
        assert!(TRUST_DEFAULT_FOR_SUBJECT_SQL.contains("COALESCE"));
        assert!(
            TRUST_DEFAULT_FOR_SUBJECT_SQL.contains("subject_membership.principal_kind = 'carbon'")
        );
    }

    #[test]
    fn trust_rule_event_metadata_carries_the_exact_sorted_member_set() {
        let rule_id = Uuid::from_u128(10);
        let first = Uuid::from_u128(20);
        let second = Uuid::from_u128(30);
        assert_eq!(
            rule_event_metadata(rule_id, &[first, second]),
            json!({
                "trust_rule_id": rule_id,
                "affected_membership_ids": [first, second],
            })
        );
    }
}
