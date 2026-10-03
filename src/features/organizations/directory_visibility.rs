//! Directional, organization-default and per-viewer directory policies.
use super::{
    support::{self, Claim, MutationEvent},
    validation,
};
use crate::{
    api::{ApiState, authentication::Authenticated, membership_ids::MembershipPath},
    domain::id::Id,
    error::AppError,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::types::Json as SqlJson;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    mode: String,
    #[serde(default)]
    visible_membership_ids: Vec<String>,
}
pub(super) async fn get_default(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(org): Path<String>,
) -> Result<Response, AppError> {
    read(&state, &actor, &org, None).await
}
pub(super) async fn get_member(
    State(state): State<ApiState>,
    actor: Authenticated,
    MembershipPath((org, member)): MembershipPath,
) -> Result<Response, AppError> {
    read(&state, &actor, &org, Some(member)).await
}
async fn read(
    state: &ApiState,
    actor: &Authenticated,
    org: &str,
    member: Option<Id>,
) -> Result<Response, AppError> {
    let org = validation::organization_id(org)?.to_string();
    let mut tx = support::begin_organization(state, actor, &org).await?;
    let SqlJson(value): SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.directory_visibility_get($1::uuid,$2::uuid)")
            .bind(tx.access.organization_id)
            .bind(member)
            .fetch_one(&mut *tx.transaction)
            .await
            .map_err(database)?;
    tx.transaction.commit().await.map_err(support::database)?;
    support::json(StatusCode::OK, &value, value["version"].as_i64())
}
pub(super) async fn replace_default(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(org): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Policy>,
) -> Result<Response, AppError> {
    replace(&state, &actor, &org, None, &headers, input).await
}
pub(super) async fn replace_member(
    State(state): State<ApiState>,
    actor: Authenticated,
    MembershipPath((org, member)): MembershipPath,
    headers: HeaderMap,
    Json(input): Json<Policy>,
) -> Result<Response, AppError> {
    replace(&state, &actor, &org, Some(member), &headers, input).await
}
async fn replace(
    state: &ApiState,
    actor: &Authenticated,
    org: &str,
    member: Option<Id>,
    headers: &HeaderMap,
    input: Policy,
) -> Result<Response, AppError> {
    let org = validation::organization_id(org)?.to_string();
    let mut tx = support::begin_organization(state, actor, &org).await?;
    let org_key = tx.access.organization_id;
    let route = if member.is_some() {
        "PUT /api/v1/organizations/{org_id}/members/{membership_id}/directory-visibility"
    } else {
        "PUT /api/v1/organizations/{org_id}/directory-visibility"
    };
    let lease = match support::claim_resource(
        &mut tx.transaction,
        state,
        actor,
        headers,
        route,
        &member.unwrap_or(org_key).to_string(),
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let version = validation::expected_version(headers)?;
    let SqlJson(before): SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.directory_visibility_get($1::uuid,$2::uuid)")
            .bind(org_key)
            .bind(member)
            .fetch_one(&mut *tx.transaction)
            .await
            .map_err(database)?;
    let SqlJson(after): SqlJson<Value> = sqlx::query_scalar(
        "SELECT iam_private.directory_visibility_replace($1::uuid,$2::uuid,$3,$4,$5)",
    )
    .bind(org_key)
    .bind(member)
    .bind(&input.mode)
    .bind(&input.visible_membership_ids)
    .bind(version)
    .fetch_one(&mut *tx.transaction)
    .await
    .map_err(database)?;
    let current = after["version"].as_i64().ok_or(AppError::Internal {
        category: "directory_visibility_version",
    })?;
    support::record_mutation(
        &mut tx.transaction,
        actor,
        org_key,
        MutationEvent {
            action: "directory.visibility_updated",
            target_type: if member.is_some() {
                "organization_membership"
            } else {
                "organization"
            },
            target_id: member.unwrap_or(org_key),
            aggregate_type: "directory_visibility",
            aggregate_id: member.unwrap_or(org_key),
            aggregate_version: current,
            event_type: "organization.directory_visibility.updated.v1",
            before_state: Some(before),
            after_state: Some(after.clone()),
            metadata: json!({"membership_id":member}),
        },
    )
    .await?;
    let body =
        support::finish_json(&mut tx.transaction, state, lease, StatusCode::OK, &after).await?;
    tx.transaction.commit().await.map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(current), false)
}
fn database(error: sqlx::Error) -> AppError {
    match error
        .as_database_error()
        .map(sqlx::error::DatabaseError::message)
    {
        Some("directory_visibility_forbidden") => AppError::Forbidden,
        Some("directory_member_not_found") => AppError::NotFound,
        Some("directory_visibility_changed") => AppError::PreconditionFailed {
            code: "etag_mismatch".into(),
        },
        Some("directory_visibility_invalid") => AppError::Validation {
            details: json!({"directory_visibility":"Choose all, self, selected, or a member's inherit policy, with up to 1000 distinct active membership IDs from this organization only for selected mode."}),
        },
        _ => support::database(error),
    }
}

pub(super) async fn candidates(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(org): Path<String>,
) -> Result<Response, AppError> {
    let org = validation::organization_id(&org)?.to_string();
    let mut scope = support::begin_organization(&state, &actor, &org).await?;
    let SqlJson(value): SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.directory_visibility_candidates($1)")
            .bind(scope.access.organization_id)
            .fetch_one(&mut *scope.transaction)
            .await
            .map_err(database)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &value, None)
}
