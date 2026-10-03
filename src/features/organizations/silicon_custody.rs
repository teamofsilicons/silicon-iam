//! Explicit organization-owned custody settings; membership invitations do not transfer custody.
use super::{
    support::{self, Claim, MutationEvent},
    validation,
};
use crate::{
    api::{ApiState, authentication::Authenticated},
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyPatch {
    can_create_organizations: bool,
}

pub(super) async fn get(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path((org, silicon)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let org = validation::organization_id(&org)?.to_string();
    let mut scope = support::begin_organization(&state, &actor, &org).await?;
    let value = read(
        &mut scope.transaction,
        scope.access.organization_id,
        &silicon,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &value, value["version"].as_i64())
}

pub(super) async fn patch(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path((org, silicon)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<CustodyPatch>,
) -> Result<Response, AppError> {
    let org = validation::organization_id(&org)?.to_string();
    let mut scope = support::begin_organization(&state, &actor, &org).await?;
    let org_id = scope.access.organization_id;
    let before = read(&mut scope.transaction, org_id, &silicon).await?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &actor,
        &headers,
        "PATCH /api/v1/organizations/{org_id}/silicons/{silicon_id}/custody",
        &silicon,
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let expected = validation::expected_version(&headers)?;
    let after: Value = sqlx::query_scalar::<_, Option<Value>>(
        "SELECT iam_private.update_organization_silicon_custody($1,$2,$3,$4)",
    )
    .bind(org_id)
    .bind(&silicon)
    .bind(expected)
    .bind(input.can_create_organizations)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(database)?
    .ok_or(AppError::PreconditionFailed {
        code: "etag_mismatch".into(),
    })?;
    let version = after["version"].as_i64().ok_or(AppError::Internal {
        category: "organization_custody_version",
    })?;
    let silicon_id = Id::identity(&silicon).map_err(|_| AppError::NotFound)?;
    support::record_mutation(
        &mut scope.transaction,
        &actor,
        org_id,
        MutationEvent {
            action: "silicon.custody.updated",
            target_type: "silicon",
            target_id: silicon_id,
            aggregate_type: "silicon_custody",
            aggregate_id: silicon_id,
            aggregate_version: version,
            event_type: "organization.silicon_custody.updated.v1",
            before_state: Some(before),
            after_state: Some(after.clone()),
            metadata: json!({"custodian_organization_id":org_id}),
        },
    )
    .await?;
    let body = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &after,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::OK, body, Some(version), false)
}

async fn read(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org: Id,
    silicon: &str,
) -> Result<Value, AppError> {
    sqlx::query_scalar::<_, Option<Value>>("SELECT iam_private.organization_silicon_custody($1,$2)")
        .bind(org)
        .bind(silicon)
        .fetch_one(&mut **tx)
        .await
        .map_err(database)?
        .ok_or(AppError::NotFound)
}
fn database(error: sqlx::Error) -> AppError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == "42501")
    {
        AppError::Forbidden
    } else {
        support::database(error)
    }
}
