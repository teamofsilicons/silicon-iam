//! Account-owned acceptance of invitations for existing Silicon identities.
use super::{
    support::{self, Claim},
    validation,
};
use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{actor::ActorType, id::Id},
    error::AppError,
    infrastructure::postgres::context::{self, DatabaseContext},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction, types::Json as SqlJson};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Create {
    silicon_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Decision {
    decision: String,
}
pub(super) async fn candidates(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(org): Path<String>,
) -> Result<Response, AppError> {
    list_organization(&state, &actor, &org, true).await
}
pub(super) async fn list(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(org): Path<String>,
) -> Result<Response, AppError> {
    list_organization(&state, &actor, &org, false).await
}
async fn list_organization(
    state: &ApiState,
    actor: &Authenticated,
    org: &str,
    candidates: bool,
) -> Result<Response, AppError> {
    let org = validation::organization_id(org)?.to_string();
    let mut scope = support::begin_organization(state, actor, &org).await?;
    let query = if candidates {
        "SELECT iam_private.silicon_invitation_candidates($1)"
    } else {
        "SELECT iam_private.silicon_invitations_list($1)"
    };
    let SqlJson(result): SqlJson<Value> = sqlx::query_scalar(query)
        .bind(scope.access.organization_id)
        .fetch_one(&mut *scope.transaction)
        .await
        .map_err(database)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &result, None)
}
pub(super) async fn create(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(org): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Create>,
) -> Result<Response, AppError> {
    let org = validation::organization_id(&org)?.to_string();
    let mut scope = support::begin_organization(&state, &actor, &org).await?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &actor,
        &headers,
        "POST /api/v1/organizations/{org_id}/silicon-invitations",
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let SqlJson(result): SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.silicon_invitation_create($1,$2,$3)")
            .bind(scope.access.organization_id)
            .bind(input.silicon_id)
            .bind(Id::now_v7())
            .fetch_one(&mut *scope.transaction)
            .await
            .map_err(database)?;
    let bytes = support::finish_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &result,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(StatusCode::CREATED, bytes, None, false)
}
async fn own_context<'a>(
    state: &'a ApiState,
    actor: &Authenticated,
) -> Result<Transaction<'a, Postgres>, AppError> {
    if actor.0.subject.actor_type != ActorType::Silicon
        || actor.0.client_application_id.is_some()
        || actor.0.audience != "silicon-iam"
        || !actor.0.scopes.iter().any(|scope| scope == "iam.self")
    {
        return Err(AppError::Forbidden);
    }
    context::begin(state.db(), DatabaseContext::principal(actor.0.subject.id))
        .await
        .map_err(support::database)
}
pub(super) async fn inbox(
    State(state): State<ApiState>,
    actor: Authenticated,
) -> Result<Response, AppError> {
    let mut tx = own_context(&state, &actor).await?;
    let SqlJson(result): SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.silicon_invitations_list(NULL)")
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    tx.commit().await.map_err(support::database)?;
    support::json(StatusCode::OK, &result, None)
}
pub(super) async fn decide(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(id): Path<uuid::Uuid>,
    headers: HeaderMap,
    Json(input): Json<Decision>,
) -> Result<Response, AppError> {
    let mut tx = own_context(&state, &actor).await?;
    let lease = match support::claim_resource(
        &mut tx,
        &state,
        &actor,
        &headers,
        "POST /api/v1/me/silicon-invitations/{id}/decision",
        &id.to_string(),
        &input,
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let SqlJson(result): SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.silicon_invitation_decide($1,$2)")
            .bind(id)
            .bind(input.decision)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    let bytes = support::finish_json(&mut tx, &state, lease, StatusCode::OK, &result).await?;
    tx.commit().await.map_err(support::database)?;
    support::json_response(StatusCode::OK, bytes, None, false)
}
pub(super) async fn revoke(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path((org, id)): Path<(String, uuid::Uuid)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org = validation::organization_id(&org)?.to_string();
    let mut scope = support::begin_organization(&state, &actor, &org).await?;
    let lease = match support::claim_resource(
        &mut scope.transaction,
        &state,
        &actor,
        &headers,
        "POST /api/v1/organizations/{org_id}/silicon-invitations/{id}/revoke",
        &id.to_string(),
        &json!({}),
        false,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };
    let SqlJson(result): SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.silicon_invitation_revoke($1,$2)")
            .bind(scope.access.organization_id)
            .bind(id)
            .fetch_one(&mut *scope.transaction)
            .await
            .map_err(database)?;
    let bytes = support::finish_json(
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
    support::json_response(StatusCode::OK, bytes, None, false)
}
fn database(error: sqlx::Error) -> AppError {
    match error
        .as_database_error()
        .map(sqlx::error::DatabaseError::message)
    {
        Some("silicon_invitation_forbidden") => AppError::Forbidden,
        Some("silicon_invitation_not_found") => AppError::NotFound,
        Some("silicon_invitation_inactive") => AppError::Gone {
            code: "silicon_invitation_inactive".into(),
        },
        Some("silicon_already_member") => AppError::Conflict {
            code: "silicon_already_member".into(),
        },
        _ if error
            .as_database_error()
            .is_some_and(|e| e.code().as_deref() == Some("23505")) =>
        {
            AppError::Conflict {
                code: "silicon_invitation_exists".into(),
            }
        }
        _ => support::database(error),
    }
}
