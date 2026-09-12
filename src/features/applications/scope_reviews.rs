//! Application-specific critical-permission review discussions.
use super::{
    applications,
    error::ApiError,
    events::{self, Mutation},
    idempotency::{self, Claim},
    model::{AppPath, ApplicationScope, PageQuery},
    scopes,
    security::{Bearer, expected_version, require_carbon},
};
use crate::{
    api::ApiState,
    infrastructure::postgres::context::{self, DatabaseContext},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction, types::Json as SqlJson};
use uuid::Uuid;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Submit {
    app_scope: ApplicationScope,
    message: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Message {
    message: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Decision {
    decision: String,
    reason: Option<String>,
}
#[derive(Deserialize)]
pub(super) struct RequestPath {
    request_id: Uuid,
}
fn validate_message(message: &str) -> Result<(), ApiError> {
    if message.trim().is_empty() || message.chars().count() > 10000 {
        return Err(ApiError::validation(
            "message",
            "must contain 1-10000 characters",
        ));
    }
    Ok(())
}
async fn view(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> Result<Value, ApiError> {
    sqlx::query_scalar::<_, Option<SqlJson<Value>>>(
        "SELECT iam_private.application_scope_request_view($1)",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| scopes::database_error(&error))?
    .map(|value| value.0)
    .ok_or_else(ApiError::not_found)
}
pub(super) async fn get(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<RequestPath>,
) -> Result<Response, ApiError> {
    let actor = require_carbon(&access)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(actor))
        .await
        .map_err(|_| ApiError::internal("scope_review_context"))?;
    let result = view(&mut tx, path.request_id).await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("scope_review_commit"))?;
    applications::json_with_etag(StatusCode::OK, &result, version(&result)?)
}
pub(super) async fn list(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_carbon(&access)?;
    if query
        .status
        .as_deref()
        .is_some_and(|value| !matches!(value, "pending" | "approved" | "denied" | "superseded"))
    {
        return Err(ApiError::validation("status", "unknown review status"));
    }
    let cursor = super::cursor::decode(query.cursor.as_deref())?;
    let (at, id) = cursor.map_or((None, None), |c| (Some(c.at), Some(c.id)));
    let limit = super::cursor::limit(query.limit);
    let mut tx = context::begin(state.db(), DatabaseContext::principal(actor))
        .await
        .map_err(|_| ApiError::internal("scope_review_context"))?;
    let mut rows=sqlx::query_as::<_,(Uuid,time::OffsetDateTime,SqlJson<Value>)>("SELECT id,created_at,iam_private.application_scope_request_view(id) FROM iam.application_scope_requests WHERE ($1::text IS NULL OR status=$1) AND ($2::timestamptz IS NULL OR (created_at,id)<($2,$3)) ORDER BY created_at DESC,id DESC LIMIT $4")
        .bind(query.status).bind(at).bind(id).bind(limit+1).fetch_all(&mut *tx).await.map_err(|error|scopes::database_error(&error))?;
    let more = i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit;
    if more {
        rows.pop();
    }
    let next = if more {
        rows.last()
            .map(|(id, at, _)| super::cursor::encode(*at, *id))
            .transpose()?
    } else {
        None
    };
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("scope_review_commit"))?;
    Ok(Json(
        json!({"items":rows.into_iter().map(|(_,_,value)|value.0).collect::<Vec<_>>(),"page":{"next_cursor":next,"has_more":more}}),
    ))
}
pub(super) async fn submit(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AppPath>,
    headers: HeaderMap,
    Json(input): Json<Submit>,
) -> Result<Response, ApiError> {
    let actor = require_carbon(&access)?;
    validate_message(&input.message)?;
    scopes::validate(&input.app_scope)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(actor))
        .await
        .map_err(|_| ApiError::internal("scope_review_context"))?;
    let app = applications::resolve_technical_app(&mut tx, actor, &path.app_id, false).await?;
    let canonical =
        serde_json::to_vec(&input).map_err(|_| ApiError::internal("scope_review_canonical"))?;
    let caller = format!("scope-review:{actor}:{}", app.id);
    let claim = idempotency::claim::<Value>(
        &mut tx,
        &state.crypto,
        &headers,
        &caller,
        "POST /api/v1/applications/{app_id}/scope-requests",
        &canonical,
        false,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("scope_review_replay"))?;
        return applications::json_with_etag_replayed(
            StatusCode::from_u16(status).map_err(|_| ApiError::internal("scope_review_status"))?,
            &response,
            response["version"].as_i64().unwrap_or(app.version),
        );
    }
    let Claim::Acquired(key) = claim else {
        return Err(ApiError::internal("scope_review_claim"));
    };
    let app = applications::resolve_technical_app(&mut tx, actor, &path.app_id, true).await?;
    if expected_version(&headers)? != app.version {
        return Err(ApiError::precondition_failed());
    }
    scopes::configure(&mut tx, app.id, &input.app_scope, actor).await?;
    let ids = sqlx::query_scalar::<_, Vec<Uuid>>(
        "SELECT iam_private.submit_application_scope_requests($1,$2,$3)",
    )
    .bind(app.id)
    .bind(actor)
    .bind(&input.message)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| scopes::database_error(&error))?;
    if ids.is_empty() {
        return Err(ApiError::conflict("no_critical_scopes_awaiting_review"));
    }
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        items.push(view(&mut tx, id).await?);
    }
    let app_version =
        sqlx::query_scalar::<_, i64>("SELECT version FROM iam.applications WHERE id=$1")
            .bind(app.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ApiError::internal("scope_review_version"))?;
    let result = json!({"items":items,"version":app_version});
    record(
        &mut tx,
        actor,
        access.authentication_session_id,
        app.organization_id,
        app.id,
        app.id,
        app_version,
        "application.scope_requested",
        &result,
    )
    .await?;
    idempotency::complete(&mut tx, &state.crypto, key, 201, &result, false).await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("scope_review_commit"))?;
    applications::json_with_etag(StatusCode::CREATED, &result, app_version)
}
pub(super) async fn reply(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<RequestPath>,
    headers: HeaderMap,
    Json(input): Json<Message>,
) -> Result<Response, ApiError> {
    validate_message(&input.message)?;
    mutate(
        &state,
        &access,
        &headers,
        path.request_id,
        "message",
        &input.message,
        serde_json::to_vec(&input).map_err(|_| ApiError::internal("scope_review_canonical"))?,
    )
    .await
}
pub(super) async fn decide(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<RequestPath>,
    headers: HeaderMap,
    Json(input): Json<Decision>,
) -> Result<Response, ApiError> {
    if !matches!(input.decision.as_str(), "approve" | "deny") {
        return Err(ApiError::validation("decision", "must be approve or deny"));
    }
    if input.decision == "deny" {
        validate_message(input.reason.as_deref().unwrap_or(""))?;
    }
    let message = input
        .reason
        .clone()
        .unwrap_or_else(|| "Approved the requested critical permissions.".into());
    validate_message(&message)?;
    mutate(
        &state,
        &access,
        &headers,
        path.request_id,
        &input.decision,
        &message,
        serde_json::to_vec(&input).map_err(|_| ApiError::internal("scope_review_canonical"))?,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn mutate(
    state: &ApiState,
    access: &crate::infrastructure::postgres::tokens::AccessContext,
    headers: &HeaderMap,
    id: Uuid,
    action: &str,
    message: &str,
    canonical: Vec<u8>,
) -> Result<Response, ApiError> {
    let actor = require_carbon(access)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(actor))
        .await
        .map_err(|_| ApiError::internal("scope_review_context"))?;
    view(&mut tx, id).await?;
    let caller = format!("scope-review:{actor}:{id}");
    let route = if action == "message" {
        "POST /api/v1/application-scope-requests/{request_id}/messages"
    } else {
        "POST /api/v1/application-scope-requests/{request_id}/decisions"
    };
    let claim = idempotency::claim::<Value>(
        &mut tx,
        &state.crypto,
        headers,
        &caller,
        route,
        &canonical,
        false,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("scope_review_replay"))?;
        return applications::json_with_etag_replayed(
            StatusCode::from_u16(status).map_err(|_| ApiError::internal("scope_review_status"))?,
            &response,
            version(&response)?,
        );
    }
    let Claim::Acquired(key) = claim else {
        return Err(ApiError::internal("scope_review_claim"));
    };
    let response = sqlx::query_scalar::<_, SqlJson<Value>>(
        "SELECT iam_private.mutate_application_scope_request($1,$2,$3,$4,$5)",
    )
    .bind(id)
    .bind(actor)
    .bind(expected_version(headers)?)
    .bind(action)
    .bind(message)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| scopes::database_error(&error))?
    .0;
    let (app, org) = sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT * FROM iam_private.application_scope_request_context($1)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ApiError::internal("scope_review_application"))?;
    context::select_organization(&mut tx, org)
        .await
        .map_err(|_| ApiError::internal("scope_review_org"))?;
    record(
        &mut tx,
        actor,
        access.authentication_session_id,
        org,
        app,
        id,
        version(&response)?,
        "application.scope_review_updated",
        &response,
    )
    .await?;
    idempotency::complete(&mut tx, &state.crypto, key, 200, &response, false).await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("scope_review_commit"))?;
    applications::json_with_etag(StatusCode::OK, &response, version(&response)?)
}
fn version(value: &Value) -> Result<i64, ApiError> {
    value["version"]
        .as_i64()
        .ok_or_else(|| ApiError::internal("scope_review_version"))
}
#[allow(clippy::too_many_arguments)]
async fn record(
    tx: &mut Transaction<'_, Postgres>,
    actor: Uuid,
    session: Uuid,
    org: Uuid,
    app: Uuid,
    id: Uuid,
    version: i64,
    action: &'static str,
    value: &Value,
) -> Result<(), ApiError> {
    events::record(
        tx,
        Mutation {
            actor_id: Some(actor),
            authentication_session_id: Some(session),
            organization_id: org,
            application_id: app,
            action,
            target_type: "application_scope_request",
            target_id: Some(id),
            aggregate_type: "application_scope_request",
            aggregate_id: id,
            aggregate_version: version,
            before: None,
            after: Some(value.clone()),
            metadata: json!({"request_id":id}),
            event_type: action,
        },
    )
    .await
}
