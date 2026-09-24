//! One presentation identity, with independent consent and credentials per member.
use std::collections::BTreeSet;

use crate::domain::id::Id;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction, types::Json as SqlJson};

use super::{
    applications, batch_login, cursor,
    error::ApiError,
    idempotency::{self, Claim},
    model::{BatchLoginRequest, OrganizationPageQuery},
    oauth,
    security::{Bearer, expected_version, organization_filter, require_carbon},
    validation,
};
use crate::{
    api::ApiState,
    infrastructure::postgres::{
        context::{self, DatabaseContext},
        events::{self, AggregateVersion, AuditRecord, OutboxRecord},
        tokens::AccessContext,
    },
};

#[derive(Deserialize)]
pub(super) struct BundlePath {
    bundle_id: String,
}

#[derive(Deserialize)]
pub(super) struct AvailabilityPath {
    org_id: String,
}

#[derive(Serialize)]
struct Availability {
    available: bool,
}

pub(super) const BUNDLE_AVAILABILITY_QUERY: &str =
    "SELECT iam_private.application_bundle_availability($1)";

pub(super) const BUNDLE_LIST_QUERY: &str = r"
    SELECT id, created_at, bundle_id
    FROM iam.application_bundles
    WHERE deleted_at IS NULL
      AND ($4::uuid IS NULL OR organization_id = $4)
      AND ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2))
    ORDER BY created_at DESC, id DESC
    LIMIT $3
";

pub(super) async fn availability(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<AvailabilityPath>,
) -> Result<Response, ApiError> {
    let actor = require_carbon(&access)?;
    validation::org_id(&path.org_id)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(actor))
        .await
        .map_err(|_| ApiError::internal("bundle_availability_context"))?;
    let available = sqlx::query_scalar::<_, Option<bool>>(BUNDLE_AVAILABILITY_QUERY)
        .bind(path.org_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::internal("bundle_availability"))?
        .ok_or_else(ApiError::not_found)?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("bundle_availability_commit"))?;
    let mut response = Json(Availability { available }).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Create {
    org_id: String,
    app_id: String,
    app_name: Option<String>,
    app_logo: Option<String>,
    app_ids: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Public wire field names mirror ApplicationPatch.
pub(super) struct Patch {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_with::rust::double_option"
    )]
    #[allow(clippy::option_option)]
    app_name: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_with::rust::double_option"
    )]
    #[allow(clippy::option_option)]
    app_logo: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_ids: Option<Vec<String>>,
}

#[derive(sqlx::FromRow)]
struct BundleRow {
    organization_id: Id,
    document: SqlJson<Value>,
}

pub(super) fn database_error(error: &sqlx::Error) -> ApiError {
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
    {
        Some("42501") => ApiError::forbidden("application_bundle_forbidden"),
        Some("40001") => ApiError::precondition_failed(),
        Some("P0002") => ApiError::not_found(),
        Some("23505") => ApiError::conflict("bundle_id_already_exists"),
        Some("22023" | "23514" | "23503") => ApiError::validation(
            "bundle",
            "Choose 1–100 unique, active applications belonging to this organization.",
        ),
        _ => ApiError::internal("application_bundle_database"),
    }
}

async fn view(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    login: bool,
    lock: bool,
) -> Result<BundleRow, ApiError> {
    sqlx::query_as::<_, BundleRow>("SELECT * FROM iam_private.application_bundle_view($1,$2,$3)")
        .bind(id)
        .bind(login)
        .bind(lock)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| database_error(&error))?
        .ok_or_else(ApiError::not_found)
}
fn version(value: &Value) -> Result<i64, ApiError> {
    value["version"]
        .as_i64()
        .ok_or_else(|| ApiError::internal("bundle_version"))
}
fn identity(value: &Value) -> Result<Id, ApiError> {
    value["id"]
        .as_str()
        .and_then(|id| Id::parse(id).ok())
        .ok_or_else(|| ApiError::internal("bundle_id"))
}
fn member_ids(value: &Value) -> Result<Vec<String>, ApiError> {
    serde_json::from_value(value["app_ids"].clone())
        .map_err(|_| ApiError::internal("bundle_members"))
}
fn metadata(name: Option<&str>, logo: Option<&str>) -> Result<(), ApiError> {
    if name.is_some_and(|value| value.trim().is_empty() || value.chars().count() > 200) {
        return Err(ApiError::validation(
            "app_name",
            "must contain 1–200 characters",
        ));
    }
    if let Some(logo) = logo {
        let url = url::Url::parse(logo)
            .map_err(|_| ApiError::validation("app_logo", "must be an HTTPS URL"))?;
        if logo.len() > 2048
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(ApiError::validation(
                "app_logo",
                "must be an HTTPS URL without credentials",
            ));
        }
    }
    Ok(())
}
fn selections(expected: &[String], input: &BatchLoginRequest) -> Result<(), ApiError> {
    batch_login::validate(input)?;
    let expected = expected.iter().collect::<BTreeSet<_>>();
    let supplied = input
        .applications
        .iter()
        .map(|app| &app.app_id)
        .collect::<BTreeSet<_>>();
    if expected != supplied {
        return Err(ApiError::precondition(
            "bundle_members_changed",
            "The bundle members changed. Reload the bundle and review its current permissions.",
        ));
    }
    Ok(())
}

pub(super) async fn list(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Query(query): Query<OrganizationPageQuery>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_carbon(&access)?;
    let cursor = cursor::decode(query.cursor.as_deref())?;
    let (at, id) = cursor.map_or((None, None), |value| (Some(value.at), Some(value.id)));
    let limit = cursor::limit(query.limit);
    let mut tx = context::begin(state.db(), DatabaseContext::principal(actor))
        .await
        .map_err(|_| ApiError::internal("bundle_context"))?;
    let organization_id = organization_filter(&mut tx, query.org_id.as_deref()).await?;
    let mut rows = sqlx::query_as::<_, (Id, time::OffsetDateTime, String)>(BUNDLE_LIST_QUERY)
        .bind(at)
        .bind(id)
        .bind(limit + 1)
        .bind(organization_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| database_error(&error))?;
    let more = i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit;
    if more {
        rows.pop();
    }
    let next = if more {
        rows.last()
            .map(|(id, at, _)| cursor::encode(*at, *id))
            .transpose()?
    } else {
        None
    };
    let mut items = Vec::with_capacity(rows.len());
    for (_, _, id) in rows {
        items.push(view(&mut tx, &id, false, false).await?.document.0);
    }
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("bundle_commit"))?;
    Ok(Json(
        json!({"items":items,"page":{"next_cursor":next,"has_more":more}}),
    ))
}

pub(super) async fn get(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<BundlePath>,
) -> Result<Response, ApiError> {
    let actor = require_carbon(&access)?;
    validation::bundle_id(&path.bundle_id)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(actor))
        .await
        .map_err(|_| ApiError::internal("bundle_context"))?;
    let value = view(&mut tx, &path.bundle_id, false, false)
        .await?
        .document
        .0;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("bundle_commit"))?;
    applications::json_with_etag(StatusCode::OK, &value, version(&value)?)
}

pub(super) async fn create(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    headers: HeaderMap,
    Json(input): Json<Create>,
) -> Result<Response, ApiError> {
    validation::org_id(&input.org_id)?;
    validation::local_app_id(&input.app_id)?;
    validation::batch_app_ids(input.app_ids.iter().map(String::as_str))?;
    metadata(input.app_name.as_deref(), input.app_logo.as_deref())?;
    let id = validation::qualify_bundle_id(&input.org_id, &input.app_id)?;
    mutate(
        &state,
        &access,
        &headers,
        &id,
        "create",
        serde_json::to_value(input).map_err(|_| ApiError::internal("bundle_input"))?,
    )
    .await
}
pub(super) async fn patch(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<BundlePath>,
    headers: HeaderMap,
    Json(input): Json<Patch>,
) -> Result<Response, ApiError> {
    if input.app_name.is_none() && input.app_logo.is_none() && input.app_ids.is_none() {
        return Err(ApiError::validation(
            "body",
            "must contain at least one change",
        ));
    }
    if let Some(ids) = &input.app_ids {
        validation::batch_app_ids(ids.iter().map(String::as_str))?;
    }
    metadata(
        input.app_name.as_ref().and_then(Option::as_deref),
        input.app_logo.as_ref().and_then(Option::as_deref),
    )?;
    mutate(
        &state,
        &access,
        &headers,
        &path.bundle_id,
        "update",
        serde_json::to_value(input).map_err(|_| ApiError::internal("bundle_input"))?,
    )
    .await
}
pub(super) async fn delete(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<BundlePath>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    mutate(
        &state,
        &access,
        &headers,
        &path.bundle_id,
        "delete",
        json!({}),
    )
    .await
}

async fn mutate(
    state: &ApiState,
    access: &AccessContext,
    headers: &HeaderMap,
    id: &str,
    action: &str,
    input: Value,
) -> Result<Response, ApiError> {
    let actor = require_carbon(access)?;
    validation::bundle_id(id)?;
    let required_version = if action == "create" {
        0
    } else {
        expected_version(headers)?
    };
    let mut tx = context::begin(state.db(), DatabaseContext::principal(actor))
        .await
        .map_err(|_| ApiError::internal("bundle_context"))?;
    let org = management_organization(&mut tx, id, action, &input, actor).await?;
    context::select_organization(&mut tx, org)
        .await
        .map_err(|_| ApiError::internal("bundle_organization"))?;
    applications::lock_current_application_manager(&mut tx, org, actor).await?;
    let route = match action {
        "create" => "POST /api/v1/application-bundles",
        "delete" => "DELETE /api/v1/application-bundles/{bundle_id}",
        _ => "PATCH /api/v1/application-bundles/{bundle_id}",
    };
    let caller = format!("bundle:{actor}:{id}");
    let canonical = serde_json::to_vec(&input).map_err(|_| ApiError::internal("bundle_input"))?;
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
            .map_err(|_| ApiError::internal("bundle_replay"))?;
        if status == 204 {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response
                .headers_mut()
                .insert("idempotency-replayed", HeaderValue::from_static("true"));
            return Ok(response);
        }
        return applications::json_with_etag_replayed(
            StatusCode::from_u16(status).map_err(|_| ApiError::internal("bundle_status"))?,
            &response,
            version(&response)?,
        );
    }
    let Claim::Acquired(key) = claim else {
        return Err(ApiError::internal("bundle_claim"));
    };
    let before = if action == "create" {
        None
    } else {
        Some(view(&mut tx, id, false, false).await?.document.0)
    };
    let row = sqlx::query_as::<_, BundleRow>(
        "SELECT * FROM iam_private.mutate_application_bundle($1,$2,$3,$4,$5)",
    )
    .bind(id)
    .bind(actor)
    .bind(required_version)
    .bind(action)
    .bind(SqlJson(input))
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| database_error(&error))?;
    let value = row.document.0;
    let event = match action {
        "create" => "application_bundle.created.v1",
        "delete" => "application_bundle.deleted.v1",
        _ => "application_bundle.updated.v1",
    };
    record(&mut tx, access, row.organization_id, &value, before, event).await?;
    let status = match action {
        "create" => StatusCode::CREATED,
        "delete" => StatusCode::NO_CONTENT,
        _ => StatusCode::OK,
    };
    idempotency::complete(&mut tx, &state.crypto, key, status.as_u16(), &value, false).await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("bundle_commit"))?;
    if action == "delete" {
        Ok(status.into_response())
    } else {
        applications::json_with_etag(status, &value, version(&value)?)
    }
}

async fn management_organization(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    action: &str,
    input: &Value,
    actor: Id,
) -> Result<Id, ApiError> {
    if action == "create" {
        sqlx::query_scalar::<_, Option<Id>>(
            "SELECT iam_private.lock_application_creation_organization($1,$2)",
        )
        .bind(input["org_id"].as_str())
        .bind(actor)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| database_error(&error))?
    } else {
        sqlx::query_scalar::<_, Option<Id>>(
            "SELECT iam_private.application_bundle_management_organization($1)",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| database_error(&error))?
    }
    .ok_or_else(ApiError::not_found)
}

async fn record(
    tx: &mut Transaction<'_, Postgres>,
    access: &AccessContext,
    org: Id,
    value: &Value,
    before: Option<Value>,
    event: &'static str,
) -> Result<(), ApiError> {
    let aggregate = AggregateVersion {
        aggregate_type: "application_bundle",
        aggregate_id: identity(value)?,
        version: version(value)?,
    };
    events::record_audit(
        tx,
        AuditRecord {
            actor: Some(access.subject),
            authentication_session_id: Some(access.authentication_session_id),
            organization_id: Some(org),
            application_id: None,
            action: event,
            target_type: "application_bundle",
            target_id: Some(aggregate.aggregate_id),
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state: before,
            after_state: Some(value.clone()),
            metadata: json!({"bundle_id":value["bundle_id"]}),
        },
    )
    .await
    .map_err(|_| ApiError::internal("bundle_audit"))?;
    events::enqueue_outbox(
        tx,
        OutboxRecord {
            organization_id: Some(org),
            aggregate,
            event_ordinal: 1,
            event_type: event,
            schema_version: 1,
            payload: json!({"bundle_id":value["bundle_id"]}),
            silicon_webhook_routing: None,
        },
    )
    .await
    .map_err(|_| ApiError::internal("bundle_outbox"))?;
    Ok(())
}

pub(super) async fn organizations(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<BundlePath>,
) -> Result<Json<Value>, ApiError> {
    oauth::require_direct_login(&access)?;
    validation::bundle_id(&path.bundle_id)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(access.subject.id))
        .await
        .map_err(|_| ApiError::internal("bundle_context"))?;
    let bundle = view(&mut tx, &path.bundle_id, true, true).await?.document.0;
    let mut items = Vec::new();
    for id in member_ids(&bundle)? {
        items.push(oauth::login_choices(&mut tx, &access, &id).await?);
    }
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("bundle_commit"))?;
    Ok(Json(json!({"bundle":bundle,"items":items})))
}
pub(super) async fn issue(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Path(path): Path<BundlePath>,
    headers: HeaderMap,
    Json(input): Json<BatchLoginRequest>,
) -> Result<Response, ApiError> {
    oauth::require_direct_login(&access)?;
    validation::bundle_id(&path.bundle_id)?;
    batch_login::validate(&input)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(access.subject.id))
        .await
        .map_err(|_| ApiError::internal("bundle_context"))?;
    let bundle = view(&mut tx, &path.bundle_id, true, true).await?.document.0;
    selections(&member_ids(&bundle)?, &input)?;
    let caller = format!(
        "bundle-login:{}:{}:{}",
        access.subject.id,
        access.authentication_session_id,
        identity(&bundle)?
    );
    let (status, response) = batch_login::issue_in_transaction(
        &mut tx,
        &state,
        &access,
        &headers,
        &input,
        &caller,
        "POST /api/v1/app-auth/bundles/{bundle_id}/short-lived-tokens",
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("bundle_commit"))?;
    Ok((status, Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use super::super::model::BatchLoginSelection;
    use super::*;
    #[tokio::test]
    #[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL on isolated local PostgreSQL"]
    async fn bundle_database_contract() -> anyhow::Result<()> {
        let database = crate::test_database::TestDatabase::start().await?;
        let pool = database.pool.clone();
        crate::infrastructure::postgres::migrate(&pool).await?;
        sqlx::raw_sql(include_str!("bundles_test.sql"))
            .execute(&pool)
            .await?;
        Ok(())
    }
    #[test]
    fn bundle_handoff_rejects_omitted_added_and_duplicate_members() {
        let mut request = BatchLoginRequest {
            applications: vec![BatchLoginSelection {
                app_id: "files".into(),
                org_ids: vec!["work".into()],
                scope_version: 1,
                approved_scopes: vec!["self.identity.read".into()],
            }],
            redirect_uri: None,
        };
        let expected = vec!["files".into()];
        assert!(selections(&expected, &request).is_ok());
        assert!(selections(&["files".into(), "notes".into()], &request).is_err());
        request.applications.push(request.applications[0].clone());
        assert!(selections(&expected, &request).is_err());
        request.applications[1].app_id = "other-notes".into();
        assert!(selections(&expected, &request).is_err());
    }
    #[test]
    fn bundle_metadata_preserves_safe_external_images() {
        assert!(metadata(Some("Workspace"), Some("https://example.com/icon.svg")).is_ok());
        assert!(metadata(Some("  "), None).is_err());
        assert!(metadata(None, Some("javascript:alert(1)")).is_err());
        assert!(metadata(None, Some("https://secret@example.com/icon.svg")).is_err());
        assert!(metadata(None, Some("https://cdn.example/icon.png?version=2")).is_ok());
        assert!(metadata(None, Some("http://example.com/icon.png")).is_err());
    }
    #[test]
    fn bundle_logo_clear_and_omission_have_distinct_wire_meanings() -> anyhow::Result<()> {
        let unchanged: Patch = serde_json::from_value(json!({"app_name":"Workspace"}))?;
        assert_eq!(unchanged.app_logo, None);
        let cleared: Patch = serde_json::from_value(json!({"app_logo":null}))?;
        assert_eq!(cleared.app_logo, Some(None));
        assert_eq!(serde_json::to_value(cleared)?, json!({"app_logo":null}));
        assert_eq!(
            serde_json::to_value(Availability { available: false })?,
            json!({"available":false})
        );
        Ok(())
    }
}
