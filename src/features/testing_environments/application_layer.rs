//! Application-authenticated testing-environment orchestration.

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::actor::{ActorRef, ActorType},
    error::AppError,
    features::applications::security::ApplicationClient,
    infrastructure::{
        postgres::{
            context::{self, DatabaseContext},
            idempotency::{self, IdempotencyClaim, IdempotencyKey},
        },
        testing_plane::{self, SelectedEnvironment},
    },
};

use super::{
    graph,
    model::{EnvironmentCreate, PageInfo, PageQuery},
    support, validation,
};

const CREATE_ROUTE: &str = "POST /api/v1/application/testing-environments";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateRequest {
    name: String,
    description: Option<String>,
    iam_test_key: Option<String>,
}

#[derive(Serialize)]
struct Created {
    environment_id: Uuid,
    org_id: String,
    name: String,
    description: Option<String>,
    iam_test_key: String,
    app_id: String,
    app_secret: String,
    dependencies: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    secret_replay_expires_at: OffsetDateTime,
}

#[derive(Serialize, sqlx::FromRow)]
struct ApplicationEnvironment {
    environment_id: Uuid,
    org_id: String,
    name: String,
    description: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    last_activity_at: OffsetDateTime,
    retention_days: i32,
    status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    purge_after: Option<OffsetDateTime>,
    version: i64,
    can_manage: bool,
}

#[derive(Serialize)]
struct Page {
    items: Vec<ApplicationEnvironment>,
    page: PageInfo,
}

pub(super) async fn list(
    State(state): State<ApiState>,
    client: ApplicationClient,
    Query(query): Query<PageQuery>,
) -> Result<Response, AppError> {
    support::plane(&state)?;
    let (cursor, limit, status) = validation::page(&query)?;
    let mut transaction = begin(&state, &client).await?;
    let mut items = sqlx::query_as::<_, ApplicationEnvironment>(
        "SELECT * FROM iam_private.list_application_testing_environments($1,$2,$3)",
    )
    .bind(cursor)
    .bind(i32::try_from(limit + 1).unwrap_or(101))
    .bind(status)
    .fetch_all(&mut *transaction)
    .await
    .map_err(support::database)?;
    let has_more = items.len() > usize::try_from(limit).unwrap_or(100);
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        items.last().map(|item| item.environment_id)
    } else {
        None
    };
    transaction.commit().await.map_err(support::database)?;
    support::json(
        StatusCode::OK,
        &Page {
            items,
            page: PageInfo {
                next_cursor,
                has_more,
            },
        },
        None,
    )
}

#[allow(clippy::too_many_lines)]
pub(super) async fn create(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Json(input): Json<CreateRequest>,
) -> Result<Response, AppError> {
    let plane = support::plane(&state)?;
    let raw_request =
        SecretString::from(
            serde_json::to_string(&input).map_err(|_| AppError::Internal {
                category: "application_testing_request",
            })?,
        );
    let mut detail = EnvironmentCreate {
        name: input.name,
        description: input.description,
    };
    validation::create(&mut detail)?;
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| validation::field("idempotency_key", "is required"))?;
    let key = IdempotencyKey::parse(key).map_err(|_| {
        validation::field(
            "idempotency_key",
            "must contain 16 to 255 visible ASCII characters",
        )
    })?;
    let mut transaction = begin(&state, &client).await?;
    let caller = SecretString::from(format!("application-testing:{}", client.application_id));
    let lease = match idempotency::claim(
        &mut transaction,
        &state.crypto,
        idempotency::IdempotencyRequest {
            route: CREATE_ROUTE,
            caller_scope: &caller,
            key: &key,
            request_payload: &raw_request,
            contains_one_time_secret: true,
        },
    )
    .await?
    {
        IdempotencyClaim::Acquired(lease) => lease,
        IdempotencyClaim::Replay(replay) => {
            let status = StatusCode::from_u16(replay.status).map_err(|_| AppError::Internal {
                category: "application_testing_replay_status",
            })?;
            let mut response = support::json_response(status, replay.body, None, true)?;
            response
                .headers_mut()
                .insert("idempotency-replayed", HeaderValue::from_static("true"));
            return Ok(response);
        }
    };
    let graph = graph::load(&state, &client.app_id).await?;
    let (environment_id, iam_test_key, created) = if let Some(presented) = input.iam_test_key {
        let environment = support::resolve_key(&state.pool, &state, &presented)
            .await?
            .ok_or(AppError::NotFound)?;
        if environment.organization_id != client.organization_id {
            return Err(AppError::Forbidden);
        }
        (environment.id, presented, false)
    } else {
        let environment_id = Uuid::now_v7();
        let key = state
            .crypto
            .generate_testing_environment_key()
            .map_err(|_| AppError::Internal {
                category: "testing_environment_key_generate",
            })?;
        let stored = support::store_key(&state, client.organization_id, environment_id, &key)?;
        sqlx::query_scalar::<_, String>(
            "SELECT iam_private.create_application_testing_environment($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(environment_id)
        .bind(&detail.name)
        .bind(&detail.description)
        .bind(stored.digest)
        .bind(stored.digest_key_version)
        .bind(stored.ciphertext)
        .bind(stored.nonce)
        .bind(stored.encryption_key_version)
        .bind(i32::from(plane.settings.max_per_organization))
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| {
            support::conflict_from_database(error, "testing_environment_creation_conflict")
        })?;
        (environment_id, key.expose_secret().to_owned(), true)
    };
    let (org_id, name, description, version) =
        sqlx::query_as::<_, (String, String, Option<String>, i64)>(
            "SELECT * FROM iam_private.lock_application_testing_environment($1)",
        )
        .bind(environment_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)?;
    let selected = SelectedEnvironment {
        id: environment_id,
        organization_id: client.organization_id,
    };
    let imported = testing_plane::scope(selected, async {
        let mut test_transaction = context::begin(state.db(), DatabaseContext::anonymous())
            .await
            .map_err(support::database)?;
        let imported =
            graph::import_all(&mut test_transaction, &state, &graph, &client.app_id).await?;
        test_transaction.commit().await.map_err(support::database)?;
        Ok::<_, AppError>(imported)
    })
    .await?;
    let result = async {
        for (app_id, imported_app) in &imported {
            let source = graph.get(app_id).ok_or(AppError::Internal { category: "testing_dependency_missing" })?;
            sqlx::query("SELECT iam_private.link_application_testing_environment($1,$2,$3)")
                .bind(environment_id).bind(source.source_application_id).bind(imported_app.application_id)
                .execute(&mut *transaction).await.map_err(support::database)?;
        }
        let root = imported.get(&client.app_id).ok_or(AppError::Internal { category: "testing_root_missing" })?;
        let response = Created { environment_id, org_id, name, description, iam_test_key, app_id: client.app_id.clone(),
            app_secret: root.app_secret.expose_secret().to_owned(),
            dependencies: imported.keys().filter(|app_id| **app_id != client.app_id).cloned().collect(),
            secret_replay_expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(10) };
        support::record_audit(&mut transaction, support::AuditEvent {
            actor: Some(ActorRef { actor_type: ActorType::Application, id: client.application_id }),
            authentication_session_id: None, organization_id: client.organization_id,
            action: "application.testing_environment.created", environment_id, version,
            before_state: None, after_state: Some(serde_json::json!({"app_id":client.app_id,"dependency_count":response.dependencies.len()})),
            metadata: &serde_json::json!({"environment_created":created}),
        }).await?;
        let body = support::finish(&mut transaction, &state, lease, StatusCode::CREATED, &response, true).await?;
        transaction.commit().await.map_err(support::database)?;
        support::json_response(StatusCode::CREATED, body, None, true)
    }.await;
    if result.is_err() && created && creation_rolled_back(&state, &client, environment_id).await {
        // Compensate an unsuccessful control-plane commit after data was
        // materialized. A commit error can be ambiguous, so first confirm the
        // control record is absent. If that check fails, maintenance handles
        // the orphan after its grace period instead of risking live data.
        if let Err(error) = sqlx::query("SELECT iam_private.erase_testing_environment($1)")
            .bind(environment_id)
            .execute(&plane.pool)
            .await
        {
            tracing::error!(%error, %environment_id, "failed to compensate application testing creation");
        }
    }
    result
}

async fn creation_rolled_back(state: &ApiState, client: &ApplicationClient, id: Uuid) -> bool {
    let Ok(mut transaction) = begin(state, client).await else {
        return false;
    };
    matches!(
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM iam_private.lock_application_testing_environment($1))",
        )
        .bind(id)
        .fetch_one(&mut *transaction)
        .await,
        Ok(false)
    )
}

async fn begin<'a>(
    state: &'a ApiState,
    client: &ApplicationClient,
) -> Result<Transaction<'a, Postgres>, AppError> {
    context::begin(
        &state.pool,
        DatabaseContext {
            principal_id: Some(client.application_id),
            application_id: Some(client.application_id),
            organization_id: Some(client.organization_id),
            signup_session_id: None,
        },
    )
    .await
    .map_err(support::database)
}
