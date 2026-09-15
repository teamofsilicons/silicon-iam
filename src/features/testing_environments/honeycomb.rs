//! Durable, production-authorized instructions for IAM's test data only.
#![allow(clippy::too_many_lines, clippy::type_complexity)]
use super::support;
mod imports;
use crate::{
    api::ApiState,
    domain::actor::{ActorRef, ActorType},
    features::applications::{
        error::ApiError,
        honeycomb::{Service, operations},
    },
    infrastructure::postgres::context::{self, DatabaseContext},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Instruction {
    operation_id: Uuid,
    expected_iam_revision: i64,
    environment_id: Uuid,
    generation: i64,
    operation: String,
    org_id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    app_id: Option<String>,
    #[serde(default)]
    source_revisions: std::collections::BTreeMap<String, i64>,
}

pub(crate) fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/honeycomb/testing-environments/{environment_id}",
            get(record),
        )
        .route(
            "/api/v1/honeycomb/testing-environments/{environment_id}/operations",
            post(instruct),
        )
}
#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err adapter consumes the database error"
)]
fn database(error: sqlx::Error) -> ApiError {
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
    {
        Some("42501") => ApiError::forbidden("testing_manager_required"),
        Some("40001") => ApiError::conflict("testing_revision_or_state_conflict"),
        Some("P0002") => ApiError::not_found(),
        Some("23505") => ApiError::conflict("testing_identity_conflict"),
        Some("22023" | "23514") => {
            ApiError::validation("instruction", "invalid lifecycle instruction")
        }
        _ => ApiError::internal("honeycomb_testing_database"),
    }
}
async fn record(
    State(state): State<ApiState>,
    service: Service,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let record: Option<sqlx::types::Json<Value>> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_testing_record($1,$2)")
            .bind(service.application_id)
            .bind(id)
            .fetch_one(&state.pool)
            .await
            .map_err(database)?;
    Ok(Json(record.ok_or_else(ApiError::not_found)?.0))
}
async fn instruct(
    State(state): State<ApiState>,
    service: Service,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, ApiError> {
    let input: Instruction = serde_json::from_slice(&body)
        .map_err(|_| ApiError::validation("instruction", "invalid lifecycle instruction"))?;
    if input.environment_id != id
        || input.generation <= 0
        || input.expected_iam_revision < 0
        || !matches!(
            input.operation.as_str(),
            "prepare"
                | "rotate-key"
                | "clean"
                | "disable"
                | "restore"
                | "purge"
                | "activate"
                | "import"
        )
    {
        return Err(ApiError::validation(
            "instruction",
            "invalid identity, revision, generation or operation",
        ));
    }
    let plane = state.testing.as_ref().ok_or_else(|| {
        ApiError::precondition(
            "testing_not_configured",
            "The IAM testing database must be configured.",
        )
    })?;
    let access = if headers.contains_key("x-honeycomb-actor-token") {
        Some(service.actor(&state, &headers).await?)
    } else {
        None
    };
    let actor = if let Some(access) = &access {
        access.subject
    } else {
        if !state
            .settings
            .honeycomb
            .as_ref()
            .is_some_and(|settings| settings.scheduled_testing)
            || !matches!(
                input.operation.as_str(),
                "clean" | "disable" | "restore" | "purge" | "activate"
            )
        {
            return Err(ApiError::forbidden("scheduled_testing_authority_required"));
        }
        ActorRef {
            actor_type: ActorType::Application,
            id: service.application_id,
        }
    };
    let mut tx = context::begin(&state.pool, DatabaseContext::principal(actor.id))
        .await
        .map_err(database)?;
    // User authority is checked even before replay. This does not depend on the
    // test identity or root key about to be invalidated.
    if let Some(access) = &access {
        let allowed: bool =
            sqlx::query_scalar("SELECT iam_private.honeycomb_testing_actor($1,$2,$3,$4)")
                .bind(id)
                .bind(actor.id)
                .bind(access.token_id)
                .bind(&input.org_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        if !allowed {
            return Err(ApiError::forbidden("testing_manager_required"));
        }
    }
    let resource = id.to_string();
    if let Some(response) = operations::claim(
        &mut tx,
        &state,
        &service,
        &actor,
        &headers,
        input.operation_id,
        &format!("testing-{}", input.operation),
        &resource,
        &body,
    )
    .await?
    {
        tx.commit().await.map_err(database)?;
        return Ok(operations::management_response(response, true));
    }
    let import_graph = if input.operation == "import" {
        Some(
            imports::snapshot(
                &mut tx,
                &state,
                &service,
                &actor,
                access.as_ref().map(|access| access.token_id),
                &input,
            )
            .await?,
        )
    } else {
        None
    };
    // Keys are generated locally and never persisted in plaintext. Retrying an
    // unfinished operation uses the key already installed in the environment.
    let generate = (input.operation == "prepare" && input.expected_iam_revision == 0)
        || input.operation == "rotate-key";
    let keys = if generate {
        let org: Uuid =
            sqlx::query_scalar("SELECT iam_private.honeycomb_testing_organization($1,$2)")
                .bind(id)
                .bind(&input.org_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        let secret = state
            .crypto
            .generate_testing_environment_key()
            .map_err(|_| ApiError::internal("honeycomb_testing_key_generate"))?;
        let stored = support::store_key(&state, org, id, &secret)
            .map_err(|_| ApiError::internal("honeycomb_testing_key_encrypt"))?;
        json!({"digest":hex::encode(stored.digest),"digest_version":stored.digest_key_version,"ciphertext":hex::encode(stored.ciphertext),"nonce":hex::encode(stored.nonce),"encryption_version":stored.encryption_key_version})
    } else {
        Value::Null
    };
    let details = json!({"org_id":input.org_id,"name":input.name,"description":input.description});
    let snapshot: sqlx::types::Json<Value> = sqlx::query_scalar(
        "SELECT iam_private.honeycomb_testing_start($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(id)
    .bind(service.application_id)
    .bind(actor.id)
    .bind(access.as_ref().map(|access| access.token_id))
    .bind(input.operation_id)
    .bind(&input.operation)
    .bind(input.expected_iam_revision)
    .bind(input.generation)
    .bind(sqlx::types::Json(details))
    .bind(sqlx::types::Json(keys))
    .fetch_one(&mut *tx)
    .await
    .map_err(database)?;
    sqlx::query(
        "UPDATE iam.honeycomb_operations SET environment_id=$2,result=$3 WHERE operation_id=$1",
    )
    .bind(input.operation_id)
    .bind(id)
    .bind(&snapshot)
    .execute(&mut *tx)
    .await
    .map_err(database)?;
    tx.commit().await.map_err(database)?;
    let mut tx = context::begin(&state.pool, DatabaseContext::principal(actor.id))
        .await
        .map_err(database)?;
    // Same operation lock excludes simultaneous retries while finishing.
    if let Some(response) = operations::claim(
        &mut tx,
        &state,
        &service,
        &actor,
        &headers,
        input.operation_id,
        &format!("testing-{}", input.operation),
        &resource,
        &body,
    )
    .await?
    {
        tx.commit().await.map_err(database)?;
        return Ok(operations::management_response(response, true));
    }
    // Serialize the entire erasure and receipt completion against same-operation
    // retries; a late retry must not erase newly activated data.
    let mut test_tx = plane.pool.begin().await.map_err(database)?;
    sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
        .bind(id.to_string())
        .execute(&mut *test_tx)
        .await
        .map_err(database)?;
    let generation = snapshot.0["generation"]
        .as_i64()
        .ok_or_else(|| ApiError::internal("honeycomb_testing_generation"))?;
    let key_version = snapshot.0["key_version"]
        .as_i64()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| ApiError::internal("honeycomb_testing_key_version"))?;
    sqlx::query("SELECT iam_private.set_testing_runtime_state($1,$2,$3,$4)")
        .bind(id)
        .bind(generation)
        .bind(key_version)
        .bind(snapshot.0["state"] == "active")
        .execute(&mut *test_tx)
        .await
        .map_err(database)?;
    if matches!(input.operation.as_str(), "clean" | "purge") {
        sqlx::query("SELECT iam_private.erase_testing_environment($1)")
            .bind(id)
            .execute(&mut *test_tx)
            .await
            .map_err(database)?;
    }
    let imported = if let Some(graph) = &import_graph {
        let org: Uuid =
            sqlx::query_scalar("SELECT iam_private.honeycomb_testing_organization($1,NULL)")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        Some(
            crate::infrastructure::testing_plane::scope(
                crate::infrastructure::testing_plane::SelectedEnvironment {
                    id,
                    organization_id: org,
                },
                async {
                    super::graph::import_exact(
                        &mut test_tx,
                        &state,
                        graph,
                        input.app_id.as_deref().unwrap_or_default(),
                    )
                    .await
                },
            )
            .await
            .map_err(|_| ApiError::conflict("testing_import_failed"))?,
        )
    } else {
        None
    };
    test_tx.commit().await.map_err(database)?;
    if input.operation == "purge" {
        sqlx::query("SELECT iam_private.honeycomb_testing_purge_receipts($1,$2)")
            .bind(service.application_id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(database)?;
    }
    let snapshot: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_testing_finish($1,$2,$3)")
            .bind(service.application_id)
            .bind(id)
            .bind(input.operation_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    let revision = snapshot.0["iam_revision"]
        .as_i64()
        .ok_or_else(|| ApiError::internal("honeycomb_testing_revision"))?;
    let mut response = json!({"operation_id":input.operation_id,"state":"accepted","environment_id":id,"iam_revision":revision,"iam_completion":true,"environment":snapshot.0});
    if let Some(imported) = &imported {
        let root = imported
            .get(input.app_id.as_deref().unwrap_or_default())
            .ok_or_else(|| ApiError::internal("testing_import_result"))?;
        response["app_secret"] = json!(root.app_secret.expose_secret());
        response["app_id"] = json!(input.app_id);
        response["source_revisions"] = json!(input.source_revisions);
    }
    let returns_key = matches!(input.operation.as_str(), "prepare" | "rotate-key");
    if returns_key {
        let (org, digest, digest_version, ciphertext, nonce, encryption_version): (
            Uuid,
            Vec<u8>,
            i16,
            Vec<u8>,
            Vec<u8>,
            i16,
        ) = sqlx::query_as("SELECT * FROM iam_private.honeycomb_testing_key($1,$2)")
            .bind(service.application_id)
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
        let stored = support::StoredKey {
            digest,
            digest_key_version: digest_version,
            ciphertext,
            nonce,
            encryption_key_version: encryption_version,
        };
        response["key"] = json!(
            support::read_key(&state, org, id, &stored)
                .map_err(|_| ApiError::internal("honeycomb_testing_key_decrypt"))?
        );
    }
    operations::complete(
        &mut tx,
        &state,
        &service,
        input.operation_id,
        &resource,
        revision,
        &response,
        returns_key || imported.is_some(),
    )
    .await?;
    tx.commit().await.map_err(database)?;
    Ok(operations::management_response(response, false))
}
