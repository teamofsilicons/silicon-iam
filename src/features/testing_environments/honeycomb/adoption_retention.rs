//! Protected legacy transfer and service-authorized, exact application erasure.
#![allow(clippy::too_many_lines)]
#[cfg(test)]
#[path = "adoption_retention_tests.rs"]
mod live_tests;
use super::{database, operations, support};
use crate::{
    api::ApiState,
    domain::actor::{ActorRef, ActorType},
    features::applications::{error::ApiError, honeycomb::Service},
    infrastructure::postgres::context::{self, DatabaseContext},
};
use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    routing::post,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    operation_id: Uuid,
    expected_iam_revision: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retention {
    operation_id: Uuid,
    environment_id: Uuid,
    /// Honeycomb's revision is echoed; the IAM revision is checked separately.
    environment_revision: i64,
    expected_iam_revision: i64,
    generation: i64,
    key_version: i32,
    retired_apps: Vec<String>,
}
impl Retention {
    fn validate(&self, environment: Uuid) -> Result<(), ApiError> {
        if self.environment_id != environment
            || self.environment_revision <= 0
            || self.expected_iam_revision <= 0
            || self.generation <= 0
            || self.key_version <= 0
            || self.retired_apps.is_empty()
            || self.retired_apps.len() > 100
            || self
                .retired_apps
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.retired_apps.len()
        {
            return Err(ApiError::validation(
                "retention",
                "exact environment versions and unique retired app IDs are required",
            ));
        }
        for app in &self.retired_apps {
            if app.len() > 200 || !app.contains('>') {
                return Err(ApiError::validation(
                    "retired_apps",
                    "qualified app IDs are required",
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/honeycomb/testing-environments/{environment_id}/adoption-export",
            post(export),
        )
        .route(
            "/api/v1/honeycomb/testing-environments/{environment_id}/retention",
            post(retire),
        )
}

async fn export(
    State(state): State<ApiState>,
    service: Service,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, ApiError> {
    let input: Export = serde_json::from_slice(&body)
        .map_err(|_| ApiError::validation("export", "invalid export request"))?;
    if input.expected_iam_revision <= 0 {
        return Err(ApiError::validation(
            "expected_iam_revision",
            "must be positive",
        ));
    }
    let actor = ActorRef {
        actor_type: ActorType::Application,
        id: service.application_id,
    };
    let mut tx = context::begin(&state.pool, DatabaseContext::principal(actor.id))
        .await
        .map_err(database)?;
    let resource = id.to_string();
    if let Some(response) = operations::claim(
        &mut tx,
        &state,
        &service,
        &actor,
        &headers,
        input.operation_id,
        "testing-adoption-export",
        &resource,
        &body,
    )
    .await?
    {
        tx.commit().await.map_err(database)?;
        return Ok(operations::management_response(response, true));
    }
    let mut snapshot: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_adoption_export($1,$2,$3)")
            .bind(service.application_id)
            .bind(id)
            .bind(input.expected_iam_revision)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    let (org, digest, digest_version, ciphertext, nonce, encryption_key_version): (
        Uuid,
        Vec<u8>,
        i16,
        Vec<u8>,
        Vec<u8>,
        i16,
    ) = sqlx::query_as("SELECT * FROM iam_private.honeycomb_adoption_key($1,$2)")
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
        encryption_key_version,
    };
    let key = support::read_key(&state, org, id, &stored)
        .map_err(|_| ApiError::internal("adoption_key_decrypt"))?;
    super::keys::remember(&mut tx, &service, id, input.operation_id, &key).await?;
    if let Some(plane) = &state.testing {
        let mut test_tx = plane.pool.begin().await.map_err(database)?;
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(id.to_string())
            .execute(&mut *test_tx)
            .await
            .map_err(database)?;
        sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
            .bind(format!("testing-runtime:{id}"))
            .execute(&mut *test_tx)
            .await
            .map_err(database)?;
        let imports: sqlx::types::Json<Value> =
            sqlx::query_scalar("SELECT iam_private.honeycomb_adoption_imports($1)")
                .bind(id)
                .fetch_one(&mut *test_tx)
                .await
                .map_err(database)?;
        snapshot.0["imported_applications"] = imports.0;
        test_tx.commit().await.map_err(database)?;
    }
    // Only the top-level key contains a secret, matching the shared receipt
    // redactor. The transfer receipt and notification never carry this key.
    let response = json!({"operation_id":input.operation_id,"state":"accepted","environment_id":id,"iam_revision":input.expected_iam_revision,"environment":snapshot.0,"key":key,"credentials_preserved":true});
    sqlx::query("UPDATE iam.honeycomb_operations SET environment_id=$2 WHERE operation_id=$1")
        .bind(input.operation_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    operations::complete(
        &mut tx,
        &state,
        &service,
        input.operation_id,
        &resource,
        input.expected_iam_revision,
        &response,
        true,
    )
    .await?;
    tx.commit().await.map_err(database)?;
    Ok(operations::management_response(response, false))
}

async fn retire(
    State(state): State<ApiState>,
    service: Service,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, ApiError> {
    if !state
        .settings
        .honeycomb
        .as_ref()
        .is_some_and(|settings| settings.scheduled_testing)
    {
        return Err(ApiError::forbidden("scheduled_testing_authority_required"));
    }
    let input: Retention = serde_json::from_slice(&body)
        .map_err(|_| ApiError::validation("retention", "invalid retention request"))?;
    input.validate(id)?;
    let plane = state.testing.as_ref().ok_or_else(|| {
        ApiError::precondition(
            "testing_not_configured",
            "The IAM testing database must be configured.",
        )
    })?;
    // Test-only applications have no production source link. Discover them
    // from the explicitly selected testing plane, never from caller assertions.
    let mut selected = plane.pool.begin().await.map_err(database)?;
    sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
        .bind(id.to_string())
        .execute(&mut *selected)
        .await
        .map_err(database)?;
    let available: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_adoption_imports($1)")
            .bind(id)
            .fetch_one(&mut *selected)
            .await
            .map_err(database)?;
    let test_apps = available
        .0
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|app| app["app_id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    selected.commit().await.map_err(database)?;
    let actor = ActorRef {
        actor_type: ActorType::Application,
        id: service.application_id,
    };
    let resource = id.to_string();
    let mut tx = context::begin(&state.pool, DatabaseContext::principal(actor.id))
        .await
        .map_err(database)?;
    if let Some(response) = operations::claim(
        &mut tx,
        &state,
        &service,
        &actor,
        &headers,
        input.operation_id,
        "testing-retention",
        &resource,
        &body,
    )
    .await?
    {
        tx.commit().await.map_err(database)?;
        return Ok(operations::management_response(response, true));
    }
    let _: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_retention_start($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(service.application_id)
            .bind(id)
            .bind(input.operation_id)
            .bind(input.expected_iam_revision)
            .bind(input.generation)
            .bind(input.key_version)
            .bind(&input.retired_apps)
            .bind(&test_apps)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    sqlx::query("UPDATE iam.honeycomb_operations SET environment_id=$2 WHERE operation_id=$1")
        .bind(input.operation_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    tx.commit().await.map_err(database)?;
    // Persisted reservation prevents other lifecycle/import instructions from
    // racing a crash retry. Hold the operation lock through erasure and finish.
    let mut tx = context::begin(&state.pool, DatabaseContext::principal(actor.id))
        .await
        .map_err(database)?;
    if let Some(response) = operations::claim(
        &mut tx,
        &state,
        &service,
        &actor,
        &headers,
        input.operation_id,
        "testing-retention",
        &resource,
        &body,
    )
    .await?
    {
        tx.commit().await.map_err(database)?;
        return Ok(operations::management_response(response, true));
    }
    let mut test_tx = plane.pool.begin().await.map_err(database)?;
    sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
        .bind(id.to_string())
        .execute(&mut *test_tx)
        .await
        .map_err(database)?;
    let deleted_rows: i64 =
        sqlx::query_scalar("SELECT iam_private.erase_testing_applications($1,$2,$3,$4,$5)")
            .bind(id)
            .bind(input.operation_id)
            .bind(&input.retired_apps)
            .bind(input.generation)
            .bind(input.key_version)
            .fetch_one(&mut *test_tx)
            .await
            .map_err(database)?;
    test_tx.commit().await.map_err(database)?;
    let snapshot: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_retention_finish($1,$2,$3,$4)")
            .bind(service.application_id)
            .bind(id)
            .bind(input.operation_id)
            .bind(&input.retired_apps)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    let revision = snapshot.0["iam_revision"]
        .as_i64()
        .ok_or_else(|| ApiError::internal("retention_iam_revision"))?;
    let response = json!({"operation_id":input.operation_id,"state":"accepted","environment_id":id,"environment_revision":input.environment_revision,
        "iam_revision":revision,"generation":input.generation,"key_version":input.key_version,"retired_apps":input.retired_apps,
        "iam_completion":true,"deleted_rows":deleted_rows,"environment":snapshot.0});
    operations::complete(
        &mut tx,
        &state,
        &service,
        input.operation_id,
        &resource,
        revision,
        &response,
        false,
    )
    .await?;
    tx.commit().await.map_err(database)?;
    Ok(operations::management_response(response, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retention_requires_exact_unique_apps_and_all_versions() {
        let id = Uuid::now_v7();
        let mut input = Retention {
            operation_id: Uuid::now_v7(),
            environment_id: id,
            environment_revision: 1,
            expected_iam_revision: 1,
            generation: 1,
            key_version: 1,
            retired_apps: vec!["tos>honeycomb".into()],
        };
        assert!(input.validate(id).is_ok());
        input.retired_apps.push("tos>honeycomb".into());
        assert!(input.validate(id).is_err());
        input.retired_apps.pop();
        input.generation = 0;
        assert!(input.validate(id).is_err());
    }
}
