//! Encrypted immutable source snapshots make interrupted imports replayable.
use super::{ActorRef, ApiError, ApiState, Instruction, Service, Uuid, database};
use crate::infrastructure::crypto::{EncryptedValue, EncryptionContext, ProtectedField};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeMap;
type Graph = BTreeMap<String, super::super::imports::ProductionApplication>;
pub(super) async fn snapshot(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    service: &Service,
    actor: &ActorRef,
    token: Option<Uuid>,
    input: &Instruction,
) -> Result<Graph, ApiError> {
    let root = input
        .app_id
        .as_deref()
        .ok_or_else(|| ApiError::validation("app_id", "required for import"))?;
    let cached:Option<(Vec<u8>,Vec<u8>,i16)>=sqlx::query_as("SELECT response_ciphertext,response_nonce,response_key_version FROM iam.honeycomb_operations WHERE operation_id=$1 AND response_ciphertext IS NOT NULL AND NOT completed").bind(input.operation_id).fetch_optional(&mut **tx).await.map_err(database)?;
    let encryption_context = EncryptionContext::global(
        ProtectedField::IdempotencySecretResponse,
        input.operation_id,
    );
    let is_cached = cached.is_some();
    let graph: Graph = if let Some((ciphertext, nonce, key_version)) = cached {
        let value = EncryptedValue {
            ciphertext,
            nonce: nonce
                .try_into()
                .map_err(|_| ApiError::internal("testing_snapshot_nonce"))?,
            key_version,
        };
        let plaintext = state
            .crypto
            .decrypt(encryption_context, &value)
            .map_err(|_| ApiError::internal("testing_snapshot_decrypt"))?;
        serde_json::from_slice(&plaintext)
            .map_err(|_| ApiError::internal("testing_snapshot_decode"))?
    } else {
        let plane = state
            .testing
            .as_ref()
            .ok_or_else(|| ApiError::internal("testing_plane_required"))?;
        let mut test_tx = plane.pool.begin().await.map_err(database)?;
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(input.environment_id.to_string())
            .execute(&mut *test_tx)
            .await
            .map_err(database)?;
        let snapshots: Vec<sqlx::types::Json<super::super::imports::ProductionApplication>> =
            sqlx::query_scalar("SELECT * FROM iam_private.honeycomb_testing_source_snapshots()")
                .fetch_all(&mut *test_tx)
                .await
                .map_err(database)?;
        test_tx.commit().await.map_err(database)?;
        let pins = snapshots
            .into_iter()
            .map(|snapshot| (snapshot.0.app_id.clone(), snapshot.0))
            .collect();
        super::super::graph::load_with_pins(state, root, &pins, &input.refresh_app_ids)
            .await
            .map_err(|_| ApiError::conflict("testing_import_source_unavailable"))?
    };
    if actor.actor_type == crate::domain::actor::ActorType::Application
        && graph
            .get(root)
            .is_none_or(|source| source.source_application_id != actor.id)
    {
        return Err(ApiError::forbidden(
            "testing_application_source_identity_required",
        ));
    }
    if input
        .refresh_app_ids
        .iter()
        .any(|id| !graph.contains_key(id))
    {
        return Err(ApiError::validation(
            "refresh_app_ids",
            "refresh targets must belong to the requested dependency graph",
        ));
    }
    if graph.len() != input.source_revisions.len()
        || graph
            .iter()
            .any(|(id, source)| input.source_revisions.get(id) != Some(&source.source_revision))
    {
        return Err(ApiError::conflict("testing_source_revision_conflict"));
    }
    for source in graph
        .values()
        .filter(|source| source.visibility == "private")
    {
        let allowed: bool = if actor.actor_type == crate::domain::actor::ActorType::Service {
            false
        } else if actor.actor_type == crate::domain::actor::ActorType::Application {
            super::authority::private_import_allowed(tx, actor.id, &source.org_id).await?
        } else {
            sqlx::query_scalar("SELECT iam_private.honeycomb_testing_actor(NULL,$1,$2,$3)")
                .bind(actor.id)
                .bind(token)
                .bind(&source.org_id)
                .fetch_one(&mut **tx)
                .await
                .map_err(database)?
        };
        if !allowed {
            return Err(ApiError::forbidden("private_import_membership_required"));
        }
    }
    if is_cached {
        return Ok(graph);
    }
    let plaintext =
        serde_json::to_vec(&graph).map_err(|_| ApiError::internal("testing_snapshot_encode"))?;
    let encrypted = state
        .crypto
        .encrypt(encryption_context, &plaintext)
        .map_err(|_| ApiError::internal("testing_snapshot_encrypt"))?;
    sqlx::query("UPDATE iam.honeycomb_operations SET response_ciphertext=$3,response_nonce=$4,response_key_version=$5 WHERE operation_id=$1 AND service_application_id=$2").bind(input.operation_id).bind(service.application_id).bind(encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).execute(&mut **tx).await.map_err(database)?;
    Ok(graph)
}
