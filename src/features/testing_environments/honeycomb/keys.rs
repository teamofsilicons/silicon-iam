//! Shared root material is encrypted locally and fenced against reuse.
use super::{ApiError, ApiState, Id, Instruction, Service, Value, database, json, support};
use secrecy::ExposeSecret as _;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};

pub(super) async fn prepare(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    service: &Service,
    input: &Instruction,
) -> Result<Value, ApiError> {
    let org: Id = sqlx::query_scalar("SELECT iam_private.honeycomb_testing_organization($1,$2)")
        .bind(input.environment_id)
        .bind(&input.org_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(database)?;
    let secret = match &input.testing_key {
        Some(secret) => secret.clone(),
        None => state
            .crypto
            .generate_testing_environment_key()
            .map_err(|_| ApiError::internal("honeycomb_testing_key_generate"))?,
    };
    let stored = support::store_key(state, org, input.environment_id, &secret)
        .map_err(|_| ApiError::internal("honeycomb_testing_key_encrypt"))?;
    let prior: Option<(Id, Vec<u8>, i16, Vec<u8>, Vec<u8>, i16)> =
        sqlx::query_as("SELECT * FROM iam_private.honeycomb_testing_key($1,$2)")
            .bind(service.application_id)
            .bind(input.environment_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(database)?;
    let previous_fingerprint =
        if let Some((org, digest, digest_key_version, ciphertext, nonce, encryption_key_version)) =
            prior
        {
            let key = support::read_key(
                state,
                org,
                input.environment_id,
                &support::StoredKey {
                    digest,
                    digest_key_version,
                    ciphertext,
                    nonce,
                    encryption_key_version,
                },
            )
            .map_err(|_| ApiError::internal("honeycomb_testing_key_decrypt"))?;
            Some(hex::encode(Sha256::digest(key.as_bytes())))
        } else {
            None
        };
    Ok(
        json!({"digest":hex::encode(stored.digest),"digest_version":stored.digest_key_version,
        "ciphertext":hex::encode(stored.ciphertext),"nonce":hex::encode(stored.nonce),
        "encryption_version":stored.encryption_key_version,
        "fingerprint":hex::encode(Sha256::digest(secret.expose_secret().as_bytes())),
        "previous_fingerprint":previous_fingerprint}),
    )
}

pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<secrecy::SecretString>, D::Error> {
    use serde::Deserialize as _;
    Ok(Option::<String>::deserialize(deserializer)?.map(secrecy::SecretString::from))
}

pub(super) async fn remember(
    tx: &mut Transaction<'_, Postgres>,
    service: &Service,
    environment: Id,
    operation: Id,
    key: &str,
) -> Result<(), ApiError> {
    sqlx::query("SELECT iam_private.honeycomb_remember_testing_key($1,$2,$3,$4)")
        .bind(service.application_id)
        .bind(environment)
        .bind(operation)
        .bind(Sha256::digest(key.as_bytes()).as_slice())
        .execute(&mut **tx)
        .await
        .map_err(database)?;
    Ok(())
}
