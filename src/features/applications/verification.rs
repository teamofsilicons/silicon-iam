//! Short-lived application identity proofs, independent of user and OBO authority.

use axum::{
    Json,
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse as _, Response},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;

use crate::{
    api::ApiState,
    domain::id::Id,
    infrastructure::{
        crypto::{DigestPurpose, SecretDigest, SecretKind},
        postgres::context::{self, DatabaseContext},
        testing_plane,
    },
};

use super::{error::ApiError, security::ApplicationClient, validation};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IssueRequest {
    #[serde(default = "default_lifetime")]
    ttl_seconds: i32,
}

const fn default_lifetime() -> i32 {
    300
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifyRequest {
    app_id: String,
    #[serde(deserialize_with = "super::model::deserialize_secret_string")]
    app_access_key: SecretString,
}

#[derive(Serialize)]
struct IssuedKey {
    app_access_key: String,
    #[serde(with = "time::serde::rfc3339")]
    valid_till: OffsetDateTime,
    app_id: String,
}

#[derive(FromRow, Serialize)]
struct VerifiedKey {
    app_id: String,
    #[serde(with = "time::serde::rfc3339")]
    valid_till: OffsetDateTime,
}

#[derive(Serialize)]
struct Verification {
    valid_key: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    key: Option<VerifiedKey>,
}

pub(super) async fn issue(
    State(state): State<ApiState>,
    client: ApplicationClient,
    Json(input): Json<IssueRequest>,
) -> Result<Response, ApiError> {
    if !(60..=3600).contains(&input.ttl_seconds) {
        return Err(ApiError::validation(
            "ttl_seconds",
            "Lifetime must be between 60 and 3600 seconds inclusive.",
        ));
    }
    let mut tx = application_transaction(&state, &client).await?;
    let secret_id = lock_client(&mut tx, &state, &client).await?;
    let key = state
        .crypto
        .generate_secret(SecretKind::ApplicationAccessKey)
        .map_err(|_| ApiError::internal("application_access_key_generate"))?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationAccessKey, &key)
        .map_err(|_| ApiError::internal("application_access_key_digest"))?;
    let issued = sqlx::query_as::<_, VerifiedKey>(
        "SELECT app_id,valid_till FROM iam_private.issue_application_access_key($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(secret_id).bind(client.auth_epoch).bind(Id::now_v7())
    .bind(digest.as_bytes().as_slice()).bind(digest.key_version())
    .bind(input.ttl_seconds).bind(generation())
    .fetch_optional(&mut *tx).await
    .map_err(|_| ApiError::internal("application_access_key_issue"))?
    .ok_or_else(ApiError::invalid_client)?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("application_access_key_commit"))?;
    Ok(uncached_json(IssuedKey {
        app_access_key: key.expose_secret().to_owned(),
        valid_till: issued.valid_till,
        app_id: issued.app_id,
    }))
}

pub(super) async fn verify(
    State(state): State<ApiState>,
    client: ApplicationClient,
    Json(input): Json<VerifyRequest>,
) -> Result<Response, ApiError> {
    let mut tx = application_transaction(&state, &client).await?;
    lock_client(&mut tx, &state, &client).await?;
    // Wrong token classes and arbitrary inputs fail exactly like unknown keys.
    // Do not echo their contents in errors, events or diagnostic fields.
    let key =
        if validation::app_id(&input.app_id).is_ok()
            && key_format_is_valid(input.app_access_key.expose_secret())
        {
            let (versions, digests) = digests(
                &state,
                DigestPurpose::ApplicationAccessKey,
                &input.app_access_key,
            )?;
            sqlx::query_as::<_, VerifiedKey>(
            "SELECT app_id,valid_till FROM iam_private.verify_application_access_key($1,$2,$3,$4)",
        )
        .bind(&input.app_id).bind(versions).bind(digests).bind(generation())
        .fetch_optional(&mut *tx).await
        .map_err(|_| ApiError::internal("application_access_key_verify"))?
        } else {
            None
        };
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("application_access_key_verify_commit"))?;
    Ok(uncached_json(Verification {
        valid_key: key.is_some(),
        key,
    }))
}

async fn application_transaction<'a>(
    state: &'a ApiState,
    client: &ApplicationClient,
) -> Result<Transaction<'a, Postgres>, ApiError> {
    context::begin(
        state.db(),
        DatabaseContext::application(client.application_id, client.application_id),
    )
    .await
    .map_err(|_| ApiError::internal("application_access_key_context"))
}

async fn lock_client(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
) -> Result<Id, ApiError> {
    let (versions, digests) = digests(
        state,
        DigestPurpose::ApplicationSecret,
        &client.authenticated_secret,
    )?;
    sqlx::query_scalar::<_, Option<Id>>(
        "SELECT iam_private.lock_application_verification_client($1,$2,$3,$4)",
    )
    .bind(client.application_id)
    .bind(client.auth_epoch)
    .bind(versions)
    .bind(digests)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::internal("application_access_key_client_lock"))?
    .ok_or_else(ApiError::invalid_client)
}

fn digests(
    state: &ApiState,
    purpose: DigestPurpose,
    secret: &SecretString,
) -> Result<(Vec<i16>, Vec<Vec<u8>>), ApiError> {
    let candidates = state
        .crypto
        .digest_secrets(purpose, secret)
        .map_err(|_| ApiError::internal("application_verification_digest"))?;
    Ok((
        candidates.iter().map(SecretDigest::key_version).collect(),
        candidates
            .iter()
            .map(|digest| digest.as_bytes().to_vec())
            .collect(),
    ))
}

fn generation() -> Option<i64> {
    testing_plane::current_id()
        .map(|_| testing_plane::runtime_version().map_or(1, |(generation, _)| generation))
}

fn key_format_is_valid(key: &str) -> bool {
    key.len() == 47
        && key.starts_with("aak_")
        && key[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn uncached_json(value: impl Serialize) -> Response {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;
