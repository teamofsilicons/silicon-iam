//! Reusable application-only ATA credentials with live recipient/endpoint verification.
use super::{
    error::ApiError,
    idempotency::{self, Claim},
    security::ApplicationClient,
    validation,
};
use crate::{
    api::ApiState,
    domain::id::Id,
    infrastructure::{
        crypto::{DigestPurpose, SecretKind},
        postgres::context::{self, DatabaseContext},
    },
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::post,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction, types::Json as SqlJson};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/ata-access/tokens", post(refresh))
        .route("/api/v1/ata-access/verify", post(verify))
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Refresh {
    refresh_token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verify {
    app_id: String,
    app_proof_token: String,
    endpoint: String,
}

async fn transaction<'a>(
    state: &'a ApiState,
    app: &ApplicationClient,
) -> Result<Transaction<'a, Postgres>, ApiError> {
    let mut tx = context::begin(
        state.db(),
        DatabaseContext::application(app.application_id, app.application_id),
    )
    .await
    .map_err(|_| ApiError::internal("ata_context"))?;
    super::verification::lock_client(&mut tx, state, app).await?;
    Ok(tx)
}
fn credential(
    state: &ApiState,
    kind: SecretKind,
    purpose: DigestPurpose,
) -> Result<(SecretString, Value), ApiError> {
    let secret = state
        .crypto
        .generate_secret(kind)
        .map_err(|_| ApiError::internal("ata_credential_generate"))?;
    let digest = state
        .crypto
        .digest_secret(purpose, &secret)
        .map_err(|_| ApiError::internal("ata_credential_digest"))?;
    Ok((
        secret,
        json!({"id":Id::now_v7(),"digest":hex::encode(digest.as_bytes()),"key_version":digest.key_version()}),
    ))
}
fn digests(
    state: &ApiState,
    token: &str,
    prefix: &str,
    purpose: DigestPurpose,
) -> Result<Option<Value>, ApiError> {
    if !token.strip_prefix(prefix).is_some_and(|s| {
        s.len() == 43
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    }) {
        return Ok(None);
    }
    let candidates = state
        .crypto
        .digest_secrets(purpose, &SecretString::from(token.to_owned()))
        .map_err(|_| ApiError::internal("ata_token_lookup"))?;
    Ok(Some(json!(
        candidates
            .iter()
            .map(|d| json!({"key_version":d.key_version(),"digest":hex::encode(d.as_bytes())}))
            .collect::<Vec<_>>()
    )))
}
async fn response(
    tx: Transaction<'_, Postgres>,
    value: Value,
    replayed: bool,
) -> Result<Response, ApiError> {
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("ata_commit"))?;
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if replayed {
        response
            .headers_mut()
            .insert("idempotency-replayed", HeaderValue::from_static("true"));
    }
    Ok(response)
}
fn db_error(error: &sqlx::Error) -> ApiError {
    if matches!(&error,sqlx::Error::Database(e) if e.message().starts_with("ata_")) {
        ApiError::forbidden("invalid_ata_credential")
    } else {
        tracing::error!(%error,"ATA database operation failed");
        ApiError::internal("ata_database")
    }
}
async fn refresh(
    State(state): State<ApiState>,
    app: ApplicationClient,
    headers: HeaderMap,
    Json(input): Json<Refresh>,
) -> Result<Response, ApiError> {
    let lookup = digests(
        &state,
        &input.refresh_token,
        "atr_",
        DigestPurpose::AtaRefreshToken,
    )?
    .ok_or_else(|| ApiError::forbidden("invalid_ata_credential"))?;
    let mut tx = transaction(&state, &app).await?;
    let canonical =
        serde_json::to_vec(&input).map_err(|_| ApiError::internal("ata_request_encode"))?;
    let claim: Claim<Value> = idempotency::claim(
        &mut tx,
        &state.crypto,
        &headers,
        &format!("ata-app:{}", app.application_id),
        "POST /api/v1/ata-access/tokens",
        &canonical,
        true,
    )
    .await?;
    let operation = match claim {
        Claim::Acquired(id) => id,
        Claim::Replay {
            status,
            response: stored,
        } => {
            if status != 200 {
                tx.commit()
                    .await
                    .map_err(|_| ApiError::internal("ata_replay_commit"))?;
                return Err(ApiError::forbidden("invalid_ata_credential"));
            }
            let token: Id = serde_json::from_value(stored["token_id"].clone())
                .map_err(|_| ApiError::internal("ata_replay_id"))?;
            let active: bool =
                sqlx::query_scalar("SELECT iam_private.ata_token_result_is_live($1)")
                    .bind(token)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|error| db_error(&error))?;
            if !active {
                return Err(ApiError::gone("ata_credential_revoked"));
            }
            return response(tx, stored, true).await;
        }
    };
    let (access, access_record) = credential(
        &state,
        SecretKind::AtaAccessToken,
        DigestPurpose::AtaAccessToken,
    )?;
    let (refresh, refresh_record) = credential(
        &state,
        SecretKind::AtaRefreshToken,
        DigestPurpose::AtaRefreshToken,
    )?;
    let SqlJson(mut result): SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.ata_token_refresh($1,$2)")
            .bind(SqlJson(lookup))
            .bind(SqlJson(
                json!({"access":access_record,"refresh":refresh_record}),
            ))
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| db_error(&error))?;
    if result.get("error").is_some() {
        idempotency::complete(&mut tx, &state.crypto, operation, 403, &result, true).await?;
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("ata_compromise_commit"))?;
        return Err(ApiError::forbidden("invalid_ata_credential"));
    }
    result["access_token"] = json!(access.expose_secret());
    result["refresh_token"] = json!(refresh.expose_secret());
    let expiry = result["expires_at"]
        .as_str()
        .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
        .ok_or_else(|| ApiError::internal("ata_expiry"))?;
    idempotency::complete_no_later_than(
        &mut tx,
        &state.crypto,
        operation,
        StatusCode::OK.as_u16(),
        &result,
        true,
        expiry,
    )
    .await?;
    response(tx, result, false).await
}
async fn verify(
    State(state): State<ApiState>,
    app: ApplicationClient,
    Json(input): Json<Verify>,
) -> Result<Response, ApiError> {
    let mut tx = transaction(&state, &app).await?;
    let lookup = digests(
        &state,
        &input.app_proof_token,
        "ata_",
        DigestPurpose::AtaAccessToken,
    )?;
    let result = if validation::app_id(&input.app_id).is_err()
        || input.endpoint.len() > 2048
        || lookup.is_none()
    {
        json!({"verified":false})
    } else {
        sqlx::query_scalar::<_, SqlJson<Value>>("SELECT iam_private.ata_token_verify($1,$2,$3)")
            .bind(&input.app_id)
            .bind(SqlJson(lookup))
            .bind(&input.endpoint)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| db_error(&error))?
            .0
    };
    response(tx, result, false).await
}

#[cfg(test)]
#[path = "ata_token_tests.rs"]
mod database_tests;
