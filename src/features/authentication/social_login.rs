//! Provider verification proves the current email, never a saved provider subject.
use super::super::{
    model::{TokenResponse, ValidatedContact},
    tokens,
};
use super::*;
use sqlx::{Postgres, Transaction};

#[derive(FromRow)]
pub(super) struct LoginTarget {
    pub(super) principal_id: Id,
    pub(super) contact_id: Id,
    pub(super) auth_epoch: i64,
    eligible: bool,
}
pub(super) async fn resolve_target(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    email: &ValidatedContact,
) -> Result<Option<LoginTarget>, AppError> {
    let digests = Value::Array(contacts::blind_indexes(&state.crypto, email)?.iter()
        .map(|index| json!({"key_version": index.key_version(), "digest": hex::encode(index.as_bytes())})).collect());
    let mut targets =
        sqlx::query_as::<_, LoginTarget>("SELECT * FROM iam_private.social_email_login_target($1)")
            .bind(digests)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| database_error(error, "social_email_target_read"))?;
    // Every accepted blind-index key must identify the same current contact.
    if targets.len() > 1 || targets.iter().any(|target| !target.eligible) {
        return Err(AppError::Unauthenticated);
    }
    Ok(targets.pop())
}

#[derive(FromRow)]
struct LoginProof {
    status: String,
    active: bool,
    login_principal_id: Option<Id>,
    login_auth_epoch: Option<i64>,
    login_contact_id: Option<Id>,
    candidate_id: Option<Id>,
    email_ciphertext: Option<Vec<u8>>,
    email_nonce: Option<Vec<u8>>,
    email_key_version: Option<i16>,
}
async fn proof(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    provider: &str,
    input: &StatusInput,
) -> Result<LoginProof, AppError> {
    let secret = SecretString::from(input.poll_token.clone());
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::SocialSignupPoll, &secret)
        .map_err(|_| internal("social_poll_digest"))?;
    for digest in digests {
        let row = sqlx::query_as::<_, LoginProof>("SELECT status,expires_at>transaction_timestamp() AS active,login_principal_id,login_auth_epoch,login_contact_id,candidate_id,email_ciphertext,email_nonce,email_key_version FROM iam.social_signup_requests WHERE id=$1 AND provider=$2 AND intent='login' AND poll_key_version=$3 AND poll_digest=$4 FOR UPDATE")
            .bind(input.request_id).bind(provider).bind(digest.key_version()).bind(digest.as_bytes().as_slice())
            .fetch_optional(&mut **tx).await.map_err(|error| database_error(error,"social_login_proof_read"))?;
        if let Some(row) = row {
            if !row.active {
                return Err(AppError::Unauthenticated);
            }
            return Ok(row);
        }
    }
    Err(AppError::Unauthenticated)
}

pub(super) async fn complete(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Json(input): Json<StatusInput>,
) -> Result<Response, AppError> {
    configured(&state, &provider)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    if input.poll_token.is_empty() || input.poll_token.len() > 256 {
        return Err(AppError::Unauthenticated);
    }
    let secret = SecretString::from(input.poll_token.clone());
    http::enforce_limit(
        &state,
        "social_login_complete",
        &secret,
        15,
        std::time::Duration::from_secs(60),
    )
    .await?;
    for attempt in 0..3 {
        match complete_once(&state, &provider, &key, &input).await {
            Err(AppError::Internal {
                category: "database_serialization" | "database_deadlock",
            }) if attempt < 2 => {
                tokio::time::sleep(std::time::Duration::from_millis(10 * (attempt + 1))).await;
            }
            result => return result,
        }
    }
    Err(internal("social_login_retry_exhausted"))
}
fn database_error(error: sqlx::Error, fallback: &'static str) -> AppError {
    match AppError::from(error) {
        transient @ AppError::Internal {
            category: "database_serialization" | "database_deadlock",
        } => transient,
        _ => internal(fallback),
    }
}
async fn complete_once(
    state: &ApiState,
    provider: &str,
    key: &IdempotencyKey,
    input: &StatusInput,
) -> Result<Response, AppError> {
    let mut tx = serializable(state.db(), "social_login_complete_begin").await?;
    let row = proof(&mut tx, state, provider, input).await?;
    let principal_id = row.login_principal_id.ok_or(AppError::Unauthenticated)?;
    let email = contacts::decrypt_contact(
        &state.crypto,
        ContactChannel::Email,
        row.candidate_id.ok_or(AppError::Unauthenticated)?,
        row.email_key_version.ok_or(AppError::Unauthenticated)?,
        row.email_nonce.ok_or(AppError::Unauthenticated)?,
        row.email_ciphertext.ok_or(AppError::Unauthenticated)?,
    )?;
    let current = resolve_target(
        &mut tx,
        state,
        &validation::email(email.expose_secret().to_owned())?,
    )
    .await?
    .ok_or(AppError::Unauthenticated)?;
    if current.principal_id != principal_id
        || Some(current.contact_id) != row.login_contact_id
        || Some(current.auth_epoch) != row.login_auth_epoch
    {
        return Err(AppError::Unauthenticated);
    }
    let digest = idempotency::digest_parts(
        b"social-login-complete",
        &[provider.as_bytes(), input.request_id.to_string().as_bytes()],
    );
    let record = match idempotency::begin::<TokenResponse>(
        &mut tx,
        &state.crypto,
        key,
        input.request_id.to_string().as_bytes(),
        "POST /api/v1/login/social/{provider}/complete",
        digest,
        true,
    )
    .await?
    {
        Claim::Replay { status, response } => {
            tx.commit()
                .await
                .map_err(|error| database_error(error, "social_login_replay_commit"))?;
            return http::login_success_response(state, status, response, true);
        }
        Claim::Acquired { record_id } => record_id,
    };
    if row.status != "login_ready" {
        return Err(AppError::Unauthenticated);
    }
    let method = if provider == "google" {
        "google_oidc"
    } else {
        "apple_oidc"
    };
    let response = tokens::issue_carbon_session(
        &mut tx,
        &state.crypto,
        &state.settings.security,
        principal_id,
        method,
    )
    .await?;
    sqlx::query("UPDATE iam.social_signup_requests SET status='completed',completed_at=transaction_timestamp() WHERE id=$1 AND status='login_ready'")
        .bind(input.request_id).execute(&mut *tx).await.map_err(|error| database_error(error,"social_login_consume"))?;
    idempotency::complete(&mut tx, &state.crypto, record, 200, &response, true).await?;
    tx.commit()
        .await
        .map_err(|error| database_error(error, "social_login_complete_commit"))?;
    http::login_success_response(state, 200, response, false)
}

pub(super) async fn link(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    configured(&state, &provider)?;
    Err(AppError::Gone {
        code: "provider_link_retired_restart_login".into(),
    })
}
