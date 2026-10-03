//! CLI-first social enrollment. Only the initiating client receives the signup
//! continuation; provider callbacks return a neutral, credential-free page.
use super::{
    contacts,
    database::serializable,
    http,
    idempotency::{self, Claim, IdempotencyKey, Outcome},
    model::ContactChannel,
    social_provider, validation,
};
use crate::{
    api::ApiState,
    config::SocialProviderSettings,
    domain::id::Id,
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField, SecretKind},
        postgres::context::begin_scoped,
        testing_plane,
    },
};
use axum::{
    Json, Router,
    extract::{Form, Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse as _, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::FromRow;
use time::OffsetDateTime;

#[path = "social_login.rs"]
mod login;

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/signup/social/providers", get(providers))
        .route("/api/v1/signup/social/{provider}/start", post(start))
        .route("/api/v1/signup/social/{provider}/status", post(status))
        .route("/api/v1/login/social/{provider}/start", post(login_start))
        .route("/api/v1/login/social/{provider}/status", post(login_status))
        .route(
            "/api/v1/login/social/{provider}/complete",
            post(login::complete),
        )
        .route("/api/v1/login/social/{provider}/link", post(login::link))
        .route(
            "/api/v1/signup/social/{provider}/callback",
            get(callback_get).post(callback_post),
        )
}
fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}
fn configured<'a>(
    state: &'a ApiState,
    provider: &str,
) -> Result<&'a SocialProviderSettings, AppError> {
    if testing_plane::current().is_some() {
        return Err(AppError::ServiceUnavailable);
    }
    match provider {
        "google" => state.settings.providers.google.as_ref(),
        "apple" => state.settings.providers.apple.as_ref(),
        _ => return Err(AppError::NotFound),
    }
    .ok_or(AppError::ServiceUnavailable)
}
async fn providers(State(state): State<ApiState>) -> Result<Response, AppError> {
    http::idempotent_no_store_json(Outcome::fresh(
        200,
        json!({"providers":[
 {"id":"google","enabled":configured(&state,"google").is_ok(),"login_enabled":configured(&state,"google").is_ok()},
 {"id":"apple","enabled":configured(&state,"apple").is_ok(),"login_enabled":configured(&state,"apple").is_ok()}]}),
    ))
}
fn callback_uri(state: &ApiState, provider: &str) -> String {
    format!(
        "{}/api/v1/signup/social/{provider}/callback",
        state
            .settings
            .server
            .public_base_url
            .as_str()
            .trim_end_matches('/')
    )
}
#[derive(Deserialize, Serialize)]
struct Proof {
    nonce: String,
    pkce: String,
}
#[derive(Deserialize, Serialize)]
struct StartReply {
    request_id: Id,
    authorization_url: String,
    poll_token: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}
#[allow(
    clippy::too_many_lines,
    reason = "nonce, PKCE, state, polling authority and encrypted replay are created atomically"
)]
async fn start(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    start_with_intent(state, provider, headers, "signup").await
}
async fn login_start(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    start_with_intent(state, provider, headers, "login").await
}
#[allow(
    clippy::too_many_lines,
    reason = "provider proof and encrypted initiating authority commit atomically"
)]
async fn start_with_intent(
    state: ApiState,
    provider: String,
    headers: HeaderMap,
    intent: &'static str,
) -> Result<Response, AppError> {
    let config = configured(&state, &provider)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let mut tx = serializable(state.db(), "social_signup_start").await?;
    let digest = if intent == "signup" {
        idempotency::digest_parts(b"social-signup-start", &[provider.as_bytes()])
    } else {
        idempotency::digest_parts(b"social-login-start", &[provider.as_bytes()])
    };
    let route = if intent == "signup" {
        "POST /api/v1/signup/social/{provider}/start"
    } else {
        "POST /api/v1/login/social/{provider}/start"
    };
    let lease = match idempotency::begin::<StartReply>(
        &mut tx,
        &state.crypto,
        &key,
        b"anonymous-social-signup",
        route,
        digest,
        true,
    )
    .await?
    {
        Claim::Replay { status, response } => {
            tx.commit()
                .await
                .map_err(|_| internal("social_signup_commit"))?;
            return http::idempotent_no_store_json(Outcome::replay(status, response));
        }
        Claim::Acquired { record_id } => record_id,
    };
    let request_id = Id::now_v7();
    let state_token = state
        .crypto
        .generate_secret(SecretKind::SsoState)
        .map_err(|_| internal("social_state_generate"))?;
    let poll = state
        .crypto
        .generate_secret(SecretKind::SsoState)
        .map_err(|_| internal("social_poll_generate"))?;
    let nonce = state
        .crypto
        .generate_secret(SecretKind::SsoNonce)
        .map_err(|_| internal("social_nonce_generate"))?;
    let pkce = state
        .crypto
        .generate_secret(SecretKind::SsoNonce)
        .map_err(|_| internal("social_pkce_generate"))?;
    let proof = Proof {
        nonce: nonce.expose_secret().into(),
        pkce: pkce.expose_secret().into(),
    };
    let proof_bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(&proof).map_err(|_| internal("social_proof_encode"))?,
    );
    let encrypted = state
        .crypto
        .encrypt(
            EncryptionContext::global(ProtectedField::ProviderCredential, request_id),
            &proof_bytes,
        )
        .map_err(|_| internal("social_proof_encrypt"))?;
    let state_digest = state
        .crypto
        .digest_secret(DigestPurpose::SocialSignupState, &state_token)
        .map_err(|_| internal("social_state_digest"))?;
    let poll_digest = state
        .crypto
        .digest_secret(DigestPurpose::SocialSignupPoll, &poll)
        .map_err(|_| internal("social_poll_digest"))?;
    let expires_at=sqlx::query_scalar::<_,OffsetDateTime>("INSERT INTO iam.social_signup_requests(id,provider,state_digest,state_key_version,poll_digest,poll_key_version,proof_ciphertext,proof_nonce,proof_key_version,intent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING expires_at")
 .bind(request_id).bind(&provider).bind(state_digest.as_bytes().as_slice()).bind(state_digest.key_version()).bind(poll_digest.as_bytes().as_slice()).bind(poll_digest.key_version()).bind(&encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).bind(intent).fetch_one(&mut *tx).await.map_err(|_|internal("social_signup_insert"))?;
    let mut url = url::Url::parse(if provider == "google" {
        "https://accounts.google.com/o/oauth2/v2/auth"
    } else {
        "https://appleid.apple.com/auth/authorize"
    })
    .map_err(|_| internal("social_authorize_url"))?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &callback_uri(&state, &provider))
            .append_pair("response_type", "code")
            .append_pair(
                "scope",
                if provider == "google" {
                    "openid email profile"
                } else {
                    "email name"
                },
            )
            .append_pair("state", state_token.expose_secret())
            .append_pair("nonce", &proof.nonce);
        if provider == "google" {
            query
                .append_pair("code_challenge_method", "S256")
                .append_pair(
                    "code_challenge",
                    &URL_SAFE_NO_PAD.encode(Sha256::digest(proof.pkce.as_bytes())),
                )
                .append_pair("prompt", "select_account");
        } else {
            query.append_pair("response_mode", "form_post");
        }
    }
    let reply = StartReply {
        request_id,
        authorization_url: url.into(),
        poll_token: poll.expose_secret().into(),
        expires_at,
    };
    idempotency::complete(&mut tx, &state.crypto, lease, 201, &reply, true).await?;
    tx.commit()
        .await
        .map_err(|_| internal("social_signup_commit"))?;
    http::idempotent_no_store_json(Outcome::fresh(201, reply))
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusInput {
    request_id: Id,
    poll_token: String,
}
#[derive(FromRow)]
struct PollRow {
    status: String,
    active: bool,
    signup_session_id: Option<Id>,
    candidate_id: Option<Id>,
    email_ciphertext: Option<Vec<u8>>,
    email_nonce: Option<Vec<u8>>,
    email_key_version: Option<i16>,
    display_name: Option<String>,
}
async fn status(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
    Json(input): Json<StatusInput>,
) -> Result<Response, AppError> {
    status_with_intent(state, provider, input, "signup").await
}
async fn login_status(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
    Json(input): Json<StatusInput>,
) -> Result<Response, AppError> {
    status_with_intent(state, provider, input, "login").await
}
async fn status_with_intent(
    state: ApiState,
    provider: String,
    input: StatusInput,
    intent: &'static str,
) -> Result<Response, AppError> {
    configured(&state, &provider)?;
    if input.poll_token.len() > 256 {
        return Err(AppError::Unauthenticated);
    }
    let credential = SecretString::from(input.poll_token);
    http::enforce_limit(
        &state,
        "social_signup_status",
        &credential,
        60,
        std::time::Duration::from_secs(60),
    )
    .await?;
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::SocialSignupPoll, &credential)
        .map_err(|_| internal("social_poll_digest"))?;
    let mut tx = begin_scoped(state.db())
        .await
        .map_err(|_| internal("social_poll_begin"))?;
    let mut result = None;
    for digest in digests {
        result=sqlx::query_as::<_,PollRow>("SELECT status,expires_at>transaction_timestamp() AS active,signup_session_id,candidate_id,email_ciphertext,email_nonce,email_key_version,display_name FROM iam.social_signup_requests WHERE id=$1 AND provider=$2 AND poll_key_version=$3 AND poll_digest=$4 AND intent=$5")
 .bind(input.request_id).bind(&provider).bind(digest.key_version()).bind(digest.as_bytes().as_slice()).bind(intent).fetch_optional(&mut *tx).await.map_err(|_|internal("social_poll_read"))?;
        if result.is_some() {
            break;
        }
    }
    tx.commit()
        .await
        .map_err(|_| internal("social_poll_commit"))?;
    let row = result.ok_or(AppError::Unauthenticated)?;
    let mut reply = json!({"status":if !row.active{"expired"}else if row.status=="processing"{"pending"}else{&row.status}});
    if row.active
        && matches!(
            row.status.as_str(),
            "verified" | "already_registered" | "login_ready" | "link_required"
        )
    {
        if let (Some(id), Some(ciphertext), Some(nonce), Some(version)) = (
            row.candidate_id,
            row.email_ciphertext,
            row.email_nonce,
            row.email_key_version,
        ) {
            let email = contacts::decrypt_contact(
                &state.crypto,
                ContactChannel::Email,
                id,
                version,
                nonce,
                ciphertext,
            )?;
            reply["email"] = json!(email.expose_secret());
        }
        reply["display_name"] = json!(row.display_name);
        if row.status == "verified" {
            reply["signup_session_id"] = json!(row.signup_session_id);
        }
    }
    http::idempotent_no_store_json(Outcome::fresh(200, reply))
}
#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}
async fn callback_get(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
    Query(input): Query<Callback>,
) -> Response {
    callback(state, provider, input).await
}
async fn callback_post(
    State(state): State<ApiState>,
    Path(provider): Path<String>,
    Form(input): Form<Callback>,
) -> Response {
    callback(state, provider, input).await
}
#[derive(FromRow)]
struct Claimed {
    id: Id,
    intent: String,
    proof_ciphertext: Vec<u8>,
    proof_nonce: Vec<u8>,
    proof_key_version: i16,
}
async fn claim(state: &ApiState, provider: &str, input: &Callback) -> Result<Claimed, AppError> {
    if input.state.len() > 256 || input.code.as_ref().is_some_and(|code| code.len() > 8192) {
        return Err(AppError::Unauthenticated);
    }
    let mut tx = begin_scoped(state.db())
        .await
        .map_err(|_| internal("social_callback_begin"))?;
    let state_digests = state
        .crypto
        .digest_secrets(
            DigestPurpose::SocialSignupState,
            &SecretString::from(input.state.clone()),
        )
        .map_err(|_| internal("social_state_digest"))?;
    let mut result = None;
    for digest in state_digests {
        result=sqlx::query_as::<_,Claimed>("UPDATE iam.social_signup_requests SET status='processing' WHERE provider=$1 AND state_key_version=$2 AND state_digest=$3 AND status='pending' AND expires_at>transaction_timestamp() RETURNING id,intent,proof_ciphertext,proof_nonce,proof_key_version")
 .bind(provider).bind(digest.key_version()).bind(digest.as_bytes().as_slice()).fetch_optional(&mut *tx).await.map_err(|_|internal("social_callback_claim"))?;
        if result.is_some() {
            break;
        }
    }
    tx.commit()
        .await
        .map_err(|_| internal("social_callback_commit"))?;
    result.ok_or(AppError::Unauthenticated)
}
async fn callback(state: ApiState, provider: String, input: Callback) -> Response {
    let outcome=async{
 let config=configured(&state,&provider)?;
 let request=claim(&state,&provider,&input).await?;
 let completion=async{
 if input.error.is_some(){return Err(AppError::Unauthenticated)}
 let code=input.code.as_deref().filter(|code|!code.is_empty()).ok_or(AppError::Unauthenticated)?;
 let proof_bytes=state.crypto.decrypt(EncryptionContext::global(ProtectedField::ProviderCredential,request.id),&EncryptedValue{key_version:request.proof_key_version,nonce:request.proof_nonce.try_into().map_err(|_|internal("social_proof_shape"))?,ciphertext:request.proof_ciphertext}).map_err(|_|internal("social_proof_decrypt"))?;
 let proof:Proof=serde_json::from_slice(&proof_bytes).map_err(|_|internal("social_proof_decode"))?;
 let identity=social_provider::exchange(&provider,&config.client_id,&config.client_secret,&callback_uri(&state,&provider),code,&proof.nonce,&proof.pkce).await?;
 finish_with_intent(&state,&provider,request.id,&request.intent,identity).await
 }.await;
 if completion.is_err(){
 let mut tx=begin_scoped(state.db()).await.map_err(|_|internal("social_failure_begin"))?;
 sqlx::query("UPDATE iam.social_signup_requests SET status='failed',proof_ciphertext=NULL,proof_nonce=NULL,proof_key_version=NULL WHERE id=$1 AND status='processing'").bind(request.id).execute(&mut *tx).await.map_err(|_|internal("social_failure_write"))?;
 tx.commit().await.map_err(|_|internal("social_failure_commit"))?;}
 completion
 }.await;
    let (title, message) = if outcome.is_ok() {
        (
            "Email verified",
            "Return to the IAM window or terminal where you started to continue.",
        )
    } else {
        (
            "Verification could not continue",
            "Return to IAM and try again. This link may have expired or already been used.",
        )
    };
    let html = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>IAM · {title}</title><style>html{{color-scheme:light}}*{{box-sizing:border-box}}body{{margin:0;background:#f6f8fc;color:#15213a;font:16px/1.6 ui-sans-serif,system-ui,-apple-system,sans-serif;min-height:100dvh;display:grid;place-items:center;padding:24px}}main{{width:min(100%,480px);padding:40px;background:#fff;border:1px solid #e2e8f2;border-radius:20px;box-shadow:0 16px 48px #18345a08}}main>p:first-child{{font-size:13px;font-weight:650;letter-spacing:.08em;color:#2563eb}}h1{{font-size:28px;line-height:1.25;letter-spacing:-.035em;margin:24px 0 12px}}p{{color:#647187;margin:0}}@media(max-width:480px){{main{{padding:28px}}h1{{font-size:25px}}}}</style><body><main><p>SILICON IAM</p><h1>{title}</h1><p>{message}</p></main></body></html>"
    );
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        "referrer-policy",
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        "content-security-policy",
        axum::http::HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    response
}
async fn finish_with_intent(
    state: &ApiState,
    provider: &str,
    request_id: Id,
    intent: &str,
    identity: social_provider::VerifiedIdentity,
) -> Result<(), AppError> {
    let email = validation::email(identity.email)?;
    let candidate_id = Id::now_v7();
    let encrypted = contacts::encrypt_contact(&state.crypto, &email, candidate_id)?;
    let subject = SecretString::from(format!("{provider}:{}", identity.subject));
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::SocialIdentity, &subject)
        .map_err(|_| internal("social_subject_digest"))?;
    let subject_json = Value::Array(
        digests
            .iter()
            .map(|d| json!({"key_version":d.key_version(),"digest":hex::encode(d.as_bytes())}))
            .collect(),
    );
    let mut tx = serializable(state.db(), "social_finish_begin").await?;
    let active=sqlx::query_scalar::<_,bool>("SELECT status='processing' AND expires_at>transaction_timestamp() FROM iam.social_signup_requests WHERE id=$1 AND provider=$2 FOR UPDATE").bind(request_id).bind(provider).fetch_optional(&mut *tx).await.map_err(|_|internal("social_finish_lock"))?.unwrap_or(false);
    if !active {
        return Err(AppError::Unauthenticated);
    }
    let mut exists =
        contacts::contact_associated_with_non_deleted_carbon(&mut tx, &state.crypto, &email)
            .await?;
    for digest in &digests {
        exists |= sqlx::query_scalar::<_, bool>(
            "SELECT iam_private.social_identity_registered($1,$2,$3)",
        )
        .bind(provider)
        .bind(digest.key_version())
        .bind(digest.as_bytes().as_slice())
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| internal("social_subject_lookup"))?;
    }
    let login_target = if intent == "login" {
        login::resolve_target(&mut tx, state, provider, &subject_json, &email).await?
    } else {
        None
    };
    let session = if exists || login_target.is_some() {
        None
    } else {
        let session = Id::now_v7();
        sqlx::query("INSERT INTO iam.signup_sessions(id,expires_at) VALUES($1,transaction_timestamp()+interval '48 hours')").bind(session).execute(&mut *tx).await.map_err(|_|internal("social_signup_create"))?;
        sqlx::query("INSERT INTO iam.signup_contact_candidates(id,signup_session_id,kind,ciphertext,nonce,encryption_key_version,verified_at) VALUES($1,$2,'email',$3,$4,$5,transaction_timestamp())").bind(candidate_id).bind(session).bind(&encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).execute(&mut *tx).await.map_err(|_|internal("social_candidate_create"))?;
        for index in contacts::blind_indexes(&state.crypto, &email)? {
            sqlx::query("INSERT INTO iam.signup_candidate_blind_indexes(candidate_id,contact_kind,hmac_key_version,digest) VALUES($1,'email',$2,$3)").bind(candidate_id).bind(index.key_version()).bind(index.as_bytes().as_slice()).execute(&mut *tx).await.map_err(|_|internal("social_candidate_index"))?;
        }
        Some(session)
    };
    let display_name = identity
        .display_name
        .map(|name| {
            name.chars()
                .filter(|c| !c.is_control())
                .take(160)
                .collect::<String>()
        })
        .filter(|name| !name.trim().is_empty());
    let status = login_target.as_ref().map_or(
        if exists {
            "already_registered"
        } else {
            "verified"
        },
        |target| {
            if target.linked {
                "login_ready"
            } else {
                "link_required"
            }
        },
    );
    sqlx::query("UPDATE iam.social_signup_requests SET status=$2,signup_session_id=$3,candidate_id=$4,email_ciphertext=$5,email_nonce=$6,email_key_version=$7,display_name=$8,subject_digests=$9,login_principal_id=$10,login_auth_epoch=$11,proof_ciphertext=NULL,proof_nonce=NULL,proof_key_version=NULL WHERE id=$1")
 .bind(request_id).bind(status).bind(session).bind(candidate_id).bind(&encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).bind(display_name).bind(subject_json).bind(login_target.as_ref().map(|target| target.principal_id.to_string())).bind(login_target.as_ref().map(|target| target.auth_epoch)).execute(&mut *tx).await.map_err(|_|internal("social_finish_write"))?;
    tx.commit()
        .await
        .map_err(|_| internal("social_finish_commit"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::{
        crypto::CryptoService, postgres, providers::NotificationProviders,
    };
    use anyhow::{Context as _, ensure};
    use axum::body::to_bytes;
    use sqlx::postgres::PgPoolOptions;
    use std::{str::FromStr as _, sync::Arc};
    fn headers(value: &str) -> anyhow::Result<HeaderMap> {
        let mut h = HeaderMap::new();
        h.insert("idempotency-key", axum::http::HeaderValue::from_str(value)?);
        Ok(h)
    }
    async fn body(response: Response) -> anyhow::Result<Value> {
        Ok(serde_json::from_slice(
            &to_bytes(response.into_body(), 1_048_576).await?,
        )?)
    }
    async fn initiate(state: &ApiState, key: &str) -> anyhow::Result<Value> {
        body(start(State(state.clone()), Path("google".into()), headers(key)?).await?).await
    }
    async fn authenticate(
        state: &ApiState,
        start: &Value,
        subject: &str,
        email: &str,
    ) -> anyhow::Result<()> {
        let url = url::Url::parse(
            start["authorization_url"]
                .as_str()
                .context("authorization_url")?,
        )?;
        let csrf = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .context("state")?
            .1
            .into_owned();
        let callback = Callback {
            state: csrf,
            code: Some("synthetic-provider-code".into()),
            error: None,
        };
        let request = claim(state, "google", &callback).await?;
        ensure!(
            claim(state, "google", &callback).await.is_err(),
            "callback is single use"
        );
        finish_with_intent(
            state,
            "google",
            request.id,
            &request.intent,
            social_provider::VerifiedIdentity {
                subject: subject.into(),
                email: email.into(),
                display_name: Some("Ada Lovelace".into()),
            },
        )
        .await?;
        Ok(())
    }
    async fn poll(state: &ApiState, start: &Value) -> anyhow::Result<Value> {
        body(
            status(
                State(state.clone()),
                Path("google".into()),
                Json(StatusInput {
                    request_id: Id::from_str(start["request_id"].as_str().context("id")?)?,
                    poll_token: start["poll_token"].as_str().context("poll")?.into(),
                }),
            )
            .await?,
        )
        .await
    }
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "restricted-role signup, login, linking, replay and revocation share one bounded fixture"
    )]
    #[ignore = "requires isolated local PostgreSQL and synthetic IAM settings"]
    async fn social_signup_state_and_subject_binding() -> anyhow::Result<()> {
        let database = crate::test_database::TestDatabase::start().await?;
        postgres::migrate(&database.pool).await?;
        sqlx::raw_sql("INSERT INTO iam.cryptographic_key_versions(purpose,key_version) VALUES ('contact_aead',1),('contact_lookup_hmac',1),('token_hmac',1)").execute(&database.pool).await?;
        let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
            .execute(&database.pool)
            .await?;
        let mut settings = crate::config::Settings::from_env()?;
        settings.providers.google = Some(SocialProviderSettings {
            client_id: "synthetic-google-client".into(),
            client_secret: SecretString::from("synthetic-secret"),
        });
        settings.providers.apple = None;
        settings.providers.postmark_server_token = None;
        settings.providers.twilio_account_sid = None;
        settings.providers.twilio_auth_token = None;
        settings.providers.twilio_messaging_service_sid = None;
        settings.providers.twilio_verify_service_sid = None;
        settings.providers.allow_local_providers = true;
        settings.providers.expose_local_otps = true;
        let runtime = PgPoolOptions::new()
            .max_connections(2)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET ROLE silicon_iam_api")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database.url)
            .await?;
        let state = ApiState {
            pool: runtime,
            crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
            notifications: NotificationProviders::from_settings(&settings.providers)?,
            settings: Arc::new(settings),
            workos: None,
            testing: None,
        };
        ensure!(configured(&state, "apple").is_err());
        let first = initiate(&state, "social-first-start").await?;
        ensure!(
            first == initiate(&state, "social-first-start").await?,
            "start replays the exact initiating credential"
        );
        ensure!(poll(&state, &first).await?["status"] == "pending");
        let mut stolen = first.clone();
        stolen["poll_token"] = json!("wrong");
        ensure!(poll(&state, &stolen).await.is_err());
        authenticate(&state, &first, "subject-one", "ada-social@example.test").await?;
        let ready = poll(&state, &first).await?;
        ensure!(ready["status"] == "verified");
        ensure!(ready["email"] == "ada-social@example.test");
        let session = Id::from_str(ready["signup_session_id"].as_str().context("session")?)?;
        let profile = validation::signup_completion(
            super::super::model::SignupCompletionInput {
                carbon_id: None,
                display_name: None,
                timezone: Some("Asia/Kolkata".into()),
                profile_photo: None,
            },
            false,
        )?;
        let key = IdempotencyKey::from_headers(&headers("social-first-complete")?)?;
        let completed =
            super::super::signup::complete_signup(&state, &key, session, profile).await?;
        let completed_json = serde_json::to_value(completed.value)?;
        ensure!(completed_json["access_token"].is_string());
        let bound: i64 = sqlx::query_scalar("SELECT count(*) FROM iam.carbon_social_identities")
            .fetch_one(&database.pool)
            .await?;
        ensure!(bound == 1);
        let second = initiate(&state, "social-duplicate-email").await?;
        authenticate(&state, &second, "subject-two", "ada-social@example.test").await?;
        ensure!(poll(&state, &second).await?["status"] == "already_registered");
        let third = initiate(&state, "social-duplicate-subject").await?;
        authenticate(&state, &third, "subject-one", "changed-email@example.test").await?;
        ensure!(
            poll(&state, &third).await?["status"] == "already_registered",
            "immutable provider subject must not spawn another account after email changes"
        );
        // Existing subjects log in without trusting a newly presented email as account authority.
        let input = |start: &Value| -> anyhow::Result<StatusInput> {
            Ok(StatusInput {
                request_id: Id::from_str(start["request_id"].as_str().context("request")?)?,
                poll_token: start["poll_token"].as_str().context("poll")?.to_owned(),
            })
        };
        let known = body(
            login_start(
                State(state.clone()),
                Path("google".into()),
                headers("social-known-login")?,
            )
            .await?,
        )
        .await?;
        authenticate(
            &state,
            &known,
            "subject-one",
            "new-provider-email@example.test",
        )
        .await?;
        let ready = body(
            login_status(
                State(state.clone()),
                Path("google".into()),
                Json(input(&known)?),
            )
            .await?,
        )
        .await?;
        ensure!(ready["status"] == "login_ready");
        ensure!(
            status(
                State(state.clone()),
                Path("google".into()),
                Json(input(&known)?)
            )
            .await
            .is_err(),
            "signup polling cannot retrieve a login proof"
        );
        let first_login = body(
            login::complete(
                State(state.clone()),
                Path("google".into()),
                headers("social-login-completion")?,
                Json(input(&known)?),
            )
            .await?,
        )
        .await?;
        let replay = body(
            login::complete(
                State(state.clone()),
                Path("google".into()),
                headers("social-login-completion")?,
                Json(input(&known)?),
            )
            .await?,
        )
        .await?;
        ensure!(
            first_login == replay,
            "uncertain completion replays the exact token pair"
        );
        ensure!(
            login::complete(
                State(state.clone()),
                Path("google".into()),
                headers("social-login-another-key")?,
                Json(input(&known)?)
            )
            .await
            .is_err(),
            "one proof cannot create another session"
        );
        let method: String = sqlx::query_scalar(
            "SELECT authentication_method FROM iam.authentication_sessions WHERE id=$1",
        )
        .bind(Id::from_str(
            first_login["session_id"].as_str().context("session")?,
        )?)
        .fetch_one(&database.pool)
        .await?;
        ensure!(
            method == "google_oidc",
            "provider login is never reported as an OTP"
        );
        let mut wrong_proof = input(&known)?;
        wrong_proof.poll_token.push('x');
        ensure!(
            login::complete(
                State(state.clone()),
                Path("google".into()),
                headers("social-wrong-poll-denied")?,
                Json(wrong_proof),
            )
            .await
            .is_err(),
            "provider state alone cannot redeem an initiating client's proof"
        );
        testing_plane::scope(
            testing_plane::SelectedEnvironment {
                id: Id::now_v7(),
                organization_id: Id::now_v7(),
            },
            async {
                ensure!(matches!(
                    login_start(
                        State(state.clone()),
                        Path("google".into()),
                        headers("social-test-plane")?
                    )
                    .await,
                    Err(AppError::ServiceUnavailable)
                ));
                ensure!(matches!(
                    login::complete(
                        State(state.clone()),
                        Path("google".into()),
                        headers("social-test-proof")?,
                        Json(input(&known)?)
                    )
                    .await,
                    Err(AppError::ServiceUnavailable)
                ));
                anyhow::Ok(())
            },
        )
        .await?;
        let unbound = body(
            login_start(
                State(state.clone()),
                Path("google".into()),
                headers("social-new-subject-link")?,
            )
            .await?,
        )
        .await?;
        authenticate(&state, &unbound, "subject-link", "ada-social@example.test").await?;
        ensure!(
            body(
                login_status(
                    State(state.clone()),
                    Path("google".into()),
                    Json(input(&unbound)?)
                )
                .await?
            )
            .await?["status"]
                == "link_required"
        );
        ensure!(
            login::complete(
                State(state.clone()),
                Path("google".into()),
                headers("social-email-only-denied")?,
                Json(input(&unbound)?)
            )
            .await
            .is_err(),
            "verified email alone cannot link or log in"
        );
        let old_access = crate::infrastructure::postgres::tokens::authenticate(
            state.db(),
            &state.crypto,
            &SecretString::from(
                completed_json["access_token"]
                    .as_str()
                    .context("access")?
                    .to_owned(),
            ),
        )
        .await?
        .context("old access")?;
        ensure!(
            login::link(
                State(state.clone()),
                crate::api::authentication::Authenticated(old_access.clone()),
                Path("google".into()),
                headers("social-stale-session-denied")?,
                Json(input(&unbound)?)
            )
            .await
            .is_err(),
            "link requires a fresh independent login"
        );
        let mut tx = serializable(state.db(), "social-test-fresh-login").await?;
        let fresh = super::super::tokens::issue_login_session(
            &mut tx,
            &state.crypto,
            &state.settings.security,
            old_access.subject.id,
            ContactChannel::Email,
        )
        .await?;
        tx.commit().await?;
        let access = crate::infrastructure::postgres::tokens::authenticate(
            state.db(),
            &state.crypto,
            &SecretString::from(fresh.access_token),
        )
        .await?
        .context("fresh access")?;
        let linked = body(
            login::link(
                State(state.clone()),
                crate::api::authentication::Authenticated(access.clone()),
                Path("google".into()),
                headers("social-fresh-link")?,
                Json(input(&unbound)?),
            )
            .await?,
        )
        .await?;
        ensure!(linked["linked"] == true);
        let linked_replay = body(
            login::link(
                State(state.clone()),
                crate::api::authentication::Authenticated(access),
                Path("google".into()),
                headers("social-fresh-link")?,
                Json(input(&unbound)?),
            )
            .await?,
        )
        .await?;
        ensure!(linked == linked_replay);
        let audit_count: i64 = sqlx::query_scalar("SELECT count(*) FROM iam.authentication_events WHERE event_type='social_identity.linked' AND subject_principal_id=$1")
            .bind(old_access.subject.id).fetch_one(&database.pool).await?;
        ensure!(
            audit_count == 1,
            "linking is audited exactly once across replay"
        );
        let again = body(
            login_start(
                State(state.clone()),
                Path("google".into()),
                headers("social-linked-next-login")?,
            )
            .await?,
        )
        .await?;
        authenticate(&state, &again, "subject-link", "ada-social@example.test").await?;
        ensure!(
            body(
                login_status(
                    State(state.clone()),
                    Path("google".into()),
                    Json(input(&again)?)
                )
                .await?
            )
            .await?["status"]
                == "login_ready"
        );
        sqlx::query("UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id=$1")
            .bind(old_access.subject.id)
            .execute(&database.pool)
            .await?;
        ensure!(
            login::complete(
                State(state.clone()),
                Path("google".into()),
                headers("social-reset-denied")?,
                Json(input(&again)?)
            )
            .await
            .is_err(),
            "security reset invalidates pending provider login proof"
        );
        sqlx::query("UPDATE iam.social_signup_requests SET expires_at=transaction_timestamp()-interval '1 second',created_at=transaction_timestamp()-interval '11 minutes' WHERE id=$1").bind(Id::from_str(first["request_id"].as_str().context("first id")?)?).execute(&database.pool).await?;
        ensure!(poll(&state, &first).await?["status"] == "expired");
        Ok(())
    }
}
