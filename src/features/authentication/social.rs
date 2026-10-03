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
    let mut tx = serializable(state.db(), "social_finish_begin").await?;
    let active=sqlx::query_scalar::<_,bool>("SELECT status='processing' AND expires_at>transaction_timestamp() FROM iam.social_signup_requests WHERE id=$1 AND provider=$2 FOR UPDATE").bind(request_id).bind(provider).fetch_optional(&mut *tx).await.map_err(|_|internal("social_finish_lock"))?.unwrap_or(false);
    if !active {
        return Err(AppError::Unauthenticated);
    }
    // A retained verified contact must not become a second signup, even when
    // its owner is suspended or deleted. Explicitly retired contacts are free.
    let target = login::resolve_target(&mut tx, state, &email).await?;
    let exists = target.is_some();
    let login_target = if intent == "login" { target } else { None };
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
    let status = if login_target.is_some() {
        "login_ready"
    } else if exists {
        "already_registered"
    } else {
        "verified"
    };
    sqlx::query("UPDATE iam.social_signup_requests SET status=$2,signup_session_id=$3,candidate_id=$4,email_ciphertext=$5,email_nonce=$6,email_key_version=$7,display_name=$8,subject_digests=NULL,login_principal_id=$9,login_auth_epoch=$10,login_contact_id=$11,proof_ciphertext=NULL,proof_nonce=NULL,proof_key_version=NULL WHERE id=$1")
 .bind(request_id).bind(status).bind(session).bind(candidate_id).bind(&encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).bind(display_name).bind(login_target.as_ref().map(|target| target.principal_id.to_string())).bind(login_target.as_ref().map(|target| target.auth_epoch)).bind(login_target.as_ref().map(|target| target.contact_id)).execute(&mut *tx).await.map_err(|_|internal("social_finish_write"))?;
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
        h.insert(
            "idempotency-key",
            axum::http::HeaderValue::from_str(&format!("provider-email-test-{value}"))?,
        );
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
        _subject: &str,
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
    fn input(start: &Value) -> anyhow::Result<StatusInput> {
        Ok(StatusInput {
            request_id: Id::from_str(start["request_id"].as_str().context("request")?)?,
            poll_token: start["poll_token"].as_str().context("poll")?.into(),
        })
    }
    fn profile() -> Result<super::super::model::ValidatedSignupCompletion, AppError> {
        validation::signup_completion(
            super::super::model::SignupCompletionInput {
                carbon_id: None,
                display_name: None,
                timezone: Some("Asia/Kolkata".into()),
                profile_photo: None,
            },
            false,
        )
    }
    async fn login_poll(state: &ApiState, provider: &str, start: &Value) -> anyhow::Result<Value> {
        body(
            login_status(
                State(state.clone()),
                Path(provider.into()),
                Json(input(start)?),
            )
            .await?,
        )
        .await
    }
    async fn provider_request(
        state: &ApiState,
        provider: &str,
        key: &str,
        email: &str,
    ) -> anyhow::Result<Value> {
        let start =
            body(login_start(State(state.clone()), Path(provider.into()), headers(key)?).await?)
                .await?;
        let url = url::Url::parse(start["authorization_url"].as_str().context("url")?)?;
        let csrf = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .context("state")?
            .1
            .into_owned();
        let request = claim(
            state,
            provider,
            &Callback {
                state: csrf,
                code: Some("synthetic-code".into()),
                error: None,
            },
        )
        .await?;
        finish_with_intent(
            state,
            provider,
            request.id,
            &request.intent,
            social_provider::VerifiedIdentity {
                email: email.into(),
                display_name: None,
            },
        )
        .await?;
        Ok(start)
    }
    async fn complete_login(
        state: &ApiState,
        provider: &str,
        start: &Value,
        key: &str,
    ) -> anyhow::Result<Value> {
        body(
            login::complete(
                State(state.clone()),
                Path(provider.into()),
                headers(key)?,
                Json(input(start)?),
            )
            .await?,
        )
        .await
    }
    async fn ordinary_signup(state: &ApiState, email: &str, key: &str) -> anyhow::Result<Value> {
        let key_for = |suffix: &str| -> anyhow::Result<IdempotencyKey> {
            Ok(IdempotencyKey::from_headers(&headers(&format!(
                "{key}-{suffix}"
            ))?)?)
        };
        let session = super::super::signup::create_session(state, &key_for("start")?)
            .await?
            .value
            .session_id;
        let dispatch = super::super::signup::start_contact(
            state,
            &key_for("contact")?,
            session,
            validation::email(email.into())?,
        )
        .await?
        .value;
        super::super::signup::verify_contact(
            state,
            &key_for("verify")?,
            session,
            ContactChannel::Email,
            SecretString::from(dispatch.local_otp.context("synthetic OTP")?),
        )
        .await?;
        Ok(serde_json::to_value(
            super::super::signup::complete_signup(
                state,
                &key_for("complete")?,
                session,
                profile()?,
            )
            .await?
            .value,
        )?)
    }
    async fn fixture(
        testing: bool,
    ) -> anyhow::Result<(crate::test_database::TestDatabase, ApiState)> {
        let database = crate::test_database::TestDatabase::start().await?;
        if testing {
            postgres::migrate_testing(&database.pool).await?;
        } else {
            postgres::migrate(&database.pool).await?;
        }
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
        Ok((database, state))
    }
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "restricted-role provider email journeys share one bounded fixture"
    )]
    #[ignore = "requires isolated local PostgreSQL and synthetic IAM settings"]
    async fn provider_email_authentication_protocol() -> anyhow::Result<()> {
        let (database, state) = fixture(false).await?;
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
        let initial_profile = validation::signup_completion(
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
            super::super::signup::complete_signup(&state, &key, session, initial_profile).await?;
        let completed_json = serde_json::to_value(completed.value)?;
        ensure!(completed_json["access_token"].is_string());
        let bound: i64 = sqlx::query_scalar("SELECT count(*) FROM iam.carbon_social_identities")
            .fetch_one(&database.pool)
            .await?;
        ensure!(
            bound == 0,
            "signup must not create provider subject associations"
        );
        let principal = Id::from_str(
            completed_json["actor"]["principal_id"]
                .as_str()
                .context("principal")?,
        )?;
        // A provider-created contact is an ordinary verified email login target.
        let otp_key = IdempotencyKey::from_headers(&headers("provider-to-email-otp")?)?;
        let challenge = super::super::login::create_challenge(
            &state,
            &otp_key,
            super::super::model::ValidatedLoginIdentifier::Contact(validation::email(
                "ada-social@example.test".into(),
            )?),
        )
        .await?
        .value;
        let verified = super::super::login::verify_challenge(
            &state,
            &IdempotencyKey::from_headers(&headers("provider-email-otp-verify")?)?,
            challenge.session_id,
            SecretString::from(challenge.local_otp.context("synthetic OTP")?),
        )
        .await?
        .value;
        let super::super::model::LoginVerificationOutcome::Success(otp_tokens) = verified else {
            anyhow::bail!("ordinary OTP must sign in")
        };
        ensure!(otp_tokens.actor.principal_id == principal);

        // Complete a second Carbon entirely through the ordinary email OTP flow.
        let normal = ordinary_signup(&state, "email-created@example.test", "email-created").await?;
        let normal_id = Id::from_str(
            normal["actor"]["principal_id"]
                .as_str()
                .context("normal principal")?,
        )?;
        let known = provider_request(
            &state,
            "google",
            "normal-google",
            "email-created@example.test",
        )
        .await?;
        let first_login =
            complete_login(&state, "google", &known, "normal-google-complete").await?;
        ensure!(first_login["actor"]["principal_id"] == normal["actor"]["principal_id"]);
        ensure!(
            first_login
                == complete_login(&state, "google", &known, "normal-google-complete").await?
        );
        ensure!(
            complete_login(&state, "google", &known, "normal-google-another-key")
                .await
                .is_err()
        );
        let mut stolen = input(&known)?;
        stolen.poll_token.push('x');
        ensure!(
            login::complete(
                State(state.clone()),
                Path("google".into()),
                headers("bad-proof")?,
                Json(stolen)
            )
            .await
            .is_err()
        );
        ensure!(
            status(
                State(state.clone()),
                Path("google".into()),
                Json(input(&known)?)
            )
            .await
            .is_err(),
            "proof is bound to its flow"
        );
        ensure!(matches!(
            login::link(State(state.clone()), Path("google".into())).await,
            Err(AppError::Gone { .. })
        ));
        let login_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM iam.login_challenges WHERE carbon_id=$1")
                .bind(normal_id)
                .fetch_one(&database.pool)
                .await?;
        ensure!(
            login_count == 0,
            "provider login must not send an additional IAM OTP"
        );

        let mut apple_state = state.clone();
        let mut apple_settings = (*state.settings).clone();
        apple_settings.providers.apple = apple_settings.providers.google.clone();
        apple_state.settings = Arc::new(apple_settings);
        let apple = provider_request(
            &apple_state,
            "apple",
            "normal-apple",
            "EMAIL-CREATED@example.test",
        )
        .await?;
        let apple_login =
            complete_login(&apple_state, "apple", &apple, "normal-apple-complete").await?;
        ensure!(apple_login["actor"]["principal_id"] == normal["actor"]["principal_id"]);
        let method: String = sqlx::query_scalar(
            "SELECT authentication_method FROM iam.authentication_sessions WHERE id=$1",
        )
        .bind(Id::from_str(
            apple_login["session_id"].as_str().context("session")?,
        )?)
        .fetch_one(&database.pool)
        .await?;
        ensure!(method == "apple_oidc");

        // Historical subjects confer no authority and do not reserve an identity.
        sqlx::query("INSERT INTO iam.carbon_social_identities(provider,key_version,subject_digest,principal_id) VALUES ('google',1,$1,$2)")
            .bind(vec![1_u8;32]).bind(principal).execute(&database.pool).await?;
        let changed = provider_request(
            &state,
            "google",
            "changed-current-email",
            "email-created@example.test",
        )
        .await?;
        ensure!(
            complete_login(&state, "google", &changed, "changed-current-email-complete").await?["actor"]
                ["principal_id"]
                == normal["actor"]["principal_id"]
        );
        let new_email = provider_request(
            &state,
            "google",
            "new-current-email",
            "new-current@example.test",
        )
        .await?;
        let new_status = login_poll(&state, "google", &new_email).await?;
        ensure!(new_status["status"] == "verified" && new_status["signup_session_id"].is_string());
        let private_alias = provider_request(
            &apple_state,
            "apple",
            "apple-relay",
            "private-alias@privaterelay.appleid.com",
        )
        .await?;
        ensure!(
            login_poll(&apple_state, "apple", &private_alias).await?["status"] == "verified",
            "Apple alias never resolves the hidden underlying email"
        );
        let second = initiate(&state, "legacy-duplicate-email").await?;
        authenticate(
            &state,
            &second,
            "ignored-subject",
            "ada-social@example.test",
        )
        .await?;
        ensure!(
            poll(&state, &second).await?["status"] == "already_registered",
            "legacy signup wire remains compatible"
        );

        // Two independent requests for one account cannot deadlock on a lock upgrade.
        let parallel_a =
            provider_request(&state, "google", "parallel-a", "email-created@example.test").await?;
        let parallel_b =
            provider_request(&state, "google", "parallel-b", "email-created@example.test").await?;
        let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(
                complete_login(&state, "google", &parallel_a, "parallel-a-complete"),
                complete_login(&state, "google", &parallel_b, "parallel-b-complete")
            )
        })
        .await?;
        ensure!(a?["actor"]["principal_id"] == b?["actor"]["principal_id"]);

        // Security reset invalidates pending proof and even exact-key response replay.
        let reset = provider_request(
            &state,
            "google",
            "reset-proof",
            "email-created@example.test",
        )
        .await?;
        sqlx::query("UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id=$1")
            .bind(normal_id)
            .execute(&database.pool)
            .await?;
        ensure!(
            complete_login(&state, "google", &reset, "reset-complete")
                .await
                .is_err()
        );
        ensure!(
            complete_login(&state, "google", &known, "normal-google-complete")
                .await
                .is_err()
        );

        let suspended = provider_request(
            &state,
            "google",
            "suspended-proof",
            "email-created@example.test",
        )
        .await?;
        sqlx::query("UPDATE iam.principals SET status='suspended',suspended_at=transaction_timestamp() WHERE id=$1")
            .bind(normal_id)
            .execute(&database.pool)
            .await?;
        ensure!(
            complete_login(&state, "google", &suspended, "suspended-complete")
                .await
                .is_err()
        );
        ensure!(
            provider_request(
                &state,
                "google",
                "suspended-start",
                "email-created@example.test"
            )
            .await
            .is_err(),
            "retained suspended email must not create signup"
        );
        sqlx::query("UPDATE iam.principals SET status='active',suspended_at=NULL WHERE id=$1")
            .bind(normal_id)
            .execute(&database.pool)
            .await?;
        sqlx::query("UPDATE iam.carbons SET deleted_at=transaction_timestamp() WHERE id=$1")
            .bind(normal_id)
            .execute(&database.pool)
            .await?;
        ensure!(
            provider_request(
                &state,
                "google",
                "deleted-start",
                "email-created@example.test"
            )
            .await
            .is_err(),
            "retained deleted email must not create signup"
        );
        sqlx::query("UPDATE iam.carbons SET deleted_at=NULL WHERE id=$1")
            .bind(normal_id)
            .execute(&database.pool)
            .await?;

        // Retiring and re-adding the same address to the same Carbon cannot revive proof.
        let contact_proof = provider_request(
            &state,
            "google",
            "contact-proof",
            "email-created@example.test",
        )
        .await?;
        let old_contact: Id = sqlx::query_scalar("SELECT id FROM iam.carbon_contacts WHERE carbon_id=$1 AND kind='email' AND is_primary AND status='active'")
            .bind(normal_id).fetch_one(&database.pool).await?;
        let new_contact = Id::now_v7();
        let encrypted = contacts::encrypt_contact(
            &state.crypto,
            &validation::email("email-created@example.test".into())?,
            new_contact,
        )?;
        let mut admin = database.pool.begin().await?;
        sqlx::query("UPDATE iam.carbon_contacts SET status='retired',retired_at=transaction_timestamp(),is_primary=false WHERE id=$1").bind(old_contact).execute(&mut *admin).await?;
        sqlx::query("INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at,is_primary) VALUES($1,$2,'email',$3,$4,$5,transaction_timestamp(),true)")
            .bind(new_contact).bind(normal_id).bind(encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).execute(&mut *admin).await?;
        sqlx::query("UPDATE iam.contact_blind_indexes SET contact_id=$1 WHERE contact_id=$2")
            .bind(new_contact)
            .bind(old_contact)
            .execute(&mut *admin)
            .await?;
        admin.commit().await?;
        ensure!(
            complete_login(&state, "google", &contact_proof, "contact-proof-complete")
                .await
                .is_err()
        );
        let after_contact = provider_request(
            &state,
            "google",
            "new-contact-proof",
            "email-created@example.test",
        )
        .await?;
        ensure!(
            complete_login(&state, "google", &after_contact, "new-contact-complete").await?["actor"]
                ["principal_id"]
                == normal["actor"]["principal_id"]
        );

        // A separate verified signup may win before provider enrollment completes.
        let racing =
            provider_request(&state, "google", "signup-race", "signup-race@example.test").await?;
        let candidate = login_poll(&state, "google", &racing).await?;
        ordinary_signup(&state, "signup-race@example.test", "signup-race-email").await?;
        let race_result = super::super::signup::complete_signup(
            &state,
            &IdempotencyKey::from_headers(&headers("signup-race-provider-complete")?)?,
            Id::from_str(
                candidate["signup_session_id"]
                    .as_str()
                    .context("race session")?,
            )?,
            profile()?,
        )
        .await;
        ensure!(
            matches!(race_result, Err(AppError::Conflict { .. })),
            "concurrent signup must be a clean conflict, got {:?}",
            race_result.err()
        );

        // All accepted key versions must agree; a first-match resolver would miss this corruption.
        let mut ambiguous_settings = (*state.settings).clone();
        let retained = ambiguous_settings
            .security
            .blind_index_keys
            .keys
            .get(&1)
            .context("key1")?
            .clone();
        ambiguous_settings
            .security
            .blind_index_keys
            .keys
            .insert(2, retained);
        let mut ambiguous = state.clone();
        ambiguous.crypto = Arc::new(CryptoService::from_settings(&ambiguous_settings.security)?);
        let ada_contact: Id=sqlx::query_scalar("SELECT id FROM iam.carbon_contacts WHERE carbon_id=$1 AND kind='email' AND status='active'").bind(principal).fetch_one(&database.pool).await?;
        sqlx::query("INSERT INTO iam.cryptographic_key_versions(purpose,key_version,status) VALUES ('contact_lookup_hmac',2,'decrypt_only')").execute(&database.pool).await?;
        let index = contacts::blind_indexes(
            &ambiguous.crypto,
            &validation::email("email-created@example.test".into())?,
        )?
        .into_iter()
        .find(|index| index.key_version() == 2)
        .context("key2 digest")?;
        sqlx::query("INSERT INTO iam.contact_blind_indexes(contact_id,contact_kind,hmac_key_version,digest) VALUES($1,'email',2,$2)").bind(ada_contact).bind(index.as_bytes().as_slice()).execute(&database.pool).await?;
        ensure!(
            provider_request(
                &ambiguous,
                "google",
                "ambiguous-keys",
                "email-created@example.test"
            )
            .await
            .is_err()
        );

        let expired = provider_request(
            &state,
            "google",
            "expired-proof",
            "email-created@example.test",
        )
        .await?;
        sqlx::query("UPDATE iam.social_signup_requests SET expires_at=transaction_timestamp()-interval '1 second',created_at=transaction_timestamp()-interval '11 minutes' WHERE id=$1")
            .bind(input(&expired)?.request_id).execute(&database.pool).await?;
        ensure!(login_poll(&state, "google", &expired).await?["status"] == "expired");
        ensure!(
            complete_login(&state, "google", &expired, "expired-complete")
                .await
                .is_err()
        );
        // Ownership reassignment invalidates both pending proof and exact-key replay.
        let moved_proof = provider_request(
            &state,
            "google",
            "reassigned-proof",
            "email-created@example.test",
        )
        .await?;
        let replacement = contacts::encrypt_contact(
            &state.crypto,
            &validation::email("email-created@example.test".into())?,
            ada_contact,
        )?;
        let replacement_contact = Id::now_v7();
        let replacement_email = validation::email("replacement-normal@example.test".into())?;
        let replacement_encrypted =
            contacts::encrypt_contact(&state.crypto, &replacement_email, replacement_contact)?;
        let mut admin = database.pool.begin().await?;
        sqlx::query("UPDATE iam.carbon_contacts SET status='retired',retired_at=transaction_timestamp(),is_primary=false WHERE id=$1").bind(new_contact).execute(&mut *admin).await?;
        sqlx::query("INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at,is_primary) VALUES($1,$2,'email',$3,$4,$5,transaction_timestamp(),true)")
            .bind(replacement_contact).bind(normal_id).bind(replacement_encrypted.ciphertext).bind(replacement_encrypted.nonce.as_slice()).bind(replacement_encrypted.key_version).execute(&mut *admin).await?;
        for index in contacts::blind_indexes(&state.crypto, &replacement_email)? {
            sqlx::query("INSERT INTO iam.contact_blind_indexes(contact_id,contact_kind,hmac_key_version,digest) VALUES($1,'email',$2,$3)").bind(replacement_contact).bind(index.key_version()).bind(index.as_bytes().as_slice()).execute(&mut *admin).await?;
        }
        sqlx::query("DELETE FROM iam.contact_blind_indexes WHERE contact_id=$1")
            .bind(ada_contact)
            .execute(&mut *admin)
            .await?;
        sqlx::query("UPDATE iam.carbon_contacts SET ciphertext=$2,nonce=$3,encryption_key_version=$4 WHERE id=$1")
            .bind(ada_contact).bind(replacement.ciphertext).bind(replacement.nonce.as_slice()).bind(replacement.key_version).execute(&mut *admin).await?;
        sqlx::query("UPDATE iam.contact_blind_indexes SET contact_id=$1 WHERE contact_id=$2")
            .bind(ada_contact)
            .bind(new_contact)
            .execute(&mut *admin)
            .await?;
        admin.commit().await?;
        ensure!(
            complete_login(&state, "google", &moved_proof, "reassigned-complete")
                .await
                .is_err()
        );
        ensure!(
            complete_login(&state, "google", &after_contact, "new-contact-complete")
                .await
                .is_err()
        );
        let new_owner = provider_request(
            &state,
            "google",
            "new-owner-proof",
            "email-created@example.test",
        )
        .await?;
        ensure!(
            complete_login(&state, "google", &new_owner, "new-owner-complete").await?["actor"]["principal_id"]
                == completed_json["actor"]["principal_id"]
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
                        headers("testing-provider")?
                    )
                    .await,
                    Err(AppError::ServiceUnavailable)
                ));
                ensure!(matches!(
                    login::complete(
                        State(state.clone()),
                        Path("google".into()),
                        headers("testing-complete")?,
                        Json(input(&known)?)
                    )
                    .await,
                    Err(AppError::ServiceUnavailable)
                ));
                anyhow::Ok(())
            },
        )
        .await?;
        for name in [
            "social_login_identity(text,jsonb)",
            "social_identity_registered(text,smallint,bytea)",
            "bind_social_login_identity(uuid,text,uuid)",
        ] {
            let exists: bool =
                sqlx::query_scalar("SELECT to_regprocedure('iam_private.'||$1) IS NOT NULL")
                    .bind(name)
                    .fetch_one(&database.pool)
                    .await?;
            ensure!(!exists, "old subject helper must be absent");
        }
        let denied = sqlx::query("SELECT * FROM iam.carbon_social_identities")
            .fetch_all(state.db())
            .await;
        ensure!(
            denied.is_err(),
            "historical association rows remain private"
        );
        Ok(())
    }
    #[tokio::test]
    #[ignore = "requires isolated local PostgreSQL and synthetic IAM settings"]
    async fn provider_email_helper_testing_isolation() -> anyhow::Result<()> {
        let (_database, state) = fixture(true).await?;
        let world = testing_plane::SelectedEnvironment {
            id: Id::from_u128(0x145),
            organization_id: Id::from_u128(0x146),
        };
        let email = validation::email("testing-provider@example.test".into())?;
        Box::pin(testing_plane::scope(world, async {
            let account =
                ordinary_signup(&state, "testing-provider@example.test", "testing-email").await?;
            let mut tx = serializable(state.db(), "testing-email-helper").await?;
            let target = login::resolve_target(&mut tx, &state, &email)
                .await?
                .context("same world email target")?;
            ensure!(
                target.principal_id.to_string()
                    == account["actor"]["principal_id"].as_str().context("actor")?
            );
            tx.commit().await?;
            ensure!(matches!(
                login_start(
                    State(state.clone()),
                    Path("google".into()),
                    headers("testing-denial")?
                )
                .await,
                Err(AppError::ServiceUnavailable)
            ));
            anyhow::Ok(())
        }))
        .await?;
        testing_plane::scope(
            testing_plane::SelectedEnvironment {
                id: Id::from_u128(0x147),
                organization_id: Id::from_u128(0x148),
            },
            async {
                let mut tx = serializable(state.db(), "other-testing-email-helper").await?;
                ensure!(
                    login::resolve_target(&mut tx, &state, &email)
                        .await?
                        .is_none()
                );
                tx.commit().await?;
                anyhow::Ok(())
            },
        )
        .await?;
        Ok(())
    }
}
