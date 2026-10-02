//! Independently registered Silicon identities, approved by a verified Carbon.
use super::{
    contacts,
    database::{database_conflict, serializable},
    http::idempotent_no_store_json,
    idempotency::{self, Claim, IdempotencyKey, Outcome},
    silicon, validation,
};
use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{actor::ActorType, id::Id},
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, EncryptionContext, ProtectedField, SecretDigest, SecretKind},
        postgres::{
            context::{self, DatabaseContext},
            rate_limit::{self, RateLimitPolicy},
        },
    },
};
use argon2::{
    Argon2, PasswordHasher as _, PasswordVerifier as _,
    password_hash::{PasswordHash, SaltString},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignupInput {
    silicon_id: String,
    silicon_token: Option<String>,
    custodian_email: String,
    display_name: Option<String>,
    timezone: Option<String>,
    webhook_url: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Decision {
    approve: bool,
    #[serde(default = "default_true")]
    can_create_organizations: bool,
}
fn default_true() -> bool {
    true
}
fn internal() -> AppError {
    AppError::Internal {
        category: "silicon_signup",
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "signup credential creation, invitation queue, and replay receipt commit atomically"
)]
pub(super) async fn create(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<SignupInput>,
) -> Result<Response, AppError> {
    silicon::validate_global_id(&input.silicon_id)?;
    let email = validation::email(input.custodian_email.clone())?;
    let name = input
        .display_name
        .clone()
        .unwrap_or_else(|| input.silicon_id[3..].to_owned());
    if name.trim().is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err(validation::validation(
            "display_name",
            "must contain 1 to 100 printable characters",
        ));
    }
    let timezone = input.timezone.clone().unwrap_or_else(|| "UTC".to_owned());
    if !crate::domain::timezone::is_valid_identifier(&timezone) {
        return Err(validation::validation(
            "timezone",
            "must be a valid IANA TZ identifier",
        ));
    }
    if let Some(url) = &input.webhook_url {
        let url = url::Url::parse(url)
            .map_err(|_| validation::validation("webhook_url", "must be an absolute HTTPS URL"))?;
        crate::infrastructure::providers::webhook::validate_url(state.settings.environment, &url)
            .map_err(|_| {
            validation::validation("webhook_url", "must use HTTPS and a permitted public host")
        })?;
    }
    if let Some(password) = &input.silicon_token {
        validate_password(password)?;
    }
    let key = IdempotencyKey::from_headers(&headers)?;
    let serialized = serde_json::to_vec(&input).map_err(|_| internal())?;
    let mut tx = serializable(state.db(), "silicon_signup_transaction").await?;
    let record = match idempotency::begin::<Value>(
        &mut tx,
        &state.crypto,
        &key,
        input.silicon_id.as_bytes(),
        "POST /api/v1/silicon-signup/requests",
        idempotency::digest_parts(b"silicon-signup", &[&serialized]),
        true,
    )
    .await?
    {
        Claim::Replay { status, response } => {
            tx.commit().await.map_err(|_| internal())?;
            return idempotent_no_store_json(Outcome {
                status,
                value: response,
                replayed: true,
            });
        }
        Claim::Acquired { record_id } => record_id,
    };
    let policy = RateLimitPolicy::new(
        std::num::NonZeroU32::new(5).ok_or_else(internal)?,
        std::time::Duration::from_hours(1),
        std::time::Duration::from_hours(1),
    )
    .map_err(|_| internal())?;
    rate_limit::enforce(
        state.db(),
        &state.crypto,
        "silicon_signup_email",
        &SecretString::from(email.normalized.clone()),
        policy,
    )
    .await?;
    let request_id = Id::now_v7();
    let poll = state
        .crypto
        .generate_secret(SecretKind::SiliconSignupPoll)
        .map_err(|_| internal())?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::SiliconSignupPoll, &poll)
        .map_err(|_| internal())?;
    let generated = input.silicon_token.is_none();
    let password = if let Some(value) = input.silicon_token {
        SecretString::from(value)
    } else {
        let random = state
            .crypto
            .generate_secret(SecretKind::SiliconSignupPoll)
            .map_err(|_| internal())?;
        SecretString::from(random.expose_secret()[4..28].to_owned())
    };
    let salt = state
        .crypto
        .generate_secret(SecretKind::SiliconSignupPoll)
        .map_err(|_| internal())?;
    let hash = hash_password(password.clone(), salt).await?;
    let encrypted = state
        .crypto
        .encrypt(
            EncryptionContext::global(ProtectedField::SiliconCustodianEmail, request_id),
            email.presentation.expose_secret().as_bytes(),
        )
        .map_err(|_| internal())?;
    let indexes = contacts::blind_indexes(&state.crypto, &email)?
        .into_iter()
        .map(|d| format!("{}:{}", d.key_version(), hex::encode(d.as_bytes())))
        .collect::<Vec<_>>();
    let webhook_secret = if input.webhook_url.is_some() {
        Some(
            state
                .crypto
                .generate_secret(SecretKind::SiliconWebhookSigningSecret)
                .map_err(|_| internal())?,
        )
    } else {
        None
    };
    let webhook = if let Some(url) = input.webhook_url {
        Some(state.crypto.encrypt(EncryptionContext::global(ProtectedField::SiliconSignupWebhook,request_id),&serde_json::to_vec(&json!({"url":url,"signing_secret":webhook_secret.as_ref().map(secrecy::ExposeSecret::expose_secret)})).map_err(|_|internal())?).map_err(|_|internal())?)
    } else {
        None
    };
    let expires=sqlx::query_scalar::<_,time::OffsetDateTime>("SELECT iam_private.create_silicon_signup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)")
 .bind(request_id).bind(&input.silicon_id).bind(&name).bind(&timezone).bind(hash).bind(encrypted.ciphertext).bind(encrypted.nonce.to_vec()).bind(encrypted.key_version).bind(indexes).bind(digest.as_bytes().to_vec()).bind(digest.key_version()).bind(webhook.as_ref().map(|e|e.ciphertext.clone())).bind(webhook.as_ref().map(|e|e.nonce.to_vec())).bind(webhook.as_ref().map(|e|e.key_version)).bind(Id::now_v7()).fetch_one(&mut *tx).await.map_err(|e|database_conflict(&e,"silicon_id_unavailable"))?;
    let mut response = json!({"request_id":request_id,"silicon_id":input.silicon_id,"status":"pending","poll_token":poll.expose_secret(),"expires_at":expires.format(&time::format_description::well_known::Rfc3339).map_err(|_|internal())?});
    if generated {
        response["generated_silicon_token"] = json!(password.expose_secret());
    }
    if let Some(secret) = webhook_secret {
        response["webhook_signing_secret"] = json!(secret.expose_secret());
    }
    super::events::record(
        &mut tx,
        super::events::SecurityMutation {
            authentication_event: "silicon.signup.requested",
            authentication_outcome: "success",
            audit_action: "silicon.signup.requested",
            audit_result: "success",
            outbox_event: "silicon.signup.requested.v1",
            subject_id: None,
            actor_id: None,
            authentication_session_id: None,
            application_id: None,
            aggregate_type: "silicon_signup",
            aggregate_id: request_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({"silicon_id":input.silicon_id,"status":"pending"}),
        },
    )
    .await?;
    idempotency::complete(&mut tx, &state.crypto, record, 201, &response, true).await?;
    tx.commit()
        .await
        .map_err(|e| database_conflict(&e, "silicon_signup_conflict"))?;
    idempotent_no_store_json(Outcome {
        status: 201,
        value: response,
        replayed: false,
    })
}

pub(super) async fn status(
    State(state): State<ApiState>,
    Path(id): Path<Id>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let token = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|s| s.starts_with("ssp_") && s.len() == 47)
        .ok_or(AppError::Unauthenticated)?;
    let digests = state
        .crypto
        .digest_secrets(
            DigestPurpose::SiliconSignupPoll,
            &SecretString::from(token.to_owned()),
        )
        .map_err(|_| internal())?;
    let mut tx = context::begin(state.db(), DatabaseContext::anonymous())
        .await
        .map_err(|_| internal())?;
    let value = sqlx::query_scalar::<_, Option<Value>>(
        "SELECT iam_private.silicon_signup_status($1,$2,$3,false)",
    )
    .bind(id)
    .bind(
        digests
            .iter()
            .map(SecretDigest::key_version)
            .collect::<Vec<_>>(),
    )
    .bind(
        digests
            .iter()
            .map(|d| d.as_bytes().to_vec())
            .collect::<Vec<_>>(),
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| internal())?
    .ok_or(AppError::NotFound)?;
    tx.commit().await.map_err(|_| internal())?;
    idempotent_no_store_json(Outcome {
        status: 200,
        value,
        replayed: false,
    })
}
fn custodian(actor: &Authenticated) -> Result<Id, AppError> {
    if actor.0.subject.actor_type != ActorType::Carbon
        || actor.0.audience != "silicon-iam"
        || actor.0.client_application_id.is_some()
    {
        return Err(AppError::Forbidden);
    }
    Ok(actor.0.subject.id)
}
pub(super) async fn review(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(id): Path<Id>,
) -> Result<Response, AppError> {
    let mut tx = context::begin(state.db(), DatabaseContext::principal(custodian(&actor)?))
        .await
        .map_err(|_| internal())?;
    let value = sqlx::query_scalar::<_, Option<Value>>(
        "SELECT iam_private.silicon_signup_status($1,'{}','{}',true)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| internal())?
    .ok_or(AppError::NotFound)?;
    tx.commit().await.map_err(|_| internal())?;
    idempotent_no_store_json(Outcome {
        status: 200,
        value,
        replayed: false,
    })
}
pub(super) async fn decide(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(id): Path<Id>,
    headers: HeaderMap,
    Json(input): Json<Decision>,
) -> Result<Response, AppError> {
    let principal = custodian(&actor)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(principal))
        .await
        .map_err(|_| internal())?;
    let body = serde_json::to_vec(&input).map_err(|_| internal())?;
    let record = match idempotency::begin::<Value>(
        &mut tx,
        &state.crypto,
        &key,
        principal.to_string().as_bytes(),
        "POST /api/v1/silicon-signup/requests/{request_id}/custodian",
        idempotency::digest_parts(
            b"silicon-custody-decision",
            &[id.to_string().as_bytes(), &body],
        ),
        false,
    )
    .await?
    {
        Claim::Replay { status, response } => {
            tx.commit().await.map_err(|_| internal())?;
            return idempotent_no_store_json(Outcome {
                status,
                value: response,
                replayed: true,
            });
        }
        Claim::Acquired { record_id } => record_id,
    };
    let value =
        sqlx::query_scalar::<_, Value>("SELECT iam_private.decide_silicon_signup($1,$2,$3,$4)")
            .bind(id)
            .bind(input.approve)
            .bind(input.can_create_organizations)
            .bind(Id::now_v7())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                if e.as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .is_some_and(|code| code == "42501")
                {
                    AppError::Forbidden
                } else {
                    database_conflict(&e, "silicon_custody_request_inactive")
                }
            })?;
    super::events::record(&mut tx, super::events::SecurityMutation {
        authentication_event: "silicon.custody.decided", authentication_outcome: "success", audit_action: "silicon.custody.decided", audit_result: "success", outbox_event: "silicon.custody.decided.v1",
        subject_id: Some(principal), actor_id: Some(principal), authentication_session_id: Some(actor.0.authentication_session_id), application_id: None,
        aggregate_type: "silicon_signup", aggregate_id: id, aggregate_version: 2, failure_code: None,
        metadata: json!({"silicon_id":value["silicon_id"],"approved":input.approve,"can_create_organizations":input.can_create_organizations}),
    }).await?;
    idempotency::complete(&mut tx, &state.crypto, record, 200, &value, false).await?;
    tx.commit().await.map_err(|_| internal())?;
    idempotent_no_store_json(Outcome {
        status: 200,
        value,
        replayed: false,
    })
}

pub(crate) async fn profile(state: ApiState, actor: Authenticated) -> Result<Response, AppError> {
    if actor.0.subject.actor_type != ActorType::Silicon
        || actor.0.client_application_id.is_some()
        || actor.0.audience != "silicon-iam"
    {
        return Err(AppError::Forbidden);
    }
    let mut tx = context::begin(state.db(), DatabaseContext::principal(actor.0.subject.id))
        .await
        .map_err(|_| internal())?;
    let mut value =
        sqlx::query_scalar::<_, Option<Value>>("SELECT iam_private.silicon_identity_profile()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| internal())?
            .ok_or(AppError::NotFound)?;
    profile_photo_default(&state, &mut value)?;
    tx.commit().await.map_err(|_| internal())?;
    let version = value["version"].as_i64().ok_or_else(internal)?;
    crate::api::me::json_with_etag(axum::http::StatusCode::OK, &value, version)
}

pub(crate) fn profile_photo_default(state: &ApiState, value: &mut Value) -> Result<(), AppError> {
    if value["profile_photo"].is_null() {
        let mut url = state
            .settings
            .providers
            .iris_base_url
            .join("pfp/silicon")
            .map_err(|_| internal())?;
        url.query_pairs_mut()
            .append_pair("id", value["silicon_id"].as_str().ok_or_else(internal)?)
            .append_pair("level", "1");
        value["profile_photo"] = json!(url);
    }
    Ok(())
}

pub(super) fn validate_password(value: &str) -> Result<(), AppError> {
    if !(12..=24).contains(&value.chars().count()) || value.chars().any(char::is_control) {
        return Err(validation::validation(
            "silicon_token",
            "must contain 12 to 24 case-sensitive characters without control characters",
        ));
    }
    Ok(())
}
static PASSWORD_WORK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
async fn hash_password(password: SecretString, salt: SecretString) -> Result<String, AppError> {
    let permit = PASSWORD_WORK.acquire().await.map_err(|_| internal())?;
    let hash = tokio::task::spawn_blocking(move || {
        let salt = SaltString::encode_b64(&salt.expose_secret().as_bytes()[4..28])
            .map_err(|_| internal())?;
        Argon2::default()
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|_| internal())
    })
    .await
    .map_err(|_| internal())?;
    drop(permit);
    hash
}
pub(super) async fn verify_password(
    password: SecretString,
    hash: String,
) -> Result<bool, AppError> {
    let permit = PASSWORD_WORK.acquire().await.map_err(|_| internal())?;
    let result = tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&hash).map_err(|_| internal())?;
        Ok(Argon2::default()
            .verify_password(password.expose_secret().as_bytes(), &parsed)
            .is_ok())
    })
    .await
    .map_err(|_| internal())?;
    drop(permit);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn passwords_are_case_sensitive_and_argon2id() -> Result<(), AppError> {
        assert!(validate_password("CaseSensitive!12").is_ok());
        assert!(validate_password("short").is_err());
        assert!(validate_password(&"a".repeat(25)).is_err());
        let hash = hash_password(
            SecretString::from("CaseSensitive!12"),
            SecretString::from("ssp_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG"),
        )
        .await?;
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(SecretString::from("CaseSensitive!12"), hash.clone()).await?);
        assert!(!verify_password(SecretString::from("casesensitive!12"), hash).await?);
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodySettings {
    can_create_organizations: bool,
}
pub(super) async fn list_custodies(
    State(state): State<ApiState>,
    actor: Authenticated,
) -> Result<Response, AppError> {
    let mut tx = context::begin(state.db(), DatabaseContext::principal(custodian(&actor)?))
        .await
        .map_err(|_| internal())?;
    let value = sqlx::query_scalar::<_, Value>("SELECT iam_private.list_silicon_custodies()")
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| internal())?;
    tx.commit().await.map_err(|_| internal())?;
    idempotent_no_store_json(Outcome {
        status: 200,
        value,
        replayed: false,
    })
}
pub(super) async fn update_custody(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CustodySettings>,
) -> Result<Response, AppError> {
    silicon::validate_global_id(&id)?;
    let principal = custodian(&actor)?;
    let expected = crate::api::me::expected_version(&headers)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(principal))
        .await
        .map_err(|_| internal())?;
    let body = serde_json::to_vec(&(expected, &input)).map_err(|_| internal())?;
    let record = match idempotency::begin::<Value>(
        &mut tx,
        &state.crypto,
        &key,
        principal.to_string().as_bytes(),
        "PATCH /api/v1/me/silicon-custodies/{silicon_id}",
        idempotency::digest_parts(b"silicon-custody-settings", &[id.as_bytes(), &body]),
        false,
    )
    .await?
    {
        Claim::Replay { status, response } => {
            tx.commit().await.map_err(|_| internal())?;
            return idempotent_no_store_json(Outcome {
                status,
                value: response,
                replayed: true,
            });
        }
        Claim::Acquired { record_id } => record_id,
    };
    let value = sqlx::query_scalar::<_, Option<Value>>(
        "SELECT iam_private.update_silicon_custody($1,$2,$3)",
    )
    .bind(&id)
    .bind(expected)
    .bind(input.can_create_organizations)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| internal())?
    .ok_or(AppError::PreconditionFailed {
        code: "custody_setting_unavailable_or_stale".into(),
    })?;
    super::events::record(&mut tx, super::events::SecurityMutation {
        authentication_event: "silicon.custody.updated", authentication_outcome: "success", audit_action: "silicon.custody.updated", audit_result: "success", outbox_event: "silicon.custody.updated.v1",
        subject_id: Some(principal), actor_id: Some(principal), authentication_session_id: Some(actor.0.authentication_session_id), application_id: None,
        aggregate_type: "silicon_custody", aggregate_id: Id::identity(&id).map_err(|_|internal())?, aggregate_version: expected+1, failure_code: None,
        metadata: json!({"silicon_id":id,"can_create_organizations":input.can_create_organizations}),
    }).await?;
    idempotency::complete(&mut tx, &state.crypto, record, 200, &value, false).await?;
    tx.commit().await.map_err(|_| internal())?;
    idempotent_no_store_json(Outcome {
        status: 200,
        value,
        replayed: false,
    })
}
