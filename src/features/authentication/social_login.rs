//! A provider subject authenticates only its bound Carbon. Linking requires an
//! independent, fresh IAM login for the exact account; an email match is no login.
use super::super::{
    events::{self, SecurityMutation},
    model::{TokenResponse, ValidatedContact, ValidatedLoginIdentifier},
    tokens,
};
use super::*;
use crate::{
    api::authentication::Authenticated,
    domain::actor::ActorType,
    infrastructure::postgres::context::{self, DatabaseContext},
};
use sqlx::{Postgres, Transaction};

#[derive(FromRow)]
struct BoundIdentity {
    principal_id: Id,
    auth_epoch: i64,
}
pub(super) struct LoginTarget {
    pub(super) principal_id: Id,
    pub(super) auth_epoch: i64,
    pub(super) linked: bool,
}
pub(super) async fn resolve_target(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    provider: &str,
    digests: &Value,
    email: &ValidatedContact,
) -> Result<Option<LoginTarget>, AppError> {
    let bindings = sqlx::query_as::<_, BoundIdentity>(
        "SELECT * FROM iam_private.social_login_identity($1,$2)",
    )
    .bind(provider)
    .bind(digests)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| internal("social_login_subject_read"))?;
    if bindings.len() > 1 {
        return Err(AppError::Unauthenticated);
    }
    if let Some(binding) = bindings.into_iter().next() {
        return Ok(Some(LoginTarget {
            principal_id: binding.principal_id,
            auth_epoch: binding.auth_epoch,
            linked: true,
        }));
    }
    // A suspended binding must not be redirected into a different account by email.
    for digest in digests
        .as_array()
        .ok_or_else(|| internal("social_subject_shape"))?
    {
        let registered = sqlx::query_scalar::<_, bool>(
            "SELECT iam_private.social_identity_registered($1,$2,$3)",
        )
        .bind(provider)
        .bind(
            i16::try_from(
                digest["key_version"]
                    .as_i64()
                    .ok_or_else(|| internal("social_subject_shape"))?,
            )
            .map_err(|_| internal("social_subject_shape"))?,
        )
        .bind(
            hex::decode(
                digest["digest"]
                    .as_str()
                    .ok_or_else(|| internal("social_subject_shape"))?,
            )
            .map_err(|_| internal("social_subject_shape"))?,
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| internal("social_subject_read"))?;
        if registered {
            return Err(AppError::Unauthenticated);
        }
    }
    let identifier = ValidatedLoginIdentifier::Contact(validation::email(
        email.presentation.expose_secret().to_owned(),
    )?);
    let Some(carbon) = contacts::resolve_login_identifier(tx, &state.crypto, &identifier).await?
    else {
        return Ok(None);
    };
    let epoch = sqlx::query_scalar::<_, i64>("SELECT auth_epoch FROM iam.principals WHERE id=$1 AND kind='carbon' AND status='active' FOR SHARE")
        .bind(carbon.principal_id).fetch_optional(&mut **tx).await.map_err(|_| internal("social_link_target_read"))?.ok_or(AppError::Unauthenticated)?;
    Ok(Some(LoginTarget {
        principal_id: carbon.principal_id,
        auth_epoch: epoch,
        linked: false,
    }))
}

#[derive(FromRow)]
struct LoginProof {
    status: String,
    active: bool,
    login_principal_id: Option<Id>,
    login_auth_epoch: Option<i64>,
    subject_digests: Option<Value>,
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
    if input.poll_token.is_empty() || input.poll_token.len() > 256 {
        return Err(AppError::Unauthenticated);
    }
    let secret = SecretString::from(input.poll_token.clone());
    http::enforce_limit(
        state,
        "social_login_complete",
        &secret,
        15,
        std::time::Duration::from_secs(60),
    )
    .await?;
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::SocialSignupPoll, &secret)
        .map_err(|_| internal("social_poll_digest"))?;
    for digest in digests {
        let row = sqlx::query_as::<_, LoginProof>("SELECT status,expires_at>transaction_timestamp() AS active,login_principal_id,login_auth_epoch,subject_digests,candidate_id,email_ciphertext,email_nonce,email_key_version FROM iam.social_signup_requests WHERE id=$1 AND provider=$2 AND intent='login' AND poll_key_version=$3 AND poll_digest=$4 FOR UPDATE")
            .bind(input.request_id).bind(provider).bind(digest.key_version()).bind(digest.as_bytes().as_slice())
            .fetch_optional(&mut **tx).await.map_err(|_| internal("social_login_proof_read"))?;
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
    let mut tx = serializable(state.db(), "social_login_complete_begin").await?;
    let row = proof(&mut tx, &state, &provider, &input).await?;
    let principal_id = row.login_principal_id.ok_or(AppError::Unauthenticated)?;
    let current = sqlx::query_as::<_, BoundIdentity>(
        "SELECT * FROM iam_private.social_login_identity($1,$2)",
    )
    .bind(&provider)
    .bind(
        row.subject_digests
            .as_ref()
            .ok_or(AppError::Unauthenticated)?,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| internal("social_login_binding_read"))?;
    if current.len() != 1
        || current[0].principal_id != principal_id
        || Some(current[0].auth_epoch) != row.login_auth_epoch
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
        &key,
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
                .map_err(|_| internal("social_login_replay_commit"))?;
            return http::login_success_response(&state, status, response, true);
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
        .bind(input.request_id).execute(&mut *tx).await.map_err(|_| internal("social_login_consume"))?;
    idempotency::complete(&mut tx, &state.crypto, record, 200, &response, true).await?;
    tx.commit()
        .await
        .map_err(|_| internal("social_login_complete_commit"))?;
    http::login_success_response(&state, 200, response, false)
}

pub(super) async fn link(
    State(state): State<ApiState>,
    Authenticated(access): Authenticated,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Json(input): Json<StatusInput>,
) -> Result<Response, AppError> {
    configured(&state, &provider)?;
    if access.subject.actor_type != ActorType::Carbon
        || access.client_application_id.is_some()
        || access.audience_application_id.is_some()
    {
        return Err(AppError::Unauthenticated);
    }
    let key = IdempotencyKey::from_headers(&headers)?;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(access.subject.id))
        .await
        .map_err(|_| internal("social_link_begin"))?;
    let row = proof(&mut tx, &state, &provider, &input).await?;
    if row.login_principal_id != Some(access.subject.id) {
        return Err(AppError::Unauthenticated);
    }
    let email = contacts::decrypt_contact(
        &state.crypto,
        ContactChannel::Email,
        row.candidate_id.ok_or(AppError::Unauthenticated)?,
        row.email_key_version.ok_or(AppError::Unauthenticated)?,
        row.email_nonce.ok_or(AppError::Unauthenticated)?,
        row.email_ciphertext.ok_or(AppError::Unauthenticated)?,
    )?;
    let identity =
        ValidatedLoginIdentifier::Contact(validation::email(email.expose_secret().to_owned())?);
    let current = contacts::resolve_login_identifier(&mut tx, &state.crypto, &identity)
        .await?
        .ok_or(AppError::Unauthenticated)?;
    if current.principal_id != access.subject.id {
        return Err(AppError::Unauthenticated);
    }
    let digest = idempotency::digest_parts(
        b"social-login-link",
        &[
            provider.as_bytes(),
            input.request_id.to_string().as_bytes(),
            access.authentication_session_id.to_string().as_bytes(),
        ],
    );
    let record = match idempotency::begin::<Value>(
        &mut tx,
        &state.crypto,
        &key,
        access.subject.id.to_string().as_bytes(),
        "POST /api/v1/login/social/{provider}/link",
        digest,
        false,
    )
    .await?
    {
        Claim::Replay { status, response } => {
            tx.commit()
                .await
                .map_err(|_| internal("social_link_replay_commit"))?;
            return http::idempotent_no_store_json(Outcome::replay(status, response));
        }
        Claim::Acquired { record_id } => record_id,
    };
    if row.status != "link_required" {
        return Err(AppError::Unauthenticated);
    }
    let linked =
        sqlx::query_scalar::<_, bool>("SELECT iam_private.bind_social_login_identity($1,$2,$3)")
            .bind(input.request_id)
            .bind(access.subject.id)
            .bind(access.authentication_session_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| internal("social_link_write"))?;
    if !linked {
        return Err(AppError::Unauthenticated);
    }
    events::record(
        &mut tx,
        SecurityMutation {
            authentication_event: "social_identity.linked",
            authentication_outcome: "success",
            audit_action: "social_identity.link",
            audit_result: "success",
            outbox_event: "social_identity.linked",
            subject_id: Some(access.subject.id),
            actor_id: Some(access.subject.id),
            authentication_session_id: Some(access.authentication_session_id),
            application_id: None,
            aggregate_type: "social_login",
            aggregate_id: input.request_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({"provider":provider}),
        },
    )
    .await?;
    let result = json!({"linked":true,"provider":provider});
    idempotency::complete(&mut tx, &state.crypto, record, 200, &result, false).await?;
    tx.commit()
        .await
        .map_err(|_| internal("social_link_commit"))?;
    http::idempotent_no_store_json(Outcome::fresh(200, result))
}
