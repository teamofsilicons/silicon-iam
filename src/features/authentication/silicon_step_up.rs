//! Fresh STK proof for a single protected Silicon action.
use super::{
    http::idempotent_no_store_json,
    idempotency::{self, Claim, IdempotencyKey, Outcome},
    model::{StepUpAction, StepUpTokenResponse},
    silicon,
};
use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{actor::ActorType, id::Id},
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, SecretKind},
        postgres::context::{self, DatabaseContext},
    },
};
use axum::{Json, extract::State, http::HeaderMap, response::Response};
use secrecy::ExposeSecret as _;
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    silicon_token: String,
    action: StepUpAction,
    resource_id: Id,
}
fn internal() -> AppError {
    AppError::Internal {
        category: "silicon_step_up",
    }
}
pub(super) async fn create(
    State(state): State<ApiState>,
    actor: Authenticated,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> Result<Response, AppError> {
    if actor.0.subject.actor_type != ActorType::Silicon
        || actor.0.client_application_id.is_some()
        || actor.0.audience != "silicon-iam"
    {
        return Err(AppError::Forbidden);
    }
    let action = input.action.database_value();
    if (action.starts_with("account.")
        && !matches!(
            action,
            "account.session_revoke" | "account.sessions_revoke_all"
        ))
        || action.starts_with("platform_admin.")
    {
        return Err(AppError::Forbidden);
    }
    let credential = silicon::validate_credential(input.silicon_token)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let principal = actor.0.subject.id;
    let mut tx = context::begin(state.db(), DatabaseContext::principal(principal))
        .await
        .map_err(|_| internal())?;
    let digest = idempotency::digest_parts(
        b"silicon-action-proof",
        &[
            principal.as_bytes(),
            actor.0.authentication_session_id.as_bytes(),
            action.as_bytes(),
            input.resource_id.as_bytes(),
            credential.expose_secret().as_bytes(),
        ],
    );
    let lease = match idempotency::begin::<StepUpTokenResponse>(
        &mut tx,
        &state.crypto,
        &key,
        principal.as_bytes(),
        "POST /api/v1/silicon-auth/step-up",
        digest,
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
    silicon::enforce_limit(&state, &principal.to_string(), &credential).await?;
    let verified =
        silicon::verify_credentials(&mut tx, &state, &principal.to_string(), &credential).await?;
    if verified.principal_id != principal {
        return Err(AppError::Forbidden);
    }
    let token = state
        .crypto
        .generate_secret(SecretKind::StepUpAssertion)
        .map_err(|_| internal())?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::StepUpAssertion, &token)
        .map_err(|_| internal())?;
    let issued = sqlx::query_scalar::<_, bool>(
        "SELECT iam_private.issue_silicon_step_up($1,$2,$3,$4,$5,$6)",
    )
    .bind(Id::now_v7())
    .bind(actor.0.authentication_session_id)
    .bind(action)
    .bind(input.resource_id.to_string())
    .bind(digest.as_bytes().to_vec())
    .bind(digest.key_version())
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| internal())?;
    if !issued {
        return Err(AppError::Unauthenticated);
    }
    let value = StepUpTokenResponse {
        step_up_token: token.expose_secret().to_owned(),
        action: input.action,
        assurance: "silicon_credential".into(),
        expires_in: 300,
    };
    idempotency::complete(&mut tx, &state.crypto, lease, 200, &value, true).await?;
    tx.commit().await.map_err(|_| internal())?;
    idempotent_no_store_json(Outcome {
        status: 200,
        value,
        replayed: false,
    })
}
