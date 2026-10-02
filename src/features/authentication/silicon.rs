use std::{num::NonZeroU32, time::Duration};

use crate::domain::id::Id;
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use sqlx::FromRow;

use crate::{
    api::ApiState,
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, SecretDigest},
        postgres::rate_limit::{self, RateLimitPolicy},
    },
};

use super::{
    database::{database_conflict, serializable},
    idempotency::{self, Claim, IdempotencyKey},
    model::TokenResponse,
    tokens::{self, SiliconLoginIdentity},
    validation,
};

const ROUTE: &str = "POST /api/v1/silicon-auth/token";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SiliconAuthenticationInput {
    silicon_id: String,
    silicon_token: String,
}

#[derive(FromRow)]
struct CredentialRow {
    principal_id: Id,
    credential_id: Id,
    secret_digest: Vec<u8>,
    pepper_key_version: i16,
    principal_auth_epoch: i64,
    global_silicon_id: String,
}

pub(super) async fn authenticate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: Result<Json<SiliconAuthenticationInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let input = payload
        .map(|Json(value)| value)
        .map_err(|_| validation::validation("body", "must match the documented JSON schema"))?;
    validate_global_id(&input.silicon_id)?;
    let credential = validate_credential(input.silicon_token)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let request_digest = silicon_login_request_digest(&input.silicon_id, &credential);
    let mut transaction = serializable(state.db(), "silicon_login_transaction").await?;
    let record_id = match idempotency::begin::<TokenResponse>(
        &mut transaction,
        &state.crypto,
        &key,
        input.silicon_id.as_bytes(),
        ROUTE,
        request_digest,
        true,
    )
    .await?
    {
        Claim::Replay { status, response } => {
            transaction
                .commit()
                .await
                .map_err(|error| database_conflict(&error, "silicon_login_conflict"))?;
            return no_store(&state, status, response, true);
        }
        Claim::Acquired { record_id } => record_id,
    };
    enforce_limit(&state, &input.silicon_id, &credential).await?;
    let identity =
        verify_credentials(&mut transaction, &state, &input.silicon_id, &credential).await?;
    let response = tokens::issue_silicon_session(
        &mut transaction,
        &state.crypto,
        &state.settings.security,
        identity,
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        StatusCode::OK.as_u16(),
        &response,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "silicon_login_conflict"))?;
    no_store(&state, StatusCode::OK.as_u16(), response, false)
}

pub(super) async fn verify_credentials(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &ApiState,
    silicon_id: &str,
    credential: &SecretString,
) -> Result<SiliconLoginIdentity, AppError> {
    Ok(
        if credential.expose_secret().starts_with("stk-") && credential.expose_secret().len() == 36
        {
            let row = resolve_credential(transaction, state, silicon_id, credential)
                .await?
                .ok_or(AppError::Unauthenticated)?;
            let expected = SecretDigest::from_parts(row.pepper_key_version, &row.secret_digest)
                .ok_or(AppError::Internal {
                    category: "silicon_credential_digest_shape",
                })?;
            let valid = state
                .crypto
                .verify_secret(DigestPurpose::SiliconCredential, credential, expected)
                .map_err(|_| AppError::Internal {
                    category: "silicon_credential_verify",
                })?;
            if !valid {
                return Err(AppError::Unauthenticated);
            }
            SiliconLoginIdentity {
                principal_id: row.principal_id,
                credential_id: Some(row.credential_id),
                principal_auth_epoch: row.principal_auth_epoch,
                organization_id: None,
                membership_id: None,
                membership_authz_epoch: None,
                global_silicon_id: row.global_silicon_id,
            }
        } else {
            let row = sqlx::query_as::<_, (Id, String, i64)>(
                "SELECT * FROM iam_private.resolve_silicon_password($1)",
            )
            .bind(silicon_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| AppError::Internal {
                category: "silicon_password_lookup",
            })?
            .ok_or(AppError::Unauthenticated)?;
            if !super::silicon_signup::verify_password(credential.clone(), row.1).await? {
                return Err(AppError::Unauthenticated);
            }
            SiliconLoginIdentity {
                principal_id: row.0,
                credential_id: None,
                principal_auth_epoch: row.2,
                organization_id: None,
                membership_id: None,
                membership_authz_epoch: None,
                global_silicon_id: silicon_id.to_owned(),
            }
        },
    )
}

async fn resolve_credential(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &ApiState,
    silicon_id: &str,
    credential: &SecretString,
) -> Result<Option<CredentialRow>, AppError> {
    let candidates = state
        .crypto
        .digest_secrets(DigestPurpose::SiliconCredential, credential)
        .map_err(|_| AppError::Internal {
            category: "silicon_credential_digest",
        })?;
    let versions = candidates
        .iter()
        .map(SecretDigest::key_version)
        .collect::<Vec<_>>();
    let digests = candidates
        .iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();
    sqlx::query_as::<_, CredentialRow>(
        "SELECT * FROM iam_private.resolve_active_silicon_credential($1, $2, $3)",
    )
    .bind(silicon_id)
    .bind(versions)
    .bind(digests)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "silicon_credential_resolve",
    })
}

pub(super) async fn enforce_limit(
    state: &ApiState,
    silicon_id: &str,
    credential: &SecretString,
) -> Result<(), AppError> {
    let identity_scope = SecretString::from(silicon_id.to_owned());
    let credential_scope =
        SecretString::from(format!("{silicon_id}:{}", credential.expose_secret()));
    let maximum = NonZeroU32::new(10).ok_or(AppError::Internal {
        category: "silicon_login_rate_policy",
    })?;
    let window = Duration::from_mins(10);
    let policy = RateLimitPolicy::new(maximum, window, window).map_err(|_| AppError::Internal {
        category: "silicon_login_rate_policy",
    })?;
    rate_limit::enforce(
        state.db(),
        &state.crypto,
        "silicon_login_identity",
        &identity_scope,
        policy,
    )
    .await?;
    rate_limit::enforce(
        state.db(),
        &state.crypto,
        "silicon_login_credential",
        &credential_scope,
        policy,
    )
    .await?;
    Ok(())
}

pub(super) fn validate_global_id(value: &str) -> Result<(), AppError> {
    let Some(local) = value.strip_prefix("si:") else {
        return Err(validation::validation(
            "silicon_id",
            "has an invalid format",
        ));
    };
    if !valid_handle(local, 50) {
        return Err(validation::validation(
            "silicon_id",
            "has an invalid format",
        ));
    }
    Ok(())
}

fn valid_handle(value: &str, maximum: usize) -> bool {
    (3..=maximum).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

pub(super) fn validate_credential(value: String) -> Result<SecretString, AppError> {
    let legacy = value.len() == 36
        && value.starts_with("stk-")
        && value[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'));
    if !legacy {
        super::silicon_signup::validate_password(&value)?;
    }
    Ok(SecretString::from(value))
}

fn silicon_login_request_digest(silicon_id: &str, credential: &SecretString) -> [u8; 32] {
    idempotency::digest_parts(
        b"silicon-login",
        &[silicon_id.as_bytes(), credential.expose_secret().as_bytes()],
    )
}

fn no_store(
    state: &ApiState,
    status: u16,
    body: TokenResponse,
    replayed: bool,
) -> Result<Response, AppError> {
    let status = StatusCode::from_u16(status).map_err(|_| AppError::Internal {
        category: "silicon_login_replay_status",
    })?;
    let cookie = crate::infrastructure::browser_session::issue(
        body.session_id,
        body.refresh_expires_at,
        &state.settings.security.cookie_key,
    )
    .map_err(|_| AppError::Internal {
        category: "silicon_browser_session",
    })?;
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{silicon_login_request_digest, validate_credential, validate_global_id};

    #[test]
    fn silicon_login_inputs_use_exact_wire_formats() {
        assert!(validate_global_id("si:assistant").is_ok());
        assert!(validate_global_id("Assistant:acme").is_err());
        assert!(validate_global_id("assistant:acme:extra").is_err());
        assert!(validate_credential(format!("stk-{}", "a".repeat(32))).is_ok());
        assert!(validate_credential(format!("stk-{}", "A".repeat(32))).is_err());
        assert!(validate_credential(format!("stk-{}", "a".repeat(64))).is_err());
    }

    #[test]
    fn silicon_login_idempotency_material_is_pepper_version_independent() {
        let credential = SecretString::from(format!("stk-{}", "a".repeat(32)));
        let digest = silicon_login_request_digest("assistant:acme", &credential);
        assert_eq!(
            digest,
            silicon_login_request_digest("assistant:acme", &credential)
        );
        assert_ne!(
            digest,
            silicon_login_request_digest("other:acme", &credential)
        );
    }
}
