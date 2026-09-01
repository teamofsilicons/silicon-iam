#![allow(clippy::too_many_lines)]

use std::{num::NonZeroU32, time::Duration};

use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, header, request::Parts},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::SecretString;
use sqlx::{FromRow, Postgres, Transaction};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    api::ApiState,
    domain::actor::ActorType,
    infrastructure::{
        browser_session::{self, BrowserSessionCookieError},
        crypto::{DigestPurpose, SecretDigest},
        postgres::{
            context::{self, DatabaseContext},
            rate_limit::{self, RateLimitPolicy},
            step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
            tokens::{self, AccessContext, AccessTokenError},
        },
    },
};

use super::{error::ApiError, validation};

#[derive(Clone, Debug)]
pub(super) struct Bearer(pub(super) AccessContext);

#[derive(Clone, Debug)]
pub(super) struct BrowserSession {
    pub(super) session_id: Uuid,
    pub(super) carbon_id: Uuid,
    pub(super) csrf_token: String,
}

#[derive(Debug)]
pub(crate) struct ApplicationClient {
    pub(crate) application_id: Uuid,
    pub(crate) app_id: String,
    pub(crate) organization_id: Uuid,
    pub(crate) auth_epoch: i64,
    pub(crate) authenticated_secret: SecretString,
}

#[derive(FromRow)]
struct ClientSecretRow {
    application_id: Uuid,
    secret_digest: Vec<u8>,
    pepper_key_version: i16,
}

#[derive(FromRow)]
struct BrowserSessionRow {
    session_id: Uuid,
    carbon_id: Uuid,
}

impl FromRequestParts<ApiState> for Bearer {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let credential = bearer_credential(&parts.headers)?;
        enforce_request_rate_limit(
            state,
            "applications_bearer_credential",
            SecretString::from(format!("credential:{credential}:{}", parts.uri.path())),
            240,
        )
        .await?;
        let token = SecretString::from(credential.to_owned());
        match tokens::authenticate(&state.pool, &state.crypto, &token).await {
            Ok(Some(access)) => {
                enforce_request_rate_limit(
                    state,
                    "applications_bearer_request",
                    SecretString::from(format!(
                        "{}:{}:{}",
                        access.subject.actor_type.as_str(),
                        access.subject.id,
                        parts.uri.path()
                    )),
                    120,
                )
                .await?;
                Ok(Self(access))
            }
            Ok(None) | Err(AccessTokenError::InvalidFormat) => Err(ApiError::unauthenticated()),
            Err(AccessTokenError::Crypto(_)) => Err(ApiError::internal("bearer_crypto")),
            Err(AccessTokenError::Database(_)) => Err(ApiError::internal("bearer_database")),
            Err(AccessTokenError::InvalidStoredActorKind) => {
                Err(ApiError::internal("bearer_actor_kind"))
            }
        }
    }
}

impl FromRequestParts<ApiState> for BrowserSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let verified =
            browser_session::verify_headers(&parts.headers, &state.settings.security.cookie_key)
                .map_err(|error| match error {
                    BrowserSessionCookieError::InvalidConfiguration => {
                        ApiError::internal("browser_session_cookie_configuration")
                    }
                    BrowserSessionCookieError::InvalidCookie
                    | BrowserSessionCookieError::Expired => ApiError::unauthenticated(),
                })?;
        enforce_request_rate_limit(
            state,
            "applications_browser_request",
            SecretString::from(format!(
                "browser-session:{}:{}",
                verified.session_id,
                parts.uri.path()
            )),
            60,
        )
        .await?;
        let mut transaction = context::begin(&state.pool, DatabaseContext::principal(Uuid::nil()))
            .await
            .map_err(|_| ApiError::internal("browser_session_context"))?;
        let row = sqlx::query_as::<_, BrowserSessionRow>(
            r"
            SELECT
                session.id AS session_id,
                session.subject_principal_id AS carbon_id
            FROM iam.authentication_sessions AS session
            JOIN iam.principals AS principal
              ON principal.id = session.subject_principal_id
             AND principal.kind = 'carbon'
             AND principal.status = 'active'
             AND principal.auth_epoch = session.subject_auth_epoch
            WHERE session.id = $1
              AND session.subject_kind = 'carbon'
              AND session.status = 'active'
              AND session.idle_expires_at > transaction_timestamp()
              AND session.absolute_expires_at > transaction_timestamp()
            ",
        )
        .bind(verified.session_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("browser_session_read"))?
        .ok_or_else(ApiError::unauthenticated)?;
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("browser_session_commit"))?;
        Ok(Self {
            session_id: row.session_id,
            carbon_id: row.carbon_id,
            csrf_token: verified.csrf_token,
        })
    }
}

impl FromRequestParts<ApiState> for ApplicationClient {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let (app_id, supplied) = basic_credentials(&parts.headers)?;
        validation::app_id(&app_id).map_err(|_| ApiError::invalid_client())?;
        enforce_request_rate_limit(
            state,
            "applications_client_request",
            SecretString::from(format!("application:{app_id}:{}", parts.uri.path())),
            120,
        )
        .await?;
        let candidates = state
            .crypto
            .digest_secrets(DigestPurpose::ApplicationSecret, &supplied)
            .map_err(|_| ApiError::internal("application_secret_digest"))?;
        let versions = candidates
            .iter()
            .map(SecretDigest::key_version)
            .collect::<Vec<_>>();
        let digests = candidates
            .iter()
            .map(|digest| digest.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let mut transaction = context::begin(
            &state.pool,
            DatabaseContext {
                principal_id: None,
                organization_id: None,
                application_id: None,
                signup_session_id: None,
            },
        )
        .await
        .map_err(|_| ApiError::internal("application_client_context"))?;
        let candidate_rows = sqlx::query_as::<_, ClientSecretRow>(
            r"
            WITH supplied_digest (key_version, digest) AS (
                SELECT * FROM unnest($1::smallint[], $2::bytea[])
            )
            SELECT secret.application_id, secret.secret_digest, secret.pepper_key_version
            FROM supplied_digest
            JOIN iam.application_secrets AS secret
              ON secret.pepper_key_version = supplied_digest.key_version
             AND secret.secret_digest = supplied_digest.digest
            JOIN iam.applications AS application ON application.id = secret.application_id
            WHERE application.app_id = $3
              AND (
                  secret.status = 'active'
                  OR (secret.status = 'retiring' AND secret.retires_at > transaction_timestamp())
              )
            FOR UPDATE OF secret
            ",
        )
        .bind(versions)
        .bind(digests)
        .bind(&app_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("application_secret_lookup"))?;

        for candidate in candidate_rows {
            let Some(expected) =
                SecretDigest::from_parts(candidate.pepper_key_version, &candidate.secret_digest)
            else {
                continue;
            };
            if !state
                .crypto
                .verify_secret(DigestPurpose::ApplicationSecret, &supplied, expected)
                .map_err(|_| ApiError::internal("application_secret_verify"))?
            {
                continue;
            }
            sqlx::query(
                r"
                SELECT set_config('iam.principal_id', $1, true),
                       set_config('iam.application_id', $1, true)
                ",
            )
            .bind(candidate.application_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("application_client_rls_context"))?;
            let resolved = sqlx::query_as::<_, (Uuid, String, Uuid, i64)>(
                r"
                SELECT application.id, application.app_id,
                       application.organization_id, principal.auth_epoch
                FROM iam.applications AS application
                JOIN iam.principals AS principal
                  ON principal.id = application.id
                 AND principal.kind = 'application'
                 AND principal.status = 'active'
                JOIN iam.application_secrets AS secret
                  ON secret.application_id = application.id
                 AND secret.pepper_key_version = $3
                 AND secret.secret_digest = $4
                WHERE application.id = $1
                  AND application.app_id = $2
                  AND application.review_status = 'verified'
                  AND application.deleted_at IS NULL
                  AND (
                      secret.status = 'active'
                      OR (
                          secret.status = 'retiring'
                          AND secret.retires_at > transaction_timestamp()
                      )
                  )
                FOR UPDATE OF application, principal, secret
                ",
            )
            .bind(candidate.application_id)
            .bind(&app_id)
            .bind(candidate.pepper_key_version)
            .bind(&candidate.secret_digest)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("application_client_read"))?;
            let Some((application_id, app_id, organization_id, auth_epoch)) = resolved else {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| ApiError::internal("application_client_rollback"))?;
                return Err(ApiError::invalid_client());
            };
            sqlx::query(
                r"
                UPDATE iam.application_secrets
                SET last_used_at = transaction_timestamp()
                WHERE application_id = $1
                  AND pepper_key_version = $2
                  AND secret_digest = $3
                ",
            )
            .bind(application_id)
            .bind(candidate.pepper_key_version)
            .bind(candidate.secret_digest)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("application_secret_touch"))?;
            transaction
                .commit()
                .await
                .map_err(|_| ApiError::internal("application_client_commit"))?;
            return Ok(Self {
                application_id,
                app_id,
                organization_id,
                auth_epoch,
                authenticated_secret: supplied,
            });
        }
        transaction
            .rollback()
            .await
            .map_err(|_| ApiError::internal("application_client_reject_rollback"))?;
        Err(ApiError::invalid_client())
    }
}

async fn enforce_request_rate_limit(
    state: &ApiState,
    name: &'static str,
    scope: SecretString,
    maximum: u32,
) -> Result<(), ApiError> {
    let maximum = NonZeroU32::new(maximum)
        .ok_or_else(|| ApiError::internal("application_rate_limit_policy"))?;
    let policy = RateLimitPolicy::new(maximum, Duration::from_secs(60), Duration::from_secs(60))
        .map_err(|_| ApiError::internal("application_rate_limit_policy"))?;
    match rate_limit::enforce(&state.pool, &state.crypto, name, &scope, policy).await {
        Ok(_) => Ok(()),
        Err(crate::error::AppError::RateLimited {
            limit,
            remaining,
            reset_after_seconds,
            retry_after_seconds,
        }) => Err(ApiError::rate_limited(
            limit,
            remaining,
            reset_after_seconds,
            retry_after_seconds,
        )),
        Err(_) => Err(ApiError::internal("application_rate_limit")),
    }
}

pub(super) fn require_carbon(access: &AccessContext) -> Result<Uuid, ApiError> {
    if access.subject.actor_type != ActorType::Carbon
        || access.audience != "silicon-iam"
        || access.client_application_id.is_some()
        || access.organization_id.is_some()
        || access.membership_id.is_some()
        || !access.scopes.iter().any(|scope| scope == "iam.self")
    {
        return Err(ApiError::forbidden("forbidden"));
    }
    Ok(access.subject.id)
}

pub(super) fn require_csrf(headers: &HeaderMap, session: &BrowserSession) -> Result<(), ApiError> {
    let supplied = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::precondition_required("X-CSRF-Token"))?;
    if bool::from(supplied.as_bytes().ct_eq(session.csrf_token.as_bytes())) {
        Ok(())
    } else {
        Err(ApiError::forbidden("csrf_failed"))
    }
}

pub(super) async fn require_step_up(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &crate::infrastructure::crypto::CryptoService,
    headers: &HeaderMap,
    access: &AccessContext,
    action: &'static str,
    resource_id: Uuid,
    assurance: RequiredAssurance,
) -> Result<(), ApiError> {
    let raw = headers
        .get("x-step-up-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::precondition_required("X-Step-Up-Token"))?;
    let token = StepUpToken::parse(raw)
        .map_err(|_| ApiError::precondition("step_up_invalid", "The step-up token is invalid."))?;
    step_up::consume(
        transaction,
        crypto,
        &token,
        StepUpExpectation {
            carbon_id: access.subject.id,
            authentication_session_id: access.authentication_session_id,
            action,
            resource_id: Some(resource_id),
            required_assurance: assurance,
        },
    )
    .await
    .map(|_| ())
    .map_err(|_| ApiError::precondition("step_up_invalid", "The step-up token is invalid."))
}

pub(super) async fn require_platform_capability(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    capability: &'static str,
) -> Result<(), ApiError> {
    let allowed =
        sqlx::query_scalar::<_, bool>("SELECT iam_private.has_platform_capability($1, $2)")
            .bind(carbon_id)
            .bind(capability)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("platform_capability_read"))?;
    if allowed {
        Ok(())
    } else {
        Err(ApiError::forbidden("forbidden"))
    }
}

pub(super) fn expected_version(headers: &HeaderMap) -> Result<i64, ApiError> {
    let value = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::precondition_required("If-Match"))?;
    let digits = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(ApiError::precondition_failed)?;
    digits
        .parse::<i64>()
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(ApiError::precondition_failed)
}

fn bearer_credential(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthenticated)?;
    let (scheme, credential) = value
        .split_once(' ')
        .ok_or_else(ApiError::unauthenticated)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || credential.len() != 47
        || credential
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    {
        return Err(ApiError::unauthenticated());
    }
    Ok(credential)
}

fn basic_credentials(headers: &HeaderMap) -> Result<(String, SecretString), ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::invalid_client)?;
    let (scheme, encoded) = value.split_once(' ').ok_or_else(ApiError::invalid_client)?;
    if !scheme.eq_ignore_ascii_case("Basic") || encoded.len() > 4_096 {
        return Err(ApiError::invalid_client());
    }
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| ApiError::invalid_client())?,
    );
    let decoded = std::str::from_utf8(&decoded).map_err(|_| ApiError::invalid_client())?;
    let (username, password) = decoded
        .split_once(':')
        .ok_or_else(ApiError::invalid_client)?;
    if username.is_empty()
        || username.contains(':')
        || password.len() != 47
        || !password.starts_with("ask_")
        || password[4..]
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    {
        return Err(ApiError::invalid_client());
    }
    Ok((username.to_owned(), SecretString::from(password.to_owned())))
}

#[cfg(test)]
mod tests {
    use super::require_carbon;
    use crate::{
        domain::actor::{ActorRef, ActorType},
        infrastructure::postgres::tokens::AccessContext,
    };
    use uuid::Uuid;

    fn direct_carbon_access() -> AccessContext {
        AccessContext {
            token_id: Uuid::now_v7(),
            authentication_session_id: Uuid::now_v7(),
            subject: ActorRef {
                actor_type: ActorType::Carbon,
                id: Uuid::now_v7(),
            },
            client_application_id: None,
            audience_application_id: None,
            audience: "silicon-iam".to_owned(),
            organization_id: None,
            membership_id: None,
            scopes: vec!["iam.self".to_owned()],
            assurance_level: 1,
        }
    }

    #[test]
    fn application_management_requires_a_direct_iam_carbon_credential() {
        let direct = direct_carbon_access();
        assert!(require_carbon(&direct).is_ok());

        let mut delegated = direct_carbon_access();
        delegated.client_application_id = Some(Uuid::now_v7());
        delegated.audience = "third_party_app".to_owned();
        assert!(require_carbon(&delegated).is_err());

        let mut organization_bound = direct_carbon_access();
        organization_bound.organization_id = Some(Uuid::now_v7());
        organization_bound.membership_id = Some(Uuid::now_v7());
        assert!(require_carbon(&organization_bound).is_err());

        let mut missing_scope = direct_carbon_access();
        missing_scope.scopes.clear();
        assert!(require_carbon(&missing_scope).is_err());
    }
}
