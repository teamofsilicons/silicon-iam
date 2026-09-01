//! Authentication extractors shared by protected HTTP routes.

use axum::{extract::FromRequestParts, http::request::Parts};
use secrecy::SecretString;

use crate::{
    error::AppError,
    infrastructure::postgres::tokens::{self, AccessContext, AccessTokenError},
};

use super::ApiState;

/// Revocation-aware access context extracted from an opaque Bearer token.
#[derive(Clone, Debug)]
pub(crate) struct Authenticated(pub(crate) AccessContext);

impl FromRequestParts<ApiState> for Authenticated {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(AppError::Unauthenticated)?;
        let (scheme, credential) = header.split_once(' ').ok_or(AppError::Unauthenticated)?;
        if !scheme.eq_ignore_ascii_case("Bearer")
            || credential.is_empty()
            || credential.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(AppError::Unauthenticated);
        }

        let credential = SecretString::from(credential.to_owned());
        match tokens::authenticate(&state.pool, &state.crypto, &credential).await {
            Ok(Some(context)) => Ok(Self(context)),
            Ok(None) | Err(AccessTokenError::InvalidFormat) => Err(AppError::Unauthenticated),
            Err(AccessTokenError::Crypto(_)) => Err(AppError::Internal {
                category: "access_token_crypto",
            }),
            Err(AccessTokenError::Database(_)) => Err(AppError::Internal {
                category: "access_token_database",
            }),
            Err(AccessTokenError::InvalidStoredActorKind) => Err(AppError::Internal {
                category: "access_token_actor_kind",
            }),
        }
    }
}
