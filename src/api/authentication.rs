//! Authentication extractors shared by protected HTTP routes.

use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, header, request::Parts},
};
use secrecy::SecretString;
use sqlx::FromRow;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

use crate::{
    domain::actor::ActorType,
    error::AppError,
    infrastructure::{
        browser_session::{self, BrowserSessionCookieError},
        postgres::{
            context::{self, DatabaseContext},
            tokens::{self, AccessContext, AccessTokenError},
        },
    },
};

use super::ApiState;

/// Revocation-aware access context extracted from an opaque Bearer token.
#[derive(Clone, Debug)]
pub(crate) struct Authenticated(pub(crate) AccessContext);

/// First-party Carbon identity accepted by logout through either a bearer
/// credential or the signed browser session plus double-submit CSRF token.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LogoutAuthenticated {
    pub(crate) principal_id: Uuid,
    pub(crate) authentication_session_id: Uuid,
}

#[derive(FromRow)]
struct BrowserLogoutSessionRow {
    session_id: Uuid,
    carbon_id: Uuid,
}

const ACTIVE_BROWSER_LOGOUT_SESSION_QUERY: &str = r"
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
    ";

impl FromRequestParts<ApiState> for Authenticated {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(authenticate_bearer(state, &parts.headers).await?))
    }
}

impl FromRequestParts<ApiState> for LogoutAuthenticated {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        // An explicitly supplied Authorization header is authoritative. Never
        // fall back to a cookie when a malformed or revoked bearer is present.
        if parts.headers.contains_key(header::AUTHORIZATION) {
            let access = authenticate_bearer(state, &parts.headers).await?;
            return logout_bearer_identity(&access);
        }

        let verified =
            browser_session::verify_headers(&parts.headers, &state.settings.security.cookie_key)
                .map_err(map_browser_cookie_error)?;
        require_matching_csrf(&parts.headers, &verified.csrf_token)?;

        let mut transaction = context::begin(&state.pool, DatabaseContext::anonymous())
            .await
            .map_err(|_| AppError::Internal {
                category: "logout_browser_session_context",
            })?;
        let row = sqlx::query_as::<_, BrowserLogoutSessionRow>(ACTIVE_BROWSER_LOGOUT_SESSION_QUERY)
            .bind(verified.session_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AppError::Internal {
                category: "logout_browser_session_read",
            })?
            .ok_or(AppError::Unauthenticated)?;
        transaction.commit().await.map_err(|_| AppError::Internal {
            category: "logout_browser_session_commit",
        })?;
        Ok(Self {
            principal_id: row.carbon_id,
            authentication_session_id: row.session_id,
        })
    }
}

async fn authenticate_bearer(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<AccessContext, AppError> {
    let authorization_headers = headers.get_all(header::AUTHORIZATION);
    let mut authorization_values = authorization_headers.iter();
    let header = authorization_values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthenticated)?;
    if authorization_values.next().is_some() {
        return Err(AppError::Unauthenticated);
    }
    let (scheme, credential) = header.split_once(' ').ok_or(AppError::Unauthenticated)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || credential.is_empty()
        || credential.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(AppError::Unauthenticated);
    }

    let credential = SecretString::from(credential.to_owned());
    match tokens::authenticate(&state.pool, &state.crypto, &credential).await {
        Ok(Some(context)) => Ok(context),
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

fn logout_bearer_identity(access: &AccessContext) -> Result<LogoutAuthenticated, AppError> {
    if access.subject.actor_type != ActorType::Carbon
        || access.audience != "silicon-iam"
        || access.client_application_id.is_some()
        || access.organization_id.is_some()
        || access.membership_id.is_some()
        || !access.scopes.iter().any(|scope| scope == "iam.self")
    {
        return Err(AppError::Forbidden);
    }
    Ok(LogoutAuthenticated {
        principal_id: access.subject.id,
        authentication_session_id: access.authentication_session_id,
    })
}

fn require_matching_csrf(headers: &HeaderMap, expected: &str) -> Result<(), AppError> {
    let csrf_headers = headers.get_all("x-csrf-token");
    let mut csrf_values = csrf_headers.iter();
    let supplied = csrf_values
        .next()
        .ok_or_else(|| AppError::PreconditionRequired {
            code: "csrf_token_required".into(),
        })?
        .to_str()
        .map_err(|_| AppError::Forbidden)?;
    if csrf_values.next().is_some() {
        return Err(AppError::Forbidden);
    }
    if bool::from(supplied.as_bytes().ct_eq(expected.as_bytes())) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn map_browser_cookie_error(error: BrowserSessionCookieError) -> AppError {
    match error {
        BrowserSessionCookieError::InvalidConfiguration => AppError::Internal {
            category: "logout_browser_cookie_configuration",
        },
        BrowserSessionCookieError::InvalidCookie | BrowserSessionCookieError::Expired => {
            AppError::Unauthenticated
        }
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};
    use uuid::Uuid;

    use crate::{
        domain::actor::{ActorRef, ActorType},
        infrastructure::postgres::tokens::AccessContext,
    };

    use super::{
        ACTIVE_BROWSER_LOGOUT_SESSION_QUERY, logout_bearer_identity, require_matching_csrf,
    };

    #[test]
    fn cookie_logout_requires_an_exact_csrf_token() {
        let mut headers = HeaderMap::new();
        assert!(require_matching_csrf(&headers, "expected-token").is_err());
        headers.insert("x-csrf-token", HeaderValue::from_static("different-token"));
        assert!(require_matching_csrf(&headers, "expected-token").is_err());
        headers.insert("x-csrf-token", HeaderValue::from_static("expected-token"));
        assert!(require_matching_csrf(&headers, "expected-token").is_ok());
        headers.append("x-csrf-token", HeaderValue::from_static("expected-token"));
        assert!(require_matching_csrf(&headers, "expected-token").is_err());
    }

    #[test]
    fn browser_logout_revalidates_every_session_authority_layer() {
        for required in [
            "principal.kind = 'carbon'",
            "principal.status = 'active'",
            "principal.auth_epoch = session.subject_auth_epoch",
            "session.subject_kind = 'carbon'",
            "session.status = 'active'",
            "session.idle_expires_at > transaction_timestamp()",
            "session.absolute_expires_at > transaction_timestamp()",
        ] {
            assert!(ACTIVE_BROWSER_LOGOUT_SESSION_QUERY.contains(required));
        }
    }

    #[test]
    fn delegated_bearer_cannot_use_first_party_logout() {
        let principal_id = Uuid::from_u128(1);
        let mut access = AccessContext {
            token_id: Uuid::from_u128(2),
            authentication_session_id: Uuid::from_u128(3),
            subject: ActorRef {
                actor_type: ActorType::Carbon,
                id: principal_id,
            },
            client_application_id: None,
            audience: "silicon-iam".to_owned(),
            organization_id: None,
            membership_id: None,
            scopes: vec!["iam.self".to_owned()],
            assurance_level: 1,
        };
        assert!(logout_bearer_identity(&access).is_ok());
        access.client_application_id = Some(Uuid::from_u128(4));
        assert!(logout_bearer_identity(&access).is_err());
    }
}
