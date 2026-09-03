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
    domain::actor::{ActorRef, ActorType},
    error::AppError,
    features::authentication::{LogoutCredentialState, LogoutTrigger},
    infrastructure::{
        browser_session::{self, BrowserSessionCookieError},
        postgres::{
            context::{self, DatabaseContext},
            tokens::{self, AccessContext, AccessTokenError, LogoutReplayIdentity},
        },
    },
};

use super::ApiState;

/// Revocation-aware access context extracted from an opaque Bearer token.
#[derive(Clone, Debug)]
pub(crate) struct Authenticated(pub(crate) AccessContext);

/// Carbon session and immutable trigger identity accepted by global logout.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LogoutAuthenticated {
    pub(crate) principal_id: Uuid,
    pub(crate) authentication_session_id: Uuid,
    pub(crate) trigger: LogoutTrigger,
    pub(crate) credential_state: LogoutCredentialState,
}

#[derive(FromRow)]
struct BrowserLogoutSessionRow {
    session_id: Uuid,
    carbon_id: Uuid,
    authority_active: bool,
}

const BROWSER_LOGOUT_SESSION_QUERY: &str = r"
    SELECT
        session.id AS session_id,
        session.subject_principal_id AS carbon_id,
        (
            principal.status = 'active'
            AND principal.auth_epoch = session.subject_auth_epoch
            AND session.status = 'active'
            AND session.idle_expires_at > transaction_timestamp()
            AND session.absolute_expires_at > transaction_timestamp()
        ) AS authority_active
    FROM iam.authentication_sessions AS session
    JOIN iam.principals AS principal
      ON principal.id = session.subject_principal_id
     AND principal.kind = 'carbon'
    WHERE session.id = $1
      AND session.subject_kind = 'carbon'
    ";

#[derive(Clone, Copy)]
struct LogoutBearerContext<'a> {
    token_id: Uuid,
    authentication_session_id: Uuid,
    subject: ActorRef,
    client_application_id: Option<Uuid>,
    audience_application_id: Option<Uuid>,
    audience: &'a str,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    scopes: &'a [String],
}

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
            return authenticate_logout_bearer(state, &parts.headers).await;
        }

        let verified =
            browser_session::verify_headers(&parts.headers, &state.settings.security.cookie_key)
                .map_err(map_browser_cookie_error)?;
        require_matching_csrf(&parts.headers, &verified.csrf_token)?;

        let mut transaction = context::begin(state.db(), DatabaseContext::anonymous())
            .await
            .map_err(|_| AppError::Internal {
                category: "logout_browser_session_context",
            })?;
        let row = sqlx::query_as::<_, BrowserLogoutSessionRow>(BROWSER_LOGOUT_SESSION_QUERY)
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
            trigger: LogoutTrigger::FirstPartyCarbon,
            credential_state: if row.authority_active {
                LogoutCredentialState::Active
            } else {
                LogoutCredentialState::ReplayOnly
            },
        })
    }
}

async fn authenticate_bearer(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<AccessContext, AppError> {
    let credential = bearer_credential(headers)?;
    tokens::authenticate(state.db(), &state.crypto, &credential)
        .await
        .map_err(|error| map_access_token_error(&error))?
        .ok_or(AppError::Unauthenticated)
}

async fn authenticate_logout_bearer(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<LogoutAuthenticated, AppError> {
    let credential = bearer_credential(headers)?;
    if let Some(context) = tokens::authenticate(state.db(), &state.crypto, &credential)
        .await
        .map_err(|error| map_access_token_error(&error))?
    {
        logout_bearer_identity(
            LogoutBearerContext::from(&context),
            LogoutCredentialState::Active,
        )
    } else {
        let identity = tokens::identify_for_logout_replay(state.db(), &state.crypto, &credential)
            .await
            .map_err(|error| map_access_token_error(&error))?
            .ok_or(AppError::Unauthenticated)?;
        logout_bearer_identity(
            LogoutBearerContext::from(&identity),
            LogoutCredentialState::ReplayOnly,
        )
    }
}

fn bearer_credential(headers: &HeaderMap) -> Result<SecretString, AppError> {
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

    Ok(SecretString::from(credential.to_owned()))
}

fn map_access_token_error(error: &AccessTokenError) -> AppError {
    match error {
        AccessTokenError::InvalidFormat => AppError::Unauthenticated,
        AccessTokenError::Crypto(_) => AppError::Internal {
            category: "access_token_crypto",
        },
        AccessTokenError::Database(_) => AppError::Internal {
            category: "access_token_database",
        },
        AccessTokenError::InvalidStoredActorKind => AppError::Internal {
            category: "access_token_actor_kind",
        },
    }
}

fn logout_bearer_identity(
    access: LogoutBearerContext<'_>,
    credential_state: LogoutCredentialState,
) -> Result<LogoutAuthenticated, AppError> {
    if access.subject.actor_type != ActorType::Carbon {
        return Err(AppError::Forbidden);
    }

    let trigger = match (access.client_application_id, access.audience_application_id) {
        (None, None)
            if access.audience == "silicon-iam"
                && access.organization_id.is_none()
                && access.membership_id.is_none()
                && access.scopes.iter().any(|scope| scope == "iam.self") =>
        {
            LogoutTrigger::FirstPartyCarbon
        }
        (Some(application_id), Some(audience_application_id))
            if application_id == audience_application_id =>
        {
            LogoutTrigger::Application {
                application_id,
                access_token_id: access.token_id,
            }
        }
        _ => return Err(AppError::Forbidden),
    };

    Ok(LogoutAuthenticated {
        principal_id: access.subject.id,
        authentication_session_id: access.authentication_session_id,
        trigger,
        credential_state,
    })
}

impl<'a> From<&'a AccessContext> for LogoutBearerContext<'a> {
    fn from(access: &'a AccessContext) -> Self {
        Self {
            token_id: access.token_id,
            authentication_session_id: access.authentication_session_id,
            subject: access.subject,
            client_application_id: access.client_application_id,
            audience_application_id: access.audience_application_id,
            audience: &access.audience,
            organization_id: access.organization_id,
            membership_id: access.membership_id,
            scopes: &access.scopes,
        }
    }
}

impl<'a> From<&'a LogoutReplayIdentity> for LogoutBearerContext<'a> {
    fn from(access: &'a LogoutReplayIdentity) -> Self {
        Self {
            token_id: access.token_id,
            authentication_session_id: access.authentication_session_id,
            subject: access.subject,
            client_application_id: access.client_application_id,
            audience_application_id: access.audience_application_id,
            audience: &access.audience,
            organization_id: access.organization_id,
            membership_id: access.membership_id,
            scopes: &access.scopes,
        }
    }
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
        BROWSER_LOGOUT_SESSION_QUERY, LogoutBearerContext, logout_bearer_identity,
        require_matching_csrf,
    };
    use crate::features::authentication::{LogoutCredentialState, LogoutTrigger};

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
    fn browser_logout_classifies_live_authority_and_retains_replay_identity() {
        for required in [
            "principal.kind = 'carbon'",
            "principal.status = 'active'",
            "principal.auth_epoch = session.subject_auth_epoch",
            "session.subject_kind = 'carbon'",
            "session.status = 'active'",
            "session.idle_expires_at > transaction_timestamp()",
            "session.absolute_expires_at > transaction_timestamp()",
        ] {
            assert!(BROWSER_LOGOUT_SESSION_QUERY.contains(required));
        }
        assert!(BROWSER_LOGOUT_SESSION_QUERY.contains(") AS authority_active"));
        assert!(!BROWSER_LOGOUT_SESSION_QUERY.contains("WHERE session.status = 'active'"));
    }

    #[test]
    fn logout_accepts_only_direct_carbon_or_bound_application_bearers() {
        let principal_id = Uuid::from_u128(1);
        let mut access = AccessContext {
            token_id: Uuid::from_u128(2),
            authentication_session_id: Uuid::from_u128(3),
            subject: ActorRef {
                actor_type: ActorType::Carbon,
                id: principal_id,
            },
            client_application_id: None,
            audience_application_id: None,
            audience: "silicon-iam".to_owned(),
            organization_id: None,
            membership_id: None,
            scopes: vec!["iam.self".to_owned()],
            assurance_level: 1,
        };
        assert!(matches!(
            logout_bearer_identity(
                LogoutBearerContext::from(&access),
                LogoutCredentialState::Active,
            ),
            Ok(super::LogoutAuthenticated {
                trigger: LogoutTrigger::FirstPartyCarbon,
                credential_state: LogoutCredentialState::Active,
                ..
            })
        ));
        assert!(matches!(
            logout_bearer_identity(
                LogoutBearerContext::from(&access),
                LogoutCredentialState::ReplayOnly,
            ),
            Ok(super::LogoutAuthenticated {
                trigger: LogoutTrigger::FirstPartyCarbon,
                credential_state: LogoutCredentialState::ReplayOnly,
                ..
            })
        ));
        access.client_application_id = Some(Uuid::from_u128(4));
        access.audience_application_id = Some(Uuid::from_u128(4));
        access.audience = "configured-app".to_owned();
        assert!(matches!(
            logout_bearer_identity(
                LogoutBearerContext::from(&access),
                LogoutCredentialState::Active,
            ),
            Ok(super::LogoutAuthenticated {
                trigger: LogoutTrigger::Application {
                    application_id,
                    access_token_id,
                },
                ..
            }) if application_id == Uuid::from_u128(4)
                && access_token_id == Uuid::from_u128(2)
        ));
        access.audience_application_id = Some(Uuid::from_u128(5));
        assert!(
            logout_bearer_identity(
                LogoutBearerContext::from(&access),
                LogoutCredentialState::Active,
            )
            .is_err()
        );
    }
}
