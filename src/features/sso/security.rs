use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::ActorType,
    error::AppError,
    features::organizations::support as organization_support,
    infrastructure::{
        browser_session::{self, BrowserSessionCookieError},
        postgres::{
            context::{self, DatabaseContext},
            tokens::AccessContext,
        },
    },
};

const IAM_AUDIENCE: &str = "silicon-iam";
const IAM_SELF_SCOPE: &str = "iam.self";

#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::struct_field_names,
    reason = "each identifier preserves the SSO actor, root session, and application audit binding"
)]
pub(super) struct BrowserSession {
    pub(super) session_id: Uuid,
    pub(super) carbon_id: Uuid,
    pub(super) application_id: Option<Uuid>,
}

#[derive(FromRow)]
struct BrowserSessionRow {
    session_id: Uuid,
    carbon_id: Uuid,
}

impl FromRequestParts<ApiState> for BrowserSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        // An explicit bearer is authoritative: a revoked or insufficiently
        // scoped application token must never fall back to the IAM cookie.
        if parts.headers.contains_key(header::AUTHORIZATION) {
            if let Some(authenticated) = parts.extensions.get::<Authenticated>() {
                return from_bearer(authenticated);
            }
            let authenticated = Authenticated::from_request_parts(parts, state).await?;
            return from_bearer(&authenticated);
        }
        let verified =
            browser_session::verify_headers(&parts.headers, &state.settings.security.cookie_key)
                .map_err(map_cookie_error)?;
        let mut transaction = context::begin(state.db(), DatabaseContext::principal(Uuid::nil()))
            .await
            .map_err(|_| internal("sso_browser_session_context"))?;
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
        .map_err(|_| internal("sso_browser_session_read"))?
        .ok_or(AppError::Unauthenticated)?;
        transaction
            .commit()
            .await
            .map_err(|_| internal("sso_browser_session_commit"))?;
        drop(verified.csrf_token);
        Ok(Self {
            session_id: row.session_id,
            carbon_id: row.carbon_id,
            application_id: None,
        })
    }
}

fn from_bearer(authenticated: &Authenticated) -> Result<BrowserSession, AppError> {
    let carbon_id =
        organization_support::require_scoped_carbon(authenticated, "organizations.join")?;
    Ok(BrowserSession {
        session_id: authenticated.0.authentication_session_id,
        carbon_id,
        application_id: authenticated.0.client_application_id,
    })
}

pub(super) fn require_first_party_carbon(access: &AccessContext) -> Result<Uuid, AppError> {
    if access.subject.actor_type != ActorType::Carbon
        || access.audience != IAM_AUDIENCE
        || access.client_application_id.is_some()
        || access.organization_id.is_some()
        || access.membership_id.is_some()
        || !access.scopes.iter().any(|scope| scope == IAM_SELF_SCOPE)
    {
        return Err(AppError::Forbidden);
    }
    Ok(access.subject.id)
}

fn map_cookie_error(error: BrowserSessionCookieError) -> AppError {
    match error {
        BrowserSessionCookieError::InvalidConfiguration => {
            internal("sso_browser_cookie_configuration")
        }
        BrowserSessionCookieError::InvalidCookie | BrowserSessionCookieError::Expired => {
            AppError::Unauthenticated
        }
    }
}

const fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{from_bearer, require_first_party_carbon};
    use crate::{
        api::authentication::Authenticated,
        domain::actor::{ActorRef, ActorType},
        infrastructure::postgres::tokens::AccessContext,
    };

    fn access() -> AccessContext {
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

    fn application_access() -> Authenticated {
        let mut delegated = access();
        let application_id = Uuid::now_v7();
        delegated.client_application_id = Some(application_id);
        delegated.audience_application_id = Some(application_id);
        delegated.audience = "tos>interface".to_owned();
        delegated.scopes = vec!["organizations.join".to_owned()];
        Authenticated(delegated)
    }

    #[test]
    fn sso_join_bearer_preserves_actor_session_and_application() {
        let authenticated = application_access();
        let Ok(browser) = from_bearer(&authenticated) else {
            panic!("an ordinary Carbon application token may initiate SSO join");
        };
        assert_eq!(browser.carbon_id, authenticated.0.subject.id);
        assert_eq!(
            browser.session_id,
            authenticated.0.authentication_session_id
        );
        assert_eq!(
            browser.application_id,
            authenticated.0.client_application_id
        );
        assert!(from_bearer(&Authenticated(access())).is_ok());
    }

    #[test]
    fn sso_join_requires_its_exact_scope_and_a_human_self_audience_token() {
        let mut authenticated = application_access();
        authenticated.0.scopes = vec!["organization.sso.manage".to_owned()];
        assert!(from_bearer(&authenticated).is_err());
        authenticated.0.scopes = vec!["organizations.join".to_owned()];
        authenticated.0.audience_application_id = Some(Uuid::now_v7());
        assert!(from_bearer(&authenticated).is_err());
        authenticated.0.audience_application_id = authenticated.0.client_application_id;
        authenticated.0.subject.actor_type = ActorType::Silicon;
        assert!(from_bearer(&authenticated).is_err());
        authenticated.0.subject.actor_type = ActorType::Application;
        assert!(from_bearer(&authenticated).is_err());
    }

    #[test]
    fn application_tokens_cannot_change_platform_sso_entitlement() {
        let direct = access();
        assert!(require_first_party_carbon(&direct).is_ok());
        let mut delegated = access();
        delegated.client_application_id = Some(Uuid::now_v7());
        assert!(require_first_party_carbon(&delegated).is_err());
    }
}
