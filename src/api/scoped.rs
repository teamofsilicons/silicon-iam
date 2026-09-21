//! Explicit, application-only IAM route composition.

use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::Response,
    routing::get,
};

use super::{ApiState, authentication::Authenticated, me};
use crate::{
    domain::actor::ActorType, error::AppError, infrastructure::postgres::tokens::AccessContext,
};

/// Include only endpoints governed by published IAM scopes. The outer gate is
/// independent of individual handlers, so future direct-IAM bypasses in a
/// handler cannot grant first-party or delegated tokens access to this host.
pub(crate) fn router(state: ApiState) -> Router<ApiState> {
    Router::new()
        .route("/api/v1/me", get(me::get))
        .merge(crate::features::organizations::scoped_router())
        .merge(crate::features::applications::scoped_router())
        .merge(crate::features::sso::scoped_router())
        .route_layer(middleware::from_fn_with_state(state, require_application))
}

/// Production control operations stay outside testing database selection.
pub(crate) fn control_plane_router(state: ApiState) -> Router<ApiState> {
    crate::features::testing_environments::scoped_router()
        .route_layer(middleware::from_fn_with_state(state, require_application))
}

async fn require_application(
    Authenticated(access): Authenticated,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    if !is_application_session(&access) {
        return Err(AppError::Forbidden);
    }
    request.extensions_mut().insert(Authenticated(access));
    Ok(next.run(request).await)
}

fn is_application_session(access: &AccessContext) -> bool {
    matches!(
        access.subject.actor_type,
        ActorType::Carbon | ActorType::Silicon
    ) && access.client_application_id.is_some()
        && access.client_application_id == access.audience_application_id
        && access.audience != "silicon-iam"
}

#[cfg(test)]
mod tests {
    use super::is_application_session;
    use crate::domain::id::Id;
    use crate::{
        domain::actor::{ActorRef, ActorType},
        infrastructure::postgres::tokens::AccessContext,
    };

    fn access() -> AccessContext {
        AccessContext {
            token_id: Id::from_u128(1),
            authentication_session_id: Id::from_u128(2),
            subject: ActorRef {
                actor_type: ActorType::Carbon,
                id: Id::from_u128(3),
            },
            client_application_id: Some(Id::from_u128(4)),
            audience_application_id: Some(Id::from_u128(4)),
            audience: "tos>scoped-iam".into(),
            organization_id: None,
            membership_id: None,
            scopes: vec!["self.identity.read".into()],
            assurance_level: 1,
        }
    }

    #[test]
    fn scoped_backend_accepts_only_ordinary_application_sessions() {
        let mut token = access();
        assert!(is_application_session(&token));
        token.subject.actor_type = ActorType::Silicon;
        assert!(is_application_session(&token));
        token.subject.actor_type = ActorType::Application;
        assert!(!is_application_session(&token));
        token.subject.actor_type = ActorType::Service;
        assert!(!is_application_session(&token));
        token.subject.actor_type = ActorType::Carbon;
        token.audience_application_id = Some(Id::from_u128(5));
        assert!(
            !is_application_session(&token),
            "OBO target must be rejected"
        );
        token.audience_application_id = None;
        assert!(!is_application_session(&token));
        token = access();
        token.client_application_id = None;
        token.audience_application_id = None;
        token.audience = "silicon-iam".into();
        token.scopes = vec!["iam.self".into()];
        assert!(
            !is_application_session(&token),
            "direct IAM session must be rejected"
        );
        token = access();
        token.audience = "silicon-iam".into();
        assert!(!is_application_session(&token));
    }

    #[tokio::test]
    #[ignore = "requires the CI IAM test settings"]
    async fn scoped_route_composition_omits_identity_admin_and_obo_surfaces() -> anyhow::Result<()>
    {
        use crate::{
            api::{ApiState, Surface},
            config::{RuntimeEnvironment, Settings},
            infrastructure::{crypto::CryptoService, providers::NotificationProviders},
        };
        use axum::{
            body::Body,
            http::{Method, Request, StatusCode},
        };
        use sqlx::postgres::PgPoolOptions;
        use std::sync::Arc;
        use tower::ServiceExt as _;
        let settings = Settings::from_env()?;
        anyhow::ensure!(settings.environment == RuntimeEnvironment::Test);
        // No database is contacted: omitted paths and missing bearer credentials
        // must be resolved by routing and extraction, before data-plane access.
        let state = ApiState {
            pool: PgPoolOptions::new()
                .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")?,
            crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
            notifications: NotificationProviders::from_settings(&settings.providers)?,
            workos: None,
            testing: None,
            settings: Arc::new(settings),
        };
        let full = crate::api::router(state.clone(), Surface::Scoped)?;
        for (method, path) in [
            (Method::GET, "/admin"),
            (Method::GET, "/docs/api"),
            (Method::POST, "/api/v1/auth/register"),
            (Method::POST, "/api/v1/auth/step-up/challenges"),
            (Method::POST, "/api/v1/app-auth/tokens"),
            (Method::POST, "/api/v1/app-verification/keys"),
            (Method::POST, "/api/v1/app-verification/verify"),
            (Method::POST, "/api/v1/obo-access/exchanges"),
            (Method::POST, "/api/v1/obo-access/verify"),
            (
                Method::GET,
                "/api/v1/obo-access/applications/tos%3Eapp/endpoints",
            ),
            (Method::POST, "/api/v1/applications"),
            (Method::GET, "/api/v1/admin/applications"),
            (Method::GET, "/api/v1/testing-environments"),
            (
                Method::POST,
                "/api/v1/organizations/tos/ownership-transfers",
            ),
            (
                Method::GET,
                "/api/v1/organizations/tos/silicons/00000000-0000-0000-0000-000000000001/webhook",
            ),
            (Method::POST, "/api/v1/provider-webhooks/workos"),
            (Method::GET, "/api/v1/sso/callback"),
        ] {
            let response = full
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())?,
                )
                .await?;
            anyhow::ensure!(
                response.status() == StatusCode::NOT_FOUND,
                "unexpected scoped route: {path}: {}",
                response.status()
            );
        }
        let protected = super::router(state.clone()).with_state(state);
        for path in [
            "/api/v1/me",
            "/api/v1/application-scopes",
            "/api/v1/organizations",
            "/api/v1/organizations/tos/sso",
        ] {
            let response = protected
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty())?)
                .await?;
            anyhow::ensure!(
                response.status() == StatusCode::UNAUTHORIZED,
                "route accepted missing bearer: {path}"
            );
        }
        Ok(())
    }
}
