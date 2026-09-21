//! Production authority for the shared environment lifecycle.

use crate::domain::id::Id;
use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use sqlx::{Postgres, Transaction};

use super::{model::EnvironmentResponse, support};
use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::{ActorRef, ActorType},
    error::AppError,
    features::{applications::security::ApplicationClient, organizations},
    infrastructure::postgres::context::{self, DatabaseContext},
};

#[allow(
    clippy::large_enum_variant,
    reason = "bounded canonical handles preserve Copy authority snapshots without interning or lifetime coupling"
)]
pub(super) enum EnvironmentManager {
    Member(Authenticated),
    Application(ApplicationClient),
}

pub(super) struct Scope<'a> {
    pub(super) transaction: Transaction<'a, Postgres>,
    pub(super) organization_id: Id,
}

impl FromRequestParts<ApiState> for EnvironmentManager {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &ApiState) -> Result<Self, Response> {
        // The control-plane router never selects a testing database. Test app
        // secrets and application-issued bearer tokens cannot administer it.
        if parts
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| {
                h.split_once(' ')
                    .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
            })
        {
            ApplicationClient::from_request_parts(parts, state)
                .await
                .map(Self::Application)
                .map_err(IntoResponse::into_response)
        } else {
            Authenticated::from_request_parts(parts, state)
                .await
                .map(Self::Member)
                .map_err(IntoResponse::into_response)
        }
    }
}

impl EnvironmentManager {
    pub(super) fn actor(&self) -> ActorRef {
        match self {
            Self::Member(member) => member.0.subject,
            Self::Application(app) => ActorRef {
                actor_type: ActorType::Application,
                id: app.application_id,
            },
        }
    }

    pub(super) fn session_id(&self) -> Option<Id> {
        match self {
            Self::Member(member) => Some(member.0.authentication_session_id),
            Self::Application(_) => None,
        }
    }

    pub(super) async fn begin<'a>(
        &self,
        state: &'a ApiState,
        org_id: &str,
    ) -> Result<Scope<'a>, AppError> {
        match self {
            Self::Member(member) => {
                let scope = organizations::begin_organization(state, member, org_id).await?;
                Ok(Scope {
                    transaction: scope.transaction,
                    organization_id: scope.access.organization_id,
                })
            }
            Self::Application(app) => {
                if app.app_id.split_once('>').map(|(org, _)| org) != Some(org_id) {
                    return Err(AppError::NotFound);
                }
                let transaction = context::begin(
                    &state.pool,
                    DatabaseContext {
                        principal_id: Some(app.application_id),
                        application_id: Some(app.application_id),
                        organization_id: Some(app.organization_id),
                        signup_session_id: None,
                    },
                )
                .await
                .map_err(support::database)?;
                Ok(Scope {
                    transaction,
                    organization_id: app.organization_id,
                })
            }
        }
    }

    pub(super) async fn require_administrator(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Id,
        environment: &EnvironmentResponse,
    ) -> Result<(), AppError> {
        match self {
            Self::Member(member) => {
                support::require_administrator(
                    transaction,
                    organization_id,
                    environment.created_by_membership_id,
                    member.0.subject.id,
                )
                .await
            }
            Self::Application(_) => {
                let allowed = sqlx::query_scalar::<_, bool>(
                    "SELECT iam_private.is_application_testing_environment_administrator($1)",
                )
                .bind(environment.id)
                .fetch_one(&mut **transaction)
                .await
                .map_err(support::database)?;
                if allowed {
                    Ok(())
                } else {
                    Err(AppError::Forbidden)
                }
            }
        }
    }
}
