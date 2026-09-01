use std::borrow::Cow;

use axum::http::HeaderMap;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{actor::ActorType, organization::Capability},
    error::AppError,
    infrastructure::postgres::{authorization::OrganizationAccess, step_up::RequiredAssurance},
};

use super::super::support;

#[derive(Clone, Debug, FromRow)]
pub(super) struct TargetSilicon {
    pub(super) principal_id: Uuid,
    pub(super) membership_id: Uuid,
    pub(super) status: String,
}

pub(super) async fn load_target(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: &str,
) -> Result<TargetSilicon, AppError> {
    load_target_with_query(transaction, organization_id, silicon_id, TARGET_SQL).await
}

pub(super) async fn load_target_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: &str,
) -> Result<TargetSilicon, AppError> {
    load_target_with_query(
        transaction,
        organization_id,
        silicon_id,
        TARGET_FOR_UPDATE_SQL,
    )
    .await
}

async fn load_target_with_query(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    silicon_id: &str,
    query: &'static str,
) -> Result<TargetSilicon, AppError> {
    sqlx::query_as::<_, TargetSilicon>(query)
        .bind(organization_id)
        .bind(silicon_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(support::database)?
        .ok_or(AppError::NotFound)
}

const TARGET_SQL: &str = r"
        SELECT silicon.id AS principal_id,
               silicon.membership_id,
               CASE
                   WHEN silicon.provisioning_status <> 'deleted'
                    AND membership.status = 'active'
                   THEN 'active'
                   ELSE 'removed'
               END AS status
        FROM iam.silicons AS silicon
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id
        WHERE silicon.organization_id = $1
          AND silicon.global_silicon_id = $2
        LIMIT 1
";

const TARGET_FOR_UPDATE_SQL: &str = r"
        SELECT principal_id, membership_id, status
        FROM iam_private.lock_silicon_webhook_target($1, $2)
";

pub(super) fn authorize(
    authenticated: &Authenticated,
    access: &OrganizationAccess,
    target: &TargetSilicon,
) -> Result<(), AppError> {
    if target.status != "active" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("silicon_not_active"),
        });
    }
    authorize_identity(authenticated, access, target)
}

/// Performs only the immutable same-tenant/target authorization needed before
/// an idempotency replay. Mutable target status is checked again after a new
/// claim is acquired and the target row is locked.
pub(super) fn authorize_identity(
    authenticated: &Authenticated,
    access: &OrganizationAccess,
    target: &TargetSilicon,
) -> Result<(), AppError> {
    match authenticated.0.subject.actor_type {
        ActorType::Silicon if access.membership_id == target.membership_id => Ok(()),
        ActorType::Carbon => {
            support::require_capability(access, Capability::SiliconsUpdateDirectory)
        }
        ActorType::Silicon | ActorType::Application | ActorType::Service => {
            Err(AppError::Forbidden)
        }
    }
}

pub(super) async fn consume_carbon_step_up(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    action: &'static str,
    target: &TargetSilicon,
) -> Result<(), AppError> {
    if authenticated.0.subject.actor_type == ActorType::Carbon {
        support::consume_step_up(
            transaction,
            state,
            authenticated,
            headers,
            action,
            Some(target.membership_id),
            RequiredAssurance::VerifiedChannel,
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn cancel_deliveries(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    endpoint_id: Uuid,
    reason: &'static str,
) -> Result<(), AppError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT iam_private.cancel_silicon_webhook_deliveries($1, $2, $3)",
    )
    .bind(organization_id)
    .bind(endpoint_id)
    .bind(reason)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    Ok(())
}

pub(super) async fn lock_delivery_scope(
    transaction: &mut Transaction<'_, Postgres>,
    endpoint_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT iam_private.lock_silicon_webhook_delivery_scope($1)")
        .bind(endpoint_id)
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{TARGET_FOR_UPDATE_SQL, TARGET_SQL};

    #[test]
    fn mutation_target_query_uses_the_authorized_database_lock() {
        assert!(TARGET_FOR_UPDATE_SQL.contains("iam_private.lock_silicon_webhook_target"));
        assert!(!TARGET_SQL.contains("FOR UPDATE"));
    }
}
