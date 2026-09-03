//! Transaction-local PostgreSQL identity context for row-level security.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::infrastructure::testing_plane;

/// Identity and tenant boundary applied to one database transaction.
#[derive(Clone, Copy, Debug)]
pub struct DatabaseContext {
    /// Authenticated principal, if the operation is not public.
    pub principal_id: Option<Uuid>,
    /// Organization selected for an organization-scoped operation.
    pub organization_id: Option<Uuid>,
    /// Application selected for an application-scoped operation.
    pub application_id: Option<Uuid>,
    /// Public signup session authorized to finalize a Carbon.
    pub signup_session_id: Option<Uuid>,
}

impl DatabaseContext {
    /// Creates an unauthenticated context for a public operation whose
    /// authority is established by a separate, narrowly scoped credential.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self {
            principal_id: None,
            organization_id: None,
            application_id: None,
            signup_session_id: None,
        }
    }

    /// Creates a context for a principal without a selected tenant.
    #[must_use]
    pub const fn principal(principal_id: Uuid) -> Self {
        Self {
            principal_id: Some(principal_id),
            organization_id: None,
            application_id: None,
            signup_session_id: None,
        }
    }

    /// Creates an organization-scoped principal context.
    #[must_use]
    pub const fn organization(principal_id: Uuid, organization_id: Uuid) -> Self {
        Self {
            principal_id: Some(principal_id),
            organization_id: Some(organization_id),
            application_id: None,
            signup_session_id: None,
        }
    }

    /// Creates an application-scoped principal context.
    #[must_use]
    pub const fn application(principal_id: Uuid, application_id: Uuid) -> Self {
        Self {
            principal_id: Some(principal_id),
            organization_id: None,
            application_id: Some(application_id),
            signup_session_id: None,
        }
    }

    /// Creates an anonymous context bound to a verified signup session.
    #[must_use]
    pub const fn signup(signup_session_id: Uuid) -> Self {
        Self {
            principal_id: None,
            organization_id: None,
            application_id: None,
            signup_session_id: Some(signup_session_id),
        }
    }
}

/// Begins a transaction and installs RLS context with transaction-local scope.
///
/// The testing environment is not part of [`DatabaseContext`] because it is
/// not a choice any caller makes: it is fixed for the whole request by the
/// middleware that verified the environment key, and is read here so that no
/// handler can open a transaction against the testing database without it.
/// Against production it is always empty.
///
/// # Errors
///
/// Returns an error when the transaction cannot begin or PostgreSQL rejects a
/// context setting. No setting survives transaction commit, rollback, or pool
/// reuse.
pub async fn begin(
    pool: &PgPool,
    context: DatabaseContext,
) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        SELECT
            set_config('iam.principal_id', $1, true),
            set_config('iam.organization_id', $2, true),
            set_config('iam.application_id', $3, true),
            set_config('iam.signup_session_id', $4, true),
            set_config('iam.testing_environment_id', $5, true)
        ",
    )
    .bind(
        context
            .principal_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    )
    .bind(
        context
            .organization_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    )
    .bind(
        context
            .application_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    )
    .bind(
        context
            .signup_session_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    )
    .bind(
        testing_plane::current_id()
            .map(|id| id.to_string())
            .unwrap_or_default(),
    )
    .execute(&mut *transaction)
    .await?;
    Ok(transaction)
}

/// Begins a transaction carrying only the testing-environment scope.
///
/// A handful of flows install their identity settings themselves, or must
/// raise the isolation level before anything else runs. They still must not
/// reach the shared testing database without an environment selected -- row
/// security would answer with nothing and the failure would look like missing
/// data rather than a missing scope -- so they begin here instead of calling
/// `PgPool::begin` directly.
///
/// # Errors
///
/// Returns an error when the transaction cannot begin or PostgreSQL rejects
/// the setting.
pub async fn begin_scoped(pool: &PgPool) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    apply_testing_scope(&mut transaction).await?;
    Ok(transaction)
}

/// Installs the testing-environment scope on an already-open transaction.
///
/// For the flows that must issue their own first statement -- raising the
/// isolation level, which PostgreSQL only accepts before anything else -- and
/// so cannot use [`begin_scoped`].
///
/// # Errors
///
/// Returns an error if PostgreSQL rejects the setting.
pub async fn apply_testing_scope(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('iam.testing_environment_id', $1, true)")
        .bind(
            testing_plane::current_id()
                .map(|id| id.to_string())
                .unwrap_or_default(),
        )
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// Selects an organization after resolving its public handle in a transaction.
///
/// # Errors
///
/// Returns an error if PostgreSQL rejects the transaction-local setting.
pub async fn select_organization(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('iam.organization_id', $1, true)")
        .bind(organization_id.to_string())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}
