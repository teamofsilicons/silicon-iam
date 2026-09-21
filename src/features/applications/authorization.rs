//! Live, token-bound authorization for application bootstrap and delegated requests.

use crate::domain::id::Id;
use sqlx::{Postgres, Transaction, types::Json};

use super::{error::ApiError, model::ApplicationAuthorization, security::ApplicationIdentity};

/// The caller has authenticated the token or proof and installed its exact
/// subject context. A constrained definer helper locks/rechecks that chain;
/// ordinary members must not need organization UPDATE authority to use it.
/// Cross-application disclosure additionally requires the exact persisted OBO
/// proof, not merely a parent's token ID. Missing roles/tags are undisclosed.
pub(super) async fn load(
    transaction: &mut Transaction<'_, Postgres>,
    token_id: Id,
    subject_id: Id,
    organization_id: Id,
    membership_id: Id,
    audience: &ApplicationIdentity,
    proof_id: Option<Id>,
) -> Result<Option<ApplicationAuthorization>, ApiError> {
    sqlx::query_scalar::<_, Option<Json<ApplicationAuthorization>>>(
        "SELECT iam_private.get_current_application_authorization($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(token_id)
    .bind(subject_id)
    .bind(organization_id)
    .bind(membership_id)
    .bind(audience.application_id)
    .bind(audience.auth_epoch)
    .bind(proof_id)
    .fetch_one(&mut **transaction)
    .await
    .map(|value| value.map(|value| value.0))
    .map_err(|error| {
        if let sqlx::Error::Database(database) = &error
            && database.code().as_deref() == Some("P0001")
            && database.message() == "obo_proof_consumed"
        {
            return ApiError::conflict("obo_proof_consumed");
        }
        ApiError::internal("application_authorization_snapshot")
    })
}

/// Every organization an unscoped bearer currently reaches, one snapshot per
/// active membership.
///
/// `None` means the bearer chain itself is dead and the caller must report the
/// token inactive; an empty vector means the chain is live but the subject
/// holds no active membership anywhere, which is not the same thing.
pub(super) async fn load_all(
    transaction: &mut Transaction<'_, Postgres>,
    token_id: Id,
    subject_id: Id,
    audience: &ApplicationIdentity,
) -> Result<Option<Vec<ApplicationAuthorization>>, ApiError> {
    sqlx::query_scalar::<_, Option<Json<Vec<ApplicationAuthorization>>>>(
        "SELECT iam_private.list_current_application_authorizations($1, $2, $3, $4)",
    )
    .bind(token_id)
    .bind(subject_id)
    .bind(audience.application_id)
    .bind(audience.auth_epoch)
    .fetch_one(&mut **transaction)
    .await
    .map(|value| value.map(|value| value.0))
    .map_err(|_| ApiError::internal("application_authorization_snapshots"))
}
