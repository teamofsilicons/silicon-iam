//! Current production IAM scope policy for imported testing applications.

use std::collections::BTreeMap;

use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::ApiState,
    error::AppError,
    infrastructure::{
        postgres::context::{self, DatabaseContext},
        testing_plane,
    },
};

use super::support;

#[derive(sqlx::FromRow)]
#[allow(
    clippy::struct_field_names,
    reason = "the local application, source application and organization identifiers bind import provenance"
)]
struct ImportedSource {
    application_id: Uuid,
    source_application_id: Uuid,
    org_id: String,
}

#[derive(sqlx::FromRow)]
struct SourcePolicy {
    source_application_id: Uuid,
    org_id: String,
    trusted_org: bool,
    allowed_scopes: Vec<String>,
}

#[derive(Serialize)]
struct ImportedPolicy {
    application_id: Uuid,
    source_application_id: Uuid,
    org_id: String,
    trusted_org: bool,
    allowed_scopes: Vec<String>,
}

/// The verified testing key middleware runs this before any data-plane
/// authentication, including actor-ID login, bearer access and token refresh.
pub(super) async fn revalidate(state: &ApiState) -> Result<(), AppError> {
    let environment_id = testing_plane::current_id().ok_or(AppError::Forbidden)?;
    let mut transaction = context::begin(state.db(), DatabaseContext::anonymous())
        .await
        .map_err(support::database)?;
    // Use the import lock so a stale request snapshot cannot undo a policy
    // update applied by another request or a concurrent explicit reimport.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("testing-import:{environment_id}"))
        .execute(&mut *transaction)
        .await
        .map_err(support::database)?;
    synchronize(&mut transaction, &state.pool).await?;
    transaction.commit().await.map_err(support::database)
}

/// Call while holding the environment import lock. All policy data comes from
/// the production pool; the HTTP import body contains only an application ID.
pub(super) async fn synchronize(
    transaction: &mut Transaction<'_, Postgres>,
    production: &PgPool,
) -> Result<(), AppError> {
    let imports = sqlx::query_as::<_, ImportedSource>(
        "SELECT * FROM iam_private.list_testing_import_iam_scope_sources()",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(support::database)?;
    if imports.is_empty() {
        return Ok(());
    }
    let sources = sqlx::query_as::<_, SourcePolicy>(
        "SELECT * FROM iam_private.get_testing_source_iam_scope_policies($1)",
    )
    .bind(
        imports
            .iter()
            .map(|imported| imported.source_application_id)
            .collect::<Vec<_>>(),
    )
    .fetch_all(production)
    .await
    .map_err(support::database)?
    .into_iter()
    .map(|policy| (policy.source_application_id, policy))
    .collect::<BTreeMap<_, _>>();
    let policies = imports
        .into_iter()
        .map(|imported| {
            // Source applications retain their own independent lifecycle.
            // This lookup verifies only owning-org policy and provenance;
            // a missing/mismatched source must fail closed without rewriting
            // shared organization policy based on one app's status.
            let source = sources
                .get(&imported.source_application_id)
                .filter(|source| source.org_id == imported.org_id)
                .ok_or(AppError::ServiceUnavailable)?;
            Ok(ImportedPolicy {
                application_id: imported.application_id,
                source_application_id: imported.source_application_id,
                org_id: imported.org_id,
                trusted_org: source.trusted_org,
                allowed_scopes: source.allowed_scopes.clone(),
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    sqlx::query("SELECT iam_private.apply_testing_import_iam_scope_policies($1)")
        .bind(sqlx::types::Json(policies))
        .execute(&mut **transaction)
        .await
        .map_err(support::database)?;
    Ok(())
}
