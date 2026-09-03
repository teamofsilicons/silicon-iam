//! Idle retirement and permanent destruction of testing environments.
//!
//! Two transitions, both bounded per sweep. An environment nobody has touched
//! for the configured window is retired into the same recoverable state a
//! manual deletion produces, and an environment whose recovery window has
//! elapsed has its data erased and its record removed.
//!
//! The second transition spans two databases that cannot commit together, so
//! it is ordered rather than atomic: erase the data, then drop the record. A
//! failure in between leaves an environment that is empty but still recorded
//! and still past its deadline, which the next sweep picks up and finishes. The
//! opposite order would drop the record first and strand rows nobody can reach.

use sqlx::PgPool;
use uuid::Uuid;

use crate::{config::TestingSettings, error::AppError};

use super::WorkerContext;

/// Environments handled per sweep, in each direction.
///
/// Small on purpose. These are slow-moving lifecycle transitions, and an
/// erase is a wide multi-table delete that should not monopolise the testing
/// database in one pass.
const SWEEP_LIMIT: i32 = 25;

pub(super) async fn process_batch(context: &WorkerContext) -> Result<(), AppError> {
    let (Some(settings), Some(testing_pool)) = (
        context.settings.testing.as_ref(),
        context.testing_pool.as_ref(),
    ) else {
        return Ok(());
    };

    let expired = expire_idle(&context.pool, settings).await;
    let purged = purge_expired(&context.pool, testing_pool).await;

    match (expired, purged) {
        (Ok(expired), Ok(purged)) => {
            if expired > 0 || purged > 0 {
                tracing::info!(
                    worker.stage = "testing_environment_maintenance",
                    retired = expired,
                    purged = purged,
                    "testing environment maintenance batch completed"
                );
            }
            Ok(())
        }
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

/// Retires environments that have gone quiet.
///
/// Idleness is measured from the activity every accepted request records, so
/// an environment stays alive exactly as long as somebody is using it.
async fn expire_idle(pool: &PgPool, settings: &TestingSettings) -> Result<i64, AppError> {
    sqlx::query_scalar::<_, i64>("SELECT iam_private.expire_idle_testing_environments($1, $2, $3)")
        .bind(i32::from(settings.idle_days))
        .bind(i32::from(settings.recovery_days))
        .bind(SWEEP_LIMIT)
        .fetch_one(pool)
        .await
        .map_err(|error| {
            tracing::error!(
                error = %error,
                worker.stage = "testing_environment_maintenance",
                "could not retire idle testing environments"
            );
            AppError::Internal {
                category: "testing_environment_idle_sweep",
            }
        })
}

/// Destroys environments whose recovery window has closed.
///
/// One environment's failure does not stop the others: the loop records it and
/// moves on, and the deadline that selected it will select it again next sweep.
async fn purge_expired(pool: &PgPool, testing_pool: &PgPool) -> Result<i64, AppError> {
    let candidates = sqlx::query_scalar::<_, Uuid>(
        "SELECT * FROM iam_private.list_testing_environments_for_purge($1)",
    )
    .bind(SWEEP_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(|error| {
        tracing::error!(
            error = %error,
            worker.stage = "testing_environment_maintenance",
            "could not list testing environments for purge"
        );
        AppError::Internal {
            category: "testing_environment_purge_list",
        }
    })?;

    let mut purged = 0;
    for environment_id in candidates {
        if let Err(error) = purge_one(pool, testing_pool, environment_id).await {
            tracing::error!(
                error = %error,
                worker.stage = "testing_environment_maintenance",
                testing_environment.id = %environment_id,
                "could not purge testing environment"
            );
            continue;
        }
        purged += 1;
    }
    Ok(purged)
}

async fn purge_one(
    pool: &PgPool,
    testing_pool: &PgPool,
    environment_id: Uuid,
) -> Result<(), sqlx::Error> {
    let erased = sqlx::query_scalar::<_, i64>("SELECT iam_private.erase_testing_environment($1)")
        .bind(environment_id)
        .fetch_one(testing_pool)
        .await?;

    // Re-checked under the row lock inside the function, so a restore that
    // landed between listing and here wins and the environment survives with
    // its data already gone -- empty, but recoverable and usable.
    let removed = sqlx::query_scalar::<_, bool>("SELECT iam_private.purge_testing_environment($1)")
        .bind(environment_id)
        .fetch_one(pool)
        .await?;

    tracing::info!(
        worker.stage = "testing_environment_maintenance",
        testing_environment.id = %environment_id,
        erased_rows = erased,
        removed = removed,
        "testing environment purge completed"
    );
    Ok(())
}
