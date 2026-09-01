use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::error::AppError;

pub(super) async fn serializable<'pool>(
    pool: &'pool PgPool,
    category: &'static str,
) -> Result<Transaction<'pool, Postgres>, AppError> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|_| AppError::Internal { category })?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::Internal { category })?;
    Ok(transaction)
}

pub(super) fn database_conflict(error: &sqlx::Error, fallback: &'static str) -> AppError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| matches!(code.as_ref(), "23505" | "40001" | "40P01"))
    {
        AppError::Conflict {
            code: std::borrow::Cow::Borrowed(fallback),
        }
    } else {
        AppError::Internal {
            category: "authentication_database",
        }
    }
}

pub(super) fn expired() -> AppError {
    AppError::Gone {
        code: std::borrow::Cow::Borrowed("challenge_expired"),
    }
}

pub(super) async fn set_principal_context(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT set_config('iam.principal_id', $1, true)")
        .bind(principal_id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "authentication_principal_context",
        })?;
    Ok(())
}
