//! Bounded finalization of due Carbon account-deletion requests.

use uuid::Uuid;

use crate::error::AppError;

use super::WorkerContext;

pub(super) async fn process_batch(context: &WorkerContext) -> Result<(), AppError> {
    let batch_size = i32::try_from(context.settings.worker.batch_size.get()).map_err(|_| {
        AppError::Internal {
            category: "account_deletion_batch_size",
        }
    })?;
    let count = usize::try_from(batch_size).map_err(|_| AppError::Internal {
        category: "account_deletion_batch_size",
    })?;
    let request_ids = (0..count).map(|_| Uuid::now_v7()).collect::<Vec<_>>();
    let audit_event_ids = (0..count).map(|_| Uuid::now_v7()).collect::<Vec<_>>();
    let outbox_event_ids = (0..count).map(|_| Uuid::now_v7()).collect::<Vec<_>>();
    let finalized = sqlx::query_scalar::<_, i32>(
        "SELECT iam_private.run_worker_account_deletion_finalization($1, $2, $3, $4)",
    )
    .bind(batch_size)
    .bind(request_ids)
    .bind(audit_event_ids)
    .bind(outbox_event_ids)
    .fetch_one(&context.pool)
    .await?;
    if finalized > 0 {
        tracing::info!(
            worker.stage = "account_deletion",
            finalized,
            "due account deletions finalized"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn deletion_batch_ids_are_generated_per_claim_slot() {
        let count = 4_usize;
        let ids = (0..count).map(|_| uuid::Uuid::now_v7()).collect::<Vec<_>>();
        assert_eq!(ids.len(), count);
        assert!(ids.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
