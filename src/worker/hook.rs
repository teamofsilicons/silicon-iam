//! Idempotent asynchronous Silicon Hook provisioning.

use futures::{StreamExt as _, stream};
use secrecy::ExposeSecret as _;
use uuid::Uuid;

use crate::{
    error::AppError,
    infrastructure::{
        crypto::{EncryptionContext, ProtectedField},
        providers::hook::HookError,
    },
};

use super::{WorkerContext, delivery_claim_limit, retry_delay_seconds};

#[derive(sqlx::FromRow)]
struct ClaimedHook {
    id: Uuid,
    attempt_count: i32,
}

#[derive(sqlx::FromRow)]
struct HookIdentity {
    organization_id: Uuid,
    global_silicon_id: String,
}

pub(super) async fn process_batch(context: &WorkerContext) -> Result<(), AppError> {
    let _outbound_stage = context.outbound_stage_lock.lock().await;
    let claim_limit = delivery_claim_limit(context)?;
    let lease_seconds =
        i64::try_from(context.settings.worker.lease_duration.as_secs()).map_err(|_| {
            AppError::Internal {
                category: "worker_lease_duration",
            }
        })?;
    let hooks = sqlx::query_as::<_, ClaimedHook>(
        r"
        WITH candidates AS (
            SELECT hook.id
            FROM iam.silicon_hooks AS hook
            WHERE (
                    hook.status = 'pending'
                    OR (
                        hook.status = 'failed'
                        AND hook.next_attempt_at <= transaction_timestamp()
                    )
                    OR (
                        hook.status = 'provisioning'
                        AND hook.lease_expires_at <= transaction_timestamp()
                    )
                )
              AND (
                    hook.attempt_count < $4
                    OR (
                        hook.status = 'provisioning'
                        AND hook.lease_expires_at <= transaction_timestamp()
                    )
              )
            ORDER BY COALESCE(hook.next_attempt_at, hook.created_at), hook.id
            FOR UPDATE SKIP LOCKED
            LIMIT $1
        )
        UPDATE iam.silicon_hooks AS hook
        SET status = 'provisioning',
            lease_owner = $2,
            lease_expires_at = transaction_timestamp()
                + ($3::bigint * interval '1 second'),
            attempt_count = hook.attempt_count + 1,
            last_error_code = NULL
        FROM candidates
        WHERE hook.id = candidates.id
        RETURNING hook.id, hook.attempt_count
        ",
    )
    .bind(claim_limit)
    .bind(&context.instance_id)
    .bind(lease_seconds)
    .bind(i32::from(context.settings.worker.max_attempts))
    .fetch_all(&context.pool)
    .await?;

    let results = stream::iter(hooks)
        .map(|hook| async move { process_hook(context, &hook).await })
        .buffer_unordered(context.settings.worker.delivery_concurrency.get())
        .collect::<Vec<_>>()
        .await;
    for result in results {
        result?;
    }
    Ok(())
}

async fn process_hook(context: &WorkerContext, hook: &ClaimedHook) -> Result<(), AppError> {
    let identity = sqlx::query_as::<_, HookIdentity>(
        r"
        SELECT organization_id, global_silicon_id
        FROM iam_private.get_worker_silicon_hook_identity($1, $2)
        ",
    )
    .bind(hook.id)
    .bind(&context.instance_id)
    .fetch_optional(&context.pool)
    .await?
    .ok_or(AppError::Internal {
        category: "hook_lease_lost",
    })?;
    if !renew_lease(context, hook.id).await? {
        return Ok(());
    }
    let provisioned = match context
        .hook_client
        .provision(
            hook.id,
            identity.organization_id,
            &identity.global_silicon_id,
        )
        .await
    {
        Ok(provisioned) => provisioned,
        Err(error) => {
            record_failure(context, hook, error).await?;
            return Ok(());
        }
    };
    let Ok(encrypted) = context.encryption.encrypt(
        EncryptionContext::tenant(
            ProtectedField::SiliconHookUrl,
            identity.organization_id,
            hook.id,
        ),
        provisioned.url.expose_secret().as_bytes(),
    ) else {
        record_failure(context, hook, HookError::Unavailable).await?;
        return Ok(());
    };

    sqlx::query(
        r"
        SELECT iam_private.complete_worker_silicon_hook(
            $1, $2, $3, $4, $5, $6, $7, $8, $9
        )
        ",
    )
    .bind(hook.id)
    .bind(&context.instance_id)
    .bind(provisioned.provider_hook_id)
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce.as_slice())
    .bind(encrypted.key_version)
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .execute(&context.pool)
    .await?;
    Ok(())
}

async fn renew_lease(context: &WorkerContext, hook_id: Uuid) -> Result<bool, AppError> {
    let lease_seconds =
        i64::try_from(context.settings.worker.lease_duration.as_secs()).map_err(|_| {
            AppError::Internal {
                category: "worker_lease_duration",
            }
        })?;
    let result = sqlx::query(
        r"
        UPDATE iam.silicon_hooks
        SET lease_expires_at = transaction_timestamp()
            + ($3::bigint * interval '1 second')
        WHERE id = $1
          AND status = 'provisioning'
          AND lease_owner = $2
          AND lease_expires_at > transaction_timestamp()
        ",
    )
    .bind(hook_id)
    .bind(&context.instance_id)
    .bind(lease_seconds)
    .execute(&context.pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn record_failure(
    context: &WorkerContext,
    hook: &ClaimedHook,
    error: HookError,
) -> Result<(), AppError> {
    let retryable =
        error.retryable() && hook.attempt_count < i32::from(context.settings.worker.max_attempts);
    let delay = retry_delay_seconds(
        u32::try_from(hook.attempt_count).unwrap_or(u32::MAX),
        context.settings.worker.max_retry_delay,
        hook.id,
    );
    sqlx::query(
        r"
        SELECT iam_private.fail_worker_silicon_hook($1, $2, $3, $4, $5)
        ",
    )
    .bind(hook.id)
    .bind(&context.instance_id)
    .bind(error.code())
    .bind(delay)
    .bind(retryable)
    .execute(&context.pool)
    .await?;
    Ok(())
}
