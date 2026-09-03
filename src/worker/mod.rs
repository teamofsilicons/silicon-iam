//! Durable outbox, webhook, notification, and maintenance worker.

mod maintenance;
mod notification;
mod outbox;
mod testing_environments;
mod webhook;

use std::sync::{Arc, atomic::AtomicUsize};

use sqlx::PgPool;
use tokio::{
    sync::Mutex,
    task::{JoinError, JoinSet},
    time::{Instant, MissedTickBehavior},
};
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    config::WorkerProcessSettings,
    infrastructure::{crypto::EncryptionService, postgres, providers::NotificationProviders},
    shutdown,
};

pub(super) struct WorkerContext {
    pool: PgPool,
    /// Shared testing database, present only where the feature is deployed.
    ///
    /// The worker reaches it for exactly one purpose: erasing an environment
    /// whose recovery window has closed. No delivery, outbox or retention
    /// stage runs against it, which is what keeps a testing environment from
    /// ever sending a real message or a real webhook.
    testing_pool: Option<PgPool>,
    settings: Arc<WorkerProcessSettings>,
    encryption: Arc<EncryptionService>,
    notifications: NotificationProviders,
    outbound_stage_lock: Mutex<()>,
    retention_phase_cursor: AtomicUsize,
    instance_id: String,
}

fn delivery_claim_limit(context: &WorkerContext) -> Result<i64, crate::error::AppError> {
    let claim_limit = context
        .settings
        .worker
        .batch_size
        .get()
        .min(context.settings.worker.delivery_concurrency.get());
    i64::try_from(claim_limit).map_err(|_| crate::error::AppError::Internal {
        category: "worker_delivery_claim_limit",
    })
}

/// Runs durable worker stages until coordinated shutdown.
///
/// # Errors
///
/// Returns an error when dependencies cannot be initialized or shutdown signal
/// registration fails. Individual jobs retain retry/dead-letter state instead
/// of terminating the process.
pub async fn run(settings: WorkerProcessSettings) -> anyhow::Result<()> {
    let pool = postgres::connect(&settings.database, "iam-worker").await?;
    if !postgres::ready(&pool).await {
        anyhow::bail!("database migrations are not current");
    }
    postgres::register_runtime_encryption_key_versions(&pool, &settings.encryption_keys).await?;
    let testing_pool = match settings.testing.as_ref() {
        Some(testing) => Some(postgres::connect(&testing.database, "iam-worker-testing").await?),
        None => None,
    };
    let encryption = EncryptionService::from_settings(&settings.encryption_keys)?;
    let notifications = NotificationProviders::from_worker_settings(&settings.providers)?;
    let poll_interval = settings.worker.poll_interval;
    let retention_sweep_interval = settings.worker.retention.sweep_interval;
    let retention_phase_seed =
        maintenance::retention_phase_seed(std::time::SystemTime::now(), retention_sweep_interval);
    let shutdown_timeout = settings.shutdown_timeout;
    let context = Arc::new(WorkerContext {
        pool,
        testing_pool,
        settings: Arc::new(settings),
        encryption: Arc::new(encryption),
        notifications,
        outbound_stage_lock: Mutex::new(()),
        retention_phase_cursor: AtomicUsize::new(retention_phase_seed),
        instance_id: format!("iam-worker-{}", Uuid::now_v7()),
    });
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut maintenance_ticker = tokio::time::interval_at(
        Instant::now() + retention_sweep_interval,
        retention_sweep_interval,
    );
    maintenance_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut cycle_tasks = JoinSet::new();
    let mut cycle_in_flight = false;

    info!(worker.instance_id = %context.instance_id, "Silicon IAM worker started");
    let shutdown = shutdown::signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            result = &mut shutdown => {
                result?;
                break;
            }
            result = cycle_tasks.join_next(), if cycle_in_flight => {
                cycle_in_flight = false;
                if let Some(result) = result {
                    report_worker_task_result(result);
                }
            }
            _ = maintenance_ticker.tick(), if !cycle_in_flight => {
                let cycle_context = Arc::clone(&context);
                cycle_tasks.spawn(async move {
                    run_maintenance(&cycle_context).await;
                });
                cycle_in_flight = true;
            }
            _ = ticker.tick(), if !cycle_in_flight => {
                let cycle_context = Arc::clone(&context);
                cycle_tasks.spawn(async move {
                    run_once(&cycle_context).await;
                });
                cycle_in_flight = true;
            }
        }
    }

    info!(
        worker.instance_id = %context.instance_id,
        "Silicon IAM worker stopped claiming and is draining"
    );
    let shutdown_deadline = Instant::now() + shutdown_timeout;
    if !drain_worker_tasks(&mut cycle_tasks, shutdown_deadline).await {
        error!("worker shutdown deadline elapsed; aborted the in-flight cycle");
    }
    if tokio::time::timeout_at(shutdown_deadline, context.pool.close())
        .await
        .is_err()
    {
        error!("worker shutdown deadline elapsed while closing database pool");
    }
    if let Some(testing_pool) = context.testing_pool.as_ref()
        && tokio::time::timeout_at(shutdown_deadline, testing_pool.close())
            .await
            .is_err()
    {
        error!("worker shutdown deadline elapsed while closing testing database pool");
    }
    Ok(())
}

async fn drain_worker_tasks(tasks: &mut JoinSet<()>, deadline: Instant) -> bool {
    let drained = tokio::time::timeout_at(deadline, async {
        while let Some(result) = tasks.join_next().await {
            report_worker_task_result(result);
        }
    })
    .await
    .is_ok();
    if drained {
        return true;
    }

    tasks.abort_all();
    tasks.detach_all();
    false
}

fn report_worker_task_result(result: Result<(), JoinError>) {
    if let Err(error) = result {
        if error.is_cancelled() {
            return;
        }
        error!(error = %error, "worker cycle task failed");
    }
}

async fn run_maintenance(context: &WorkerContext) {
    if let Err(error) = maintenance::process_batch(context).await {
        error!(error = %error, worker.stage = "retention_maintenance", "worker stage failed");
    }
    if let Err(error) = testing_environments::process_batch(context).await {
        error!(
            error = %error,
            worker.stage = "testing_environment_maintenance",
            "worker stage failed"
        );
    }
}

async fn run_once(context: &WorkerContext) {
    let (notification_result, outbox_result, webhook_result) = tokio::join!(
        notification::process_batch(context),
        outbox::process_batch(context),
        webhook::process_batch(context),
    );
    if let Err(error) = outbox_result {
        error!(error = %error, worker.stage = "outbox_expansion", "worker stage failed");
    }
    if let Err(error) = notification_result {
        error!(error = %error, worker.stage = "notification_delivery", "worker stage failed");
    }
    if let Err(error) = webhook_result {
        error!(error = %error, worker.stage = "webhook_delivery", "worker stage failed");
    }
}

pub(super) fn retry_delay_seconds(attempt: u32, maximum: std::time::Duration, id: Uuid) -> i64 {
    use sha2::{Digest as _, Sha256};

    let exponent = attempt.saturating_sub(1).min(20);
    let base = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let capped = base.min(maximum.as_secs().max(1));
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(attempt.to_be_bytes());
    let digest = hasher.finalize();
    let jitter_percent = 75_u64 + u64::from(digest[0] % 51);
    let jittered = capped.saturating_mul(jitter_percent).div_ceil(100);
    i64::try_from(jittered.max(1)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_positive_deterministic_and_capped_with_jitter() {
        let id = Uuid::nil();
        let first = retry_delay_seconds(10, std::time::Duration::from_secs(60), id);
        let second = retry_delay_seconds(10, std::time::Duration::from_secs(60), id);
        assert_eq!(first, second);
        assert!((1..=75).contains(&first));
    }

    #[tokio::test]
    async fn shutdown_drain_completes_finished_cycle() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async {});

        let drained = drain_worker_tasks(
            &mut tasks,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;

        assert!(drained);
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn shutdown_drain_aborts_cycle_at_deadline() {
        let mut tasks = JoinSet::new();
        tasks.spawn(std::future::pending());

        let drained = drain_worker_tasks(
            &mut tasks,
            Instant::now() + std::time::Duration::from_millis(1),
        )
        .await;

        assert!(!drained);
        assert!(tasks.is_empty());
    }
}
