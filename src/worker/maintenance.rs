//! Bounded deletion and cryptographic erasure of expired security state.

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{config::RetentionSettings, error::AppError};

use super::WorkerContext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetentionParameters {
    login_history_days: i32,
    ephemeral_security_days: i32,
    token_metadata_days: i32,
    compromised_refresh_days: i32,
    webhook_attempt_days: i32,
    audit_event_days: i32,
    batch_size: i32,
}

#[derive(sqlx::FromRow)]
struct EphemeralMaintenanceOutcome {
    erased_secret_responses: i64,
    deleted_idempotency_records: i64,
    deleted_rate_limit_buckets: i64,
}

#[derive(sqlx::FromRow)]
struct RetentionPhaseOutcome {
    completed_phase: String,
    affected_rows: i64,
}

const RETENTION_PHASES: [&str; 21] = [
    "authentication_events",
    "signup_sessions",
    "login_challenges",
    "invitation_challenges",
    "contact_change_sessions",
    "oauth_authorization_requests",
    "sso_authorization_transactions",
    "sso_setup_sessions",
    "governance_step_up_challenges_purge",
    "governance_step_up_assertions_purge",
    "governance_webauthn_ceremonies_purge",
    "step_up_assertions_delete",
    "step_up_challenges_delete",
    "webauthn_ceremonies_delete",
    "obo_proofs",
    "access_tokens",
    "refresh_token_families",
    "webhook_delivery_attempts",
    "audit_events",
    "authentication_sessions_delete",
    "authentication_sessions_purge",
];

pub(super) async fn process_batch(context: &WorkerContext) -> Result<(), AppError> {
    let parameters = retention_parameters(&context.settings.worker.retention)?;
    let mut first_error = None;
    let ephemeral = sqlx::query_as::<_, EphemeralMaintenanceOutcome>(
        "SELECT * FROM iam_private.run_worker_ephemeral_maintenance($1)",
    )
    .bind(parameters.batch_size)
    .fetch_one(&context.pool)
    .await;
    match ephemeral {
        Ok(ephemeral) => {
            tracing::debug!(
                worker.stage = "retention_maintenance",
                erased_secret_responses = ephemeral.erased_secret_responses,
                deleted_idempotency_records = ephemeral.deleted_idempotency_records,
                deleted_rate_limit_buckets = ephemeral.deleted_rate_limit_buckets,
                "worker ephemeral maintenance batch completed"
            );
        }
        Err(error) => {
            let error = AppError::from(error);
            tracing::error!(
                error = %error,
                worker.stage = "retention_maintenance",
                retention.phase = "ephemeral_security_state",
                "worker retention phase failed"
            );
            first_error = Some(error);
        }
    }

    let phase = next_retention_phase(&context.retention_phase_cursor);
    match process_retention_phase(context, parameters, phase).await {
        Ok(outcome) => {
            tracing::debug!(
                worker.stage = "retention_maintenance",
                retention.phase = phase,
                affected_rows = outcome.affected_rows,
                "worker retention phase completed"
            );
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                worker.stage = "retention_maintenance",
                retention.phase = phase,
                "worker retention phase failed"
            );
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }

    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(())
}

async fn process_retention_phase(
    context: &WorkerContext,
    parameters: RetentionParameters,
    phase: &'static str,
) -> Result<RetentionPhaseOutcome, AppError> {
    let outcome = sqlx::query_as::<_, RetentionPhaseOutcome>(
        r"
        SELECT *
        FROM iam_private.run_worker_retention_maintenance(
            $1, $2, $3, $4, $5, $6, $7, $8
        )
        ",
    )
    .bind(phase)
    .bind(parameters.login_history_days)
    .bind(parameters.ephemeral_security_days)
    .bind(parameters.token_metadata_days)
    .bind(parameters.compromised_refresh_days)
    .bind(parameters.webhook_attempt_days)
    .bind(parameters.audit_event_days)
    .bind(parameters.batch_size)
    .fetch_one(&context.pool)
    .await?;
    if outcome.completed_phase != phase {
        return Err(AppError::Internal {
            category: "retention_phase_mismatch",
        });
    }
    Ok(outcome)
}

fn next_retention_phase(cursor: &AtomicUsize) -> &'static str {
    let position = cursor.fetch_add(1, Ordering::Relaxed);
    RETENTION_PHASES[position % RETENTION_PHASES.len()]
}

pub(super) fn retention_phase_seed(now: SystemTime, sweep_interval: Duration) -> usize {
    let sweep_seconds = sweep_interval.as_secs();
    if sweep_seconds == 0 {
        return 0;
    }
    let Ok(elapsed) = now.duration_since(UNIX_EPOCH) else {
        return 0;
    };
    let Ok(sweep_slot) = usize::try_from(elapsed.as_secs() / sweep_seconds) else {
        return 0;
    };
    sweep_slot % RETENTION_PHASES.len()
}

fn retention_parameters(settings: &RetentionSettings) -> Result<RetentionParameters, AppError> {
    let batch_size = i32::try_from(settings.batch_size.get()).map_err(|_| AppError::Internal {
        category: "maintenance_batch_size",
    })?;
    Ok(RetentionParameters {
        login_history_days: i32::from(settings.login_history_days),
        ephemeral_security_days: i32::from(settings.ephemeral_security_days),
        token_metadata_days: i32::from(settings.token_metadata_days),
        compromised_refresh_days: i32::from(settings.compromised_refresh_days),
        webhook_attempt_days: i32::from(settings.webhook_attempt_days),
        audit_event_days: i32::from(settings.audit_event_days),
        batch_size,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        num::NonZeroUsize,
        sync::atomic::AtomicUsize,
        time::{Duration, UNIX_EPOCH},
    };

    use crate::config::RetentionSettings;

    use super::{
        RETENTION_PHASES, RetentionParameters, next_retention_phase, retention_parameters,
        retention_phase_seed,
    };

    #[test]
    fn retention_phase_vocabulary_is_unique_and_closed() {
        let unique = RETENTION_PHASES.into_iter().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), RETENTION_PHASES.len());
        assert!(RETENTION_PHASES.iter().all(|phase| {
            !phase.is_empty()
                && phase
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        }));
    }

    #[test]
    fn retention_phase_cursor_rotates_in_order_and_wraps() {
        let cursor = AtomicUsize::new(0);
        for expected in RETENTION_PHASES {
            assert_eq!(next_retention_phase(&cursor), expected);
        }
        assert_eq!(next_retention_phase(&cursor), RETENTION_PHASES[0]);
        assert_eq!(next_retention_phase(&cursor), RETENTION_PHASES[1]);
    }

    #[test]
    fn retention_phase_seed_uses_the_global_sweep_slot() {
        let interval = Duration::from_secs(30);
        assert_eq!(retention_phase_seed(UNIX_EPOCH, interval), 0);
        assert_eq!(
            retention_phase_seed(UNIX_EPOCH + interval * 20, interval),
            20
        );
        assert_eq!(
            retention_phase_seed(UNIX_EPOCH + interval * 21, interval),
            0
        );
    }

    #[test]
    fn retention_phase_seed_fails_safe_for_invalid_wall_clock_inputs() {
        let Some(before_epoch) = UNIX_EPOCH.checked_sub(Duration::from_secs(1)) else {
            panic!("system time must represent one second before the Unix epoch");
        };
        assert_eq!(
            retention_phase_seed(before_epoch, Duration::from_secs(30)),
            0
        );
        assert_eq!(retention_phase_seed(UNIX_EPOCH, Duration::ZERO), 0);
    }

    #[test]
    fn configured_policy_maps_to_exact_database_arguments() {
        let Some(batch_size) = NonZeroUsize::new(77) else {
            panic!("test batch size must be nonzero");
        };
        let settings = RetentionSettings {
            sweep_interval: Duration::from_secs(60),
            batch_size,
            login_history_days: 365,
            ephemeral_security_days: 30,
            token_metadata_days: 90,
            compromised_refresh_days: 365,
            webhook_attempt_days: 45,
            audit_event_days: 2_555,
        };

        let Ok(parameters) = retention_parameters(&settings) else {
            panic!("test retention settings must fit database integer parameters");
        };
        assert_eq!(
            parameters,
            RetentionParameters {
                login_history_days: 365,
                ephemeral_security_days: 30,
                token_metadata_days: 90,
                compromised_refresh_days: 365,
                webhook_attempt_days: 45,
                audit_event_days: 2_555,
                batch_size: 77,
            }
        );
    }
}
