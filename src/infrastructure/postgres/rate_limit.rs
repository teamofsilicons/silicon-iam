//! PostgreSQL-backed distributed abuse controls.

use std::{num::NonZeroU32, time::Duration};

use secrecy::SecretString;
use sqlx::PgPool;
use thiserror::Error;

use crate::{
    error::AppError,
    infrastructure::crypto::{CryptoService, DigestPurpose},
};

const MAX_WINDOW: Duration = Duration::from_hours(24);
const BURST_COOLDOWN_CONSUMPTION_SQL: &str = r"
    WITH timing AS MATERIALIZED (
        SELECT transaction_timestamp() AS current_time
    ), consumed AS (
        INSERT INTO iam.rate_limit_buckets (
            scope_digest,
            limit_name,
            window_started_at,
            request_count,
            blocked_until,
            expires_at,
            updated_at
        )
        SELECT
            $1,
            $2,
            timestamptz '1970-01-01 00:00:00+00',
            1,
            CASE
                WHEN $3 = 1
                    THEN timing.current_time + ($5::bigint * interval '1 second')
                ELSE NULL
            END,
            timing.current_time
                + (($4 + $5)::bigint * interval '1 second')
                + interval '1 hour',
            timing.current_time
        FROM timing
        ON CONFLICT (scope_digest, limit_name, window_started_at)
        DO UPDATE SET
            request_count = CASE
                WHEN iam.rate_limit_buckets.blocked_until > transaction_timestamp()
                    THEN $3 + 1
                WHEN iam.rate_limit_buckets.blocked_until IS NOT NULL
                    OR iam.rate_limit_buckets.updated_at
                        + ($4::bigint * interval '1 second') <= transaction_timestamp()
                    THEN 1
                ELSE LEAST(iam.rate_limit_buckets.request_count + 1, $3 + 1)
            END,
            blocked_until = CASE
                WHEN iam.rate_limit_buckets.blocked_until > transaction_timestamp()
                    THEN iam.rate_limit_buckets.blocked_until
                WHEN iam.rate_limit_buckets.blocked_until IS NOT NULL
                    OR iam.rate_limit_buckets.updated_at
                        + ($4::bigint * interval '1 second') <= transaction_timestamp()
                    THEN CASE
                        WHEN $3 = 1
                            THEN transaction_timestamp()
                                + ($5::bigint * interval '1 second')
                        ELSE NULL
                    END
                WHEN iam.rate_limit_buckets.request_count + 1 >= $3
                    THEN transaction_timestamp()
                        + ($5::bigint * interval '1 second')
                ELSE NULL
            END,
            expires_at = transaction_timestamp()
                + (($4 + $5)::bigint * interval '1 second')
                + interval '1 hour',
            updated_at = CASE
                WHEN iam.rate_limit_buckets.blocked_until IS NOT NULL
                    OR iam.rate_limit_buckets.updated_at
                        + ($4::bigint * interval '1 second') <= transaction_timestamp()
                    THEN transaction_timestamp()
                ELSE iam.rate_limit_buckets.updated_at
            END
        RETURNING request_count, blocked_until
    )
    SELECT
        consumed.request_count <= $3 AS allowed,
        consumed.request_count::bigint AS request_count,
        CASE
            WHEN consumed.request_count > $3
                THEN GREATEST(
                    1,
                    CEIL(EXTRACT(EPOCH FROM consumed.blocked_until - timing.current_time))
                )::bigint
            ELSE 0
        END AS retry_after_seconds
    FROM consumed
    CROSS JOIN timing
";

/// Validated fixed-window rate-limit policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitPolicy {
    maximum_requests: NonZeroU32,
    window: Duration,
    block_for: Duration,
}

/// Invalid rate-limit policy configuration.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RateLimitPolicyError {
    /// Windows must be representable as whole seconds and no longer than a day.
    #[error("the rate-limit window must be between one second and 24 hours")]
    InvalidWindow,
    /// A block may not outlive the fixed window that owns it.
    #[error("the rate-limit block duration must be between one second and the window duration")]
    InvalidBlockDuration,
}

/// Result of consuming one request from a rate-limit bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitState {
    /// Requests still available in the active window.
    pub remaining: u32,
}

#[derive(sqlx::FromRow)]
struct ConsumptionRow {
    allowed: bool,
    request_count: i64,
    retry_after_seconds: i64,
}

impl RateLimitPolicy {
    /// Creates a bounded fixed-window policy.
    ///
    /// # Errors
    ///
    /// Returns an error for sub-second, zero, or excessively long durations,
    /// or when the block duration exceeds its owning window.
    pub fn new(
        maximum_requests: NonZeroU32,
        window: Duration,
        block_for: Duration,
    ) -> Result<Self, RateLimitPolicyError> {
        if window.is_zero() || window > MAX_WINDOW || window.subsec_nanos() != 0 {
            return Err(RateLimitPolicyError::InvalidWindow);
        }
        if block_for.is_zero() || block_for > window || block_for.subsec_nanos() != 0 {
            return Err(RateLimitPolicyError::InvalidBlockDuration);
        }
        Ok(Self {
            maximum_requests,
            window,
            block_for,
        })
    }
}

/// Atomically consumes one request from a distributed fixed-window bucket.
///
/// The raw scope is keyed before persistence so IP addresses, contact points,
/// and actor identifiers never appear in the rate-limit table. Callers should
/// use a stable, unambiguous scope representation for each `limit_name`.
///
/// # Errors
///
/// Returns [`AppError::RateLimited`] when the policy is exhausted, or a safe
/// internal error when cryptography or PostgreSQL is unavailable.
pub async fn enforce(
    pool: &PgPool,
    crypto: &CryptoService,
    limit_name: &'static str,
    raw_scope: &SecretString,
    policy: RateLimitPolicy,
) -> Result<RateLimitState, AppError> {
    let scope_digest = crypto
        .digest_secret(DigestPurpose::RateLimitScope, raw_scope)
        .map_err(|_| AppError::Internal {
            category: "rate_limit_digest",
        })?;
    let maximum_requests = i64::from(policy.maximum_requests.get());
    let window_seconds = duration_seconds(policy.window)?;
    let block_seconds = duration_seconds(policy.block_for)?;

    // The bucket write needs its own transaction rather than a bare pool
    // statement: the testing-environment scope is transaction-local, and a
    // request inside an environment must land its bucket there. The consumption
    // statement is atomic on its own, so the transaction adds no contention.
    let mut transaction = super::context::begin_scoped(pool).await?;
    let row = sqlx::query_as::<_, ConsumptionRow>(
        r"
        WITH timing AS MATERIALIZED (
            SELECT
                transaction_timestamp() AS current_time,
                date_bin(
                    $4::bigint * interval '1 second',
                    transaction_timestamp(),
                    timestamptz '1970-01-01 00:00:00+00'
                ) AS window_started_at
        ), consumed AS (
            INSERT INTO iam.rate_limit_buckets (
                scope_digest,
                limit_name,
                window_started_at,
                request_count,
                blocked_until,
                expires_at,
                updated_at
            )
            SELECT
                $1,
                $2,
                timing.window_started_at,
                1,
                NULL,
                timing.window_started_at + ($4::bigint * interval '1 second')
                    + interval '1 hour',
                timing.current_time
            FROM timing
            ON CONFLICT (scope_digest, limit_name, window_started_at)
            DO UPDATE SET
                request_count = iam.rate_limit_buckets.request_count + 1,
                blocked_until = CASE
                    WHEN iam.rate_limit_buckets.blocked_until > transaction_timestamp()
                        THEN iam.rate_limit_buckets.blocked_until
                    WHEN iam.rate_limit_buckets.request_count + 1 > $3
                        THEN GREATEST(
                            iam.rate_limit_buckets.window_started_at
                                + ($4::bigint * interval '1 second'),
                            transaction_timestamp()
                                + ($5::bigint * interval '1 second')
                        )
                    ELSE NULL
                END,
                updated_at = transaction_timestamp()
            RETURNING request_count, blocked_until
        )
        SELECT
            consumed.request_count <= $3
                AND (
                    consumed.blocked_until IS NULL
                    OR consumed.blocked_until <= timing.current_time
                ) AS allowed,
            consumed.request_count::bigint AS request_count,
            COALESCE(
                CEIL(EXTRACT(EPOCH FROM consumed.blocked_until - timing.current_time)),
                0
            )::bigint AS retry_after_seconds
        FROM consumed
        CROSS JOIN timing
        ",
    )
    .bind(scope_digest.as_bytes().as_slice())
    .bind(limit_name)
    .bind(maximum_requests)
    .bind(window_seconds)
    .bind(block_seconds)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;

    if !row.allowed {
        let retry_after_seconds = u64::try_from(row.retry_after_seconds.max(1)).unwrap_or(1);
        return Err(AppError::RateLimited {
            limit: u64::from(policy.maximum_requests.get()),
            remaining: 0,
            reset_after_seconds: retry_after_seconds,
            retry_after_seconds,
        });
    }

    let remaining = maximum_requests.saturating_sub(row.request_count);
    Ok(RateLimitState {
        remaining: u32::try_from(remaining).unwrap_or(0),
    })
}

/// Atomically consumes one request from a burst bucket with a post-limit cooldown.
///
/// Unlike [`enforce`], this policy does not align its accounting interval to a
/// wall-clock boundary. The first request starts the interval. The request that
/// reaches the limit is allowed and starts `block_for`; every later request is
/// rejected until that complete cooldown elapses. This is appropriate for OTP
/// sends, where crossing a fixed-window boundary must not evade a cooldown.
///
/// The raw scope is keyed before persistence. Callers must include every actor
/// and resource dimension that should share one abuse budget.
///
/// # Errors
///
/// Returns [`AppError::RateLimited`] while the bucket is cooling down, or a safe
/// internal error when cryptography or PostgreSQL is unavailable.
#[allow(
    clippy::too_many_lines,
    reason = "the atomic PostgreSQL cooldown state machine is kept next to its bindings"
)]
pub async fn enforce_burst_cooldown(
    pool: &PgPool,
    crypto: &CryptoService,
    limit_name: &'static str,
    raw_scope: &SecretString,
    policy: RateLimitPolicy,
) -> Result<RateLimitState, AppError> {
    let scope_digest = crypto
        .digest_secret(DigestPurpose::RateLimitScope, raw_scope)
        .map_err(|_| AppError::Internal {
            category: "rate_limit_digest",
        })?;
    let maximum_requests = i64::from(policy.maximum_requests.get());
    let interval_seconds = duration_seconds(policy.window)?;
    let block_seconds = duration_seconds(policy.block_for)?;

    // The bucket write needs its own transaction rather than a bare pool
    // statement: the testing-environment scope is transaction-local, and a
    // request inside an environment must land its bucket there. The consumption
    // statement is atomic on its own, so the transaction adds no contention.
    let mut transaction = super::context::begin_scoped(pool).await?;
    let row = sqlx::query_as::<_, ConsumptionRow>(BURST_COOLDOWN_CONSUMPTION_SQL)
        .bind(scope_digest.as_bytes().as_slice())
        .bind(limit_name)
        .bind(maximum_requests)
        .bind(interval_seconds)
        .bind(block_seconds)
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;

    if !row.allowed {
        let retry_after_seconds = u64::try_from(row.retry_after_seconds.max(1)).unwrap_or(1);
        return Err(AppError::RateLimited {
            limit: u64::from(policy.maximum_requests.get()),
            remaining: 0,
            reset_after_seconds: retry_after_seconds,
            retry_after_seconds,
        });
    }

    let remaining = maximum_requests.saturating_sub(row.request_count);
    Ok(RateLimitState {
        remaining: u32::try_from(remaining).unwrap_or(0),
    })
}

fn duration_seconds(duration: Duration) -> Result<i64, AppError> {
    i64::try_from(duration.as_secs()).map_err(|_| AppError::Internal {
        category: "rate_limit_policy",
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use anyhow::ensure;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres;

    use super::*;
    use crate::config::{KeyringSettings, SecuritySettings};

    fn crypto() -> CryptoService {
        let keyring = |byte| KeyringSettings {
            current_version: 1,
            keys: BTreeMap::from([(1, SecretString::from(URL_SAFE_NO_PAD.encode([byte; 32])))]),
        };
        let settings = SecuritySettings {
            token_peppers: keyring(11),
            blind_index_keys: keyring(21),
            encryption_keys: keyring(31),
            cookie_key: SecretString::from(URL_SAFE_NO_PAD.encode([41_u8; 32])),
            access_token_ttl: Duration::from_mins(30),
            refresh_family_ttl: Duration::from_hours(2_160),
            authorization_code_ttl: Duration::from_mins(2),
            otp_ttl: Duration::from_mins(10),
            otp_max_attempts: 10,
        };
        let Ok(crypto) = CryptoService::from_settings(&settings) else {
            panic!("valid test keyrings must initialize");
        };
        crypto
    }

    #[test]
    fn policy_rejects_subsecond_windows() {
        let result = RateLimitPolicy::new(
            NonZeroU32::MIN,
            Duration::from_millis(500),
            Duration::from_millis(500),
        );

        assert_eq!(result, Err(RateLimitPolicyError::InvalidWindow));
    }

    #[test]
    fn policy_rejects_blocks_longer_than_the_window() {
        let result = RateLimitPolicy::new(
            NonZeroU32::MIN,
            Duration::from_mins(1),
            Duration::from_secs(61),
        );

        assert_eq!(result, Err(RateLimitPolicyError::InvalidBlockDuration));
    }

    #[test]
    fn policy_accepts_bounded_whole_second_durations() {
        let result = RateLimitPolicy::new(
            NonZeroU32::MIN,
            Duration::from_mins(1),
            Duration::from_secs(30),
        );

        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    async fn burst_cooldown_survives_the_accounting_interval_boundary() -> anyhow::Result<()> {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        super::super::migrate(&pool).await?;

        let crypto = crypto();
        let policy = RateLimitPolicy::new(
            NonZeroU32::new(10).ok_or_else(|| anyhow::anyhow!("invalid test limit"))?,
            Duration::from_mins(1),
            Duration::from_mins(1),
        )?;
        let scope = SecretString::from("carbon=one:organization=acme");
        for expected_remaining in (0_u32..10).rev() {
            let consumed =
                enforce_burst_cooldown(&pool, &crypto, "test_email_join_send", &scope, policy)
                    .await?;
            assert_eq!(consumed.remaining, expected_remaining);
        }

        let Err(AppError::RateLimited {
            retry_after_seconds,
            ..
        }) = enforce_burst_cooldown(&pool, &crypto, "test_email_join_send", &scope, policy).await
        else {
            anyhow::bail!("the eleventh request must enter cooldown");
        };
        ensure!((1..=60).contains(&retry_after_seconds));

        sqlx::query(
            "UPDATE iam.rate_limit_buckets SET updated_at = transaction_timestamp() - interval '61 seconds' WHERE limit_name = 'test_email_join_send'",
        )
        .execute(&pool)
        .await?;
        ensure!(
            matches!(
                enforce_burst_cooldown(&pool, &crypto, "test_email_join_send", &scope, policy,)
                    .await,
                Err(AppError::RateLimited { .. })
            ),
            "an active cooldown must survive the accounting interval boundary"
        );

        sqlx::query(
            "UPDATE iam.rate_limit_buckets SET blocked_until = transaction_timestamp() - interval '1 second' WHERE limit_name = 'test_email_join_send'",
        )
        .execute(&pool)
        .await?;
        let reset =
            enforce_burst_cooldown(&pool, &crypto, "test_email_join_send", &scope, policy).await?;
        assert_eq!(reset.remaining, 9);
        Ok(())
    }
}
