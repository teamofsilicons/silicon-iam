//! PostgreSQL-backed distributed fixed-window abuse controls.

use std::{num::NonZeroU32, time::Duration};

use secrecy::SecretString;
use sqlx::PgPool;
use thiserror::Error;

use crate::{
    error::AppError,
    infrastructure::crypto::{CryptoService, DigestPurpose},
};

const MAX_WINDOW: Duration = Duration::from_hours(24);

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
    .fetch_one(pool)
    .await?;

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
    use super::*;

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
            Duration::from_secs(60),
            Duration::from_secs(61),
        );

        assert_eq!(result, Err(RateLimitPolicyError::InvalidBlockDuration));
    }

    #[test]
    fn policy_accepts_bounded_whole_second_durations() {
        let result = RateLimitPolicy::new(
            NonZeroU32::MIN,
            Duration::from_secs(60),
            Duration::from_secs(30),
        );

        assert!(result.is_ok());
    }
}
