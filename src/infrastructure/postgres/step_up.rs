//! Atomic validation and consumption of action-bound step-up assertions.

use std::borrow::Cow;

use secrecy::SecretString;
use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    error::AppError,
    infrastructure::crypto::{CryptoService, DigestPurpose},
};

/// Opaque step-up assertion token accepted from `X-Step-Up-Token`.
pub struct StepUpToken(SecretString);

/// Invalid step-up token wire shape.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StepUpTokenError {
    /// Tokens use `sup_` followed by 43 base64url characters.
    #[error("the step-up token has an invalid format")]
    InvalidFormat,
}

/// Minimum assurance required by a privileged operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i16)]
pub enum RequiredAssurance {
    /// A recently verified Carbon contact channel.
    VerifiedChannel = 2,
}

/// Exact actor, action, resource, and assurance binding for a privileged call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepUpExpectation {
    /// Carbon performing the privileged mutation.
    pub carbon_id: Uuid,
    /// Current interactive authentication session.
    pub authentication_session_id: Uuid,
    /// Closed action string issued with the challenge.
    pub action: &'static str,
    /// Optional aggregate to which the action is restricted.
    pub resource_id: Option<Uuid>,
    /// Minimum acceptable authentication assurance.
    pub required_assurance: RequiredAssurance,
}

#[derive(Clone, Debug, FromRow)]
struct PrincipalAuthority {
    status: String,
    auth_epoch: i64,
}

#[derive(Clone, Debug, FromRow)]
struct SessionAuthority {
    status: String,
    idle_active: bool,
    absolute_active: bool,
    subject_auth_epoch: i64,
}

fn authority_is_active(principal: &PrincipalAuthority, session: &SessionAuthority) -> bool {
    principal.status == "active"
        && session.status == "active"
        && session.idle_active
        && session.absolute_active
        && session.subject_auth_epoch == principal.auth_epoch
}

impl StepUpToken {
    /// Parses the exact public step-up token shape without normalizing it.
    ///
    /// # Errors
    ///
    /// Returns [`StepUpTokenError::InvalidFormat`] for malformed input.
    pub fn parse(value: &str) -> Result<Self, StepUpTokenError> {
        let encoded = value
            .strip_prefix("sup_")
            .ok_or(StepUpTokenError::InvalidFormat)?;
        if encoded.len() != 43
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(StepUpTokenError::InvalidFormat);
        }
        Ok(Self(SecretString::from(value.to_owned())))
    }
}

/// Atomically consumes a step-up assertion with its protected mutation.
///
/// The token is bound to the current Carbon, authentication session, exact
/// action, optional resource, minimum assurance, and a five-minute database
/// expiry. The caller must commit this update in the same transaction as the
/// privileged operation so a failed mutation does not burn the assertion.
///
/// # Errors
///
/// Returns a precondition failure for an invalid, expired, already consumed,
/// mismatched, or insufficient-assurance assertion.
pub async fn consume(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    token: &StepUpToken,
    expectation: StepUpExpectation,
) -> Result<Uuid, AppError> {
    lock_active_authority(transaction, expectation).await?;
    let digests = crypto
        .digest_secrets(DigestPurpose::StepUpAssertion, &token.0)
        .map_err(|_| AppError::Internal {
            category: "step_up_digest",
        })?;

    for digest in digests {
        let assertion_id = sqlx::query_scalar::<_, Uuid>(
            r"
            WITH candidate AS (
                SELECT assertion.id
                FROM iam.step_up_assertions AS assertion
                JOIN iam.step_up_challenges AS challenge
                  ON challenge.id = assertion.step_up_challenge_id
                 AND challenge.authentication_session_id = assertion.authentication_session_id
                 AND challenge.carbon_id = assertion.carbon_id
                 AND challenge.purpose = assertion.purpose
                WHERE assertion.digest_key_version = $1
                  AND assertion.token_digest = $2
                  AND assertion.carbon_id = $3
                  AND assertion.authentication_session_id = $4
                  AND assertion.purpose = $5
                  AND assertion.assurance_level >= $7
                  AND assertion.consumed_at IS NULL
                  AND assertion.expires_at > transaction_timestamp()
                  AND challenge.status = 'completed'
                  AND challenge.resource_id IS NOT DISTINCT FROM $6
                FOR UPDATE OF assertion
            )
            UPDATE iam.step_up_assertions AS assertion
            SET consumed_at = transaction_timestamp()
            FROM candidate
            WHERE assertion.id = candidate.id
            RETURNING assertion.id
            ",
        )
        .bind(digest.key_version())
        .bind(digest.as_bytes().as_slice())
        .bind(expectation.carbon_id)
        .bind(expectation.authentication_session_id)
        .bind(expectation.action)
        .bind(expectation.resource_id)
        .bind(expectation.required_assurance as i16)
        .fetch_optional(&mut **transaction)
        .await?;

        if let Some(assertion_id) = assertion_id {
            return Ok(assertion_id);
        }
    }

    Err(AppError::PreconditionFailed {
        code: Cow::Borrowed("step_up_invalid"),
    })
}

async fn lock_active_authority(
    transaction: &mut Transaction<'_, Postgres>,
    expectation: StepUpExpectation,
) -> Result<(), AppError> {
    // Use the same principal-before-session lock order as lifecycle changes so
    // suspension and revocation serialize without creating an inverted lock order.
    let principal = sqlx::query_as::<_, PrincipalAuthority>(
        r"
        SELECT status, auth_epoch
        FROM iam.principals
        WHERE id = $1 AND kind = 'carbon'
        FOR UPDATE
        ",
    )
    .bind(expectation.carbon_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(principal) = principal else {
        return Err(invalid_step_up());
    };

    let session = sqlx::query_as::<_, SessionAuthority>(
        r"
        SELECT
            status,
            idle_expires_at > transaction_timestamp() AS idle_active,
            absolute_expires_at > transaction_timestamp() AS absolute_active,
            subject_auth_epoch
        FROM iam.authentication_sessions
        WHERE id = $1
          AND subject_principal_id = $2
          AND subject_kind = 'carbon'
        FOR UPDATE
        ",
    )
    .bind(expectation.authentication_session_id)
    .bind(expectation.carbon_id)
    .fetch_optional(&mut **transaction)
    .await?;

    if session.is_some_and(|session| authority_is_active(&principal, &session)) {
        Ok(())
    } else {
        Err(invalid_step_up())
    }
}

fn invalid_step_up() -> AppError {
    AppError::PreconditionFailed {
        code: Cow::Borrowed("step_up_invalid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_exact_step_up_wire_shape() {
        assert!(StepUpToken::parse("sup_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok());
        assert!(StepUpToken::parse("obo_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
        assert!(StepUpToken::parse("sup_too-short").is_err());
    }

    #[test]
    fn authority_must_remain_active_and_epoch_current() {
        let principal = PrincipalAuthority {
            status: "active".to_owned(),
            auth_epoch: 7,
        };
        let session = SessionAuthority {
            status: "active".to_owned(),
            idle_active: true,
            absolute_active: true,
            subject_auth_epoch: 7,
        };
        assert!(authority_is_active(&principal, &session));

        for inactive_session in [
            SessionAuthority {
                status: "revoked".to_owned(),
                ..session.clone()
            },
            SessionAuthority {
                idle_active: false,
                ..session.clone()
            },
            SessionAuthority {
                absolute_active: false,
                ..session.clone()
            },
            SessionAuthority {
                subject_auth_epoch: 6,
                ..session
            },
        ] {
            assert!(!authority_is_active(&principal, &inactive_session));
        }

        let suspended = PrincipalAuthority {
            status: "suspended".to_owned(),
            ..principal
        };
        assert!(!authority_is_active(
            &suspended,
            &SessionAuthority {
                status: "active".to_owned(),
                idle_active: true,
                absolute_active: true,
                subject_auth_epoch: 7,
            }
        ));
    }
}
