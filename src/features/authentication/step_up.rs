use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, SecretDigest, SecretKind},
        postgres::tokens::AccessContext,
    },
};

use super::{
    contacts,
    database::{database_conflict, serializable, set_principal_context},
    events::{self, SecurityMutation},
    idempotency::{self, Claim, IdempotencyKey},
    model::{
        AuthSessionResponse, ContactChannel, Delivery, StepUpAction, StepUpChallengeInput,
        StepUpTokenResponse, StepUpVerificationOutcome,
    },
    otp, sessions,
};

const CREATE_ROUTE: &str = "/api/v1/step-up/challenges";
const VERIFY_ROUTE: &str = "/api/v1/step-up/challenges/:session_id/verify";
const ASSERTION_TTL_SECONDS: i64 = 300;

pub(super) struct StepUpDispatch {
    pub(super) response: AuthSessionResponse,
    pub(super) delivery: Option<Delivery>,
}

#[derive(FromRow)]
struct ContactRow {
    id: Uuid,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(FromRow)]
struct ChallengeRow {
    channel: String,
    purpose: String,
    resource_id: Option<Uuid>,
    challenge_digest: Vec<u8>,
    digest_key_version: i16,
    attempt_count: i16,
    max_attempts: i16,
    status: String,
    active: bool,
}

#[derive(FromRow)]
struct CancelledChallengeRow {
    id: Uuid,
    channel: String,
    attempt_count: i16,
}

#[derive(FromRow)]
struct FailureUpdateRow {
    attempt_count: i16,
}

#[allow(
    clippy::too_many_lines,
    reason = "challenge creation, security records, and idempotency form one transaction"
)]
pub(super) async fn create_challenge(
    state: &ApiState,
    context: &AccessContext,
    key: &IdempotencyKey,
    input: StepUpChallengeInput,
) -> Result<StepUpDispatch, AppError> {
    let principal_id = sessions::carbon_context(context)?;
    let resource = input.resource_id.map(Uuid::into_bytes);
    let request_digest = idempotency::digest_parts(
        b"step-up-challenge-create",
        &[
            principal_id.as_bytes(),
            context.authentication_session_id.as_bytes(),
            input.channel.database_value().as_bytes(),
            input.action.database_value().as_bytes(),
            resource.as_ref().map_or(&[], <[u8; 16]>::as_slice),
        ],
    );
    let mut transaction = serializable(&state.pool, "step_up_create_transaction").await?;
    let record_id = match idempotency::begin::<AuthSessionResponse>(
        &mut transaction,
        &state.crypto,
        key,
        principal_id.as_bytes(),
        CREATE_ROUTE,
        request_digest,
        state.settings.providers.expose_local_otps,
    )
    .await?
    {
        Claim::Replay { response } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "step_up_create_serialization_conflict")
            })?;
            return Ok(StepUpDispatch {
                response,
                delivery: None,
            });
        }
        Claim::Acquired { record_id } => record_id,
    };
    lock_current_session(&mut transaction, context, principal_id).await?;
    set_principal_context(&mut transaction, principal_id).await?;
    let contact = active_contact(&mut transaction, principal_id, input.channel).await?;
    let recipient = contacts::decrypt_contact(
        &state.crypto,
        input.channel,
        contact.id,
        contact.encryption_key_version,
        contact.nonce,
        contact.ciphertext,
    )?;

    let challenge_id = Uuid::now_v7();
    let otp = state
        .crypto
        .generate_otp()
        .map_err(|_| AppError::Internal {
            category: "step_up_otp_generate",
        })?;
    let bound_otp = otp::bound_secret("step-up-otp", challenge_id, &otp);
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::StepUpOtp, &bound_otp)
        .map_err(|_| AppError::Internal {
            category: "step_up_otp_digest",
        })?;
    let otp_seconds = duration_seconds(state.settings.security.otp_ttl, "step_up_otp_ttl")?;
    let cancelled = sqlx::query_as::<_, CancelledChallengeRow>(
        r"
        UPDATE iam.step_up_challenges
        SET status = 'cancelled'
        WHERE authentication_session_id = $1
          AND carbon_id = $2
          AND purpose = $3
          AND resource_id IS NOT DISTINCT FROM $4
          AND status = 'pending'
        RETURNING id, channel::text AS channel, attempt_count
        ",
    )
    .bind(context.authentication_session_id)
    .bind(principal_id)
    .bind(input.action.database_value())
    .bind(input.resource_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_challenge_supersede",
    })?;
    for prior in cancelled {
        record_cancellation(
            &mut transaction,
            principal_id,
            context.authentication_session_id,
            prior,
        )
        .await?;
    }
    let max_attempts = i16::try_from(state.settings.security.otp_max_attempts).map_err(|_| {
        AppError::Internal {
            category: "step_up_otp_attempts",
        }
    })?;
    let expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        r"
        INSERT INTO iam.step_up_challenges (
            id,
            authentication_session_id,
            carbon_id,
            channel,
            purpose,
            resource_id,
            challenge_digest,
            digest_key_version,
            max_attempts,
            expires_at
        )
        VALUES (
            $1, $2, $3, $4::iam.contact_kind, $5, $6, $7, $8, $9,
            transaction_timestamp() + ($10::bigint * interval '1 second')
        )
        RETURNING expires_at
        ",
    )
    .bind(challenge_id)
    .bind(context.authentication_session_id)
    .bind(principal_id)
    .bind(input.channel.database_value())
    .bind(input.action.database_value())
    .bind(input.resource_id)
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(max_attempts)
    .bind(otp_seconds)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_challenge_create",
    })?;
    let local_otp = state
        .settings
        .providers
        .expose_local_otps
        .then(|| otp.expose_secret().to_owned());
    let response = AuthSessionResponse {
        session_id: challenge_id,
        expires_at,
        local_otp,
    };
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "step_up.challenge",
            authentication_outcome: "success",
            audit_action: "step_up.challenge_create",
            audit_result: "success",
            outbox_event: "step_up.challenge_created",
            subject_id: Some(principal_id),
            actor_id: Some(principal_id),
            authentication_session_id: Some(context.authentication_session_id),
            aggregate_type: "step_up_challenge",
            aggregate_id: challenge_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({
                "action": input.action.database_value(),
                "channel": input.channel.database_value(),
                "resource_id": input.resource_id,
            }),
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        201,
        &response,
        state.settings.providers.expose_local_otps,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "step_up_create_serialization_conflict"))?;
    Ok(StepUpDispatch {
        response,
        delivery: Some(Delivery {
            channel: input.channel,
            recipient,
            code: otp,
            purpose: "step-up",
        }),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "challenge consumption and one-time assertion issuance must be reviewed atomically"
)]
pub(super) async fn verify_challenge(
    state: &ApiState,
    context: &AccessContext,
    key: &IdempotencyKey,
    challenge_id: Uuid,
    code: SecretString,
) -> Result<StepUpVerificationOutcome, AppError> {
    let principal_id = sessions::carbon_context(context)?;
    let bound_otp = otp::bound_secret("step-up-otp", challenge_id, &code);
    let keyed_request = state
        .crypto
        .digest_secret(DigestPurpose::StepUpOtp, &bound_otp)
        .map_err(|_| AppError::Internal {
            category: "step_up_verify_request_digest",
        })?;
    let request_version = keyed_request.key_version().to_be_bytes();
    let request_digest = idempotency::digest_parts(
        b"step-up-challenge-verify",
        &[
            principal_id.as_bytes(),
            context.authentication_session_id.as_bytes(),
            challenge_id.as_bytes(),
            &request_version,
            keyed_request.as_bytes(),
        ],
    );
    let mut transaction = serializable(&state.pool, "step_up_verify_transaction").await?;
    let record_id = match idempotency::begin::<StepUpVerificationOutcome>(
        &mut transaction,
        &state.crypto,
        key,
        principal_id.as_bytes(),
        VERIFY_ROUTE,
        request_digest,
        true,
    )
    .await?
    {
        Claim::Replay { response } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "step_up_verify_serialization_conflict")
            })?;
            return Ok(response);
        }
        Claim::Acquired { record_id } => record_id,
    };
    lock_current_session(&mut transaction, context, principal_id).await?;
    let challenge = lock_challenge(
        &mut transaction,
        challenge_id,
        principal_id,
        context.authentication_session_id,
    )
    .await?;
    let Some(challenge) = challenge else {
        return Ok(StepUpVerificationOutcome::Expired);
    };
    if challenge.attempt_count >= challenge.max_attempts {
        return Err(AppError::RateLimited {
            limit: u64::try_from(challenge.max_attempts.max(1)).unwrap_or(1),
            remaining: 0,
            reset_after_seconds: state.settings.security.otp_ttl.as_secs(),
            retry_after_seconds: state.settings.security.otp_ttl.as_secs(),
        });
    }
    if challenge.status != "pending" || !challenge.active {
        return Ok(StepUpVerificationOutcome::Expired);
    }
    let expected =
        SecretDigest::from_parts(challenge.digest_key_version, &challenge.challenge_digest).ok_or(
            AppError::Internal {
                category: "step_up_otp_digest_shape",
            },
        )?;
    let matches = state
        .crypto
        .verify_secret(DigestPurpose::StepUpOtp, &bound_otp, expected)
        .map_err(|_| AppError::Internal {
            category: "step_up_otp_verify",
        })?;
    if !matches {
        let failure = sqlx::query_as::<_, FailureUpdateRow>(
            r"
            UPDATE iam.step_up_challenges
            SET attempt_count = attempt_count + 1,
                status = CASE
                    WHEN attempt_count + 1 >= max_attempts THEN 'cancelled'
                    ELSE status
                END
            WHERE id = $1
              AND status = 'pending'
              AND expires_at > transaction_timestamp()
              AND attempt_count < max_attempts
            RETURNING attempt_count
            ",
        )
        .bind(challenge_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "step_up_failure_record",
        })?
        .ok_or(AppError::Conflict {
            code: std::borrow::Cow::Borrowed("step_up_verification_race"),
        })?;
        record_failure(
            &mut transaction,
            principal_id,
            context.authentication_session_id,
            challenge_id,
            &challenge.channel,
            failure.attempt_count,
        )
        .await?;
        let outcome = StepUpVerificationOutcome::Invalid;
        idempotency::complete(
            &mut transaction,
            &state.crypto,
            record_id,
            422,
            &outcome,
            true,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_conflict(&error, "step_up_verify_serialization_conflict"))?;
        return Ok(outcome);
    }

    let assertion = state
        .crypto
        .generate_secret(SecretKind::StepUpAssertion)
        .map_err(|_| AppError::Internal {
            category: "step_up_assertion_generate",
        })?;
    let assertion_digest = state
        .crypto
        .digest_secret(DigestPurpose::StepUpAssertion, &assertion)
        .map_err(|_| AppError::Internal {
            category: "step_up_assertion_digest",
        })?;
    let challenge_update = sqlx::query(
        r"
        UPDATE iam.step_up_challenges
        SET status = 'completed', consumed_at = transaction_timestamp()
        WHERE id = $1
          AND status = 'pending'
          AND expires_at > transaction_timestamp()
        ",
    )
    .bind(challenge_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_challenge_complete",
    })?;
    if challenge_update.rows_affected() != 1 {
        return Err(AppError::Conflict {
            code: std::borrow::Cow::Borrowed("step_up_verification_race"),
        });
    }
    let assertion_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.step_up_assertions (
            id,
            step_up_challenge_id,
            authentication_session_id,
            carbon_id,
            purpose,
            token_prefix,
            token_digest,
            digest_key_version,
            assurance_level,
            expires_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, 2,
            transaction_timestamp() + ($9::bigint * interval '1 second')
        )
        ",
    )
    .bind(assertion_id)
    .bind(challenge_id)
    .bind(context.authentication_session_id)
    .bind(principal_id)
    .bind(&challenge.purpose)
    .bind(token_prefix(&assertion)?)
    .bind(assertion_digest.as_bytes().as_slice())
    .bind(assertion_digest.key_version())
    .bind(ASSERTION_TTL_SECONDS)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_assertion_create",
    })?;
    let action = parse_action(&challenge.purpose)?;
    let response = StepUpTokenResponse {
        step_up_token: assertion.expose_secret().to_owned(),
        action,
        assurance: "verified_channel".to_owned(),
        expires_in: u64::try_from(ASSERTION_TTL_SECONDS).map_err(|_| AppError::Internal {
            category: "step_up_assertion_expiry",
        })?,
    };
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "step_up.success",
            authentication_outcome: "success",
            audit_action: "step_up.challenge_verify",
            audit_result: "success",
            outbox_event: "step_up.assertion_created",
            subject_id: Some(principal_id),
            actor_id: Some(principal_id),
            authentication_session_id: Some(context.authentication_session_id),
            aggregate_type: "step_up_challenge",
            aggregate_id: challenge_id,
            aggregate_version: i64::from(challenge.attempt_count) + 2,
            failure_code: None,
            metadata: json!({
                "action": challenge.purpose,
                "assurance": "verified_channel",
                "channel": challenge.channel,
                "resource_id": challenge.resource_id,
            }),
        },
    )
    .await?;
    let outcome = StepUpVerificationOutcome::Success(response);
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        200,
        &outcome,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "step_up_verify_serialization_conflict"))?;
    Ok(outcome)
}

async fn lock_current_session(
    transaction: &mut Transaction<'_, Postgres>,
    context: &AccessContext,
    principal_id: Uuid,
) -> Result<(), AppError> {
    let locked_session_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT session.id
        FROM iam.authentication_sessions AS session
        JOIN iam.principals AS principal
          ON principal.id = session.subject_principal_id
         AND principal.kind = session.subject_kind
        WHERE session.id = $1
          AND session.subject_principal_id = $2
          AND session.subject_kind = 'carbon'
          AND session.status = 'active'
          AND session.idle_expires_at > transaction_timestamp()
          AND session.absolute_expires_at > transaction_timestamp()
          AND session.subject_auth_epoch = principal.auth_epoch
          AND principal.status = 'active'
        FOR UPDATE OF session, principal
        ",
    )
    .bind(context.authentication_session_id)
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_session_lock",
    })?;
    if locked_session_id.is_some() {
        Ok(())
    } else {
        Err(AppError::Unauthenticated)
    }
}

async fn active_contact(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    channel: ContactChannel,
) -> Result<ContactRow, AppError> {
    sqlx::query_as::<_, ContactRow>(
        r"
        SELECT id, ciphertext, nonce, encryption_key_version
        FROM iam.carbon_contacts
        WHERE carbon_id = $1
          AND kind = $2::iam.contact_kind
          AND status = 'active'
          AND is_primary
        ORDER BY verified_at DESC, id DESC
        LIMIT 1
        ",
    )
    .bind(principal_id)
    .bind(channel.database_value())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_contact_read",
    })?
    .ok_or(AppError::Forbidden)
}

async fn lock_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
    principal_id: Uuid,
    authentication_session_id: Uuid,
) -> Result<Option<ChallengeRow>, AppError> {
    sqlx::query_as::<_, ChallengeRow>(
        r"
        SELECT
            channel::text AS channel,
            purpose,
            resource_id,
            challenge_digest,
            digest_key_version,
            attempt_count,
            max_attempts,
            status,
            expires_at > transaction_timestamp() AS active
        FROM iam.step_up_challenges
        WHERE id = $1
          AND carbon_id = $2
          AND authentication_session_id = $3
        FOR UPDATE
        ",
    )
    .bind(challenge_id)
    .bind(principal_id)
    .bind(authentication_session_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_challenge_lock",
    })
}

async fn record_failure(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    authentication_session_id: Uuid,
    challenge_id: Uuid,
    channel: &str,
    attempt_count: i16,
) -> Result<(), AppError> {
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "step_up.failure",
            authentication_outcome: "failure",
            audit_action: "step_up.challenge_verify",
            audit_result: "failure",
            outbox_event: "step_up.challenge_failed",
            subject_id: Some(principal_id),
            actor_id: Some(principal_id),
            authentication_session_id: Some(authentication_session_id),
            aggregate_type: "step_up_challenge",
            aggregate_id: challenge_id,
            aggregate_version: i64::from(attempt_count) + 1,
            failure_code: Some("invalid_otp"),
            metadata: json!({
                "challenge_id": challenge_id,
                "channel": channel,
            }),
        },
    )
    .await
}

async fn record_cancellation(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    authentication_session_id: Uuid,
    challenge: CancelledChallengeRow,
) -> Result<(), AppError> {
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "step_up.cancelled",
            authentication_outcome: "denied",
            audit_action: "step_up.challenge_cancel",
            audit_result: "success",
            outbox_event: "step_up.challenge_cancelled",
            subject_id: Some(principal_id),
            actor_id: Some(principal_id),
            authentication_session_id: Some(authentication_session_id),
            aggregate_type: "step_up_challenge",
            aggregate_id: challenge.id,
            aggregate_version: i64::from(challenge.attempt_count) + 2,
            failure_code: Some("superseded"),
            metadata: json!({
                "challenge_id": challenge.id,
                "channel": challenge.channel,
            }),
        },
    )
    .await
}

fn token_prefix(token: &SecretString) -> Result<String, AppError> {
    let value = token.expose_secret();
    if value.len() != 47 || !value.starts_with("sup_") {
        return Err(AppError::Internal {
            category: "generated_step_up_token_shape",
        });
    }
    value
        .get(..12)
        .map(str::to_owned)
        .ok_or(AppError::Internal {
            category: "generated_step_up_token_shape",
        })
}

fn parse_action(value: &str) -> Result<StepUpAction, AppError> {
    match value {
        "account.contact_change" => Ok(StepUpAction::AccountContactChange),
        "account.delete" => Ok(StepUpAction::AccountDelete),
        "organization.transfer_ownership" => Ok(StepUpAction::OrganizationTransferOwnership),
        "organization.authorization_change" => Ok(StepUpAction::OrganizationAuthorizationChange),
        "organization.sso_change" => Ok(StepUpAction::OrganizationSsoChange),
        "silicon.rotate_token" => Ok(StepUpAction::SiliconRotateToken),
        "application.delete" => Ok(StepUpAction::ApplicationDelete),
        "application.rotate_secret" => Ok(StepUpAction::ApplicationRotateSecret),
        "application.manage_collaborators" => Ok(StepUpAction::ApplicationManageCollaborators),
        "platform_admin.manage" => Ok(StepUpAction::PlatformAdminManage),
        "platform_admin.application_review" => Ok(StepUpAction::PlatformAdminApplicationReview),
        _ => Err(AppError::Internal {
            category: "step_up_action",
        }),
    }
}

fn duration_seconds(
    duration: std::time::Duration,
    category: &'static str,
) -> Result<i64, AppError> {
    i64::try_from(duration.as_secs()).map_err(|_| AppError::Internal { category })
}

#[cfg(test)]
mod tests {
    use super::{StepUpAction, parse_action};

    #[test]
    fn persisted_actions_use_the_closed_public_vocabulary() {
        assert!(matches!(
            parse_action("application.rotate_secret"),
            Ok(StepUpAction::ApplicationRotateSecret)
        ));
        assert!(parse_action("application.rotate-anything").is_err());
    }
}
