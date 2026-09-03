use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::auth::OTP_COOLDOWN_SECONDS,
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, SecretDigest, SecretKind},
        postgres::tokens::AccessContext,
    },
};

use super::{
    contacts,
    database::{database_conflict, serializable, set_principal_context},
    delivery,
    events::{self, SecurityMutation},
    idempotency::{self, Claim, IdempotencyKey, Outcome},
    model::{
        AuthSessionResponse, ContactChannel, Delivery, StepUpAction, StepUpChallengeInput,
        StepUpTokenResponse, StepUpVerificationOutcome,
    },
    otp, sessions,
};

const CREATE_ROUTE: &str = "POST /api/v1/step-up/challenges";
const VERIFY_ROUTE: &str = "POST /api/v1/step-up/challenges/{session_id}/verify";
const ASSERTION_TTL_SECONDS: i64 = 300;
const STEP_UP_CHALLENGE_LOCK_QUERY: &str = r"
    SELECT
        channel::text AS channel,
        purpose,
        resource_id,
        challenge_digest,
        digest_key_version,
        provider_verification_sid,
        max_attempts,
        status,
        expires_at > transaction_timestamp()
            AND delivery_status = 'delivered' AS active,
        CASE
            WHEN status = 'pending'
                 AND expires_at > transaction_timestamp()
                 AND cooldown_until > transaction_timestamp()
                THEN GREATEST(
                    1,
                    CEIL(EXTRACT(EPOCH FROM cooldown_until - transaction_timestamp()))::bigint
                )
            ELSE 0
        END AS cooldown_retry_after_seconds
    FROM iam.step_up_challenges
    WHERE id = $1
      AND carbon_id = $2
      AND authentication_session_id = $3
    FOR UPDATE
";
const SESSION_RESOURCE_OWNERSHIP_QUERY: &str = r"
    SELECT id
    FROM iam.authentication_sessions
    WHERE id = $1
      AND subject_principal_id = $2
      AND subject_kind = 'carbon'
    FOR SHARE
";
const APPLICATION_RESOURCE_OWNERSHIP_QUERY: &str = r"
    SELECT application.id
    FROM iam.applications AS application
    WHERE application.id = $1
      AND iam_private.is_active_organization_owner_or_admin(
          application.organization_id,
          $2
      )
      AND application.deleted_at IS NULL
    FOR SHARE OF application
";

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
    challenge_digest: Option<Vec<u8>>,
    digest_key_version: Option<i16>,
    provider_verification_sid: Option<String>,
    max_attempts: i16,
    status: String,
    active: bool,
    cooldown_retry_after_seconds: i64,
}

#[derive(FromRow)]
struct CancelledChallengeRow {
    id: Uuid,
    channel: String,
    was_delivered: bool,
    failed_attempts: i16,
    cooldown_until: Option<OffsetDateTime>,
}

#[allow(
    clippy::too_many_lines,
    reason = "challenge preparation and delivery finalization are explicit fail-closed phases"
)]
pub(super) async fn create_challenge(
    state: &ApiState,
    context: &AccessContext,
    key: &IdempotencyKey,
    input: StepUpChallengeInput,
) -> Result<Outcome<AuthSessionResponse>, AppError> {
    let principal_id = sessions::carbon_context(context)?;
    let request_digest = idempotency::digest_parts(
        b"step-up-challenge-create",
        &[
            principal_id.as_bytes(),
            context.authentication_session_id.as_bytes(),
            input.channel.database_value().as_bytes(),
            input.action.database_value().as_bytes(),
            input.resource_id.as_bytes(),
        ],
    );
    let mut transaction = serializable(state.db(), "step_up_create_transaction").await?;
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
        Claim::Replay { status, response } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "step_up_create_serialization_conflict")
            })?;
            return Ok(Outcome::replay(status, response));
        }
        Claim::Acquired { record_id } => record_id,
    };
    let rate_limit_scope = SecretString::from(format!(
        "{}:{}:{}:{}",
        principal_id,
        context.authentication_session_id,
        input.action.database_value(),
        input.channel.database_value(),
    ));
    super::http::enforce_limit(
        state,
        "step_up_challenge_create",
        &rate_limit_scope,
        5,
        std::time::Duration::from_mins(10),
    )
    .await?;
    lock_current_session(&mut transaction, context, principal_id).await?;
    set_principal_context(&mut transaction, principal_id).await?;
    validate_resource_binding(
        &mut transaction,
        principal_id,
        input.action,
        input.resource_id,
    )
    .await?;
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
    // A provider-managed phone code never passes through IAM, so no digest is
    // stored for it.
    let local_digest = (!delivery::provider_manages_otp(state, input.channel)).then_some(digest);
    let otp_seconds = duration_seconds(state.settings.security.otp_ttl, "step_up_otp_ttl")?;
    let cancelled = sqlx::query_as::<_, CancelledChallengeRow>(
        r"
        UPDATE iam.step_up_challenges
        SET status = 'cancelled',
            delivery_status = CASE
                WHEN delivery_status = 'pending' THEN 'failed'
                ELSE delivery_status
            END,
            delivered_at = CASE
                WHEN delivery_status = 'pending' THEN NULL
                ELSE delivered_at
            END,
            delivery_failed_at = CASE
                WHEN delivery_status = 'pending' THEN transaction_timestamp()
                ELSE delivery_failed_at
            END
        WHERE authentication_session_id = $1
          AND carbon_id = $2
          AND purpose = $3
          AND resource_id IS NOT DISTINCT FROM $4
          AND status = 'pending'
        RETURNING id,
                  channel::text AS channel,
                  delivery_status = 'delivered' AS was_delivered,
                  attempt_count AS failed_attempts,
                  CASE
                      WHEN cooldown_until > transaction_timestamp() THEN cooldown_until
                      ELSE NULL
                  END AS cooldown_until
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
    let attempt_rows = cancelled
        .iter()
        .map(|prior| otp::AttemptState {
            failed_attempts: prior.failed_attempts,
            cooldown_until: prior.cooldown_until,
        })
        .collect::<Vec<_>>();
    let attempt_state = otp::inherited_attempt_state(&attempt_rows);
    for prior in cancelled {
        // Pending-delivery challenges never emitted a creation event and are
        // silently retired as orphan recovery. Delivered challenges preserve
        // the existing auditable cancellation transition.
        if prior.was_delivered {
            record_cancellation(
                &mut transaction,
                principal_id,
                context.authentication_session_id,
                prior,
            )
            .await?;
        }
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
            attempt_count,
            max_attempts,
            cooldown_until,
            expires_at,
            delivery_status,
            delivered_at
        )
        VALUES (
            $1, $2, $3, $4::iam.contact_kind, $5, $6, $7, $8, $9, $10, $11,
            transaction_timestamp() + ($12::bigint * interval '1 second'),
            'pending', NULL
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
    .bind(
        local_digest
            .as_ref()
            .map(|digest| digest.as_bytes().as_slice()),
    )
    .bind(local_digest.as_ref().map(SecretDigest::key_version))
    .bind(attempt_state.failed_attempts)
    .bind(max_attempts)
    .bind(attempt_state.cooldown_until)
    .bind(otp_seconds)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_challenge_create",
    })?;
    let response = AuthSessionResponse {
        session_id: challenge_id,
        expires_at,
        local_otp: state
            .settings
            .providers
            .expose_local_otps
            .then(|| otp.expose_secret().to_owned()),
    };
    let required_delivery = Delivery {
        channel: input.channel,
        recipient,
        code: otp,
        purpose: "step-up",
    };

    // Commit the digest-only pending challenge and its exclusive request
    // reservation before invoking the provider. Pending challenges cannot be
    // verified, including across a post-send/pre-finalize process crash.
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "step_up_create_serialization_conflict"))?;

    match delivery::send_required(state, &required_delivery).await {
        Ok(receipt) => {
            confirm_step_up_delivery(
                state,
                record_id,
                principal_id,
                context.authentication_session_id,
                challenge_id,
                input.channel,
                &receipt.provider_message_id,
                input.action,
                input.resource_id,
                &response,
            )
            .await?;
            Ok(Outcome::fresh(201, response))
        }
        Err(delivery::RequiredDeliveryError::Definitive) => {
            fail_step_up_delivery(state, record_id, principal_id, challenge_id).await?;
            Err(delivery::public_error())
        }
        Err(delivery::RequiredDeliveryError::OutcomeUnknown) => Err(delivery::public_error()),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the exact challenge authority and response are required for atomic activation"
)]
async fn confirm_step_up_delivery(
    state: &ApiState,
    record_id: idempotency::Lease,
    principal_id: Uuid,
    authentication_session_id: Uuid,
    challenge_id: Uuid,
    channel: ContactChannel,
    provider_message_id: &str,
    action: StepUpAction,
    resource_id: Uuid,
    response: &AuthSessionResponse,
) -> Result<(), AppError> {
    let mut transaction = serializable(state.db(), "step_up_delivery_finalize_transaction").await?;
    set_principal_context(&mut transaction, principal_id).await?;
    // Only Twilio Verify produces a verification SID, and the column is
    // constrained to that shape. Any other transport -- a plain SMS provider,
    // or a testing environment that sent nothing at all -- has no SID to
    // record, and writing its receipt id there would violate the constraint
    // and fail the delivery.
    let activated = sqlx::query(
        r"
        UPDATE iam.step_up_challenges AS challenge
        SET delivery_status = 'delivered',
            delivered_at = transaction_timestamp(),
            provider_verification_sid = CASE
                WHEN challenge.channel = 'phone' AND $5 THEN $4
                ELSE NULL
            END
        WHERE challenge.id = $1
          AND challenge.carbon_id = $2
          AND challenge.authentication_session_id = $3
          AND challenge.status = 'pending'
          AND challenge.delivery_status = 'pending'
          AND challenge.delivered_at IS NULL
          AND challenge.delivery_failed_at IS NULL
          AND challenge.expires_at > transaction_timestamp()
          AND EXISTS (
              SELECT 1
              FROM iam.authentication_sessions AS session
              JOIN iam.principals AS principal
                ON principal.id = session.subject_principal_id
               AND principal.kind = 'carbon'
               AND principal.status = 'active'
               AND principal.auth_epoch = session.subject_auth_epoch
              WHERE session.id = challenge.authentication_session_id
                AND session.subject_principal_id = challenge.carbon_id
                AND session.status = 'active'
                AND session.idle_expires_at > transaction_timestamp()
                AND session.absolute_expires_at > transaction_timestamp()
          )
        ",
    )
    .bind(challenge_id)
    .bind(principal_id)
    .bind(authentication_session_id)
    .bind(provider_message_id)
    .bind(delivery::provider_manages_otp(state, ContactChannel::Phone))
    .execute(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_delivery_activate",
    })?;
    if activated.rows_affected() != 1 {
        idempotency::cancel_for_retry(&mut transaction, record_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_conflict(&error, "step_up_delivery_finalize_conflict"))?;
        return Err(AppError::Conflict {
            code: std::borrow::Cow::Borrowed("otp_delivery_superseded"),
        });
    }

    let aggregate_version =
        events::next_aggregate_version(&mut transaction, "step_up_challenge", challenge_id).await?;
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
            authentication_session_id: Some(authentication_session_id),
            application_id: None,
            aggregate_type: "step_up_challenge",
            aggregate_id: challenge_id,
            aggregate_version,
            failure_code: None,
            metadata: json!({
                "action": action.database_value(),
                "channel": channel.database_value(),
                "resource_id": resource_id,
            }),
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        201,
        response,
        state.settings.providers.expose_local_otps,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "step_up_delivery_finalize_conflict"))
}

async fn fail_step_up_delivery(
    state: &ApiState,
    record_id: idempotency::Lease,
    principal_id: Uuid,
    challenge_id: Uuid,
) -> Result<(), AppError> {
    let mut transaction = serializable(state.db(), "step_up_delivery_failure_transaction").await?;
    set_principal_context(&mut transaction, principal_id).await?;
    sqlx::query(
        r"
        UPDATE iam.step_up_challenges
        SET status = 'cancelled',
            delivery_status = 'failed',
            delivered_at = NULL,
            delivery_failed_at = transaction_timestamp()
        WHERE id = $1
          AND carbon_id = $2
          AND status = 'pending'
          AND delivery_status = 'pending'
        ",
    )
    .bind(challenge_id)
    .bind(principal_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "step_up_delivery_fail",
    })?;
    idempotency::cancel_for_retry(&mut transaction, record_id).await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "step_up_delivery_failure_conflict"))
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
) -> Result<Outcome<StepUpVerificationOutcome>, AppError> {
    let principal_id = sessions::carbon_context(context)?;
    let bound_otp = otp::bound_secret("step-up-otp", challenge_id, &code);
    let request_digest = idempotency::digest_parts(
        b"step-up-challenge-verify",
        &[
            principal_id.as_bytes(),
            context.authentication_session_id.as_bytes(),
            challenge_id.as_bytes(),
            code.expose_secret().as_bytes(),
        ],
    );
    let mut transaction = serializable(state.db(), "step_up_verify_transaction").await?;
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
        Claim::Replay { status, response } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "step_up_verify_serialization_conflict")
            })?;
            return Ok(Outcome::replay(status, response));
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
        return Ok(Outcome::fresh(410, StepUpVerificationOutcome::Expired));
    };
    if challenge.status != "pending" || !challenge.active {
        return Ok(Outcome::fresh(410, StepUpVerificationOutcome::Expired));
    }
    if challenge.cooldown_retry_after_seconds > 0 {
        let retry_after_seconds =
            u64::try_from(challenge.cooldown_retry_after_seconds).unwrap_or(u64::MAX);
        return Err(AppError::RateLimited {
            limit: u64::try_from(challenge.max_attempts.max(1)).unwrap_or(1),
            remaining: 0,
            reset_after_seconds: retry_after_seconds,
            retry_after_seconds,
        });
    }
    // Inside a testing environment the fixed code stands in for a delivered
    // one: nothing was ever sent, so there is nothing to compare against.
    let managed_verification =
        if crate::infrastructure::testing_plane::accepts_verification_code(&code) {
            Some(true)
        } else if challenge.channel == "phone" {
            delivery::verify_managed_phone_otp(
                state,
                challenge.provider_verification_sid.as_deref(),
                &code,
            )
            .await?
        } else {
            None
        };
    let matches = if let Some(approved) = managed_verification {
        approved
    } else {
        let (Some(key_version), Some(digest)) = (
            challenge.digest_key_version,
            challenge.challenge_digest.as_deref(),
        ) else {
            // Only a provider-managed challenge stores no digest, and that path
            // is answered above. Fail closed rather than guess.
            return Err(AppError::Internal {
                category: "step_up_otp_digest_missing",
            });
        };
        let expected = SecretDigest::from_parts(key_version, digest).ok_or(AppError::Internal {
            category: "step_up_otp_digest_shape",
        })?;
        state
            .crypto
            .verify_secret(DigestPurpose::StepUpOtp, &bound_otp, expected)
            .map_err(|_| AppError::Internal {
                category: "step_up_otp_verify",
            })?
    };
    if !matches {
        let failure = sqlx::query(
            r"
            UPDATE iam.step_up_challenges
            SET attempt_count = CASE
                    WHEN attempt_count + 1 >= max_attempts THEN 0
                    ELSE attempt_count + 1
                END,
                cooldown_until = CASE
                    WHEN attempt_count + 1 >= max_attempts
                        THEN transaction_timestamp() + ($2::bigint * interval '1 second')
                    ELSE NULL
                END
            WHERE id = $1
              AND status = 'pending'
              AND expires_at > transaction_timestamp()
              AND (cooldown_until IS NULL OR cooldown_until <= transaction_timestamp())
            ",
        )
        .bind(challenge_id)
        .bind(OTP_COOLDOWN_SECONDS)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "step_up_failure_record",
        })?;
        if failure.rows_affected() != 1 {
            return Err(AppError::Conflict {
                code: std::borrow::Cow::Borrowed("step_up_verification_race"),
            });
        }
        record_failure(
            &mut transaction,
            principal_id,
            context.authentication_session_id,
            challenge_id,
            &challenge.channel,
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
        return Ok(Outcome::fresh(422, outcome));
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
    let aggregate_version =
        events::next_aggregate_version(&mut transaction, "step_up_challenge", challenge_id).await?;
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
            application_id: None,
            aggregate_type: "step_up_challenge",
            aggregate_id: challenge_id,
            aggregate_version,
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
    Ok(Outcome::fresh(200, outcome))
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

async fn validate_resource_binding(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    action: StepUpAction,
    resource_id: Uuid,
) -> Result<(), AppError> {
    match action {
        StepUpAction::AccountSessionRevoke => {
            let owned_session = sqlx::query_scalar::<_, Uuid>(SESSION_RESOURCE_OWNERSHIP_QUERY)
                .bind(resource_id)
                .bind(principal_id)
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|_| AppError::Internal {
                    category: "step_up_session_resource_validate",
                })?;
            if owned_session.is_none() {
                return Err(AppError::NotFound);
            }
        }
        StepUpAction::AccountSessionsRevokeAll if resource_id != principal_id => {
            return Err(AppError::Validation {
                details: json!({
                    "resource_id": ["must equal the current Carbon principal_id for this action"]
                }),
            });
        }
        StepUpAction::ApplicationClientSecretRotate => {
            let owned_application =
                sqlx::query_scalar::<_, Uuid>(APPLICATION_RESOURCE_OWNERSHIP_QUERY)
                    .bind(resource_id)
                    .bind(principal_id)
                    .fetch_optional(&mut **transaction)
                    .await
                    .map_err(|_| AppError::Internal {
                        category: "step_up_application_resource_validate",
                    })?;
            if owned_application.is_none() {
                return Err(AppError::NotFound);
            }
        }
        _ => {}
    }
    Ok(())
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
    sqlx::query_as::<_, ChallengeRow>(STEP_UP_CHALLENGE_LOCK_QUERY)
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
) -> Result<(), AppError> {
    let aggregate_version =
        events::next_aggregate_version(transaction, "step_up_challenge", challenge_id).await?;
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
            application_id: None,
            aggregate_type: "step_up_challenge",
            aggregate_id: challenge_id,
            aggregate_version,
            failure_code: Some("invalid_otp"),
            metadata: json!({
                "challenge_id": challenge_id,
                "channel": channel,
                "cooldown_seconds": OTP_COOLDOWN_SECONDS,
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
    let aggregate_version =
        events::next_aggregate_version(transaction, "step_up_challenge", challenge.id).await?;
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
            application_id: None,
            aggregate_type: "step_up_challenge",
            aggregate_id: challenge.id,
            aggregate_version,
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
        "account.session_revoke" => Ok(StepUpAction::AccountSessionRevoke),
        "account.sessions_revoke_all" => Ok(StepUpAction::AccountSessionsRevokeAll),
        "application.client_secret.rotate" => Ok(StepUpAction::ApplicationClientSecretRotate),
        "organization.transfer_ownership" => Ok(StepUpAction::OrganizationTransferOwnership),
        "organization.authorization_change" => Ok(StepUpAction::OrganizationAuthorizationChange),
        "organization.sso_change" => Ok(StepUpAction::OrganizationSsoChange),
        "organization.silicon_webhook.redirect" => {
            Ok(StepUpAction::OrganizationSiliconWebhookRedirect)
        }
        "silicon.rotate_token" => Ok(StepUpAction::SiliconRotateToken),
        "platform_admin.sso_entitlement" => Ok(StepUpAction::PlatformAdminSsoEntitlement),
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
    use super::{
        APPLICATION_RESOURCE_OWNERSHIP_QUERY, SESSION_RESOURCE_OWNERSHIP_QUERY,
        STEP_UP_CHALLENGE_LOCK_QUERY, StepUpAction, StepUpChallengeInput, parse_action,
    };

    #[test]
    fn persisted_actions_use_the_closed_public_vocabulary() {
        assert!(parse_action("application.rotate_secret").is_err());
        assert!(parse_action("application.delete").is_err());
        assert!(parse_action("platform_admin.manage").is_err());
        assert!(matches!(
            parse_action("account.session_revoke"),
            Ok(StepUpAction::AccountSessionRevoke)
        ));
        assert!(matches!(
            parse_action("account.sessions_revoke_all"),
            Ok(StepUpAction::AccountSessionsRevokeAll)
        ));
        assert!(matches!(
            parse_action("application.client_secret.rotate"),
            Ok(StepUpAction::ApplicationClientSecretRotate)
        ));
        assert!(matches!(
            parse_action("organization.silicon_webhook.redirect"),
            Ok(StepUpAction::OrganizationSiliconWebhookRedirect)
        ));
        assert!(matches!(
            parse_action("platform_admin.sso_entitlement"),
            Ok(StepUpAction::PlatformAdminSsoEntitlement)
        ));
        assert!(parse_action("organization.silicon_webhook.rotate_secret").is_err());
        assert!(parse_action("application.rotate-anything").is_err());
    }

    #[test]
    fn pending_or_failed_step_up_delivery_cannot_verify() {
        assert!(STEP_UP_CHALLENGE_LOCK_QUERY.contains("delivery_status = 'delivered'"));
    }

    #[test]
    fn every_step_up_challenge_requires_a_resource() {
        let missing = serde_json::json!({
            "channel": "email",
            "action": "account.session_revoke"
        });
        assert!(serde_json::from_value::<StepUpChallengeInput>(missing).is_err());

        let resource_id = uuid::Uuid::from_u128(1);
        let valid = serde_json::json!({
            "channel": "email",
            "action": "account.session_revoke",
            "resource_id": resource_id
        });
        assert!(serde_json::from_value::<StepUpChallengeInput>(valid).is_ok());
        assert!(SESSION_RESOURCE_OWNERSHIP_QUERY.contains("subject_principal_id = $2"));
        assert!(SESSION_RESOURCE_OWNERSHIP_QUERY.contains("subject_kind = 'carbon'"));
    }

    #[test]
    fn client_secret_rotation_step_up_is_bound_to_a_managed_live_application() {
        assert!(APPLICATION_RESOURCE_OWNERSHIP_QUERY.contains("application.id = $1"));
        assert!(
            APPLICATION_RESOURCE_OWNERSHIP_QUERY
                .contains("iam_private.is_active_organization_owner_or_admin")
        );
        assert!(APPLICATION_RESOURCE_OWNERSHIP_QUERY.contains("application.organization_id"));
        assert!(APPLICATION_RESOURCE_OWNERSHIP_QUERY.contains("application.deleted_at IS NULL"));
    }

    #[test]
    fn forward_migration_closes_step_up_action_and_resource_catalogs() {
        let migration = include_str!("../../../migrations/0035_auth_contract_hardening.sql");
        assert!(migration.contains("'platform_admin.sso_entitlement'"));
        assert!(migration.contains("WHERE purpose = 'platform_admin.manage'"));
        assert!(migration.contains("CHECK (resource_id IS NOT NULL) NOT VALID"));
        assert!(migration.contains("step_up_challenges_supported_purpose"));
        assert!(migration.contains("step_up_assertions_supported_purpose"));
        let application_migration = include_str!(
            "../../../migrations/0037_application_credential_and_redirect_lifecycle.sql"
        );
        assert!(application_migration.contains("'application.client_secret.rotate'"));
    }
}
