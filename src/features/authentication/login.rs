use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::auth::OTP_COOLDOWN_SECONDS,
    error::AppError,
    infrastructure::crypto::{DigestPurpose, SecretDigest},
};

use super::{
    contacts,
    database::{database_conflict, serializable},
    delivery,
    events::{self, SecurityMutation},
    idempotency::{self, Claim, IdempotencyKey, Outcome},
    model::{
        AuthSessionResponse, ContactChannel, Delivery, LoginVerificationOutcome,
        ValidatedLoginIdentifier,
    },
    otp, tokens,
};

#[derive(FromRow)]
struct LoginChallengeRow {
    carbon_id: Uuid,
    status: String,
    active: bool,
}

#[derive(FromRow)]
struct LoginChannelRow {
    id: Uuid,
    contact_kind: String,
    code_digest: Option<Vec<u8>>,
    digest_key_version: Option<i16>,
    provider_verification_sid: Option<String>,
    usable: bool,
    cooldown_retry_after_seconds: i64,
}

const LOGIN_CHALLENGE_LOCK_QUERY: &str = r"
    SELECT
        carbon_id,
        status,
        expires_at > transaction_timestamp()
            AND delivery_status = 'delivered' AS active
    FROM iam.login_challenges
    WHERE id = $1
    FOR UPDATE
";

#[allow(
    clippy::too_many_lines,
    reason = "challenge preparation and multi-provider delivery finalization are explicit phases"
)]
pub(super) async fn create_challenge(
    state: &ApiState,
    key: &IdempotencyKey,
    identifier: ValidatedLoginIdentifier,
) -> Result<Outcome<AuthSessionResponse>, AppError> {
    let caller_scope = identifier_scope(&identifier);
    let request_digest = idempotency::digest_parts(
        b"login-challenge-create",
        &[identifier.database_value().as_bytes(), &caller_scope],
    );
    let mut transaction = serializable(state.db(), "login_challenge_transaction").await?;
    let record_id = match idempotency::begin::<AuthSessionResponse>(
        &mut transaction,
        &state.crypto,
        key,
        &caller_scope,
        "POST /api/v1/login/challenges",
        request_digest,
        state.settings.providers.expose_local_otps,
    )
    .await?
    {
        Claim::Replay { status, response } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "login_challenge_serialization_conflict")
            })?;
            return Ok(Outcome::replay(status, response));
        }
        Claim::Acquired { record_id } => record_id,
    };

    let rate_limit_scope = super::http::login_scope(&identifier);
    super::http::enforce_limit(
        state,
        "login_challenge_create",
        &rate_limit_scope,
        5,
        std::time::Duration::from_mins(10),
    )
    .await?;

    let carbon = contacts::resolve_login_identifier(&mut transaction, &state.crypto, &identifier)
        .await?
        .ok_or(AppError::NotFound)?;
    let attempt_state =
        supersede_login_attempt_scope(&mut transaction, carbon.principal_id).await?;

    let challenge_id = Uuid::now_v7();
    let otp = state
        .crypto
        .generate_otp()
        .map_err(|_| AppError::Internal {
            category: "login_otp_generate",
        })?;
    let otp_seconds = duration_seconds(state.settings.security.otp_ttl, "login_otp_ttl")?;
    let mut deliveries = Vec::new();
    let expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        r"
        INSERT INTO iam.login_challenges (
            id,
            carbon_id,
            requested_identifier_kind,
            expires_at,
            delivery_status,
            delivered_at
        )
        VALUES (
            $1, $2, $3,
            transaction_timestamp() + ($4::bigint * interval '1 second'),
            'pending', NULL
        )
        RETURNING expires_at
        ",
    )
    .bind(challenge_id)
    .bind(carbon.principal_id)
    .bind(identifier.database_value())
    .bind(otp_seconds)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_challenge_create",
    })?;
    let max_attempts = i16::try_from(state.settings.security.otp_max_attempts).map_err(|_| {
        AppError::Internal {
            category: "login_otp_attempts",
        }
    })?;
    for contact in carbon.contacts {
        let digest = state
            .crypto
            .digest_secret(
                login_otp_purpose(contact.channel),
                &otp::bound_secret("login", challenge_id, &otp),
            )
            .map_err(|_| AppError::Internal {
                category: "login_otp_digest",
            })?;
        // A provider-managed phone code never passes through IAM, so no digest
        // is stored for that channel.
        let local_digest =
            (!delivery::provider_manages_otp(state, contact.channel)).then_some(digest);
        sqlx::query(
            r"
            INSERT INTO iam.login_challenge_channels (
                id,
                login_challenge_id,
                carbon_id,
                contact_id,
                contact_kind,
                code_digest,
                digest_key_version,
                failed_attempts,
                max_attempts,
                cooldown_until,
                expires_at
            )
            VALUES (
                $1, $2, $3, $4, $5::iam.contact_kind, $6, $7, $8, $9, $10,
                transaction_timestamp() + ($11::bigint * interval '1 second')
            )
            ",
        )
        .bind(Uuid::now_v7())
        .bind(challenge_id)
        .bind(carbon.principal_id)
        .bind(contact.id)
        .bind(contact.channel.database_value())
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
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "login_channel_create",
        })?;
        deliveries.push(Delivery {
            channel: contact.channel,
            recipient: contact.recipient,
            code: otp.clone(),
            purpose: "login",
        });
    }
    let response = AuthSessionResponse {
        session_id: challenge_id,
        expires_at,
        local_otp: state
            .settings
            .providers
            .expose_local_otps
            .then(|| otp.expose_secret().to_owned()),
    };

    // Only the digest-backed pending challenge and processing reservation are
    // durable here. Providers are called after this transaction releases all
    // locks, and verification requires a later delivered transition.
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "login_challenge_serialization_conflict"))?;

    match delivery::send_all_required(state, &deliveries).await {
        Ok(receipts) => {
            confirm_login_delivery(
                state,
                record_id,
                carbon.principal_id,
                challenge_id,
                identifier.database_value(),
                &receipts,
                &response,
            )
            .await?;
            Ok(Outcome::fresh(201, response))
        }
        Err(delivery::RequiredDeliveryError::Definitive) => {
            fail_login_delivery(state, record_id, challenge_id).await?;
            Err(delivery::public_error())
        }
        Err(delivery::RequiredDeliveryError::OutcomeUnknown) => Err(delivery::public_error()),
    }
}

async fn supersede_login_attempt_scope(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
) -> Result<otp::AttemptState, AppError> {
    let challenge_ids = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM iam.login_challenges
        WHERE carbon_id = $1
          AND status = 'pending'
        ORDER BY created_at, id
        FOR UPDATE
        ",
    )
    .bind(carbon_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_challenge_scope_lock",
    })?;
    if challenge_ids.is_empty() {
        return Ok(otp::AttemptState::default());
    }

    let attempt_rows = sqlx::query_as::<_, otp::AttemptState>(
        r"
        SELECT
            failed_attempts,
            CASE
                WHEN cooldown_until > transaction_timestamp() THEN cooldown_until
                ELSE NULL
            END AS cooldown_until
        FROM iam.login_challenge_channels
        WHERE login_challenge_id = ANY($1::uuid[])
          AND consumed_at IS NULL
          AND superseded_at IS NULL
          AND expires_at > transaction_timestamp()
        ORDER BY created_at DESC, id DESC
        FOR UPDATE
        ",
    )
    .bind(&challenge_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_attempt_scope_lock",
    })?;
    let attempt_state = otp::inherited_attempt_state(&attempt_rows);

    sqlx::query(
        r"
        UPDATE iam.login_challenges
        SET status = 'cancelled',
            cancelled_at = transaction_timestamp(),
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
        WHERE id = ANY($1::uuid[])
          AND status = 'pending'
        ",
    )
    .bind(&challenge_ids)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_challenge_supersede",
    })?;
    sqlx::query(
        r"
        UPDATE iam.login_challenge_channels
        SET superseded_at = COALESCE(superseded_at, transaction_timestamp())
        WHERE login_challenge_id = ANY($1::uuid[])
          AND consumed_at IS NULL
        ",
    )
    .bind(challenge_ids)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_channels_supersede",
    })?;
    Ok(attempt_state)
}

async fn confirm_login_delivery(
    state: &ApiState,
    record_id: idempotency::Lease,
    carbon_id: Uuid,
    challenge_id: Uuid,
    identifier_kind: &'static str,
    receipts: &[delivery::RequiredDeliveryReceipt],
    response: &AuthSessionResponse,
) -> Result<(), AppError> {
    let mut transaction = serializable(state.db(), "login_delivery_finalize_transaction").await?;
    persist_login_phone_receipts(
        &mut transaction,
        challenge_id,
        receipts,
        delivery::provider_manages_otp(state, ContactChannel::Phone),
    )
    .await?;
    let activated = sqlx::query(
        r"
        UPDATE iam.login_challenges AS challenge
        SET delivery_status = 'delivered',
            delivered_at = transaction_timestamp()
        WHERE challenge.id = $1
          AND challenge.carbon_id = $2
          AND challenge.status = 'pending'
          AND challenge.delivery_status = 'pending'
          AND challenge.delivered_at IS NULL
          AND challenge.delivery_failed_at IS NULL
          AND challenge.expires_at > transaction_timestamp()
          AND EXISTS (
              SELECT 1
              FROM iam.login_challenge_channels AS channel
              WHERE channel.login_challenge_id = challenge.id
                AND channel.consumed_at IS NULL
                AND channel.superseded_at IS NULL
                AND channel.expires_at > transaction_timestamp()
          )
        ",
    )
    .bind(challenge_id)
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_delivery_activate",
    })?;
    if activated.rows_affected() != 1 {
        idempotency::cancel_for_retry(&mut transaction, record_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_conflict(&error, "login_delivery_finalize_conflict"))?;
        return Err(AppError::Conflict {
            code: std::borrow::Cow::Borrowed("otp_delivery_superseded"),
        });
    }

    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "login.challenge",
            authentication_outcome: "success",
            audit_action: "login.challenge_create",
            audit_result: "success",
            outbox_event: "login.challenge_created",
            subject_id: Some(carbon_id),
            actor_id: None,
            authentication_session_id: None,
            application_id: None,
            aggregate_type: "login_challenge",
            aggregate_id: challenge_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({ "identifier_kind": identifier_kind }),
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
        .map_err(|error| database_conflict(&error, "login_delivery_finalize_conflict"))
}

/// Records the provider's verification reference for a delivered phone code.
///
/// Only Twilio Verify produces a verification SID, and the column is
/// constrained to that shape. Any other transport -- a plain SMS provider, or a
/// testing environment that sent nothing at all -- has no SID to record, and
/// writing its receipt id there would violate the constraint and fail the
/// delivery.
async fn persist_login_phone_receipts(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
    receipts: &[delivery::RequiredDeliveryReceipt],
    provider_manages_otp: bool,
) -> Result<(), AppError> {
    for receipt in receipts {
        if receipt.channel != ContactChannel::Phone {
            continue;
        }
        let updated = sqlx::query(
            r"
            UPDATE iam.login_challenge_channels
            SET provider_verification_sid = CASE WHEN $3 THEN $2 ELSE NULL END
            WHERE login_challenge_id = $1
              AND contact_kind = 'phone'
              AND provider_verification_sid IS NULL
              AND consumed_at IS NULL
              AND superseded_at IS NULL
            ",
        )
        .bind(challenge_id)
        .bind(&receipt.provider_message_id)
        .bind(provider_manages_otp)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "login_delivery_provider_reference",
        })?;
        if updated.rows_affected() != 1 {
            return Err(AppError::Conflict {
                code: std::borrow::Cow::Borrowed("otp_delivery_superseded"),
            });
        }
    }
    Ok(())
}

async fn fail_login_delivery(
    state: &ApiState,
    record_id: idempotency::Lease,
    challenge_id: Uuid,
) -> Result<(), AppError> {
    let mut transaction = serializable(state.db(), "login_delivery_failure_transaction").await?;
    sqlx::query(
        r"
        UPDATE iam.login_challenges
        SET status = 'cancelled',
            cancelled_at = transaction_timestamp(),
            delivery_status = 'failed',
            delivered_at = NULL,
            delivery_failed_at = transaction_timestamp()
        WHERE id = $1
          AND status = 'pending'
          AND delivery_status = 'pending'
        ",
    )
    .bind(challenge_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_delivery_fail",
    })?;
    sqlx::query(
        r"
        UPDATE iam.login_challenge_channels
        SET superseded_at = COALESCE(superseded_at, transaction_timestamp())
        WHERE login_challenge_id = $1
          AND consumed_at IS NULL
        ",
    )
    .bind(challenge_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_delivery_channels_fail",
    })?;
    idempotency::cancel_for_retry(&mut transaction, record_id).await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "login_delivery_failure_conflict"))
}

#[allow(
    clippy::too_many_lines,
    reason = "attempt accounting, token issuance, audit, outbox, and idempotency are one transition"
)]
pub(super) async fn verify_challenge(
    state: &ApiState,
    key: &IdempotencyKey,
    challenge_id: Uuid,
    code: SecretString,
) -> Result<Outcome<LoginVerificationOutcome>, AppError> {
    let bound_code = otp::bound_secret("login", challenge_id, &code);
    let request_digest = idempotency::digest_parts(
        b"login-challenge-verify",
        &[challenge_id.as_bytes(), code.expose_secret().as_bytes()],
    );
    let mut transaction = serializable(state.db(), "login_verify_transaction").await?;
    let record_id = match idempotency::begin::<LoginVerificationOutcome>(
        &mut transaction,
        &state.crypto,
        key,
        challenge_id.as_bytes(),
        "POST /api/v1/login/challenges/{session_id}/verify",
        request_digest,
        true,
    )
    .await?
    {
        Claim::Replay { status, response } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "login_verify_serialization_conflict")
            })?;
            return Ok(Outcome::replay(status, response));
        }
        Claim::Acquired { record_id } => record_id,
    };
    let Some(challenge) = lock_challenge(&mut transaction, challenge_id).await? else {
        record_unknown_login_failure(&mut transaction).await?;
        let outcome = LoginVerificationOutcome::Invalid;
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
            .map_err(|error| database_conflict(&error, "login_verify_serialization_conflict"))?;
        return Ok(Outcome::fresh(422, outcome));
    };
    if challenge.status != "pending" || !challenge.active {
        return Ok(Outcome::fresh(410, LoginVerificationOutcome::Expired));
    }
    let channels = lock_channels(&mut transaction, challenge_id).await?;
    if channels.is_empty() {
        return Err(AppError::Unauthenticated);
    }
    let mut matched_channel = None;
    for channel in &channels {
        if !channel.usable {
            continue;
        }
        let contact_channel = contacts::parse_channel(&channel.contact_kind)?;
        // Inside a testing environment the fixed code stands in for a
        // delivered one: nothing was ever sent, so there is nothing to
        // compare against.
        let managed_verification =
            if crate::infrastructure::testing_plane::accepts_verification_code(&code) {
                Some(true)
            } else if contact_channel == ContactChannel::Phone {
                delivery::verify_managed_phone_otp(
                    state,
                    channel.provider_verification_sid.as_deref(),
                    &code,
                )
                .await?
            } else {
                None
            };
        let matches = if let Some(approved) = managed_verification {
            approved
        } else {
            let (Some(key_version), Some(digest)) =
                (channel.digest_key_version, channel.code_digest.as_deref())
            else {
                // Only a provider-managed channel stores no digest, and that
                // path is answered above. Fail closed rather than guess.
                return Err(AppError::Internal {
                    category: "login_otp_digest_missing",
                });
            };
            let expected =
                SecretDigest::from_parts(key_version, digest).ok_or(AppError::Internal {
                    category: "login_otp_digest_shape",
                })?;
            state
                .crypto
                .verify_secret(login_otp_purpose(contact_channel), &bound_code, expected)
                .map_err(|_| AppError::Internal {
                    category: "login_otp_verify",
                })?
        };
        if matches && matched_channel.is_none() {
            matched_channel = Some(contact_channel);
        }
    }
    let Some(channel) = matched_channel else {
        if channels.iter().all(|channel| !channel.usable) {
            let retry_after_seconds = channels
                .iter()
                .map(|channel| channel.cooldown_retry_after_seconds)
                .max()
                .unwrap_or_default();
            if retry_after_seconds > 0 {
                let retry_after_seconds = u64::try_from(retry_after_seconds).unwrap_or(u64::MAX);
                return Err(AppError::RateLimited {
                    limit: u64::from(state.settings.security.otp_max_attempts),
                    remaining: 0,
                    reset_after_seconds: retry_after_seconds,
                    retry_after_seconds,
                });
            }
            return Ok(Outcome::fresh(410, LoginVerificationOutcome::Expired));
        }
        record_login_failure(
            &mut transaction,
            state,
            challenge_id,
            challenge.carbon_id,
            &channels,
        )
        .await?;
        let outcome = LoginVerificationOutcome::Invalid;
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
            .map_err(|error| database_conflict(&error, "login_verify_serialization_conflict"))?;
        return Ok(Outcome::fresh(422, outcome));
    };

    let challenge_update = sqlx::query(
        r"
        UPDATE iam.login_challenge_channels
        SET consumed_at = transaction_timestamp()
        WHERE login_challenge_id = $1
          AND consumed_at IS NULL
          AND superseded_at IS NULL
        ",
    )
    .bind(challenge_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_channels_consume",
    })?;
    let login_challenge_update = sqlx::query(
        r"
        UPDATE iam.login_challenges
        SET status = 'completed', consumed_at = transaction_timestamp()
        WHERE id = $1 AND status = 'pending'
        ",
    )
    .bind(challenge_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_challenge_consume",
    })?;
    if challenge_update.rows_affected() == 0 || login_challenge_update.rows_affected() != 1 {
        return Err(AppError::Conflict {
            code: std::borrow::Cow::Borrowed("login_verification_race"),
        });
    }
    let tokens = tokens::issue_login_session(
        &mut transaction,
        &state.crypto,
        &state.settings.security,
        challenge.carbon_id,
        channel,
    )
    .await?;
    let challenge_version =
        events::next_aggregate_version(&mut transaction, "login_challenge", challenge_id).await?;
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "login.challenge_completed",
            authentication_outcome: "success",
            audit_action: "login.challenge_complete",
            audit_result: "success",
            outbox_event: "login.challenge_completed",
            subject_id: Some(challenge.carbon_id),
            actor_id: Some(challenge.carbon_id),
            authentication_session_id: Some(tokens.session_id),
            application_id: None,
            aggregate_type: "login_challenge",
            aggregate_id: challenge_id,
            aggregate_version: challenge_version,
            failure_code: None,
            metadata: json!({ "channel": channel.database_value() }),
        },
    )
    .await?;
    let outcome = LoginVerificationOutcome::Success(tokens);
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
        .map_err(|error| database_conflict(&error, "login_verify_serialization_conflict"))?;
    Ok(Outcome::fresh(200, outcome))
}

async fn lock_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
) -> Result<Option<LoginChallengeRow>, AppError> {
    sqlx::query_as::<_, LoginChallengeRow>(LOGIN_CHALLENGE_LOCK_QUERY)
        .bind(challenge_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "login_challenge_lock",
        })
}

async fn lock_channels(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
) -> Result<Vec<LoginChannelRow>, AppError> {
    sqlx::query_as::<_, LoginChannelRow>(
        r"
        SELECT
            id,
            contact_kind::text AS contact_kind,
            code_digest,
            digest_key_version,
            provider_verification_sid,
            expires_at > transaction_timestamp()
                AND superseded_at IS NULL
                AND consumed_at IS NULL
                AND (cooldown_until IS NULL OR cooldown_until <= transaction_timestamp()) AS usable,
            CASE
                WHEN expires_at > transaction_timestamp()
                     AND superseded_at IS NULL
                     AND consumed_at IS NULL
                     AND cooldown_until > transaction_timestamp()
                    THEN GREATEST(
                        1,
                        CEIL(EXTRACT(EPOCH FROM cooldown_until - transaction_timestamp()))::bigint
                    )
                ELSE 0
            END AS cooldown_retry_after_seconds
        FROM iam.login_challenge_channels
        WHERE login_challenge_id = $1
        ORDER BY contact_kind, id
        FOR UPDATE
        ",
    )
    .bind(challenge_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_channels_lock",
    })
}

async fn record_unknown_login_failure(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), AppError> {
    let attempt_id = Uuid::now_v7();
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "login.failure",
            authentication_outcome: "failure",
            audit_action: "login.challenge_verify",
            audit_result: "failure",
            outbox_event: "login.challenge_failed",
            subject_id: None,
            actor_id: None,
            authentication_session_id: None,
            application_id: None,
            aggregate_type: "authentication_attempt",
            aggregate_id: attempt_id,
            aggregate_version: 1,
            failure_code: Some("invalid_otp"),
            metadata: json!({}),
        },
    )
    .await
}

async fn record_login_failure(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    challenge_id: Uuid,
    carbon_id: Uuid,
    channels: &[LoginChannelRow],
) -> Result<(), AppError> {
    let channel_ids = channels
        .iter()
        .map(|channel| channel.id)
        .collect::<Vec<_>>();
    let failure_update = sqlx::query(
        r"
        UPDATE iam.login_challenge_channels
        SET failed_attempts = CASE
                WHEN failed_attempts + 1 >= max_attempts
                    THEN 0
                ELSE failed_attempts + 1
            END,
            cooldown_until = CASE
                WHEN failed_attempts + 1 >= max_attempts
                    THEN transaction_timestamp() + ($2::bigint * interval '1 second')
                ELSE NULL
            END
        WHERE id = ANY($1::uuid[])
          AND consumed_at IS NULL
          AND superseded_at IS NULL
          AND expires_at > transaction_timestamp()
          AND (cooldown_until IS NULL OR cooldown_until <= transaction_timestamp())
        ",
    )
    .bind(channel_ids)
    .bind(OTP_COOLDOWN_SECONDS)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_failure_record",
    })?;
    if failure_update.rows_affected() == 0 {
        return Err(AppError::Conflict {
            code: std::borrow::Cow::Borrowed("login_verification_race"),
        });
    }
    let aggregate_version =
        events::next_aggregate_version(transaction, "login_challenge", challenge_id).await?;
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "login.failure",
            authentication_outcome: "failure",
            audit_action: "login.challenge_verify",
            audit_result: "failure",
            outbox_event: "login.challenge_failed",
            subject_id: Some(carbon_id),
            actor_id: None,
            authentication_session_id: None,
            application_id: None,
            aggregate_type: "login_challenge",
            aggregate_id: challenge_id,
            aggregate_version,
            failure_code: Some("invalid_otp"),
            metadata: json!({
                "max_attempts": state.settings.security.otp_max_attempts,
                "cooldown_seconds": OTP_COOLDOWN_SECONDS,
            }),
        },
    )
    .await
}

fn identifier_scope(identifier: &ValidatedLoginIdentifier) -> [u8; 32] {
    match identifier {
        ValidatedLoginIdentifier::Contact(contact) => idempotency::digest_parts(
            b"login-identifier",
            &[
                contact.channel.database_value().as_bytes(),
                contact.normalized.as_bytes(),
            ],
        ),
        ValidatedLoginIdentifier::CarbonId(carbon_id) => idempotency::digest_parts(
            b"login-identifier",
            &[b"carbon_id", carbon_id.as_str().as_bytes()],
        ),
    }
}

const fn login_otp_purpose(channel: ContactChannel) -> DigestPurpose {
    match channel {
        ContactChannel::Email => DigestPurpose::LoginEmailOtp,
        ContactChannel::Phone => DigestPurpose::LoginPhoneOtp,
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
    use secrecy::SecretString;

    use super::{LOGIN_CHALLENGE_LOCK_QUERY, identifier_scope};
    use crate::features::authentication::model::{
        ContactChannel, ValidatedContact, ValidatedLoginIdentifier,
    };

    #[test]
    fn pending_or_failed_login_delivery_cannot_verify() {
        assert!(LOGIN_CHALLENGE_LOCK_QUERY.contains("delivery_status = 'delivered'"));
    }

    #[test]
    fn login_identifier_scope_is_normalized_and_key_version_independent() {
        let identifier = ValidatedLoginIdentifier::Contact(ValidatedContact {
            channel: ContactChannel::Email,
            normalized: "person@example.com".to_owned(),
            presentation: SecretString::from("Person@example.com".to_owned()),
        });
        let scope = identifier_scope(&identifier);
        assert_eq!(scope, identifier_scope(&identifier));

        let other = ValidatedLoginIdentifier::Contact(ValidatedContact {
            channel: ContactChannel::Email,
            normalized: "other@example.com".to_owned(),
            presentation: SecretString::from("other@example.com".to_owned()),
        });
        assert_ne!(scope, identifier_scope(&other));
    }
}
