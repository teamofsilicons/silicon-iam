use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    error::AppError,
    infrastructure::crypto::{DigestPurpose, SecretDigest},
};

use super::{
    contacts,
    database::{database_conflict, serializable},
    events::{self, SecurityMutation},
    idempotency::{self, Claim, IdempotencyKey},
    model::{
        AuthSessionResponse, ContactChannel, Delivery, LoginVerificationOutcome,
        ValidatedLoginIdentifier,
    },
    otp, tokens,
};

pub(super) struct LoginDispatch {
    pub(super) response: AuthSessionResponse,
    pub(super) deliveries: Vec<Delivery>,
}

#[derive(FromRow)]
struct LoginChallengeRow {
    carbon_id: Uuid,
    status: String,
    active: bool,
    retry_after_seconds: i64,
}

#[derive(FromRow)]
struct LoginChannelRow {
    id: Uuid,
    contact_kind: String,
    code_digest: Vec<u8>,
    digest_key_version: i16,
    failed_attempts: i16,
    max_attempts: i16,
    unexpired: bool,
    usable: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "challenge, verifiers, audit, outbox, and idempotency commit atomically"
)]
pub(super) async fn create_challenge(
    state: &ApiState,
    key: &IdempotencyKey,
    identifier: ValidatedLoginIdentifier,
) -> Result<LoginDispatch, AppError> {
    let caller_scope = identifier_scope(state, &identifier)?;
    let request_digest = idempotency::digest_parts(
        b"login-challenge-create",
        &[identifier.database_value().as_bytes(), &caller_scope],
    );
    let mut transaction = serializable(&state.pool, "login_challenge_transaction").await?;
    match idempotency::begin::<AuthSessionResponse>(
        &mut transaction,
        &state.crypto,
        key,
        &caller_scope,
        "/api/v1/login/challenges",
        request_digest,
        state.settings.providers.expose_local_otps,
    )
    .await?
    {
        Claim::Replay { response, .. } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "login_challenge_serialization_conflict")
            })?;
            Ok(LoginDispatch {
                response,
                deliveries: Vec::new(),
            })
        }
        Claim::Acquired { record_id } => {
            let resolved =
                contacts::resolve_login_identifier(&mut transaction, &state.crypto, &identifier)
                    .await?;
            let challenge_id = Uuid::now_v7();
            let otp = state
                .crypto
                .generate_otp()
                .map_err(|_| AppError::Internal {
                    category: "login_otp_generate",
                })?;
            let otp_seconds = duration_seconds(state.settings.security.otp_ttl, "login_otp_ttl")?;
            let fallback_expires_at =
                OffsetDateTime::now_utc() + time::Duration::seconds(otp_seconds);
            let mut deliveries = Vec::new();
            let (subject_id, expires_at) = if let Some(carbon) = resolved {
                let expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
                    r"
                    INSERT INTO iam.login_challenges (
                        id,
                        carbon_id,
                        requested_identifier_kind,
                        expires_at
                    )
                    VALUES (
                        $1, $2, $3,
                        transaction_timestamp() + ($4::bigint * interval '1 second')
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
                let max_attempts = i16::try_from(state.settings.security.otp_max_attempts)
                    .map_err(|_| AppError::Internal {
                        category: "login_otp_attempts",
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
                            max_attempts,
                            expires_at
                        )
                        VALUES (
                            $1, $2, $3, $4, $5::iam.contact_kind, $6, $7, $8,
                            transaction_timestamp() + ($9::bigint * interval '1 second')
                        )
                        ",
                    )
                    .bind(Uuid::now_v7())
                    .bind(challenge_id)
                    .bind(carbon.principal_id)
                    .bind(contact.id)
                    .bind(contact.channel.database_value())
                    .bind(digest.as_bytes().as_slice())
                    .bind(digest.key_version())
                    .bind(max_attempts)
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
                (Some(carbon.principal_id), expires_at)
            } else {
                (None, fallback_expires_at)
            };
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
                    authentication_event: "login.challenge",
                    authentication_outcome: "success",
                    audit_action: "login.challenge_create",
                    audit_result: "success",
                    outbox_event: "login.challenge_created",
                    subject_id,
                    actor_id: None,
                    authentication_session_id: None,
                    aggregate_type: "login_challenge",
                    aggregate_id: challenge_id,
                    aggregate_version: 1,
                    failure_code: None,
                    metadata: json!({ "identifier_kind": identifier.database_value() }),
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
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "login_challenge_serialization_conflict")
            })?;
            Ok(LoginDispatch {
                response,
                deliveries,
            })
        }
    }
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
) -> Result<LoginVerificationOutcome, AppError> {
    let bound_code = otp::bound_secret("login", challenge_id, &code);
    let keyed_request = state
        .crypto
        .digest_secret(DigestPurpose::LoginEmailOtp, &bound_code)
        .map_err(|_| AppError::Internal {
            category: "login_verify_request_digest",
        })?;
    let request_version = keyed_request.key_version().to_be_bytes();
    let request_digest = idempotency::digest_parts(
        b"login-challenge-verify",
        &[
            challenge_id.as_bytes(),
            &request_version,
            keyed_request.as_bytes(),
        ],
    );
    let mut transaction = serializable(&state.pool, "login_verify_transaction").await?;
    let record_id = match idempotency::begin::<LoginVerificationOutcome>(
        &mut transaction,
        &state.crypto,
        key,
        challenge_id.as_bytes(),
        "/api/v1/login/challenges/:session_id/verify",
        request_digest,
        true,
    )
    .await?
    {
        Claim::Replay { response, .. } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "login_verify_serialization_conflict")
            })?;
            return Ok(response);
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
        return Ok(outcome);
    };
    if challenge.status != "pending" || !challenge.active {
        return Ok(LoginVerificationOutcome::Expired);
    }
    let channels = lock_channels(&mut transaction, challenge_id).await?;
    if channels.is_empty() {
        return Err(AppError::Unauthenticated);
    }
    let mut matched_channel = None;
    let mut maximum_failed_attempts = 0_i16;
    for channel in &channels {
        maximum_failed_attempts = maximum_failed_attempts.max(channel.failed_attempts);
        if !channel.usable || channel.failed_attempts >= channel.max_attempts {
            continue;
        }
        let contact_channel = contacts::parse_channel(&channel.contact_kind)?;
        let expected = SecretDigest::from_parts(channel.digest_key_version, &channel.code_digest)
            .ok_or(AppError::Internal {
            category: "login_otp_digest_shape",
        })?;
        let matches = state
            .crypto
            .verify_secret(login_otp_purpose(contact_channel), &bound_code, expected)
            .map_err(|_| AppError::Internal {
                category: "login_otp_verify",
            })?;
        if matches && matched_channel.is_none() {
            matched_channel = Some(contact_channel);
        }
    }
    let Some(channel) = matched_channel else {
        if channels.iter().all(|channel| !channel.usable) {
            if channels.iter().any(|channel| channel.unexpired) {
                return Err(AppError::RateLimited {
                    limit: u64::from(state.settings.security.otp_max_attempts),
                    remaining: 0,
                    reset_after_seconds: u64::try_from(challenge.retry_after_seconds.max(1))
                        .unwrap_or(1),
                    retry_after_seconds: u64::try_from(challenge.retry_after_seconds.max(1))
                        .unwrap_or(1),
                });
            }
            return Ok(LoginVerificationOutcome::Expired);
        }
        record_login_failure(
            &mut transaction,
            state,
            challenge_id,
            challenge.carbon_id,
            maximum_failed_attempts,
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
        return Ok(outcome);
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
    let challenge_version = i64::from(maximum_failed_attempts) + 2;
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
    Ok(outcome)
}

async fn lock_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
) -> Result<Option<LoginChallengeRow>, AppError> {
    sqlx::query_as::<_, LoginChallengeRow>(
        r"
        SELECT
            carbon_id,
            status,
            expires_at > transaction_timestamp() AS active,
            GREATEST(
                1,
                CEIL(EXTRACT(EPOCH FROM expires_at - transaction_timestamp()))::bigint
            ) AS retry_after_seconds
        FROM iam.login_challenges
        WHERE id = $1
        FOR UPDATE
        ",
    )
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
            failed_attempts,
            max_attempts,
            expires_at > transaction_timestamp() AS unexpired,
            expires_at > transaction_timestamp()
                AND superseded_at IS NULL
                AND consumed_at IS NULL AS usable
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
    previous_maximum: i16,
    channels: &[LoginChannelRow],
) -> Result<(), AppError> {
    let channel_ids = channels
        .iter()
        .map(|channel| channel.id)
        .collect::<Vec<_>>();
    sqlx::query(
        r"
        UPDATE iam.login_challenge_channels
        SET failed_attempts = LEAST(failed_attempts + 1, max_attempts),
            superseded_at = CASE
                WHEN failed_attempts + 1 >= max_attempts
                    THEN transaction_timestamp()
                ELSE superseded_at
            END
        WHERE id = ANY($1::uuid[])
          AND consumed_at IS NULL
          AND superseded_at IS NULL
        ",
    )
    .bind(channel_ids)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_failure_record",
    })?;
    let aggregate_version = i64::from(previous_maximum) + 2;
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
            aggregate_type: "login_challenge",
            aggregate_id: challenge_id,
            aggregate_version,
            failure_code: Some("invalid_otp"),
            metadata: json!({
                "max_attempts": state.settings.security.otp_max_attempts,
            }),
        },
    )
    .await
}

fn identifier_scope(
    state: &ApiState,
    identifier: &ValidatedLoginIdentifier,
) -> Result<[u8; 32], AppError> {
    match identifier {
        ValidatedLoginIdentifier::Contact(contact) => state
            .crypto
            .blind_index(
                contacts::blind_index_purpose(contact.channel),
                &contact.normalized,
            )
            .map(|digest| *digest.as_bytes())
            .map_err(|_| AppError::Internal {
                category: "login_identifier_scope",
            }),
        ValidatedLoginIdentifier::CarbonId(carbon_id) => Ok(idempotency::digest_parts(
            b"carbon-id",
            &[carbon_id.as_str().as_bytes()],
        )),
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
