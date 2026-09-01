use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    error::AppError,
    infrastructure::crypto::{DigestPurpose, EncryptedValue, SecretDigest},
};

use super::{
    contacts,
    database::{database_conflict, expired, serializable},
    events::{self, SecurityMutation},
    idempotency::{self, Claim, IdempotencyKey},
    model::{
        AuthSessionResponse, CarbonSelfResponse, CodeDispatchResponse, ContactChannel, Delivery,
        ValidatedContact, ValidatedSignupCompletion, VerificationOutcome,
    },
    otp,
};

const SIGNUP_LIFETIME_HOURS: i64 = 48;

pub(super) struct DispatchResult {
    pub(super) response: CodeDispatchResponse,
    pub(super) delivery: Option<Delivery>,
}

#[derive(FromRow)]
struct SignupSessionRow {
    status: String,
    active: bool,
}

#[derive(FromRow)]
struct SignupChallengeRow {
    challenge_id: Uuid,
    candidate_id: Uuid,
    code_digest: Vec<u8>,
    digest_key_version: i16,
    failed_attempts: i16,
    max_attempts: i16,
    challenge_usable: bool,
    verified: bool,
    session_usable: bool,
}

#[derive(FromRow)]
struct CandidateRow {
    id: Uuid,
    kind: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(FromRow)]
struct CompletionRow {
    principal_id: Uuid,
    carbon_handle: String,
    aggregate_version: i64,
    created_at: OffsetDateTime,
}

pub(super) async fn create_session(
    state: &ApiState,
    key: &IdempotencyKey,
) -> Result<AuthSessionResponse, AppError> {
    let mut transaction = serializable(&state.pool, "signup_session_transaction").await?;
    let request_digest = idempotency::digest_parts(b"signup-session-create", &[]);
    match idempotency::begin::<AuthSessionResponse>(
        &mut transaction,
        &state.crypto,
        key,
        b"anonymous-signup",
        "/api/v1/signup/sessions",
        request_digest,
        false,
    )
    .await?
    {
        Claim::Replay { response, .. } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "signup_session_serialization_conflict")
            })?;
            Ok(response)
        }
        Claim::Acquired { record_id } => {
            let session_id = Uuid::now_v7();
            let expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
                r"
                INSERT INTO iam.signup_sessions (id, expires_at)
                VALUES (
                    $1,
                    transaction_timestamp() + ($2::bigint * interval '1 hour')
                )
                RETURNING expires_at
                ",
            )
            .bind(session_id)
            .bind(SIGNUP_LIFETIME_HOURS)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| AppError::Internal {
                category: "signup_session_create",
            })?;
            let response = AuthSessionResponse {
                session_id,
                expires_at,
                local_otp: None,
            };
            events::record(
                &mut transaction,
                SecurityMutation {
                    authentication_event: "signup.session_created",
                    authentication_outcome: "success",
                    audit_action: "signup.session_create",
                    audit_result: "success",
                    outbox_event: "signup.session_created",
                    subject_id: None,
                    actor_id: None,
                    authentication_session_id: None,
                    aggregate_type: "signup_session",
                    aggregate_id: session_id,
                    aggregate_version: 1,
                    failure_code: None,
                    metadata: json!({}),
                },
            )
            .await?;
            idempotency::complete(
                &mut transaction,
                &state.crypto,
                record_id,
                201,
                &response,
                false,
            )
            .await?;
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "signup_session_serialization_conflict")
            })?;
            Ok(response)
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "candidate, OTP, audit, outbox, and idempotency commit atomically"
)]
pub(super) async fn start_contact(
    state: &ApiState,
    key: &IdempotencyKey,
    signup_session_id: Uuid,
    contact: ValidatedContact,
) -> Result<DispatchResult, AppError> {
    let channel = contact.channel;
    let request_index = state
        .crypto
        .blind_index(contacts::blind_index_purpose(channel), &contact.normalized)
        .map_err(|_| AppError::Internal {
            category: "signup_contact_request_digest",
        })?;
    let request_version = request_index.key_version().to_be_bytes();
    let request_digest = idempotency::digest_parts(
        b"signup-contact-start",
        &[
            signup_session_id.as_bytes(),
            channel.database_value().as_bytes(),
            &request_version,
            request_index.as_bytes(),
        ],
    );
    let mut transaction = serializable(&state.pool, "signup_contact_transaction").await?;
    match idempotency::begin::<CodeDispatchResponse>(
        &mut transaction,
        &state.crypto,
        key,
        signup_session_id.as_bytes(),
        signup_start_route(channel),
        request_digest,
        state.settings.providers.expose_local_otps,
    )
    .await?
    {
        Claim::Replay { response, .. } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "signup_contact_serialization_conflict")
            })?;
            Ok(DispatchResult {
                response,
                delivery: None,
            })
        }
        Claim::Acquired { record_id } => {
            let session = lock_signup_session(&mut transaction, signup_session_id).await?;
            ensure_pending_session(&session)?;
            let verified_exists = sqlx::query_scalar::<_, bool>(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM iam.signup_contact_candidates
                    WHERE signup_session_id = $1
                      AND kind = $2::iam.contact_kind
                      AND verified_at IS NOT NULL
                      AND superseded_at IS NULL
                )
                ",
            )
            .bind(signup_session_id)
            .bind(channel.database_value())
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| AppError::Internal {
                category: "signup_verified_candidate_check",
            })?;
            if verified_exists {
                return Err(AppError::Conflict {
                    code: std::borrow::Cow::Borrowed("signup_contact_already_verified"),
                });
            }

            let existing_contact =
                contacts::active_contact_exists(&mut transaction, &state.crypto, &contact).await?;
            let candidate_id = Uuid::now_v7();
            let challenge_id = Uuid::now_v7();
            let encrypted = contacts::encrypt_contact(&state.crypto, &contact, candidate_id)?;
            let indexes = contacts::blind_indexes(&state.crypto, &contact)?;
            let otp = state
                .crypto
                .generate_otp()
                .map_err(|_| AppError::Internal {
                    category: "signup_otp_generate",
                })?;
            let otp_digest = state
                .crypto
                .digest_secret(
                    signup_otp_purpose(channel),
                    &otp::bound_secret("signup", signup_session_id, &otp),
                )
                .map_err(|_| AppError::Internal {
                    category: "signup_otp_digest",
                })?;

            supersede_signup_contact(&mut transaction, signup_session_id, channel).await?;
            insert_candidate(
                &mut transaction,
                signup_session_id,
                candidate_id,
                channel,
                encrypted,
                &indexes,
            )
            .await?;
            let otp_ttl = duration_seconds(state.settings.security.otp_ttl, "signup_otp_ttl")?;
            let max_attempts =
                i16::try_from(state.settings.security.otp_max_attempts).map_err(|_| {
                    AppError::Internal {
                        category: "signup_otp_attempts",
                    }
                })?;
            sqlx::query(
                r"
                INSERT INTO iam.signup_otp_challenges (
                    id,
                    signup_session_id,
                    candidate_id,
                    contact_kind,
                    code_digest,
                    digest_key_version,
                    max_attempts,
                    expires_at
                )
                VALUES (
                    $1, $2, $3, $4::iam.contact_kind, $5, $6, $7,
                    transaction_timestamp() + ($8::bigint * interval '1 second')
                )
                ",
            )
            .bind(challenge_id)
            .bind(signup_session_id)
            .bind(candidate_id)
            .bind(channel.database_value())
            .bind(otp_digest.as_bytes().as_slice())
            .bind(otp_digest.key_version())
            .bind(max_attempts)
            .bind(otp_ttl)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AppError::Internal {
                category: "signup_otp_create",
            })?;
            let version = bump_signup_session(&mut transaction, signup_session_id).await?;
            let local_otp = state
                .settings
                .providers
                .expose_local_otps
                .then(|| otp.expose_secret().to_owned());
            let response = CodeDispatchResponse {
                accepted: true,
                expires_in: state.settings.security.otp_ttl.as_secs(),
                local_otp,
            };
            events::record(
                &mut transaction,
                SecurityMutation {
                    authentication_event: "signup.otp_issued",
                    authentication_outcome: "success",
                    audit_action: "signup.contact_start",
                    audit_result: "success",
                    outbox_event: "signup.otp_issued",
                    subject_id: None,
                    actor_id: None,
                    authentication_session_id: None,
                    aggregate_type: "signup_session",
                    aggregate_id: signup_session_id,
                    aggregate_version: version,
                    failure_code: None,
                    metadata: json!({
                        "candidate_id": candidate_id,
                        "channel": channel.database_value(),
                    }),
                },
            )
            .await?;
            idempotency::complete(
                &mut transaction,
                &state.crypto,
                record_id,
                202,
                &response,
                state.settings.providers.expose_local_otps,
            )
            .await?;
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "signup_contact_serialization_conflict")
            })?;
            let delivery = (!existing_contact).then(|| Delivery {
                channel,
                recipient: contact.presentation,
                code: otp,
                purpose: "signup",
            });
            Ok(DispatchResult { response, delivery })
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "attempt accounting, candidate verification, and security records share one lock"
)]
pub(super) async fn verify_contact(
    state: &ApiState,
    key: &IdempotencyKey,
    signup_session_id: Uuid,
    channel: ContactChannel,
    supplied_code: SecretString,
) -> Result<VerificationOutcome, AppError> {
    let bound_code = otp::bound_secret("signup", signup_session_id, &supplied_code);
    let keyed_request = state
        .crypto
        .digest_secret(signup_otp_purpose(channel), &bound_code)
        .map_err(|_| AppError::Internal {
            category: "signup_verify_request_digest",
        })?;
    let request_version = keyed_request.key_version().to_be_bytes();
    let request_digest = idempotency::digest_parts(
        b"signup-contact-verify",
        &[
            signup_session_id.as_bytes(),
            channel.database_value().as_bytes(),
            &request_version,
            keyed_request.as_bytes(),
        ],
    );
    let mut transaction = serializable(&state.pool, "signup_verify_transaction").await?;
    let record_id = match idempotency::begin::<VerificationOutcome>(
        &mut transaction,
        &state.crypto,
        key,
        signup_session_id.as_bytes(),
        signup_verify_route(channel),
        request_digest,
        false,
    )
    .await?
    {
        Claim::Replay { response, .. } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "signup_verify_serialization_conflict")
            })?;
            return Ok(response);
        }
        Claim::Acquired { record_id } => record_id,
    };
    let row = lock_signup_challenge(&mut transaction, signup_session_id, channel).await?;
    if !row.session_usable {
        return Ok(VerificationOutcome::Expired);
    }
    if row.verified {
        let outcome = VerificationOutcome::Verified;
        idempotency::complete(
            &mut transaction,
            &state.crypto,
            record_id,
            200,
            &outcome,
            false,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_conflict(&error, "signup_verify_serialization_conflict"))?;
        return Ok(outcome);
    }
    if !row.challenge_usable {
        return Ok(VerificationOutcome::Expired);
    }
    if row.failed_attempts >= row.max_attempts {
        return Err(AppError::RateLimited {
            limit: u64::try_from(row.max_attempts.max(1)).unwrap_or(1),
            remaining: 0,
            reset_after_seconds: state.settings.security.otp_ttl.as_secs(),
            retry_after_seconds: state.settings.security.otp_ttl.as_secs(),
        });
    }
    let expected = SecretDigest::from_parts(row.digest_key_version, &row.code_digest).ok_or(
        AppError::Internal {
            category: "signup_otp_digest_shape",
        },
    )?;
    let matches = state
        .crypto
        .verify_secret(signup_otp_purpose(channel), &bound_code, expected)
        .map_err(|_| AppError::Internal {
            category: "signup_otp_verify",
        })?;
    let outcome = if matches {
        let challenge_update = sqlx::query(
            r"
            UPDATE iam.signup_otp_challenges
            SET consumed_at = transaction_timestamp()
            WHERE id = $1 AND consumed_at IS NULL AND superseded_at IS NULL
            ",
        )
        .bind(row.challenge_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "signup_otp_consume",
        })?;
        let candidate_update = sqlx::query(
            r"
            UPDATE iam.signup_contact_candidates
            SET verified_at = transaction_timestamp()
            WHERE id = $1 AND verified_at IS NULL AND superseded_at IS NULL
            ",
        )
        .bind(row.candidate_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "signup_candidate_verify",
        })?;
        if challenge_update.rows_affected() != 1 || candidate_update.rows_affected() != 1 {
            return Err(AppError::Conflict {
                code: std::borrow::Cow::Borrowed("signup_verification_race"),
            });
        }
        VerificationOutcome::Verified
    } else {
        sqlx::query(
            r"
            UPDATE iam.signup_otp_challenges
            SET failed_attempts = LEAST(failed_attempts + 1, max_attempts),
                superseded_at = CASE
                    WHEN failed_attempts + 1 >= max_attempts
                        THEN transaction_timestamp()
                    ELSE superseded_at
                END
            WHERE id = $1 AND consumed_at IS NULL AND superseded_at IS NULL
            ",
        )
        .bind(row.challenge_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "signup_otp_failure_record",
        })?;
        VerificationOutcome::Invalid
    };
    let version = bump_signup_session(&mut transaction, signup_session_id).await?;
    let success = matches!(outcome, VerificationOutcome::Verified);
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: if success {
                "signup.otp_verified"
            } else {
                "signup.otp_failed"
            },
            authentication_outcome: if success { "success" } else { "failure" },
            audit_action: "signup.contact_verify",
            audit_result: if success { "success" } else { "failure" },
            outbox_event: if success {
                "signup.contact_verified"
            } else {
                "signup.otp_failed"
            },
            subject_id: None,
            actor_id: None,
            authentication_session_id: None,
            aggregate_type: "signup_session",
            aggregate_id: signup_session_id,
            aggregate_version: version,
            failure_code: (!success).then_some("invalid_otp"),
            metadata: json!({ "channel": channel.database_value() }),
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        if success { 200 } else { 422 },
        &outcome,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "signup_verify_serialization_conflict"))?;
    Ok(outcome)
}

#[allow(
    clippy::too_many_lines,
    reason = "signup completion and its security records must remain visibly atomic"
)]
pub(super) async fn complete_signup(
    state: &ApiState,
    key: &IdempotencyKey,
    signup_session_id: Uuid,
    input: ValidatedSignupCompletion,
) -> Result<CarbonSelfResponse, AppError> {
    let profile_photo = match input.profile_photo {
        Some(url) => url,
        None => default_profile_photo(state, input.carbon_id.as_str())?,
    };
    let description = input.description.as_deref().unwrap_or_default();
    let description_presence = [u8::from(input.description.is_some())];
    let request_digest = idempotency::digest_parts(
        b"signup-complete",
        &[
            signup_session_id.as_bytes(),
            input.carbon_id.as_str().as_bytes(),
            input.display_name.as_bytes(),
            &description_presence,
            description.as_bytes(),
            profile_photo.as_str().as_bytes(),
        ],
    );
    let mut transaction = serializable(&state.pool, "signup_complete_transaction").await?;
    let record_id = match idempotency::begin::<CarbonSelfResponse>(
        &mut transaction,
        &state.crypto,
        key,
        signup_session_id.as_bytes(),
        "/api/v1/signup/sessions/:session_id/complete",
        request_digest,
        false,
    )
    .await?
    {
        Claim::Replay { response, .. } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "signup_complete_serialization_conflict")
            })?;
            return Ok(response);
        }
        Claim::Acquired { record_id } => record_id,
    };
    let session = lock_signup_session(&mut transaction, signup_session_id).await?;
    ensure_pending_session(&session)?;
    let candidates = verified_candidates(&mut transaction, signup_session_id).await?;
    let email = candidate_plaintext(&state.crypto, &candidates, ContactChannel::Email)?;
    let phone = candidate_plaintext(&state.crypto, &candidates, ContactChannel::Phone)?;
    let email_id = candidate_id(&candidates, ContactChannel::Email)?;
    let phone_id = candidate_id(&candidates, ContactChannel::Phone)?;
    let principal_id = Uuid::now_v7();
    let completion = sqlx::query_as::<_, CompletionRow>(
        r"
        SELECT principal_id, carbon_handle, aggregate_version, created_at
        FROM iam_private.complete_verified_signup($1, $2, $3, $4, $5, $6, $7, $8)
        ",
    )
    .bind(signup_session_id)
    .bind(principal_id)
    .bind(input.carbon_id.as_str())
    .bind(&input.display_name)
    .bind(input.description.as_deref())
    .bind(profile_photo.as_str())
    .bind(email_id)
    .bind(phone_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| database_conflict(&error, "signup_conflict"))?;
    let response = CarbonSelfResponse {
        principal_id: completion.principal_id,
        carbon_id: completion.carbon_handle,
        display_name: input.display_name,
        description: input.description,
        profile_photo: profile_photo.to_string(),
        email: email.expose_secret().to_owned(),
        phone_number: phone.expose_secret().to_owned(),
        status: "active".to_owned(),
        version: completion.aggregate_version,
        created_at: completion.created_at,
        updated_at: completion.created_at,
    };
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "signup.completed",
            authentication_outcome: "success",
            audit_action: "carbon.signup_complete",
            audit_result: "success",
            outbox_event: "carbon.created",
            subject_id: Some(completion.principal_id),
            actor_id: Some(completion.principal_id),
            authentication_session_id: None,
            aggregate_type: "carbon",
            aggregate_id: completion.principal_id,
            aggregate_version: completion.aggregate_version,
            failure_code: None,
            metadata: json!({ "carbon_id": input.carbon_id.as_str() }),
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        201,
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "signup_complete_serialization_conflict"))?;
    Ok(response)
}

async fn lock_signup_session(
    transaction: &mut Transaction<'_, Postgres>,
    signup_session_id: Uuid,
) -> Result<SignupSessionRow, AppError> {
    sqlx::query_as::<_, SignupSessionRow>(
        r"
        SELECT
            status,
            expires_at > transaction_timestamp() AS active
        FROM iam.signup_sessions
        WHERE id = $1
        FOR UPDATE
        ",
    )
    .bind(signup_session_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "signup_session_lock",
    })?
    .ok_or(AppError::NotFound)
}

fn ensure_pending_session(session: &SignupSessionRow) -> Result<(), AppError> {
    if session.status == "pending" && session.active {
        Ok(())
    } else {
        Err(expired())
    }
}

async fn supersede_signup_contact(
    transaction: &mut Transaction<'_, Postgres>,
    signup_session_id: Uuid,
    channel: ContactChannel,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.signup_otp_challenges AS challenge
        SET superseded_at = transaction_timestamp()
        FROM iam.signup_contact_candidates AS candidate
        WHERE candidate.id = challenge.candidate_id
          AND candidate.signup_session_id = $1
          AND candidate.kind = $2::iam.contact_kind
          AND candidate.verified_at IS NULL
          AND candidate.superseded_at IS NULL
          AND challenge.consumed_at IS NULL
          AND challenge.superseded_at IS NULL
        ",
    )
    .bind(signup_session_id)
    .bind(channel.database_value())
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "signup_challenge_supersede",
    })?;
    sqlx::query(
        r"
        UPDATE iam.signup_contact_candidates
        SET superseded_at = transaction_timestamp()
        WHERE signup_session_id = $1
          AND kind = $2::iam.contact_kind
          AND verified_at IS NULL
          AND superseded_at IS NULL
        ",
    )
    .bind(signup_session_id)
    .bind(channel.database_value())
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "signup_candidate_supersede",
    })?;
    Ok(())
}

async fn insert_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    signup_session_id: Uuid,
    candidate_id: Uuid,
    channel: ContactChannel,
    encrypted: EncryptedValue,
    indexes: &[SecretDigest],
) -> Result<(), AppError> {
    sqlx::query(
        r"
        INSERT INTO iam.signup_contact_candidates (
            id,
            signup_session_id,
            kind,
            ciphertext,
            nonce,
            encryption_key_version
        )
        VALUES ($1, $2, $3::iam.contact_kind, $4, $5, $6)
        ",
    )
    .bind(candidate_id)
    .bind(signup_session_id)
    .bind(channel.database_value())
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce.as_slice())
    .bind(encrypted.key_version)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "signup_candidate_create",
    })?;
    for index in indexes {
        sqlx::query(
            r"
            INSERT INTO iam.signup_candidate_blind_indexes (
                candidate_id,
                contact_kind,
                hmac_key_version,
                digest
            )
            VALUES ($1, $2::iam.contact_kind, $3, $4)
            ",
        )
        .bind(candidate_id)
        .bind(channel.database_value())
        .bind(index.key_version())
        .bind(index.as_bytes().as_slice())
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "signup_candidate_index_create",
        })?;
    }
    Ok(())
}

async fn lock_signup_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    signup_session_id: Uuid,
    channel: ContactChannel,
) -> Result<SignupChallengeRow, AppError> {
    sqlx::query_as::<_, SignupChallengeRow>(
        r"
        SELECT
            challenge.id AS challenge_id,
            candidate.id AS candidate_id,
            challenge.code_digest,
            challenge.digest_key_version,
            challenge.failed_attempts,
            challenge.max_attempts,
            challenge.expires_at > transaction_timestamp()
                AND challenge.superseded_at IS NULL
                AND challenge.consumed_at IS NULL AS challenge_usable,
            challenge.consumed_at IS NOT NULL
                OR candidate.verified_at IS NOT NULL AS verified,
            signup_session.status = 'pending'
                AND signup_session.expires_at > transaction_timestamp() AS session_usable
        FROM iam.signup_sessions AS signup_session
        JOIN iam.signup_contact_candidates AS candidate
          ON candidate.signup_session_id = signup_session.id
         AND candidate.kind = $2::iam.contact_kind
         AND candidate.superseded_at IS NULL
        JOIN iam.signup_otp_challenges AS challenge
          ON challenge.candidate_id = candidate.id
         AND challenge.contact_kind = candidate.kind
        WHERE signup_session.id = $1
        ORDER BY challenge.created_at DESC, challenge.id DESC
        LIMIT 1
        FOR UPDATE OF signup_session, candidate, challenge
        ",
    )
    .bind(signup_session_id)
    .bind(channel.database_value())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "signup_challenge_lock",
    })?
    .ok_or(AppError::NotFound)
}

async fn bump_signup_session(
    transaction: &mut Transaction<'_, Postgres>,
    signup_session_id: Uuid,
) -> Result<i64, AppError> {
    sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.signup_sessions
        SET updated_at = transaction_timestamp()
        WHERE id = $1
        RETURNING version
        ",
    )
    .bind(signup_session_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "signup_session_version",
    })
}

async fn verified_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    signup_session_id: Uuid,
) -> Result<Vec<CandidateRow>, AppError> {
    let candidates = sqlx::query_as::<_, CandidateRow>(
        r"
        SELECT
            id,
            kind::text AS kind,
            ciphertext,
            nonce,
            encryption_key_version
        FROM iam.signup_contact_candidates
        WHERE signup_session_id = $1
          AND verified_at IS NOT NULL
          AND superseded_at IS NULL
        ORDER BY kind
        FOR UPDATE
        ",
    )
    .bind(signup_session_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "signup_candidates_read",
    })?;
    if candidates.len() != 2 {
        return Err(AppError::Conflict {
            code: std::borrow::Cow::Borrowed("signup_contacts_not_verified"),
        });
    }
    Ok(candidates)
}

fn candidate_plaintext(
    crypto: &crate::infrastructure::crypto::CryptoService,
    candidates: &[CandidateRow],
    channel: ContactChannel,
) -> Result<SecretString, AppError> {
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.kind == channel.database_value())
        .ok_or(AppError::Conflict {
            code: std::borrow::Cow::Borrowed("signup_contacts_not_verified"),
        })?;
    contacts::decrypt_contact(
        crypto,
        channel,
        candidate.id,
        candidate.encryption_key_version,
        candidate.nonce.clone(),
        candidate.ciphertext.clone(),
    )
}

fn candidate_id(candidates: &[CandidateRow], channel: ContactChannel) -> Result<Uuid, AppError> {
    candidates
        .iter()
        .find(|candidate| candidate.kind == channel.database_value())
        .map(|candidate| candidate.id)
        .ok_or(AppError::Conflict {
            code: std::borrow::Cow::Borrowed("signup_contacts_not_verified"),
        })
}

fn default_profile_photo(state: &ApiState, carbon_id: &str) -> Result<url::Url, AppError> {
    profile_photo_url(&state.settings.providers.iris_base_url, carbon_id)
}

fn profile_photo_url(iris_base_url: &url::Url, carbon_id: &str) -> Result<url::Url, AppError> {
    let mut url = iris_base_url
        .join("pfp/carbon")
        .map_err(|_| AppError::Internal {
            category: "iris_profile_photo_url",
        })?;
    url.query_pairs_mut().append_pair("id", carbon_id);
    Ok(url)
}

const fn signup_otp_purpose(channel: ContactChannel) -> DigestPurpose {
    match channel {
        ContactChannel::Email => DigestPurpose::SignupEmailOtp,
        ContactChannel::Phone => DigestPurpose::SignupPhoneOtp,
    }
}

const fn signup_start_route(channel: ContactChannel) -> &'static str {
    match channel {
        ContactChannel::Email => "/api/v1/signup/sessions/:session_id/email",
        ContactChannel::Phone => "/api/v1/signup/sessions/:session_id/phone",
    }
}

const fn signup_verify_route(channel: ContactChannel) -> &'static str {
    match channel {
        ContactChannel::Email => "/api/v1/signup/sessions/:session_id/email/verify",
        ContactChannel::Phone => "/api/v1/signup/sessions/:session_id/phone/verify",
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
    use super::*;

    #[test]
    fn omitted_profile_photo_uses_the_backend_owned_iris_default() {
        let base = url::Url::parse("https://iris.teamofsilicons.com/").expect("valid base URL");

        let photo = profile_photo_url(&base, "ada").expect("profile URL");

        assert_eq!(
            photo.as_str(),
            "https://iris.teamofsilicons.com/pfp/carbon?id=ada"
        );
    }

    #[test]
    fn carbon_id_is_encoded_as_one_query_parameter() {
        let base = url::Url::parse("https://iris.example.test/root/").expect("valid base URL");

        let photo = profile_photo_url(&base, "space & slash/").expect("profile URL");

        assert_eq!(
            photo.as_str(),
            "https://iris.example.test/root/pfp/carbon?id=space+%26+slash%2F"
        );
    }
}
