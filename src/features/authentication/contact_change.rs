use std::{borrow::Cow, num::NonZeroU32, time::Duration};

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated, me},
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, EncryptedValue, SecretDigest},
        postgres::{
            rate_limit::{self, RateLimitPolicy},
            step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
        },
    },
};

use super::{
    contacts,
    database::{database_conflict, serializable, set_principal_context},
    events::{self, SecurityMutation},
    idempotency::{self, Claim, IdempotencyKey},
    model::{
        AuthSessionResponse, ContactChannel, Delivery, EmailInput, PhoneInput, ValidatedContact,
        VerificationInput,
    },
    otp, sessions, validation,
};

const EMAIL_START_ROUTE: &str = "/api/v1/me/email-change/sessions";
const EMAIL_VERIFY_ROUTE: &str = "/api/v1/me/email-change/sessions/:session_id/verify";
const PHONE_START_ROUTE: &str = "/api/v1/me/phone-change/sessions";
const PHONE_VERIFY_ROUTE: &str = "/api/v1/me/phone-change/sessions/:session_id/verify";
const ACTION: &str = "account.contact_change";

#[derive(FromRow)]
struct ChangeRow {
    id: Uuid,
    candidate_contact_id: Uuid,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
    code_digest: Vec<u8>,
    digest_key_version: i16,
    failed_attempts: i16,
    max_attempts: i16,
    status: String,
    expires_at: OffsetDateTime,
}

#[derive(FromRow)]
struct ExistingContactRow {
    id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum VerificationOutcome {
    Updated(Box<me::CarbonProfileResponse>),
    Invalid,
    Expired,
}

struct StartResult {
    response: AuthSessionResponse,
    delivery: Option<Delivery>,
}

pub(super) async fn start_email(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
    payload: Result<Json<EmailInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let input = payload
        .map(|Json(value)| value)
        .map_err(|_| validation::validation("body", "must match the documented JSON schema"))?;
    start(
        &state,
        &authenticated,
        &headers,
        validation::email(input.email)?,
    )
    .await
}

pub(super) async fn start_phone(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
    payload: Result<Json<PhoneInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let input = payload
        .map(|Json(value)| value)
        .map_err(|_| validation::validation("body", "must match the documented JSON schema"))?;
    start(
        &state,
        &authenticated,
        &headers,
        validation::phone(input.phone_number)?,
    )
    .await
}

pub(super) async fn verify_email(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<VerificationInput>, JsonRejection>,
) -> Result<Response, AppError> {
    verify_handler(
        &state,
        &authenticated,
        &headers,
        session_id,
        ContactChannel::Email,
        payload,
    )
    .await
}

pub(super) async fn verify_phone(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<VerificationInput>, JsonRejection>,
) -> Result<Response, AppError> {
    verify_handler(
        &state,
        &authenticated,
        &headers,
        session_id,
        ContactChannel::Phone,
        payload,
    )
    .await
}

async fn start(
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    contact: ValidatedContact,
) -> Result<Response, AppError> {
    let carbon_id = sessions::carbon_context(&authenticated.0)?;
    enforce_limit(
        state,
        "contact_change_start",
        carbon_id,
        &contact.normalized,
        5,
    )
    .await?;
    let key = IdempotencyKey::from_headers(headers)?;
    let result = start_change(state, authenticated, headers, &key, carbon_id, contact).await?;
    deliver_otp(state, result.delivery.as_ref()).await;
    Ok(no_store(StatusCode::CREATED, result.response))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "candidate encryption, OTP issuance, step-up, idempotency, audit, and outbox commit atomically"
)]
async fn start_change(
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    key: &IdempotencyKey,
    carbon_id: Uuid,
    contact: ValidatedContact,
) -> Result<StartResult, AppError> {
    let channel = contact.channel;
    let request_index = state
        .crypto
        .blind_index(contacts::blind_index_purpose(channel), &contact.normalized)
        .map_err(|_| internal("contact_change_request_digest"))?;
    let request_version = request_index.key_version().to_be_bytes();
    let request_digest = idempotency::digest_parts(
        b"contact-change-start",
        &[
            carbon_id.as_bytes(),
            channel.database_value().as_bytes(),
            &request_version,
            request_index.as_bytes(),
        ],
    );
    let mut transaction = serializable(&state.pool, "contact_change_start_transaction").await?;
    set_principal_context(&mut transaction, carbon_id).await?;
    let record_id = match idempotency::begin::<AuthSessionResponse>(
        &mut transaction,
        &state.crypto,
        key,
        carbon_id.as_bytes(),
        start_route(channel),
        request_digest,
        state.settings.providers.expose_local_otps,
    )
    .await?
    {
        Claim::Replay { response } => {
            transaction
                .commit()
                .await
                .map_err(|error| database_conflict(&error, "contact_change_start_conflict"))?;
            return Ok(StartResult {
                response,
                delivery: None,
            });
        }
        Claim::Acquired { record_id } => record_id,
    };
    lock_current_session(&mut transaction, authenticated, carbon_id).await?;
    consume_step_up(&mut transaction, state, authenticated, headers, carbon_id).await?;
    sqlx::query(
        r"
        UPDATE iam.contact_change_sessions
        SET status = 'cancelled', superseded_at = transaction_timestamp()
        WHERE carbon_id = $1 AND kind = $2::iam.contact_kind AND status = 'pending'
        ",
    )
    .bind(carbon_id)
    .bind(channel.database_value())
    .execute(&mut *transaction)
    .await
    .map_err(|_| internal("contact_change_supersede"))?;
    let change_id = Uuid::now_v7();
    let candidate_id = Uuid::now_v7();
    let encrypted = contacts::encrypt_contact(&state.crypto, &contact, candidate_id)?;
    let indexes = contacts::blind_indexes(&state.crypto, &contact)?;
    let otp = state
        .crypto
        .generate_otp()
        .map_err(|_| internal("contact_change_otp_generate"))?;
    let bound = otp::bound_secret("contact-change", change_id, &otp);
    let digest = state
        .crypto
        .digest_secret(otp_purpose(channel), &bound)
        .map_err(|_| internal("contact_change_otp_digest"))?;
    let ttl = i64::try_from(state.settings.security.otp_ttl.as_secs())
        .map_err(|_| internal("contact_change_otp_ttl"))?;
    let max_attempts = i16::try_from(state.settings.security.otp_max_attempts)
        .map_err(|_| internal("contact_change_otp_attempts"))?;
    let expires_at = insert_change(
        &mut transaction,
        ChangeInsert {
            change_id,
            carbon_id,
            authentication_session_id: authenticated.0.authentication_session_id,
            channel,
            candidate_id,
            encrypted,
            digest,
            max_attempts,
            ttl,
        },
    )
    .await?;
    for index in indexes {
        sqlx::query(
            r"
            INSERT INTO iam.contact_change_blind_indexes (
                contact_change_session_id, carbon_id, contact_kind,
                hmac_key_version, digest
            ) VALUES ($1, $2, $3::iam.contact_kind, $4, $5)
            ",
        )
        .bind(change_id)
        .bind(carbon_id)
        .bind(channel.database_value())
        .bind(index.key_version())
        .bind(index.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| internal("contact_change_index_create"))?;
    }
    let response = AuthSessionResponse {
        session_id: change_id,
        expires_at,
        local_otp: state
            .settings
            .providers
            .expose_local_otps
            .then(|| otp.expose_secret().to_owned()),
    };
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "contact_change.challenge",
            authentication_outcome: "success",
            audit_action: "carbon.contact_change_start",
            audit_result: "success",
            outbox_event: "carbon.contact_change_started",
            subject_id: Some(carbon_id),
            actor_id: Some(carbon_id),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            aggregate_type: "contact_change_session",
            aggregate_id: change_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({ "channel": channel.database_value() }),
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        StatusCode::CREATED.as_u16(),
        &response,
        state.settings.providers.expose_local_otps,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "contact_change_start_conflict"))?;
    Ok(StartResult {
        response,
        delivery: Some(Delivery {
            channel,
            recipient: contact.presentation,
            code: otp,
            purpose: "contact_change",
        }),
    })
}

struct ChangeInsert {
    change_id: Uuid,
    carbon_id: Uuid,
    authentication_session_id: Uuid,
    channel: ContactChannel,
    candidate_id: Uuid,
    encrypted: EncryptedValue,
    digest: SecretDigest,
    max_attempts: i16,
    ttl: i64,
}

async fn insert_change(
    transaction: &mut Transaction<'_, Postgres>,
    input: ChangeInsert,
) -> Result<OffsetDateTime, AppError> {
    sqlx::query_scalar::<_, OffsetDateTime>(
        r"
        INSERT INTO iam.contact_change_sessions (
            id, carbon_id, authentication_session_id, kind, candidate_contact_id,
            ciphertext, nonce, encryption_key_version, code_digest,
            digest_key_version, max_attempts, expires_at
        ) VALUES (
            $1, $2, $3, $4::iam.contact_kind, $5, $6, $7, $8, $9, $10, $11,
            transaction_timestamp() + ($12::bigint * interval '1 second')
        )
        RETURNING expires_at
        ",
    )
    .bind(input.change_id)
    .bind(input.carbon_id)
    .bind(input.authentication_session_id)
    .bind(input.channel.database_value())
    .bind(input.candidate_id)
    .bind(input.encrypted.ciphertext)
    .bind(input.encrypted.nonce.as_slice())
    .bind(input.encrypted.key_version)
    .bind(input.digest.as_bytes().as_slice())
    .bind(input.digest.key_version())
    .bind(input.max_attempts)
    .bind(input.ttl)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_create"))
}

async fn verify_handler(
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    session_id: Uuid,
    channel: ContactChannel,
    payload: Result<Json<VerificationInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let input = payload
        .map(|Json(value)| value)
        .map_err(|_| validation::validation("body", "must match the documented JSON schema"))?;
    let code = validation::verification_code(input.code)?;
    let carbon_id = sessions::carbon_context(&authenticated.0)?;
    enforce_limit(
        state,
        "contact_change_verify",
        carbon_id,
        &session_id.to_string(),
        5,
    )
    .await?;
    let expected_version = me::expected_version(headers)?;
    let key = IdempotencyKey::from_headers(headers)?;
    match verify_change(
        state,
        authenticated,
        headers,
        &key,
        session_id,
        channel,
        code,
        expected_version,
    )
    .await?
    {
        VerificationOutcome::Updated(profile) => profile_response(*profile),
        VerificationOutcome::Invalid => Err(validation::validation("code", "is invalid")),
        VerificationOutcome::Expired => Err(AppError::Gone {
            code: Cow::Borrowed("challenge_expired"),
        }),
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "OTP attempt accounting and atomic contact replacement, revocation, notification, audit, and outbox are one workflow"
)]
async fn verify_change(
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    key: &IdempotencyKey,
    change_id: Uuid,
    channel: ContactChannel,
    supplied_code: SecretString,
    expected_version: i64,
) -> Result<VerificationOutcome, AppError> {
    let carbon_id = authenticated.0.subject.id;
    let bound = otp::bound_secret("contact-change", change_id, &supplied_code);
    let keyed = state
        .crypto
        .digest_secret(otp_purpose(channel), &bound)
        .map_err(|_| internal("contact_change_verify_request_digest"))?;
    let request_version = keyed.key_version().to_be_bytes();
    let expected_bytes = expected_version.to_be_bytes();
    let request_digest = idempotency::digest_parts(
        b"contact-change-verify",
        &[
            change_id.as_bytes(),
            channel.database_value().as_bytes(),
            &expected_bytes,
            &request_version,
            keyed.as_bytes(),
        ],
    );
    let mut transaction = serializable(&state.pool, "contact_change_verify_transaction").await?;
    set_principal_context(&mut transaction, carbon_id).await?;
    let record_id = match idempotency::begin::<VerificationOutcome>(
        &mut transaction,
        &state.crypto,
        key,
        carbon_id.as_bytes(),
        verify_route(channel),
        request_digest,
        false,
    )
    .await?
    {
        Claim::Replay { response } => {
            transaction
                .commit()
                .await
                .map_err(|error| database_conflict(&error, "contact_change_verify_conflict"))?;
            return Ok(response);
        }
        Claim::Acquired { record_id } => record_id,
    };
    lock_current_session(&mut transaction, authenticated, carbon_id).await?;
    consume_step_up(&mut transaction, state, authenticated, headers, carbon_id).await?;
    let row = lock_change(&mut transaction, change_id, carbon_id, channel).await?;
    if row.status != "pending" || row.expires_at <= OffsetDateTime::now_utc() {
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
    let expected = SecretDigest::from_parts(row.digest_key_version, &row.code_digest)
        .ok_or_else(|| internal("contact_change_digest_shape"))?;
    let valid = state
        .crypto
        .verify_secret(otp_purpose(channel), &bound, expected)
        .map_err(|_| internal("contact_change_otp_verify"))?;
    if !valid {
        record_failed_attempt(&mut transaction, &row).await?;
        let outcome = VerificationOutcome::Invalid;
        events::record(
            &mut transaction,
            SecurityMutation {
                authentication_event: "contact_change.failure",
                authentication_outcome: "failure",
                audit_action: "carbon.contact_change_verify",
                audit_result: "failure",
                outbox_event: "carbon.contact_change_failed",
                subject_id: Some(carbon_id),
                actor_id: Some(carbon_id),
                authentication_session_id: Some(authenticated.0.authentication_session_id),
                aggregate_type: "contact_change_session",
                aggregate_id: change_id,
                aggregate_version: i64::from(row.failed_attempts) + 2,
                failure_code: Some("invalid_otp"),
                metadata: json!({ "channel": channel.database_value() }),
            },
        )
        .await?;
        idempotency::complete(
            &mut transaction,
            &state.crypto,
            record_id,
            StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            &outcome,
            false,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_conflict(&error, "contact_change_verify_conflict"))?;
        return Ok(outcome);
    }

    let profile_before = me::read_profile(&mut transaction, state, carbon_id, true).await?;
    if profile_before.version != expected_version {
        return Err(AppError::PreconditionFailed {
            code: Cow::Borrowed("etag_mismatch"),
        });
    }
    let old_contact = active_contact(&mut transaction, carbon_id, channel).await?;
    ensure_candidate_unique(&mut transaction, change_id, carbon_id, old_contact.id).await?;
    replace_contact(
        &mut transaction,
        change_id,
        carbon_id,
        channel,
        &row,
        old_contact.id,
    )
    .await?;
    queue_contact_change_notices(
        &mut transaction,
        change_id,
        channel,
        old_contact.id,
        row.candidate_contact_id,
    )
    .await?;
    revoke_other_sessions(
        &mut transaction,
        carbon_id,
        authenticated.0.authentication_session_id,
    )
    .await?;
    sqlx::query("UPDATE iam.carbons SET updated_at = transaction_timestamp() WHERE id = $1")
        .bind(carbon_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| internal("contact_change_carbon_version"))?;
    let profile = me::read_profile(&mut transaction, state, carbon_id, false).await?;
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "contact_change.success",
            authentication_outcome: "success",
            audit_action: "carbon.contact_change_complete",
            audit_result: "success",
            outbox_event: "carbon.contact_changed",
            subject_id: Some(carbon_id),
            actor_id: Some(carbon_id),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            aggregate_type: "carbon",
            aggregate_id: carbon_id,
            aggregate_version: profile.version,
            failure_code: None,
            metadata: json!({ "channel": channel.database_value() }),
        },
    )
    .await?;
    let outcome = VerificationOutcome::Updated(Box::new(profile));
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        StatusCode::OK.as_u16(),
        &outcome,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "contact_change_verify_conflict"))?;
    Ok(outcome)
}

async fn lock_change(
    transaction: &mut Transaction<'_, Postgres>,
    change_id: Uuid,
    carbon_id: Uuid,
    channel: ContactChannel,
) -> Result<ChangeRow, AppError> {
    sqlx::query_as::<_, ChangeRow>(
        r"
        SELECT id, candidate_contact_id, ciphertext, nonce, encryption_key_version,
               code_digest, digest_key_version, failed_attempts, max_attempts,
               status, expires_at
        FROM iam.contact_change_sessions
        WHERE id = $1 AND carbon_id = $2 AND kind = $3::iam.contact_kind
        FOR UPDATE
        ",
    )
    .bind(change_id)
    .bind(carbon_id)
    .bind(channel.database_value())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_read"))?
    .ok_or(AppError::NotFound)
}

async fn record_failed_attempt(
    transaction: &mut Transaction<'_, Postgres>,
    row: &ChangeRow,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.contact_change_sessions
        SET failed_attempts = LEAST(failed_attempts + 1, max_attempts),
            status = CASE WHEN failed_attempts + 1 >= max_attempts THEN 'cancelled' ELSE status END,
            superseded_at = CASE
                WHEN failed_attempts + 1 >= max_attempts THEN transaction_timestamp()
                ELSE superseded_at
            END
        WHERE id = $1 AND status = 'pending'
        ",
    )
    .bind(row.id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_attempt_record"))?;
    Ok(())
}

async fn active_contact(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    channel: ContactChannel,
) -> Result<ExistingContactRow, AppError> {
    sqlx::query_as::<_, ExistingContactRow>(
        r"
        SELECT id
        FROM iam.carbon_contacts
        WHERE carbon_id = $1 AND kind = $2::iam.contact_kind
          AND status = 'active' AND is_primary
        FOR UPDATE
        ",
    )
    .bind(carbon_id)
    .bind(channel.database_value())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_old_contact"))?
    .ok_or_else(|| internal("contact_change_contact_invariant"))
}

async fn ensure_candidate_unique(
    transaction: &mut Transaction<'_, Postgres>,
    change_id: Uuid,
    carbon_id: Uuid,
    current_contact_id: Uuid,
) -> Result<(), AppError> {
    let conflict = sqlx::query_as::<_, (Uuid, Uuid)>(
        r"
        SELECT contact.id, contact.carbon_id
        FROM iam.contact_change_blind_indexes AS candidate_index
        JOIN iam.contact_blind_indexes AS contact_index
          ON contact_index.contact_kind = candidate_index.contact_kind
         AND contact_index.hmac_key_version = candidate_index.hmac_key_version
         AND contact_index.digest = candidate_index.digest
        JOIN iam.carbon_contacts AS contact ON contact.id = contact_index.contact_id
        WHERE candidate_index.contact_change_session_id = $1
          AND contact.status = 'active'
        LIMIT 1
        FOR UPDATE OF contact
        ",
    )
    .bind(change_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_uniqueness_check"))?;
    match conflict {
        Some((contact_id, owner)) if contact_id == current_contact_id && owner == carbon_id => {
            Err(AppError::Conflict {
                code: Cow::Borrowed("contact_unchanged"),
            })
        }
        Some(_) => Err(AppError::Conflict {
            code: Cow::Borrowed("contact_in_use"),
        }),
        None => Ok(()),
    }
}

async fn replace_contact(
    transaction: &mut Transaction<'_, Postgres>,
    change_id: Uuid,
    carbon_id: Uuid,
    channel: ContactChannel,
    row: &ChangeRow,
    old_contact_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE iam.carbon_contacts SET status = 'retired', retired_at = transaction_timestamp(), is_primary = false WHERE id = $1 AND status = 'active'",
    )
    .bind(old_contact_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_retire_old"))?;
    sqlx::query(
        r"
        INSERT INTO iam.carbon_contacts (
            id, carbon_id, kind, ciphertext, nonce, encryption_key_version,
            is_primary, status, verified_at
        ) VALUES ($1, $2, $3::iam.contact_kind, $4, $5, $6, true, 'active', transaction_timestamp())
        ",
    )
    .bind(row.candidate_contact_id)
    .bind(carbon_id)
    .bind(channel.database_value())
    .bind(&row.ciphertext)
    .bind(&row.nonce)
    .bind(row.encryption_key_version)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_insert_contact"))?;
    sqlx::query(
        r"
        INSERT INTO iam.contact_blind_indexes (
            contact_id, contact_kind, hmac_key_version, digest
        )
        SELECT $2, contact_kind, hmac_key_version, digest
        FROM iam.contact_change_blind_indexes
        WHERE contact_change_session_id = $1
        ",
    )
    .bind(change_id)
    .bind(row.candidate_contact_id)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_conflict(&error, "contact_in_use"))?;
    sqlx::query(
        "UPDATE iam.contact_change_sessions SET status = 'verified', verified_at = transaction_timestamp(), previous_contact_id = $2 WHERE id = $1 AND status = 'pending'",
    )
    .bind(change_id)
    .bind(old_contact_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_complete"))?;
    Ok(())
}

async fn queue_contact_change_notices(
    transaction: &mut Transaction<'_, Postgres>,
    change_id: Uuid,
    channel: ContactChannel,
    old_contact_id: Uuid,
    new_contact_id: Uuid,
) -> Result<(), AppError> {
    let provider = match channel {
        ContactChannel::Email => "postmark",
        ContactChannel::Phone => "twilio_messaging",
    };
    for contact_id in [old_contact_id, new_contact_id] {
        sqlx::query(
            r"
            INSERT INTO iam.notification_jobs (
                id, notification_kind, provider, recipient_contact_id,
                recipient_contact_kind, template_id, context_type, context_id
            ) VALUES (
                $1, 'security_notice', $2, $3, $4::iam.contact_kind,
                'security.contact_changed', 'contact_change', $5
            )
            ",
        )
        .bind(Uuid::now_v7())
        .bind(provider)
        .bind(contact_id)
        .bind(channel.database_value())
        .bind(change_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| internal("contact_change_notice_queue"))?;
    }
    Ok(())
}

async fn revoke_other_sessions(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    current_session_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.authentication_sessions
        SET status = 'revoked', revoked_at = transaction_timestamp(),
            revocation_reason = 'contact_changed', version = version + 1
        WHERE subject_principal_id = $1 AND id <> $2 AND status = 'active'
        ",
    )
    .bind(carbon_id)
    .bind(current_session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_sessions_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'revoked', revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = 'contact_changed'
        WHERE subject_principal_id = $1 AND authentication_session_id <> $2 AND status = 'active'
        ",
    )
    .bind(carbon_id)
    .bind(current_session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_families_revoke"))?;
    sqlx::query(
        "UPDATE iam.refresh_tokens SET revoked_at = COALESCE(revoked_at, transaction_timestamp()) WHERE family_id IN (SELECT id FROM iam.refresh_token_families WHERE subject_principal_id = $1 AND authentication_session_id <> $2)",
    )
    .bind(carbon_id)
    .bind(current_session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_refresh_revoke"))?;
    sqlx::query(
        "UPDATE iam.access_tokens SET revoked_at = COALESCE(revoked_at, transaction_timestamp()), revocation_reason = COALESCE(revocation_reason, 'contact_changed') WHERE subject_principal_id = $1 AND authentication_session_id <> $2",
    )
    .bind(carbon_id)
    .bind(current_session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_access_revoke"))?;
    Ok(())
}

async fn lock_current_session(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    carbon_id: Uuid,
) -> Result<(), AppError> {
    let active = sqlx::query_scalar::<_, bool>(
        r"
        SELECT true
        FROM iam.authentication_sessions AS session
        JOIN iam.principals AS principal
          ON principal.id = session.subject_principal_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
         AND principal.auth_epoch = session.subject_auth_epoch
        WHERE session.id = $1 AND session.subject_principal_id = $2
          AND session.status = 'active'
          AND session.idle_expires_at > transaction_timestamp()
          AND session.absolute_expires_at > transaction_timestamp()
        FOR UPDATE OF session, principal
        ",
    )
    .bind(authenticated.0.authentication_session_id)
    .bind(carbon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| internal("contact_change_session_lock"))?
    .unwrap_or(false);
    if active {
        Ok(())
    } else {
        Err(AppError::Unauthenticated)
    }
}

async fn consume_step_up(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    carbon_id: Uuid,
) -> Result<(), AppError> {
    let raw = headers
        .get("x-step-up-token")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::PreconditionRequired {
            code: Cow::Borrowed("step_up_required"),
        })?;
    let token = StepUpToken::parse(raw).map_err(|_| AppError::PreconditionFailed {
        code: Cow::Borrowed("step_up_invalid"),
    })?;
    step_up::consume(
        transaction,
        &state.crypto,
        &token,
        StepUpExpectation {
            carbon_id,
            authentication_session_id: authenticated.0.authentication_session_id,
            action: ACTION,
            resource_id: Some(carbon_id),
            required_assurance: RequiredAssurance::VerifiedChannel,
        },
    )
    .await
    .map(|_| ())
}

async fn deliver_otp(state: &ApiState, delivery: Option<&Delivery>) {
    let Some(delivery) = delivery else {
        return;
    };
    let minutes = state.settings.security.otp_ttl.as_secs().div_ceil(60);
    let expires_in_minutes = u16::try_from(minutes).unwrap_or(u16::MAX);
    let result = match delivery.channel {
        ContactChannel::Email => {
            state
                .notifications
                .email
                .send_otp(crate::application::ports::EmailOtp {
                    recipient: &delivery.recipient,
                    code: &delivery.code,
                    purpose: delivery.purpose,
                    expires_in_minutes,
                })
                .await
        }
        ContactChannel::Phone => {
            state
                .notifications
                .sms
                .send_otp(crate::application::ports::SmsOtp {
                    recipient: &delivery.recipient,
                    code: &delivery.code,
                    expires_in_minutes,
                })
                .await
        }
    };
    if result.is_err() {
        tracing::warn!(
            channel = delivery.channel.database_value(),
            "contact-change OTP delivery did not complete"
        );
    }
}

async fn enforce_limit(
    state: &ApiState,
    name: &'static str,
    carbon_id: Uuid,
    value: &str,
    maximum: u32,
) -> Result<(), AppError> {
    let scope = SecretString::from(format!("{carbon_id}:{value}"));
    let maximum = NonZeroU32::new(maximum).ok_or_else(|| internal("contact_change_rate_policy"))?;
    let window = Duration::from_mins(10);
    let policy = RateLimitPolicy::new(maximum, window, window)
        .map_err(|_| internal("contact_change_rate_policy"))?;
    rate_limit::enforce(&state.pool, &state.crypto, name, &scope, policy).await?;
    Ok(())
}

fn profile_response(profile: me::CarbonProfileResponse) -> Result<Response, AppError> {
    let version = profile.version;
    let mut response = (StatusCode::OK, Json(profile)).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{version}\""))
            .map_err(|_| internal("contact_change_etag"))?,
    );
    Ok(response)
}

fn no_store<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

const fn start_route(channel: ContactChannel) -> &'static str {
    match channel {
        ContactChannel::Email => EMAIL_START_ROUTE,
        ContactChannel::Phone => PHONE_START_ROUTE,
    }
}

const fn verify_route(channel: ContactChannel) -> &'static str {
    match channel {
        ContactChannel::Email => EMAIL_VERIFY_ROUTE,
        ContactChannel::Phone => PHONE_VERIFY_ROUTE,
    }
}

const fn otp_purpose(channel: ContactChannel) -> DigestPurpose {
    match channel {
        ContactChannel::Email => DigestPurpose::ContactChangeEmailOtp,
        ContactChannel::Phone => DigestPurpose::ContactChangePhoneOtp,
    }
}

const fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use super::{ContactChannel, otp_purpose, start_route, verify_route};
    use crate::infrastructure::crypto::DigestPurpose;

    #[test]
    fn contact_change_channels_have_distinct_routes_and_digest_domains() {
        assert_ne!(
            start_route(ContactChannel::Email),
            start_route(ContactChannel::Phone)
        );
        assert_ne!(
            verify_route(ContactChannel::Email),
            verify_route(ContactChannel::Phone)
        );
        assert_eq!(
            otp_purpose(ContactChannel::Email),
            DigestPurpose::ContactChangeEmailOtp
        );
        assert_eq!(
            otp_purpose(ContactChannel::Phone),
            DigestPurpose::ContactChangePhoneOtp
        );
    }
}
