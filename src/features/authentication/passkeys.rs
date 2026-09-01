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
use webauthn_rs::prelude::{
    CreationChallengeResponse, Credential, CredentialID, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn, WebauthnBuilder,
};

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::ActorType,
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField, SecretKind},
        postgres::{
            rate_limit::{self, RateLimitPolicy},
            step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
        },
    },
};

use super::{
    database::{database_conflict, serializable, set_principal_context},
    events::{self, SecurityMutation},
    idempotency::{self, Claim, IdempotencyKey},
    model::{EmptyMutationOutcome, StepUpAction, StepUpTokenResponse},
    validation,
};

const REGISTRATION_OPTIONS_ROUTE: &str = "/api/v1/me/passkeys/registration-options";
const REGISTRATION_COMPLETE_ROUTE: &str = "/api/v1/me/passkeys/registrations";
const PASSKEY_REVOKE_ROUTE: &str = "/api/v1/me/passkeys/:credential_id";
const STEP_UP_OPTIONS_ROUTE: &str = "/api/v1/step-up/passkey/options";
const STEP_UP_VERIFY_ROUTE: &str = "/api/v1/step-up/passkey/verify";
const CEREMONY_TTL_SECONDS: i64 = 300;
const ASSERTION_TTL_SECONDS: i64 = 300;
const ACCOUNT_CREDENTIAL_CHANGE_ACTION: &str = "account.contact_change";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistrationVerifyInput {
    ceremony_id: Uuid,
    name: String,
    credential: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StepUpOptionsInput {
    action: StepUpAction,
    resource_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssertionVerifyInput {
    ceremony_id: Uuid,
    credential: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RegistrationOptionsResponse {
    ceremony_id: Uuid,
    #[serde(flatten)]
    options: CreationChallengeResponse,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AssertionOptionsResponse {
    ceremony_id: Uuid,
    #[serde(flatten)]
    options: RequestChallengeResponse,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct PasskeyResponse {
    id: Uuid,
    name: String,
    transports: Vec<String>,
    backup_eligible: bool,
    backup_state: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_used_at: Option<OffsetDateTime>,
}

#[derive(Serialize)]
pub(super) struct PasskeyListResponse {
    items: Vec<PasskeyResponse>,
}

#[derive(FromRow)]
struct CarbonRegistrationIdentity {
    carbon_id: String,
    display_name: String,
}

#[derive(FromRow)]
struct CredentialRow {
    id: Uuid,
    credential_id: Vec<u8>,
    credential_state: Vec<u8>,
    name: String,
    sign_count: i64,
    transports: Vec<String>,
    backup_eligible: bool,
    backup_state: bool,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
}

#[derive(FromRow)]
struct CeremonyRow {
    id: Uuid,
    action: Option<String>,
    resource_id: Option<Uuid>,
    rp_id: String,
    origin: String,
    state_ciphertext: Vec<u8>,
    state_nonce: Vec<u8>,
    state_encryption_key_version: i16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum AssertionOutcome {
    Success(StepUpTokenResponse),
    Compromised,
}

pub(super) async fn list(
    State(state): State<ApiState>,
    authenticated: Authenticated,
) -> Result<Json<PasskeyListResponse>, AppError> {
    let carbon_id = require_self_service(&authenticated)?;
    let mut transaction = crate::infrastructure::postgres::context::begin(
        &state.pool,
        crate::infrastructure::postgres::context::DatabaseContext::principal(carbon_id),
    )
    .await
    .map_err(|_| internal("passkey_list_context"))?;
    let rows = sqlx::query_as::<_, CredentialRow>(
        r"
        SELECT id, credential_id, credential_state, name, sign_count, transports,
               backup_eligible, backup_state, created_at, last_used_at
        FROM iam.webauthn_credentials
        WHERE carbon_id = $1 AND status = 'active'
        ORDER BY created_at, id
        ",
    )
    .bind(carbon_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| internal("passkey_list_read"))?;
    transaction
        .commit()
        .await
        .map_err(|_| internal("passkey_list_commit"))?;
    let items = rows.into_iter().map(CredentialRow::public).collect();
    Ok(Json(PasskeyListResponse { items }))
}

#[allow(
    clippy::too_many_lines,
    reason = "registration options bind step-up, existing credentials, server state, audit, and idempotency atomically"
)]
pub(super) async fn registration_options(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let carbon_id = require_self_service(&authenticated)?;
    enforce_limit(&state, "passkey_registration_options", carbon_id, 5).await?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let request_digest = idempotency::digest_parts(
        b"passkey-registration-options",
        &[
            carbon_id.as_bytes(),
            authenticated.0.authentication_session_id.as_bytes(),
        ],
    );
    let mut transaction =
        serializable(&state.pool, "passkey_registration_options_transaction").await?;
    set_principal_context(&mut transaction, carbon_id).await?;
    let record_id = match idempotency::begin::<RegistrationOptionsResponse>(
        &mut transaction,
        &state.crypto,
        &key,
        carbon_id.as_bytes(),
        REGISTRATION_OPTIONS_ROUTE,
        request_digest,
        true,
    )
    .await?
    {
        Claim::Replay { response } => {
            transaction
                .commit()
                .await
                .map_err(|_| internal("passkey_registration_options_replay_commit"))?;
            return Ok(no_store_json(StatusCode::CREATED, response));
        }
        Claim::Acquired { record_id } => record_id,
    };
    lock_current_session(&mut transaction, &authenticated, carbon_id).await?;
    consume_step_up(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        ACCOUNT_CREDENTIAL_CHANGE_ACTION,
        carbon_id,
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let identity = registration_identity(&mut transaction, carbon_id).await?;
    let credentials = active_credentials(&mut transaction, carbon_id, false).await?;
    let excluded = credentials
        .iter()
        .map(|row| CredentialID::from(row.credential_id.clone()))
        .collect::<Vec<_>>();
    let binding = webauthn(&state)?;
    let (options, registration_state) = binding
        .service
        .start_passkey_registration(
            carbon_id,
            &identity.carbon_id,
            &identity.display_name,
            Some(excluded),
        )
        .map_err(|_| internal("passkey_registration_start"))?;
    let ceremony_id = Uuid::now_v7();
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(CEREMONY_TTL_SECONDS);
    insert_ceremony(
        &mut transaction,
        &state,
        CeremonyInsert {
            id: ceremony_id,
            carbon_id,
            authentication_session_id: authenticated.0.authentication_session_id,
            kind: "registration",
            action: None,
            resource_id: None,
            binding: &binding,
            state: &registration_state,
            field: ProtectedField::WebauthnRegistrationState,
            expires_at,
        },
    )
    .await?;
    let response = RegistrationOptionsResponse {
        ceremony_id,
        options,
        expires_at,
    };
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "passkey.registration_started",
            authentication_outcome: "success",
            audit_action: "passkey.registration_start",
            audit_result: "success",
            outbox_event: "passkey.registration_started",
            subject_id: Some(carbon_id),
            actor_id: Some(carbon_id),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            aggregate_type: "webauthn_ceremony",
            aggregate_id: ceremony_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({ "credential_count": credentials.len() }),
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        StatusCode::CREATED.as_u16(),
        &response,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "passkey_registration_options_conflict"))?;
    Ok(no_store_json(StatusCode::CREATED, response))
}

#[allow(
    clippy::too_many_lines,
    reason = "library verification, credential uniqueness, ceremony consumption, audit, and idempotency must commit together"
)]
pub(super) async fn complete_registration(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
    payload: Result<Json<RegistrationVerifyInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let carbon_id = require_self_service(&authenticated)?;
    let input = json_body(payload)?;
    let name = bounded_name(input.name)?;
    let credential: RegisterPublicKeyCredential = serde_json::from_value(input.credential.clone())
        .map_err(|_| validation::validation("credential", "has an invalid WebAuthn shape"))?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let request_bytes = serde_json::to_vec(&input.credential)
        .map_err(|_| internal("passkey_registration_request_encode"))?;
    let request_digest = idempotency::digest_parts(
        b"passkey-registration-complete",
        &[
            input.ceremony_id.as_bytes(),
            name.as_bytes(),
            &request_bytes,
        ],
    );
    let mut transaction =
        serializable(&state.pool, "passkey_registration_complete_transaction").await?;
    set_principal_context(&mut transaction, carbon_id).await?;
    let record_id = match idempotency::begin::<PasskeyResponse>(
        &mut transaction,
        &state.crypto,
        &key,
        carbon_id.as_bytes(),
        REGISTRATION_COMPLETE_ROUTE,
        request_digest,
        false,
    )
    .await?
    {
        Claim::Replay { response } => {
            transaction
                .commit()
                .await
                .map_err(|_| internal("passkey_registration_replay_commit"))?;
            return Ok(no_store_json(StatusCode::CREATED, response));
        }
        Claim::Acquired { record_id } => record_id,
    };
    lock_current_session(&mut transaction, &authenticated, carbon_id).await?;
    let ceremony = lock_ceremony(
        &mut transaction,
        input.ceremony_id,
        carbon_id,
        authenticated.0.authentication_session_id,
        "registration",
    )
    .await?;
    let binding = webauthn(&state)?;
    validate_binding(&ceremony, &binding)?;
    let registration_state: PasskeyRegistration =
        decrypt_ceremony(&state, &ceremony, ProtectedField::WebauthnRegistrationState)?;
    let passkey = binding
        .service
        .finish_passkey_registration(&credential, &registration_state)
        .map_err(|_| validation::validation("credential", "failed WebAuthn verification"))?;
    let stored = StoredCredential::from_verified(passkey)?;
    let credential_id = Uuid::now_v7();
    let row = sqlx::query_as::<_, CredentialRow>(
        r"
        INSERT INTO iam.webauthn_credentials (
            id, carbon_id, credential_id, credential_state, name, sign_count,
            transports, backup_eligible, backup_state
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, credential_id, credential_state, name, sign_count, transports,
                  backup_eligible, backup_state, created_at, last_used_at
        ",
    )
    .bind(credential_id)
    .bind(carbon_id)
    .bind(&stored.credential_id)
    .bind(&stored.state)
    .bind(name)
    .bind(stored.sign_count)
    .bind(&stored.transports)
    .bind(stored.backup_eligible)
    .bind(stored.backup_state)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| database_conflict(&error, "passkey_credential_conflict"))?;
    complete_ceremony(&mut transaction, ceremony.id).await?;
    let response = row.public();
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "passkey.registered",
            authentication_outcome: "success",
            audit_action: "passkey.register",
            audit_result: "success",
            outbox_event: "passkey.registered",
            subject_id: Some(carbon_id),
            actor_id: Some(carbon_id),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            aggregate_type: "webauthn_credential",
            aggregate_id: credential_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({ "backup_eligible": response.backup_eligible }),
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        StatusCode::CREATED.as_u16(),
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "passkey_registration_conflict"))?;
    Ok(no_store_json(StatusCode::CREATED, response))
}

#[allow(
    clippy::too_many_lines,
    reason = "revocation enforces step-up, last-admin-passkey policy, audit, and idempotency in one transaction"
)]
pub(super) async fn revoke(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(credential_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let carbon_id = require_self_service(&authenticated)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let request_digest = idempotency::digest_parts(
        b"passkey-revoke",
        &[carbon_id.as_bytes(), credential_id.as_bytes()],
    );
    let mut transaction = serializable(&state.pool, "passkey_revoke_transaction").await?;
    set_principal_context(&mut transaction, carbon_id).await?;
    let record_id = match idempotency::begin::<EmptyMutationOutcome>(
        &mut transaction,
        &state.crypto,
        &key,
        carbon_id.as_bytes(),
        PASSKEY_REVOKE_ROUTE,
        request_digest,
        false,
    )
    .await?
    {
        Claim::Replay { .. } => {
            transaction
                .commit()
                .await
                .map_err(|_| internal("passkey_revoke_replay_commit"))?;
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        Claim::Acquired { record_id } => record_id,
    };
    lock_current_session(&mut transaction, &authenticated, carbon_id).await?;
    consume_step_up(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        ACCOUNT_CREDENTIAL_CHANGE_ACTION,
        carbon_id,
        RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let is_platform_admin = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1 FROM iam.platform_role_grants
            WHERE carbon_id = $1 AND role = 'platform_administrator' AND revoked_at IS NULL
        )
        ",
    )
    .bind(carbon_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| internal("passkey_admin_status"))?;
    let active_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.webauthn_credentials WHERE carbon_id = $1 AND status = 'active'",
    )
    .bind(carbon_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| internal("passkey_active_count"))?;
    if is_platform_admin && active_count <= 1 {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("last_platform_admin_passkey"),
        });
    }
    let version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.webauthn_credentials
        SET status = 'revoked', revoked_at = transaction_timestamp()
        WHERE id = $1 AND carbon_id = $2 AND status = 'active'
        RETURNING version
        ",
    )
    .bind(credential_id)
    .bind(carbon_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| internal("passkey_revoke_update"))?
    .ok_or(AppError::NotFound)?;
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "passkey.revoked",
            authentication_outcome: "success",
            audit_action: "passkey.revoke",
            audit_result: "success",
            outbox_event: "passkey.revoked",
            subject_id: Some(carbon_id),
            actor_id: Some(carbon_id),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            aggregate_type: "webauthn_credential",
            aggregate_id: credential_id,
            aggregate_version: version,
            failure_code: None,
            metadata: json!({}),
        },
    )
    .await?;
    let response = EmptyMutationOutcome::Completed;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        StatusCode::NO_CONTENT.as_u16(),
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "passkey_revoke_conflict"))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[allow(
    clippy::too_many_lines,
    reason = "assertion options bind the current session, action, credentials, server state, audit, and idempotency"
)]
pub(super) async fn step_up_options(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
    payload: Result<Json<StepUpOptionsInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let carbon_id = require_self_service(&authenticated)?;
    let input = json_body(payload)?;
    enforce_limit(&state, "passkey_step_up_options", carbon_id, 10).await?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let resource = input.resource_id.map(Uuid::into_bytes);
    let request_digest = idempotency::digest_parts(
        b"passkey-step-up-options",
        &[
            carbon_id.as_bytes(),
            authenticated.0.authentication_session_id.as_bytes(),
            input.action.database_value().as_bytes(),
            resource.as_ref().map_or(&[], |value| value.as_slice()),
        ],
    );
    let mut transaction = serializable(&state.pool, "passkey_step_up_options_transaction").await?;
    set_principal_context(&mut transaction, carbon_id).await?;
    let record_id = match idempotency::begin::<AssertionOptionsResponse>(
        &mut transaction,
        &state.crypto,
        &key,
        carbon_id.as_bytes(),
        STEP_UP_OPTIONS_ROUTE,
        request_digest,
        true,
    )
    .await?
    {
        Claim::Replay { response } => {
            transaction
                .commit()
                .await
                .map_err(|_| internal("passkey_step_up_options_replay_commit"))?;
            return Ok(no_store_json(StatusCode::CREATED, response));
        }
        Claim::Acquired { record_id } => record_id,
    };
    lock_current_session(&mut transaction, &authenticated, carbon_id).await?;
    let rows = active_credentials(&mut transaction, carbon_id, true).await?;
    if rows.is_empty() {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("passkey_required"),
        });
    }
    let passkeys = rows
        .iter()
        .map(CredentialRow::decode)
        .collect::<Result<Vec<_>, _>>()?;
    let binding = webauthn(&state)?;
    let (options, authentication_state) = binding
        .service
        .start_passkey_authentication(&passkeys)
        .map_err(|_| internal("passkey_authentication_start"))?;
    let ceremony_id = Uuid::now_v7();
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(CEREMONY_TTL_SECONDS);
    insert_ceremony(
        &mut transaction,
        &state,
        CeremonyInsert {
            id: ceremony_id,
            carbon_id,
            authentication_session_id: authenticated.0.authentication_session_id,
            kind: "step_up",
            action: Some(input.action.database_value()),
            resource_id: input.resource_id,
            binding: &binding,
            state: &authentication_state,
            field: ProtectedField::WebauthnAuthenticationState,
            expires_at,
        },
    )
    .await?;
    let response = AssertionOptionsResponse {
        ceremony_id,
        options,
        expires_at,
    };
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "passkey.step_up_started",
            authentication_outcome: "success",
            audit_action: "passkey.step_up_start",
            audit_result: "success",
            outbox_event: "passkey.step_up_started",
            subject_id: Some(carbon_id),
            actor_id: Some(carbon_id),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            aggregate_type: "webauthn_ceremony",
            aggregate_id: ceremony_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({
                "action": input.action.database_value(),
                "resource_id": input.resource_id,
            }),
        },
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        StatusCode::CREATED.as_u16(),
        &response,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "passkey_step_up_options_conflict"))?;
    Ok(no_store_json(StatusCode::CREATED, response))
}

#[allow(
    clippy::too_many_lines,
    reason = "assertion verification, defensive counter handling, credential update, token issue, audit, and idempotency are atomic"
)]
pub(super) async fn verify_step_up(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
    payload: Result<Json<AssertionVerifyInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let carbon_id = require_self_service(&authenticated)?;
    let input = json_body(payload)?;
    let credential: PublicKeyCredential = serde_json::from_value(input.credential.clone())
        .map_err(|_| validation::validation("credential", "has an invalid WebAuthn shape"))?;
    enforce_limit(&state, "passkey_step_up_verify", input.ceremony_id, 10).await?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let request_bytes = serde_json::to_vec(&input.credential)
        .map_err(|_| internal("passkey_assertion_request_encode"))?;
    let request_digest = idempotency::digest_parts(
        b"passkey-step-up-verify",
        &[input.ceremony_id.as_bytes(), &request_bytes],
    );
    let mut transaction = serializable(&state.pool, "passkey_step_up_verify_transaction").await?;
    set_principal_context(&mut transaction, carbon_id).await?;
    let record_id = match idempotency::begin::<AssertionOutcome>(
        &mut transaction,
        &state.crypto,
        &key,
        carbon_id.as_bytes(),
        STEP_UP_VERIFY_ROUTE,
        request_digest,
        true,
    )
    .await?
    {
        Claim::Replay { response } => {
            transaction
                .commit()
                .await
                .map_err(|_| internal("passkey_step_up_replay_commit"))?;
            return assertion_outcome_response(response);
        }
        Claim::Acquired { record_id } => record_id,
    };
    lock_current_session(&mut transaction, &authenticated, carbon_id).await?;
    let ceremony = lock_ceremony(
        &mut transaction,
        input.ceremony_id,
        carbon_id,
        authenticated.0.authentication_session_id,
        "step_up",
    )
    .await?;
    let binding = webauthn(&state)?;
    validate_binding(&ceremony, &binding)?;
    let authentication_state: PasskeyAuthentication = decrypt_ceremony(
        &state,
        &ceremony,
        ProtectedField::WebauthnAuthenticationState,
    )?;
    let result = binding
        .service
        .finish_passkey_authentication(&credential, &authentication_state)
        .map_err(|_| AppError::Unauthenticated)?;
    let mut row =
        lock_credential_by_wire_id(&mut transaction, carbon_id, result.cred_id().as_slice())
            .await?;
    let new_counter = i64::from(result.counter());
    if row.sign_count > 0 && new_counter <= row.sign_count {
        revoke_compromised_credential(&mut transaction, &authenticated, carbon_id, &row).await?;
        complete_ceremony(&mut transaction, ceremony.id).await?;
        let outcome = AssertionOutcome::Compromised;
        idempotency::complete(
            &mut transaction,
            &state.crypto,
            record_id,
            StatusCode::CONFLICT.as_u16(),
            &outcome,
            false,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_conflict(&error, "passkey_counter_revoke_conflict"))?;
        return assertion_outcome_response(outcome);
    }
    let mut passkey = row.decode()?;
    passkey
        .update_credential(&result)
        .ok_or_else(|| internal("passkey_credential_result_mismatch"))?;
    let credential_state =
        serde_json::to_vec(&passkey).map_err(|_| internal("passkey_credential_encode"))?;
    row.sign_count = new_counter.max(row.sign_count);
    sqlx::query(
        r"
        UPDATE iam.webauthn_credentials
        SET credential_state = $2,
            sign_count = $3,
            backup_eligible = $4,
            backup_state = $5,
            last_used_at = transaction_timestamp()
        WHERE id = $1 AND status = 'active'
        ",
    )
    .bind(row.id)
    .bind(credential_state)
    .bind(row.sign_count)
    .bind(result.backup_eligible())
    .bind(result.backup_state())
    .execute(&mut *transaction)
    .await
    .map_err(|_| internal("passkey_credential_update"))?;
    complete_ceremony(&mut transaction, ceremony.id).await?;
    let token =
        issue_step_up_assertion(&mut transaction, &state, &authenticated, &ceremony).await?;
    events::record(
        &mut transaction,
        SecurityMutation {
            authentication_event: "passkey.step_up_success",
            authentication_outcome: "success",
            audit_action: "passkey.step_up_verify",
            audit_result: "success",
            outbox_event: "step_up.assertion_created",
            subject_id: Some(carbon_id),
            actor_id: Some(carbon_id),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            aggregate_type: "webauthn_ceremony",
            aggregate_id: ceremony.id,
            aggregate_version: 2,
            failure_code: None,
            metadata: json!({
                "action": ceremony.action,
                "resource_id": ceremony.resource_id,
                "credential_id": row.id,
                "assurance": "phishing_resistant",
            }),
        },
    )
    .await?;
    let outcome = AssertionOutcome::Success(token);
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        StatusCode::OK.as_u16(),
        &outcome,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "passkey_step_up_verify_conflict"))?;
    assertion_outcome_response(outcome)
}

struct WebauthnBinding {
    service: Webauthn,
    rp_id: String,
    origin: String,
}

struct CeremonyInsert<'a, T> {
    id: Uuid,
    carbon_id: Uuid,
    authentication_session_id: Uuid,
    kind: &'static str,
    action: Option<&'static str>,
    resource_id: Option<Uuid>,
    binding: &'a WebauthnBinding,
    state: &'a T,
    field: ProtectedField,
    expires_at: OffsetDateTime,
}

struct StoredCredential {
    credential_id: Vec<u8>,
    state: Vec<u8>,
    sign_count: i64,
    transports: Vec<String>,
    backup_eligible: bool,
    backup_state: bool,
}

impl StoredCredential {
    fn from_verified(passkey: Passkey) -> Result<Self, AppError> {
        let state =
            serde_json::to_vec(&passkey).map_err(|_| internal("passkey_credential_encode"))?;
        let credential: Credential = passkey.into();
        let transports = credential
            .transports
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .filter(|value| {
                matches!(
                    value.as_str(),
                    "usb" | "nfc" | "ble" | "internal" | "hybrid"
                )
            })
            .collect::<Vec<_>>();
        Ok(Self {
            credential_id: credential.cred_id.as_slice().to_vec(),
            state,
            sign_count: i64::from(credential.counter),
            transports,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
        })
    }
}

impl CredentialRow {
    fn decode(&self) -> Result<Passkey, AppError> {
        serde_json::from_slice(&self.credential_state)
            .map_err(|_| internal("passkey_credential_decode"))
    }

    fn public(self) -> PasskeyResponse {
        PasskeyResponse {
            id: self.id,
            name: self.name,
            transports: self.transports,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        }
    }
}

fn require_self_service(authenticated: &Authenticated) -> Result<Uuid, AppError> {
    let access = &authenticated.0;
    if access.subject.actor_type == ActorType::Carbon
        && access.audience == "silicon-iam"
        && access.client_application_id.is_none()
        && access.organization_id.is_none()
        && access.membership_id.is_none()
        && access.scopes.iter().any(|scope| scope == "iam.self")
    {
        Ok(access.subject.id)
    } else {
        Err(AppError::Forbidden)
    }
}

async fn lock_current_session(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    carbon_id: Uuid,
) -> Result<(), AppError> {
    let active = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM iam.authentication_sessions AS session
            JOIN iam.principals AS principal
              ON principal.id = session.subject_principal_id
             AND principal.kind = 'carbon'
             AND principal.status = 'active'
             AND principal.auth_epoch = session.subject_auth_epoch
            WHERE session.id = $1
              AND session.subject_principal_id = $2
              AND session.subject_kind = 'carbon'
              AND session.status = 'active'
              AND session.idle_expires_at > transaction_timestamp()
              AND session.absolute_expires_at > transaction_timestamp()
            FOR UPDATE OF session, principal
        )
        ",
    )
    .bind(authenticated.0.authentication_session_id)
    .bind(carbon_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| internal("passkey_session_lock"))?;
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
    action: &'static str,
    resource_id: Uuid,
    assurance: RequiredAssurance,
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
            carbon_id: authenticated.0.subject.id,
            authentication_session_id: authenticated.0.authentication_session_id,
            action,
            resource_id: Some(resource_id),
            required_assurance: assurance,
        },
    )
    .await
    .map(|_| ())
}

fn webauthn(state: &ApiState) -> Result<WebauthnBinding, AppError> {
    let mut origin = state.settings.server.auth_base_url.clone();
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    let rp_id = origin
        .host_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| internal("webauthn_rp_id"))?
        .to_owned();
    let origin_value = origin.origin().ascii_serialization();
    let service = WebauthnBuilder::new(&rp_id, &origin)
        .map_err(|_| internal("webauthn_configuration"))?
        .rp_name("Silicon")
        .timeout(Duration::from_secs(
            u64::try_from(CEREMONY_TTL_SECONDS).unwrap_or(300),
        ))
        .build()
        .map_err(|_| internal("webauthn_configuration"))?;
    Ok(WebauthnBinding {
        service,
        rp_id,
        origin: origin_value,
    })
}

async fn registration_identity(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
) -> Result<CarbonRegistrationIdentity, AppError> {
    sqlx::query_as::<_, CarbonRegistrationIdentity>(
        r"
        SELECT carbon.carbon_id, carbon.display_name
        FROM iam.carbons AS carbon
        JOIN iam.principals AS principal
          ON principal.id = carbon.id AND principal.kind = 'carbon' AND principal.status = 'active'
        WHERE carbon.id = $1 AND carbon.deleted_at IS NULL
        ",
    )
    .bind(carbon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| internal("passkey_carbon_read"))?
    .ok_or(AppError::Unauthenticated)
}

async fn active_credentials(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    lock: bool,
) -> Result<Vec<CredentialRow>, AppError> {
    let sql = if lock {
        r"
        SELECT id, credential_id, credential_state, name, sign_count, transports,
               backup_eligible, backup_state, created_at, last_used_at
        FROM iam.webauthn_credentials
        WHERE carbon_id = $1 AND status = 'active'
        ORDER BY created_at, id
        FOR UPDATE
        "
    } else {
        r"
        SELECT id, credential_id, credential_state, name, sign_count, transports,
               backup_eligible, backup_state, created_at, last_used_at
        FROM iam.webauthn_credentials
        WHERE carbon_id = $1 AND status = 'active'
        ORDER BY created_at, id
        "
    };
    sqlx::query_as::<_, CredentialRow>(sql)
        .bind(carbon_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| internal("passkey_credentials_read"))
}

async fn insert_ceremony<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    input: CeremonyInsert<'_, T>,
) -> Result<(), AppError> {
    let serialized =
        serde_json::to_vec(input.state).map_err(|_| internal("webauthn_state_encode"))?;
    let encrypted = state
        .crypto
        .encrypt(
            EncryptionContext::global(input.field, input.id),
            &serialized,
        )
        .map_err(|_| internal("webauthn_state_encrypt"))?;
    sqlx::query(
        r"
        INSERT INTO iam.webauthn_ceremonies (
            id, carbon_id, authentication_session_id, ceremony_kind,
            action, resource_id, rp_id, origin,
            state_ciphertext, state_nonce, state_encryption_key_version, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ",
    )
    .bind(input.id)
    .bind(input.carbon_id)
    .bind(input.authentication_session_id)
    .bind(input.kind)
    .bind(input.action)
    .bind(input.resource_id)
    .bind(&input.binding.rp_id)
    .bind(&input.binding.origin)
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce.as_slice())
    .bind(encrypted.key_version)
    .bind(input.expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| database_conflict(&error, "webauthn_ceremony_conflict"))?;
    Ok(())
}

async fn lock_ceremony(
    transaction: &mut Transaction<'_, Postgres>,
    ceremony_id: Uuid,
    carbon_id: Uuid,
    authentication_session_id: Uuid,
    kind: &'static str,
) -> Result<CeremonyRow, AppError> {
    sqlx::query_as::<_, CeremonyRow>(
        r"
        SELECT id, action, resource_id, rp_id, origin,
               state_ciphertext, state_nonce, state_encryption_key_version
        FROM iam.webauthn_ceremonies
        WHERE id = $1
          AND carbon_id = $2
          AND authentication_session_id = $3
          AND ceremony_kind = $4
          AND status = 'pending'
          AND expires_at > transaction_timestamp()
        FOR UPDATE
        ",
    )
    .bind(ceremony_id)
    .bind(carbon_id)
    .bind(authentication_session_id)
    .bind(kind)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| internal("webauthn_ceremony_lock"))?
    .ok_or(AppError::Gone {
        code: Cow::Borrowed("webauthn_ceremony_expired"),
    })
}

fn decrypt_ceremony<T: for<'de> Deserialize<'de>>(
    state: &ApiState,
    ceremony: &CeremonyRow,
    field: ProtectedField,
) -> Result<T, AppError> {
    let nonce: [u8; 12] = ceremony
        .state_nonce
        .as_slice()
        .try_into()
        .map_err(|_| internal("webauthn_state_nonce"))?;
    let plaintext = state
        .crypto
        .decrypt(
            EncryptionContext::global(field, ceremony.id),
            &EncryptedValue {
                key_version: ceremony.state_encryption_key_version,
                nonce,
                ciphertext: ceremony.state_ciphertext.clone(),
            },
        )
        .map_err(|_| internal("webauthn_state_decrypt"))?;
    serde_json::from_slice(&plaintext).map_err(|_| internal("webauthn_state_decode"))
}

fn validate_binding(ceremony: &CeremonyRow, binding: &WebauthnBinding) -> Result<(), AppError> {
    if ceremony.rp_id == binding.rp_id && ceremony.origin == binding.origin {
        Ok(())
    } else {
        Err(AppError::PreconditionFailed {
            code: Cow::Borrowed("webauthn_binding_changed"),
        })
    }
}

async fn complete_ceremony(
    transaction: &mut Transaction<'_, Postgres>,
    ceremony_id: Uuid,
) -> Result<(), AppError> {
    let result = sqlx::query(
        r"
        UPDATE iam.webauthn_ceremonies
        SET status = 'completed', consumed_at = transaction_timestamp()
        WHERE id = $1 AND status = 'pending' AND expires_at > transaction_timestamp()
        ",
    )
    .bind(ceremony_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("webauthn_ceremony_complete"))?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AppError::Conflict {
            code: Cow::Borrowed("webauthn_ceremony_race"),
        })
    }
}

async fn lock_credential_by_wire_id(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    credential_id: &[u8],
) -> Result<CredentialRow, AppError> {
    sqlx::query_as::<_, CredentialRow>(
        r"
        SELECT id, credential_id, credential_state, name, sign_count, transports,
               backup_eligible, backup_state, created_at, last_used_at
        FROM iam.webauthn_credentials
        WHERE carbon_id = $1 AND credential_id = $2 AND status = 'active'
        FOR UPDATE
        ",
    )
    .bind(carbon_id)
    .bind(credential_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| internal("passkey_credential_lock"))?
    .ok_or(AppError::Unauthenticated)
}

async fn revoke_compromised_credential(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    carbon_id: Uuid,
    row: &CredentialRow,
) -> Result<(), AppError> {
    let version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.webauthn_credentials
        SET status = 'revoked', revoked_at = transaction_timestamp()
        WHERE id = $1 AND carbon_id = $2 AND status = 'active'
        RETURNING version
        ",
    )
    .bind(row.id)
    .bind(carbon_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| internal("passkey_counter_revoke"))?;
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "passkey.counter_replay",
            authentication_outcome: "denied",
            audit_action: "passkey.counter_replay_revoke",
            audit_result: "denied",
            outbox_event: "passkey.compromised",
            subject_id: Some(carbon_id),
            actor_id: Some(carbon_id),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            aggregate_type: "webauthn_credential",
            aggregate_id: row.id,
            aggregate_version: version,
            failure_code: Some("signature_counter_replay"),
            metadata: json!({}),
        },
    )
    .await
}

async fn issue_step_up_assertion(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    ceremony: &CeremonyRow,
) -> Result<StepUpTokenResponse, AppError> {
    let action = ceremony
        .action
        .as_deref()
        .ok_or_else(|| internal("passkey_step_up_action"))?;
    let token = state
        .crypto
        .generate_secret(SecretKind::StepUpAssertion)
        .map_err(|_| internal("passkey_step_up_token_generate"))?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::StepUpAssertion, &token)
        .map_err(|_| internal("passkey_step_up_token_digest"))?;
    let assertion_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.step_up_assertions (
            id, step_up_challenge_id, webauthn_ceremony_id,
            authentication_session_id, carbon_id, purpose,
            token_prefix, token_digest, digest_key_version,
            assurance_level, expires_at
        ) VALUES (
            $1, NULL, $2, $3, $4, $5, $6, $7, $8, 3,
            transaction_timestamp() + ($9::bigint * interval '1 second')
        )
        ",
    )
    .bind(assertion_id)
    .bind(ceremony.id)
    .bind(authenticated.0.authentication_session_id)
    .bind(authenticated.0.subject.id)
    .bind(action)
    .bind(token_prefix(&token)?)
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(ASSERTION_TTL_SECONDS)
    .execute(&mut **transaction)
    .await
    .map_err(|_| internal("passkey_step_up_assertion_create"))?;
    Ok(StepUpTokenResponse {
        step_up_token: token.expose_secret().to_owned(),
        action: parse_action(action)?,
        assurance: "phishing_resistant".to_owned(),
        expires_in: u64::try_from(ASSERTION_TTL_SECONDS).unwrap_or(300),
    })
}

fn parse_action(value: &str) -> Result<StepUpAction, AppError> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|_| internal("passkey_step_up_action"))
}

fn token_prefix(token: &SecretString) -> Result<String, AppError> {
    let value = token.expose_secret();
    if !value.starts_with("sup_") || value.len() != 47 {
        return Err(internal("passkey_step_up_token_shape"));
    }
    value
        .get(..12)
        .map(str::to_owned)
        .ok_or_else(|| internal("passkey_step_up_token_shape"))
}

async fn enforce_limit(
    state: &ApiState,
    name: &'static str,
    scope_id: Uuid,
    maximum: u32,
) -> Result<(), AppError> {
    let maximum = NonZeroU32::new(maximum).ok_or_else(|| internal("passkey_rate_limit"))?;
    let policy = RateLimitPolicy::new(maximum, Duration::from_mins(10), Duration::from_mins(10))
        .map_err(|_| internal("passkey_rate_limit"))?;
    rate_limit::enforce(
        &state.pool,
        &state.crypto,
        name,
        &SecretString::from(scope_id.to_string()),
        policy,
    )
    .await?;
    Ok(())
}

fn bounded_name(value: String) -> Result<String, AppError> {
    let length = value.chars().count();
    if !(1..=200).contains(&length)
        || value.trim().is_empty()
        || value.chars().any(char::is_control)
    {
        Err(validation::validation(
            "name",
            "must contain 1 to 200 non-control characters",
        ))
    } else {
        Ok(value)
    }
}

fn json_body<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, AppError> {
    payload
        .map(|Json(value)| value)
        .map_err(|_| validation::validation("body", "must be valid JSON matching the schema"))
}

fn no_store_json<T: Serialize>(status: StatusCode, value: T) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn assertion_outcome_response(outcome: AssertionOutcome) -> Result<Response, AppError> {
    match outcome {
        AssertionOutcome::Success(response) => Ok(no_store_json(StatusCode::OK, response)),
        AssertionOutcome::Compromised => Err(AppError::Conflict {
            code: Cow::Borrowed("passkey_signature_counter_replay"),
        }),
    }
}

const fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use super::{bounded_name, parse_action};

    #[test]
    fn passkey_names_are_bounded_and_non_control() {
        assert!(bounded_name("MacBook Touch ID".to_owned()).is_ok());
        assert!(bounded_name(String::new()).is_err());
        assert!(bounded_name("bad\nname".to_owned()).is_err());
    }

    #[test]
    fn persisted_step_up_actions_remain_closed() {
        assert!(parse_action("account.delete").is_ok());
        assert!(parse_action("account.future_action").is_err());
    }
}
