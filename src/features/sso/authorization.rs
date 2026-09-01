use std::time::Duration;

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use sqlx::FromRow;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    api::ApiState,
    error::AppError,
    infrastructure::{
        crypto::{
            BlindIndexPurpose, DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField,
            SecretDigest, SecretKind,
        },
        postgres::context::{self, DatabaseContext},
    },
};

use super::{
    model::{CallbackQuery, CorrelationSecret},
    security::BrowserSession,
    support::{self, MutationEvent},
    validation,
};

const AUTHORIZATION_TTL_SECONDS: i64 = 10 * 60;

#[derive(FromRow)]
#[allow(
    clippy::struct_field_names,
    reason = "row fields intentionally mirror the provider and database identifier names"
)]
struct BeginAuthorizationRow {
    organization_id: Uuid,
    connection_id: Uuid,
    provider_organization_id: String,
    provider_connection_id: String,
}

#[derive(FromRow)]
struct CompletionRow {
    authorization_transaction_id: Uuid,
    organization_id: Uuid,
    membership_id: Uuid,
    sso_identity_id: Uuid,
    membership_created: bool,
    config_version: i64,
    return_uri_ciphertext: Vec<u8>,
    return_uri_nonce: Vec<u8>,
    return_uri_encryption_key_version: i16,
}

#[allow(
    clippy::too_many_lines,
    reason = "authorization correlation, encrypted relay state, audit, and provider redirect form one atomic workflow"
)]
pub(super) async fn authorize(
    State(state): State<ApiState>,
    browser_session: BrowserSession,
    Path(raw_org_id): Path<String>,
    query: Result<Query<super::model::AuthorizeQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&raw_org_id)?;
    let Query(query) = query.map_err(|_| validation::field("query", "has an invalid format"))?;
    let input = validation::authorize(
        query,
        &state.settings.server.auth_base_url,
        state.settings.environment,
    )?;
    support::enforce_rate_limit(
        &state,
        "workos_authorization_start",
        SecretString::from(format!(
            "{}:{}:{}",
            browser_session.carbon_id,
            browser_session.session_id,
            org_id.as_str()
        )),
        10,
        Duration::from_mins(10),
    )
    .await?;

    let correlation = generate_correlation(&state)?;
    let state_digest = state
        .crypto
        .digest_secret(DigestPurpose::SsoState, &correlation.state)
        .map_err(|_| internal("sso_state_digest"))?;
    let nonce_digest = state
        .crypto
        .digest_secret(DigestPurpose::SsoNonce, &correlation.nonce)
        .map_err(|_| internal("sso_nonce_digest"))?;
    if state_digest.key_version() != nonce_digest.key_version() {
        return Err(internal("sso_correlation_key_versions"));
    }
    let transaction_id = Uuid::now_v7();
    let encrypted_return_to = state
        .crypto
        .encrypt(
            EncryptionContext::global(ProtectedField::SsoReturnUri, transaction_id),
            input.return_to.as_str().as_bytes(),
        )
        .map_err(|_| internal("sso_return_uri_encrypt"))?;
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(AUTHORIZATION_TTL_SECONDS);
    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext::principal(browser_session.carbon_id),
    )
    .await
    .map_err(support::database)?;
    let target = sqlx::query_as::<_, BeginAuthorizationRow>(
        r"
        SELECT
            organization_id,
            connection_id,
            provider_organization_id,
            provider_connection_id
        FROM iam_private.begin_sso_authorization(
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
        )
        ",
    )
    .bind(org_id.as_str())
    .bind(browser_session.session_id)
    .bind(transaction_id)
    .bind(state_digest.as_bytes().as_slice())
    .bind(nonce_digest.as_bytes().as_slice())
    .bind(state_digest.key_version())
    .bind(&encrypted_return_to.ciphertext)
    .bind(encrypted_return_to.nonce.as_slice())
    .bind(encrypted_return_to.key_version)
    .bind(expires_at)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_authorization_database_error)?
    .ok_or(AppError::NotFound)?;
    support::record_browser_mutation(
        &mut transaction,
        browser_session,
        target.organization_id,
        MutationEvent {
            action: "sso.authorization.start",
            target_type: "sso_authorization_transaction",
            target_id: Some(transaction_id),
            aggregate_type: "sso_authorization_transaction",
            aggregate_id: transaction_id,
            aggregate_version: 1,
            event_type: "sso.authorization.started.v1",
            before_state: None,
            after_state: None,
            metadata: json!({
                "connection_id": target.connection_id,
                "provider_connection_id": target.provider_connection_id,
                "expires_in": AUTHORIZATION_TTL_SECONDS,
            }),
        },
    )
    .await?;
    transaction.commit().await.map_err(support::database)?;

    let callback_url = callback_url(&state)?;
    let authorization_url = support::workos(&state)?
        .authorization_url(
            &target.provider_organization_id,
            &callback_url,
            &correlation.wire_state,
            &correlation.nonce,
        )
        .map_err(support::map_workos)?;
    redirect(&authorization_url)
}

#[allow(
    clippy::too_many_lines,
    reason = "callback correlation, provider exchange, admission, audit, and redirect are explicit"
)]
pub(super) async fn callback(
    State(state): State<ApiState>,
    browser_session: BrowserSession,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Result<Response, AppError> {
    let Query(query) = query.map_err(|_| validation::field("query", "has an invalid format"))?;
    let query = validation::callback(query)?;
    let correlation = validation::correlation_from_wire(&query.state)?;
    validation::validate_correlation_parts(&correlation)?;
    let state_digests = state
        .crypto
        .digest_secrets(DigestPurpose::SsoState, &correlation.state)
        .map_err(|_| internal("sso_state_digest"))?;
    let nonce_digests = state
        .crypto
        .digest_secrets(DigestPurpose::SsoNonce, &correlation.nonce)
        .map_err(|_| internal("sso_nonce_digest"))?;
    let candidates = CorrelationCandidates::new(&state_digests, &nonce_digests)?;
    require_valid_callback_correlation(&state, browser_session, &candidates).await?;
    support::enforce_rate_limit(
        &state,
        "workos_callback",
        correlation.wire_state.clone(),
        5,
        Duration::from_mins(10),
    )
    .await?;

    let code = SecretString::from(query.code);
    let profile = support::workos(&state)?
        .exchange_code(&code)
        .await
        .map_err(support::map_workos)?;
    let normalized_email = validation::provider_email(&profile.email)?;
    let contact_digests = state
        .crypto
        .blind_indexes(BlindIndexPurpose::CarbonEmail, &normalized_email)
        .map_err(|_| internal("sso_contact_digest"))?;
    let contact_versions = contact_digests
        .iter()
        .map(SecretDigest::key_version)
        .collect::<Vec<_>>();
    let contact_values = contact_digests
        .iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();

    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext::principal(browser_session.carbon_id),
    )
    .await
    .map_err(support::database)?;
    let new_membership_id = Uuid::now_v7();
    let new_sso_identity_id = Uuid::now_v7();
    let completion = sqlx::query_as::<_, CompletionRow>(
        r"
        SELECT
            authorization_transaction_id,
            organization_id,
            membership_id,
            sso_identity_id,
            membership_created,
            config_version,
            return_uri_ciphertext,
            return_uri_nonce,
            return_uri_encryption_key_version
        FROM iam_private.complete_sso_authorization(
            $1,
            $2::smallint[], $3::bytea[], $4::bytea[],
            $5, $6, $7, $8,
            $9::smallint[], $10::bytea[], $11::text[],
            $12, $13
        )
        ",
    )
    .bind(browser_session.session_id)
    .bind(&candidates.versions)
    .bind(&candidates.state_values)
    .bind(&candidates.nonce_values)
    .bind(&profile.organization_id)
    .bind(&profile.connection_id)
    .bind(&profile.id)
    .bind(&normalized_email)
    .bind(&contact_versions)
    .bind(&contact_values)
    .bind(&profile.groups)
    .bind(new_membership_id)
    .bind(new_sso_identity_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_completion_database_error)?
    .ok_or(AppError::Forbidden)?;
    let return_to = decrypt_return_uri(&state, &completion)?;
    support::record_browser_mutation(
        &mut transaction,
        browser_session,
        completion.organization_id,
        MutationEvent {
            action: "sso.authorization.complete",
            target_type: "organization_membership",
            target_id: Some(completion.membership_id),
            aggregate_type: "sso_authorization_transaction",
            aggregate_id: completion.authorization_transaction_id,
            aggregate_version: 1,
            event_type: "sso.authorization.completed.v1",
            before_state: None,
            after_state: Some(json!({
                "membership_id": completion.membership_id,
                "membership_created": completion.membership_created,
            })),
            metadata: json!({
                "sso_identity_id": completion.sso_identity_id,
                "config_version": completion.config_version,
                "group_count": profile.groups.len(),
            }),
        },
    )
    .await?;
    transaction.commit().await.map_err(support::database)?;
    redirect(&return_to)
}

async fn require_valid_callback_correlation(
    state: &ApiState,
    browser_session: BrowserSession,
    candidates: &CorrelationCandidates,
) -> Result<(), AppError> {
    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext::principal(browser_session.carbon_id),
    )
    .await
    .map_err(support::database)?;
    let is_valid = sqlx::query_scalar::<_, bool>(
        r"
        SELECT iam_private.is_valid_sso_callback_correlation(
            $1, $2::smallint[], $3::bytea[], $4::bytea[]
        )
        ",
    )
    .bind(browser_session.session_id)
    .bind(&candidates.versions)
    .bind(&candidates.state_values)
    .bind(&candidates.nonce_values)
    .fetch_one(&mut *transaction)
    .await
    .map_err(support::database)?;
    transaction.commit().await.map_err(support::database)?;
    if !is_valid {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

struct CorrelationCandidates {
    versions: Vec<i16>,
    state_values: Vec<Vec<u8>>,
    nonce_values: Vec<Vec<u8>>,
}

impl CorrelationCandidates {
    fn new(
        state_digests: &[SecretDigest],
        nonce_digests: &[SecretDigest],
    ) -> Result<Self, AppError> {
        let mut versions = Vec::new();
        let mut state_values = Vec::new();
        let mut nonce_values = Vec::new();
        for state_digest in state_digests {
            let Some(nonce_digest) = nonce_digests
                .iter()
                .find(|candidate| candidate.key_version() == state_digest.key_version())
            else {
                return Err(internal("sso_correlation_key_versions"));
            };
            versions.push(state_digest.key_version());
            state_values.push(state_digest.as_bytes().to_vec());
            nonce_values.push(nonce_digest.as_bytes().to_vec());
        }
        if versions.is_empty() {
            return Err(internal("sso_correlation_key_versions"));
        }
        Ok(Self {
            versions,
            state_values,
            nonce_values,
        })
    }
}

fn decrypt_return_uri(state: &ApiState, completion: &CompletionRow) -> Result<Url, AppError> {
    let nonce: [u8; 12] = completion
        .return_uri_nonce
        .as_slice()
        .try_into()
        .map_err(|_| internal("sso_return_uri_nonce"))?;
    let plaintext = state
        .crypto
        .decrypt(
            EncryptionContext::global(
                ProtectedField::SsoReturnUri,
                completion.authorization_transaction_id,
            ),
            &EncryptedValue {
                key_version: completion.return_uri_encryption_key_version,
                nonce,
                ciphertext: completion.return_uri_ciphertext.clone(),
            },
        )
        .map_err(|_| internal("sso_return_uri_decrypt"))?;
    let value = std::str::from_utf8(&plaintext).map_err(|_| internal("sso_return_uri_utf8"))?;
    let return_to = Url::parse(value).map_err(|_| internal("sso_return_uri_parse"))?;
    validation::authorize(
        super::model::AuthorizeQuery {
            return_to: Some(return_to.to_string()),
        },
        &state.settings.server.auth_base_url,
        state.settings.environment,
    )
    .map(|validated| validated.return_to)
    .map_err(|_| internal("sso_return_uri_policy"))
}

fn generate_correlation(state: &ApiState) -> Result<CorrelationSecret, AppError> {
    let state_secret = state
        .crypto
        .generate_secret(SecretKind::SsoState)
        .map_err(|_| internal("sso_state_generate"))?;
    let nonce = state
        .crypto
        .generate_secret(SecretKind::SsoNonce)
        .map_err(|_| internal("sso_nonce_generate"))?;
    let wire_state = SecretString::from(format!(
        "{}.{}",
        state_secret.expose_secret(),
        nonce.expose_secret()
    ));
    let correlation = CorrelationSecret {
        state: state_secret,
        nonce,
        wire_state,
    };
    validation::validate_correlation_parts(&correlation)?;
    Ok(correlation)
}

fn callback_url(state: &ApiState) -> Result<Url, AppError> {
    state
        .settings
        .server
        .public_base_url
        .join("api/v1/sso/callback")
        .map_err(|_| internal("sso_callback_url"))
}

fn redirect(location: &Url) -> Result<Response, AppError> {
    let location =
        HeaderValue::from_str(location.as_str()).map_err(|_| internal("sso_redirect"))?;
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
}

fn map_authorization_database_error(error: sqlx::Error) -> AppError {
    let message = error
        .as_database_error()
        .map(sqlx::error::DatabaseError::message);
    match message {
        Some("sso_not_entitled") => AppError::Forbidden,
        Some("sso_not_active" | "sso_policy_missing") => AppError::Conflict {
            code: "sso_not_active".into(),
        },
        Some("sso_session_invalid") => AppError::Unauthenticated,
        _ => support::database(error),
    }
}

fn map_completion_database_error(error: sqlx::Error) -> AppError {
    let message = error
        .as_database_error()
        .map(sqlx::error::DatabaseError::message);
    match message {
        Some("sso_authorization_expired") => AppError::Gone {
            code: "sso_authorization_expired".into(),
        },
        Some("sso_authorization_consumed") => AppError::Gone {
            code: "sso_authorization_consumed".into(),
        },
        Some("sso_identity_mismatch" | "sso_admission_denied") => AppError::Forbidden,
        Some("sso_identity_conflict") => AppError::Conflict {
            code: "sso_identity_conflict".into(),
        },
        Some("sso_session_invalid") => AppError::Unauthenticated,
        _ => support::database(error),
    }
}

const fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use super::CorrelationCandidates;
    use crate::infrastructure::crypto::SecretDigest;

    #[test]
    fn correlation_candidates_require_matching_key_versions() {
        let state = SecretDigest::from_parts(1, &[1_u8; 32]);
        let nonce = SecretDigest::from_parts(2, &[2_u8; 32]);
        assert!(state.is_some());
        assert!(nonce.is_some());
        if let (Some(state), Some(nonce)) = (state, nonce) {
            assert!(CorrelationCandidates::new(&[state], &[nonce]).is_err());
        }
    }
}
