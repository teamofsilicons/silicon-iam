//! Transaction-bound idempotency for externally initiated mutations.

use std::{borrow::Cow, time::Duration};

use secrecy::SecretString;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    error::AppError,
    infrastructure::crypto::{
        CryptoService, DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField,
        SecretDigest,
    },
};

const IDEMPOTENCY_TTL_HOURS: i32 = 24;
const MIN_SECRET_REPLAY_SECONDS: u64 = 1;
const MAX_SECRET_REPLAY_SECONDS: u64 = 10 * 60;
const MAX_REPLAY_BODY_BYTES: usize = 64 * 1024;
// This value intentionally matches the applications protocol boundary so both
// implementations share one lock namespace whenever their canonical caller,
// route, and key identity is the same.
const ADVISORY_LOCK_DOMAIN: &[u8] = b"silicon-iam:v1:application-idempotency-lock";

/// Validated opaque client-supplied idempotency key.
pub struct IdempotencyKey(SecretString);

/// Invalid idempotency key.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IdempotencyKeyError {
    /// Keys must be untrimmed visible ASCII and fit the public contract.
    #[error("idempotency keys must contain 16 to 255 visible ASCII characters")]
    InvalidFormat,
}

/// Inputs used to bind an idempotency claim to one caller and request.
pub struct IdempotencyRequest<'a> {
    /// Stable API route template, never a raw URL.
    pub route: &'static str,
    /// Stable secret-wrapped caller boundary (for example `carbon:<uuid>`).
    pub caller_scope: &'a SecretString,
    /// Validated caller-generated key.
    pub key: &'a IdempotencyKey,
    /// Deterministically serialized semantic request payload.
    pub request_payload: &'a SecretString,
    /// Whether a successful response includes a credential shown only once.
    pub contains_one_time_secret: bool,
}

/// Result of acquiring a request-bound idempotency record.
pub enum IdempotencyClaim {
    /// The caller owns the new record and may execute the mutation.
    Acquired(IdempotencyLease),
    /// An equivalent committed response is safe to replay.
    Replay(ReplayResponse),
}

/// Transaction-local right to complete one idempotent mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdempotencyLease {
    record_id: Uuid,
}

/// Bounded availability window for replaying an encrypted one-time-secret
/// response. The default remains ten minutes; shorter provider-controlled
/// secrets can select their exact lifetime without route-specific behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneTimeResponseReplayTtl(Duration);

/// Invalid one-time-secret replay policy.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReplayTtlError {
    /// The replay window must be an exact number of seconds from one second
    /// through the documented ten-minute maximum.
    #[error("one-time response replay TTL must be 1 to 600 whole seconds")]
    OutOfRange,
}

/// Previously committed JSON response.
#[derive(Debug, Eq, PartialEq)]
pub struct ReplayResponse {
    /// Original HTTP response status.
    pub status: u16,
    /// Exact original response body.
    pub body: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct ExistingRecord {
    id: Uuid,
    request_digest: Vec<u8>,
    status: String,
    response_status: Option<i16>,
    response_ciphertext: Option<Vec<u8>>,
    response_nonce: Option<Vec<u8>>,
    encryption_key_version: Option<i16>,
    response_is_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DigestCandidate {
    caller: SecretDigest,
    key: SecretDigest,
    request: SecretDigest,
}

impl IdempotencyKey {
    /// Validates an opaque `Idempotency-Key` header value.
    ///
    /// # Errors
    ///
    /// Returns [`IdempotencyKeyError::InvalidFormat`] for a value outside the
    /// contract bounds or containing whitespace/control/non-ASCII bytes.
    pub fn parse(value: &str) -> Result<Self, IdempotencyKeyError> {
        if !(16..=255).contains(&value.len()) || !value.as_bytes().iter().all(u8::is_ascii_graphic)
        {
            return Err(IdempotencyKeyError::InvalidFormat);
        }
        Ok(Self(SecretString::from(value.to_owned())))
    }

    fn secret(&self) -> &SecretString {
        &self.0
    }
}

impl OneTimeResponseReplayTtl {
    /// Validates an explicit one-time-secret replay window.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayTtlError::OutOfRange`] for sub-second, zero, or longer
    /// than ten-minute windows.
    pub fn new(value: Duration) -> Result<Self, ReplayTtlError> {
        if value.subsec_nanos() != 0
            || !(MIN_SECRET_REPLAY_SECONDS..=MAX_SECRET_REPLAY_SECONDS).contains(&value.as_secs())
        {
            return Err(ReplayTtlError::OutOfRange);
        }
        Ok(Self(value))
    }

    fn seconds(self) -> Result<i32, AppError> {
        i32::try_from(self.0.as_secs()).map_err(|_| internal("idempotency_replay_ttl"))
    }
}

impl Default for OneTimeResponseReplayTtl {
    fn default() -> Self {
        Self(Duration::from_secs(MAX_SECRET_REPLAY_SECONDS))
    }
}

/// Claims or replays one request within the caller's domain transaction.
///
/// The claim row and domain mutation commit together. A process failure before
/// commit rolls both back, eliminating a durable ambiguous `processing` row.
///
/// # Errors
///
/// Returns a conflict when the key was used for different request bytes, its
/// replay window expired, or an earlier outcome is not safely replayable.
pub async fn claim(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    request: IdempotencyRequest<'_>,
) -> Result<IdempotencyClaim, AppError> {
    validate_route(request.route)?;
    let candidates = digest_candidates(
        crypto,
        request.caller_scope,
        request.key.secret(),
        request.request_payload,
    )?;
    acquire_rotation_locks(transaction, request.route, &candidates).await?;

    for candidate in &candidates {
        if let Some(existing) = find_existing(transaction, request.route, *candidate).await? {
            return classify_existing(crypto, existing, candidate.request);
        }
    }

    let current_caller_digest = crypto
        .digest_secret(DigestPurpose::IdempotencyCallerScope, request.caller_scope)
        .map_err(|_| internal("idempotency_digest"))?;
    let current = candidates
        .iter()
        .copied()
        .find(|candidate| candidate.caller == current_caller_digest)
        .ok_or_else(|| internal("idempotency_digest_versions"))?;

    let record_id = Uuid::now_v7();
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO iam.idempotency_records (
            id,
            digest_key_version,
            caller_scope_digest,
            route,
            idempotency_key_digest,
            request_digest,
            contains_one_time_secret,
            expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            transaction_timestamp() + ($8::integer * interval '1 hour')
        )
        ON CONFLICT (
            digest_key_version,
            caller_scope_digest,
            route,
            idempotency_key_digest
        ) DO NOTHING
        RETURNING id
        ",
    )
    .bind(record_id)
    .bind(current.caller.key_version())
    .bind(current.caller.as_bytes().as_slice())
    .bind(request.route)
    .bind(current.key.as_bytes().as_slice())
    .bind(current.request.as_bytes().as_slice())
    .bind(request.contains_one_time_secret)
    .bind(IDEMPOTENCY_TTL_HOURS)
    .fetch_optional(&mut **transaction)
    .await?;

    if inserted.is_some() {
        return Ok(IdempotencyClaim::Acquired(IdempotencyLease { record_id }));
    }

    let existing = find_existing(transaction, request.route, current)
        .await?
        .ok_or_else(|| internal("idempotency_conflict_lookup"))?;
    classify_existing(crypto, existing, current.request)
}

/// Stores the exact successful response in the same transaction as a mutation.
///
/// # Errors
///
/// Returns a safe internal error if the response is too large, encryption
/// fails, or the lease is no longer in its expected processing state.
pub async fn complete(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    lease: IdempotencyLease,
    response_status: u16,
    response_body: &[u8],
) -> Result<(), AppError> {
    complete_with_replay_ttl(
        transaction,
        crypto,
        lease,
        response_status,
        response_body,
        OneTimeResponseReplayTtl::default(),
    )
    .await
}

/// Stores the exact successful response with an explicit bounded replay
/// lifetime for responses that contain one-time secrets.
///
/// Non-secret responses retain the idempotency record's ordinary lifetime.
///
/// # Errors
///
/// Returns a safe internal error if the response is too large, encryption
/// fails, or the lease is no longer in its expected processing state.
pub async fn complete_with_replay_ttl(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    lease: IdempotencyLease,
    response_status: u16,
    response_body: &[u8],
    one_time_response_replay_ttl: OneTimeResponseReplayTtl,
) -> Result<(), AppError> {
    if !(200..=299).contains(&response_status) || response_body.len() > MAX_REPLAY_BODY_BYTES {
        return Err(internal("idempotency_response"));
    }
    let replay_seconds = one_time_response_replay_ttl.seconds()?;

    let encrypted = crypto
        .encrypt(
            EncryptionContext::global(ProtectedField::IdempotencySecretResponse, lease.record_id),
            response_body,
        )
        .map_err(|_| internal("idempotency_encryption"))?;
    let result = sqlx::query(
        r"
        UPDATE iam.idempotency_records
        SET status = 'completed',
            lease_owner = NULL,
            lease_expires_at = NULL,
            response_status = $2,
            response_ciphertext = $3,
            response_nonce = $4,
            encryption_key_version = $5,
            response_expires_at = CASE
                WHEN contains_one_time_secret
                    THEN LEAST(
                        created_at + ($6::integer * interval '1 second'),
                        transaction_timestamp() + ($6::integer * interval '1 second')
                    )
                ELSE expires_at
            END
        WHERE id = $1
          AND status = 'processing'
        ",
    )
    .bind(lease.record_id)
    .bind(i16::try_from(response_status).map_err(|_| internal("idempotency_response"))?)
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce.as_slice())
    .bind(encrypted.key_version)
    .bind(replay_seconds)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(internal("idempotency_lease"));
    }
    Ok(())
}

async fn find_existing(
    transaction: &mut Transaction<'_, Postgres>,
    route: &'static str,
    candidate: DigestCandidate,
) -> Result<Option<ExistingRecord>, sqlx::Error> {
    sqlx::query_as::<_, ExistingRecord>(
        r"
        SELECT
            id,
            request_digest,
            status,
            response_status,
            response_ciphertext,
            response_nonce,
            encryption_key_version,
            COALESCE(
                response_expires_at > transaction_timestamp(),
                false
            ) AS response_is_available
        FROM iam.idempotency_records
        WHERE digest_key_version = $1
          AND caller_scope_digest = $2
          AND route = $3
          AND idempotency_key_digest = $4
        FOR UPDATE
        ",
    )
    .bind(candidate.caller.key_version())
    .bind(candidate.caller.as_bytes().as_slice())
    .bind(route)
    .bind(candidate.key.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
}

fn classify_existing(
    crypto: &CryptoService,
    existing: ExistingRecord,
    expected_request_digest: SecretDigest,
) -> Result<IdempotencyClaim, AppError> {
    if existing.request_digest.len() != expected_request_digest.as_bytes().len()
        || !bool::from(
            existing
                .request_digest
                .ct_eq(expected_request_digest.as_bytes()),
        )
    {
        return Err(conflict("idempotency_conflict"));
    }

    if existing.status != "completed" {
        let code = match existing.status.as_str() {
            "processing" => "idempotency_in_progress",
            "failed" => "idempotency_outcome_unknown",
            "expired" => "idempotency_expired",
            _ => return Err(internal("idempotency_status")),
        };
        return Err(conflict(code));
    }
    if !existing.response_is_available {
        return Err(conflict("idempotency_expired"));
    }

    let status = existing
        .response_status
        .and_then(|status| u16::try_from(status).ok())
        .ok_or_else(|| internal("idempotency_response"))?;
    let ciphertext = existing
        .response_ciphertext
        .ok_or_else(|| internal("idempotency_response"))?;
    let nonce: [u8; 12] = existing
        .response_nonce
        .ok_or_else(|| internal("idempotency_response"))?
        .try_into()
        .map_err(|_| internal("idempotency_response"))?;
    let key_version = existing
        .encryption_key_version
        .ok_or_else(|| internal("idempotency_response"))?;
    let plaintext = crypto
        .decrypt(
            EncryptionContext::global(ProtectedField::IdempotencySecretResponse, existing.id),
            &EncryptedValue {
                key_version,
                nonce,
                ciphertext,
            },
        )
        .map_err(|_| internal("idempotency_decryption"))?;
    Ok(IdempotencyClaim::Replay(ReplayResponse {
        status,
        body: plaintext.to_vec(),
    }))
}

fn digest_candidates(
    crypto: &CryptoService,
    caller: &SecretString,
    key: &SecretString,
    request: &SecretString,
) -> Result<Vec<DigestCandidate>, AppError> {
    let callers = crypto
        .digest_secrets(DigestPurpose::IdempotencyCallerScope, caller)
        .map_err(|_| internal("idempotency_digest"))?;
    let keys = crypto
        .digest_secrets(DigestPurpose::IdempotencyKey, key)
        .map_err(|_| internal("idempotency_digest"))?;
    let requests = crypto
        .digest_secrets(DigestPurpose::IdempotencyRequest, request)
        .map_err(|_| internal("idempotency_digest"))?;

    let mut candidates = Vec::with_capacity(callers.len());
    for caller_digest in callers {
        let version = caller_digest.key_version();
        let key_digest = digest_at_version(&keys, version)
            .ok_or_else(|| internal("idempotency_digest_versions"))?;
        let request_digest = digest_at_version(&requests, version)
            .ok_or_else(|| internal("idempotency_digest_versions"))?;
        candidates.push(DigestCandidate {
            caller: caller_digest,
            key: key_digest,
            request: request_digest,
        });
    }
    if candidates.len() != keys.len() || candidates.len() != requests.len() {
        return Err(internal("idempotency_digest_versions"));
    }
    candidates.sort_unstable_by_key(|candidate| candidate.caller.key_version());
    Ok(candidates)
}

fn digest_at_version(digests: &[SecretDigest], version: i16) -> Option<SecretDigest> {
    digests
        .iter()
        .copied()
        .find(|digest| digest.key_version() == version)
}

async fn acquire_rotation_locks(
    transaction: &mut Transaction<'_, Postgres>,
    route: &'static str,
    candidates: &[DigestCandidate],
) -> Result<(), AppError> {
    for candidate in candidates {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(advisory_lock_id(route, *candidate))
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

fn advisory_lock_id(route: &'static str, candidate: DigestCandidate) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(ADVISORY_LOCK_DOMAIN);
    hasher.update(candidate.caller.as_bytes());
    hasher.update(route.as_bytes());
    hasher.update(candidate.key.as_bytes());
    let digest = hasher.finalize();
    let mut lock_bytes = [0_u8; size_of::<i64>()];
    lock_bytes.copy_from_slice(&digest[..size_of::<i64>()]);
    i64::from_be_bytes(lock_bytes)
}

pub(crate) fn validate_route(route: &'static str) -> Result<(), AppError> {
    if route.is_empty()
        || route.len() > 255
        || !route.starts_with('/')
        || !route.as_bytes().iter().all(u8::is_ascii_graphic)
    {
        return Err(internal("idempotency_route"));
    }
    Ok(())
}

fn conflict(code: &'static str) -> AppError {
    AppError::Conflict {
        code: Cow::Borrowed(code),
    }
}

fn internal(category: &'static str) -> AppError {
    AppError::Internal { category }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use anyhow::{Context as _, ensure};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use secrecy::ExposeSecret as _;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres as PostgresImage;
    use tokio::{sync::oneshot, time::timeout};

    use crate::config::{KeyringSettings, SecuritySettings};

    const TEST_ROUTE: &str = "/api/v1/test/idempotent-mutation";
    const TEST_CALLER: &str = "carbon:018f47ac-75c7-7f84-a6b2-9c2a2617c154";
    const TEST_KEY: &str = "018f47ac-75c7-7f84-a6b2-9c2a2617c155";

    fn crypto(current_version: i16, pepper_keys: &[(i16, u8)]) -> CryptoService {
        let token_peppers = KeyringSettings {
            current_version,
            keys: pepper_keys
                .iter()
                .map(|(version, byte)| {
                    (
                        *version,
                        SecretString::from(URL_SAFE_NO_PAD.encode([*byte; 32])),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        };
        let single_keyring = |version, byte| KeyringSettings {
            current_version: version,
            keys: BTreeMap::from([(
                version,
                SecretString::from(URL_SAFE_NO_PAD.encode([byte; 32])),
            )]),
        };
        let settings = SecuritySettings {
            token_peppers,
            blind_index_keys: single_keyring(1, 31),
            encryption_keys: single_keyring(1, 41),
            cookie_key: SecretString::from(URL_SAFE_NO_PAD.encode([51_u8; 32])),
            jwt_ed25519_private_key: SecretString::from(URL_SAFE_NO_PAD.encode([61_u8; 32])),
            jwt_key_id: "shared-idempotency-test".to_owned(),
            access_token_ttl: Duration::from_mins(15),
            refresh_family_ttl: Duration::from_hours(8_760),
            authorization_code_ttl: Duration::from_secs(120),
            otp_ttl: Duration::from_secs(600),
            otp_max_attempts: 5,
        };
        let Ok(crypto) = CryptoService::from_settings(&settings) else {
            panic!("valid test keyrings must initialize");
        };
        crypto
    }

    #[test]
    fn accepts_contract_shaped_keys() {
        assert!(IdempotencyKey::parse("018f47ac-75c7-7f84-a6b2-9c2a2617c154").is_ok());
    }

    #[test]
    fn rejects_short_or_whitespace_keys() {
        assert!(IdempotencyKey::parse("too-short").is_err());
        assert!(IdempotencyKey::parse("sixteen chars ok ").is_err());
    }

    #[test]
    fn route_validation_requires_a_bounded_template() {
        assert!(validate_route("/api/v1/organizations/{organization_id}").is_ok());
        assert!(validate_route("api/v1/missing-leading-slash").is_err());
    }

    #[test]
    fn one_time_replay_ttl_is_exact_and_bounded() {
        assert!(OneTimeResponseReplayTtl::new(Duration::from_secs(300)).is_ok());
        assert!(OneTimeResponseReplayTtl::new(Duration::ZERO).is_err());
        assert!(OneTimeResponseReplayTtl::new(Duration::from_millis(1_500)).is_err());
        assert!(OneTimeResponseReplayTtl::new(Duration::from_secs(601)).is_err());
        assert_eq!(
            OneTimeResponseReplayTtl::default().0,
            Duration::from_secs(600)
        );
    }

    #[test]
    fn key_never_exposes_plaintext_through_debug() {
        let key = IdempotencyKey::parse("018f47ac-75c7-7f84-a6b2-9c2a2617c154");
        assert!(key.is_ok());
        if let Ok(key) = key {
            assert_ne!(key.secret().expose_secret(), "");
        }
    }

    #[test]
    fn retained_pepper_preserves_request_binding_and_lock_identity() {
        let old = crypto(1, &[(1, 11)]);
        let rotated = crypto(2, &[(1, 11), (2, 12)]);
        let caller = SecretString::from(TEST_CALLER);
        let key = SecretString::from(TEST_KEY);
        let request = SecretString::from("canonical-request-a");
        let changed_request = SecretString::from("canonical-request-b");

        let Ok(old_candidates) = digest_candidates(&old, &caller, &key, &request) else {
            panic!("old keyring must digest the request");
        };
        let Ok(rotated_candidates) = digest_candidates(&rotated, &caller, &key, &request) else {
            panic!("rotated keyring must digest the request");
        };
        let Ok(changed_candidates) = digest_candidates(&rotated, &caller, &key, &changed_request)
        else {
            panic!("rotated keyring must digest the changed request");
        };
        let Some(old_candidate) = old_candidates.first().copied() else {
            panic!("old keyring must produce one candidate");
        };
        let Some(retained_candidate) = rotated_candidates
            .iter()
            .copied()
            .find(|candidate| candidate.caller.key_version() == 1)
        else {
            panic!("rotated keyring must retain version one");
        };
        let Some(changed_candidate) = changed_candidates
            .iter()
            .copied()
            .find(|candidate| candidate.caller.key_version() == 1)
        else {
            panic!("changed request must retain version one");
        };

        assert_eq!(old_candidate, retained_candidate);
        assert_eq!(old_candidate.caller, changed_candidate.caller);
        assert_eq!(old_candidate.key, changed_candidate.key);
        assert_ne!(old_candidate.request, changed_candidate.request);
        assert_eq!(
            advisory_lock_id(TEST_ROUTE, old_candidate),
            advisory_lock_id(TEST_ROUTE, retained_candidate)
        );
        assert_eq!(
            advisory_lock_id(TEST_ROUTE, old_candidate),
            advisory_lock_id(TEST_ROUTE, changed_candidate),
            "payload changes must not split concurrency control for one logical key"
        );
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    #[allow(
        clippy::too_many_lines,
        reason = "one live test exercises the complete cross-version transaction overlap"
    )]
    async fn rotated_pod_waits_for_old_pod_then_replays() -> anyhow::Result<()> {
        let container = PostgresImage::default()
            .with_tag("16-alpine")
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        super::super::migrate(&pool).await?;
        sqlx::query(
            "INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status) \
             VALUES ('token_hmac', 1, 'decrypt_only'), \
                    ('token_hmac', 2, 'active'), \
                    ('contact_aead', 1, 'active')",
        )
        .execute(&pool)
        .await?;

        let old_crypto = crypto(1, &[(1, 11)]);
        let rotated_crypto = crypto(2, &[(1, 11), (2, 12)]);
        let caller = SecretString::from(TEST_CALLER);
        let key = IdempotencyKey::parse(TEST_KEY)?;
        let request_payload = SecretString::from("canonical-request-a");
        let mut old_transaction = pool.begin().await?;
        let old_claim = claim(
            &mut old_transaction,
            &old_crypto,
            IdempotencyRequest {
                route: TEST_ROUTE,
                caller_scope: &caller,
                key: &key,
                request_payload: &request_payload,
                contains_one_time_secret: false,
            },
        )
        .await?;
        let IdempotencyClaim::Acquired(old_lease) = old_claim else {
            anyhow::bail!("the old pod unexpectedly replayed a fresh request");
        };

        let rotated_pool = pool.clone();
        let (ready_sender, ready_receiver) = oneshot::channel();
        let mut rotated_task = tokio::spawn(async move {
            let caller = SecretString::from(TEST_CALLER);
            let key = IdempotencyKey::parse(TEST_KEY)?;
            let request_payload = SecretString::from("canonical-request-a");
            let mut transaction = rotated_pool.begin().await?;
            let _ = ready_sender.send(());
            let outcome = claim(
                &mut transaction,
                &rotated_crypto,
                IdempotencyRequest {
                    route: TEST_ROUTE,
                    caller_scope: &caller,
                    key: &key,
                    request_payload: &request_payload,
                    contains_one_time_secret: false,
                },
            )
            .await?;
            let IdempotencyClaim::Replay(replay) = outcome else {
                anyhow::bail!("the rotated pod created a second versioned record");
            };
            transaction.commit().await?;
            Ok::<ReplayResponse, anyhow::Error>(replay)
        });
        ready_receiver
            .await
            .context("rotated pod stopped before issuing its claim")?;
        ensure!(
            timeout(Duration::from_millis(250), &mut rotated_task)
                .await
                .is_err(),
            "the rotated pod did not wait on the retained-version lock"
        );

        complete(
            &mut old_transaction,
            &old_crypto,
            old_lease,
            201,
            br#"{"created":true}"#,
        )
        .await?;
        old_transaction.commit().await?;

        let replay = rotated_task
            .await
            .context("rotated idempotency task panicked")??;
        ensure!(
            replay.status == 201 && replay.body == br#"{"created":true}"#,
            "the rotated pod did not replay the old pod's exact response"
        );

        let mut changed_transaction = pool.begin().await?;
        let changed_payload = SecretString::from("canonical-request-b");
        let changed_key = IdempotencyKey::parse(TEST_KEY)?;
        let changed = claim(
            &mut changed_transaction,
            &crypto(2, &[(1, 11), (2, 12)]),
            IdempotencyRequest {
                route: TEST_ROUTE,
                caller_scope: &caller,
                key: &changed_key,
                request_payload: &changed_payload,
                contains_one_time_secret: false,
            },
        )
        .await;
        let Err(AppError::Conflict { code }) = changed else {
            anyhow::bail!("a changed payload did not conflict with the retained record");
        };
        ensure!(code == "idempotency_conflict", "unexpected conflict code");
        changed_transaction.rollback().await?;

        let records = sqlx::query_as::<_, (i64, Option<i16>)>(
            "SELECT count(*), min(digest_key_version) \
             FROM iam.idempotency_records WHERE route = $1",
        )
        .bind(TEST_ROUTE)
        .fetch_one(&pool)
        .await?;
        ensure!(records == (1, Some(1)), "versioned duplicate rows survived");
        Ok(())
    }
}
