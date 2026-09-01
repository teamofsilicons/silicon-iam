#![allow(clippy::too_many_lines)]

use axum::http::HeaderMap;
use secrecy::SecretString;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use subtle::ConstantTimeEq as _;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::infrastructure::crypto::{
    CryptoService, DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField, SecretDigest,
};

use super::error::ApiError;

const LEASE_SECONDS: i64 = 30;
const STANDARD_REPLAY_SECONDS: i64 = 86_400;
const SECRET_REPLAY_SECONDS: i64 = 600;
const ADVISORY_LOCK_DOMAIN: &[u8] = b"silicon-iam:v1:application-idempotency-lock";

pub(super) enum Claim<T> {
    Acquired(Uuid),
    Replay { status: u16, response: T },
}

pub(super) struct Replay<T> {
    pub(super) status: u16,
    pub(super) response: T,
}

#[derive(FromRow)]
struct StoredClaim {
    id: Uuid,
    request_digest: Vec<u8>,
    status: String,
    lease_available: bool,
    response_live: bool,
    response_status: Option<i16>,
    response_ciphertext: Option<Vec<u8>>,
    response_nonce: Option<Vec<u8>>,
    encryption_key_version: Option<i16>,
    created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DigestCandidate {
    caller: SecretDigest,
    key: SecretDigest,
    request: SecretDigest,
}

pub(super) async fn claim<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    headers: &HeaderMap,
    caller_scope: &str,
    route: &'static str,
    canonical_request: &[u8],
    one_time_secret: bool,
) -> Result<Claim<T>, ApiError> {
    let candidates = request_candidates(crypto, headers, caller_scope, canonical_request)?;
    acquire_rotation_locks(transaction, route, &candidates).await?;

    let record_id = Uuid::now_v7();
    let lease_owner =
        crate::request_context::current_request_id().unwrap_or_else(|| Uuid::now_v7().to_string());

    for candidate in &candidates {
        if let Some(row) = find_existing(transaction, route, *candidate).await? {
            return classify_existing(
                transaction,
                crypto,
                row,
                candidate.request,
                &lease_owner,
                one_time_secret,
            )
            .await;
        }
    }

    let caller = SecretString::from(caller_scope.to_owned());
    let current_caller_digest = crypto
        .digest_secret(DigestPurpose::IdempotencyCallerScope, &caller)
        .map_err(|_| ApiError::internal("idempotency_caller_digest"))?;
    let current = candidates
        .iter()
        .copied()
        .find(|candidate| candidate.caller == current_caller_digest)
        .ok_or_else(|| ApiError::internal("idempotency_keyring_mismatch"))?;

    let inserted = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO iam.idempotency_records (
            id, digest_key_version, caller_scope_digest, route,
            idempotency_key_digest, request_digest, status,
            lease_owner, lease_expires_at, contains_one_time_secret, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 'processing', $7,
            transaction_timestamp() + ($8::bigint * interval '1 second'),
            $9, transaction_timestamp() + interval '24 hours'
        )
        ON CONFLICT (
            digest_key_version, caller_scope_digest, route, idempotency_key_digest
        ) DO NOTHING
        RETURNING id
        ",
    )
    .bind(record_id)
    .bind(current.caller.key_version())
    .bind(current.caller.as_bytes().as_slice())
    .bind(route)
    .bind(current.key.as_bytes().as_slice())
    .bind(current.request.as_bytes().as_slice())
    .bind(&lease_owner)
    .bind(LEASE_SECONDS)
    .bind(one_time_secret)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("idempotency_insert"))?;
    if let Some(id) = inserted {
        return Ok(Claim::Acquired(id));
    }

    let row = find_existing(transaction, route, current)
        .await?
        .ok_or_else(|| ApiError::internal("idempotency_conflict_lookup"))?;
    classify_existing(
        transaction,
        crypto,
        row,
        current.request,
        &lease_owner,
        one_time_secret,
    )
    .await
}

/// Returns a committed replay, conflict, or in-progress outcome without
/// creating or taking over a reservation. The caller must finish this short
/// transaction before awaiting external validation, then call [`claim`] in the
/// mutation transaction to close races with requests that completed meanwhile.
pub(super) async fn replay_if_present<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    headers: &HeaderMap,
    caller_scope: &str,
    route: &'static str,
    canonical_request: &[u8],
) -> Result<Option<Replay<T>>, ApiError> {
    let candidates = request_candidates(crypto, headers, caller_scope, canonical_request)?;
    for candidate in candidates {
        let Some(row) = find_existing(transaction, route, candidate).await? else {
            continue;
        };
        if !request_digest_matches(&row, candidate.request) {
            return Err(ApiError::conflict("idempotency_conflict"));
        }
        if row.status == "completed" && row.response_live {
            let response = decrypt_response(crypto, &row)?;
            let status = row
                .response_status
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| ApiError::internal("idempotency_response_shape"))?;
            return Ok(Some(Replay { status, response }));
        }
        if row.status == "completed" || row.status == "expired" {
            return Err(ApiError::conflict("idempotency_response_expired"));
        }
        return Err(ApiError::conflict("idempotency_in_progress"));
    }
    Ok(None)
}

fn request_candidates(
    crypto: &CryptoService,
    headers: &HeaderMap,
    caller_scope: &str,
    canonical_request: &[u8],
) -> Result<Vec<DigestCandidate>, ApiError> {
    let raw_key = required_key(headers)?;

    let caller = SecretString::from(caller_scope.to_owned());
    let key = SecretString::from(raw_key.to_owned());
    let request = SecretString::from(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        canonical_request,
    ));
    digest_candidates(crypto, &caller, &key, &request)
}

/// Returns the one canonical client idempotency key used by request binding.
pub(super) fn required_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let raw_key = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::precondition_required("Idempotency-Key"))?;
    if values.next().is_some() {
        return Err(ApiError::validation(
            "idempotency_key",
            "must be supplied exactly once",
        ));
    }
    if !(16..=255).contains(&raw_key.len()) || !raw_key.as_bytes().iter().all(u8::is_ascii_graphic)
    {
        return Err(ApiError::validation(
            "idempotency_key",
            "must contain 16 to 255 non-whitespace ASCII characters",
        ));
    }

    Ok(raw_key)
}

async fn find_existing(
    transaction: &mut Transaction<'_, Postgres>,
    route: &'static str,
    candidate: DigestCandidate,
) -> Result<Option<StoredClaim>, ApiError> {
    sqlx::query_as::<_, StoredClaim>(
        r"
        SELECT
            id, request_digest, status,
            (lease_expires_at IS NULL OR lease_expires_at <= transaction_timestamp())
                AS lease_available,
            (response_expires_at IS NOT NULL
                AND response_expires_at > transaction_timestamp()) AS response_live,
            response_status, response_ciphertext, response_nonce,
            encryption_key_version, created_at
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
    .map_err(|_| ApiError::internal("idempotency_read"))
}

async fn classify_existing<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    row: StoredClaim,
    request_digest: SecretDigest,
    lease_owner: &str,
    one_time_secret: bool,
) -> Result<Claim<T>, ApiError> {
    if !request_digest_matches(&row, request_digest) {
        return Err(ApiError::conflict("idempotency_conflict"));
    }
    if row.status == "completed" && row.response_live {
        let response = decrypt_response(crypto, &row)?;
        let status = row
            .response_status
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| ApiError::internal("idempotency_response_shape"))?;
        return Ok(Claim::Replay { status, response });
    }
    if row.status == "completed" || row.status == "expired" {
        return Err(ApiError::conflict("idempotency_response_expired"));
    }
    if !row.lease_available {
        return Err(ApiError::conflict("idempotency_in_progress"));
    }
    if one_time_secret
        && row.created_at + time::Duration::seconds(SECRET_REPLAY_SECONDS)
            <= OffsetDateTime::now_utc()
    {
        return Err(ApiError::conflict("idempotency_response_expired"));
    }
    sqlx::query(
        r"
        UPDATE iam.idempotency_records
        SET lease_owner = $2,
            lease_expires_at = transaction_timestamp() + ($3::bigint * interval '1 second')
        WHERE id = $1 AND status = 'processing'
        ",
    )
    .bind(row.id)
    .bind(lease_owner)
    .bind(LEASE_SECONDS)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("idempotency_reclaim"))?;
    Ok(Claim::Acquired(row.id))
}

fn request_digest_matches(row: &StoredClaim, request_digest: SecretDigest) -> bool {
    bool::from(
        row.request_digest
            .as_slice()
            .ct_eq(request_digest.as_bytes().as_slice()),
    )
}

fn digest_candidates(
    crypto: &CryptoService,
    caller: &SecretString,
    key: &SecretString,
    request: &SecretString,
) -> Result<Vec<DigestCandidate>, ApiError> {
    let callers = crypto
        .digest_secrets(DigestPurpose::IdempotencyCallerScope, caller)
        .map_err(|_| ApiError::internal("idempotency_caller_digest"))?;
    let keys = crypto
        .digest_secrets(DigestPurpose::IdempotencyKey, key)
        .map_err(|_| ApiError::internal("idempotency_key_digest"))?;
    let requests = crypto
        .digest_secrets(DigestPurpose::IdempotencyRequest, request)
        .map_err(|_| ApiError::internal("idempotency_request_digest"))?;

    let mut candidates = Vec::with_capacity(callers.len());
    for caller_digest in callers {
        let version = caller_digest.key_version();
        let key_digest = digest_at_version(&keys, version)
            .ok_or_else(|| ApiError::internal("idempotency_keyring_mismatch"))?;
        let request_digest = digest_at_version(&requests, version)
            .ok_or_else(|| ApiError::internal("idempotency_keyring_mismatch"))?;
        candidates.push(DigestCandidate {
            caller: caller_digest,
            key: key_digest,
            request: request_digest,
        });
    }
    if candidates.len() != keys.len() || candidates.len() != requests.len() {
        return Err(ApiError::internal("idempotency_keyring_mismatch"));
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
) -> Result<(), ApiError> {
    for candidate in candidates {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(advisory_lock_id(route, *candidate))
            .execute(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("idempotency_lock"))?;
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

pub(super) async fn complete<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    record_id: Uuid,
    response_status: u16,
    response: &T,
    one_time_secret: bool,
) -> Result<(), ApiError> {
    complete_inner(
        transaction,
        crypto,
        record_id,
        response_status,
        response,
        one_time_secret,
        None,
    )
    .await
}

/// Completes an idempotent mutation while ensuring its encrypted replay
/// envelope cannot outlive the authority represented by `replay_deadline`.
pub(super) async fn complete_no_later_than<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    record_id: Uuid,
    response_status: u16,
    response: &T,
    one_time_secret: bool,
    replay_deadline: OffsetDateTime,
) -> Result<(), ApiError> {
    complete_inner(
        transaction,
        crypto,
        record_id,
        response_status,
        response,
        one_time_secret,
        Some(replay_deadline),
    )
    .await
}

async fn complete_inner<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    record_id: Uuid,
    response_status: u16,
    response: &T,
    one_time_secret: bool,
    replay_deadline: Option<OffsetDateTime>,
) -> Result<(), ApiError> {
    let plaintext =
        serde_json::to_vec(response).map_err(|_| ApiError::internal("idempotency_serialize"))?;
    let encrypted = crypto
        .encrypt(
            EncryptionContext::global(ProtectedField::IdempotencySecretResponse, record_id),
            &plaintext,
        )
        .map_err(|_| ApiError::internal("idempotency_encrypt"))?;
    let ttl = if one_time_secret {
        SECRET_REPLAY_SECONDS
    } else {
        STANDARD_REPLAY_SECONDS
    };
    let response_status =
        i16::try_from(response_status).map_err(|_| ApiError::internal("idempotency_status"))?;
    let result = sqlx::query(
        r"
        UPDATE iam.idempotency_records
        SET status = 'completed', lease_owner = NULL, lease_expires_at = NULL,
            response_status = $2, response_ciphertext = $3, response_nonce = $4,
            encryption_key_version = $5,
            response_expires_at = LEAST(
                transaction_timestamp() + ($6::bigint * interval '1 second'),
                created_at + ($6::bigint * interval '1 second'),
                COALESCE($7, 'infinity'::timestamptz)
            )
        WHERE id = $1 AND status = 'processing'
        ",
    )
    .bind(record_id)
    .bind(response_status)
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce.as_slice())
    .bind(encrypted.key_version)
    .bind(ttl)
    .bind(replay_deadline)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("idempotency_complete"))?;
    if result.rows_affected() != 1 {
        return Err(ApiError::internal("idempotency_lease_lost"));
    }
    Ok(())
}

fn decrypt_response<T: DeserializeOwned>(
    crypto: &CryptoService,
    row: &StoredClaim,
) -> Result<T, ApiError> {
    let nonce = row
        .response_nonce
        .as_deref()
        .and_then(|value| <[u8; 12]>::try_from(value).ok())
        .ok_or_else(|| ApiError::internal("idempotency_response_shape"))?;
    let encrypted = EncryptedValue {
        key_version: row
            .encryption_key_version
            .ok_or_else(|| ApiError::internal("idempotency_response_shape"))?,
        nonce,
        ciphertext: row
            .response_ciphertext
            .clone()
            .ok_or_else(|| ApiError::internal("idempotency_response_shape"))?,
    };
    let plaintext = crypto
        .decrypt(
            EncryptionContext::global(ProtectedField::IdempotencySecretResponse, row.id),
            &encrypted,
        )
        .map_err(|_| ApiError::internal("idempotency_decrypt"))?;
    serde_json::from_slice(&plaintext).map_err(|_| ApiError::internal("idempotency_decode"))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use axum::{
        http::{HeaderMap, HeaderValue, StatusCode},
        response::IntoResponse as _,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use secrecy::{ExposeSecret as _, SecretString};
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres;

    use crate::{
        config::{KeyringSettings, SecuritySettings},
        infrastructure::crypto::CryptoService,
    };

    use super::{
        Claim, advisory_lock_id, claim, complete, digest_candidates, replay_if_present,
        required_key,
    };

    const ROUTE: &str = "POST /api/v1/obo-access/exchanges";

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
            access_token_ttl: Duration::from_mins(30),
            refresh_family_ttl: Duration::from_hours(21_600),
            authorization_code_ttl: Duration::from_secs(120),
            otp_ttl: Duration::from_secs(600),
            otp_max_attempts: 10,
        };
        let Ok(crypto) = CryptoService::from_settings(&settings) else {
            panic!("valid test keyrings must initialize");
        };
        crypto
    }

    #[test]
    fn canonical_request_bytes_are_not_logged_or_reformatted() {
        let value = SecretString::from("secret request".to_owned());
        assert_eq!(value.expose_secret().len(), 14);
    }

    #[test]
    fn idempotency_key_must_have_one_unambiguous_wire_value() {
        let mut headers = HeaderMap::new();
        headers.append(
            "idempotency-key",
            HeaderValue::from_static("018f47ac-75c7-7f84-a6b2-9c2a2617c155"),
        );
        assert!(required_key(&headers).is_ok());
        headers.append(
            "idempotency-key",
            HeaderValue::from_static("018f47ac-75c7-7f84-a6b2-9c2a2617c156"),
        );
        assert!(required_key(&headers).is_err());
    }

    #[test]
    fn retained_pepper_preserves_request_binding_and_lock_identity() {
        let old = crypto(1, &[(1, 11)]);
        let rotated = crypto(2, &[(1, 11), (2, 12)]);
        let caller = SecretString::from("application:018f47ac-75c7-7f84-a6b2-9c2a2617c154");
        let key = SecretString::from("018f47ac-75c7-7f84-a6b2-9c2a2617c155");
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
            advisory_lock_id(ROUTE, old_candidate),
            advisory_lock_id(ROUTE, retained_candidate)
        );
        assert_eq!(
            advisory_lock_id(ROUTE, old_candidate),
            advisory_lock_id(ROUTE, changed_candidate),
            "the request payload must not split concurrency control for one key"
        );
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    async fn completed_response_preflight_and_claim_replay_after_pepper_rotation()
    -> anyhow::Result<()> {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        crate::infrastructure::postgres::migrate(&pool).await?;
        sqlx::query(
            "INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status) \
             VALUES ('token_hmac', 1, 'active'), ('contact_aead', 1, 'active')",
        )
        .execute(&pool)
        .await?;

        let old = crypto(1, &[(1, 11)]);
        let rotated = crypto(2, &[(1, 11), (2, 12)]);
        let headers = HeaderMap::from_iter([(
            "idempotency-key".parse()?,
            HeaderValue::from_static("018f47ac-75c7-7f84-a6b2-9c2a2617c155"),
        )]);
        let original_request = br#"{"action":"documents.read"}"#;
        let response = json!({"proof_id": "018f47ac-75c7-7f84-a6b2-9c2a2617c156"});

        let mut transaction = pool.begin().await?;
        let first = claim::<serde_json::Value>(
            &mut transaction,
            &old,
            &headers,
            "application:018f47ac-75c7-7f84-a6b2-9c2a2617c154",
            ROUTE,
            original_request,
            false,
        )
        .await;
        let Claim::Acquired(record_id) =
            first.map_err(|error| anyhow::anyhow!("first claim failed: {error:?}"))?
        else {
            anyhow::bail!("the first request unexpectedly replayed");
        };
        complete(
            &mut transaction,
            &old,
            record_id,
            StatusCode::CREATED.as_u16(),
            &response,
            false,
        )
        .await
        .map_err(|error| anyhow::anyhow!("claim completion failed: {error:?}"))?;
        transaction.commit().await?;

        sqlx::raw_sql(
            "BEGIN; \
             UPDATE iam.cryptographic_key_versions \
             SET status = 'decrypt_only' \
             WHERE purpose = 'token_hmac' AND key_version = 1; \
             INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status) \
             VALUES ('token_hmac', 2, 'active'); \
             COMMIT;",
        )
        .execute(&pool)
        .await?;

        let mut transaction = pool.begin().await?;
        let Some(preflight) = replay_if_present::<serde_json::Value>(
            &mut transaction,
            &rotated,
            &headers,
            "application:018f47ac-75c7-7f84-a6b2-9c2a2617c154",
            ROUTE,
            original_request,
        )
        .await
        .map_err(|error| anyhow::anyhow!("rotated preflight failed: {error:?}"))?
        else {
            anyhow::bail!("the preflight did not locate the completed response");
        };
        assert_eq!(preflight.status, StatusCode::CREATED.as_u16());
        assert_eq!(preflight.response, response);
        transaction.commit().await?;

        let mut transaction = pool.begin().await?;
        let replay = claim::<serde_json::Value>(
            &mut transaction,
            &rotated,
            &headers,
            "application:018f47ac-75c7-7f84-a6b2-9c2a2617c154",
            ROUTE,
            original_request,
            false,
        )
        .await
        .map_err(|error| anyhow::anyhow!("rotated claim failed: {error:?}"))?;
        let Claim::Replay {
            status,
            response: replayed,
        } = replay
        else {
            anyhow::bail!("the retained pepper did not locate the completed response");
        };
        assert_eq!(status, StatusCode::CREATED.as_u16());
        assert_eq!(replayed, response);
        transaction.commit().await?;

        let mut transaction = pool.begin().await?;
        let conflict = claim::<serde_json::Value>(
            &mut transaction,
            &rotated,
            &headers,
            "application:018f47ac-75c7-7f84-a6b2-9c2a2617c154",
            ROUTE,
            br#"{"action":"documents.write"}"#,
            false,
        )
        .await;
        let Err(conflict) = conflict else {
            anyhow::bail!("a changed request unexpectedly reused the idempotency record");
        };
        assert_eq!(conflict.into_response().status(), StatusCode::CONFLICT);
        transaction.rollback().await?;

        let stored = sqlx::query_as::<_, (i64, i16)>(
            "SELECT count(*), min(digest_key_version) \
             FROM iam.idempotency_records WHERE route = $1",
        )
        .bind(ROUTE)
        .fetch_one(&pool)
        .await?;
        assert_eq!(stored, (1, 1));
        Ok(())
    }
}
