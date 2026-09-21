use crate::domain::id::Id;
use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::SecretString;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};

use crate::{
    error::AppError,
    infrastructure::{
        crypto::CryptoService,
        postgres::idempotency::{
            self as shared, IdempotencyClaim, IdempotencyLease, IdempotencyRequest,
        },
    },
};

const IDEMPOTENCY_HEADER: &str = "idempotency-key";

pub(super) struct IdempotencyKey {
    parsed: shared::IdempotencyKey,
}

pub(super) enum Claim<T> {
    Acquired { record_id: Lease },
    Replay { status: u16, response: T },
}

pub(super) struct Lease(IdempotencyLease);

pub(super) struct Outcome<T> {
    pub(super) status: u16,
    pub(super) value: T,
    pub(super) replayed: bool,
}

impl<T> Outcome<T> {
    pub(super) const fn fresh(status: u16, value: T) -> Self {
        Self {
            status,
            value,
            replayed: false,
        }
    }

    pub(super) const fn replay(status: u16, value: T) -> Self {
        Self {
            status,
            value,
            replayed: true,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct StoredResponse<T> {
    public_status: u16,
    response: T,
}

impl IdempotencyKey {
    pub(super) fn from_headers(headers: &HeaderMap) -> Result<Self, AppError> {
        let value = headers
            .get(IDEMPOTENCY_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                crate::features::authentication::validation::validation(
                    "idempotency_key",
                    "is required",
                )
            })?;
        let parsed = shared::IdempotencyKey::parse(value).map_err(|_| {
            crate::features::authentication::validation::validation(
                "idempotency_key",
                "must be 16 to 255 non-whitespace ASCII characters",
            )
        })?;
        Ok(Self { parsed })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReplayDigest {
    current: [u8; 32],
    legacy: Option<[u8; 32]>,
    legacy_caller: Option<[u8; 32]>,
}
impl From<[u8; 32]> for ReplayDigest {
    fn from(current: [u8; 32]) -> Self {
        Self {
            current,
            legacy: None,
            legacy_caller: None,
        }
    }
}
impl ReplayDigest {
    pub(super) fn with_legacy(current: [u8; 32], legacy: [u8; 32]) -> Self {
        Self {
            current,
            legacy: Some(legacy),
            legacy_caller: None,
        }
    }
    pub(super) fn with_caller(mut self, caller: Option<[u8; 32]>) -> Self {
        self.legacy_caller = caller;
        self
    }
    pub(super) const fn legacy(self) -> Option<[u8; 32]> {
        self.legacy
    }
}

pub(super) fn digest_parts_with_legacy(
    crypto: &CryptoService,
    domain: &[u8],
    parts: &[&[u8]],
    identities: &[usize],
) -> ReplayDigest {
    let current = digest_parts(domain, parts);
    let mut old: Vec<Vec<u8>> = parts.iter().map(|part| part.to_vec()).collect();
    let mut changed = false;
    for index in identities {
        if let Some(value) = crypto.replay.legacy_identity(parts[*index]) {
            old[*index] = value.as_bytes().to_vec();
            changed = true;
        }
    }
    ReplayDigest {
        current,
        legacy: changed
            .then(|| digest_parts(domain, &old.iter().map(Vec::as_slice).collect::<Vec<_>>())),
        legacy_caller: None,
    }
}

fn replay_inputs(
    crypto: &CryptoService,
    caller: &[u8],
    request: ReplayDigest,
) -> Option<(SecretString, SecretString)> {
    let legacy_caller = request
        .legacy_caller
        .map(|value| value.to_vec())
        .or_else(|| {
            crypto
                .replay
                .legacy_identity(caller)
                .map(|value| value.as_bytes().to_vec())
        });
    if request.legacy.is_none() && legacy_caller.is_none() {
        return None;
    }
    Some((
        SecretString::from(URL_SAFE_NO_PAD.encode(legacy_caller.as_deref().unwrap_or(caller))),
        SecretString::from(URL_SAFE_NO_PAD.encode(request.legacy.unwrap_or(request.current))),
    ))
}

pub(super) async fn begin<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    key: &IdempotencyKey,
    caller_scope: &[u8],
    route: &'static str,
    request_digest: impl Into<ReplayDigest>,
    contains_one_time_secret: bool,
) -> Result<Claim<T>, AppError> {
    let request_digest = request_digest.into();
    let legacy = replay_inputs(crypto, caller_scope, request_digest);
    let caller_scope = SecretString::from(URL_SAFE_NO_PAD.encode(caller_scope));
    let request_payload = SecretString::from(URL_SAFE_NO_PAD.encode(request_digest.current));
    let request = IdempotencyRequest {
        route,
        caller_scope: &caller_scope,
        key: &key.parsed,
        request_payload: &request_payload,
        contains_one_time_secret,
    };
    match shared::claim_with_legacy(transaction, crypto, request, legacy).await? {
        IdempotencyClaim::Acquired(lease) => Ok(Claim::Acquired {
            record_id: Lease(lease),
        }),
        IdempotencyClaim::Replay(replay) => {
            let stored = decode_stored_response(&replay.body)?;
            Ok(Claim::Replay {
                status: stored.public_status,
                response: stored.response,
            })
        }
    }
}

/// Looks up an exact committed response without creating a fresh reservation.
/// This is the only idempotency operation permitted for an inactive logout
/// credential.
pub(super) async fn replay_if_present<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    key: &IdempotencyKey,
    caller_scope: &[u8],
    route: &'static str,
    request_digest: impl Into<ReplayDigest>,
    contains_one_time_secret: bool,
) -> Result<Option<Outcome<T>>, AppError> {
    let request_digest = request_digest.into();
    let legacy = replay_inputs(crypto, caller_scope, request_digest);
    let caller_scope = SecretString::from(URL_SAFE_NO_PAD.encode(caller_scope));
    let request_payload = SecretString::from(URL_SAFE_NO_PAD.encode(request_digest.current));
    let request = IdempotencyRequest {
        route,
        caller_scope: &caller_scope,
        key: &key.parsed,
        request_payload: &request_payload,
        contains_one_time_secret,
    };
    let Some(replay) =
        shared::replay_if_present_with_legacy(transaction, crypto, request, legacy).await?
    else {
        return Ok(None);
    };
    let stored = decode_stored_response(&replay.body)?;
    Ok(Some(Outcome::replay(stored.public_status, stored.response)))
}

fn decode_stored_response<T: DeserializeOwned>(body: &[u8]) -> Result<StoredResponse<T>, AppError> {
    let stored =
        serde_json::from_slice::<StoredResponse<T>>(body).map_err(|_| AppError::Internal {
            category: "idempotency_response_decode",
        })?;
    if !(100..=599).contains(&stored.public_status) {
        return Err(AppError::Internal {
            category: "idempotency_response_status",
        });
    }
    Ok(stored)
}

pub(super) async fn complete<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    record_id: Lease,
    response_status: u16,
    response: &T,
    _contains_one_time_secret: bool,
) -> Result<(), AppError> {
    if !(100..=599).contains(&response_status) {
        return Err(AppError::Internal {
            category: "idempotency_response_status",
        });
    }
    let serialized = serde_json::to_vec(&StoredResponse {
        public_status: response_status,
        response,
    })
    .map_err(|_| AppError::Internal {
        category: "idempotency_response_serialize",
    })?;
    shared::complete(transaction, crypto, record_id.0, 200, &serialized).await
}

pub(super) async fn cancel_for_retry(
    transaction: &mut Transaction<'_, Postgres>,
    record_id: Lease,
) -> Result<(), AppError> {
    shared::cancel_for_retry(transaction, record_id.0).await
}

pub(super) fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"silicon-iam:v1:");
    digest.update(domain);
    for part in parts {
        digest.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

pub(super) fn request_uuid() -> Id {
    crate::request_context::current_request_id()
        .and_then(|value| Id::parse_str(&value).ok())
        .unwrap_or_else(Id::now_v7)
}

#[cfg(test)]
mod tests {
    use super::digest_parts;

    #[test]
    fn binary_identity_digests_retain_pre_cutover_logout_binding() {
        use crate::{
            config::{KeyringSettings, SecuritySettings},
            infrastructure::{canonical_replay::Bridge, crypto::CryptoService},
        };
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use secrecy::{ExposeSecret as _, SecretString};
        use std::{collections::BTreeMap, time::Duration};
        let ring = KeyringSettings {
            current_version: 1,
            keys: BTreeMap::from([(1, SecretString::from(URL_SAFE_NO_PAD.encode([7_u8; 32])))]),
        };
        let security = SecuritySettings {
            token_peppers: ring.clone(),
            blind_index_keys: ring.clone(),
            encryption_keys: ring,
            cookie_key: SecretString::from(URL_SAFE_NO_PAD.encode([8_u8; 32])),
            access_token_ttl: Duration::from_mins(30),
            refresh_family_ttl: Duration::from_hours(24),
            authorization_code_ttl: Duration::from_mins(2),
            otp_ttl: Duration::from_mins(10),
            otp_max_attempts: 10,
        };
        let Ok(mut crypto) = CryptoService::from_settings(&security) else {
            panic!("test keyring")
        };
        let old = uuid::Uuid::from_u128(1);
        let app = uuid::Uuid::from_u128(2);
        let session = uuid::Uuid::from_u128(3);
        crypto.replay = Bridge::fixture(
            &[(None, "saket", old), (None, "test>app", app)],
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        );
        let caller = super::digest_parts_with_legacy(
            &crypto,
            b"application-triggered-logout-caller",
            &[b"saket", b"test>app"],
            &[0, 1],
        );
        let request = super::digest_parts_with_legacy(
            &crypto,
            b"application-triggered-logout",
            &[b"saket", session.as_bytes(), b"test>app", b"current"],
            &[0, 2],
        )
        .with_caller(caller.legacy());
        let Some((legacy_caller, legacy_request)) =
            super::replay_inputs(&crypto, &caller.current, request)
        else {
            panic!("replay inputs")
        };
        assert_eq!(
            legacy_caller.expose_secret(),
            URL_SAFE_NO_PAD.encode(digest_parts(
                b"application-triggered-logout-caller",
                &[old.as_bytes(), app.as_bytes()]
            ))
        );
        assert_eq!(
            legacy_request.expose_secret(),
            URL_SAFE_NO_PAD.encode(digest_parts(
                b"application-triggered-logout",
                &[
                    old.as_bytes(),
                    session.as_bytes(),
                    app.as_bytes(),
                    b"current"
                ]
            ))
        );
        assert_ne!(request.current, request.legacy.unwrap_or(request.current));
    }

    #[test]
    fn request_digests_are_framed_and_domain_separated() {
        assert_ne!(
            digest_parts(b"request", &[b"ab", b"c"]),
            digest_parts(b"request", &[b"a", b"bc"]),
        );
        assert_ne!(
            digest_parts(b"request", &[b"same"]),
            digest_parts(b"scope", &[b"same"]),
        );
    }
}
