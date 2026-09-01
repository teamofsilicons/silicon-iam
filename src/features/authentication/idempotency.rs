use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::SecretString;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

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
    raw: SecretString,
}

pub(super) enum Claim<T> {
    Acquired { record_id: Lease },
    Replay { response: T },
}

pub(super) struct Lease(IdempotencyLease);

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
        Ok(Self {
            parsed,
            raw: SecretString::from(value.to_owned()),
        })
    }

    pub(super) fn as_secret(&self) -> &SecretString {
        &self.raw
    }
}

pub(super) async fn begin<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    key: &IdempotencyKey,
    caller_scope: &[u8],
    route: &'static str,
    request_digest: [u8; 32],
    contains_one_time_secret: bool,
) -> Result<Claim<T>, AppError> {
    let caller_scope = SecretString::from(URL_SAFE_NO_PAD.encode(caller_scope));
    let request_payload = SecretString::from(URL_SAFE_NO_PAD.encode(request_digest));
    let request = IdempotencyRequest {
        route,
        caller_scope: &caller_scope,
        key: &key.parsed,
        request_payload: &request_payload,
        contains_one_time_secret,
    };
    match shared::claim(transaction, crypto, request).await? {
        IdempotencyClaim::Acquired(lease) => Ok(Claim::Acquired {
            record_id: Lease(lease),
        }),
        IdempotencyClaim::Replay(replay) => {
            let stored =
                serde_json::from_slice::<StoredResponse<T>>(&replay.body).map_err(|_| {
                    AppError::Internal {
                        category: "idempotency_response_decode",
                    }
                })?;
            if !(100..=599).contains(&stored.public_status) {
                return Err(AppError::Internal {
                    category: "idempotency_response_status",
                });
            }
            Ok(Claim::Replay {
                response: stored.response,
            })
        }
    }
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

pub(super) fn request_uuid() -> Uuid {
    crate::request_context::current_request_id()
        .and_then(|value| Uuid::parse_str(&value).ok())
        .unwrap_or_else(Uuid::now_v7)
}

#[cfg(test)]
mod tests {
    use super::digest_parts;

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
