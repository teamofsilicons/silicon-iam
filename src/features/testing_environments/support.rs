//! Shared plumbing for the testing-environment control plane.

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::{ApiState, TestingPlane, authentication::Authenticated},
    domain::actor::ActorRef,
    error::AppError,
    infrastructure::{
        crypto::{DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField},
        postgres::{
            events::{self, AggregateVersion, AuditRecord},
            idempotency::{
                self, IdempotencyClaim, IdempotencyKey, IdempotencyLease, OneTimeResponseReplayTtl,
            },
        },
    },
};

use super::validation;

/// A live environment together with the authority the caller has over it.
pub(super) struct AdministeredEnvironment {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
}

pub(super) enum Claim {
    Acquired(IdempotencyLease),
    Replay(Response),
}

/// Stored form of an environment key.
pub(super) struct StoredKey {
    pub(super) digest: Vec<u8>,
    pub(super) digest_key_version: i16,
    pub(super) ciphertext: Vec<u8>,
    pub(super) nonce: Vec<u8>,
    pub(super) encryption_key_version: i16,
}

/// Resolves the testing plane, or reports it is not deployed here.
///
/// A 503 rather than a 404: the routes exist, the deployment simply has no
/// database to put environments in, and telling an operator that is more
/// useful than pretending the feature was never built.
pub(super) fn plane(state: &ApiState) -> Result<&TestingPlane, AppError> {
    state.testing.as_ref().ok_or(AppError::ServiceUnavailable)
}

/// Encrypts and digests a freshly generated environment key.
///
/// The digest is the lookup path taken on every request that presents a key;
/// the ciphertext exists because an administrator is entitled to read the key
/// back, which is unusual enough in this schema to be worth restating. Both are
/// bound to the environment row, so a ciphertext lifted into another row will
/// not authenticate.
pub(super) fn store_key(
    state: &ApiState,
    organization_id: Uuid,
    environment_id: Uuid,
    key: &SecretString,
) -> Result<StoredKey, AppError> {
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::TestingEnvironmentKey, key)
        .map_err(|_| AppError::Internal {
            category: "testing_environment_key_digest",
        })?;
    let encrypted = state
        .crypto
        .encrypt(
            key_encryption_context(organization_id, environment_id),
            key.expose_secret().as_bytes(),
        )
        .map_err(|_| AppError::Internal {
            category: "testing_environment_key_encrypt",
        })?;
    Ok(StoredKey {
        digest: digest.as_bytes().to_vec(),
        digest_key_version: digest.key_version(),
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce.to_vec(),
        encryption_key_version: encrypted.key_version,
    })
}

/// Recovers a stored key for an authorized read.
pub(super) fn read_key(
    state: &ApiState,
    organization_id: Uuid,
    environment_id: Uuid,
    stored: &StoredKey,
) -> Result<String, AppError> {
    let nonce: [u8; 12] = stored
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| AppError::Internal {
            category: "testing_environment_key_nonce",
        })?;
    let plaintext = state
        .crypto
        .decrypt(
            key_encryption_context(organization_id, environment_id),
            &EncryptedValue {
                key_version: stored.encryption_key_version,
                nonce,
                ciphertext: stored.ciphertext.clone(),
            },
        )
        .map_err(|_| AppError::Internal {
            category: "testing_environment_key_decrypt",
        })?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Internal {
        category: "testing_environment_key_encoding",
    })
}

const fn key_encryption_context(organization_id: Uuid, environment_id: Uuid) -> EncryptionContext {
    EncryptionContext::tenant(
        ProtectedField::TestingEnvironmentKey,
        organization_id,
        environment_id,
    )
}

/// Resolves a presented key to a live environment.
///
/// Runs against the production database, because that is where the control
/// plane lives, and returns nothing at all for a key that is malformed,
/// unknown, or attached to a deleted environment. Digests are computed for
/// every retained pepper version so a rotation does not lock out live keys.
pub(super) async fn resolve_key(
    pool: &PgPool,
    state: &ApiState,
    presented: &str,
) -> Result<Option<AdministeredEnvironment>, AppError> {
    let Some(presented) = validation::key_shape(presented) else {
        return Ok(None);
    };
    let key = SecretString::from(presented.to_owned());
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::TestingEnvironmentKey, &key)
        .map_err(|_| AppError::Internal {
            category: "testing_environment_key_digest",
        })?
        .into_iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();

    let resolved = sqlx::query_as::<_, (Uuid, Uuid, i16)>(
        "SELECT * FROM iam_private.resolve_testing_environment($1)",
    )
    .bind(&digests)
    .fetch_optional(pool)
    .await
    .map_err(database)?;

    Ok(
        resolved.map(|(id, organization_id, _)| AdministeredEnvironment {
            id,
            organization_id,
        }),
    )
}

/// Marks an environment as used, so the idle sweep leaves it alone.
///
/// Deliberately best-effort and outside the request's own transaction: an
/// environment that served a request but failed to record it will simply be
/// touched by the next one, and failing a working request over bookkeeping
/// would be the worse trade.
pub(super) async fn touch(pool: &PgPool, environment_id: Uuid) {
    if let Err(error) = sqlx::query("SELECT iam_private.touch_testing_environment($1)")
        .bind(environment_id)
        .execute(pool)
        .await
    {
        tracing::warn!(
            error = %error,
            testing_environment.id = %environment_id,
            "could not record testing environment activity"
        );
    }
}

/// Confirms the caller administers this environment.
///
/// Row security already restricts updates to administrators, but a read that
/// discloses the key is not an update, and "the database would have refused it"
/// is not a reason to leave the check implicit.
pub(super) async fn require_administrator(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    created_by_membership_id: Uuid,
    principal_id: Uuid,
) -> Result<(), AppError> {
    let allowed = sqlx::query_scalar::<_, bool>(
        "SELECT iam_private.is_testing_environment_administrator($1, $2, $3)",
    )
    .bind(organization_id)
    .bind(created_by_membership_id)
    .bind(principal_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database)?;
    if allowed {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Reserves a client's idempotency key for one mutation.
///
/// Scoped to the actor, the organization and the concrete environment, so the
/// same key reused against a different environment is a different request
/// rather than a spurious replay.
#[allow(
    clippy::too_many_arguments,
    reason = "the route, resource and secrecy inputs are idempotency security boundaries and stay explicit"
)]
pub(super) async fn claim<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    authenticated: &Authenticated,
    headers: &HeaderMap,
    route: &'static str,
    resource_scope: &str,
    request: &T,
    contains_key: bool,
) -> Result<Claim, AppError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| validation::field("idempotency_key", "is required"))?;
    let key = IdempotencyKey::parse(key).map_err(|_| {
        validation::field(
            "idempotency_key",
            "must contain 16 to 255 visible ASCII characters",
        )
    })?;
    let caller_scope = SecretString::from(format!(
        "testing_environment:{}:{}:{resource_scope}",
        authenticated.0.subject.actor_type.as_str(),
        authenticated.0.subject.id,
    ));
    let request_payload =
        SecretString::from(
            serde_json::to_string(request).map_err(|_| AppError::Internal {
                category: "testing_environment_request_serialize",
            })?,
        );

    match idempotency::claim(
        transaction,
        &state.crypto,
        idempotency::IdempotencyRequest {
            route,
            caller_scope: &caller_scope,
            key: &key,
            request_payload: &request_payload,
            contains_one_time_secret: contains_key,
        },
    )
    .await?
    {
        IdempotencyClaim::Acquired(lease) => Ok(Claim::Acquired(lease)),
        IdempotencyClaim::Replay(replay) => {
            let status = StatusCode::from_u16(replay.status).map_err(|_| AppError::Internal {
                category: "testing_environment_replay_status",
            })?;
            let mut response = json_response(status, replay.body, None, contains_key)?;
            response.headers_mut().insert(
                http::HeaderName::from_static("idempotency-replayed"),
                HeaderValue::from_static("true"),
            );
            Ok(Claim::Replay(response))
        }
    }
}

/// Records the response against the lease so a retry replays it.
///
/// A response carrying the key is retained encrypted and for a short window
/// only, matching how every other credential-bearing response in this API is
/// replayed.
pub(super) async fn finish<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    lease: IdempotencyLease,
    status: StatusCode,
    value: &T,
    contains_key: bool,
) -> Result<Vec<u8>, AppError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AppError::Internal {
        category: "testing_environment_response_serialize",
    })?;
    if contains_key {
        let ttl = OneTimeResponseReplayTtl::default();
        idempotency::complete_with_replay_ttl(
            transaction,
            &state.crypto,
            lease,
            status.as_u16(),
            &bytes,
            ttl,
        )
        .await?;
    } else {
        idempotency::complete(transaction, &state.crypto, lease, status.as_u16(), &bytes).await?;
    }
    Ok(bytes)
}

/// One environment lifecycle change, as the audit log records it.
pub(super) struct AuditEvent<'a> {
    /// Who caused it; absent when the environment key alone authorized it.
    pub(super) actor: Option<ActorRef>,
    /// Parent authentication session, when the actor is interactive.
    pub(super) authentication_session_id: Option<Uuid>,
    /// Organization that owns the environment.
    pub(super) organization_id: Uuid,
    /// Stable dotted action vocabulary.
    pub(super) action: &'static str,
    /// Environment the change applied to.
    pub(super) environment_id: Uuid,
    /// Environment version after the change.
    pub(super) version: i64,
    /// Redacted prior state.
    pub(super) before_state: Option<serde_json::Value>,
    /// Redacted new state.
    pub(super) after_state: Option<serde_json::Value>,
    /// Supplemental, secret-free metadata.
    pub(super) metadata: &'a serde_json::Value,
}

/// Appends one audit event for an environment lifecycle change.
///
/// Audit only, with no outbox event: no webhook subscription vocabulary
/// includes testing environments, and enqueueing events nothing can subscribe
/// to would leave the worker expanding rows to no recipient.
pub(super) async fn record_audit(
    transaction: &mut Transaction<'_, Postgres>,
    event: AuditEvent<'_>,
) -> Result<(), AppError> {
    events::record_audit(
        transaction,
        AuditRecord {
            actor: event.actor,
            authentication_session_id: event.authentication_session_id,
            organization_id: Some(event.organization_id),
            application_id: None,
            action: event.action,
            target_type: "testing_environment",
            target_id: Some(event.environment_id),
            authentication_method: None,
            aggregate: Some(AggregateVersion {
                aggregate_type: "testing_environment",
                aggregate_id: event.environment_id,
                version: event.version,
            }),
            before_state: event.before_state,
            after_state: event.after_state,
            metadata: event.metadata.clone(),
        },
    )
    .await
    .map(|_| ())
    .map_err(database)
}

pub(super) fn json_response(
    status: StatusCode,
    body: Vec<u8>,
    version: Option<i64>,
    contains_key: bool,
) -> Result<Response, AppError> {
    let mut response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|_| AppError::Internal {
            category: "testing_environment_response_build",
        })?;
    if let Some(version) = version {
        let etag =
            HeaderValue::from_str(&format!("\"{version}\"")).map_err(|_| AppError::Internal {
                category: "testing_environment_etag",
            })?;
        response.headers_mut().insert(http::header::ETAG, etag);
    }
    if contains_key {
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        response
            .headers_mut()
            .insert(http::header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    Ok(response)
}

pub(super) fn json<T: Serialize>(
    status: StatusCode,
    value: &T,
    version: Option<i64>,
) -> Result<Response, AppError> {
    let body = serde_json::to_vec(value).map_err(|_| AppError::Internal {
        category: "testing_environment_response_serialize",
    })?;
    json_response(status, body, version, false)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "this function is used directly as an owned Result::map_err adapter"
)]
pub(super) fn database(error: sqlx::Error) -> AppError {
    tracing::error!(error = %error, "testing-environment database operation failed");
    AppError::Internal {
        category: "testing_environment_database",
    }
}

pub(super) fn conflict_from_database(error: sqlx::Error, code: &'static str) -> AppError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|database_code| matches!(database_code.as_ref(), "23505" | "23514" | "23P01"))
    {
        AppError::Conflict { code: code.into() }
    } else {
        database(error)
    }
}

/// Reads the optimistic-concurrency precondition a mutation requires.
pub(super) fn expected_version(headers: &HeaderMap) -> Result<i64, AppError> {
    let value = headers
        .get(http::header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::PreconditionRequired {
            code: "if_match_required".into(),
        })?;
    value
        .trim()
        .trim_start_matches("W/")
        .trim_matches('"')
        .parse::<i64>()
        .map_err(|_| AppError::PreconditionFailed {
            code: "etag_mismatch".into(),
        })
}
