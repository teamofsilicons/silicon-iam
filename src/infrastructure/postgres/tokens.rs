//! Opaque access-token authentication and revocation-aware introspection.

use secrecy::SecretString;
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    domain::actor::{ActorRef, ActorType},
    infrastructure::crypto::{CryptoError, CryptoService, DigestPurpose},
};

/// Current authority represented by an active opaque access token.
#[derive(Clone, Debug)]
pub struct AccessContext {
    /// Stored token identity.
    pub token_id: Uuid,
    /// Revocable parent authentication session.
    pub authentication_session_id: Uuid,
    /// Human, Silicon, application, or service acting with the token.
    pub subject: ActorRef,
    /// OAuth client application, when one is involved.
    pub client_application_id: Option<Uuid>,
    /// Application audience, when this is an Application access token.
    pub audience_application_id: Option<Uuid>,
    /// Audience string checked by the receiving service.
    pub audience: String,
    /// Organization authorization boundary, when present.
    pub organization_id: Option<Uuid>,
    /// Organization membership snapshot, when present.
    pub membership_id: Option<Uuid>,
    /// Granted OAuth/service scopes.
    pub scopes: Vec<String>,
    /// Authentication assurance level from the parent session.
    pub assurance_level: i16,
}

/// Immutable token identity used only to locate an exact completed logout
/// replay after the presented credential has become inactive.
#[derive(Clone, Debug)]
pub(crate) struct LogoutReplayIdentity {
    pub(crate) token_id: Uuid,
    pub(crate) authentication_session_id: Uuid,
    pub(crate) subject: ActorRef,
    pub(crate) client_application_id: Option<Uuid>,
    pub(crate) audience_application_id: Option<Uuid>,
    pub(crate) audience: String,
    pub(crate) organization_id: Option<Uuid>,
    pub(crate) membership_id: Option<Uuid>,
    pub(crate) scopes: Vec<String>,
}

/// Access-token lookup failure.
#[derive(Debug, Error)]
pub enum AccessTokenError {
    /// Credential prefix does not identify a supported access-token class.
    #[error("invalid access-token format")]
    InvalidFormat,
    /// Cryptographic key material is unavailable or invalid.
    #[error("access-token digest operation failed")]
    Crypto(#[from] CryptoError),
    /// PostgreSQL lookup failed.
    #[error("access-token persistence operation failed")]
    Database(#[from] sqlx::Error),
    /// Stored actor kind is not recognized by this service version.
    #[error("stored access-token actor kind is invalid")]
    InvalidStoredActorKind,
}

#[derive(FromRow)]
struct AccessRow {
    token_id: Uuid,
    authentication_session_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    client_application_id: Option<Uuid>,
    audience_application_id: Option<Uuid>,
    audience: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    scopes: Vec<String>,
    assurance_level: i16,
}

#[derive(FromRow)]
struct AccessCandidate {
    token_id: Uuid,
    subject_principal_id: Uuid,
}

struct AccessLookup {
    token_class: &'static str,
    key_versions: Vec<i16>,
    digest_bytes: Vec<Vec<u8>>,
}

#[derive(FromRow)]
struct LogoutReplayRow {
    token_id: Uuid,
    authentication_session_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    client_application_id: Option<Uuid>,
    audience_application_id: Option<Uuid>,
    audience: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    scopes: Vec<String>,
}

const LOGOUT_REPLAY_IDENTITY_QUERY: &str = r"
    SELECT
        token.id AS token_id,
        token.authentication_session_id,
        token.subject_principal_id,
        token.subject_kind::text AS subject_kind,
        token.client_application_id,
        token.audience_application_id,
        token.audience,
        token.organization_id,
        token.membership_id,
        ARRAY(
            SELECT token_scope.scope
            FROM iam.access_token_scopes AS token_scope
            WHERE token_scope.access_token_id = token.id
            ORDER BY token_scope.scope
        ) AS scopes
    FROM iam.access_tokens AS token
    JOIN iam.authentication_sessions AS session
      ON session.id = token.authentication_session_id
     AND session.subject_principal_id = token.subject_principal_id
     AND session.subject_kind = token.subject_kind
    JOIN iam.principals AS subject
      ON subject.id = token.subject_principal_id
     AND subject.kind = token.subject_kind
    WHERE token.id = $1
      AND token.token_class = $2
      AND (
          token.token_class <> 'application_access'
          OR EXISTS (
              SELECT 1
              FROM iam.applications AS application
              WHERE application.id = token.client_application_id
                AND application.id = token.audience_application_id
                AND application.app_id = token.audience
          )
      )
    LIMIT 1
    ";

/// Resolves a bearer token only while all parent epochs and grants are active.
///
/// # Errors
///
/// Returns an error for malformed token classes, unavailable cryptographic
/// keys, inconsistent stored kinds, or database failures. An unknown, expired,
/// or revoked credential returns `Ok(None)`.
#[allow(
    clippy::too_many_lines,
    reason = "one database projection is mapped into the closed authenticated-access context"
)]
pub async fn authenticate(
    pool: &PgPool,
    crypto: &CryptoService,
    token: &SecretString,
) -> Result<Option<AccessContext>, AccessTokenError> {
    let lookup = access_lookup(crypto, token)?;
    let mut transaction = pool.begin().await?;
    let candidate = find_candidate(&mut transaction, &lookup).await?;
    let Some(candidate) = candidate else {
        transaction.rollback().await?;
        return Ok(None);
    };
    sqlx::query("SELECT set_config('iam.principal_id', $1, true)")
        .bind(candidate.subject_principal_id.to_string())
        .execute(&mut *transaction)
        .await?;

    let row = sqlx::query_as::<_, AccessRow>(
        r"
        SELECT
            token.id AS token_id,
            token.authentication_session_id,
            token.subject_principal_id,
            token.subject_kind::text AS subject_kind,
            token.client_application_id,
            token.audience_application_id,
            token.audience,
            token.organization_id,
            token.membership_id,
            ARRAY(
                SELECT token_scope.scope
                FROM iam.access_token_scopes AS token_scope
                WHERE token_scope.access_token_id = token.id
                ORDER BY token_scope.scope
            ) AS scopes,
            session.assurance_level
        FROM iam.access_tokens AS token
        JOIN iam.authentication_sessions AS session
          ON session.id = token.authentication_session_id
         AND session.subject_principal_id = token.subject_principal_id
        JOIN iam.principals AS subject
          ON subject.id = token.subject_principal_id
         AND subject.kind = token.subject_kind
        LEFT JOIN iam.organization_memberships AS membership
          ON membership.organization_id = token.organization_id
         AND membership.id = token.membership_id
         AND membership.principal_id = token.subject_principal_id
         AND membership.principal_kind = token.subject_kind
        LEFT JOIN iam.organizations AS organization
          ON organization.id = token.organization_id
        LEFT JOIN iam.principals AS client_principal
          ON client_principal.id = token.client_application_id
         AND client_principal.kind = 'application'
        LEFT JOIN iam.principals AS audience_principal
          ON audience_principal.id = token.audience_application_id
         AND audience_principal.kind = 'application'
        WHERE token.id = $1
          AND token.token_class = $2
          AND token.revoked_at IS NULL
          AND token.expires_at > transaction_timestamp()
          AND subject.status = 'active'
          AND subject.auth_epoch = token.subject_auth_epoch
          AND session.status = 'active'
          AND session.idle_expires_at > transaction_timestamp()
          AND session.absolute_expires_at > transaction_timestamp()
          AND (
              token.organization_id IS NULL
              OR (
                  organization.status = 'active'
                  AND
                  membership.status = 'active'
                  AND membership.authz_epoch = token.membership_authz_epoch
              )
          )
          AND (
              token.client_application_id IS NULL
              OR (
                  client_principal.status = 'active'
                  AND client_principal.auth_epoch = token.client_auth_epoch
              )
          )
          AND (
              token.audience_application_id IS NULL
              OR (
                  audience_principal.status = 'active'
              )
          )
        LIMIT 1
        ",
    )
    .bind(candidate.token_id)
    .bind(lookup.token_class)
    .fetch_optional(&mut *transaction)
    .await?;
    transaction.commit().await?;
    row.map(AccessContext::try_from).transpose()
}

/// Resolves only immutable Carbon/Application token identity for exact logout
/// replay lookup. This function deliberately does not confer authority: it
/// ignores current token/session/epoch/tenant state, and callers must never use
/// its result to execute a fresh mutation.
pub(crate) async fn identify_for_logout_replay(
    pool: &PgPool,
    crypto: &CryptoService,
    token: &SecretString,
) -> Result<Option<LogoutReplayIdentity>, AccessTokenError> {
    let lookup = access_lookup(crypto, token)?;
    if !matches!(lookup.token_class, "carbon_access" | "application_access") {
        return Ok(None);
    }

    let mut transaction = pool.begin().await?;
    let candidate = find_candidate(&mut transaction, &lookup).await?;
    let Some(candidate) = candidate else {
        transaction.rollback().await?;
        return Ok(None);
    };
    sqlx::query("SELECT set_config('iam.principal_id', $1, true)")
        .bind(candidate.subject_principal_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let row = sqlx::query_as::<_, LogoutReplayRow>(LOGOUT_REPLAY_IDENTITY_QUERY)
        .bind(candidate.token_id)
        .bind(lookup.token_class)
        .fetch_optional(&mut *transaction)
        .await?;
    transaction.commit().await?;
    row.map(LogoutReplayIdentity::try_from).transpose()
}

fn access_lookup(
    crypto: &CryptoService,
    token: &SecretString,
) -> Result<AccessLookup, AccessTokenError> {
    let (purpose, token_class) = token_class(token)?;
    let digests = crypto.digest_secrets(purpose, token)?;
    Ok(AccessLookup {
        token_class,
        key_versions: digests
            .iter()
            .map(crate::infrastructure::crypto::SecretDigest::key_version)
            .collect(),
        digest_bytes: digests
            .iter()
            .map(|digest| digest.as_bytes().to_vec())
            .collect(),
    })
}

async fn find_candidate(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lookup: &AccessLookup,
) -> Result<Option<AccessCandidate>, sqlx::Error> {
    sqlx::query_as::<_, AccessCandidate>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT token.id AS token_id, token.subject_principal_id
        FROM supplied_digest
        JOIN iam.access_tokens AS token
          ON token.digest_key_version = supplied_digest.key_version
         AND token.token_digest = supplied_digest.digest
        WHERE token.token_class = $3
        LIMIT 1
        ",
    )
    .bind(&lookup.key_versions)
    .bind(&lookup.digest_bytes)
    .bind(lookup.token_class)
    .fetch_optional(&mut **transaction)
    .await
}

fn token_class(token: &SecretString) -> Result<(DigestPurpose, &'static str), AccessTokenError> {
    use secrecy::ExposeSecret as _;

    let value = token.expose_secret();
    if value.len() != 47
        || !value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AccessTokenError::InvalidFormat);
    }
    match value.get(..4) {
        Some("cat_") => Ok((DigestPurpose::CarbonAccessToken, "carbon_access")),
        Some("sat_") => Ok((DigestPurpose::SiliconAccessToken, "silicon_access")),
        Some("oat_") => Ok((DigestPurpose::ApplicationAccessToken, "application_access")),
        _ => Err(AccessTokenError::InvalidFormat),
    }
}

impl TryFrom<AccessRow> for AccessContext {
    type Error = AccessTokenError;

    fn try_from(row: AccessRow) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: row.token_id,
            authentication_session_id: row.authentication_session_id,
            subject: ActorRef {
                actor_type: actor_type(&row.subject_kind)?,
                id: row.subject_principal_id,
            },
            client_application_id: row.client_application_id,
            audience_application_id: row.audience_application_id,
            audience: row.audience,
            organization_id: row.organization_id,
            membership_id: row.membership_id,
            scopes: row.scopes,
            assurance_level: row.assurance_level,
        })
    }
}

impl TryFrom<LogoutReplayRow> for LogoutReplayIdentity {
    type Error = AccessTokenError;

    fn try_from(row: LogoutReplayRow) -> Result<Self, Self::Error> {
        Ok(Self {
            token_id: row.token_id,
            authentication_session_id: row.authentication_session_id,
            subject: ActorRef {
                actor_type: actor_type(&row.subject_kind)?,
                id: row.subject_principal_id,
            },
            client_application_id: row.client_application_id,
            audience_application_id: row.audience_application_id,
            audience: row.audience,
            organization_id: row.organization_id,
            membership_id: row.membership_id,
            scopes: row.scopes,
        })
    }
}

fn actor_type(value: &str) -> Result<ActorType, AccessTokenError> {
    match value {
        "carbon" => Ok(ActorType::Carbon),
        "silicon" => Ok(ActorType::Silicon),
        "application" => Ok(ActorType::Application),
        "service" => Ok(ActorType::Service),
        _ => Err(AccessTokenError::InvalidStoredActorKind),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{AccessTokenError, LOGOUT_REPLAY_IDENTITY_QUERY, token_class};

    #[test]
    fn token_class_requires_exact_wire_shape() {
        let valid = SecretString::from(format!("cat_{}", "A".repeat(43)));
        assert!(token_class(&valid).is_ok());

        let short = SecretString::from("cat_short".to_owned());
        assert!(matches!(
            token_class(&short),
            Err(AccessTokenError::InvalidFormat)
        ));

        let retired_service_token = SecretString::from(format!("svt_{}", "A".repeat(43)));
        assert!(matches!(
            token_class(&retired_service_token),
            Err(AccessTokenError::InvalidFormat)
        ));
    }

    #[test]
    fn logout_replay_identity_is_immutable_identity_not_live_authority() {
        for binding in [
            "session.id = token.authentication_session_id",
            "session.subject_principal_id = token.subject_principal_id",
            "session.subject_kind = token.subject_kind",
            "subject.id = token.subject_principal_id",
            "subject.kind = token.subject_kind",
            "token.id = $1",
            "token.token_class = $2",
            "application.id = token.client_application_id",
            "application.id = token.audience_application_id",
            "application.app_id = token.audience",
        ] {
            assert!(LOGOUT_REPLAY_IDENTITY_QUERY.contains(binding));
        }
        for live_authority_predicate in [
            "token.revoked_at IS NULL",
            "token.expires_at >",
            "session.status = 'active'",
            "subject.status = 'active'",
        ] {
            assert!(!LOGOUT_REPLAY_IDENTITY_QUERY.contains(live_authority_predicate));
        }
    }
}
