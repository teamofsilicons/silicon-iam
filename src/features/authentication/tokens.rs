use secrecy::{ExposeSecret as _, SecretString};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::SecuritySettings,
    error::AppError,
    infrastructure::crypto::{CryptoService, DigestPurpose, SecretKind},
};

use super::{
    events::{self, SecurityMutation},
    model::{ActorResponse, ContactChannel, TokenResponse},
};

const IAM_AUDIENCE: &str = "silicon-iam";
const IAM_SELF_SCOPE: &str = "iam.self";
const CARBON_SESSION_INSERT_QUERY: &str = r"
    INSERT INTO iam.authentication_sessions (
        id,
        subject_principal_id,
        subject_kind,
        authentication_method,
        assurance_level,
        subject_auth_epoch,
        idle_expires_at,
        absolute_expires_at
    )
    VALUES (
        $1, $2, 'carbon', $3, 1, $4,
        transaction_timestamp() + ($5::bigint * interval '1 second'),
        transaction_timestamp() + ($5::bigint * interval '1 second')
    )
    RETURNING absolute_expires_at
";
const SILICON_SESSION_INSERT_QUERY: &str = r"
    INSERT INTO iam.authentication_sessions (
        id, subject_principal_id, subject_kind, authentication_method,
        assurance_level, subject_auth_epoch, idle_expires_at, absolute_expires_at
    )
    VALUES (
        $1, $2, 'silicon', 'silicon_credential', 2, $3,
        transaction_timestamp() + ($4::bigint * interval '1 second'),
        transaction_timestamp() + ($4::bigint * interval '1 second')
    )
    RETURNING absolute_expires_at
";
const SESSION_REFRESH_TOUCH_QUERY: &str = r"
    UPDATE iam.authentication_sessions
    SET last_seen_at = transaction_timestamp(),
        idle_expires_at = absolute_expires_at,
        version = version + 1
    WHERE id = $1 AND status = 'active'
    RETURNING version
";

pub(super) enum RefreshResult {
    Rotated(TokenResponse),
    ReplayRevoked,
}

pub(super) struct SiliconLoginIdentity {
    pub(super) principal_id: Uuid,
    pub(super) credential_id: Uuid,
    pub(super) principal_auth_epoch: i64,
    pub(super) organization_id: Uuid,
    pub(super) membership_id: Uuid,
    pub(super) membership_authz_epoch: i64,
    pub(super) global_silicon_id: String,
}

#[derive(FromRow)]
struct SessionInsertRow {
    absolute_expires_at: OffsetDateTime,
}

#[derive(FromRow)]
struct AccessInsertRow {
    expires_in: i64,
}

#[derive(FromRow)]
struct RefreshLookupRow {
    token_id: Uuid,
    family_id: Uuid,
    token_consumed_at: Option<OffsetDateTime>,
    family_absolute_expires_at: OffsetDateTime,
    session_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    principal_auth_epoch: i64,
    public_id: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    membership_authz_epoch: Option<i64>,
    active: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "session, family, first token pair, and security records commit atomically"
)]
pub(super) async fn issue_login_session(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    security: &SecuritySettings,
    principal_id: Uuid,
    channel: ContactChannel,
) -> Result<TokenResponse, AppError> {
    let auth_epoch = sqlx::query_scalar::<_, i64>(
        r"
        SELECT auth_epoch
        FROM iam.principals
        WHERE id = $1 AND kind = 'carbon' AND status = 'active'
        FOR UPDATE
        ",
    )
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_principal_lock",
    })?
    .ok_or(AppError::Unauthenticated)?;

    set_principal_context(transaction, principal_id).await?;
    let carbon_id = carbon_handle(transaction, principal_id).await?;
    let session_id = Uuid::now_v7();
    let refresh_family_id = Uuid::now_v7();
    let refresh_seconds = duration_seconds(security.refresh_family_ttl, "refresh_family_ttl")?;
    let session = sqlx::query_as::<_, SessionInsertRow>(CARBON_SESSION_INSERT_QUERY)
        .bind(session_id)
        .bind(principal_id)
        .bind(channel.authentication_method())
        .bind(auth_epoch)
        .bind(refresh_seconds)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "authentication_session_create",
        })?;

    sqlx::query(
        r"
        INSERT INTO iam.refresh_token_families (
            id,
            authentication_session_id,
            subject_principal_id,
            absolute_expires_at
        )
        VALUES ($1, $2, $3, $4)
        ",
    )
    .bind(refresh_family_id)
    .bind(session_id)
    .bind(principal_id)
    .bind(session.absolute_expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_family_create",
    })?;

    let response = insert_token_pair(
        transaction,
        crypto,
        security,
        TokenPairContext {
            principal_id,
            subject_kind: "carbon",
            auth_epoch,
            public_id: carbon_id,
            organization_id: None,
            membership_id: None,
            membership_authz_epoch: None,
            session_id,
            family_id: refresh_family_id,
            parent_refresh_token_id: None,
            refresh_expires_at: session.absolute_expires_at,
        },
    )
    .await?;
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "login.success",
            authentication_outcome: "success",
            audit_action: "session.login",
            audit_result: "success",
            outbox_event: "session.created",
            subject_id: Some(principal_id),
            actor_id: Some(principal_id),
            authentication_session_id: Some(session_id),
            application_id: None,
            aggregate_type: "authentication_session",
            aggregate_id: session_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({ "authentication_method": channel.authentication_method() }),
        },
    )
    .await?;
    Ok(response)
}

#[allow(
    clippy::too_many_lines,
    reason = "Silicon credential use, session, family, token pair, and security records commit atomically"
)]
pub(super) async fn issue_silicon_session(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    security: &SecuritySettings,
    identity: SiliconLoginIdentity,
) -> Result<TokenResponse, AppError> {
    set_principal_context(transaction, identity.principal_id).await?;
    let session_id = Uuid::now_v7();
    let refresh_family_id = Uuid::now_v7();
    let refresh_seconds = duration_seconds(security.refresh_family_ttl, "refresh_family_ttl")?;
    let session = sqlx::query_as::<_, SessionInsertRow>(SILICON_SESSION_INSERT_QUERY)
        .bind(session_id)
        .bind(identity.principal_id)
        .bind(identity.principal_auth_epoch)
        .bind(refresh_seconds)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "silicon_authentication_session_create",
        })?;
    sqlx::query(
        r"
        INSERT INTO iam.refresh_token_families (
            id, authentication_session_id, subject_principal_id, absolute_expires_at
        ) VALUES ($1, $2, $3, $4)
        ",
    )
    .bind(refresh_family_id)
    .bind(session_id)
    .bind(identity.principal_id)
    .bind(session.absolute_expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "silicon_refresh_family_create",
    })?;
    sqlx::query(
        "UPDATE iam.silicon_credentials SET last_used_at = transaction_timestamp() WHERE id = $1 AND status = 'active'",
    )
    .bind(identity.credential_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "silicon_credential_touch",
    })?;
    let response = insert_token_pair(
        transaction,
        crypto,
        security,
        TokenPairContext {
            principal_id: identity.principal_id,
            subject_kind: "silicon",
            auth_epoch: identity.principal_auth_epoch,
            public_id: identity.global_silicon_id,
            organization_id: Some(identity.organization_id),
            membership_id: Some(identity.membership_id),
            membership_authz_epoch: Some(identity.membership_authz_epoch),
            session_id,
            family_id: refresh_family_id,
            parent_refresh_token_id: None,
            refresh_expires_at: session.absolute_expires_at,
        },
    )
    .await?;
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "login.success",
            authentication_outcome: "success",
            audit_action: "session.login",
            audit_result: "success",
            outbox_event: "session.created",
            subject_id: Some(identity.principal_id),
            actor_id: Some(identity.principal_id),
            authentication_session_id: Some(session_id),
            application_id: None,
            aggregate_type: "authentication_session",
            aggregate_id: session_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: json!({
                "authentication_method": "silicon_credential",
                "organization_id": identity.organization_id,
                "membership_id": identity.membership_id,
            }),
        },
    )
    .await?;
    Ok(response)
}

#[allow(
    clippy::too_many_lines,
    reason = "replay detection and rotation are one row-lock-scoped state transition"
)]
pub(super) async fn rotate_refresh_token(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    security: &SecuritySettings,
    supplied: &SecretString,
) -> Result<RefreshResult, AppError> {
    let digests = crypto
        .digest_secrets(DigestPurpose::RefreshToken, supplied)
        .map_err(|_| AppError::Internal {
            category: "refresh_token_digest",
        })?;
    let versions = digests
        .iter()
        .map(crate::infrastructure::crypto::SecretDigest::key_version)
        .collect::<Vec<_>>();
    let values = digests
        .iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let subject_principal_id = sqlx::query_scalar::<_, Uuid>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT family.subject_principal_id
        FROM supplied_digest
        JOIN iam.refresh_tokens AS token
          ON token.digest_key_version = supplied_digest.key_version
         AND token.token_digest = supplied_digest.digest
        JOIN iam.refresh_token_families AS family ON family.id = token.family_id
        LIMIT 1
        ",
    )
    .bind(versions.clone())
    .bind(values.clone())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_token_subject_lookup",
    })?
    .ok_or(AppError::Unauthenticated)?;
    set_principal_context(transaction, subject_principal_id).await?;
    let row = sqlx::query_as::<_, RefreshLookupRow>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT
            token.id AS token_id,
            token.family_id,
            token.consumed_at AS token_consumed_at,
            family.absolute_expires_at AS family_absolute_expires_at,
            session.id AS session_id,
            session.subject_principal_id,
            session.subject_kind::text AS subject_kind,
            principal.auth_epoch AS principal_auth_epoch,
            COALESCE(carbon.carbon_id, silicon.global_silicon_id) AS public_id,
            silicon.organization_id,
            silicon.membership_id,
            membership.authz_epoch AS membership_authz_epoch,
            token.revoked_at IS NULL
                AND token.expires_at > transaction_timestamp()
                AND family.status = 'active'
                AND family.absolute_expires_at > transaction_timestamp()
                AND session.status = 'active'
                AND session.idle_expires_at > transaction_timestamp()
                AND session.absolute_expires_at > transaction_timestamp()
                AND principal.status = 'active'
                AND session.subject_auth_epoch = principal.auth_epoch AS active
        FROM supplied_digest
        JOIN iam.refresh_tokens AS token
          ON token.digest_key_version = supplied_digest.key_version
         AND token.token_digest = supplied_digest.digest
        JOIN iam.refresh_token_families AS family ON family.id = token.family_id
        JOIN iam.authentication_sessions AS session
          ON session.id = family.authentication_session_id
         AND session.subject_principal_id = family.subject_principal_id
        JOIN iam.principals AS principal
          ON principal.id = session.subject_principal_id
         AND principal.kind = session.subject_kind
        LEFT JOIN iam.carbons AS carbon
          ON carbon.id = principal.id
         AND principal.kind = 'carbon'
         AND carbon.deleted_at IS NULL
        LEFT JOIN iam.silicons AS silicon
          ON silicon.id = principal.id
         AND principal.kind = 'silicon'
         AND silicon.provisioning_status = 'active'
         AND silicon.deleted_at IS NULL
        LEFT JOIN iam.organization_memberships AS membership
          ON membership.organization_id = silicon.organization_id
         AND membership.id = silicon.membership_id
         AND membership.principal_id = silicon.id
         AND membership.principal_kind = 'silicon'
         AND membership.status = 'active'
        LEFT JOIN iam.organizations AS organization
          ON organization.id = silicon.organization_id
         AND organization.status = 'active'
        WHERE (
            (principal.kind = 'carbon' AND carbon.id IS NOT NULL)
            OR (
                principal.kind = 'silicon'
                AND silicon.id IS NOT NULL
                AND membership.id IS NOT NULL
                AND organization.id IS NOT NULL
            )
        )
        LIMIT 1
        FOR UPDATE OF token, family, session, principal
        ",
    )
    .bind(versions)
    .bind(values)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_token_lookup",
    })?
    .ok_or(AppError::Unauthenticated)?;

    if row.token_consumed_at.is_some() {
        revoke_replayed_family(transaction, &row).await?;
        return Ok(RefreshResult::ReplayRevoked);
    }
    if !row.active {
        return Err(AppError::Unauthenticated);
    }

    set_principal_context(transaction, row.subject_principal_id).await?;
    let replacement_id = Uuid::now_v7();
    let response = insert_token_pair_with_id(
        transaction,
        crypto,
        security,
        TokenPairContext {
            principal_id: row.subject_principal_id,
            subject_kind: subject_kind(&row.subject_kind)?,
            auth_epoch: row.principal_auth_epoch,
            public_id: row.public_id.clone(),
            organization_id: row.organization_id,
            membership_id: row.membership_id,
            membership_authz_epoch: row.membership_authz_epoch,
            session_id: row.session_id,
            family_id: row.family_id,
            parent_refresh_token_id: Some(row.token_id),
            refresh_expires_at: row.family_absolute_expires_at,
        },
        replacement_id,
    )
    .await?;
    let session_version = sqlx::query_scalar::<_, i64>(SESSION_REFRESH_TOUCH_QUERY)
        .bind(row.session_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "session_refresh_touch",
        })?;
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "refresh.success",
            authentication_outcome: "success",
            audit_action: "token.refresh",
            audit_result: "success",
            outbox_event: "token.refreshed",
            subject_id: Some(row.subject_principal_id),
            actor_id: Some(row.subject_principal_id),
            authentication_session_id: Some(row.session_id),
            application_id: None,
            aggregate_type: "authentication_session",
            aggregate_id: row.session_id,
            aggregate_version: session_version,
            failure_code: None,
            metadata: json!({}),
        },
    )
    .await?;
    Ok(RefreshResult::Rotated(response))
}

struct TokenPairContext {
    principal_id: Uuid,
    subject_kind: &'static str,
    auth_epoch: i64,
    public_id: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    membership_authz_epoch: Option<i64>,
    session_id: Uuid,
    family_id: Uuid,
    parent_refresh_token_id: Option<Uuid>,
    refresh_expires_at: OffsetDateTime,
}

async fn insert_token_pair(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    security: &SecuritySettings,
    context: TokenPairContext,
) -> Result<TokenResponse, AppError> {
    insert_token_pair_with_id(transaction, crypto, security, context, Uuid::now_v7()).await
}

#[allow(
    clippy::too_many_lines,
    reason = "paired access/refresh persistence and parent consumption are intentionally atomic"
)]
async fn insert_token_pair_with_id(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    security: &SecuritySettings,
    context: TokenPairContext,
    refresh_token_id: Uuid,
) -> Result<TokenResponse, AppError> {
    let (secret_kind, digest_purpose, token_class, expected_prefix) = match context.subject_kind {
        "carbon" => (
            SecretKind::CarbonAccessToken,
            DigestPurpose::CarbonAccessToken,
            "carbon_access",
            "cat_",
        ),
        "silicon" => (
            SecretKind::SiliconAccessToken,
            DigestPurpose::SiliconAccessToken,
            "silicon_access",
            "sat_",
        ),
        _ => {
            return Err(AppError::Internal {
                category: "iam_token_subject_kind",
            });
        }
    };
    let access = crypto
        .generate_secret(secret_kind)
        .map_err(|_| AppError::Internal {
            category: "access_token_generate",
        })?;
    let refresh = crypto
        .generate_secret(SecretKind::RefreshToken)
        .map_err(|_| AppError::Internal {
            category: "refresh_token_generate",
        })?;
    let access_digest =
        crypto
            .digest_secret(digest_purpose, &access)
            .map_err(|_| AppError::Internal {
                category: "access_token_digest",
            })?;
    let refresh_digest = crypto
        .digest_secret(DigestPurpose::RefreshToken, &refresh)
        .map_err(|_| AppError::Internal {
            category: "refresh_token_digest",
        })?;
    let access_token_id = Uuid::now_v7();
    let access_seconds = duration_seconds(security.access_token_ttl, "access_token_ttl")?;
    let access_row = sqlx::query_as::<_, AccessInsertRow>(
        r"
        WITH inserted AS (
            INSERT INTO iam.access_tokens (
                id,
                token_class,
                token_digest,
                digest_key_version,
                token_prefix,
                authentication_session_id,
                subject_principal_id,
                subject_kind,
                audience,
                organization_id,
                membership_id,
                subject_auth_epoch,
                membership_authz_epoch,
                expires_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8::iam.principal_kind, $9,
                $10, $11, $12, $13,
                LEAST(
                    transaction_timestamp() + ($14::bigint * interval '1 second'),
                    $15
                )
            )
            RETURNING expires_at
        )
        SELECT GREATEST(
            0,
            FLOOR(EXTRACT(EPOCH FROM expires_at - transaction_timestamp()))::bigint
        ) AS expires_in
        FROM inserted
        ",
    )
    .bind(access_token_id)
    .bind(token_class)
    .bind(access_digest.as_bytes().as_slice())
    .bind(access_digest.key_version())
    .bind(token_prefix(&access, expected_prefix)?)
    .bind(context.session_id)
    .bind(context.principal_id)
    .bind(context.subject_kind)
    .bind(IAM_AUDIENCE)
    .bind(context.organization_id)
    .bind(context.membership_id)
    .bind(context.auth_epoch)
    .bind(context.membership_authz_epoch)
    .bind(access_seconds)
    .bind(context.refresh_expires_at)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "access_token_create",
    })?;
    sqlx::query("INSERT INTO iam.access_token_scopes (access_token_id, scope) VALUES ($1, $2)")
        .bind(access_token_id)
        .bind(IAM_SELF_SCOPE)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "access_token_scope_create",
        })?;

    sqlx::query(
        r"
        INSERT INTO iam.refresh_tokens (
            id,
            family_id,
            parent_token_id,
            token_digest,
            digest_key_version,
            token_prefix,
            expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ",
    )
    .bind(refresh_token_id)
    .bind(context.family_id)
    .bind(context.parent_refresh_token_id)
    .bind(refresh_digest.as_bytes().as_slice())
    .bind(refresh_digest.key_version())
    .bind(token_prefix(&refresh, "rft_")?)
    .bind(context.refresh_expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_token_create",
    })?;
    if let Some(parent_id) = context.parent_refresh_token_id {
        let result = sqlx::query(
            r"
            UPDATE iam.refresh_tokens
            SET consumed_at = transaction_timestamp(), replacement_token_id = $2
            WHERE id = $1 AND consumed_at IS NULL AND replacement_token_id IS NULL
            ",
        )
        .bind(parent_id)
        .bind(refresh_token_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "refresh_token_consume",
        })?;
        if result.rows_affected() != 1 {
            return Err(AppError::Unauthenticated);
        }
    }

    let expires_in = u64::try_from(access_row.expires_in).map_err(|_| AppError::Internal {
        category: "access_token_expiry",
    })?;
    Ok(TokenResponse {
        access_token: access.expose_secret().to_owned(),
        refresh_token: refresh.expose_secret().to_owned(),
        token_type: "Bearer".to_owned(),
        expires_in,
        refresh_expires_at: context.refresh_expires_at,
        actor: ActorResponse {
            principal_id: context.principal_id,
            actor_type: context.subject_kind.to_owned(),
            public_id: context.public_id,
        },
        session_id: context.session_id,
    })
}

async fn revoke_replayed_family(
    transaction: &mut Transaction<'_, Postgres>,
    row: &RefreshLookupRow,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'compromised',
            compromised_at = COALESCE(compromised_at, transaction_timestamp()),
            revocation_reason = 'refresh_replay'
        WHERE id = $1 AND status <> 'compromised'
        ",
    )
    .bind(row.family_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_family_compromise",
    })?;
    sqlx::query(
        r"
        UPDATE iam.refresh_tokens
        SET revoked_at = COALESCE(revoked_at, transaction_timestamp())
        WHERE family_id = $1
        ",
    )
    .bind(row.family_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_family_tokens_revoke",
    })?;
    sqlx::query(
        r"
        UPDATE iam.access_tokens
        SET revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = COALESCE(revocation_reason, 'refresh_replay')
        WHERE authentication_session_id = $1
        ",
    )
    .bind(row.session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_replay_access_revoke",
    })?;
    let session_version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.authentication_sessions
        SET status = 'revoked',
            revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = 'refresh_replay',
            version = version + 1
        WHERE id = $1
        RETURNING version
        ",
    )
    .bind(row.session_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_replay_session_revoke",
    })?;
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "refresh.replay",
            authentication_outcome: "denied",
            audit_action: "refresh.replay_revoke",
            audit_result: "denied",
            outbox_event: "refresh.family_compromised",
            subject_id: Some(row.subject_principal_id),
            actor_id: None,
            authentication_session_id: Some(row.session_id),
            application_id: None,
            aggregate_type: "authentication_session",
            aggregate_id: row.session_id,
            aggregate_version: session_version,
            failure_code: Some("refresh_replay"),
            metadata: json!({ "family_id": row.family_id }),
        },
    )
    .await
}

async fn set_principal_context(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("SELECT set_config('iam.principal_id', $1, true)")
        .bind(principal_id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "authentication_principal_context",
        })?;
    Ok(())
}

async fn carbon_handle(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
) -> Result<String, AppError> {
    sqlx::query_scalar::<_, String>(
        "SELECT carbon_id FROM iam.carbons WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "carbon_handle_read",
    })?
    .ok_or(AppError::Unauthenticated)
}

fn subject_kind(value: &str) -> Result<&'static str, AppError> {
    match value {
        "carbon" => Ok("carbon"),
        "silicon" => Ok("silicon"),
        _ => Err(AppError::Internal {
            category: "refresh_subject_kind",
        }),
    }
}

fn token_prefix(token: &SecretString, expected: &'static str) -> Result<String, AppError> {
    let value = token.expose_secret();
    if !value.starts_with(expected) || value.len() != 47 {
        return Err(AppError::Internal {
            category: "generated_token_shape",
        });
    }
    value
        .get(..12)
        .map(str::to_owned)
        .ok_or(AppError::Internal {
            category: "generated_token_shape",
        })
}

fn duration_seconds(
    duration: std::time::Duration,
    category: &'static str,
) -> Result<i64, AppError> {
    i64::try_from(duration.as_secs()).map_err(|_| AppError::Internal { category })
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{
        CARBON_SESSION_INSERT_QUERY, SESSION_REFRESH_TOUCH_QUERY, SILICON_SESSION_INSERT_QUERY,
        token_prefix,
    };

    #[test]
    fn persisted_prefix_is_class_bound_and_fixed_length() {
        let token = SecretString::from(format!("cat_{}", "A".repeat(43)));
        assert!(matches!(token_prefix(&token, "cat_"), Ok(value) if value == "cat_AAAAAAAA"));
        assert!(token_prefix(&token, "rft_").is_err());
    }

    #[test]
    fn iam_session_idle_deadline_is_the_absolute_refresh_deadline() {
        for query in [CARBON_SESSION_INSERT_QUERY, SILICON_SESSION_INSERT_QUERY] {
            let deadline_assignments = query
                .lines()
                .filter(|line| line.contains("transaction_timestamp() +"))
                .map(|line| line.trim().trim_end_matches(','))
                .collect::<Vec<_>>();
            assert_eq!(deadline_assignments.len(), 2);
            assert_eq!(deadline_assignments[0], deadline_assignments[1]);
            assert!(!query.contains("30 days"));
        }
        assert!(SESSION_REFRESH_TOUCH_QUERY.contains("idle_expires_at = absolute_expires_at"));
    }

    #[test]
    fn forward_migration_aligns_existing_iam_and_oauth_refresh_credentials() {
        let migration = include_str!("../../../migrations/0028_align_refresh_session_lifetime.sql");
        assert!(migration.contains("idle_expires_at = authentication_session.absolute_expires_at"));
        assert!(migration.contains("family.client_application_id IS NOT NULL"));
        assert!(migration.contains("SET expires_at = family.absolute_expires_at"));
    }
}
