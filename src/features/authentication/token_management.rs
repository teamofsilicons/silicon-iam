use std::{num::NonZeroU32, time::Duration};

use axum::{
    Form, Json,
    extract::{
        FromRequestParts, State,
        rejection::{FormRejection, JsonRejection},
    },
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse as _, Response},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    error::AppError,
    features::applications::security::ApplicationClient,
    infrastructure::{
        crypto::{DigestPurpose, SecretDigest},
        postgres::{
            rate_limit::{self, RateLimitPolicy},
            tokens::{self as access_tokens, AccessContext, AccessTokenError},
        },
    },
};

use super::{
    database::{database_conflict, serializable, set_principal_context},
    events::{self, SecurityMutation},
    idempotency::{self, Claim, IdempotencyKey},
    model::EmptyMutationOutcome,
    validation,
};

const REVOKE_ROUTE: &str = "/api/v1/auth/tokens/revoke";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IntrospectionInput {
    token: String,
    token_type_hint: Option<TokenTypeHint>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevocationInput {
    token: String,
    token_type_hint: Option<TokenTypeHint>,
    #[serde(default)]
    revoke_family: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenTypeHint {
    AccessToken,
    RefreshToken,
}

#[derive(Debug, Serialize)]
pub(super) struct IntrospectionResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    membership_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_epoch: Option<i64>,
}

pub(super) enum RevocationActor {
    Iam(AccessContext),
    Application(ApplicationClient),
}

#[derive(FromRow)]
struct AccessMetadataRow {
    client_application_id: Option<Uuid>,
    audience_application_id: Option<Uuid>,
    client_id: Option<String>,
    subject_auth_epoch: i64,
    membership_authz_epoch: Option<i64>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

#[derive(FromRow)]
struct RefreshMetadataRow {
    session_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    client_id: Option<String>,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    subject_auth_epoch: i64,
    membership_authz_epoch: Option<i64>,
    scopes: Vec<String>,
    audience: String,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

#[derive(FromRow)]
struct AccessRevocationRow {
    id: Uuid,
    authentication_session_id: Uuid,
    subject_principal_id: Uuid,
    client_application_id: Option<Uuid>,
    audience_application_id: Option<Uuid>,
    revoked_at: Option<OffsetDateTime>,
}

#[derive(FromRow)]
struct RefreshRevocationRow {
    id: Uuid,
    family_id: Uuid,
    authentication_session_id: Uuid,
    subject_principal_id: Uuid,
    client_application_id: Option<Uuid>,
    revoked_at: Option<OffsetDateTime>,
}

enum ParsedToken {
    Access(DigestPurpose),
    Refresh(DigestPurpose),
}

impl FromRequestParts<ApiState> for RevocationActor {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let scheme = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' ').map(|(scheme, _)| scheme));
        match scheme {
            Some(value) if value.eq_ignore_ascii_case("Bearer") => {
                Authenticated::from_request_parts(parts, state)
                    .await
                    .map(|Authenticated(context)| Self::Iam(context))
                    .map_err(axum::response::IntoResponse::into_response)
            }
            Some(value) if value.eq_ignore_ascii_case("Basic") => {
                ApplicationClient::from_request_parts(parts, state)
                    .await
                    .map(Self::Application)
                    .map_err(axum::response::IntoResponse::into_response)
            }
            _ => Err(AppError::Unauthenticated.into_response()),
        }
    }
}

pub(super) async fn introspect(
    State(state): State<ApiState>,
    client: ApplicationClient,
    payload: Result<Form<IntrospectionInput>, FormRejection>,
) -> Result<Json<IntrospectionResponse>, AppError> {
    let input = payload
        .map(|Form(value)| value)
        .map_err(|_| validation::validation("body", "must be URL-encoded token input"))?;
    validate_supplied_token(&input.token)?;
    enforce_limit(
        &state,
        "iam_token_introspection",
        &client.app_id,
        &input.token,
    )
    .await?;
    let supplied = SecretString::from(input.token);
    let parsed = parse_token(&supplied, input.token_type_hint);
    let response = match parsed {
        Ok(ParsedToken::Access(_)) => introspect_access(&state, &client, &supplied).await?,
        Ok(ParsedToken::Refresh(purpose)) => {
            introspect_refresh(&state, &client, &supplied, purpose).await?
        }
        Err(()) => IntrospectionResponse::inactive(),
    };
    Ok(Json(response))
}

pub(super) async fn revoke(
    State(state): State<ApiState>,
    actor: RevocationActor,
    headers: HeaderMap,
    payload: Result<Json<RevocationInput>, JsonRejection>,
) -> Result<StatusCode, AppError> {
    let input = payload
        .map(|Json(value)| value)
        .map_err(|_| validation::validation("body", "must match the documented JSON schema"))?;
    validate_supplied_token(&input.token)?;
    let key = IdempotencyKey::from_headers(&headers)?;
    let supplied = SecretString::from(input.token.clone());
    let parsed = parse_token(&supplied, input.token_type_hint).ok();
    let actor_scope = actor_scope(&actor);
    enforce_limit(
        &state,
        "iam_token_revocation",
        &actor_scope,
        supplied.expose_secret(),
    )
    .await?;
    let request_digest = revocation_request_digest(&state, &input, &supplied, parsed.as_ref())?;
    let mut transaction = serializable(&state.pool, "iam_token_revoke_transaction").await?;
    let record_id = match idempotency::begin::<EmptyMutationOutcome>(
        &mut transaction,
        &state.crypto,
        &key,
        actor_scope.as_bytes(),
        REVOKE_ROUTE,
        request_digest,
        false,
    )
    .await?
    {
        Claim::Replay { .. } => {
            transaction
                .commit()
                .await
                .map_err(|error| database_conflict(&error, "iam_token_revoke_conflict"))?;
            return Ok(StatusCode::NO_CONTENT);
        }
        Claim::Acquired { record_id } => record_id,
    };
    match parsed {
        Some(ParsedToken::Access(purpose)) => {
            revoke_access(
                &mut transaction,
                &state,
                &actor,
                &supplied,
                purpose,
                input.revoke_family,
            )
            .await?;
        }
        Some(ParsedToken::Refresh(purpose)) => {
            revoke_refresh(
                &mut transaction,
                &state,
                &actor,
                &supplied,
                purpose,
                input.revoke_family,
            )
            .await?;
        }
        None => {}
    }
    let outcome = EmptyMutationOutcome::Completed;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        StatusCode::NO_CONTENT.as_u16(),
        &outcome,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "iam_token_revoke_conflict"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[allow(
    clippy::too_many_lines,
    reason = "all inactive-token normalization and authority checks form one protocol decision"
)]
async fn introspect_access(
    state: &ApiState,
    client: &ApplicationClient,
    supplied: &SecretString,
) -> Result<IntrospectionResponse, AppError> {
    let access = match access_tokens::authenticate(&state.pool, &state.crypto, supplied).await {
        Ok(Some(access)) => access,
        Ok(None) | Err(AccessTokenError::InvalidFormat) => {
            return Ok(IntrospectionResponse::inactive());
        }
        Err(AccessTokenError::Crypto(_)) => {
            return Err(AppError::Internal {
                category: "token_introspection_crypto",
            });
        }
        Err(AccessTokenError::Database(_)) => {
            return Err(AppError::Internal {
                category: "token_introspection_database",
            });
        }
        Err(AccessTokenError::InvalidStoredActorKind) => {
            return Err(AppError::Internal {
                category: "token_introspection_actor_kind",
            });
        }
    };
    let mut transaction = state.pool.begin().await.map_err(|_| AppError::Internal {
        category: "token_introspection_transaction",
    })?;
    set_application_context(&mut transaction, client.application_id).await?;
    set_principal_context(&mut transaction, access.subject.id).await?;
    let metadata = sqlx::query_as::<_, AccessMetadataRow>(
        r"
        SELECT token.client_application_id, token.audience_application_id,
               application.app_id AS client_id,
               token.subject_auth_epoch, token.membership_authz_epoch,
               token.created_at, token.expires_at
        FROM iam.access_tokens AS token
        JOIN iam.authentication_sessions AS session
          ON session.id = token.authentication_session_id
         AND session.subject_principal_id = token.subject_principal_id
        JOIN iam.principals AS subject
          ON subject.id = token.subject_principal_id
         AND subject.kind = token.subject_kind
        JOIN iam.principals AS caller_principal
          ON caller_principal.id = $2
         AND caller_principal.kind = 'application'
         AND caller_principal.status = 'active'
         AND caller_principal.auth_epoch = $3
        JOIN iam.applications AS caller_application
          ON caller_application.id = caller_principal.id
         AND caller_application.review_status = 'verified'
         AND caller_application.deleted_at IS NULL
        LEFT JOIN iam.applications AS application ON application.id = token.client_application_id
        LEFT JOIN iam.organization_memberships AS membership
          ON membership.organization_id = token.organization_id
         AND membership.id = token.membership_id
         AND membership.principal_id = token.subject_principal_id
         AND membership.principal_kind = token.subject_kind
        LEFT JOIN iam.organizations AS organization ON organization.id = token.organization_id
        WHERE token.id = $1
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
                  AND membership.status = 'active'
                  AND membership.authz_epoch = token.membership_authz_epoch
              )
          )
        FOR SHARE OF token, session, subject, caller_principal, caller_application
        ",
    )
    .bind(access.token_id)
    .bind(client.application_id)
    .bind(client.auth_epoch)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "token_introspection_metadata",
    })?;
    let Some(metadata) = metadata else {
        transaction
            .rollback()
            .await
            .map_err(|_| AppError::Internal {
                category: "token_introspection_rollback",
            })?;
        return Ok(IntrospectionResponse::inactive());
    };
    if metadata.client_application_id != Some(client.application_id)
        && metadata.audience_application_id != Some(client.application_id)
    {
        transaction
            .rollback()
            .await
            .map_err(|_| AppError::Internal {
                category: "token_introspection_rollback",
            })?;
        return Ok(IntrospectionResponse::inactive());
    }
    let org_id = public_organization_id(&mut transaction, access.organization_id).await?;
    transaction.commit().await.map_err(|_| AppError::Internal {
        category: "token_introspection_commit",
    })?;
    Ok(IntrospectionResponse {
        active: true,
        principal_id: Some(access.subject.id),
        actor_type: Some(access.subject.actor_type.as_str().to_owned()),
        client_id: metadata.client_id,
        org_id,
        membership_id: access.membership_id,
        session_id: Some(access.authentication_session_id),
        scope: Some(access.scopes.join(" ")),
        audience: Some(access.audience),
        issued_at: Some(metadata.created_at.unix_timestamp()),
        expires_at: Some(metadata.expires_at.unix_timestamp()),
        authorization_epoch: Some(
            metadata
                .membership_authz_epoch
                .unwrap_or(metadata.subject_auth_epoch),
        ),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "refresh introspection revalidates credential, session, consent, and membership state"
)]
async fn introspect_refresh(
    state: &ApiState,
    client: &ApplicationClient,
    supplied: &SecretString,
    purpose: DigestPurpose,
) -> Result<IntrospectionResponse, AppError> {
    let (versions, digests) = digest_candidates(state, purpose, supplied)?;
    let mut transaction = state.pool.begin().await.map_err(|_| AppError::Internal {
        category: "refresh_introspection_transaction",
    })?;
    set_application_context(&mut transaction, client.application_id).await?;
    let row = sqlx::query_as::<_, RefreshMetadataRow>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT session.id AS session_id,
               session.subject_principal_id,
               session.subject_kind::text AS subject_kind,
               application.app_id AS client_id,
               consent.organization_id,
               consent.membership_id,
               token_subject.auth_epoch AS subject_auth_epoch,
               NULL::bigint AS membership_authz_epoch,
               CASE WHEN family.client_application_id IS NULL
                    THEN ARRAY['iam.self']::text[]
                    ELSE ARRAY(
                        SELECT scope.scope
                        FROM iam.oauth_refresh_family_scopes AS scope
                        WHERE scope.family_id = family.id
                        ORDER BY scope.scope
                    )
               END AS scopes,
               application.app_id AS audience,
               refresh.created_at,
               refresh.expires_at
        FROM supplied_digest
        JOIN iam.refresh_tokens AS refresh
          ON refresh.digest_key_version = supplied_digest.key_version
         AND refresh.token_digest = supplied_digest.digest
        JOIN iam.refresh_token_families AS family ON family.id = refresh.family_id
        JOIN iam.authentication_sessions AS session
          ON session.id = family.authentication_session_id
         AND session.subject_principal_id = family.subject_principal_id
        JOIN iam.principals AS token_subject
          ON token_subject.id = session.subject_principal_id
         AND token_subject.kind = session.subject_kind
        JOIN iam.applications AS application
          ON application.id = family.client_application_id
         AND application.review_status = 'verified'
         AND application.deleted_at IS NULL
        JOIN iam.principals AS client_principal
          ON client_principal.id = family.client_application_id
         AND client_principal.kind = 'application'
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = family.oauth_consent_grant_id
         AND consent.application_id = family.client_application_id
         AND consent.subject_principal_id = family.subject_principal_id
        WHERE refresh.revoked_at IS NULL
          AND refresh.consumed_at IS NULL
          AND refresh.expires_at > transaction_timestamp()
          AND family.status = 'active'
          AND family.absolute_expires_at > transaction_timestamp()
          AND session.status = 'active'
          AND session.idle_expires_at > transaction_timestamp()
          AND session.absolute_expires_at > transaction_timestamp()
          AND token_subject.status = 'active'
          AND token_subject.auth_epoch = session.subject_auth_epoch
          AND consent.status = 'active'
          AND family.client_application_id = $3
          AND client_principal.status = 'active'
          AND client_principal.auth_epoch = $4
        LIMIT 1
        FOR SHARE OF refresh, family, session, token_subject, application, client_principal, consent
        ",
    )
    .bind(versions)
    .bind(digests)
    .bind(client.application_id)
    .bind(client.auth_epoch)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_introspection_query",
    })?;
    let Some(row) = row else {
        transaction
            .rollback()
            .await
            .map_err(|_| AppError::Internal {
                category: "refresh_introspection_rollback",
            })?;
        return Ok(IntrospectionResponse::inactive());
    };
    set_principal_context(&mut transaction, row.subject_principal_id).await?;
    let consent_membership_epoch = match (row.organization_id, row.membership_id) {
        (Some(organization_id), Some(membership_id)) => {
            let epoch = sqlx::query_scalar::<_, i64>(
                r"
                SELECT membership.authz_epoch
                FROM iam.organization_memberships AS membership
                JOIN iam.organizations AS organization
                  ON organization.id = membership.organization_id
                 AND organization.status = 'active'
                WHERE membership.organization_id = $1
                  AND membership.id = $2
                  AND membership.principal_id = $3
                  AND membership.principal_kind = $4::iam.principal_kind
                  AND membership.status = 'active'
                FOR SHARE OF membership, organization
                ",
            )
            .bind(organization_id)
            .bind(membership_id)
            .bind(row.subject_principal_id)
            .bind(&row.subject_kind)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| AppError::Internal {
                category: "refresh_introspection_membership",
            })?;
            let Some(epoch) = epoch else {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| AppError::Internal {
                        category: "refresh_introspection_rollback",
                    })?;
                return Ok(IntrospectionResponse::inactive());
            };
            Some(epoch)
        }
        (None, None) => None,
        _ => {
            transaction
                .rollback()
                .await
                .map_err(|_| AppError::Internal {
                    category: "refresh_introspection_rollback",
                })?;
            return Ok(IntrospectionResponse::inactive());
        }
    };
    let silicon_binding = if row.subject_kind == "silicon" && row.organization_id.is_none() {
        sqlx::query_as::<_, (Uuid, Uuid, i64)>(
            r"
            SELECT silicon.organization_id, silicon.membership_id, membership.authz_epoch
            FROM iam.silicons AS silicon
            JOIN iam.organization_memberships AS membership
              ON membership.organization_id = silicon.organization_id
             AND membership.id = silicon.membership_id
             AND membership.principal_id = silicon.id
             AND membership.status = 'active'
            JOIN iam.organizations AS organization
              ON organization.id = silicon.organization_id
             AND organization.status = 'active'
            WHERE silicon.id = $1
              AND silicon.provisioning_status = 'active'
              AND silicon.deleted_at IS NULL
            FOR SHARE OF silicon, membership, organization
            ",
        )
        .bind(row.subject_principal_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "refresh_introspection_silicon",
        })?
    } else {
        None
    };
    if row.subject_kind == "silicon" && row.organization_id.is_none() && silicon_binding.is_none() {
        transaction
            .rollback()
            .await
            .map_err(|_| AppError::Internal {
                category: "refresh_introspection_rollback",
            })?;
        return Ok(IntrospectionResponse::inactive());
    }
    let organization_id = row
        .organization_id
        .or_else(|| silicon_binding.map(|value| value.0));
    let membership_id = row
        .membership_id
        .or_else(|| silicon_binding.map(|value| value.1));
    let authorization_epoch = row
        .membership_authz_epoch
        .or(consent_membership_epoch)
        .or_else(|| silicon_binding.map(|value| value.2))
        .unwrap_or(row.subject_auth_epoch);
    let org_id = public_organization_id(&mut transaction, organization_id).await?;
    transaction.commit().await.map_err(|_| AppError::Internal {
        category: "refresh_introspection_commit",
    })?;
    Ok(IntrospectionResponse {
        active: true,
        principal_id: Some(row.subject_principal_id),
        actor_type: Some(row.subject_kind),
        client_id: row.client_id,
        org_id,
        membership_id,
        session_id: Some(row.session_id),
        scope: Some(row.scopes.join(" ")),
        audience: Some(row.audience),
        issued_at: Some(row.created_at.unix_timestamp()),
        expires_at: Some(row.expires_at.unix_timestamp()),
        authorization_epoch: Some(authorization_epoch),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "access-token authorization and family revocation are one locked transition"
)]
async fn revoke_access(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    actor: &RevocationActor,
    supplied: &SecretString,
    purpose: DigestPurpose,
    revoke_family: bool,
) -> Result<(), AppError> {
    let (versions, digests) = digest_candidates(state, purpose, supplied)?;
    let row = sqlx::query_as::<_, AccessRevocationRow>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT token.id, token.authentication_session_id, token.subject_principal_id,
               token.client_application_id, token.audience_application_id, token.revoked_at
        FROM supplied_digest
        JOIN iam.access_tokens AS token
          ON token.digest_key_version = supplied_digest.key_version
         AND token.token_digest = supplied_digest.digest
        LIMIT 1
        FOR UPDATE OF token
        ",
    )
    .bind(versions)
    .bind(digests)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "access_token_revoke_lookup",
    })?;
    let Some(row) = row else {
        return Ok(());
    };
    authorize_revocation(
        actor,
        row.subject_principal_id,
        row.client_application_id,
        row.audience_application_id,
    )?;
    if row.revoked_at.is_some() {
        return Ok(());
    }
    let affected = if revoke_family {
        revoke_session_family(
            transaction,
            row.authentication_session_id,
            row.client_application_id,
        )
        .await?;
        true
    } else {
        sqlx::query(
            "UPDATE iam.access_tokens SET revoked_at = transaction_timestamp(), revocation_reason = 'explicit_revocation' WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(row.id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal { category: "access_token_revoke" })?
        .rows_affected() == 1
    };
    if affected {
        record_revocation(
            transaction,
            actor,
            row.subject_principal_id,
            row.authentication_session_id,
            row.id,
            "access_token",
        )
        .await?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "refresh-token authorization and optional family revocation are one locked transition"
)]
async fn revoke_refresh(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    actor: &RevocationActor,
    supplied: &SecretString,
    purpose: DigestPurpose,
    revoke_family: bool,
) -> Result<(), AppError> {
    let (versions, digests) = digest_candidates(state, purpose, supplied)?;
    let row = sqlx::query_as::<_, RefreshRevocationRow>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT refresh.id, refresh.family_id, family.authentication_session_id,
               family.subject_principal_id, family.client_application_id, refresh.revoked_at
        FROM supplied_digest
        JOIN iam.refresh_tokens AS refresh
          ON refresh.digest_key_version = supplied_digest.key_version
         AND refresh.token_digest = supplied_digest.digest
        JOIN iam.refresh_token_families AS family ON family.id = refresh.family_id
        LIMIT 1
        FOR UPDATE OF refresh, family
        ",
    )
    .bind(versions)
    .bind(digests)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "refresh_token_revoke_lookup",
    })?;
    let Some(row) = row else {
        return Ok(());
    };
    authorize_revocation(
        actor,
        row.subject_principal_id,
        row.client_application_id,
        row.client_application_id,
    )?;
    if row.revoked_at.is_some() {
        return Ok(());
    }
    let affected = if revoke_family {
        revoke_family_by_id(transaction, &row).await?;
        true
    } else {
        sqlx::query(
            "UPDATE iam.refresh_tokens SET revoked_at = transaction_timestamp() WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(row.id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal { category: "refresh_token_revoke" })?
        .rows_affected() == 1
    };
    if affected {
        record_revocation(
            transaction,
            actor,
            row.subject_principal_id,
            row.authentication_session_id,
            row.id,
            "refresh_token",
        )
        .await?;
    }
    Ok(())
}

async fn revoke_family_by_id(
    transaction: &mut Transaction<'_, Postgres>,
    row: &RefreshRevocationRow,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE iam.refresh_token_families SET status = 'revoked', revoked_at = COALESCE(revoked_at, transaction_timestamp()), revocation_reason = 'explicit_revocation' WHERE id = $1 AND status = 'active'",
    )
    .bind(row.family_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal { category: "refresh_family_revoke" })?;
    sqlx::query("UPDATE iam.refresh_tokens SET revoked_at = COALESCE(revoked_at, transaction_timestamp()) WHERE family_id = $1")
        .bind(row.family_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal { category: "refresh_family_tokens_revoke" })?;
    sqlx::query(
        "UPDATE iam.access_tokens SET revoked_at = COALESCE(revoked_at, transaction_timestamp()), revocation_reason = COALESCE(revocation_reason, 'explicit_revocation') WHERE authentication_session_id = $1 AND client_application_id IS NOT DISTINCT FROM $2",
    )
    .bind(row.authentication_session_id)
    .bind(row.client_application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal { category: "refresh_family_access_revoke" })?;
    if row.client_application_id.is_none() {
        revoke_parent_session(transaction, row.authentication_session_id).await?;
    }
    Ok(())
}

async fn revoke_session_family(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
    client_application_id: Option<Uuid>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE iam.refresh_token_families SET status = 'revoked', revoked_at = COALESCE(revoked_at, transaction_timestamp()), revocation_reason = 'explicit_revocation' WHERE authentication_session_id = $1 AND client_application_id IS NOT DISTINCT FROM $2 AND status = 'active'",
    )
    .bind(session_id)
    .bind(client_application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal { category: "session_refresh_family_revoke" })?;
    sqlx::query(
        "UPDATE iam.refresh_tokens SET revoked_at = COALESCE(revoked_at, transaction_timestamp()) WHERE family_id IN (SELECT id FROM iam.refresh_token_families WHERE authentication_session_id = $1 AND client_application_id IS NOT DISTINCT FROM $2)",
    )
    .bind(session_id)
    .bind(client_application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal { category: "session_refresh_tokens_revoke" })?;
    sqlx::query(
        "UPDATE iam.access_tokens SET revoked_at = COALESCE(revoked_at, transaction_timestamp()), revocation_reason = COALESCE(revocation_reason, 'explicit_revocation') WHERE authentication_session_id = $1 AND client_application_id IS NOT DISTINCT FROM $2",
    )
    .bind(session_id)
    .bind(client_application_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal { category: "session_access_tokens_revoke" })?;
    if client_application_id.is_none() {
        revoke_parent_session(transaction, session_id).await?;
    }
    Ok(())
}

async fn revoke_parent_session(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE iam.authentication_sessions SET status = 'revoked', revoked_at = COALESCE(revoked_at, transaction_timestamp()), revocation_reason = 'explicit_revocation', version = version + 1 WHERE id = $1 AND status = 'active'",
    )
    .bind(session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal { category: "authentication_session_revoke" })?;
    Ok(())
}

async fn record_revocation(
    transaction: &mut Transaction<'_, Postgres>,
    actor: &RevocationActor,
    subject_id: Uuid,
    session_id: Uuid,
    token_id: Uuid,
    token_type: &'static str,
) -> Result<(), AppError> {
    let (actor_id, actor_session) = match actor {
        RevocationActor::Iam(access) => (
            Some(access.subject.id),
            Some(access.authentication_session_id),
        ),
        RevocationActor::Application(_) => (None, None),
    };
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "token.revoked",
            authentication_outcome: "success",
            audit_action: "token.revoke",
            audit_result: "success",
            outbox_event: "token.revoked",
            subject_id: Some(subject_id),
            actor_id,
            authentication_session_id: actor_session,
            aggregate_type: token_type,
            aggregate_id: token_id,
            aggregate_version: 1,
            failure_code: None,
            metadata: serde_json::json!({
                "authentication_session_id": session_id,
                "revoked_by_application_id": match actor {
                    RevocationActor::Application(client) => Some(client.application_id),
                    RevocationActor::Iam(_) => None,
                },
            }),
        },
    )
    .await
}

fn authorize_revocation(
    actor: &RevocationActor,
    subject_id: Uuid,
    client_application_id: Option<Uuid>,
    audience_application_id: Option<Uuid>,
) -> Result<(), AppError> {
    let authorized = match actor {
        RevocationActor::Iam(access) => {
            access.subject.id == subject_id
                && access.client_application_id.is_none()
                && access.audience == "silicon-iam"
                && access.scopes.iter().any(|scope| scope == "iam.self")
        }
        RevocationActor::Application(client) => {
            client_application_id == Some(client.application_id)
                || audience_application_id == Some(client.application_id)
        }
    };
    if authorized {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn revocation_request_digest(
    state: &ApiState,
    input: &RevocationInput,
    supplied: &SecretString,
    parsed: Option<&ParsedToken>,
) -> Result<[u8; 32], AppError> {
    let purpose = match parsed {
        Some(ParsedToken::Access(purpose) | ParsedToken::Refresh(purpose)) => *purpose,
        None => DigestPurpose::CarbonAccessToken,
    };
    let keyed = state
        .crypto
        .digest_secret(purpose, supplied)
        .map_err(|_| AppError::Internal {
            category: "token_revoke_request_digest",
        })?;
    let version = keyed.key_version().to_be_bytes();
    let encoded_hint =
        serde_json::to_vec(&input.token_type_hint).map_err(|_| AppError::Internal {
            category: "token_hint_encode",
        })?;
    Ok(idempotency::digest_parts(
        b"iam-token-revoke",
        &[
            &version,
            keyed.as_bytes(),
            &[u8::from(input.revoke_family)],
            &encoded_hint,
        ],
    ))
}

fn digest_candidates(
    state: &ApiState,
    purpose: DigestPurpose,
    supplied: &SecretString,
) -> Result<(Vec<i16>, Vec<Vec<u8>>), AppError> {
    let candidates = state
        .crypto
        .digest_secrets(purpose, supplied)
        .map_err(|_| AppError::Internal {
            category: "token_digest_candidates",
        })?;
    Ok((
        candidates.iter().map(SecretDigest::key_version).collect(),
        candidates
            .iter()
            .map(|digest| digest.as_bytes().to_vec())
            .collect(),
    ))
}

fn parse_token(token: &SecretString, hint: Option<TokenTypeHint>) -> Result<ParsedToken, ()> {
    let value = token.expose_secret();
    if value.len() != 47
        || !value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(());
    }
    let parsed = match value.get(..4) {
        Some("cat_") => ParsedToken::Access(DigestPurpose::CarbonAccessToken),
        Some("sat_") => ParsedToken::Access(DigestPurpose::SiliconAccessToken),
        Some("oat_") => ParsedToken::Access(DigestPurpose::ApplicationAccessToken),
        Some("svt_") => ParsedToken::Access(DigestPurpose::ServiceAccessToken),
        Some("rft_") => ParsedToken::Refresh(DigestPurpose::RefreshToken),
        Some("ort_") => ParsedToken::Refresh(DigestPurpose::OAuthRefreshToken),
        _ => return Err(()),
    };
    let hint_matches = match hint {
        None => true,
        Some(TokenTypeHint::AccessToken) => matches!(&parsed, ParsedToken::Access(_)),
        Some(TokenTypeHint::RefreshToken) => matches!(&parsed, ParsedToken::Refresh(_)),
    };
    if !hint_matches {
        return Err(());
    }
    Ok(parsed)
}

async fn set_application_context(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "SELECT set_config('iam.principal_id', $1, true), set_config('iam.application_id', $1, true)",
    )
    .bind(application_id.to_string())
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal { category: "token_application_context" })?;
    Ok(())
}

async fn public_organization_id(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Option<Uuid>,
) -> Result<Option<String>, AppError> {
    let Some(organization_id) = organization_id else {
        return Ok(None);
    };
    sqlx::query_scalar::<_, String>(
        "SELECT org_id FROM iam.organizations WHERE id = $1 AND status = 'active'",
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "token_organization_handle",
    })
}

async fn enforce_limit(
    state: &ApiState,
    name: &'static str,
    actor: &str,
    token: &str,
) -> Result<(), AppError> {
    let actor_scope = SecretString::from(actor.to_owned());
    let token_scope = SecretString::from(format!("{actor}:{token}"));
    let maximum = NonZeroU32::new(120).ok_or(AppError::Internal {
        category: "token_endpoint_rate_policy",
    })?;
    let window = Duration::from_mins(1);
    let policy = RateLimitPolicy::new(maximum, window, window).map_err(|_| AppError::Internal {
        category: "token_endpoint_rate_policy",
    })?;
    rate_limit::enforce(
        &state.pool,
        &state.crypto,
        "iam_token_endpoint_actor",
        &actor_scope,
        policy,
    )
    .await?;
    rate_limit::enforce(&state.pool, &state.crypto, name, &token_scope, policy).await?;
    Ok(())
}

fn validate_supplied_token(value: &str) -> Result<(), AppError> {
    if !(32..=4096).contains(&value.len()) || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(validation::validation(
            "token",
            "has an invalid length or format",
        ));
    }
    Ok(())
}

fn actor_scope(actor: &RevocationActor) -> String {
    match actor {
        RevocationActor::Iam(access) => {
            format!(
                "{}:{}",
                access.subject.actor_type.as_str(),
                access.subject.id
            )
        }
        RevocationActor::Application(client) => format!("application:{}", client.application_id),
    }
}

impl IntrospectionResponse {
    const fn inactive() -> Self {
        Self {
            active: false,
            principal_id: None,
            actor_type: None,
            client_id: None,
            org_id: None,
            membership_id: None,
            session_id: None,
            scope: None,
            audience: None,
            issued_at: None,
            expires_at: None,
            authorization_epoch: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{ParsedToken, TokenTypeHint, parse_token};

    #[test]
    fn token_class_and_hint_must_agree() {
        let access = SecretString::from(format!("cat_{}", "A".repeat(43)));
        assert!(matches!(
            parse_token(&access, None),
            Ok(ParsedToken::Access(_))
        ));
        assert!(parse_token(&access, Some(TokenTypeHint::RefreshToken)).is_err());
        let refresh = SecretString::from(format!("rft_{}", "A".repeat(43)));
        assert!(matches!(
            parse_token(&refresh, None),
            Ok(ParsedToken::Refresh(_))
        ));
    }
}
