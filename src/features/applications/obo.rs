#![allow(clippy::too_many_arguments, clippy::too_many_lines)]

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sha2::Digest as _;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::actor::{ActorRef, ActorType},
    infrastructure::{
        crypto::{DigestPurpose, SecretDigest, SecretKind},
        postgres::{
            context::{self, DatabaseContext},
            events::{self, AggregateVersion, AuditRecord, OutboxRecord},
            tokens,
        },
    },
};

use super::{
    error::ApiError,
    idempotency::{self, Claim},
    model::{OboAccessResult, OboExchangeRequest, OboProofResponse, OboVerifyRequest},
    security::ApplicationClient,
    validation,
};

const PROOF_LIFETIME_SECONDS: i64 = 60;

#[derive(FromRow)]
struct ExchangeAuthorityRow {
    audience_application_id: Uuid,
    audience_auth_epoch: i64,
    subject_auth_epoch: i64,
    membership_authz_epoch: i64,
}

#[derive(FromRow)]
struct ProofRow {
    id: Uuid,
    proof_digest: Vec<u8>,
    digest_key_version: i16,
    issuer_application_id: Uuid,
    issuer_app_id: String,
    subject_principal_id: Uuid,
    subject_kind: String,
    subject_public_id: String,
    organization_id: Uuid,
    membership_id: Uuid,
    parent_access_token_id: Uuid,
    action: String,
    resource_digest: Option<Vec<u8>>,
    resource_digest_key_version: Option<i16>,
    subject_auth_epoch: i64,
    membership_authz_epoch: i64,
    issuer_auth_epoch: i64,
    audience_auth_epoch: i64,
    expires_at: OffsetDateTime,
    consumed_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
}

#[derive(FromRow)]
struct CurrentProofContext {
    org_id: String,
    subject_auth_epoch: i64,
    membership_authz_epoch: i64,
    issuer_auth_epoch: i64,
    audience_auth_epoch: i64,
    parent_active: bool,
    delegation_active: bool,
    actor_authorized: bool,
}

pub(super) async fn exchange(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Json(input): Json<OboExchangeRequest>,
) -> Result<Response, ApiError> {
    validate_exchange(&input, &headers)?;
    let subject_token = SecretString::from(input.subject_token.clone());
    let access = match tokens::authenticate(&state.pool, &state.crypto, &subject_token).await {
        Ok(Some(access)) => access,
        Ok(None) | Err(tokens::AccessTokenError::InvalidFormat) => {
            return Err(ApiError::bad_request(
                "invalid_subject_token",
                "The subject token is invalid.",
            ));
        }
        Err(tokens::AccessTokenError::Crypto(_)) => {
            return Err(ApiError::internal("obo_subject_token_crypto"));
        }
        Err(tokens::AccessTokenError::Database(_)) => {
            return Err(ApiError::internal("obo_subject_token_database"));
        }
        Err(tokens::AccessTokenError::InvalidStoredActorKind) => {
            return Err(ApiError::internal("obo_subject_actor_kind"));
        }
    };
    if access.client_application_id != Some(client.application_id)
        || !access.scopes.iter().any(|scope| scope == "obo.issue")
    {
        return Err(ApiError::forbidden("obo_subject_token_forbidden"));
    }
    let organization_id = access
        .organization_id
        .ok_or_else(|| ApiError::forbidden("obo_organization_required"))?;
    let membership_id = access
        .membership_id
        .ok_or_else(|| ApiError::forbidden("obo_membership_required"))?;
    let canonical = serde_json::to_vec(&json!({
        "subject_token_id": access.token_id,
        "audience": input.audience,
        "action": input.action,
        "resource": input.resource,
        "org_id": input.org_id,
    }))
    .map_err(|_| ApiError::internal("obo_exchange_canonical"))?;
    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext {
            principal_id: Some(access.subject.id),
            organization_id: Some(organization_id),
            application_id: Some(client.application_id),
            signup_session_id: None,
        },
    )
    .await
    .map_err(|_| ApiError::internal("obo_exchange_context"))?;
    let caller_scope = format!("application:{}", client.application_id);
    let claim = idempotency::claim::<OboProofResponse>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/obo-access/exchanges",
        &canonical,
        true,
    )
    .await?;
    if let Claim::Replay { response, .. } = claim {
        if response.expires_at <= OffsetDateTime::now_utc() {
            return Err(ApiError::conflict("idempotency_response_expired"));
        }
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("obo_exchange_replay_commit"))?;
        return Ok(proof_response(response, true));
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("obo_exchange_idempotency"));
    };

    let authority = sqlx::query_as::<_, ExchangeAuthorityRow>(
        r"
        SELECT audience.id AS audience_application_id,
               audience_principal.auth_epoch AS audience_auth_epoch,
               subject_principal.auth_epoch AS subject_auth_epoch,
               membership.authz_epoch AS membership_authz_epoch
        FROM iam.applications AS audience
        JOIN iam.principals AS audience_principal
          ON audience_principal.id = audience.id
         AND audience_principal.kind = 'application'
         AND audience_principal.status = 'active'
        JOIN iam.organizations AS organization
          ON organization.id = $3
         AND organization.org_id = $4
         AND organization.status = 'active'
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = $5
         AND membership.principal_id = $6
         AND membership.principal_kind = $7::iam.principal_kind
         AND membership.status = 'active'
        JOIN iam.principals AS subject_principal
          ON subject_principal.id = membership.principal_id
         AND subject_principal.kind = membership.principal_kind
         AND subject_principal.status = 'active'
        WHERE audience.app_id = $1
          AND audience.review_status = 'verified'
          AND audience.deleted_at IS NULL
          AND EXISTS (
              SELECT 1
              FROM iam.obo_action_catalog AS action_catalog
              JOIN iam.obo_application_grants AS application_grant
                ON application_grant.audience_application_id = action_catalog.audience_application_id
               AND application_grant.action = action_catalog.action
               AND application_grant.status = 'active'
              WHERE action_catalog.audience_application_id = audience.id
                AND action_catalog.action = $2
                AND action_catalog.status = 'active'
                AND application_grant.issuer_application_id = $8
          )
          AND iam_private.has_organization_capability(organization.id, membership.principal_id, $2)
        ",
    )
    .bind(&input.audience)
    .bind(&input.action)
    .bind(organization_id)
    .bind(&input.org_id)
    .bind(membership_id)
    .bind(access.subject.id)
    .bind(access.subject.actor_type.as_str())
    .bind(client.application_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("obo_exchange_authority"))?
    .ok_or_else(|| ApiError::forbidden("obo_exchange_forbidden"))?;

    let resource_digest = digest_resource(&state, input.resource.as_deref())?;
    let proof_id = Uuid::now_v7();
    let raw_proof = state
        .crypto
        .generate_secret(SecretKind::OboProof)
        .map_err(|_| ApiError::internal("obo_proof_generate"))?;
    let proof_digest = state
        .crypto
        .digest_secret(DigestPurpose::OboProof, &raw_proof)
        .map_err(|_| ApiError::internal("obo_proof_digest"))?;
    let expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        r"
        INSERT INTO iam.obo_proofs (
            id, proof_digest, digest_key_version, proof_prefix,
            issuer_application_id, audience_application_id,
            subject_principal_id, subject_kind, organization_id, membership_id,
            parent_access_token_id, action, resource_digest,
            resource_digest_key_version, subject_auth_epoch,
            membership_authz_epoch, issuer_auth_epoch, audience_auth_epoch,
            expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8::iam.principal_kind, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18,
            transaction_timestamp() + ($19::bigint * interval '1 second')
        )
        RETURNING expires_at
        ",
    )
    .bind(proof_id)
    .bind(proof_digest.as_bytes().as_slice())
    .bind(proof_digest.key_version())
    .bind(secret_prefix(raw_proof.expose_secret()))
    .bind(client.application_id)
    .bind(authority.audience_application_id)
    .bind(access.subject.id)
    .bind(access.subject.actor_type.as_str())
    .bind(organization_id)
    .bind(membership_id)
    .bind(access.token_id)
    .bind(&input.action)
    .bind(
        resource_digest
            .as_ref()
            .map(|digest| digest.as_bytes().as_slice()),
    )
    .bind(resource_digest.as_ref().map(SecretDigest::key_version))
    .bind(authority.subject_auth_epoch)
    .bind(authority.membership_authz_epoch)
    .bind(client.auth_epoch)
    .bind(authority.audience_auth_epoch)
    .bind(PROOF_LIFETIME_SECONDS)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("obo_proof_insert"))?;
    let response = OboProofResponse {
        access_proof: raw_proof.expose_secret().to_owned(),
        proof_id,
        expires_in: u64::try_from(PROOF_LIFETIME_SECONDS).unwrap_or(60),
        expires_at,
    };
    record_protocol_event(
        &mut transaction,
        ActorRef {
            actor_type: ActorType::Application,
            id: client.application_id,
        },
        organization_id,
        client.application_id,
        proof_id,
        1,
        "obo.proof.issue",
        "obo.proof_issued",
        json!({
            "proof_id": proof_id,
            "issuer_application_id": client.application_id,
            "audience_application_id": authority.audience_application_id,
            "subject": access.subject,
            "action": input.action,
            "resource_bound": input.resource.is_some(),
            "expires_at": expires_at,
        }),
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        201,
        &response,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("obo_exchange_commit"))?;
    Ok(proof_response(response, false))
}

pub(super) async fn verify(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Json(input): Json<OboVerifyRequest>,
) -> Result<Response, ApiError> {
    validate_verify(&input, &headers, &client)?;
    let proof = SecretString::from(input.access_proof.clone());
    let lookup_digests = state
        .crypto
        .digest_secrets(DigestPurpose::OboProof, &proof)
        .map_err(|_| ApiError::internal("obo_verify_digest"))?;
    let versions = lookup_digests
        .iter()
        .map(SecretDigest::key_version)
        .collect::<Vec<_>>();
    let digest_bytes = lookup_digests
        .iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let canonical = serde_json::to_vec(&json!({
        "proof_digest": sha2::Sha256::digest(input.access_proof.as_bytes()).as_slice(),
        "audience": input.audience,
        "action": input.action,
        "resource": input.resource,
        "org_context": org_context(&headers)?,
    }))
    .map_err(|_| ApiError::internal("obo_verify_canonical"))?;
    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext::application(client.application_id, client.application_id),
    )
    .await
    .map_err(|_| ApiError::internal("obo_verify_context"))?;
    let caller_scope = format!("application:{}", client.application_id);
    let claim = idempotency::claim::<OboAccessResult>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/obo-access/verify",
        &canonical,
        false,
    )
    .await?;
    if let Claim::Replay { response, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("obo_verify_replay_commit"))?;
        return Ok(json_response(StatusCode::OK, response, true));
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("obo_verify_idempotency"));
    };
    let row = sqlx::query_as::<_, ProofRow>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT proof.id, proof.proof_digest, proof.digest_key_version,
               proof.issuer_application_id, issuer.app_id AS issuer_app_id,
               proof.subject_principal_id,
               proof.subject_kind::text AS subject_kind,
               COALESCE(carbon.carbon_id, silicon.global_silicon_id) AS subject_public_id,
               proof.organization_id,
               proof.membership_id, proof.parent_access_token_id, proof.action,
               proof.resource_digest, proof.resource_digest_key_version,
               proof.subject_auth_epoch, proof.membership_authz_epoch,
               proof.issuer_auth_epoch, proof.audience_auth_epoch,
               proof.expires_at, proof.consumed_at, proof.revoked_at
        FROM supplied_digest
        JOIN iam.obo_proofs AS proof
          ON proof.digest_key_version = supplied_digest.key_version
         AND proof.proof_digest = supplied_digest.digest
        JOIN iam.applications AS issuer ON issuer.id = proof.issuer_application_id
        LEFT JOIN iam.carbons AS carbon
          ON carbon.id = proof.subject_principal_id AND proof.subject_kind = 'carbon'
        LEFT JOIN iam.silicons AS silicon
          ON silicon.id = proof.subject_principal_id AND proof.subject_kind = 'silicon'
        WHERE proof.audience_application_id = $3
        FOR UPDATE OF proof
        ",
    )
    .bind(versions)
    .bind(digest_bytes)
    .bind(client.application_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("obo_verify_lookup"))?
    .ok_or_else(|| ApiError::gone("obo_proof_invalid"))?;
    let expected = SecretDigest::from_parts(row.digest_key_version, &row.proof_digest)
        .ok_or_else(|| ApiError::internal("obo_proof_shape"))?;
    if !state
        .crypto
        .verify_secret(DigestPurpose::OboProof, &proof, expected)
        .map_err(|_| ApiError::internal("obo_proof_verify"))?
    {
        return Err(ApiError::gone("obo_proof_invalid"));
    }
    if row.consumed_at.is_some() {
        return Err(ApiError::conflict("obo_proof_consumed"));
    }
    if row.revoked_at.is_some() || row.expires_at <= OffsetDateTime::now_utc() {
        return Err(ApiError::gone("obo_proof_expired"));
    }
    if row.action != input.action || !resource_matches(&state, &row, input.resource.as_deref())? {
        return Err(ApiError::forbidden("obo_constraints_mismatch"));
    }

    install_subject_context(
        &mut transaction,
        row.subject_principal_id,
        row.organization_id,
        client.application_id,
    )
    .await?;
    let current = load_current_context(&mut transaction, &row, client.application_id).await?;
    if let Some(header_org_id) = org_context(&headers)?
        && header_org_id != current.org_id
    {
        return Err(ApiError::forbidden("obo_organization_mismatch"));
    }
    if current.subject_auth_epoch != row.subject_auth_epoch
        || current.membership_authz_epoch != row.membership_authz_epoch
        || current.issuer_auth_epoch != row.issuer_auth_epoch
        || current.audience_auth_epoch != row.audience_auth_epoch
        || !current.parent_active
    {
        return Err(ApiError::gone("obo_proof_revoked"));
    }
    if !current.delegation_active || !current.actor_authorized {
        return Err(ApiError::forbidden("obo_authority_revoked"));
    }
    let consumed_at = sqlx::query_scalar::<_, OffsetDateTime>(
        r"
        UPDATE iam.obo_proofs
        SET consumed_at = transaction_timestamp(), consumed_by_application_id = $2
        WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
          AND expires_at > transaction_timestamp()
        RETURNING consumed_at
        ",
    )
    .bind(row.id)
    .bind(client.application_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("obo_consume"))?
    .ok_or_else(|| ApiError::conflict("obo_proof_consumed"))?;
    let actor_type = actor_type(&row.subject_kind)?;
    let response = OboAccessResult {
        valid: true,
        proof_id: row.id,
        issuer_app_id: row.issuer_app_id,
        audience: client.app_id.clone(),
        actor: super::model::PublicActor {
            principal_id: row.subject_principal_id,
            actor_type: actor_type.as_str().to_owned(),
            public_id: row.subject_public_id,
        },
        org_id: current.org_id,
        action: row.action,
        resource: input.resource,
        expires_at: row.expires_at,
        consumed_at,
    };
    record_protocol_event(
        &mut transaction,
        ActorRef {
            actor_type: ActorType::Application,
            id: client.application_id,
        },
        row.organization_id,
        client.application_id,
        row.id,
        2,
        "obo.proof.consume",
        "obo.proof_consumed",
        json!({
            "proof_id": row.id,
            "issuer_application_id": row.issuer_application_id,
            "audience_application_id": client.application_id,
            "subject": response.actor,
            "action": response.action,
            "resource_bound": response.resource.is_some(),
        }),
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        200,
        &response,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("obo_verify_commit"))?;
    Ok(json_response(StatusCode::OK, response, false))
}

fn validate_exchange(input: &OboExchangeRequest, headers: &HeaderMap) -> Result<(), ApiError> {
    validation::app_id(&input.audience)?;
    validation::action(&input.action)?;
    validation::resource(input.resource.as_deref())?;
    validation::org_id(&input.org_id)?;
    if !(32..=4_096).contains(&input.subject_token.len()) {
        return Err(ApiError::validation(
            "subject_token",
            "must contain 32 to 4096 characters",
        ));
    }
    if let Some(header_org_id) = org_context(headers)?
        && header_org_id != input.org_id
    {
        return Err(ApiError::bad_request(
            "organization_context_mismatch",
            "X-Org-ID must match org_id.",
        ));
    }
    Ok(())
}

fn validate_verify(
    input: &OboVerifyRequest,
    headers: &HeaderMap,
    client: &ApplicationClient,
) -> Result<(), ApiError> {
    validation::app_id(&input.audience)?;
    validation::action(&input.action)?;
    validation::resource(input.resource.as_deref())?;
    if input.audience != client.app_id {
        return Err(ApiError::forbidden("obo_audience_mismatch"));
    }
    if input.access_proof.len() != 47 || !input.access_proof.starts_with("obo_") {
        return Err(ApiError::bad_request(
            "invalid_proof",
            "The access proof is malformed.",
        ));
    }
    if let Some(org_id) = org_context(headers)? {
        validation::org_id(&org_id)?;
    }
    Ok(())
}

fn org_context(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    headers
        .get("x-org-id")
        .map(|value| {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .map_err(|_| ApiError::validation("X-Org-ID", "must be valid ASCII"))
        })
        .transpose()
}

fn digest_resource(
    state: &ApiState,
    resource: Option<&str>,
) -> Result<Option<SecretDigest>, ApiError> {
    resource
        .map(|resource| {
            state
                .crypto
                .digest_secret(
                    DigestPurpose::OboResource,
                    &SecretString::from(resource.to_owned()),
                )
                .map_err(|_| ApiError::internal("obo_resource_digest"))
        })
        .transpose()
}

fn resource_matches(
    state: &ApiState,
    row: &ProofRow,
    supplied: Option<&str>,
) -> Result<bool, ApiError> {
    match (
        supplied,
        row.resource_digest.as_deref(),
        row.resource_digest_key_version,
    ) {
        (None, None, None) => Ok(true),
        (Some(supplied), Some(stored), Some(key_version)) => {
            let expected = SecretDigest::from_parts(key_version, stored)
                .ok_or_else(|| ApiError::internal("obo_resource_shape"))?;
            state
                .crypto
                .verify_secret(
                    DigestPurpose::OboResource,
                    &SecretString::from(supplied.to_owned()),
                    expected,
                )
                .map_err(|_| ApiError::internal("obo_resource_verify"))
        }
        _ => Ok(false),
    }
}

async fn install_subject_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    subject_id: Uuid,
    organization_id: Uuid,
    application_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        r"
        SELECT set_config('iam.principal_id', $1, true),
               set_config('iam.organization_id', $2, true),
               set_config('iam.application_id', $3, true)
        ",
    )
    .bind(subject_id.to_string())
    .bind(organization_id.to_string())
    .bind(application_id.to_string())
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("obo_subject_context"))?;
    Ok(())
}

async fn load_current_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    proof: &ProofRow,
    audience_application_id: Uuid,
) -> Result<CurrentProofContext, ApiError> {
    sqlx::query_as::<_, CurrentProofContext>(
        r"
        SELECT organization.org_id,
               subject.auth_epoch AS subject_auth_epoch,
               membership.authz_epoch AS membership_authz_epoch,
               issuer.auth_epoch AS issuer_auth_epoch,
               audience.auth_epoch AS audience_auth_epoch,
               EXISTS (
                   SELECT 1
                   FROM iam.access_tokens AS parent
                   JOIN iam.authentication_sessions AS session
                     ON session.id = parent.authentication_session_id
                    AND session.status = 'active'
                    AND session.idle_expires_at > transaction_timestamp()
                    AND session.absolute_expires_at > transaction_timestamp()
                   WHERE parent.id = $6
                     AND parent.client_application_id = $4
                     AND parent.subject_principal_id = $1
                     AND parent.organization_id = $2
                     AND parent.membership_id = $3
                     AND parent.revoked_at IS NULL
                     AND parent.expires_at > transaction_timestamp()
                     AND EXISTS (
                         SELECT 1 FROM iam.access_token_scopes AS token_scope
                         WHERE token_scope.access_token_id = parent.id
                           AND token_scope.scope = 'obo.issue'
                     )
               ) AS parent_active,
               EXISTS (
                   SELECT 1
                   FROM iam.obo_action_catalog AS action_catalog
                   JOIN iam.obo_application_grants AS application_grant
                     ON application_grant.audience_application_id = action_catalog.audience_application_id
                    AND application_grant.action = action_catalog.action
                    AND application_grant.status = 'active'
                   WHERE action_catalog.audience_application_id = $5
                     AND action_catalog.action = $7
                     AND action_catalog.status = 'active'
                     AND application_grant.issuer_application_id = $4
               ) AS delegation_active,
               iam_private.has_organization_capability($2, $1, $7) AS actor_authorized
        FROM iam.organizations AS organization
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = $3
         AND membership.principal_id = $1
         AND membership.principal_kind = $8::iam.principal_kind
         AND membership.status = 'active'
        JOIN iam.principals AS subject
          ON subject.id = membership.principal_id
         AND subject.kind = membership.principal_kind
         AND subject.status = 'active'
        JOIN iam.applications AS issuer_application
          ON issuer_application.id = $4
         AND issuer_application.review_status = 'verified'
         AND issuer_application.deleted_at IS NULL
        JOIN iam.principals AS issuer
          ON issuer.id = issuer_application.id
         AND issuer.kind = 'application'
         AND issuer.status = 'active'
        JOIN iam.applications AS audience_application
          ON audience_application.id = $5
         AND audience_application.review_status = 'verified'
         AND audience_application.deleted_at IS NULL
        JOIN iam.principals AS audience
          ON audience.id = audience_application.id
         AND audience.kind = 'application'
         AND audience.status = 'active'
        WHERE organization.id = $2 AND organization.status = 'active'
        ",
    )
    .bind(proof.subject_principal_id)
    .bind(proof.organization_id)
    .bind(proof.membership_id)
    .bind(proof.issuer_application_id)
    .bind(audience_application_id)
    .bind(proof.parent_access_token_id)
    .bind(&proof.action)
    .bind(&proof.subject_kind)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("obo_current_context"))?
    .ok_or_else(|| ApiError::gone("obo_proof_revoked"))
}

async fn record_protocol_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: ActorRef,
    organization_id: Uuid,
    application_id: Uuid,
    proof_id: Uuid,
    version: i64,
    action: &'static str,
    event_type: &'static str,
    metadata: Value,
) -> Result<(), ApiError> {
    let aggregate = AggregateVersion {
        aggregate_type: "obo_proof",
        aggregate_id: proof_id,
        version,
    };
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(actor),
            authentication_session_id: None,
            organization_id: Some(organization_id),
            application_id: Some(application_id),
            action,
            target_type: "obo_proof",
            target_id: Some(proof_id),
            authentication_method: Some("application_secret"),
            aggregate: Some(aggregate),
            before_state: None,
            after_state: Some(
                json!({ "status": if version == 1 { "active" } else { "consumed" } }),
            ),
            metadata: metadata.clone(),
        },
    )
    .await
    .map_err(|_| ApiError::internal("obo_audit"))?;
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: Some(organization_id),
            aggregate,
            event_ordinal: 1,
            event_type,
            schema_version: 1,
            payload: metadata,
        },
    )
    .await
    .map_err(|_| ApiError::internal("obo_outbox"))?;
    Ok(())
}

fn actor_type(value: &str) -> Result<ActorType, ApiError> {
    match value {
        "carbon" => Ok(ActorType::Carbon),
        "silicon" => Ok(ActorType::Silicon),
        _ => Err(ApiError::internal("obo_subject_kind")),
    }
}

fn proof_response(response: OboProofResponse, replayed: bool) -> Response {
    let mut response = (StatusCode::CREATED, Json(response)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    response
}

fn json_response<T: serde::Serialize>(status: StatusCode, response: T, replayed: bool) -> Response {
    let mut response = (status, Json(response)).into_response();
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    response
}

fn secret_prefix(secret: &str) -> String {
    secret.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::secret_prefix;

    #[test]
    fn proofs_disclose_only_the_wire_prefix_in_storage() {
        let proof = format!("obo_{}", "A".repeat(43));
        assert_eq!(secret_prefix(&proof), "obo_AAAAAAAA");
    }
}
