#![allow(clippy::too_many_arguments, clippy::too_many_lines)]

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use hmac::{Hmac, Mac as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::FromRow;
use subtle::ConstantTimeEq as _;
use time::{Duration, OffsetDateTime};
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
    model::{
        AppPath, ApplicationOboEndpoint, OboAccessResult, OboEndpointReference, OboExchangeRequest,
        OboProofResponse, OboVerifyRequest,
    },
    security::ApplicationClient,
    validation,
};

const PROOF_LIFETIME_SECONDS: i64 = 60;
const SIGNATURE_TOLERANCE_SECONDS: u64 = 60;
const TIMESTAMP_HEADER: &str = "x-obo-timestamp";
const SIGNATURE_HEADER: &str = "x-obo-signature";

type HmacSha256 = Hmac<Sha256>;

#[derive(FromRow)]
struct ExchangeAuthorityRow {
    audience_application_id: Uuid,
    endpoint_path: String,
    metadata_definition: sqlx::types::Json<Value>,
    endpoint_version: i64,
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
    endpoint_id: String,
    request_method: String,
    request_path: String,
    request_body_sha256: Vec<u8>,
    endpoint_version: i64,
    request_metadata: sqlx::types::Json<Value>,
    subject_auth_epoch: i64,
    membership_authz_epoch: i64,
    issuer_auth_epoch: i64,
    audience_auth_epoch: i64,
    expires_at: OffsetDateTime,
    checked_at: OffsetDateTime,
    consumed_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
}

struct SignedExchange {
    timestamp: String,
    signed_at: OffsetDateTime,
    signature: [u8; 32],
    idempotency_key: String,
}

struct CanonicalRequest {
    method: String,
    body_sha256: [u8; 32],
    body_sha256_hex: String,
}

#[derive(Serialize)]
pub(super) struct OboEndpointCatalog {
    application: OboApplicationReference,
    endpoints: Vec<ApplicationOboEndpoint>,
}

#[derive(Serialize)]
struct OboApplicationReference {
    app_id: String,
    org_id: String,
}

#[derive(FromRow)]
struct CurrentProofContext {
    org_id: String,
    subject_auth_epoch: i64,
    membership_authz_epoch: i64,
    issuer_auth_epoch: i64,
    audience_auth_epoch: i64,
    parent_active: bool,
    endpoint_active: bool,
}

pub(super) async fn discover_endpoints(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Path(path): Path<AppPath>,
) -> Result<Json<OboEndpointCatalog>, ApiError> {
    reject_organization_header(&headers)?;
    validation::app_id(&path.app_id)?;
    let mut transaction = context::begin(
        state.db(),
        DatabaseContext {
            principal_id: Some(client.application_id),
            organization_id: Some(client.organization_id),
            application_id: Some(client.application_id),
            signup_session_id: None,
        },
    )
    .await
    .map_err(|_| ApiError::internal("obo_discovery_context"))?;
    let target = sqlx::query_as::<_, (Uuid, String, String)>(
        r"
        SELECT application.id, application.app_id, organization.org_id
        FROM iam.applications AS application
        JOIN LATERAL iam_private.resolve_authorized_application_organization(
            application.id
        ) AS organization ON TRUE
        JOIN iam.principals AS principal
          ON principal.id = application.id
         AND principal.kind = 'application'
         AND principal.status = 'active'
        WHERE application.app_id = $1
          AND application.organization_id = $2
          AND application.review_status = 'verified'
          AND application.deleted_at IS NULL
        ",
    )
    .bind(&path.app_id)
    .bind(client.organization_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("obo_discovery_application"))?
    .ok_or_else(ApiError::not_found)?;
    let endpoints = sqlx::query_as::<_, ApplicationOboEndpoint>(
        r"
        SELECT endpoint_id, path, metadata_definition AS metadata
        FROM iam.application_obo_endpoints
        WHERE organization_id = $1
          AND application_id = $2
          AND status = 'active'
        ORDER BY endpoint_id
        LIMIT 51
        ",
    )
    .bind(client.organization_id)
    .bind(target.0)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("obo_discovery_endpoints"))?;
    if endpoints.len() > 50 {
        return Err(ApiError::internal("obo_discovery_endpoint_limit"));
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("obo_discovery_commit"))?;
    Ok(Json(OboEndpointCatalog {
        application: OboApplicationReference {
            app_id: target.1,
            org_id: target.2,
        },
        endpoints,
    }))
}

pub(super) async fn exchange(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Json(input): Json<OboExchangeRequest>,
) -> Result<Response, ApiError> {
    reject_organization_header(&headers)?;
    validate_exchange(&input)?;
    let request = canonical_request(&input.request.method, &input.request.body_sha256)?;
    let canonical = exchange_canonical(&input)?;
    let mut transaction = context::begin(
        state.db(),
        DatabaseContext {
            principal_id: Some(client.application_id),
            organization_id: Some(client.organization_id),
            application_id: Some(client.application_id),
            signup_session_id: None,
        },
    )
    .await
    .map_err(|_| ApiError::internal("obo_exchange_context"))?;
    let transaction_now = sqlx::query_scalar::<_, OffsetDateTime>("SELECT transaction_timestamp()")
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("obo_exchange_time"))?;
    let signed = signed_exchange(&headers, transaction_now)?;

    let subject_token = SecretString::from(input.subject_token.clone());
    let access = match tokens::authenticate(state.db(), &state.crypto, &subject_token).await {
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
    if organization_id != client.organization_id {
        return Err(ApiError::forbidden("obo_organization_mismatch"));
    }
    let membership_id = access
        .membership_id
        .ok_or_else(|| ApiError::forbidden("obo_membership_required"))?;
    install_subject_context(
        &mut transaction,
        access.subject.id,
        organization_id,
        client.application_id,
    )
    .await?;

    let authority = sqlx::query_as::<_, ExchangeAuthorityRow>(
        r"
        WITH wall_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS value
        )
        SELECT audience.id AS audience_application_id,
               endpoint.path AS endpoint_path,
               endpoint.metadata_definition,
               endpoint.version AS endpoint_version,
               audience_principal.auth_epoch AS audience_auth_epoch,
               subject_principal.auth_epoch AS subject_auth_epoch,
               membership.authz_epoch AS membership_authz_epoch
        FROM wall_clock
        JOIN iam.applications AS audience ON TRUE
        JOIN iam.principals AS audience_principal
          ON audience_principal.id = audience.id
         AND audience_principal.kind = 'application'
         AND audience_principal.status = 'active'
        JOIN iam.organizations AS organization
          ON organization.id = $3
         AND organization.status = 'active'
        JOIN iam.applications AS issuer
          ON issuer.id = $7
         AND issuer.organization_id = organization.id
         AND issuer.review_status = 'verified'
         AND issuer.deleted_at IS NULL
        JOIN iam.principals AS issuer_principal
          ON issuer_principal.id = issuer.id
         AND issuer_principal.kind = 'application'
         AND issuer_principal.status = 'active'
         AND issuer_principal.auth_epoch = $8
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = $4
         AND membership.principal_id = $5
         AND membership.principal_kind = $6::iam.principal_kind
         AND membership.status = 'active'
        JOIN iam.principals AS subject_principal
          ON subject_principal.id = membership.principal_id
         AND subject_principal.kind = membership.principal_kind
         AND subject_principal.status = 'active'
        JOIN iam.access_tokens AS parent
          ON parent.id = $9
         AND parent.token_class = 'application_access'
         AND parent.client_application_id = issuer.id
         AND parent.audience_application_id = issuer.id
         AND parent.subject_principal_id = subject_principal.id
         AND parent.subject_kind = subject_principal.kind
         AND parent.organization_id = organization.id
         AND parent.membership_id = membership.id
         AND parent.subject_auth_epoch = subject_principal.auth_epoch
         AND parent.membership_authz_epoch = membership.authz_epoch
         AND parent.client_auth_epoch = issuer_principal.auth_epoch
         AND parent.revoked_at IS NULL
         AND parent.expires_at > wall_clock.value
        JOIN iam.authentication_sessions AS session
          ON session.id = parent.authentication_session_id
         AND session.subject_principal_id = subject_principal.id
         AND session.subject_kind = subject_principal.kind
         AND session.subject_auth_epoch = subject_principal.auth_epoch
         AND session.status = 'active'
         AND session.idle_expires_at > wall_clock.value
         AND session.absolute_expires_at > wall_clock.value
        JOIN iam.access_token_scopes AS parent_scope
          ON parent_scope.access_token_id = parent.id
         AND parent_scope.scope = 'obo.issue'
        JOIN iam.application_obo_endpoints AS endpoint
          ON endpoint.organization_id = organization.id
         AND endpoint.application_id = audience.id
         AND endpoint.endpoint_id = $2
         AND endpoint.status = 'active'
        WHERE audience.app_id = $1
          AND audience.organization_id = organization.id
          AND audience.review_status = 'verified'
          AND audience.deleted_at IS NULL
        FOR SHARE OF issuer, issuer_principal, audience, audience_principal,
                     organization, membership, subject_principal, parent,
                     session, parent_scope, endpoint
        ",
    )
    .bind(&input.audience)
    .bind(&input.endpoint_id)
    .bind(organization_id)
    .bind(membership_id)
    .bind(access.subject.id)
    .bind(access.subject.actor_type.as_str())
    .bind(client.application_id)
    .bind(client.auth_epoch)
    .bind(access.token_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("obo_exchange_authority"))?
    .ok_or_else(ApiError::not_found)?;
    verify_exchange_signature(&client, &signed, &request, &authority.endpoint_path)?;
    validation::obo_request_metadata(&authority.metadata_definition.0, &input.metadata)?;

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
    if let Claim::Replay { status, response } = claim {
        if !exchange_replay_is_live(
            &mut transaction,
            response.proof_id,
            client.application_id,
            client.organization_id,
        )
        .await?
        {
            return Err(ApiError::conflict("idempotency_response_expired"));
        }
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("obo_exchange_replay_commit"))?;
        let status = StatusCode::from_u16(status)
            .map_err(|_| ApiError::internal("obo_exchange_replay_status"))?;
        return Ok(proof_response(status, response, true));
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("obo_exchange_idempotency"));
    };

    let issuance_now = sqlx::query_scalar::<_, OffsetDateTime>("SELECT clock_timestamp()")
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("obo_proof_issuance_time"))?;
    ensure_signature_fresh(signed.signed_at, issuance_now)?;

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
            parent_access_token_id, endpoint_id, request_metadata, endpoint_version,
            request_method, request_path, request_body_sha256, request_signed_at,
            subject_auth_epoch,
            membership_authz_epoch, issuer_auth_epoch, audience_auth_epoch,
            created_at, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8::iam.principal_kind, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18,
            $19, $20, $21, $22,
            $23, $23 + ($24::bigint * interval '1 second')
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
    .bind(&input.endpoint_id)
    .bind(sqlx::types::Json(&input.metadata))
    .bind(authority.endpoint_version)
    .bind(&request.method)
    .bind(&authority.endpoint_path)
    .bind(request.body_sha256.as_slice())
    .bind(signed.signed_at)
    .bind(authority.subject_auth_epoch)
    .bind(authority.membership_authz_epoch)
    .bind(client.auth_epoch)
    .bind(authority.audience_auth_epoch)
    .bind(issuance_now)
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
            "endpoint_id": input.endpoint_id,
            "endpoint_path": &authority.endpoint_path,
            "metadata_bound": true,
            "request": {
                "method": &request.method,
                "path": &authority.endpoint_path,
                "body_sha256": &request.body_sha256_hex,
            },
            "expires_at": expires_at,
        }),
    )
    .await?;
    idempotency::complete_no_later_than(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        201,
        &response,
        true,
        expires_at,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("obo_exchange_commit"))?;
    Ok(proof_response(StatusCode::CREATED, response, false))
}

pub(super) async fn verify(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Json(input): Json<OboVerifyRequest>,
) -> Result<Response, ApiError> {
    reject_organization_header(&headers)?;
    validate_verify(&input)?;
    let request = canonical_request(&input.request.method, &input.request.body_sha256)?;
    if !valid_request_path(&input.request.path) {
        return Err(ApiError::validation(
            "request.path",
            "must be a valid absolute endpoint path",
        ));
    }
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
    let mut transaction = context::begin(
        state.db(),
        DatabaseContext {
            principal_id: Some(client.application_id),
            organization_id: Some(client.organization_id),
            application_id: Some(client.application_id),
            signup_session_id: None,
        },
    )
    .await
    .map_err(|_| ApiError::internal("obo_verify_context"))?;
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
               proof.membership_id, proof.parent_access_token_id, proof.endpoint_id,
               proof.request_method, proof.request_path, proof.request_body_sha256,
               proof.endpoint_version, proof.request_metadata,
               proof.subject_auth_epoch, proof.membership_authz_epoch,
               proof.issuer_auth_epoch, proof.audience_auth_epoch,
               proof.expires_at, clock_timestamp() AS checked_at,
               proof.consumed_at, proof.revoked_at
        FROM supplied_digest
        JOIN iam.obo_proofs AS proof
          ON proof.digest_key_version = supplied_digest.key_version
         AND proof.proof_digest = supplied_digest.digest
        JOIN iam.applications AS issuer
          ON issuer.organization_id = proof.organization_id
         AND issuer.id = proof.issuer_application_id
        JOIN iam.application_obo_endpoints AS endpoint
          ON endpoint.organization_id = proof.organization_id
         AND endpoint.application_id = proof.audience_application_id
         AND endpoint.endpoint_id = proof.endpoint_id
         AND endpoint.path = proof.request_path
        LEFT JOIN iam.carbons AS carbon
          ON carbon.id = proof.subject_principal_id AND proof.subject_kind = 'carbon'
        LEFT JOIN iam.silicons AS silicon
          ON silicon.id = proof.subject_principal_id AND proof.subject_kind = 'silicon'
        WHERE proof.audience_application_id = $3
          AND proof.organization_id = $4
        FOR UPDATE OF proof
        ",
    )
    .bind(versions)
    .bind(digest_bytes)
    .bind(client.application_id)
    .bind(client.organization_id)
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
    if row.revoked_at.is_some() || row.expires_at <= row.checked_at {
        return Err(ApiError::gone("obo_proof_expired"));
    }
    if !request_binding_matches(
        &row.request_method,
        &row.request_path,
        &row.request_body_sha256,
        &request,
        &input.request.path,
    ) {
        return Err(ApiError::forbidden("obo_request_binding_mismatch"));
    }
    install_subject_context(
        &mut transaction,
        row.subject_principal_id,
        row.organization_id,
        client.application_id,
    )
    .await?;
    let current = load_current_context(&mut transaction, &row, client.application_id).await?;
    if current.subject_auth_epoch != row.subject_auth_epoch
        || current.membership_authz_epoch != row.membership_authz_epoch
        || current.issuer_auth_epoch != row.issuer_auth_epoch
        || current.audience_auth_epoch != row.audience_auth_epoch
        || !current.parent_active
    {
        return Err(ApiError::gone("obo_proof_revoked"));
    }
    if !current.endpoint_active {
        return Err(ApiError::forbidden("obo_authority_revoked"));
    }
    let consumed_at = sqlx::query_scalar::<_, OffsetDateTime>(
        r"
        WITH wall_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS value
        )
        UPDATE iam.obo_proofs
        SET consumed_at = wall_clock.value, consumed_by_application_id = $2
        FROM wall_clock
        WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
          AND expires_at > wall_clock.value
        RETURNING consumed_at
        ",
    )
    .bind(row.id)
    .bind(client.application_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("obo_consume"))?
    .ok_or_else(|| ApiError::gone("obo_proof_expired"))?;
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
        endpoint: OboEndpointReference {
            endpoint_id: row.endpoint_id,
            path: row.request_path,
        },
        metadata: row.request_metadata.0,
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
            "endpoint_id": response.endpoint.endpoint_id,
            "endpoint_path": response.endpoint.path,
            "metadata_bound": true,
            "request": {
                "method": request.method,
                "path": response.endpoint.path,
                "body_sha256": request.body_sha256_hex,
            },
        }),
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("obo_verify_commit"))?;
    Ok(json_response(StatusCode::OK, response))
}

fn signed_exchange(headers: &HeaderMap, now: OffsetDateTime) -> Result<SignedExchange, ApiError> {
    let timestamp = exactly_one_header(headers, TIMESTAMP_HEADER)?;
    if timestamp.is_empty()
        || timestamp.len() > 20
        || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
        || (timestamp.len() > 1 && timestamp.starts_with('0'))
    {
        return Err(ApiError::invalid_client());
    }
    let timestamp_seconds = timestamp
        .parse::<i64>()
        .map_err(|_| ApiError::invalid_client())?;
    let signed_at = OffsetDateTime::from_unix_timestamp(timestamp_seconds)
        .map_err(|_| ApiError::invalid_client())?;
    ensure_signature_fresh(signed_at, now)?;
    let signature_hex = exactly_one_header(headers, SIGNATURE_HEADER)?;
    if signature_hex.len() != 64
        || !signature_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ApiError::invalid_client());
    }
    let mut signature = [0_u8; 32];
    hex::decode_to_slice(signature_hex, &mut signature).map_err(|_| ApiError::invalid_client())?;
    Ok(SignedExchange {
        timestamp: timestamp.to_owned(),
        signed_at,
        signature,
        idempotency_key: idempotency::required_key(headers)?.to_owned(),
    })
}

fn ensure_signature_fresh(signed_at: OffsetDateTime, now: OffsetDateTime) -> Result<(), ApiError> {
    let tolerance = Duration::seconds(
        i64::try_from(SIGNATURE_TOLERANCE_SECONDS)
            .map_err(|_| ApiError::internal("obo_signature_tolerance"))?,
    );
    if signed_at < now - tolerance || signed_at > now + tolerance {
        return Err(ApiError::invalid_client());
    }
    Ok(())
}

fn exactly_one_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, ApiError> {
    let mut values = headers.get_all(name).iter();
    let precondition = match name {
        TIMESTAMP_HEADER => "X-OBO-Timestamp",
        SIGNATURE_HEADER => "X-OBO-Signature",
        _ => name,
    };
    let value = values
        .next()
        .ok_or_else(|| ApiError::precondition_required(precondition))?
        .to_str()
        .map_err(|_| ApiError::invalid_client())?;
    if values.next().is_some() {
        return Err(ApiError::invalid_client());
    }
    Ok(value)
}

fn reject_organization_header(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.contains_key("x-org-id") {
        return Err(ApiError::bad_request(
            "unsupported_header",
            "X-Org-ID is not accepted for OBO operations.",
        ));
    }
    Ok(())
}

fn canonical_request(method: &str, body_sha256: &str) -> Result<CanonicalRequest, ApiError> {
    if method.is_empty()
        || method.len() > 32
        || !method.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_uppercase()
                || (index > 0
                    && (byte.is_ascii_digit()
                        || matches!(
                            byte,
                            b'!' | b'#'
                                | b'$'
                                | b'%'
                                | b'&'
                                | b'\''
                                | b'*'
                                | b'+'
                                | b'-'
                                | b'.'
                                | b'^'
                                | b'_'
                                | b'`'
                                | b'|'
                                | b'~'
                        )))
        })
    {
        return Err(ApiError::validation(
            "request.method",
            "must be a canonical uppercase HTTP method containing at most 32 characters",
        ));
    }
    if body_sha256.len() != 64
        || !body_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ApiError::validation(
            "request.body_sha256",
            "must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(body_sha256, &mut digest).map_err(|_| {
        ApiError::validation(
            "request.body_sha256",
            "must be exactly 64 lowercase hexadecimal characters",
        )
    })?;
    Ok(CanonicalRequest {
        method: method.to_owned(),
        body_sha256: digest,
        body_sha256_hex: body_sha256.to_owned(),
    })
}

fn verify_exchange_signature(
    client: &ApplicationClient,
    signed: &SignedExchange,
    request: &CanonicalRequest,
    endpoint_path: &str,
) -> Result<(), ApiError> {
    let canonical = format!(
        "{}.{}.{}.{}.{}",
        signed.timestamp,
        request.method,
        endpoint_path,
        request.body_sha256_hex,
        signed.idempotency_key
    );
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(
        client.authenticated_secret.expose_secret().as_bytes(),
    )
    .map_err(|_| ApiError::internal("obo_signature_hmac"))?;
    mac.update(canonical.as_bytes());
    mac.verify_slice(&signed.signature)
        .map_err(|_| ApiError::invalid_client())
}

fn valid_request_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 2_048
        && path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains(['?', '#'])
        && !path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn request_binding_matches(
    stored_method: &str,
    stored_path: &str,
    stored_body_sha256: &[u8],
    request: &CanonicalRequest,
    request_path: &str,
) -> bool {
    stored_method == request.method
        && stored_path == request_path
        && bool::from(stored_body_sha256.ct_eq(request.body_sha256.as_slice()))
}

fn validate_exchange(input: &OboExchangeRequest) -> Result<(), ApiError> {
    validation::app_id(&input.audience)?;
    validation::obo_endpoint_id(&input.endpoint_id)?;
    validation::obo_metadata("metadata", &input.metadata)?;
    if !(32..=4_096).contains(&input.subject_token.len()) {
        return Err(ApiError::validation(
            "subject_token",
            "must contain 32 to 4096 characters",
        ));
    }
    Ok(())
}

fn exchange_canonical(input: &OboExchangeRequest) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec(input).map_err(|_| ApiError::internal("obo_exchange_canonical"))
}

fn validate_verify(input: &OboVerifyRequest) -> Result<(), ApiError> {
    if input.access_proof.len() != 47
        || !input.access_proof.starts_with("obo_")
        || input.access_proof[4..]
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    {
        return Err(ApiError::bad_request(
            "invalid_proof",
            "The access proof is malformed.",
        ));
    }
    Ok(())
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

async fn exchange_replay_is_live(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    proof_id: Uuid,
    issuer_application_id: Uuid,
    organization_id: Uuid,
) -> Result<bool, ApiError> {
    sqlx::query_scalar::<_, bool>(
        r"
        WITH wall_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS value
        )
        SELECT EXISTS (
            SELECT 1
            FROM wall_clock
            JOIN iam.obo_proofs AS proof ON TRUE
            JOIN iam.applications AS issuer_application
              ON issuer_application.organization_id = proof.organization_id
             AND issuer_application.id = proof.issuer_application_id
             AND issuer_application.review_status = 'verified'
             AND issuer_application.deleted_at IS NULL
            JOIN iam.principals AS issuer
              ON issuer.id = issuer_application.id
             AND issuer.kind = 'application'
             AND issuer.status = 'active'
             AND issuer.auth_epoch = proof.issuer_auth_epoch
            JOIN iam.applications AS audience_application
              ON audience_application.organization_id = proof.organization_id
             AND audience_application.id = proof.audience_application_id
             AND audience_application.review_status = 'verified'
             AND audience_application.deleted_at IS NULL
            JOIN iam.principals AS audience
              ON audience.id = audience_application.id
             AND audience.kind = 'application'
             AND audience.status = 'active'
             AND audience.auth_epoch = proof.audience_auth_epoch
            JOIN iam.principals AS subject
              ON subject.id = proof.subject_principal_id
             AND subject.kind = proof.subject_kind
             AND subject.status = 'active'
             AND subject.auth_epoch = proof.subject_auth_epoch
            JOIN iam.organization_memberships AS membership
              ON membership.organization_id = proof.organization_id
             AND membership.id = proof.membership_id
             AND membership.principal_id = proof.subject_principal_id
             AND membership.principal_kind = proof.subject_kind
             AND membership.status = 'active'
             AND membership.authz_epoch = proof.membership_authz_epoch
            JOIN iam.access_tokens AS parent
              ON parent.id = proof.parent_access_token_id
             AND parent.client_application_id = proof.issuer_application_id
             AND parent.organization_id = proof.organization_id
             AND parent.membership_id = proof.membership_id
             AND parent.subject_auth_epoch = subject.auth_epoch
             AND parent.membership_authz_epoch = membership.authz_epoch
             AND parent.client_auth_epoch = issuer.auth_epoch
             AND parent.revoked_at IS NULL
             AND parent.expires_at > wall_clock.value
            JOIN iam.authentication_sessions AS session
             ON session.id = parent.authentication_session_id
             AND session.status = 'active'
             AND session.idle_expires_at > wall_clock.value
             AND session.absolute_expires_at > wall_clock.value
            JOIN iam.application_obo_endpoints AS endpoint
              ON endpoint.organization_id = proof.organization_id
             AND endpoint.application_id = proof.audience_application_id
             AND endpoint.endpoint_id = proof.endpoint_id
             AND endpoint.path = proof.request_path
             AND endpoint.version = proof.endpoint_version
             AND endpoint.status = 'active'
            WHERE proof.id = $1
              AND proof.issuer_application_id = $2
              AND proof.organization_id = $3
              AND proof.consumed_at IS NULL
              AND proof.revoked_at IS NULL
              AND proof.expires_at > wall_clock.value
              AND EXISTS (
                  SELECT 1
                  FROM iam.access_token_scopes AS token_scope
                  WHERE token_scope.access_token_id = parent.id
                    AND token_scope.scope = 'obo.issue'
              )
        )
        ",
    )
    .bind(proof_id)
    .bind(issuer_application_id)
    .bind(organization_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("obo_exchange_replay_authority"))
}

async fn load_current_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    proof: &ProofRow,
    audience_application_id: Uuid,
) -> Result<CurrentProofContext, ApiError> {
    sqlx::query_as::<_, CurrentProofContext>(
        r"
        WITH wall_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS value
        )
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
                    AND session.idle_expires_at > wall_clock.value
                    AND session.absolute_expires_at > wall_clock.value
                   WHERE parent.id = $6
                     AND parent.client_application_id = $4
                     AND parent.subject_principal_id = $1
                     AND parent.organization_id = $2
                     AND parent.membership_id = $3
                     AND parent.subject_auth_epoch = subject.auth_epoch
                     AND parent.membership_authz_epoch = membership.authz_epoch
                     AND parent.client_auth_epoch = issuer.auth_epoch
                     AND parent.revoked_at IS NULL
                     AND parent.expires_at > wall_clock.value
                     AND EXISTS (
                         SELECT 1 FROM iam.access_token_scopes AS token_scope
                         WHERE token_scope.access_token_id = parent.id
                           AND token_scope.scope = 'obo.issue'
                     )
               ) AS parent_active,
               EXISTS (
                   SELECT 1
                   FROM iam.application_obo_endpoints AS endpoint
                   WHERE endpoint.organization_id = $2
                     AND endpoint.application_id = $5
                     AND endpoint.endpoint_id = $7
                     AND endpoint.path = $10
                     AND endpoint.version = $8
                     AND endpoint.status = 'active'
               ) AS endpoint_active
        FROM wall_clock
        JOIN iam.organizations AS organization ON TRUE
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.id = $3
         AND membership.principal_id = $1
         AND membership.principal_kind = $9::iam.principal_kind
         AND membership.status = 'active'
        JOIN iam.principals AS subject
          ON subject.id = membership.principal_id
         AND subject.kind = membership.principal_kind
         AND subject.status = 'active'
        JOIN iam.applications AS issuer_application
          ON issuer_application.organization_id = organization.id
         AND issuer_application.id = $4
         AND issuer_application.review_status = 'verified'
         AND issuer_application.deleted_at IS NULL
        JOIN iam.principals AS issuer
          ON issuer.id = issuer_application.id
         AND issuer.kind = 'application'
         AND issuer.status = 'active'
        JOIN iam.applications AS audience_application
          ON audience_application.organization_id = organization.id
         AND audience_application.id = $5
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
    .bind(&proof.endpoint_id)
    .bind(proof.endpoint_version)
    .bind(&proof.subject_kind)
    .bind(&proof.request_path)
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
            silicon_webhook_routing: None,
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

fn proof_response(status: StatusCode, response: OboProofResponse, replayed: bool) -> Response {
    let mut response = (status, Json(response)).into_response();
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

fn json_response<T: serde::Serialize>(status: StatusCode, response: T) -> Response {
    (status, Json(response)).into_response()
}

fn secret_prefix(secret: &str) -> String {
    secret.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use axum::{
        http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
        response::IntoResponse as _,
    };
    use secrecy::SecretString;
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{
        canonical_request, exchange_canonical, reject_organization_header, request_binding_matches,
        secret_prefix, signed_exchange, validate_verify, verify_exchange_signature,
    };
    use crate::features::applications::{
        model::{OboExchangeRequest, OboExchangeRequestBinding, OboVerifyRequest},
        security::ApplicationClient,
    };

    const BODY_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const IDEMPOTENCY_KEY: &str = "018f47ac-75c7-7f84-a6b2-9c2a2617c155";

    #[test]
    fn proofs_disclose_only_the_wire_prefix_in_storage() {
        let proof = format!("obo_{}", "A".repeat(43));
        assert_eq!(secret_prefix(&proof), "obo_AAAAAAAA");
    }

    #[test]
    fn audience_verification_requires_exact_request_evidence() {
        let proof = format!("obo_{}", "A".repeat(43));
        let Ok(request) = serde_json::from_value::<OboVerifyRequest>(json!({
            "access_proof": proof,
            "request": {
                "method": "POST",
                "path": "/v1/files",
                "body_sha256": BODY_SHA256,
            },
        })) else {
            panic!("bound verification request must deserialize");
        };
        assert!(validate_verify(&request).is_ok());
        let Ok(malformed) = serde_json::from_value::<OboVerifyRequest>(json!({
            "access_proof": format!("obo_{}!", "A".repeat(42)),
            "request": {
                "method": "POST",
                "path": "/v1/files",
                "body_sha256": BODY_SHA256,
            },
        })) else {
            panic!("wire-shaped malformed proof request must deserialize");
        };
        assert!(validate_verify(&malformed).is_err());
        assert!(
            serde_json::from_value::<OboVerifyRequest>(json!({
                "access_proof": format!("obo_{}", "A".repeat(43)),
                "request": {
                    "method": "POST",
                    "path": "/v1/files",
                    "body_sha256": BODY_SHA256,
                    "endpoint_id": "caller.substitution",
                },
            }))
            .is_err()
        );
    }

    #[test]
    fn exchange_idempotency_is_bound_to_the_exact_subject_token() {
        let request = |subject_token: &str| OboExchangeRequest {
            subject_token: subject_token.to_owned(),
            audience: "documents".to_owned(),
            endpoint_id: "documents.read".to_owned(),
            metadata: json!({ "document_id": "doc-123" }),
            request: OboExchangeRequestBinding {
                method: "POST".to_owned(),
                body_sha256: BODY_SHA256.to_owned(),
            },
        };
        let Ok(first) = exchange_canonical(&request(&format!("oat_{}", "A".repeat(43)))) else {
            panic!("a valid request must serialize");
        };
        let Ok(second) = exchange_canonical(&request(&format!("oat_{}", "B".repeat(43)))) else {
            panic!("a valid request must serialize");
        };

        assert_ne!(first, second);
    }

    #[test]
    fn request_binding_accepts_only_canonical_method_and_digest() {
        assert!(canonical_request("POST", BODY_SHA256).is_ok());
        assert!(canonical_request("post", BODY_SHA256).is_err());
        assert!(canonical_request("POST", &BODY_SHA256.to_uppercase()).is_err());
        assert!(canonical_request("POST", "aa").is_err());
    }

    #[test]
    fn verification_binding_requires_every_persisted_component_to_match() {
        let Ok(request) = canonical_request("POST", BODY_SHA256) else {
            panic!("canonical downstream request must validate");
        };
        let stored_body = request.body_sha256;

        assert!(request_binding_matches(
            "POST",
            "/v1/files",
            &stored_body,
            &request,
            "/v1/files",
        ));
        assert!(!request_binding_matches(
            "PUT",
            "/v1/files",
            &stored_body,
            &request,
            "/v1/files",
        ));
        assert!(!request_binding_matches(
            "POST",
            "/v1/other",
            &stored_body,
            &request,
            "/v1/files",
        ));
        assert!(!request_binding_matches(
            "POST",
            "/v1/files",
            &[0_u8; 32],
            &request,
            "/v1/files",
        ));
    }

    #[test]
    fn signature_headers_are_unique_canonical_and_fresh() {
        let mut headers = signed_headers(
            "1700000000",
            "c5922f9a6d6ea69fe5d5a5e0a15e1e4db3698c607737dcc7290c9fe21838d4f9",
        );
        let Ok(boundary) = OffsetDateTime::from_unix_timestamp(1_700_000_060) else {
            panic!("test timestamp must be representable");
        };
        assert!(signed_exchange(&headers, boundary).is_ok());

        let Ok(stale) = OffsetDateTime::from_unix_timestamp(1_700_000_061) else {
            panic!("test timestamp must be representable");
        };
        assert!(signed_exchange(&headers, stale).is_err());
        let fractional_boundary = boundary + time::Duration::milliseconds(1);
        assert!(signed_exchange(&headers, fractional_boundary).is_err());
        headers.append("x-obo-timestamp", HeaderValue::from_static("1700000000"));
        assert!(signed_exchange(&headers, boundary).is_err());
    }

    #[test]
    fn missing_signature_preconditions_and_invalid_signatures_have_distinct_statuses() {
        let Ok(now) = OffsetDateTime::from_unix_timestamp(1_700_000_000) else {
            panic!("test timestamp must be representable");
        };
        let mut missing_signature = HeaderMap::new();
        missing_signature.insert(
            HeaderName::from_static("x-obo-timestamp"),
            HeaderValue::from_static("1700000000"),
        );
        missing_signature.insert(
            HeaderName::from_static("idempotency-key"),
            HeaderValue::from_static(IDEMPOTENCY_KEY),
        );
        let Err(missing_error) = signed_exchange(&missing_signature, now) else {
            panic!("a missing signature must fail");
        };
        assert_eq!(
            missing_error.into_response().status(),
            StatusCode::PRECONDITION_REQUIRED,
        );

        missing_signature.insert(
            HeaderName::from_static("x-obo-signature"),
            HeaderValue::from_static(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        );
        let Err(malformed_error) = signed_exchange(&missing_signature, now) else {
            panic!("an uppercase signature must fail");
        };
        assert_eq!(
            malformed_error.into_response().status(),
            StatusCode::UNAUTHORIZED,
        );
    }

    #[test]
    fn caller_supplied_organization_context_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("x-org-id"),
            HeaderValue::from_static("other-tenant"),
        );
        assert!(reject_organization_header(&headers).is_err());
    }

    #[test]
    fn signature_matches_the_published_canonical_vector() {
        let headers = signed_headers(
            "1700000000",
            "c5922f9a6d6ea69fe5d5a5e0a15e1e4db3698c607737dcc7290c9fe21838d4f9",
        );
        let Ok(now) = OffsetDateTime::from_unix_timestamp(1_700_000_000) else {
            panic!("test timestamp must be representable");
        };
        let Ok(signed) = signed_exchange(&headers, now) else {
            panic!("canonical signature headers must validate");
        };
        let Ok(request) = canonical_request("POST", BODY_SHA256) else {
            panic!("canonical downstream request must validate");
        };
        let client = ApplicationClient {
            application_id: Uuid::from_u128(1),
            app_id: "tos>files".to_owned(),
            organization_id: Uuid::from_u128(2),
            auth_epoch: 1,
            authenticated_secret: SecretString::from("ask_test_secret"),
        };

        assert!(verify_exchange_signature(&client, &signed, &request, "/v1/files").is_ok());
        assert!(verify_exchange_signature(&client, &signed, &request, "/v1/other").is_err());
    }

    fn signed_headers(timestamp: &'static str, signature: &'static str) -> HeaderMap {
        HeaderMap::from_iter([
            (
                HeaderName::from_static("x-obo-timestamp"),
                HeaderValue::from_static(timestamp),
            ),
            (
                HeaderName::from_static("x-obo-signature"),
                HeaderValue::from_static(signature),
            ),
            (
                HeaderName::from_static("idempotency-key"),
                HeaderValue::from_static(IDEMPOTENCY_KEY),
            ),
        ])
    }
}
