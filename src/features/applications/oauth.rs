#![allow(clippy::too_many_arguments, clippy::too_many_lines)]

use std::collections::BTreeSet;

use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse as _, Response},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::actor::{ActorRef, ActorType},
    infrastructure::{
        crypto::{
            DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField, SecretDigest,
            SecretKind,
        },
        postgres::{
            context::{self, DatabaseContext},
            events::{self as persistence_events, AggregateVersion, AuditRecord, OutboxRecord},
            tokens,
        },
    },
};

use super::{
    cursor,
    error::ApiError,
    events,
    idempotency::{self, Claim},
    model::{
        AuthorizeQuery, ConsentDecision, DiscoveryDocument, GrantPage, GrantPath, GrantView,
        IntrospectionResponse, JwkSet, PageInfo, PageQuery, PublicActor, TokenForm, TokenInput,
        TokenResponse, UserInfo,
    },
    security::{ApplicationClient, Bearer, BrowserSession, require_carbon, require_csrf},
    validation,
};

const AUTHORIZATION_REQUEST_SECONDS: i64 = 600;

const CURRENT_APPLICATION_CLIENT_LOCK_QUERY: &str = r"
    SELECT application.id
    FROM iam.applications AS application
    JOIN iam.principals AS principal
      ON principal.id = application.id
     AND principal.kind = 'application'
     AND principal.status = 'active'
     AND principal.auth_epoch = $2
    WHERE application.id = $1
      AND application.review_status = 'verified'
      AND application.deleted_at IS NULL
    FOR SHARE OF application, principal
";

const AUTHORIZATION_CODE_LOOKUP_QUERY: &str = r"
    WITH supplied_digest (key_version, digest) AS (
        SELECT * FROM unnest($1::smallint[], $2::bytea[])
    )
    SELECT code.id AS code_id, code.authorization_request_id,
           code.code_digest, code.digest_key_version,
           redirect.redirect_uri, request.authentication_session_id,
           request.subject_principal_id, request.subject_kind::text AS subject_kind,
           request.organization_id, request.membership_id,
           grant.id AS consent_grant_id,
           request.pkce_code_challenge, request.oidc_nonce_ciphertext,
           request.oidc_nonce_encryption_nonce, request.encryption_key_version,
           principal.auth_epoch AS subject_auth_epoch,
           membership.authz_epoch AS membership_authz_epoch,
           session.authenticated_at
    FROM supplied_digest
    JOIN iam.oauth_authorization_codes AS code
      ON code.digest_key_version = supplied_digest.key_version
     AND code.code_digest = supplied_digest.digest
    JOIN iam.oauth_authorization_requests AS request
      ON request.id = code.authorization_request_id
    JOIN iam.application_redirect_uris AS redirect
      ON redirect.id = request.redirect_uri_id
    JOIN iam.principals AS principal
      ON principal.id = request.subject_principal_id
     AND principal.kind = request.subject_kind
     AND principal.status = 'active'
    LEFT JOIN iam.organization_memberships AS membership
      ON membership.id = request.membership_id
     AND membership.organization_id = request.organization_id
     AND membership.principal_id = request.subject_principal_id
     AND membership.principal_kind = request.subject_kind
     AND membership.status = 'active'
    JOIN iam.authentication_sessions AS session
      ON session.id = request.authentication_session_id
     AND session.subject_principal_id = request.subject_principal_id
     AND session.subject_kind = request.subject_kind
     AND session.subject_auth_epoch = principal.auth_epoch
     AND session.status = 'active'
     AND session.idle_expires_at > transaction_timestamp()
     AND session.absolute_expires_at > transaction_timestamp()
    JOIN iam.oauth_consent_grants AS grant
      ON grant.application_id = request.application_id
     AND grant.subject_principal_id = request.subject_principal_id
     AND grant.subject_kind = request.subject_kind
     AND grant.organization_id IS NOT DISTINCT FROM request.organization_id
     AND grant.membership_id IS NOT DISTINCT FROM request.membership_id
     AND grant.parent_authentication_session_id = request.authentication_session_id
     AND grant.status = 'active'
    WHERE code.application_id = $3
      AND code.consumed_at IS NULL
      AND code.expires_at > transaction_timestamp()
      AND request.status = 'approved'
    FOR UPDATE OF code, request, grant
    FOR SHARE OF principal, session
";

const CODE_EXCHANGE_ACTIVE_SCOPES_QUERY: &str = r"
    SELECT request_scope.scope
    FROM iam.oauth_authorization_request_scopes AS request_scope
    JOIN iam.oauth_consent_grant_scopes AS consent_scope
      ON consent_scope.consent_grant_id = $2
     AND consent_scope.scope = request_scope.scope
    JOIN iam.application_approved_scopes AS approved
      ON approved.application_id = request_scope.application_id
     AND approved.scope = request_scope.scope
     AND approved.revoked_at IS NULL
    WHERE request_scope.authorization_request_id = $1
      AND request_scope.application_id = $3
    ORDER BY request_scope.scope
    FOR SHARE OF approved
";

const REFRESH_REUSE_ACCESS_REVOCATION_QUERY: &str = r"
    UPDATE iam.access_tokens
    SET revoked_at = COALESCE(revoked_at, transaction_timestamp()),
        revocation_reason = COALESCE(revocation_reason, 'refresh_token_reuse')
    WHERE authentication_session_id = $1
      AND client_application_id = $2
";

const REFRESH_TOKEN_CANDIDATE_QUERY: &str = r"
    WITH supplied_digest (key_version, digest) AS (
        SELECT * FROM unnest($1::smallint[], $2::bytea[])
    )
    SELECT refresh.id AS token_id, family.id AS family_id,
           refresh.token_digest, refresh.digest_key_version,
           family.authentication_session_id, family.subject_principal_id,
           principal.kind::text AS subject_kind,
           grant.organization_id, grant.membership_id,
           grant.id AS consent_grant_id
    FROM supplied_digest
    JOIN iam.refresh_tokens AS refresh
      ON refresh.digest_key_version = supplied_digest.key_version
     AND refresh.token_digest = supplied_digest.digest
    JOIN iam.refresh_token_families AS family
      ON family.id = refresh.family_id
    JOIN iam.principals AS principal
      ON principal.id = family.subject_principal_id
    JOIN iam.oauth_consent_grants AS grant
      ON grant.id = family.oauth_consent_grant_id
    WHERE family.client_application_id = $3
    LIMIT 1
";

const REFRESH_SESSION_AUTHORITY_LOCK_QUERY: &str = r"
    SELECT principal.auth_epoch AS subject_auth_epoch,
           session.authenticated_at
    FROM iam.principals AS principal
    JOIN iam.authentication_sessions AS session
      ON session.id = $2
     AND session.subject_principal_id = principal.id
     AND session.subject_kind = principal.kind
     AND session.subject_auth_epoch = principal.auth_epoch
     AND session.status = 'active'
     AND session.idle_expires_at > transaction_timestamp()
     AND session.absolute_expires_at > transaction_timestamp()
    WHERE principal.id = $1
      AND principal.kind = $3::iam.principal_kind
      AND principal.status = 'active'
    FOR SHARE OF principal, session
";

const REFRESH_MEMBERSHIP_AUTHORITY_LOCK_QUERY: &str = r"
    SELECT membership.authz_epoch
    FROM iam.organizations AS organization
    JOIN iam.organization_memberships AS membership
      ON membership.organization_id = organization.id
     AND membership.id = $2
     AND membership.principal_id = $3
     AND membership.principal_kind = $4::iam.principal_kind
     AND membership.status = 'active'
    WHERE organization.id = $1
      AND organization.status = 'active'
    FOR SHARE OF organization, membership
";

const REFRESH_GRANT_AUTHORITY_LOCK_QUERY: &str = r"
    SELECT grant.application_id, grant.subject_principal_id,
           grant.subject_kind::text AS subject_kind,
           grant.organization_id, grant.membership_id,
           grant.parent_authentication_session_id, grant.status
    FROM iam.oauth_consent_grants AS grant
    WHERE grant.id = $1
    FOR SHARE OF grant
";

const REFRESH_CREDENTIAL_LOCK_QUERY: &str = r"
    SELECT refresh.token_digest, refresh.digest_key_version,
           refresh.consumed_at, refresh.revoked_at,
           refresh.expires_at > transaction_timestamp() AS token_unexpired,
           family.status AS family_status,
           family.absolute_expires_at > transaction_timestamp() AS family_unexpired
    FROM iam.refresh_tokens AS refresh
    JOIN iam.refresh_token_families AS family
      ON family.id = refresh.family_id
    WHERE refresh.id = $1
      AND family.id = $2
      AND family.client_application_id = $3
      AND family.authentication_session_id = $4
      AND family.subject_principal_id = $5
      AND family.oauth_consent_grant_id = $6
      AND refresh.digest_key_version = $7
      AND refresh.token_digest = $8
    FOR UPDATE OF refresh, family
";

const REFRESH_ISSUANCE_SCOPES_QUERY: &str = r"
    SELECT snapshot.scope
    FROM iam.oauth_refresh_family_scopes AS snapshot
    JOIN iam.oauth_consent_grant_scopes AS consent_scope
      ON consent_scope.consent_grant_id = snapshot.consent_grant_id
     AND consent_scope.scope = snapshot.scope
    JOIN iam.application_approved_scopes AS approved
      ON approved.application_id = $3
     AND approved.scope = snapshot.scope
     AND approved.revoked_at IS NULL
    WHERE snapshot.family_id = $1
      AND snapshot.consent_grant_id = $2
    ORDER BY snapshot.scope
    FOR SHARE OF approved
";

#[derive(FromRow)]
struct AuthorizeApplicationRow {
    id: Uuid,
    app_id: String,
    app_name: Option<String>,
    notify_users: bool,
    redirect_uri_id: Uuid,
}

#[derive(FromRow)]
struct SubjectOrganizationRow {
    organization_id: Uuid,
    membership_id: Uuid,
}

#[derive(FromRow)]
struct AuthorizationRequestRow {
    id: Uuid,
    application_id: Uuid,
    redirect_uri: String,
    authentication_session_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    state_ciphertext: Vec<u8>,
    state_encryption_nonce: Vec<u8>,
    encryption_key_version: i16,
    status: String,
    expires_at: OffsetDateTime,
}

#[derive(FromRow)]
struct AuthorizationCodeRow {
    code_id: Uuid,
    authorization_request_id: Uuid,
    code_digest: Vec<u8>,
    digest_key_version: i16,
    redirect_uri: String,
    authentication_session_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    consent_grant_id: Uuid,
    pkce_code_challenge: String,
    oidc_nonce_ciphertext: Option<Vec<u8>>,
    oidc_nonce_encryption_nonce: Option<Vec<u8>>,
    encryption_key_version: i16,
    subject_auth_epoch: i64,
    membership_authz_epoch: Option<i64>,
    authenticated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct RefreshCandidateRow {
    token_id: Uuid,
    family_id: Uuid,
    token_digest: Vec<u8>,
    digest_key_version: i16,
    authentication_session_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    consent_grant_id: Uuid,
}

#[derive(FromRow)]
struct LockedRefreshCredentialRow {
    token_digest: Vec<u8>,
    digest_key_version: i16,
    consumed_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    token_unexpired: bool,
    family_status: String,
    family_unexpired: bool,
}

#[derive(FromRow)]
struct RefreshSessionAuthorityRow {
    subject_auth_epoch: i64,
    authenticated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct RefreshGrantAuthorityRow {
    application_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    parent_authentication_session_id: Uuid,
    status: String,
}

#[derive(FromRow)]
struct ActiveSigningKey {
    id: Uuid,
    key_id: String,
    algorithm: String,
    private_key_ciphertext: Vec<u8>,
    private_key_nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(FromRow)]
struct ContactRow {
    id: Uuid,
    kind: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
}

#[derive(FromRow)]
struct AccessIntrospectionMetadata {
    app_id: String,
    org_id: Option<String>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    subject_auth_epoch: i64,
    membership_authz_epoch: Option<i64>,
}

#[derive(FromRow)]
struct RefreshIntrospectionRow {
    token_digest: Vec<u8>,
    digest_key_version: i16,
    family_id: Uuid,
    consent_grant_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    org_id: Option<String>,
    membership_id: Option<Uuid>,
    authentication_session_id: Uuid,
    app_id: String,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    subject_auth_epoch: i64,
    membership_authz_epoch: Option<i64>,
}

#[derive(Serialize, Deserialize)]
struct RedirectReplay {
    location: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "outcome", content = "response", rename_all = "snake_case")]
enum TokenIdempotencyResult {
    Issued(Box<TokenResponse>),
    RefreshReuse,
}

enum RefreshExchange {
    Issued(Box<TokenResponse>),
    ReuseDetected,
}

#[derive(Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    auth_time: i64,
    sid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
}

pub(super) async fn discovery(
    State(state): State<ApiState>,
) -> Result<Json<DiscoveryDocument>, ApiError> {
    let issuer = base_url(&state);
    let scopes_supported =
        sqlx::query_scalar::<_, String>("SELECT scope FROM iam.oauth_scope_catalog ORDER BY scope")
            .fetch_all(&state.pool)
            .await
            .map_err(|_| ApiError::internal("oidc_discovery_scopes"))?;
    let signing_algorithms = sqlx::query_scalar::<_, String>(
        r"
        SELECT DISTINCT algorithm
        FROM iam.oidc_signing_keys
        WHERE status = 'active'
          AND not_before <= transaction_timestamp()
        ORDER BY algorithm
        ",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| ApiError::internal("oidc_discovery_algorithms"))?;
    if signing_algorithms.is_empty() {
        return Err(ApiError::internal("oidc_signing_key_missing"));
    }
    Ok(Json(DiscoveryDocument {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{issuer}/api/v1/oauth/authorize"),
        token_endpoint: format!("{issuer}/api/v1/oauth/token"),
        userinfo_endpoint: format!("{issuer}/api/v1/oauth/userinfo"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        revocation_endpoint: format!("{issuer}/api/v1/oauth/revoke"),
        introspection_endpoint: format!("{issuer}/api/v1/oauth/introspect"),
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: signing_algorithms,
        code_challenge_methods_supported: vec!["S256"],
        scopes_supported,
    }))
}

pub(super) async fn jwks(State(state): State<ApiState>) -> Result<Response, ApiError> {
    let keys = sqlx::query_scalar::<_, Value>(
        r"
        SELECT public_jwk
        FROM iam.oidc_signing_keys
        WHERE status IN ('active', 'retiring')
          AND not_before <= transaction_timestamp()
          AND (retires_at IS NULL OR retires_at > transaction_timestamp())
        ORDER BY (status = 'active') DESC, created_at DESC
        ",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| ApiError::internal("oidc_jwks"))?;
    let mut response = Json(JwkSet { keys }).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    Ok(response)
}

pub(super) async fn authorize(
    State(state): State<ApiState>,
    session: BrowserSession,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, ApiError> {
    let scopes = validation::authorize(&query)?;
    let redirect_digest = Sha256::digest(query.redirect_uri.as_bytes());
    let mut transaction =
        context::begin(&state.pool, DatabaseContext::principal(session.carbon_id))
            .await
            .map_err(|_| ApiError::internal("oauth_authorize_context"))?;
    let app = sqlx::query_as::<_, AuthorizeApplicationRow>(
        r"
        SELECT application.id, application.app_id, application.app_name,
               application.notify_users, redirect.id AS redirect_uri_id
        FROM iam.applications AS application
        JOIN iam.principals AS principal
          ON principal.id = application.id
         AND principal.kind = 'application'
         AND principal.status = 'active'
        JOIN iam.application_redirect_uris AS redirect
          ON redirect.application_id = application.id
         AND redirect.status = 'active'
         AND redirect.uri_digest = $3
        WHERE application.app_id = $1
          AND application.review_status = 'verified'
          AND application.deleted_at IS NULL
          AND redirect.redirect_uri = $2
        ",
    )
    .bind(&query.client_id)
    .bind(&query.redirect_uri)
    .bind(redirect_digest.as_slice())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("oauth_authorize_application"))?
    .ok_or_else(|| {
        ApiError::bad_request("invalid_request", "The client or redirect URI is invalid.")
    })?;
    let approved = sqlx::query_as::<_, (String, OffsetDateTime)>(
        r"
        SELECT scope, approved_at
        FROM iam.application_approved_scopes
        WHERE application_id = $1 AND revoked_at IS NULL
          AND scope = ANY($2::text[])
        ORDER BY scope
        ",
    )
    .bind(app.id)
    .bind(&scopes)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("oauth_authorize_scopes"))?;
    if approved.len() != scopes.len() {
        return Err(ApiError::forbidden("invalid_scope"));
    }
    let organization = if let Some(org_id) = &query.org_id {
        Some(
            sqlx::query_as::<_, SubjectOrganizationRow>(
                r"
                SELECT organization.id AS organization_id,
                       membership.id AS membership_id
                FROM iam.organizations AS organization
                JOIN iam.organization_memberships AS membership
                  ON membership.organization_id = organization.id
                 AND membership.principal_id = $2
                 AND membership.principal_kind = 'carbon'
                 AND membership.status = 'active'
                WHERE organization.org_id = $1 AND organization.status = 'active'
                ",
            )
            .bind(org_id)
            .bind(session.carbon_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("oauth_authorize_org"))?
            .ok_or_else(|| ApiError::forbidden("organization_context_forbidden"))?,
        )
    } else {
        None
    };
    let request_id = Uuid::now_v7();
    let encrypted_state = state
        .crypto
        .encrypt(
            EncryptionContext::global(ProtectedField::ProviderCredential, request_id),
            query.state.as_bytes(),
        )
        .map_err(|_| ApiError::internal("oauth_state_encrypt"))?;
    let encrypted_nonce = state
        .crypto
        .encrypt(
            EncryptionContext::global(ProtectedField::ProviderCredential, request_id),
            query.nonce.as_bytes(),
        )
        .map_err(|_| ApiError::internal("oauth_nonce_encrypt"))?;
    if encrypted_state.key_version != encrypted_nonce.key_version {
        return Err(ApiError::internal("oauth_encryption_key_mismatch"));
    }
    sqlx::query(
        r"
        INSERT INTO iam.oauth_authorization_requests (
            id, application_id, redirect_uri_id, authentication_session_id,
            subject_principal_id, subject_kind, organization_id, membership_id,
            state_digest, state_ciphertext, state_encryption_nonce,
            oidc_nonce_ciphertext, oidc_nonce_encryption_nonce,
            encryption_key_version, pkce_code_challenge, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, 'carbon', $6, $7, $8, $9, $10,
            $11, $12, $13, $14,
            transaction_timestamp() + ($15::bigint * interval '1 second')
        )
        ",
    )
    .bind(request_id)
    .bind(app.id)
    .bind(app.redirect_uri_id)
    .bind(session.session_id)
    .bind(session.carbon_id)
    .bind(organization.as_ref().map(|value| value.organization_id))
    .bind(organization.as_ref().map(|value| value.membership_id))
    .bind(Sha256::digest(query.state.as_bytes()).as_slice())
    .bind(encrypted_state.ciphertext)
    .bind(encrypted_state.nonce.as_slice())
    .bind(encrypted_nonce.ciphertext)
    .bind(encrypted_nonce.nonce.as_slice())
    .bind(encrypted_state.key_version)
    .bind(&query.code_challenge)
    .bind(AUTHORIZATION_REQUEST_SECONDS)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("oauth_authorization_request_insert"))?;
    for (scope, approved_at) in approved {
        sqlx::query(
            r"
            INSERT INTO iam.oauth_authorization_request_scopes (
                authorization_request_id, application_id, scope, approved_at
            ) VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(request_id)
        .bind(app.id)
        .bind(scope)
        .bind(approved_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_authorization_scope_insert"))?;
    }
    let existing_consent = consent_covers(
        &mut transaction,
        app.id,
        session.carbon_id,
        organization.as_ref().map(|value| value.organization_id),
        &scopes,
    )
    .await?;
    if !app.notify_users || existing_consent {
        let request = load_authorization_request(&mut transaction, request_id, true).await?;
        let location = approve_request(&mut transaction, &state, &request).await?;
        events::authentication_event(
            &mut transaction,
            app.id,
            Some(session.carbon_id),
            Some("carbon"),
            Some(session.session_id),
            "oauth.authorization",
            "success",
            None,
            json!({ "consent_prompted": false, "scope_count": scopes.len() }),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("oauth_authorize_commit"))?;
        return redirect_response(&location);
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("oauth_consent_commit"))?;
    let name = escape_html(app.app_name.as_deref().unwrap_or(&app.app_id));
    let mut scope_items = String::new();
    for scope in &scopes {
        scope_items.push_str("<li>");
        scope_items.push_str(&escape_html(scope));
        scope_items.push_str("</li>");
    }
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Authorize {name}</title></head>\
         <body><main><h1>Authorize {name}</h1><ul>{scope_items}</ul>\
         <div data-authorization-transaction-id=\"{request_id}\" data-csrf-token=\"{}\"></div>\
         </main></body></html>",
        escape_html(&session.csrf_token),
    );
    Ok(consent_html_response(html))
}

fn consent_html_response(html: String) -> Response {
    let mut response = (StatusCode::OK, Html(html)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        http::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );
    response.headers_mut().insert(
        http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub(super) async fn decide_consent(
    State(state): State<ApiState>,
    session: BrowserSession,
    headers: HeaderMap,
    Json(input): Json<ConsentDecision>,
) -> Result<Response, ApiError> {
    require_csrf(&headers, &session)?;
    if !matches!(input.decision.as_str(), "approve" | "deny") {
        return Err(ApiError::validation("decision", "must be approve or deny"));
    }
    let canonical = serde_json::to_vec(&json!({
        "authorization_transaction_id": input.authorization_request_id,
        "decision": input.decision,
    }))
    .map_err(|_| ApiError::internal("oauth_decision_canonical"))?;
    let mut transaction =
        context::begin(&state.pool, DatabaseContext::principal(session.carbon_id))
            .await
            .map_err(|_| ApiError::internal("oauth_decision_context"))?;
    let caller_scope = format!("browser-session:{}", session.session_id);
    let claim = idempotency::claim::<RedirectReplay>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/oauth/authorize/decisions",
        &canonical,
        true,
    )
    .await?;
    if let Claim::Replay { response, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("oauth_decision_replay"))?;
        return redirect_response(&response.location);
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("oauth_decision_idempotency"));
    };
    let request =
        load_authorization_request(&mut transaction, input.authorization_request_id, true).await?;
    if request.authentication_session_id != session.session_id
        || request.subject_principal_id != session.carbon_id
    {
        return Err(ApiError::not_found());
    }
    if request.expires_at <= OffsetDateTime::now_utc() {
        return Err(ApiError::gone("authorization_request_expired"));
    }
    if request.status != "pending" {
        return Err(ApiError::conflict("authorization_request_already_decided"));
    }
    let location = if input.decision == "approve" {
        approve_request(&mut transaction, &state, &request).await?
    } else {
        sqlx::query(
            r"
            UPDATE iam.oauth_authorization_requests
            SET status = 'denied', decided_at = transaction_timestamp()
            WHERE id = $1 AND status = 'pending'
            ",
        )
        .bind(request.id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_consent_deny"))?;
        let state_value = decrypt_protocol_value(
            &state,
            request.id,
            request.encryption_key_version,
            &request.state_encryption_nonce,
            &request.state_ciphertext,
        )?;
        append_redirect_parameters(
            &request.redirect_uri,
            &[("error", "access_denied"), ("state", &state_value)],
        )?
    };
    events::authentication_event(
        &mut transaction,
        request.application_id,
        Some(session.carbon_id),
        Some("carbon"),
        Some(session.session_id),
        "oauth.authorization",
        if input.decision == "approve" {
            "success"
        } else {
            "denied"
        },
        (input.decision == "deny").then_some("access_denied"),
        json!({ "consent_prompted": true }),
    )
    .await?;
    let replay = RedirectReplay {
        location: location.clone(),
    };
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        302,
        &replay,
        true,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("oauth_decision_commit"))?;
    redirect_response(&location)
}

pub(super) async fn token(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Result<Response, ApiError> {
    if form.client_id.as_deref() != Some(client.app_id.as_str()) {
        return Err(ApiError::invalid_client());
    }
    if !matches!(
        form.grant_type.as_str(),
        "authorization_code" | "refresh_token"
    ) {
        return Err(ApiError::bad_request(
            "unsupported_grant_type",
            "The grant type is not supported.",
        ));
    }
    let canonical = serde_json::to_vec(&json!({
        "grant_type": form.grant_type,
        "client_id": form.client_id,
        "code": form.code,
        "redirect_uri": form.redirect_uri,
        "code_verifier": form.code_verifier,
        "refresh_token": form.refresh_token,
    }))
    .map_err(|_| ApiError::internal("oauth_token_canonical"))?;
    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext::application(client.application_id, client.application_id),
    )
    .await
    .map_err(|_| ApiError::internal("oauth_token_context"))?;
    let caller_scope = format!("application:{}", client.application_id);
    let claim = idempotency::claim::<TokenIdempotencyResult>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/oauth/token",
        &canonical,
        true,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("oauth_token_replay"))?;
        return match (status, response) {
            (200, TokenIdempotencyResult::Issued(response)) => Ok(token_response(*response, true)),
            (400, TokenIdempotencyResult::RefreshReuse) => Err(refresh_reuse_error()),
            _ => Err(ApiError::internal("oauth_token_replay_shape")),
        };
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("oauth_token_idempotency"));
    };
    let outcome = if form.grant_type == "authorization_code" {
        RefreshExchange::Issued(Box::new(
            exchange_authorization_code(&mut transaction, &state, &client, &form).await?,
        ))
    } else {
        exchange_refresh_token(&mut transaction, &state, &client, &form).await?
    };
    match outcome {
        RefreshExchange::Issued(response) => {
            idempotency::complete(
                &mut transaction,
                &state.crypto,
                idempotency_id,
                200,
                &TokenIdempotencyResult::Issued(response.clone()),
                true,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| ApiError::internal("oauth_token_commit"))?;
            Ok(token_response(*response, false))
        }
        RefreshExchange::ReuseDetected => {
            idempotency::complete(
                &mut transaction,
                &state.crypto,
                idempotency_id,
                400,
                &TokenIdempotencyResult::RefreshReuse,
                true,
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| ApiError::internal("oauth_refresh_compromise_commit"))?;
            Err(refresh_reuse_error())
        }
    }
}

pub(super) async fn introspect(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Form(input): Form<TokenInput>,
) -> Result<Json<IntrospectionResponse>, ApiError> {
    validate_token_type_hint(input.token_type_hint.as_deref())?;
    if input.token.starts_with("ort_") {
        return introspect_refresh_token(&state, &client, &headers, &input.token).await;
    }
    let token = SecretString::from(input.token);
    let access = match tokens::authenticate(&state.pool, &state.crypto, &token).await {
        Ok(Some(access)) if access.client_application_id == Some(client.application_id) => access,
        Ok(_) | Err(crate::infrastructure::postgres::tokens::AccessTokenError::InvalidFormat) => {
            return Ok(Json(inactive_introspection()));
        }
        Err(_) => return Err(ApiError::internal("oauth_introspection")),
    };
    if let Some(org_handle) = headers
        .get("x-org-id")
        .and_then(|value| value.to_str().ok())
    {
        let matches = sqlx::query_scalar::<_, bool>(
            r"
            SELECT EXISTS (
                SELECT 1 FROM iam.organizations
                WHERE id = $1 AND org_id = $2 AND status = 'active'
            )
            ",
        )
        .bind(access.organization_id)
        .bind(org_handle)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| ApiError::internal("oauth_introspection_org"))?;
        if !matches {
            return Ok(Json(inactive_introspection()));
        }
    }
    let metadata = sqlx::query_as::<_, AccessIntrospectionMetadata>(
        r"
        SELECT application.app_id, organization.org_id,
               token.created_at, token.expires_at,
               token.subject_auth_epoch, token.membership_authz_epoch
        FROM iam.access_tokens AS token
        JOIN iam.applications AS application ON application.id = token.client_application_id
        LEFT JOIN iam.organizations AS organization ON organization.id = token.organization_id
        WHERE token.id = $1
        ",
    )
    .bind(access.token_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| ApiError::internal("oauth_introspection_metadata"))?;
    Ok(Json(IntrospectionResponse {
        active: true,
        principal_id: Some(access.subject.id),
        actor_type: Some(access.subject.actor_type.as_str().to_owned()),
        client_id: Some(metadata.app_id),
        org_id: metadata.org_id,
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
    }))
}

async fn introspect_refresh_token(
    state: &ApiState,
    client: &ApplicationClient,
    headers: &HeaderMap,
    raw_token: &str,
) -> Result<Json<IntrospectionResponse>, ApiError> {
    if raw_token.len() != 47 {
        return Ok(Json(inactive_introspection()));
    }
    let supplied = SecretString::from(raw_token.to_owned());
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::OAuthRefreshToken, &supplied)
        .map_err(|_| ApiError::internal("refresh_introspection_digest"))?;
    let versions = digests
        .iter()
        .map(SecretDigest::key_version)
        .collect::<Vec<_>>();
    let bytes = digests
        .iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext::application(client.application_id, client.application_id),
    )
    .await
    .map_err(|_| ApiError::internal("refresh_introspection_context"))?;
    let row = sqlx::query_as::<_, RefreshIntrospectionRow>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT token.token_digest, token.digest_key_version,
               family.id AS family_id,
               family.oauth_consent_grant_id AS consent_grant_id,
               family.subject_principal_id, principal.kind::text AS subject_kind,
               organization.org_id, grant.membership_id,
               family.authentication_session_id, application.app_id,
               token.created_at,
               LEAST(token.expires_at, family.absolute_expires_at,
                     session.absolute_expires_at) AS expires_at,
               principal.auth_epoch AS subject_auth_epoch,
               membership.authz_epoch AS membership_authz_epoch,
               session.authenticated_at
        FROM supplied_digest
        JOIN iam.refresh_tokens AS token
          ON token.digest_key_version = supplied_digest.key_version
         AND token.token_digest = supplied_digest.digest
        JOIN iam.refresh_token_families AS family ON family.id = token.family_id
        JOIN iam.principals AS principal
          ON principal.id = family.subject_principal_id
         AND principal.status = 'active'
        JOIN iam.authentication_sessions AS session
          ON session.id = family.authentication_session_id
         AND session.subject_principal_id = family.subject_principal_id
         AND session.subject_kind = principal.kind
         AND session.subject_auth_epoch = principal.auth_epoch
         AND session.status = 'active'
         AND session.idle_expires_at > transaction_timestamp()
         AND session.absolute_expires_at > transaction_timestamp()
        JOIN iam.oauth_consent_grants AS grant
          ON grant.id = family.oauth_consent_grant_id
         AND grant.application_id = family.client_application_id
         AND grant.subject_principal_id = family.subject_principal_id
         AND grant.subject_kind = principal.kind
         AND grant.parent_authentication_session_id = family.authentication_session_id
         AND grant.status = 'active'
        JOIN iam.applications AS application
          ON application.id = family.client_application_id
         AND application.review_status = 'verified'
         AND application.deleted_at IS NULL
        JOIN iam.principals AS application_principal
         ON application_principal.id = application.id
         AND application_principal.kind = 'application'
         AND application_principal.status = 'active'
         AND application_principal.auth_epoch = $4
        LEFT JOIN iam.organizations AS organization
          ON organization.id = grant.organization_id
         AND organization.status = 'active'
        LEFT JOIN iam.organization_memberships AS membership
          ON membership.id = grant.membership_id
         AND membership.organization_id = grant.organization_id
         AND membership.principal_id = family.subject_principal_id
         AND membership.principal_kind = principal.kind
         AND membership.status = 'active'
        WHERE family.client_application_id = $3
          AND family.status = 'active'
          AND family.absolute_expires_at > transaction_timestamp()
          AND token.consumed_at IS NULL
          AND token.revoked_at IS NULL
          AND token.expires_at > transaction_timestamp()
          AND (grant.organization_id IS NULL OR membership.id IS NOT NULL)
        LIMIT 1
        ",
    )
    .bind(versions)
    .bind(bytes)
    .bind(client.application_id)
    .bind(client.auth_epoch)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("refresh_introspection_lookup"))?;
    let Some(row) = row else {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("refresh_introspection_inactive_commit"))?;
        return Ok(Json(inactive_introspection()));
    };
    let expected = SecretDigest::from_parts(row.digest_key_version, &row.token_digest)
        .ok_or_else(|| ApiError::internal("refresh_introspection_shape"))?;
    if !state
        .crypto
        .verify_secret(DigestPurpose::OAuthRefreshToken, &supplied, expected)
        .map_err(|_| ApiError::internal("refresh_introspection_verify"))?
        || headers
            .get("x-org-id")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|org_id| row.org_id.as_deref() != Some(org_id))
    {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("refresh_introspection_mismatch_commit"))?;
        return Ok(Json(inactive_introspection()));
    }
    let scopes =
        refresh_family_scopes(&mut transaction, row.family_id, row.consent_grant_id).await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("refresh_introspection_commit"))?;
    Ok(Json(IntrospectionResponse {
        active: true,
        principal_id: Some(row.subject_principal_id),
        actor_type: Some(row.subject_kind),
        client_id: Some(row.app_id.clone()),
        org_id: row.org_id,
        membership_id: row.membership_id,
        session_id: Some(row.authentication_session_id),
        scope: Some(scopes.join(" ")),
        audience: Some(row.app_id),
        issued_at: Some(row.created_at.unix_timestamp()),
        expires_at: Some(row.expires_at.unix_timestamp()),
        authorization_epoch: Some(row.membership_authz_epoch.unwrap_or(row.subject_auth_epoch)),
    }))
}

pub(super) async fn revoke(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Form(input): Form<TokenInput>,
) -> Result<Response, ApiError> {
    validate_token_type_hint(input.token_type_hint.as_deref())?;
    if input.token.len() > 4_096 || input.token.len() < 32 {
        return Err(ApiError::bad_request(
            "invalid_request",
            "The token is malformed.",
        ));
    }
    let token = SecretString::from(input.token);
    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext::application(client.application_id, client.application_id),
    )
    .await
    .map_err(|_| ApiError::internal("oauth_revoke_context"))?;
    let caller_scope = format!("application:{}", client.application_id);
    let canonical = token.expose_secret().as_bytes();
    let claim = idempotency::claim::<Value>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/oauth/revoke",
        canonical,
        false,
    )
    .await?;
    if matches!(claim, Claim::Replay { .. }) {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("oauth_revoke_replay"))?;
        return Ok(StatusCode::OK.into_response());
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("oauth_revoke_idempotency"));
    };
    let revoked_id = if token.expose_secret().starts_with("oat_") {
        revoke_access_token(&mut transaction, &state, &client, &token).await?
    } else if token.expose_secret().starts_with("ort_") {
        revoke_refresh_family(&mut transaction, &state, &client, &token).await?
    } else {
        None
    };
    if let Some(target_id) = revoked_id {
        protocol_event(
            &mut transaction,
            &client,
            "oauth.token.revoke",
            "oauth_token",
            target_id,
            "oauth.token_revoked",
            json!({ "token_id": target_id }),
        )
        .await?;
    }
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        200,
        &Value::Null,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("oauth_revoke_commit"))?;
    Ok(StatusCode::OK.into_response())
}

pub(super) async fn userinfo(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
) -> Result<Json<UserInfo>, ApiError> {
    if access.client_application_id.is_none()
        || !access.scopes.iter().any(|scope| scope == "openid")
    {
        return Err(ApiError::forbidden("insufficient_scope"));
    }
    let mut transaction = context::begin(
        &state.pool,
        DatabaseContext {
            principal_id: Some(access.subject.id),
            organization_id: access.organization_id,
            application_id: access.client_application_id,
            signup_session_id: None,
        },
    )
    .await
    .map_err(|_| ApiError::internal("userinfo_context"))?;
    if access.subject.actor_type != ActorType::Carbon {
        return Err(ApiError::forbidden("unsupported_subject"));
    }
    let (public_id, name, picture) = sqlx::query_as::<_, (String, String, Option<String>)>(
        r"
        SELECT carbon_id, display_name, profile_photo_uri
        FROM iam.carbons WHERE id = $1 AND deleted_at IS NULL
        ",
    )
    .bind(access.subject.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("userinfo_profile"))?;
    let contacts = sqlx::query_as::<_, ContactRow>(
        r"
        SELECT id, kind::text AS kind, ciphertext, nonce, encryption_key_version
        FROM iam.carbon_contacts
        WHERE carbon_id = $1 AND status = 'active' AND is_primary
        ",
    )
    .bind(access.subject.id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("userinfo_contacts"))?;
    let mut email = None;
    let mut phone_number = None;
    for contact in contacts {
        let wanted = (contact.kind == "email"
            && access.scopes.iter().any(|scope| scope == "email"))
            || (contact.kind == "phone" && access.scopes.iter().any(|scope| scope == "phone"));
        if !wanted {
            continue;
        }
        let nonce = <[u8; 12]>::try_from(contact.nonce.as_slice())
            .map_err(|_| ApiError::internal("userinfo_contact_nonce"))?;
        let field = if contact.kind == "email" {
            ProtectedField::CarbonEmail
        } else {
            ProtectedField::CarbonPhone
        };
        let plaintext = state
            .crypto
            .decrypt(
                EncryptionContext::global(field, contact.id),
                &EncryptedValue {
                    key_version: contact.encryption_key_version,
                    nonce,
                    ciphertext: contact.ciphertext,
                },
            )
            .map_err(|_| ApiError::internal("userinfo_contact_decrypt"))?;
        let value = String::from_utf8(plaintext.to_vec())
            .map_err(|_| ApiError::internal("userinfo_contact_utf8"))?;
        if contact.kind == "email" {
            email = Some(value);
        } else {
            phone_number = Some(value);
        }
    }
    let organization = if let (Some(organization_id), Some(membership_id)) =
        (access.organization_id, access.membership_id)
    {
        sqlx::query_as::<_, (String, String, String)>(
            r"
            SELECT organization.org_id, membership.org_role::text, membership.job_role
            FROM iam.organizations AS organization
            JOIN iam.organization_memberships AS membership
              ON membership.organization_id = organization.id
            WHERE organization.id = $1 AND membership.id = $2
              AND membership.status = 'active'
            ",
        )
        .bind(organization_id)
        .bind(membership_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal("userinfo_organization"))?
        .map(|(org_id, role, job_role)| (org_id, membership_id, role, job_role))
    } else {
        None
    };
    let tags = if access
        .scopes
        .iter()
        .any(|scope| scope == "memberships.read")
    {
        if let Some(membership_id) = access.membership_id {
            sqlx::query_scalar::<_, String>(
                r"
                SELECT tag.name
                FROM iam.membership_tags AS assigned
                JOIN iam.organization_tags AS tag
                  ON tag.organization_id = assigned.organization_id AND tag.id = assigned.tag_id
                WHERE assigned.membership_id = $1 AND tag.archived_at IS NULL
                ORDER BY tag.name
                ",
            )
            .bind(membership_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("userinfo_tags"))?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("userinfo_commit"))?;
    let profile_allowed = access.scopes.iter().any(|scope| scope == "profile");
    let membership_allowed = access
        .scopes
        .iter()
        .any(|scope| scope == "memberships.read");
    Ok(Json(UserInfo {
        sub: access.subject.id,
        actor_type: "carbon".to_owned(),
        public_id,
        name: profile_allowed.then_some(name),
        picture: profile_allowed.then_some(picture).flatten(),
        email,
        phone_number,
        org_id: membership_allowed
            .then(|| organization.as_ref().map(|value| value.0.clone()))
            .flatten(),
        membership_id: membership_allowed
            .then(|| organization.as_ref().map(|value| value.1))
            .flatten(),
        org_role: membership_allowed
            .then(|| organization.as_ref().map(|value| value.2.clone()))
            .flatten(),
        job_role: access
            .scopes
            .iter()
            .any(|scope| scope == "roles.read")
            .then(|| organization.as_ref().map(|value| value.3.clone()))
            .flatten(),
        tags,
    }))
}

pub(super) async fn list_grants(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Query(query): Query<PageQuery>,
) -> Result<Json<GrantPage>, ApiError> {
    let carbon_id = require_carbon(&access)?;
    let cursor = cursor::decode(query.cursor.as_deref())?;
    let limit = cursor::limit(query.limit);
    let (at, id) = cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)));
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("grant_list_context"))?;
    let mut items = sqlx::query_as::<_, GrantView>(
        r"
        SELECT grant.id, application.app_id,
               grant.subject_principal_id AS principal_id,
               grant.subject_kind::text AS actor_type,
               carbon.carbon_id AS public_id,
               organization.org_id,
               ARRAY(
                   SELECT scope FROM iam.oauth_consent_grant_scopes
                   WHERE consent_grant_id = grant.id ORDER BY scope
               ) AS scopes,
               grant.granted_at AS created_at,
               grant.updated_at
        FROM iam.oauth_consent_grants AS grant
        JOIN iam.applications AS application ON application.id = grant.application_id
        JOIN iam.carbons AS carbon
          ON carbon.id = grant.subject_principal_id AND grant.subject_kind = 'carbon'
        LEFT JOIN iam.organizations AS organization ON organization.id = grant.organization_id
        WHERE grant.subject_principal_id = $1 AND grant.subject_kind = 'carbon'
          AND ($2::timestamptz IS NULL OR (grant.granted_at, grant.id) < ($2, $3))
        ORDER BY grant.granted_at DESC, grant.id DESC
        LIMIT $4
        ",
    )
    .bind(carbon_id)
    .bind(at)
    .bind(id)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("grant_list"))?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("grant_list_commit"))?;
    let next_cursor = if i64::try_from(items.len()).unwrap_or(i64::MAX) > limit {
        items.pop();
        items
            .last()
            .map(|item| cursor::encode(item.created_at, item.id))
            .transpose()?
    } else {
        None
    };
    Ok(Json(GrantPage {
        items,
        page: PageInfo::from_next_cursor(next_cursor),
    }))
}

pub(super) async fn revoke_grant(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    axum::extract::Path(path): axum::extract::Path<GrantPath>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let carbon_id = require_carbon(&access)?;
    let mut transaction = context::begin(&state.pool, DatabaseContext::principal(carbon_id))
        .await
        .map_err(|_| ApiError::internal("grant_revoke_context"))?;
    let caller_scope = format!("carbon:{carbon_id}");
    let claim = idempotency::claim::<Value>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "DELETE /api/v1/me/application-grants/{grant_id}",
        path.grant_id.as_bytes(),
        false,
    )
    .await?;
    if matches!(claim, Claim::Replay { .. }) {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("grant_revoke_replay"))?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("grant_revoke_idempotency"));
    };
    let row = sqlx::query_as::<_, (Uuid, Option<Uuid>, i64)>(
        r"
        UPDATE iam.oauth_consent_grants
        SET status = 'revoked', revoked_at = transaction_timestamp()
        WHERE id = $1 AND subject_principal_id = $2 AND subject_kind = 'carbon'
          AND status = 'active'
        RETURNING application_id, organization_id, version
        ",
    )
    .bind(path.grant_id)
    .bind(carbon_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("grant_revoke"))?
    .ok_or_else(ApiError::not_found)?;
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'revoked', revoked_at = transaction_timestamp(),
            revocation_reason = 'consent_revoked'
        WHERE oauth_consent_grant_id = $1 AND status = 'active'
        ",
    )
    .bind(path.grant_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("grant_refresh_revoke"))?;
    sqlx::query(
        r"
        UPDATE iam.access_tokens
        SET revoked_at = transaction_timestamp(), revocation_reason = 'consent_revoked'
        WHERE client_application_id = $1 AND subject_principal_id = $2
          AND organization_id IS NOT DISTINCT FROM $3 AND revoked_at IS NULL
        ",
    )
    .bind(row.0)
    .bind(carbon_id)
    .bind(row.1)
    .execute(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("grant_access_revoke"))?;
    persistence_events::record_audit(
        &mut transaction,
        AuditRecord {
            actor: Some(access.subject),
            authentication_session_id: Some(access.authentication_session_id),
            organization_id: row.1,
            application_id: Some(row.0),
            action: "oauth.consent.revoke",
            target_type: "oauth_consent_grant",
            target_id: Some(path.grant_id),
            authentication_method: None,
            aggregate: Some(AggregateVersion {
                aggregate_type: "oauth_consent_grant",
                aggregate_id: path.grant_id,
                version: row.2,
            }),
            before_state: Some(json!({ "status": "active" })),
            after_state: Some(json!({ "status": "revoked" })),
            metadata: json!({}),
        },
    )
    .await
    .map_err(|_| ApiError::internal("grant_revoke_audit"))?;
    persistence_events::enqueue_outbox(
        &mut transaction,
        OutboxRecord {
            organization_id: row.1,
            aggregate: AggregateVersion {
                aggregate_type: "oauth_consent_grant",
                aggregate_id: path.grant_id,
                version: row.2,
            },
            event_ordinal: 1,
            event_type: "oauth.consent_revoked",
            schema_version: 1,
            payload: json!({ "grant_id": path.grant_id, "application_id": row.0 }),
        },
    )
    .await
    .map_err(|_| ApiError::internal("grant_revoke_outbox"))?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        idempotency_id,
        204,
        &Value::Null,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("grant_revoke_commit"))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn exchange_authorization_code(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
    form: &TokenForm,
) -> Result<TokenResponse, ApiError> {
    let code = form
        .code
        .as_ref()
        .filter(|value| value.starts_with("oac_") && value.len() == 47)
        .ok_or_else(|| {
            ApiError::bad_request("invalid_grant", "The authorization code is invalid.")
        })?;
    let redirect_uri = form
        .redirect_uri
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("invalid_request", "redirect_uri is required."))?;
    let verifier = form
        .code_verifier
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("invalid_request", "code_verifier is required."))?;
    let supplied = SecretString::from(code.to_owned());
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::AuthorizationCode, &supplied)
        .map_err(|_| ApiError::internal("authorization_code_digest"))?;
    let versions = digests
        .iter()
        .map(SecretDigest::key_version)
        .collect::<Vec<_>>();
    let bytes = digests
        .iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();
    if !lock_current_application_client(transaction, client).await? {
        return Err(ApiError::bad_request(
            "invalid_grant",
            "The authorization code is invalid.",
        ));
    }
    let row = sqlx::query_as::<_, AuthorizationCodeRow>(AUTHORIZATION_CODE_LOOKUP_QUERY)
        .bind(versions)
        .bind(bytes)
        .bind(client.application_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("authorization_code_lookup"))?
        .ok_or_else(|| {
            ApiError::bad_request("invalid_grant", "The authorization code is invalid.")
        })?;
    let expected = SecretDigest::from_parts(row.digest_key_version, &row.code_digest)
        .ok_or_else(|| ApiError::internal("authorization_code_shape"))?;
    if !state
        .crypto
        .verify_secret(DigestPurpose::AuthorizationCode, &supplied, expected)
        .map_err(|_| ApiError::internal("authorization_code_verify"))?
        || row.redirect_uri != redirect_uri
        || !validation::pkce_matches(verifier, &row.pkce_code_challenge)
        || (row.organization_id.is_some() && row.membership_authz_epoch.is_none())
    {
        return Err(ApiError::bad_request(
            "invalid_grant",
            "The authorization code is invalid.",
        ));
    }
    let scopes = authorized_code_exchange_scopes(
        transaction,
        row.authorization_request_id,
        row.consent_grant_id,
        client.application_id,
    )
    .await?;
    sqlx::query("UPDATE iam.oauth_authorization_codes SET consumed_at = transaction_timestamp() WHERE id = $1")
        .bind(row.code_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("authorization_code_consume"))?;
    sqlx::query("UPDATE iam.oauth_authorization_requests SET status = 'consumed' WHERE id = $1")
        .bind(row.authorization_request_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("authorization_request_consume"))?;
    let nonce = match (&row.oidc_nonce_ciphertext, &row.oidc_nonce_encryption_nonce) {
        (Some(ciphertext), Some(nonce)) => Some(decrypt_protocol_value(
            state,
            row.authorization_request_id,
            row.encryption_key_version,
            nonce,
            ciphertext,
        )?),
        _ => None,
    };
    let response = issue_tokens(
        transaction,
        state,
        client,
        TokenSubject {
            session_id: row.authentication_session_id,
            principal_id: row.subject_principal_id,
            subject_kind: row.subject_kind,
            subject_auth_epoch: row.subject_auth_epoch,
            organization_id: row.organization_id,
            membership_id: row.membership_id,
            membership_authz_epoch: row.membership_authz_epoch,
            consent_grant_id: row.consent_grant_id,
            authenticated_at: row.authenticated_at,
        },
        &scopes,
        nonce.as_deref(),
        None,
        None,
    )
    .await?;
    events::authentication_event(
        transaction,
        client.application_id,
        Some(row.subject_principal_id),
        Some(response.actor.actor_type.as_str()),
        Some(row.authentication_session_id),
        "oauth.token_exchange",
        "success",
        None,
        json!({ "grant_type": "authorization_code", "scope_count": scopes.len() }),
    )
    .await?;
    Ok(response)
}

async fn lock_current_application_client(
    transaction: &mut Transaction<'_, Postgres>,
    client: &ApplicationClient,
) -> Result<bool, ApiError> {
    let locked = sqlx::query_scalar::<_, Uuid>(CURRENT_APPLICATION_CLIENT_LOCK_QUERY)
        .bind(client.application_id)
        .bind(client.auth_epoch)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_client_authority_lock"))?;
    Ok(locked.is_some())
}

async fn exchange_refresh_token(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
    form: &TokenForm,
) -> Result<RefreshExchange, ApiError> {
    let raw = form
        .refresh_token
        .as_ref()
        .filter(|value| value.starts_with("ort_") && value.len() == 47)
        .ok_or_else(invalid_refresh_grant)?;
    let supplied = SecretString::from(raw.to_owned());
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::OAuthRefreshToken, &supplied)
        .map_err(|_| ApiError::internal("refresh_token_digest"))?;
    let versions = digests
        .iter()
        .map(SecretDigest::key_version)
        .collect::<Vec<_>>();
    let bytes = digests
        .iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let candidate =
        load_refresh_candidate(transaction, client.application_id, versions, bytes).await?;
    let expected = SecretDigest::from_parts(candidate.digest_key_version, &candidate.token_digest)
        .ok_or_else(|| ApiError::internal("refresh_token_shape"))?;
    if !state
        .crypto
        .verify_secret(DigestPurpose::OAuthRefreshToken, &supplied, expected)
        .map_err(|_| ApiError::internal("refresh_token_verify"))?
    {
        return Err(invalid_refresh_grant());
    }

    // Keep this order aligned with lifecycle and consent revocation: app,
    // subject/session, optional membership, consent, then credential family.
    let application_current = lock_current_application_client(transaction, client).await?;
    let session_authority = lock_refresh_session_authority(transaction, &candidate).await?;
    let membership_authority = lock_refresh_membership_authority(transaction, &candidate).await?;
    let grant_authority =
        lock_refresh_grant_authority(transaction, candidate.consent_grant_id).await?;
    let credential =
        lock_refresh_credential(transaction, client.application_id, &candidate).await?;

    let locked_expected =
        SecretDigest::from_parts(credential.digest_key_version, &credential.token_digest)
            .ok_or_else(|| ApiError::internal("refresh_token_locked_shape"))?;
    if !state
        .crypto
        .verify_secret(DigestPurpose::OAuthRefreshToken, &supplied, locked_expected)
        .map_err(|_| ApiError::internal("refresh_token_locked_verify"))?
    {
        return Err(invalid_refresh_grant());
    }
    if credential.consumed_at.is_some() {
        compromise_refresh_family(
            transaction,
            candidate.family_id,
            candidate.authentication_session_id,
            client.application_id,
        )
        .await?;
        protocol_event(
            transaction,
            client,
            "oauth.refresh.reuse_detected",
            "refresh_token_family",
            candidate.family_id,
            "oauth.refresh_family_compromised",
            json!({
                "family_id": candidate.family_id,
                "reused_token_id": candidate.token_id,
            }),
        )
        .await?;
        events::authentication_event(
            transaction,
            client.application_id,
            Some(candidate.subject_principal_id),
            Some(candidate.subject_kind.as_str()),
            Some(candidate.authentication_session_id),
            "oauth.token_exchange",
            "failure",
            Some("refresh_token_reuse"),
            json!({
                "grant_type": "refresh_token",
                "family_id": candidate.family_id,
            }),
        )
        .await?;
        return Ok(RefreshExchange::ReuseDetected);
    }
    if credential.revoked_at.is_some()
        || !credential.token_unexpired
        || credential.family_status != "active"
        || !credential.family_unexpired
        || !application_current
        || session_authority.is_none()
        || !membership_authority.current
        || !refresh_grant_authority_is_current(
            grant_authority.as_ref(),
            client.application_id,
            &candidate,
        )
    {
        return Err(invalid_refresh_grant());
    }
    let scopes = locked_refresh_issuance_scopes(
        transaction,
        candidate.family_id,
        candidate.consent_grant_id,
        client.application_id,
    )
    .await?;
    let session_authority = session_authority.ok_or_else(invalid_refresh_grant)?;
    let response = issue_tokens(
        transaction,
        state,
        client,
        TokenSubject {
            session_id: candidate.authentication_session_id,
            principal_id: candidate.subject_principal_id,
            subject_kind: candidate.subject_kind,
            subject_auth_epoch: session_authority.subject_auth_epoch,
            organization_id: candidate.organization_id,
            membership_id: candidate.membership_id,
            membership_authz_epoch: membership_authority.authz_epoch,
            consent_grant_id: candidate.consent_grant_id,
            authenticated_at: session_authority.authenticated_at,
        },
        &scopes,
        None,
        Some(candidate.family_id),
        Some(candidate.token_id),
    )
    .await?;
    events::authentication_event(
        transaction,
        client.application_id,
        Some(candidate.subject_principal_id),
        Some(response.actor.actor_type.as_str()),
        Some(candidate.authentication_session_id),
        "oauth.token_exchange",
        "success",
        None,
        json!({ "grant_type": "refresh_token", "scope_count": scopes.len() }),
    )
    .await?;
    Ok(RefreshExchange::Issued(Box::new(response)))
}

async fn load_refresh_candidate(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    digest_versions: Vec<i16>,
    digests: Vec<Vec<u8>>,
) -> Result<RefreshCandidateRow, ApiError> {
    sqlx::query_as::<_, RefreshCandidateRow>(REFRESH_TOKEN_CANDIDATE_QUERY)
        .bind(digest_versions)
        .bind(digests)
        .bind(application_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("refresh_token_candidate_lookup"))?
        .ok_or_else(invalid_refresh_grant)
}

async fn lock_refresh_session_authority(
    transaction: &mut Transaction<'_, Postgres>,
    candidate: &RefreshCandidateRow,
) -> Result<Option<RefreshSessionAuthorityRow>, ApiError> {
    sqlx::query_as::<_, RefreshSessionAuthorityRow>(REFRESH_SESSION_AUTHORITY_LOCK_QUERY)
        .bind(candidate.subject_principal_id)
        .bind(candidate.authentication_session_id)
        .bind(&candidate.subject_kind)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("refresh_session_authority_lock"))
}

struct RefreshMembershipAuthority {
    current: bool,
    authz_epoch: Option<i64>,
}

async fn lock_refresh_membership_authority(
    transaction: &mut Transaction<'_, Postgres>,
    candidate: &RefreshCandidateRow,
) -> Result<RefreshMembershipAuthority, ApiError> {
    let (Some(organization_id), Some(membership_id)) =
        (candidate.organization_id, candidate.membership_id)
    else {
        return Ok(RefreshMembershipAuthority {
            current: candidate.organization_id.is_none() && candidate.membership_id.is_none(),
            authz_epoch: None,
        });
    };
    let authz_epoch = sqlx::query_scalar::<_, i64>(REFRESH_MEMBERSHIP_AUTHORITY_LOCK_QUERY)
        .bind(organization_id)
        .bind(membership_id)
        .bind(candidate.subject_principal_id)
        .bind(&candidate.subject_kind)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("refresh_membership_authority_lock"))?;
    Ok(RefreshMembershipAuthority {
        current: authz_epoch.is_some(),
        authz_epoch,
    })
}

async fn lock_refresh_grant_authority(
    transaction: &mut Transaction<'_, Postgres>,
    consent_grant_id: Uuid,
) -> Result<Option<RefreshGrantAuthorityRow>, ApiError> {
    sqlx::query_as::<_, RefreshGrantAuthorityRow>(REFRESH_GRANT_AUTHORITY_LOCK_QUERY)
        .bind(consent_grant_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("refresh_grant_authority_lock"))
}

async fn lock_refresh_credential(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    candidate: &RefreshCandidateRow,
) -> Result<LockedRefreshCredentialRow, ApiError> {
    sqlx::query_as::<_, LockedRefreshCredentialRow>(REFRESH_CREDENTIAL_LOCK_QUERY)
        .bind(candidate.token_id)
        .bind(candidate.family_id)
        .bind(application_id)
        .bind(candidate.authentication_session_id)
        .bind(candidate.subject_principal_id)
        .bind(candidate.consent_grant_id)
        .bind(candidate.digest_key_version)
        .bind(candidate.token_digest.as_slice())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("refresh_credential_lock"))?
        .ok_or_else(invalid_refresh_grant)
}

fn refresh_grant_authority_is_current(
    authority: Option<&RefreshGrantAuthorityRow>,
    application_id: Uuid,
    candidate: &RefreshCandidateRow,
) -> bool {
    authority.is_some_and(|grant| {
        grant.application_id == application_id
            && grant.subject_principal_id == candidate.subject_principal_id
            && grant.subject_kind == candidate.subject_kind
            && grant.organization_id == candidate.organization_id
            && grant.membership_id == candidate.membership_id
            && grant.parent_authentication_session_id == candidate.authentication_session_id
            && grant.status == "active"
    })
}

async fn locked_refresh_issuance_scopes(
    transaction: &mut Transaction<'_, Postgres>,
    family_id: Uuid,
    consent_grant_id: Uuid,
    application_id: Uuid,
) -> Result<Vec<String>, ApiError> {
    let scopes = sqlx::query_scalar::<_, String>(REFRESH_ISSUANCE_SCOPES_QUERY)
        .bind(family_id)
        .bind(consent_grant_id)
        .bind(application_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("refresh_issuance_scopes_lock"))?;
    if scopes.is_empty() {
        return Err(invalid_refresh_grant());
    }
    Ok(scopes)
}

fn invalid_refresh_grant() -> ApiError {
    ApiError::bad_request("invalid_grant", "The refresh token is invalid.")
}

struct TokenSubject {
    session_id: Uuid,
    principal_id: Uuid,
    subject_kind: String,
    subject_auth_epoch: i64,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    membership_authz_epoch: Option<i64>,
    consent_grant_id: Uuid,
    authenticated_at: OffsetDateTime,
}

async fn issue_tokens(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
    subject: TokenSubject,
    scopes: &[String],
    nonce: Option<&str>,
    existing_family_id: Option<Uuid>,
    parent_refresh_id: Option<Uuid>,
) -> Result<TokenResponse, ApiError> {
    let actor_type = match subject.subject_kind.as_str() {
        "carbon" => ActorType::Carbon,
        "silicon" => ActorType::Silicon,
        _ => return Err(ApiError::internal("oauth_subject_kind")),
    };
    let access_id = Uuid::now_v7();
    let raw_access = state
        .crypto
        .generate_secret(SecretKind::ApplicationAccessToken)
        .map_err(|_| ApiError::internal("oauth_access_generate"))?;
    let access_digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationAccessToken, &raw_access)
        .map_err(|_| ApiError::internal("oauth_access_digest"))?;
    let access_seconds = i64::try_from(state.settings.security.access_token_ttl.as_secs())
        .map_err(|_| ApiError::internal("oauth_access_ttl"))?;
    sqlx::query(
        r"
        INSERT INTO iam.access_tokens (
            id, token_class, token_digest, digest_key_version, token_prefix,
            authentication_session_id, subject_principal_id, subject_kind,
            client_application_id, audience, audience_application_id,
            organization_id, membership_id, subject_auth_epoch,
            membership_authz_epoch, client_auth_epoch, expires_at
        ) VALUES (
            $1, 'application_access', $2, $3, $4, $5, $6,
            $7::iam.principal_kind, $8, $9, $8, $10, $11, $12, $13, $14,
            transaction_timestamp() + ($15::bigint * interval '1 second')
        )
        ",
    )
    .bind(access_id)
    .bind(access_digest.as_bytes().as_slice())
    .bind(access_digest.key_version())
    .bind(
        raw_access
            .expose_secret()
            .chars()
            .take(12)
            .collect::<String>(),
    )
    .bind(subject.session_id)
    .bind(subject.principal_id)
    .bind(&subject.subject_kind)
    .bind(client.application_id)
    .bind(&client.app_id)
    .bind(subject.organization_id)
    .bind(subject.membership_id)
    .bind(subject.subject_auth_epoch)
    .bind(subject.membership_authz_epoch)
    .bind(client.auth_epoch)
    .bind(access_seconds)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("oauth_access_insert"))?;
    for scope in scopes {
        sqlx::query("INSERT INTO iam.access_token_scopes (access_token_id, scope) VALUES ($1, $2)")
            .bind(access_id)
            .bind(scope)
            .execute(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("oauth_access_scope_insert"))?;
    }
    let family_id = existing_family_id.unwrap_or_else(Uuid::now_v7);
    if existing_family_id.is_none() {
        let family_seconds = i64::try_from(state.settings.security.refresh_family_ttl.as_secs())
            .map_err(|_| ApiError::internal("oauth_refresh_family_ttl"))?;
        sqlx::query(
            r"
            INSERT INTO iam.refresh_token_families (
                id, authentication_session_id, subject_principal_id,
                client_application_id, oauth_consent_grant_id,
                absolute_expires_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                transaction_timestamp() + ($6::bigint * interval '1 second')
            )
            ",
        )
        .bind(family_id)
        .bind(subject.session_id)
        .bind(subject.principal_id)
        .bind(client.application_id)
        .bind(subject.consent_grant_id)
        .bind(family_seconds)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_refresh_family_insert"))?;
        for scope in scopes {
            sqlx::query(
                r"
                INSERT INTO iam.oauth_refresh_family_scopes (
                    family_id, consent_grant_id, scope
                ) VALUES ($1, $2, $3)
                ",
            )
            .bind(family_id)
            .bind(subject.consent_grant_id)
            .bind(scope)
            .execute(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("oauth_refresh_scope_snapshot"))?;
        }
    }
    let refresh_id = Uuid::now_v7();
    let raw_refresh = state
        .crypto
        .generate_secret(SecretKind::OAuthRefreshToken)
        .map_err(|_| ApiError::internal("oauth_refresh_generate"))?;
    let refresh_digest = state
        .crypto
        .digest_secret(DigestPurpose::OAuthRefreshToken, &raw_refresh)
        .map_err(|_| ApiError::internal("oauth_refresh_digest"))?;
    sqlx::query(
        r"
        INSERT INTO iam.refresh_tokens (
            id, family_id, parent_token_id, token_digest,
            digest_key_version, token_prefix, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            LEAST(
                transaction_timestamp() + interval '30 days',
                (SELECT absolute_expires_at FROM iam.refresh_token_families WHERE id = $2)
            )
        )
        ",
    )
    .bind(refresh_id)
    .bind(family_id)
    .bind(parent_refresh_id)
    .bind(refresh_digest.as_bytes().as_slice())
    .bind(refresh_digest.key_version())
    .bind(
        raw_refresh
            .expose_secret()
            .chars()
            .take(12)
            .collect::<String>(),
    )
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("oauth_refresh_insert"))?;
    if let Some(parent_id) = parent_refresh_id {
        let result = sqlx::query(
            r"
            UPDATE iam.refresh_tokens
            SET consumed_at = transaction_timestamp(), replacement_token_id = $2
            WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
            ",
        )
        .bind(parent_id)
        .bind(refresh_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_refresh_consume"))?;
        if result.rows_affected() != 1 {
            return Err(ApiError::internal("oauth_refresh_consume_invariant"));
        }
    }
    let refresh_token = raw_refresh.expose_secret().to_owned();
    let org_id = if let Some(organization_id) = subject.organization_id {
        sqlx::query_scalar::<_, String>("SELECT org_id FROM iam.organizations WHERE id = $1")
            .bind(organization_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| ApiError::internal("oauth_token_org_id"))?
    } else {
        None
    };
    let id_token = if scopes.iter().any(|scope| scope == "openid") {
        Some(
            sign_id_token(
                transaction,
                state,
                client,
                &subject,
                nonce,
                org_id.as_deref(),
            )
            .await?,
        )
    } else {
        None
    };
    let actor_public_id = match actor_type {
        ActorType::Carbon => {
            sqlx::query_scalar::<_, String>("SELECT carbon_id FROM iam.carbons WHERE id = $1")
                .bind(subject.principal_id)
                .fetch_one(&mut **transaction)
                .await
                .map_err(|_| ApiError::internal("oauth_carbon_public_id"))?
        }
        ActorType::Silicon => sqlx::query_scalar::<_, String>(
            "SELECT global_silicon_id FROM iam.silicons WHERE id = $1",
        )
        .bind(subject.principal_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_silicon_public_id"))?,
        ActorType::Application | ActorType::Service => {
            return Err(ApiError::internal("oauth_subject_kind"));
        }
    };
    protocol_event(
        transaction,
        client,
        "oauth.token.issue",
        "access_token",
        access_id,
        "oauth.token_issued",
        json!({
            "token_id": access_id,
            "subject_id": subject.principal_id,
            "organization_id": subject.organization_id,
            "scope_count": scopes.len(),
        }),
    )
    .await?;
    Ok(TokenResponse {
        access_token: raw_access.expose_secret().to_owned(),
        token_type: "Bearer".to_owned(),
        expires_in: u64::try_from(access_seconds).unwrap_or(900),
        scope: scopes.join(" "),
        id_token,
        refresh_token,
        actor: PublicActor {
            principal_id: subject.principal_id,
            actor_type: actor_type.as_str().to_owned(),
            public_id: actor_public_id,
        },
        org_id,
    })
}

fn refresh_reuse_error() -> ApiError {
    ApiError::bad_request(
        "invalid_grant",
        "Refresh-token reuse was detected and the family was revoked.",
    )
}

async fn sign_id_token(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
    subject: &TokenSubject,
    nonce: Option<&str>,
    org_id: Option<&str>,
) -> Result<String, ApiError> {
    let key = sqlx::query_as::<_, ActiveSigningKey>(
        r"
        SELECT id, key_id, algorithm, private_key_ciphertext,
               private_key_nonce, encryption_key_version
        FROM iam.oidc_signing_keys
        WHERE status = 'active' AND not_before <= transaction_timestamp()
        ORDER BY created_at DESC LIMIT 1
        ",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("oidc_signing_key_read"))?
    .ok_or_else(|| ApiError::internal("oidc_signing_key_missing"))?;
    let nonce_bytes = <[u8; 12]>::try_from(key.private_key_nonce.as_slice())
        .map_err(|_| ApiError::internal("oidc_signing_key_nonce"))?;
    let private = state
        .crypto
        .decrypt(
            EncryptionContext::global(ProtectedField::OidcSigningPrivateKey, key.id),
            &EncryptedValue {
                key_version: key.encryption_key_version,
                nonce: nonce_bytes,
                ciphertext: key.private_key_ciphertext,
            },
        )
        .map_err(|_| ApiError::internal("oidc_signing_key_decrypt"))?;
    let (algorithm, encoding_key) = match key.algorithm.as_str() {
        "EdDSA" => (Algorithm::EdDSA, EncodingKey::from_ed_der(&private)),
        "ES256" => (Algorithm::ES256, EncodingKey::from_ec_der(&private)),
        "RS256" => (Algorithm::RS256, EncodingKey::from_rsa_der(&private)),
        _ => return Err(ApiError::internal("oidc_signing_algorithm")),
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = build_id_token_claims(
        base_url(state),
        client.app_id.clone(),
        subject,
        nonce,
        org_id,
        now,
    );
    let mut header = Header::new(algorithm);
    header.kid = Some(key.key_id);
    header.typ = Some("JWT".to_owned());
    encode(&header, &claims, &encoding_key).map_err(|_| ApiError::internal("oidc_id_token_sign"))
}

fn build_id_token_claims(
    issuer: String,
    audience: String,
    subject: &TokenSubject,
    nonce: Option<&str>,
    org_id: Option<&str>,
    now: i64,
) -> IdTokenClaims {
    IdTokenClaims {
        iss: issuer,
        sub: subject.principal_id.to_string(),
        aud: audience,
        exp: now + 900,
        iat: now,
        auth_time: subject.authenticated_at.unix_timestamp(),
        sid: subject.session_id.to_string(),
        nonce: nonce.map(ToOwned::to_owned),
        org_id: org_id.map(ToOwned::to_owned),
    }
}

async fn approve_request(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    request: &AuthorizationRequestRow,
) -> Result<String, ApiError> {
    let scopes = authorization_request_scopes(transaction, request.id).await?;
    let grant_id = Uuid::now_v7();
    let grant = sqlx::query_as::<_, (Uuid, i64)>(
        r"
        INSERT INTO iam.oauth_consent_grants (
            id, application_id, subject_principal_id, subject_kind,
            organization_id, membership_id, parent_authentication_session_id
        ) VALUES ($1, $2, $3, $4::iam.principal_kind, $5, $6, $7)
        ON CONFLICT (application_id, subject_principal_id, organization_id)
            DO UPDATE SET
                status = 'active', membership_id = EXCLUDED.membership_id,
                parent_authentication_session_id = EXCLUDED.parent_authentication_session_id,
                revoked_at = NULL
        RETURNING id, version
        ",
    )
    .bind(grant_id)
    .bind(request.application_id)
    .bind(request.subject_principal_id)
    .bind(&request.subject_kind)
    .bind(request.organization_id)
    .bind(request.membership_id)
    .bind(request.authentication_session_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("oauth_consent_grant_upsert"))?;
    sqlx::query("DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id = $1")
        .bind(grant.0)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_consent_scope_clear"))?;
    for scope in &scopes {
        sqlx::query(
            "INSERT INTO iam.oauth_consent_grant_scopes (consent_grant_id, scope) VALUES ($1, $2)",
        )
        .bind(grant.0)
        .bind(scope)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_consent_scope_insert"))?;
    }
    let result = sqlx::query(
        r"
        UPDATE iam.oauth_authorization_requests
        SET status = 'approved', decided_at = transaction_timestamp()
        WHERE id = $1 AND status = 'pending' AND expires_at > transaction_timestamp()
        ",
    )
    .bind(request.id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("oauth_request_approve"))?;
    if result.rows_affected() != 1 {
        return Err(ApiError::conflict("authorization_request_already_decided"));
    }
    let raw_code = state
        .crypto
        .generate_secret(SecretKind::AuthorizationCode)
        .map_err(|_| ApiError::internal("authorization_code_generate"))?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::AuthorizationCode, &raw_code)
        .map_err(|_| ApiError::internal("authorization_code_digest"))?;
    let ttl = i64::try_from(state.settings.security.authorization_code_ttl.as_secs())
        .map_err(|_| ApiError::internal("authorization_code_ttl"))?;
    sqlx::query(
        r"
        INSERT INTO iam.oauth_authorization_codes (
            id, authorization_request_id, application_id, code_digest,
            digest_key_version, code_prefix, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            transaction_timestamp() + ($7::bigint * interval '1 second')
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(request.id)
    .bind(request.application_id)
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .bind(
        raw_code
            .expose_secret()
            .chars()
            .take(12)
            .collect::<String>(),
    )
    .bind(ttl)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("authorization_code_insert"))?;
    let state_value = decrypt_protocol_value(
        state,
        request.id,
        request.encryption_key_version,
        &request.state_encryption_nonce,
        &request.state_ciphertext,
    )?;
    append_redirect_parameters(
        &request.redirect_uri,
        &[("code", raw_code.expose_secret()), ("state", &state_value)],
    )
}

async fn load_authorization_request(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    for_update: bool,
) -> Result<AuthorizationRequestRow, ApiError> {
    let request = if for_update {
        sqlx::query_as::<_, AuthorizationRequestRow>(
            r"
            SELECT request.id, request.application_id, redirect.redirect_uri,
                   request.authentication_session_id, request.subject_principal_id,
                   request.subject_kind::text AS subject_kind,
                   request.organization_id, request.membership_id,
                   request.state_ciphertext, request.state_encryption_nonce,
                   request.encryption_key_version,
                   request.status, request.expires_at
            FROM iam.oauth_authorization_requests AS request
            JOIN iam.application_redirect_uris AS redirect
              ON redirect.id = request.redirect_uri_id
            WHERE request.id = $1
            FOR UPDATE OF request
            ",
        )
        .bind(request_id)
        .fetch_optional(&mut **transaction)
        .await
    } else {
        sqlx::query_as::<_, AuthorizationRequestRow>(
            r"
            SELECT request.id, request.application_id, redirect.redirect_uri,
                   request.authentication_session_id, request.subject_principal_id,
                   request.subject_kind::text AS subject_kind,
                   request.organization_id, request.membership_id,
                   request.state_ciphertext, request.state_encryption_nonce,
                   request.encryption_key_version,
                   request.status, request.expires_at
            FROM iam.oauth_authorization_requests AS request
            JOIN iam.application_redirect_uris AS redirect
              ON redirect.id = request.redirect_uri_id
            WHERE request.id = $1
            ",
        )
        .bind(request_id)
        .fetch_optional(&mut **transaction)
        .await
    };
    request
        .map_err(|_| ApiError::internal("authorization_request_read"))?
        .ok_or_else(ApiError::not_found)
}

async fn authorization_request_scopes(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<Vec<String>, ApiError> {
    sqlx::query_scalar::<_, String>(
        r"
        SELECT scope FROM iam.oauth_authorization_request_scopes
        WHERE authorization_request_id = $1 ORDER BY scope
        ",
    )
    .bind(request_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("authorization_request_scopes"))
}

pub(super) async fn authorized_code_exchange_scopes(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    consent_grant_id: Uuid,
    application_id: Uuid,
) -> Result<Vec<String>, ApiError> {
    // The caller holds the authorization-request and consent-grant row locks.
    // Request scopes are immutable while that request exists, and every
    // consent-scope replacement first locks its grant. Lock the remaining
    // independently mutable authority: the active platform approval rows.
    let requested = authorization_request_scopes(transaction, request_id).await?;
    let currently_authorized = sqlx::query_scalar::<_, String>(CODE_EXCHANGE_ACTIVE_SCOPES_QUERY)
        .bind(request_id)
        .bind(consent_grant_id)
        .bind(application_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("authorization_code_scope_authority"))?;
    if !scopes_retain_exact_authority(&requested, &currently_authorized) {
        return Err(ApiError::bad_request(
            "invalid_grant",
            "The authorization code is invalid.",
        ));
    }
    Ok(requested)
}

fn scopes_retain_exact_authority(requested: &[String], currently_authorized: &[String]) -> bool {
    requested == currently_authorized
}

async fn active_consent_scopes(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    subject_id: Uuid,
    organization_id: Option<Uuid>,
) -> Result<Vec<String>, ApiError> {
    sqlx::query_scalar::<_, String>(
        r"
        SELECT scope.scope
        FROM iam.oauth_consent_grants AS grant
        JOIN iam.oauth_consent_grant_scopes AS scope ON scope.consent_grant_id = grant.id
        JOIN iam.application_approved_scopes AS approved
          ON approved.application_id = grant.application_id
         AND approved.scope = scope.scope AND approved.revoked_at IS NULL
        WHERE grant.application_id = $1 AND grant.subject_principal_id = $2
          AND grant.organization_id IS NOT DISTINCT FROM $3 AND grant.status = 'active'
        ORDER BY scope.scope
        ",
    )
    .bind(application_id)
    .bind(subject_id)
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("active_consent_scopes"))
}

async fn refresh_family_scopes(
    transaction: &mut Transaction<'_, Postgres>,
    family_id: Uuid,
    consent_grant_id: Uuid,
) -> Result<Vec<String>, ApiError> {
    sqlx::query_scalar::<_, String>(
        r"
        SELECT snapshot.scope
        FROM iam.oauth_refresh_family_scopes AS snapshot
        JOIN iam.refresh_token_families AS family
          ON family.id = snapshot.family_id
         AND family.oauth_consent_grant_id = snapshot.consent_grant_id
        JOIN iam.oauth_consent_grants AS grant
          ON grant.id = snapshot.consent_grant_id
         AND grant.status = 'active'
        JOIN iam.oauth_consent_grant_scopes AS consent_scope
          ON consent_scope.consent_grant_id = grant.id
         AND consent_scope.scope = snapshot.scope
        JOIN iam.application_approved_scopes AS approved
          ON approved.application_id = grant.application_id
         AND approved.scope = snapshot.scope
         AND approved.revoked_at IS NULL
        WHERE snapshot.family_id = $1
          AND snapshot.consent_grant_id = $2
          AND family.status = 'active'
        ORDER BY snapshot.scope
        ",
    )
    .bind(family_id)
    .bind(consent_grant_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("oauth_refresh_family_scopes"))
}

async fn consent_covers(
    transaction: &mut Transaction<'_, Postgres>,
    application_id: Uuid,
    subject_id: Uuid,
    organization_id: Option<Uuid>,
    requested: &[String],
) -> Result<bool, ApiError> {
    let granted = active_consent_scopes(transaction, application_id, subject_id, organization_id)
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
    Ok(requested.iter().all(|scope| granted.contains(scope)))
}

async fn revoke_access_token(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
    supplied: &SecretString,
) -> Result<Option<Uuid>, ApiError> {
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::ApplicationAccessToken, supplied)
        .map_err(|_| ApiError::internal("revoke_access_digest"))?;
    let versions = digests
        .iter()
        .map(SecretDigest::key_version)
        .collect::<Vec<_>>();
    let bytes = digests
        .iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();
    sqlx::query_scalar::<_, Uuid>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        UPDATE iam.access_tokens AS token
        SET revoked_at = transaction_timestamp(), revocation_reason = 'client_revoked'
        FROM supplied_digest
        WHERE token.digest_key_version = supplied_digest.key_version
          AND token.token_digest = supplied_digest.digest
          AND token.client_application_id = $3 AND token.revoked_at IS NULL
        RETURNING token.id
        ",
    )
    .bind(versions)
    .bind(bytes)
    .bind(client.application_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("revoke_access_token"))
}

async fn revoke_refresh_family(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
    supplied: &SecretString,
) -> Result<Option<Uuid>, ApiError> {
    let digests = state
        .crypto
        .digest_secrets(DigestPurpose::OAuthRefreshToken, supplied)
        .map_err(|_| ApiError::internal("revoke_refresh_digest"))?;
    let versions = digests
        .iter()
        .map(SecretDigest::key_version)
        .collect::<Vec<_>>();
    let bytes = digests
        .iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let family_id = sqlx::query_scalar::<_, Uuid>(
        r"
        WITH supplied_digest (key_version, digest) AS (
            SELECT * FROM unnest($1::smallint[], $2::bytea[])
        )
        SELECT family.id
        FROM supplied_digest
        JOIN iam.refresh_tokens AS refresh
          ON refresh.digest_key_version = supplied_digest.key_version
         AND refresh.token_digest = supplied_digest.digest
        JOIN iam.refresh_token_families AS family ON family.id = refresh.family_id
        WHERE family.client_application_id = $3
        FOR UPDATE OF family
        ",
    )
    .bind(versions)
    .bind(bytes)
    .bind(client.application_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("revoke_refresh_lookup"))?;
    if let Some(family_id) = family_id {
        sqlx::query(
            r"
            UPDATE iam.refresh_token_families
            SET status = 'revoked', revoked_at = transaction_timestamp(),
                revocation_reason = 'client_revoked'
            WHERE id = $1 AND status = 'active'
            ",
        )
        .bind(family_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("revoke_refresh_family"))?;
    }
    Ok(family_id)
}

async fn compromise_refresh_family(
    transaction: &mut Transaction<'_, Postgres>,
    family_id: Uuid,
    authentication_session_id: Uuid,
    client_application_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'compromised', compromised_at = transaction_timestamp(),
            revocation_reason = 'refresh_token_reuse'
        WHERE id = $1 AND status = 'active'
        ",
    )
    .bind(family_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("refresh_family_compromise"))?;
    sqlx::query(
        r"
        UPDATE iam.refresh_tokens
        SET revoked_at = COALESCE(revoked_at, transaction_timestamp())
        WHERE family_id = $1
        ",
    )
    .bind(family_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("refresh_family_tokens_revoke"))?;
    sqlx::query(REFRESH_REUSE_ACCESS_REVOCATION_QUERY)
        .bind(authentication_session_id)
        .bind(client_application_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("refresh_reuse_access_revoke"))?;
    Ok(())
}

async fn protocol_event(
    transaction: &mut Transaction<'_, Postgres>,
    client: &ApplicationClient,
    action: &'static str,
    target_type: &'static str,
    target_id: Uuid,
    event_type: &'static str,
    payload: Value,
) -> Result<(), ApiError> {
    let aggregate = AggregateVersion {
        aggregate_type: target_type,
        aggregate_id: target_id,
        version: 1,
    };
    persistence_events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: ActorType::Application,
                id: client.application_id,
            }),
            authentication_session_id: None,
            organization_id: None,
            application_id: Some(client.application_id),
            action,
            target_type,
            target_id: Some(target_id),
            authentication_method: Some("application_secret"),
            aggregate: Some(aggregate),
            before_state: None,
            after_state: None,
            metadata: payload.clone(),
        },
    )
    .await
    .map_err(|_| ApiError::internal("oauth_audit"))?;
    persistence_events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: None,
            aggregate,
            event_ordinal: 1,
            event_type,
            schema_version: 1,
            payload,
        },
    )
    .await
    .map_err(|_| ApiError::internal("oauth_outbox"))?;
    Ok(())
}

fn decrypt_protocol_value(
    state: &ApiState,
    request_id: Uuid,
    key_version: i16,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<String, ApiError> {
    let nonce =
        <[u8; 12]>::try_from(nonce).map_err(|_| ApiError::internal("oauth_protocol_nonce"))?;
    let plaintext = state
        .crypto
        .decrypt(
            EncryptionContext::global(ProtectedField::ProviderCredential, request_id),
            &EncryptedValue {
                key_version,
                nonce,
                ciphertext: ciphertext.to_vec(),
            },
        )
        .map_err(|_| ApiError::internal("oauth_protocol_decrypt"))?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| ApiError::internal("oauth_protocol_utf8"))
}

fn append_redirect_parameters(base: &str, values: &[(&str, &str)]) -> Result<String, ApiError> {
    let mut url = Url::parse(base).map_err(|_| ApiError::internal("redirect_uri_stored"))?;
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in values {
            pairs.append_pair(key, value);
        }
    }
    Ok(url.into())
}

fn redirect_response(location: &str) -> Result<Response, ApiError> {
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location)
            .map_err(|_| ApiError::internal("redirect_location_header"))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn token_response(response: TokenResponse, replayed: bool) -> Response {
    let mut response = Json(response).into_response();
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

fn inactive_introspection() -> IntrospectionResponse {
    IntrospectionResponse {
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

fn validate_token_type_hint(token_type_hint: Option<&str>) -> Result<(), ApiError> {
    if token_type_hint.is_none_or(|hint| matches!(hint, "access_token" | "refresh_token")) {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "invalid_request",
            "The token_type_hint is not supported.",
        ))
    }
}

fn base_url(state: &ApiState) -> String {
    state
        .settings
        .server
        .public_base_url
        .as_str()
        .trim_end_matches('/')
        .to_owned()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use axum::http::header;
    use time::macros::datetime;
    use uuid::Uuid;

    use super::{
        AUTHORIZATION_CODE_LOOKUP_QUERY, CODE_EXCHANGE_ACTIVE_SCOPES_QUERY,
        CURRENT_APPLICATION_CLIENT_LOCK_QUERY, REFRESH_CREDENTIAL_LOCK_QUERY,
        REFRESH_GRANT_AUTHORITY_LOCK_QUERY, REFRESH_ISSUANCE_SCOPES_QUERY,
        REFRESH_MEMBERSHIP_AUTHORITY_LOCK_QUERY, REFRESH_REUSE_ACCESS_REVOCATION_QUERY,
        REFRESH_SESSION_AUTHORITY_LOCK_QUERY, REFRESH_TOKEN_CANDIDATE_QUERY, TokenSubject,
        append_redirect_parameters, build_id_token_claims, consent_html_response, escape_html,
        scopes_retain_exact_authority,
    };

    #[test]
    fn redirects_preserve_existing_query_and_encode_protocol_values() {
        let location = append_redirect_parameters(
            "https://client.example/cb?tenant=one",
            &[("code", "a+b"), ("state", "x&y")],
        );
        assert_eq!(
            location.ok().as_deref(),
            Some("https://client.example/cb?tenant=one&code=a%2Bb&state=x%26y")
        );
    }

    #[test]
    fn consent_html_escapes_application_control_characters() {
        assert_eq!(
            escape_html("<app & \"owner\">"),
            "&lt;app &amp; &quot;owner&quot;&gt;"
        );
    }

    #[test]
    fn consent_html_is_non_cacheable_and_scriptless() {
        let response = consent_html_response("<!doctype html>".to_owned());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&http::HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            response.headers().get(header::PRAGMA),
            Some(&http::HeaderValue::from_static("no-cache"))
        );
        assert_eq!(
            response
                .headers()
                .get(http::HeaderName::from_static("x-content-type-options")),
            Some(&http::HeaderValue::from_static("nosniff"))
        );
        let policy = response
            .headers()
            .get(http::HeaderName::from_static("content-security-policy"))
            .and_then(|value| value.to_str().ok());
        assert!(policy.is_some_and(|value| {
            value.contains("default-src 'none'")
                && value.contains("frame-ancestors 'none'")
                && value.contains("base-uri 'none'")
        }));
    }

    #[test]
    fn id_token_auth_time_comes_from_the_parent_authentication_session() {
        let authenticated_at = datetime!(2026-01-01 12:00 UTC);
        let subject = TokenSubject {
            session_id: Uuid::now_v7(),
            principal_id: Uuid::now_v7(),
            subject_kind: "carbon".to_owned(),
            subject_auth_epoch: 1,
            organization_id: None,
            membership_id: None,
            membership_authz_epoch: None,
            consent_grant_id: Uuid::now_v7(),
            authenticated_at,
        };
        let issuance_time = datetime!(2026-01-01 12:05 UTC).unix_timestamp();
        let claims = build_id_token_claims(
            "https://iam.example".to_owned(),
            "example-app".to_owned(),
            &subject,
            Some("nonce"),
            None,
            issuance_time,
        );
        assert_eq!(claims.auth_time, authenticated_at.unix_timestamp());
        assert_ne!(claims.auth_time, claims.iat);
        assert_eq!(claims.sid, subject.session_id.to_string());
        assert_eq!(claims.nonce.as_deref(), Some("nonce"));
    }

    #[test]
    fn authorization_code_lookup_binds_the_current_parent_session_authority() {
        for required_fragment in [
            "principal.status = 'active'",
            "principal.auth_epoch = $2",
            "application.review_status = 'verified'",
            "application.deleted_at IS NULL",
            "FOR SHARE OF application, principal",
        ] {
            assert!(
                CURRENT_APPLICATION_CLIENT_LOCK_QUERY.contains(required_fragment),
                "application-client lock is missing `{required_fragment}`"
            );
        }
        for required_fragment in [
            "session.authenticated_at",
            "session.subject_principal_id = request.subject_principal_id",
            "session.subject_kind = request.subject_kind",
            "session.subject_auth_epoch = principal.auth_epoch",
            "session.status = 'active'",
            "grant.parent_authentication_session_id = request.authentication_session_id",
            "FOR UPDATE OF code, request, grant",
            "FOR SHARE OF principal, session",
        ] {
            assert!(
                AUTHORIZATION_CODE_LOOKUP_QUERY.contains(required_fragment),
                "authorization-code lookup is missing `{required_fragment}`"
            );
        }
    }

    #[test]
    fn authorization_code_scopes_require_exact_current_authority() {
        let requested = vec!["openid".to_owned(), "profile".to_owned()];
        assert!(scopes_retain_exact_authority(&requested, &requested));
        assert!(!scopes_retain_exact_authority(
            &requested,
            &["openid".to_owned()]
        ));
        assert!(!scopes_retain_exact_authority(
            &["openid".to_owned()],
            &requested
        ));
        for required_fragment in [
            "iam.oauth_consent_grant_scopes",
            "iam.application_approved_scopes",
            "approved.revoked_at IS NULL",
            "FOR SHARE OF approved",
        ] {
            assert!(
                CODE_EXCHANGE_ACTIVE_SCOPES_QUERY.contains(required_fragment),
                "authorization-code scope query is missing `{required_fragment}`"
            );
        }
    }

    #[test]
    fn refresh_reuse_revocation_is_bounded_to_the_session_and_client() {
        for required_fragment in [
            "UPDATE iam.access_tokens",
            "revocation_reason = COALESCE(revocation_reason, 'refresh_token_reuse')",
            "authentication_session_id = $1",
            "client_application_id = $2",
        ] {
            assert!(
                REFRESH_REUSE_ACCESS_REVOCATION_QUERY.contains(required_fragment),
                "refresh-reuse containment is missing `{required_fragment}`"
            );
        }
        assert!(!REFRESH_REUSE_ACCESS_REVOCATION_QUERY.contains("authentication_sessions"));
    }

    #[test]
    fn refresh_issuance_revalidates_and_locks_every_authority_layer() {
        for required_fragment in [
            "family.authentication_session_id",
            "family.subject_principal_id",
            "grant.id AS consent_grant_id",
        ] {
            assert!(
                REFRESH_TOKEN_CANDIDATE_QUERY.contains(required_fragment),
                "refresh candidate lookup is missing `{required_fragment}`"
            );
        }
        for required_fragment in [
            "session.subject_principal_id = principal.id",
            "session.subject_kind = principal.kind",
            "session.subject_auth_epoch = principal.auth_epoch",
            "session.status = 'active'",
            "FOR SHARE OF principal, session",
        ] {
            assert!(
                REFRESH_SESSION_AUTHORITY_LOCK_QUERY.contains(required_fragment),
                "refresh session lock is missing `{required_fragment}`"
            );
        }
        for required_fragment in [
            "organization.status = 'active'",
            "membership.principal_id = $3",
            "membership.principal_kind = $4::iam.principal_kind",
            "membership.status = 'active'",
            "FOR SHARE OF organization, membership",
        ] {
            assert!(
                REFRESH_MEMBERSHIP_AUTHORITY_LOCK_QUERY.contains(required_fragment),
                "refresh membership lock is missing `{required_fragment}`"
            );
        }
        for required_fragment in [
            "grant.subject_kind::text AS subject_kind",
            "grant.parent_authentication_session_id",
            "FOR SHARE OF grant",
        ] {
            assert!(
                REFRESH_GRANT_AUTHORITY_LOCK_QUERY.contains(required_fragment),
                "refresh consent lock is missing `{required_fragment}`"
            );
        }
        for required_fragment in [
            "family.authentication_session_id = $4",
            "family.subject_principal_id = $5",
            "family.oauth_consent_grant_id = $6",
            "FOR UPDATE OF refresh, family",
        ] {
            assert!(
                REFRESH_CREDENTIAL_LOCK_QUERY.contains(required_fragment),
                "refresh credential lock is missing `{required_fragment}`"
            );
        }
        for required_fragment in [
            "iam.oauth_refresh_family_scopes",
            "iam.oauth_consent_grant_scopes",
            "iam.application_approved_scopes",
            "approved.revoked_at IS NULL",
            "FOR SHARE OF approved",
        ] {
            assert!(
                REFRESH_ISSUANCE_SCOPES_QUERY.contains(required_fragment),
                "refresh scope lock is missing `{required_fragment}`"
            );
        }
    }
}
