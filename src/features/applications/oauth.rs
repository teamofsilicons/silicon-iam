#![allow(clippy::too_many_arguments, clippy::too_many_lines)]

use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse as _, Response},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::actor::{ActorRef, ActorType},
    infrastructure::{
        crypto::{DigestPurpose, SecretDigest, SecretKind},
        postgres::{
            context::{self, DatabaseContext},
            events::{self as persistence_events, AggregateVersion, AuditRecord, OutboxRecord},
            tokens,
        },
    },
};

use super::{
    error::ApiError,
    events,
    idempotency::{self, Claim},
    model::{
        AppTokenForm, IntrospectionResponse, LoginQuery, LoginStatusQuery, PublicActor,
        ShortLivedTokenRequest, ShortLivedTokenResponse, TokenInput, TokenResponse,
    },
    security::{ApplicationClient, Bearer, BrowserSession},
    validation,
};

const AUTHORIZATION_REQUEST_SECONDS: i64 = 600;
/// How long the page that shows a token waits before reporting its fate.
///
/// UNDERSTANDING.md gives the token two minutes; the page reloads a moment
/// after that so the status it reports is settled rather than racing expiry.
const AUTHORIZATION_CODE_DISPLAY_SECONDS: i64 = 125;

const OAUTH_REFRESH_INSERT_QUERY: &str = r"
    INSERT INTO iam.refresh_tokens (
        id, family_id, parent_token_id, token_digest,
        digest_key_version, token_prefix, expires_at
    ) VALUES (
        $1, $2, $3, $4, $5, $6,
        (SELECT absolute_expires_at FROM iam.refresh_token_families WHERE id = $2)
    )
";

const CURRENT_APPLICATION_CLIENT_LOCK_QUERY: &str = r"
    SELECT iam_private.lock_current_application_client($1, $2)
";

const AUTHORIZATION_CODE_LOOKUP_QUERY: &str = r"
    WITH supplied_digest (key_version, digest) AS (
        SELECT * FROM unnest($1::smallint[], $2::bytea[])
    )
    SELECT code.id AS code_id, code.authorization_request_id,
           code.code_digest, code.digest_key_version,
           request.authentication_session_id,
           request.subject_principal_id, request.subject_kind::text AS subject_kind,
           request.organization_id, request.membership_id,
           consent.id AS consent_grant_id,
           principal.auth_epoch AS subject_auth_epoch,
           membership.authz_epoch AS membership_authz_epoch
    FROM supplied_digest
    JOIN iam.oauth_authorization_codes AS code
      ON code.digest_key_version = supplied_digest.key_version
     AND code.code_digest = supplied_digest.digest
    JOIN iam.oauth_authorization_requests AS request
      ON request.id = code.authorization_request_id
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
    JOIN iam.oauth_consent_grants AS consent
      ON consent.application_id = request.application_id
     AND consent.subject_principal_id = request.subject_principal_id
     AND consent.subject_kind = request.subject_kind
     AND consent.organization_id IS NOT DISTINCT FROM request.organization_id
     AND consent.membership_id IS NOT DISTINCT FROM request.membership_id
     AND consent.parent_authentication_session_id = request.authentication_session_id
     AND consent.status = 'active'
    WHERE code.application_id = $3
      AND code.consumed_at IS NULL
      AND code.expires_at > transaction_timestamp()
      AND request.status = 'approved'
    FOR UPDATE OF code, request, consent
    FOR SHARE OF principal, session
";

const CODE_EXCHANGE_ACTIVE_SCOPES_QUERY: &str = r"
    SELECT request_scope.scope
    FROM iam.oauth_authorization_request_scopes AS request_scope
    JOIN iam.oauth_consent_grant_scopes AS consent_scope
      ON consent_scope.consent_grant_id = $2
     AND consent_scope.scope = request_scope.scope
    JOIN iam_private.locked_application_approved_scopes($3) AS approved
      ON approved.scope = request_scope.scope
    WHERE request_scope.authorization_request_id = $1
      AND request_scope.application_id = $3
    ORDER BY request_scope.scope
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
           consent.organization_id, consent.membership_id,
           consent.id AS consent_grant_id
    FROM supplied_digest
    JOIN iam.refresh_tokens AS refresh
      ON refresh.digest_key_version = supplied_digest.key_version
     AND refresh.token_digest = supplied_digest.digest
    JOIN iam.refresh_token_families AS family
      ON family.id = refresh.family_id
    JOIN iam.principals AS principal
      ON principal.id = family.subject_principal_id
    JOIN iam.oauth_consent_grants AS consent
      ON consent.id = family.oauth_consent_grant_id
    WHERE family.client_application_id = $3
    LIMIT 1
";

const REFRESH_SESSION_AUTHORITY_LOCK_QUERY: &str = r"
    SELECT principal.auth_epoch AS subject_auth_epoch
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
    SELECT consent.application_id, consent.subject_principal_id,
           consent.subject_kind::text AS subject_kind,
           consent.organization_id, consent.membership_id,
           consent.parent_authentication_session_id, consent.status
    FROM iam.oauth_consent_grants AS consent
    WHERE consent.id = $1
    FOR SHARE OF consent
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
    JOIN iam_private.locked_application_approved_scopes($3) AS approved
      ON approved.scope = snapshot.scope
    WHERE snapshot.family_id = $1
      AND snapshot.consent_grant_id = $2
    ORDER BY snapshot.scope
";

#[derive(FromRow)]
struct AuthorizeApplicationRow {
    id: Uuid,
    app_id: String,
    app_name: Option<String>,
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
    authentication_session_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
}

#[derive(FromRow)]
struct AuthorizationCodeRow {
    code_id: Uuid,
    authorization_request_id: Uuid,
    code_digest: Vec<u8>,
    digest_key_version: i16,
    authentication_session_id: Uuid,
    subject_principal_id: Uuid,
    subject_kind: String,
    organization_id: Option<Uuid>,
    membership_id: Option<Uuid>,
    consent_grant_id: Uuid,
    subject_auth_epoch: i64,
    membership_authz_epoch: Option<i64>,
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
#[serde(tag = "outcome", content = "response", rename_all = "snake_case")]
enum TokenIdempotencyResult {
    Issued(Box<TokenResponse>),
    RefreshReuse,
}

enum RefreshExchange {
    Issued(Box<TokenResponse>),
    ReuseDetected,
}

/// Signs the caller in for a configured application and hands back a
/// short-lived token.
///
/// `app_id` is what makes this an application login at all. Without one there
/// is no application waiting for anything, so this is an ordinary Silicon IAM
/// login and the page says so rather than minting a credential nobody asked
/// for.
///
/// `redirect_uri` decides delivery only. Named, the token is appended to it
/// and the browser is sent there. Absent, the token is shown on a page,
/// because there is nowhere to send it and a token the caller cannot read is
/// no use to them.
///
/// There is no consent step and no scope negotiation: the login carries the
/// whole catalogue, and the consent grant is written implicitly so that
/// webhook recipients still resolve.
pub(super) async fn login(
    State(state): State<ApiState>,
    session: BrowserSession,
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    validation::login(&query)?;
    let Some(app_id) = query.app_id.as_deref() else {
        return Ok(login_page(
            "Signed in",
            "You are signed in.",
            "No application asked for this login, so there is no token to hand over.",
            "",
            "Name an app_id in the query to sign in on an application's behalf.",
            None,
        ));
    };
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(session.carbon_id))
        .await
        .map_err(|_| ApiError::internal("login_context"))?;
    let app = sqlx::query_as::<_, AuthorizeApplicationRow>(
        r"
        SELECT application.id, application.app_id, application.app_name
        FROM iam.applications AS application
        JOIN iam.principals AS principal
          ON principal.id = application.id
         AND principal.kind = 'application'
         AND principal.status = 'active'
        WHERE application.app_id = $1
          AND application.review_status = 'verified'
          AND application.deleted_at IS NULL
        ",
    )
    .bind(app_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("login_application"))?
    .ok_or_else(|| ApiError::bad_request("invalid_request", "The application is unknown."))?;
    // "Scope of the login is always everything": the catalogue is the consent.
    let scopes =
        sqlx::query_scalar::<_, String>("SELECT scope FROM iam.oauth_scope_catalog ORDER BY scope")
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("login_scopes"))?;
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
            .map_err(|_| ApiError::internal("login_org"))?
            .ok_or_else(|| ApiError::forbidden("organization_context_forbidden"))?,
        )
    } else {
        None
    };
    let (request_id, token) = mint_short_lived_token(
        &mut transaction,
        &state,
        MintSubject {
            application_id: app.id,
            session_id: session.session_id,
            principal_id: session.carbon_id,
            subject_kind: "carbon",
            organization_id: organization.as_ref().map(|value| value.organization_id),
            membership_id: organization.as_ref().map(|value| value.membership_id),
            redirect_uri: query.redirect_uri.as_deref(),
        },
        &scopes,
    )
    .await?;
    events::authentication_event(
        &mut transaction,
        app.id,
        Some(session.carbon_id),
        Some("carbon"),
        Some(session.session_id),
        "login.short_lived_token",
        "success",
        None,
        json!({ "delivered": query.redirect_uri.is_some(), "scope_count": scopes.len() }),
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("login_commit"))?;
    let display = app.app_name.as_deref().unwrap_or(&app.app_id);
    match query.redirect_uri.as_deref() {
        Some(uri) => {
            let location = append_redirect_parameters(uri, &[("slt", token.expose_secret())])?;
            redirect_response(StatusCode::FOUND, &location, false)
        }
        None => Ok(login_page(
            "Your short-lived token",
            "If requested, this is your short live token.",
            &format!("{display} can exchange it for a session. It is good for a single use."),
            &format!(
                "<div class=\"stack login-intro\"><span class=\"label\">Short-lived token</span><code class=\"login-token\">{}</code></div>",
                escape_html(token.expose_secret())
            ),
            "Nobody will ever ask you for your password or a verification code to complete this. Only this token.",
            Some(request_id),
        )),
    }
}

/// Who a short-lived token is being minted for.
pub(super) struct MintSubject<'a> {
    pub(super) application_id: Uuid,
    pub(super) session_id: Uuid,
    pub(super) principal_id: Uuid,
    pub(super) subject_kind: &'a str,
    pub(super) organization_id: Option<Uuid>,
    pub(super) membership_id: Option<Uuid>,
    pub(super) redirect_uri: Option<&'a str>,
}

/// Records the login and issues the token that completes it.
///
/// Shared by the browser login and by callers who are already signed in, so
/// the two cannot drift on what a login writes.
async fn mint_short_lived_token(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    subject: MintSubject<'_>,
    scopes: &[String],
) -> Result<(Uuid, SecretString), ApiError> {
    let request_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.oauth_authorization_requests (
            id, application_id, redirect_uri, authentication_session_id,
            subject_principal_id, subject_kind, organization_id, membership_id,
            expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6::iam.principal_kind, $7, $8,
            transaction_timestamp() + ($9::bigint * interval '1 second')
        )
        ",
    )
    .bind(request_id)
    .bind(subject.application_id)
    .bind(subject.redirect_uri)
    .bind(subject.session_id)
    .bind(subject.principal_id)
    .bind(subject.subject_kind)
    .bind(subject.organization_id)
    .bind(subject.membership_id)
    .bind(AUTHORIZATION_REQUEST_SECONDS)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ApiError::internal("login_request_insert"))?;
    for scope in scopes {
        sqlx::query(
            r"
            INSERT INTO iam.oauth_authorization_request_scopes (
                authorization_request_id, application_id, scope, approved_at
            )
            SELECT $1, $2, approved.scope, approved.approved_at
            FROM iam.application_approved_scopes AS approved
            WHERE approved.application_id = $2
              AND approved.scope = $3
              AND approved.revoked_at IS NULL
            ORDER BY approved.approved_at DESC
            LIMIT 1
            ",
        )
        .bind(request_id)
        .bind(subject.application_id)
        .bind(scope)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("login_scope_insert"))?;
    }
    let request = load_authorization_request(transaction, request_id, true).await?;
    let token = approve_request(transaction, state, &request).await?;
    Ok((request_id, token))
}

/// Hands a short-lived token to a caller who is already signed in.
///
/// UNDERSTANDING.md: "If the carbon/silicon is already logged in directly
/// return the short lived token." This is that route, and it is the one the
/// CLI and the client crate use -- a Silicon has no browser to be redirected
/// in, and a Carbon that already holds a session should not have to start
/// another one.
pub(super) async fn issue_short_lived_token(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    headers: HeaderMap,
    Json(input): Json<ShortLivedTokenRequest>,
) -> Result<Response, ApiError> {
    validation::app_id(&input.app_id)?;
    let subject_kind = match access.subject.actor_type {
        ActorType::Carbon => "carbon",
        ActorType::Silicon => "silicon",
        _ => return Err(ApiError::forbidden("forbidden")),
    };
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(access.subject.id))
        .await
        .map_err(|_| ApiError::internal("short_lived_token_context"))?;
    let caller_scope = format!("{subject_kind}:{}", access.subject.id);
    let canonical = serde_json::to_vec(&json!({ "app_id": input.app_id }))
        .map_err(|_| ApiError::internal("short_lived_token_canonical"))?;
    let claim = idempotency::claim::<ShortLivedTokenResponse>(
        &mut transaction,
        &state.crypto,
        &headers,
        &caller_scope,
        "POST /api/v1/app-auth/short-lived-tokens",
        &canonical,
        true,
    )
    .await?;
    if let Claim::Replay { status, response } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("short_lived_token_replay"))?;
        let status = StatusCode::from_u16(status)
            .map_err(|_| ApiError::internal("short_lived_token_replay_status"))?;
        return Ok((status, Json(response)).into_response());
    }
    let Claim::Acquired(idempotency_id) = claim else {
        return Err(ApiError::internal("short_lived_token_idempotency"));
    };
    let app = sqlx::query_as::<_, AuthorizeApplicationRow>(
        r"
        SELECT application.id, application.app_id, application.app_name
        FROM iam.applications AS application
        JOIN iam.principals AS principal
          ON principal.id = application.id
         AND principal.kind = 'application'
         AND principal.status = 'active'
        WHERE application.app_id = $1
          AND application.review_status = 'verified'
          AND application.deleted_at IS NULL
        ",
    )
    .bind(&input.app_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("short_lived_token_application"))?
    .ok_or_else(|| ApiError::bad_request("invalid_request", "The application is unknown."))?;
    let scopes =
        sqlx::query_scalar::<_, String>("SELECT scope FROM iam.oauth_scope_catalog ORDER BY scope")
            .fetch_all(&mut *transaction)
            .await
            .map_err(|_| ApiError::internal("short_lived_token_scopes"))?;
    let (_, token) = mint_short_lived_token(
        &mut transaction,
        &state,
        MintSubject {
            application_id: app.id,
            session_id: access.authentication_session_id,
            principal_id: access.subject.id,
            subject_kind,
            organization_id: access.organization_id,
            membership_id: access.membership_id,
            redirect_uri: None,
        },
        &scopes,
    )
    .await?;
    let expires_in = i64::try_from(state.settings.security.authorization_code_ttl.as_secs())
        .map_err(|_| ApiError::internal("short_lived_token_ttl"))?;
    let response = ShortLivedTokenResponse {
        slt: token.expose_secret().to_owned(),
        expires_in,
    };
    events::authentication_event(
        &mut transaction,
        app.id,
        Some(access.subject.id),
        Some(subject_kind),
        Some(access.authentication_session_id),
        "login.short_lived_token",
        "success",
        None,
        json!({ "delivered": false, "scope_count": scopes.len() }),
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
        .map_err(|_| ApiError::internal("short_lived_token_commit"))?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Reports what became of a token that was shown rather than delivered.
///
/// The page that shows a token cannot run a script -- there is no `script-src`
/// at all -- so it carries a meta refresh onto this route timed to the token's
/// expiry. By then the token has either been spent, in which case the login
/// worked, or it has not, in which case it is gone.
pub(super) async fn login_status(
    State(state): State<ApiState>,
    session: BrowserSession,
    Query(query): Query<LoginStatusQuery>,
) -> Result<Response, ApiError> {
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(session.carbon_id))
        .await
        .map_err(|_| ApiError::internal("login_status_context"))?;
    let status = sqlx::query_scalar::<_, String>(
        r"
        SELECT request.status
        FROM iam.oauth_authorization_requests AS request
        WHERE request.id = $1
          AND request.subject_principal_id = $2
        ",
    )
    .bind(query.request)
    .bind(session.carbon_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| ApiError::internal("login_status_lookup"))?
    .ok_or_else(ApiError::not_found)?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal("login_status_commit"))?;
    Ok(if status == "consumed" {
        login_page(
            "Authenticated",
            "Authenticated successfully.",
            "The application exchanged your token and signed you in.",
            "",
            "You can close this page.",
            None,
        )
    } else {
        login_page(
            "Token expired",
            "Token expired.",
            "This token was not used before it ran out, so it is no longer valid.",
            "",
            "Start the login again to get a new one.",
            None,
        )
    })
}

/// Renders one of the login pages.
///
/// `token_section` is pre-escaped markup rather than a value because only the
/// token page has one; every other caller passes an empty string. When
/// `refresh_to` is set the page reloads onto the status route as the token
/// expires.
fn login_page(
    title: &str,
    heading: &str,
    lead: &str,
    token_section: &str,
    note: &str,
    refresh_to: Option<Uuid>,
) -> Response {
    let refresh = match refresh_to {
        Some(request_id) => format!(
            "<meta http-equiv=\"refresh\" content=\"{AUTHORIZATION_CODE_DISPLAY_SECONDS};url=/api/v1/login/status?request={request_id}\">"
        ),
        None => String::new(),
    };
    let html = format!(
        include_str!("login_token.html"),
        refresh = refresh,
        title = escape_html(title),
        heading = escape_html(heading),
        lead = escape_html(lead),
        token_section = token_section,
        note = escape_html(note),
    );
    login_html_response(html)
}

fn login_html_response(html: String) -> Response {
    let mut response = (StatusCode::OK, Html(html)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        http::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(concat!(
            // `style-src 'self'` lets the page use the product's stylesheet.
            // There is deliberately no `script-src` at all, so this page cannot
            // execute anything -- which is why expiry is a meta refresh.
            "default-src 'none'; ",
            "style-src 'self'; ",
            "img-src 'self' data:; ",
            "font-src 'self'; ",
            "frame-ancestors 'none'; ",
            "base-uri 'none'",
        )),
    );
    response.headers_mut().insert(
        http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Trades a short-lived token, or a refresh token, for a session.
///
/// The application authenticates itself the same way in both cases, so which
/// one it is asking for is simply which credential it presented. Presenting
/// both, or neither, is a bad request rather than a guess.
pub(super) async fn app_tokens(
    State(state): State<ApiState>,
    client: ApplicationClient,
    headers: HeaderMap,
    Form(form): Form<AppTokenForm>,
) -> Result<Response, ApiError> {
    if form.app_id.as_deref() != Some(client.app_id.as_str()) {
        return Err(ApiError::invalid_client());
    }
    if form.slt.is_some() == form.refresh_token.is_some() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "Present exactly one of slt and refresh_token.",
        ));
    }
    let canonical = serde_json::to_vec(&json!({
        "app_id": form.app_id,
        "slt": form.slt,
        "refresh_token": form.refresh_token,
    }))
    .map_err(|_| ApiError::internal("oauth_token_canonical"))?;
    let mut transaction = context::begin(
        state.db(),
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
        "POST /api/v1/app-auth/tokens",
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
    let outcome = if form.slt.is_some() {
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
    let access = match tokens::authenticate(state.db(), &state.crypto, &token).await {
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
        .fetch_one(state.db())
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
    .fetch_one(state.db())
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
        state.db(),
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
               organization.org_id, consent.membership_id,
               family.authentication_session_id, application.app_id,
               token.created_at,
               LEAST(token.expires_at, family.absolute_expires_at,
                     session.absolute_expires_at) AS expires_at,
               principal.auth_epoch AS subject_auth_epoch,
               membership.authz_epoch AS membership_authz_epoch
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
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = family.oauth_consent_grant_id
         AND consent.application_id = family.client_application_id
         AND consent.subject_principal_id = family.subject_principal_id
         AND consent.subject_kind = principal.kind
         AND consent.parent_authentication_session_id = family.authentication_session_id
         AND consent.status = 'active'
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
          ON organization.id = consent.organization_id
         AND organization.status = 'active'
        LEFT JOIN iam.organization_memberships AS membership
          ON membership.id = consent.membership_id
         AND membership.organization_id = consent.organization_id
         AND membership.principal_id = family.subject_principal_id
         AND membership.principal_kind = principal.kind
         AND membership.status = 'active'
        WHERE family.client_application_id = $3
          AND family.status = 'active'
          AND family.absolute_expires_at > transaction_timestamp()
          AND token.consumed_at IS NULL
          AND token.revoked_at IS NULL
          AND token.expires_at > transaction_timestamp()
          AND (consent.organization_id IS NULL OR membership.id IS NOT NULL)
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
        state.db(),
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
    if let Claim::Replay { status, .. } = claim {
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal("oauth_revoke_replay"))?;
        let status = StatusCode::from_u16(status)
            .map_err(|_| ApiError::internal("oauth_revoke_replay_status"))?;
        return Ok(empty_idempotent_response(status, true));
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
    Ok(empty_idempotent_response(StatusCode::OK, false))
}

async fn exchange_authorization_code(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
    form: &AppTokenForm,
) -> Result<TokenResponse, ApiError> {
    let code = form
        .slt
        .as_ref()
        .filter(|value| value.starts_with("oac_") && value.len() == 47)
        .ok_or_else(|| {
            ApiError::bad_request("invalid_grant", "The short-lived token is invalid.")
        })?;
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
            "The short-lived token is invalid.",
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
            ApiError::bad_request("invalid_grant", "The short-lived token is invalid.")
        })?;
    let expected = SecretDigest::from_parts(row.digest_key_version, &row.code_digest)
        .ok_or_else(|| ApiError::internal("authorization_code_shape"))?;
    if !state
        .crypto
        .verify_secret(DigestPurpose::AuthorizationCode, &supplied, expected)
        .map_err(|_| ApiError::internal("authorization_code_verify"))?
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
        },
        &scopes,
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
        json!({ "credential": "short_lived_token", "scope_count": scopes.len() }),
    )
    .await?;
    Ok(response)
}

async fn lock_current_application_client(
    transaction: &mut Transaction<'_, Postgres>,
    client: &ApplicationClient,
) -> Result<bool, ApiError> {
    // A scalar function always answers with a row, so the absence of a match
    // arrives as NULL rather than as no row at all.
    let locked = sqlx::query_scalar::<_, Option<Uuid>>(CURRENT_APPLICATION_CLIENT_LOCK_QUERY)
        .bind(client.application_id)
        .bind(client.auth_epoch)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_client_authority_lock"))?;
    Ok(locked.flatten().is_some())
}

async fn exchange_refresh_token(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
    form: &AppTokenForm,
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
        },
        &scopes,
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
    authority.is_some_and(|consent| {
        consent.application_id == application_id
            && consent.subject_principal_id == candidate.subject_principal_id
            && consent.subject_kind == candidate.subject_kind
            && consent.organization_id == candidate.organization_id
            && consent.membership_id == candidate.membership_id
            && consent.parent_authentication_session_id == candidate.authentication_session_id
            && consent.status == "active"
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
}

async fn issue_tokens(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationClient,
    subject: TokenSubject,
    scopes: &[String],
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
    sqlx::query(OAUTH_REFRESH_INSERT_QUERY)
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
        expires_in: u64::try_from(access_seconds).unwrap_or(1_800),
        scope: scopes.join(" "),
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

async fn approve_request(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    request: &AuthorizationRequestRow,
) -> Result<SecretString, ApiError> {
    let scopes = authorization_request_scopes(transaction, request.id).await?;
    let grant_id = Uuid::now_v7();
    let consent = sqlx::query_as::<_, (Uuid, i64)>(
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
        .bind(consent.0)
        .execute(&mut **transaction)
        .await
        .map_err(|_| ApiError::internal("oauth_consent_scope_clear"))?;
    for scope in &scopes {
        sqlx::query(
            "INSERT INTO iam.oauth_consent_grant_scopes (consent_grant_id, scope) VALUES ($1, $2)",
        )
        .bind(consent.0)
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
    Ok(raw_code)
}

async fn load_authorization_request(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    for_update: bool,
) -> Result<AuthorizationRequestRow, ApiError> {
    let request = if for_update {
        sqlx::query_as::<_, AuthorizationRequestRow>(
            r"
            SELECT request.id, request.application_id,
                   request.authentication_session_id, request.subject_principal_id,
                   request.subject_kind::text AS subject_kind,
                   request.organization_id, request.membership_id
            FROM iam.oauth_authorization_requests AS request
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
            SELECT request.id, request.application_id,
                   request.authentication_session_id, request.subject_principal_id,
                   request.subject_kind::text AS subject_kind,
                   request.organization_id, request.membership_id
            FROM iam.oauth_authorization_requests AS request
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
    // consent-scope replacement first locks its consent. Lock the remaining
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
        JOIN iam.oauth_consent_grants AS consent
          ON consent.id = snapshot.consent_grant_id
         AND consent.status = 'active'
        JOIN iam.oauth_consent_grant_scopes AS consent_scope
          ON consent_scope.consent_grant_id = consent.id
         AND consent_scope.scope = snapshot.scope
        JOIN iam.application_approved_scopes AS approved
          ON approved.application_id = consent.application_id
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
            silicon_webhook_routing: None,
        },
    )
    .await
    .map_err(|_| ApiError::internal("oauth_outbox"))?;
    Ok(())
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

fn redirect_response(
    status: StatusCode,
    location: &str,
    replayed: bool,
) -> Result<Response, ApiError> {
    let mut response = status.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location)
            .map_err(|_| ApiError::internal("redirect_location_header"))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
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

fn empty_idempotent_response(status: StatusCode, replayed: bool) -> Response {
    let mut response = status.into_response();
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

    /// Locks that moved into owner-rights functions are asserted against the
    /// migration that defines them, since a share lock applies a table's
    /// UPDATE policies and an application does not manage itself.
    const CLIENT_LOCK_MIGRATION: &str =
        include_str!("../../../migrations/0057_short_lived_token_login.sql");

    use super::{
        AUTHORIZATION_CODE_LOOKUP_QUERY, CODE_EXCHANGE_ACTIVE_SCOPES_QUERY,
        CURRENT_APPLICATION_CLIENT_LOCK_QUERY, OAUTH_REFRESH_INSERT_QUERY,
        REFRESH_CREDENTIAL_LOCK_QUERY, REFRESH_GRANT_AUTHORITY_LOCK_QUERY,
        REFRESH_ISSUANCE_SCOPES_QUERY, REFRESH_MEMBERSHIP_AUTHORITY_LOCK_QUERY,
        REFRESH_REUSE_ACCESS_REVOCATION_QUERY, REFRESH_SESSION_AUTHORITY_LOCK_QUERY,
        REFRESH_TOKEN_CANDIDATE_QUERY, append_redirect_parameters, empty_idempotent_response,
        escape_html, login_html_response, scopes_retain_exact_authority,
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
    fn login_html_is_non_cacheable_and_scriptless() {
        let response = login_html_response("<!doctype html>".to_owned());
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
    fn empty_idempotent_response_marks_only_replays() {
        let initial = empty_idempotent_response(http::StatusCode::OK, false);
        assert!(initial.headers().get("idempotency-replayed").is_none());

        let replay = empty_idempotent_response(http::StatusCode::ACCEPTED, true);
        assert_eq!(replay.status(), http::StatusCode::ACCEPTED);
        assert_eq!(
            replay.headers().get("idempotency-replayed"),
            Some(&http::HeaderValue::from_static("true"))
        );
    }

    #[test]
    fn authorization_code_lookup_binds_the_current_parent_session_authority() {
        // The lock itself moved into an owner-rights function, because a
        // share lock applies the table's UPDATE policies and an application
        // does not manage itself. The conditions it holds are asserted where
        // they now live.
        for required_fragment in [
            "principal.status = 'active'",
            "principal.auth_epoch = p_auth_epoch",
            "application.review_status = 'verified'",
            "application.deleted_at IS NULL",
            "FOR SHARE OF application, principal",
        ] {
            assert!(
                CLIENT_LOCK_MIGRATION.contains(required_fragment),
                "application-client lock is missing `{required_fragment}`"
            );
        }
        assert!(
            CURRENT_APPLICATION_CLIENT_LOCK_QUERY
                .contains("iam_private.lock_current_application_client"),
            "the client lock should go through the owner-rights function"
        );
        for required_fragment in [
            "session.subject_principal_id = request.subject_principal_id",
            "session.subject_kind = request.subject_kind",
            "session.subject_auth_epoch = principal.auth_epoch",
            "session.status = 'active'",
            "consent.parent_authentication_session_id = request.authentication_session_id",
            "FOR UPDATE OF code, request, consent",
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
        let requested = vec![
            "organizations.read".to_owned(),
            "memberships.read".to_owned(),
        ];
        assert!(scopes_retain_exact_authority(&requested, &requested));
        assert!(!scopes_retain_exact_authority(
            &requested,
            &["organizations.read".to_owned()]
        ));
        assert!(!scopes_retain_exact_authority(
            &["organizations.read".to_owned()],
            &requested
        ));
        // The approved-scope ceiling is read and locked through an
        // owner-rights function: a share lock applies the table's UPDATE
        // policies, and an application is not its own administrator.
        for required_fragment in [
            "iam.oauth_consent_grant_scopes",
            "iam_private.locked_application_approved_scopes",
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
            "consent.id AS consent_grant_id",
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
            "consent.subject_kind::text AS subject_kind",
            "consent.parent_authentication_session_id",
            "FOR SHARE OF consent",
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
            "iam_private.locked_application_approved_scopes",
        ] {
            assert!(
                REFRESH_ISSUANCE_SCOPES_QUERY.contains(required_fragment),
                "refresh scope lock is missing `{required_fragment}`"
            );
        }
        // ... and the conditions it holds are asserted where they now live.
        for required_fragment in [
            "iam.application_approved_scopes",
            "approved.revoked_at IS NULL",
            "FOR SHARE OF approved",
        ] {
            assert!(
                CLIENT_LOCK_MIGRATION.contains(required_fragment),
                "scope-ceiling lock is missing `{required_fragment}`"
            );
        }
    }

    #[test]
    fn oauth_refresh_credentials_use_the_family_absolute_deadline() {
        assert!(
            OAUTH_REFRESH_INSERT_QUERY
                .contains("SELECT absolute_expires_at FROM iam.refresh_token_families")
        );
        assert!(!OAUTH_REFRESH_INSERT_QUERY.contains("30 days"));
    }
}
