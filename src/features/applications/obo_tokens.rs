//! Explicit endpoint consent and reusable, revocation-aware OBO credentials.
#![allow(clippy::too_many_lines)]

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{get, post},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction, types::Json as SqlJson};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    cursor,
    error::ApiError,
    idempotency::{self, Claim},
    model::PageInfo,
    security::{ApplicationClient, Bearer},
    validation,
};
use crate::{
    api::ApiState,
    domain::{actor::ActorType, id::Id},
    infrastructure::{
        crypto::{DigestPurpose, SecretKind},
        postgres::{
            context::{self, DatabaseContext},
            tokens::{self, AccessContext},
        },
    },
};

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/obo-access/authorizations", post(create))
        .route(
            "/api/v1/obo-access/authorizations/{id}",
            get(application_read),
        )
        .route("/api/v1/obo-access/consents/{id}", get(consent_read))
        .route("/api/v1/obo-access/consents/{id}/decision", post(decide))
        .route("/api/v1/obo-access/tokens", post(issue))
        .route("/api/v1/obo-access/token-verifications", post(verify))
        .route("/api/v1/obo-access/delegations", post(delegate))
        .route("/api/v1/obo-access/grants", get(grants))
        .route("/api/v1/obo-access/grants/{id}/revoke", post(revoke))
}

pub(super) async fn retired() -> Result<Response, ApiError> {
    Err(ApiError::gone("obo_proof_flow_retired"))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    audience: String,
    endpoint_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationRequest {
    subject_token: String,
    org_id: String,
    endpoints: Vec<Endpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_field_names,
    reason = "matches the public consent decision contract"
)]
struct Decision {
    decision: DecisionKind,
    version: i64,
    #[serde(default)]
    contexts: Vec<ProviderContext>,
    #[serde(default)]
    iam_disclosures_reviewed: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderContext {
    app_id: String,
    account_token: String,
    org_id: String,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DecisionKind {
    Approve,
    Decline,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Action {
    method: String,
    path: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Verification {
    access_token: String,
    endpoint_id: String,
    request: Action,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Delegation {
    access_token: String,
    audience: String,
    endpoint_id: String,
}

struct Credential {
    secret: SecretString,
    database: Value,
}
struct Pair {
    access: Credential,
    refresh: Credential,
    family: Id,
}

impl Pair {
    fn generate(state: &ApiState) -> Result<Self, ApiError> {
        Ok(Self {
            access: credential(
                state,
                SecretKind::OboAccessToken,
                DigestPurpose::OboAccessToken,
            )?,
            refresh: credential(
                state,
                SecretKind::OboRefreshToken,
                DigestPurpose::OboRefreshToken,
            )?,
            family: Id::now_v7(),
        })
    }
    fn database(&self) -> Value {
        json!({"access":self.access.database,"refresh":self.refresh.database,"family_id":self.family})
    }
}

enum Arg<'a> {
    Id(Id),
    Text(&'a str),
    Json(Value),
    Integer(i64),
    Boolean(bool),
}

async fn call(
    tx: &mut Transaction<'_, Postgres>,
    sql: &'static str,
    args: &[Arg<'_>],
) -> Result<Value, ApiError> {
    let mut query = sqlx::query_scalar::<_, SqlJson<Value>>(sql);
    for arg in args {
        query = match arg {
            Arg::Id(value) => query.bind(*value),
            Arg::Text(value) => query.bind(*value),
            Arg::Json(value) => query.bind(SqlJson(value)),
            Arg::Integer(value) => query.bind(*value),
            Arg::Boolean(value) => query.bind(*value),
        };
    }
    query
        .fetch_one(&mut **tx)
        .await
        .map(|value| value.0)
        .map_err(|error| database_error(&error))
}

async fn app_transaction<'a>(
    state: &'a ApiState,
    app: &ApplicationClient,
) -> Result<Transaction<'a, Postgres>, ApiError> {
    let mut tx = context::begin(
        state.db(),
        DatabaseContext::application(app.application_id, app.application_id),
    )
    .await
    .map_err(|_| ApiError::internal("obo_token_context"))?;
    super::verification::lock_client(&mut tx, state, app).await?;
    Ok(tx)
}

async fn user_transaction<'a>(
    state: &'a ApiState,
    access: &AccessContext,
) -> Result<Transaction<'a, Postgres>, ApiError> {
    require_direct_user(access)?;
    context::begin(state.db(), DatabaseContext::principal(access.subject.id))
        .await
        .map_err(|_| ApiError::internal("obo_consent_context"))
}

fn require_direct_user(access: &AccessContext) -> Result<(), ApiError> {
    if !matches!(
        access.subject.actor_type,
        ActorType::Carbon | ActorType::Silicon
    ) || access.client_application_id.is_some()
        || access.audience != "silicon-iam"
        || !access.scopes.iter().any(|scope| scope == "iam.self")
    {
        return Err(ApiError::forbidden("obo_direct_user_required"));
    }
    Ok(())
}

async fn create(
    State(state): State<ApiState>,
    app: ApplicationClient,
    headers: HeaderMap,
    Json(mut input): Json<AuthorizationRequest>,
) -> Result<Response, ApiError> {
    reject_org_header(&headers)?;
    for endpoint in &mut input.endpoints {
        endpoint.endpoint_id = local_endpoint_id(&endpoint.audience, &endpoint.endpoint_id)?;
    }
    validate_roots(&input.endpoints)?;
    match (&input.redirect_uri, &input.state) {
        (Some(uri), Some(state)) if (32..=512).contains(&state.len()) => {
            validation::redirect_uri(uri)?;
        }
        (None, None) => {}
        _ => {
            return Err(ApiError::validation(
                "redirect_uri",
                "callback delivery requires an exact URI and state of 32 to 512 bytes",
            ));
        }
    }
    validation::org_id(&input.org_id)?;
    let subject = tokens::authenticate(
        state.db(),
        &state.crypto,
        &SecretString::from(input.subject_token.clone()),
    )
    .await
    .map_err(|error| match error {
        tokens::AccessTokenError::InvalidFormat => ApiError::forbidden("invalid_subject_token"),
        _ => ApiError::internal("obo_subject_authentication"),
    })?
    .ok_or_else(|| ApiError::forbidden("invalid_subject_token"))?;
    if subject.client_application_id != Some(app.application_id) {
        return Err(ApiError::forbidden("obo_subject_token_forbidden"));
    }
    let mut tx = app_transaction(&state, &app).await?;
    let claim = claim(
        &mut tx,
        &state,
        &headers,
        &format!("obo-app:{}", app.application_id),
        "POST /api/v1/obo-access/authorizations",
        &input,
        false,
    )
    .await?;
    let id = match claim {
        Claim::Acquired(id) => id,
        Claim::Replay { status, response } => {
            return commit_response(tx, status, response, true).await;
        }
    };
    let request_id = Id::now_v7();
    let mut result = call(
        &mut tx,
        "SELECT iam_private.obo_authorization_create($1,$2,$3,$4)",
        &[
            Arg::Id(subject.token_id),
            Arg::Text(&input.org_id),
            Arg::Json(json!(input.endpoints)),
            Arg::Id(request_id),
        ],
    )
    .await?;
    if let (Some(uri), Some(callback_state)) = (&input.redirect_uri, &input.state) {
        result = call(
            &mut tx,
            "SELECT iam_private.obo_authorization_bind_callback($1,$2,$3)",
            &[
                Arg::Id(request_id),
                Arg::Text(uri),
                Arg::Text(callback_state),
            ],
        )
        .await?;
    }
    let mut url = state
        .settings
        .server
        .auth_base_url
        .join("obo/consent")
        .map_err(|_| ApiError::internal("obo_authorization_url"))?;
    url.query_pairs_mut()
        .append_pair("request", &request_id.to_string());
    result["authorization_url"] = json!(url.as_str());
    complete(&mut tx, &state, id, 201, &result, false).await?;
    commit_response(tx, 201, result, false).await
}

async fn application_read(
    State(state): State<ApiState>,
    app: ApplicationClient,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> Result<Response, ApiError> {
    resource_id(id)?;
    reject_org_header(&headers)?;
    let mut tx = app_transaction(&state, &app).await?;
    let result = read(&mut tx, id).await?;
    commit_response(tx, 200, result, false).await
}

async fn consent_read(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> Result<Response, ApiError> {
    resource_id(id)?;
    reject_org_header(&headers)?;
    let mut tx = user_transaction(&state, &access).await?;
    let result = read(&mut tx, id).await?;
    commit_response(tx, 200, result, false).await
}

async fn read(tx: &mut Transaction<'_, Postgres>, id: Id) -> Result<Value, ApiError> {
    call(
        tx,
        "SELECT iam_private.obo_authorization_read($1)",
        &[Arg::Id(id)],
    )
    .await
}

async fn decide(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    headers: HeaderMap,
    Path(request_id): Path<Id>,
    Json(input): Json<Decision>,
) -> Result<Response, ApiError> {
    resource_id(request_id)?;
    reject_org_header(&headers)?;
    if input.version < 1 {
        return Err(ApiError::precondition_failed());
    }
    if input.contexts.len() > 100 {
        return Err(ApiError::validation(
            "contexts",
            "select at most 100 provider accounts",
        ));
    }
    let mut contexts = Vec::with_capacity(input.contexts.len());
    let mut providers = std::collections::BTreeSet::new();
    for selected in &input.contexts {
        validation::app_id(&selected.app_id)?;
        validation::org_id(&selected.org_id)?;
        if !providers.insert(&selected.app_id) {
            return Err(ApiError::validation(
                "contexts",
                "select one account per provider",
            ));
        }
        let account = tokens::authenticate(
            state.db(),
            &state.crypto,
            &SecretString::from(selected.account_token.clone()),
        )
        .await
        .map_err(|_| ApiError::forbidden("obo_context_account_invalid"))?
        .ok_or_else(|| ApiError::forbidden("obo_context_account_invalid"))?;
        require_direct_user(&account)?;
        let (prefix, purpose) = if account.subject.actor_type == ActorType::Carbon {
            ("cat_", DigestPurpose::CarbonAccessToken)
        } else {
            ("sat_", DigestPurpose::SiliconAccessToken)
        };
        let digests = lookup(&state, &selected.account_token, prefix, purpose)?;
        contexts.push(json!({"app_id":selected.app_id,"org_id":selected.org_id,"token_id":account.token_id,"digests":digests}));
    }
    let mut tx = user_transaction(&state, &access).await?;
    let canonical = json!({"request_id":request_id,"decision":input.decision,"version":input.version,"session_id":access.authentication_session_id,"contexts":contexts,"iam_disclosures_reviewed":input.iam_disclosures_reviewed});
    let claim = claim(
        &mut tx,
        &state,
        &headers,
        &format!("obo-user:{}", access.subject.id),
        "POST /api/v1/obo-access/consents/{id}/decision",
        &canonical,
        true,
    )
    .await?;
    let id = match claim {
        Claim::Acquired(id) => id,
        Claim::Replay { status, response } => {
            return commit_response(tx, status, response, true).await;
        }
    };
    let request_detail = read(&mut tx, request_id).await?;
    let mut code = credential(
        &state,
        SecretKind::OboAuthorizationCode,
        DigestPurpose::OboAuthorizationCode,
    )?;
    code.database["iam_disclosures_reviewed"] = json!(input.iam_disclosures_reviewed);
    let approve = input.decision == DecisionKind::Approve;
    let mut result = call(
        &mut tx,
        "SELECT iam_private.obo_authorization_decide($1,$2,$3,$4,$5,$6)",
        &[
            Arg::Id(request_id),
            Arg::Id(access.token_id),
            Arg::Integer(input.version),
            Arg::Boolean(approve),
            Arg::Json(code.database),
            Arg::Json(json!(contexts)),
        ],
    )
    .await?;
    if approve {
        result["authorization_code"] = json!(code.secret.expose_secret());
    }
    if let (Some(uri), Some(callback_state)) = (
        request_detail["redirect_uri"].as_str(),
        request_detail["state"].as_str(),
    ) {
        let mut callback =
            url::Url::parse(uri).map_err(|_| ApiError::internal("obo_callback_stored"))?;
        callback
            .query_pairs_mut()
            .append_pair("authorization_id", &request_id.to_string())
            .append_pair("state", callback_state);
        if approve {
            callback
                .query_pairs_mut()
                .append_pair("code", code.secret.expose_secret());
        } else {
            callback
                .query_pairs_mut()
                .append_pair("error", "access_denied");
        }
        result["redirect_uri"] = json!(callback.as_str());
    }
    complete(&mut tx, &state, id, 200, &result, true).await?;
    commit_response(tx, 200, result, false).await
}

async fn issue(
    State(state): State<ApiState>,
    app: ApplicationClient,
    headers: HeaderMap,
    Json(input): Json<TokenRequest>,
) -> Result<Response, ApiError> {
    reject_org_header(&headers)?;
    validate_token_request(&input)?;
    let recovery_subject = if let Some(raw) = &input.subject_token {
        let subject =
            tokens::authenticate(state.db(), &state.crypto, &SecretString::from(raw.clone()))
                .await
                .map_err(|_| ApiError::forbidden("invalid_subject_token"))?
                .ok_or_else(|| ApiError::forbidden("invalid_subject_token"))?;
        if subject.client_application_id != Some(app.application_id) {
            return Err(ApiError::forbidden("obo_subject_token_forbidden"));
        }
        Some(subject.token_id)
    } else {
        None
    };
    let mut tx = app_transaction(&state, &app).await?;
    let claim = claim(
        &mut tx,
        &state,
        &headers,
        &format!("obo-app:{}", app.application_id),
        "POST /api/v1/obo-access/tokens",
        &input,
        true,
    )
    .await?;
    let id = match claim {
        Claim::Acquired(id) => id,
        Claim::Replay { status, response } => return replay_tokens(tx, status, response).await,
    };
    let mut pairs = Vec::new();
    let mut result = if let (Some(grant), Some(subject)) = (input.grant_id, recovery_subject) {
        let pair = Pair::generate(&state)?;
        let result = call(
            &mut tx,
            "SELECT iam_private.obo_grant_recover($1,$2,$3)",
            &[Arg::Id(grant), Arg::Id(subject), Arg::Json(pair.database())],
        )
        .await?;
        pairs.push(pair);
        result
    } else if let Some(token) = &input.refresh_token {
        let digests = lookup(&state, token, "obr_", DigestPurpose::OboRefreshToken)?;
        let pair = Pair::generate(&state)?;
        let result = call(
            &mut tx,
            "SELECT iam_private.obo_token_refresh($1,$2)",
            &[Arg::Json(digests), Arg::Json(pair.database())],
        )
        .await?;
        pairs.push(pair);
        result
    } else {
        let authorization = input
            .authorization_id
            .ok_or_else(|| ApiError::validation("authorization_id", "is required"))?;
        let code = input
            .authorization_code
            .as_deref()
            .ok_or_else(|| ApiError::validation("authorization_code", "is required"))?;
        let detail = read(&mut tx, authorization).await?;
        let count = detail["endpoints"]
            .as_array()
            .map(Vec::len)
            .filter(|count| (1..=100).contains(count))
            .ok_or_else(|| ApiError::internal("obo_authorization_endpoints"))?;
        for _ in 0..count {
            pairs.push(Pair::generate(&state)?);
        }
        let digests = lookup(&state, code, "obc_", DigestPurpose::OboAuthorizationCode)?;
        call(
            &mut tx,
            "SELECT iam_private.obo_authorization_redeem($1,$2,$3)",
            &[
                Arg::Id(authorization),
                Arg::Json(digests),
                Arg::Json(json!(pairs.iter().map(Pair::database).collect::<Vec<_>>())),
            ],
        )
        .await?
    };
    if result.get("error").is_some() {
        // The claim is marked as containing a one-time credential. Preserve its
        // short replay lifetime so recording the failure cannot roll back reuse
        // detection and the refresh family's revocation.
        idempotency::complete(&mut tx, &state.crypto, id, 403, &result, true).await?;
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("obo_refresh_compromise_commit"))?;
        return Err(ApiError::forbidden("obo_refresh_token_reused"));
    }
    attach_pairs(&mut result, &pairs)?;
    add_testing_context(&state, &mut result, &mut tx).await?;
    complete(&mut tx, &state, id, 200, &result, true).await?;
    commit_response(tx, 200, result, false).await
}

async fn verify(
    State(state): State<ApiState>,
    app: ApplicationClient,
    headers: HeaderMap,
    Json(mut input): Json<Verification>,
) -> Result<Response, ApiError> {
    reject_org_header(&headers)?;
    input.endpoint_id = local_endpoint_id(&app.app_id, &input.endpoint_id)?;
    endpoint_id(&input.endpoint_id)?;
    validate_action(&input.request)?;
    let digests = lookup(
        &state,
        &input.access_token,
        "oba_",
        DigestPurpose::OboAccessToken,
    )?;
    let mut tx = app_transaction(&state, &app).await?;
    let result = call(
        &mut tx,
        "SELECT iam_private.obo_token_verify($1,$2,$3,$4)",
        &[
            Arg::Json(digests),
            Arg::Text(&input.endpoint_id),
            Arg::Text(&input.request.method),
            Arg::Text(&input.request.path),
        ],
    )
    .await?;
    commit_response(tx, 200, result, false).await
}

async fn delegate(
    State(state): State<ApiState>,
    app: ApplicationClient,
    headers: HeaderMap,
    Json(input): Json<Delegation>,
) -> Result<Response, ApiError> {
    reject_org_header(&headers)?;
    validation::app_id(&input.audience)?;
    endpoint_id(&input.endpoint_id)?;
    let digests = lookup(
        &state,
        &input.access_token,
        "oba_",
        DigestPurpose::OboAccessToken,
    )?;
    let mut tx = app_transaction(&state, &app).await?;
    let claim = claim(
        &mut tx,
        &state,
        &headers,
        &format!("obo-app:{}", app.application_id),
        "POST /api/v1/obo-access/delegations",
        &input,
        true,
    )
    .await?;
    let id = match claim {
        Claim::Acquired(id) => id,
        Claim::Replay { status, response } => return replay_tokens(tx, status, response).await,
    };
    let token = credential(
        &state,
        SecretKind::OboAccessToken,
        DigestPurpose::OboAccessToken,
    )?;
    let mut result = call(
        &mut tx,
        "SELECT iam_private.obo_token_delegate($1,$2,$3,$4)",
        &[
            Arg::Json(digests),
            Arg::Text(&input.audience),
            Arg::Text(&input.endpoint_id),
            Arg::Json(token.database),
        ],
    )
    .await?;
    result["access_token"] = json!(input.access_token);
    add_testing_context(&state, &mut result, &mut tx).await?;
    complete(&mut tx, &state, id, 201, &result, true).await?;
    commit_response(tx, 201, result, false).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantQuery {
    cursor: Option<String>,
    limit: Option<u16>,
    app_id: Option<String>,
}

async fn grants(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    headers: HeaderMap,
    Query(query): Query<GrantQuery>,
) -> Result<Response, ApiError> {
    reject_org_header(&headers)?;
    if let Some(app_id) = &query.app_id {
        validation::app_id(app_id)?;
    }
    let cursor = cursor::decode(query.cursor.as_deref())?;
    if let Some(cursor) = cursor {
        resource_id(cursor.id)?;
    }
    let limit = i32::from(query.limit.unwrap_or(10).clamp(1, 10));
    let mut tx = user_transaction(&state, &access).await?;
    let SqlJson(mut result): SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.obo_grants_list($1::uuid,$2,$3::uuid,$4,$5)")
            .bind(access.token_id)
            .bind(cursor.map(|cursor| cursor.at))
            .bind(cursor.map(|cursor| cursor.id))
            .bind(limit)
            .bind(query.app_id.as_deref())
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| database_error(&error))?;
    let items = result["items"]
        .as_array_mut()
        .ok_or_else(|| ApiError::internal("obo_grants_result"))?;
    let next = if items.len() > usize::try_from(limit).unwrap_or(10) {
        items.pop();
        let last = items
            .last()
            .ok_or_else(|| ApiError::internal("obo_grants_cursor"))?;
        let at = OffsetDateTime::parse(
            last["created_at"]
                .as_str()
                .ok_or_else(|| ApiError::internal("obo_grants_cursor"))?,
            &Rfc3339,
        )
        .map_err(|_| ApiError::internal("obo_grants_cursor"))?;
        let id = serde_json::from_value(last["id"].clone())
            .map_err(|_| ApiError::internal("obo_grants_cursor"))?;
        Some(cursor::encode(at, id)?)
    } else {
        None
    };
    result["page"] = json!(PageInfo::from_next_cursor(next));
    commit_response(tx, 200, result, false).await
}

async fn revoke(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    headers: HeaderMap,
    Path(grant_id): Path<Id>,
) -> Result<Response, ApiError> {
    reject_org_header(&headers)?;
    resource_id(grant_id)?;
    let mut tx = user_transaction(&state, &access).await?;
    let canonical = json!({"grant_id":grant_id,"session_id":access.authentication_session_id});
    let claim = claim(
        &mut tx,
        &state,
        &headers,
        &format!("obo-user:{}", access.subject.id),
        "POST /api/v1/obo-access/grants/{id}/revoke",
        &canonical,
        false,
    )
    .await?;
    let id = match claim {
        Claim::Acquired(id) => id,
        Claim::Replay { status, response } => {
            return commit_response(tx, status, response, true).await;
        }
    };
    let result = call(
        &mut tx,
        "SELECT iam_private.obo_grant_revoke($1,$2)",
        &[Arg::Id(grant_id), Arg::Id(access.token_id)],
    )
    .await?;
    complete(&mut tx, &state, id, 200, &result, false).await?;
    commit_response(tx, 200, result, false).await
}

async fn claim<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    headers: &HeaderMap,
    caller: &str,
    route: &'static str,
    input: &T,
    secret: bool,
) -> Result<Claim<Value>, ApiError> {
    let body = serde_json::to_vec(input).map_err(|_| ApiError::internal("obo_request_encode"))?;
    idempotency::claim(tx, &state.crypto, headers, caller, route, &body, secret).await
}

async fn complete(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    id: Id,
    status: u16,
    result: &Value,
    secret: bool,
) -> Result<(), ApiError> {
    let deadline = if let Some(items) = result["items"].as_array() {
        items.iter().filter_map(expiry).min()
    } else {
        expiry(result)
    };
    if let Some(deadline) = deadline {
        idempotency::complete_no_later_than(tx, &state.crypto, id, status, result, secret, deadline)
            .await
    } else {
        idempotency::complete(tx, &state.crypto, id, status, result, secret).await
    }
}

fn expiry(value: &Value) -> Option<OffsetDateTime> {
    value["expires_at"]
        .as_str()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
}

async fn replay_tokens(
    mut tx: Transaction<'_, Postgres>,
    status: u16,
    response: Value,
) -> Result<Response, ApiError> {
    if response.get("error").is_some() {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("obo_replay_commit"))?;
        return Err(ApiError::forbidden("obo_refresh_token_reused"));
    }
    let items = response["items"]
        .as_array()
        .map_or_else(|| vec![&response], |items| items.iter().collect());
    let ids = items
        .iter()
        .map(|item| {
            item["token_id"]
                .as_str()
                .and_then(|value| value.parse::<uuid::Uuid>().ok())
                .ok_or_else(|| ApiError::internal("obo_replay_token_id"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let active: SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.obo_token_result_is_live($1)")
            .bind(ids)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| database_error(&error))?;
    if active.0["active"] != true {
        return Err(ApiError::gone("obo_token_revoked"));
    }
    commit_response(tx, status, response, true).await
}

async fn commit_response(
    tx: Transaction<'_, Postgres>,
    status: u16,
    value: Value,
    replayed: bool,
) -> Result<Response, ApiError> {
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("obo_token_commit"))?;
    let mut response = (
        StatusCode::from_u16(status).map_err(|_| ApiError::internal("obo_response_status"))?,
        Json(value),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if replayed {
        response
            .headers_mut()
            .insert("idempotency-replayed", HeaderValue::from_static("true"));
    }
    Ok(response)
}

fn credential(
    state: &ApiState,
    kind: SecretKind,
    purpose: DigestPurpose,
) -> Result<Credential, ApiError> {
    let secret = state
        .crypto
        .generate_secret(kind)
        .map_err(|_| ApiError::internal("obo_secret_generate"))?;
    let digest = state
        .crypto
        .digest_secret(purpose, &secret)
        .map_err(|_| ApiError::internal("obo_secret_digest"))?;
    Ok(Credential {
        secret,
        database: json!({"id":Id::now_v7(),"digest":hex::encode(digest.as_bytes()),"key_version":digest.key_version()}),
    })
}

fn lookup(
    state: &ApiState,
    token: &str,
    prefix: &str,
    purpose: DigestPurpose,
) -> Result<Value, ApiError> {
    let Some(suffix) = token.strip_prefix(prefix) else {
        return Err(ApiError::forbidden("obo_token_invalid"));
    };
    if suffix.len() != 43
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ApiError::forbidden("obo_token_invalid"));
    }
    state.crypto.digest_secrets(purpose,&SecretString::from(token.to_owned()))
        .map(|digests|json!(digests.iter().map(|digest|json!({"key_version":digest.key_version(),"digest":hex::encode(digest.as_bytes())})).collect::<Vec<_>>()))
        .map_err(|_|ApiError::internal("obo_token_digest"))
}

async fn add_testing_context(
    state: &ApiState,
    result: &mut Value,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    let items = if let Some(items) = result.get_mut("items") {
        items
            .as_array_mut()
            .ok_or_else(|| ApiError::internal("obo_token_result"))?
            .iter_mut()
            .collect::<Vec<_>>()
    } else {
        vec![result]
    };
    for item in items {
        let audience = item["audience"]
            .as_str()
            .ok_or_else(|| ApiError::internal("obo_token_audience"))?;
        if let Some(context) =
            crate::features::testing_environments::obo_context_in_transaction(state, audience, tx)
                .await
                .map_err(|_| ApiError::internal("obo_testing_context"))?
        {
            item["testing_context"] = context;
        }
    }
    Ok(())
}

fn attach_pairs(result: &mut Value, pairs: &[Pair]) -> Result<(), ApiError> {
    let items = result["items"]
        .as_array_mut()
        .ok_or_else(|| ApiError::internal("obo_token_result"))?;
    if items.len() != pairs.len() {
        return Err(ApiError::internal("obo_token_result_count"));
    }
    for (item, pair) in items.iter_mut().zip(pairs) {
        if let Some(object) = item.as_object_mut() {
            object.remove("refresh_token_id");
        }
        item["access_token"] = json!(pair.access.secret.expose_secret());
        item["refresh_token"] = json!(pair.refresh.secret.expose_secret());
    }
    Ok(())
}

fn validate_roots(roots: &[Endpoint]) -> Result<(), ApiError> {
    if !(1..=100).contains(&roots.len()) {
        return Err(ApiError::validation(
            "endpoints",
            "select 1-100 unique endpoints",
        ));
    }
    let mut unique = std::collections::BTreeSet::new();
    for root in roots {
        validation::app_id(&root.audience)?;
        endpoint_id(&root.endpoint_id)?;
        if !unique.insert((&root.audience, &root.endpoint_id)) {
            return Err(ApiError::validation("endpoints", "duplicate endpoint"));
        }
    }
    Ok(())
}

fn local_endpoint_id(app: &str, value: &str) -> Result<String, ApiError> {
    if let Some(canonical) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        let prefix = format!("{app}:obo:");
        let local = canonical.strip_prefix(&prefix).ok_or_else(|| {
            ApiError::validation(
                "endpoint_id",
                "endpoint belongs to another app or credential type",
            )
        })?;
        endpoint_id(local)?;
        Ok(local.to_owned())
    } else {
        endpoint_id(value)?;
        Ok(value.to_owned())
    }
}

fn endpoint_id(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b':')
        })
    {
        return Err(ApiError::validation(
            "endpoint_id",
            "must name a published endpoint",
        ));
    }
    Ok(())
}

fn validate_action(action: &Action) -> Result<(), ApiError> {
    if !matches!(
        action.method.as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    ) {
        return Err(ApiError::validation(
            "request.method",
            "must be a canonical HTTP method",
        ));
    }
    if !action.path.starts_with('/')
        || action.path.starts_with("//")
        || action.path.len() > 2048
        || action
            .path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || action.path.contains(['#', '?', '\\'])
    {
        return Err(ApiError::validation(
            "request.path",
            "must be the canonical registered endpoint path",
        ));
    }
    Ok(())
}

fn validate_token_request(input: &TokenRequest) -> Result<(), ApiError> {
    match (
        &input.authorization_id,
        &input.authorization_code,
        &input.refresh_token,
        &input.grant_id,
        &input.subject_token,
    ) {
        (Some(id), Some(_), None, None, None) | (None, None, None, Some(id), Some(_)) => {
            resource_id(*id)
        }
        (None, None, Some(_), None, None) => Ok(()),
        _ => Err(ApiError::validation(
            "token",
            "provide authorization_id and authorization_code, refresh_token, or grant_id and current subject_token",
        )),
    }
}

fn resource_id(id: Id) -> Result<(), ApiError> {
    if !matches!(id, Id::Resource(_)) {
        return Err(ApiError::validation("id", "must be a UUID"));
    }
    Ok(())
}

fn reject_org_header(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.contains_key("x-org-id") {
        return Err(ApiError::validation(
            "x-org-id",
            "OBO operations use the grant's organization; select org_id in the authorization request",
        ));
    }
    Ok(())
}

fn database_error(error: &sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(error) = error {
        match error.message() {
            "obo_not_found"
            | "obo_request_not_found"
            | "obo_grant_not_found"
            | "obo_authorization_not_found" => {
                return ApiError::not_found();
            }
            "obo_consent_stale"
            | "obo_graph_changed"
            | "obo_version_mismatch"
            | "obo_consent_changed" => return ApiError::precondition_failed(),
            "obo_request_expired" | "obo_code_expired" | "obo_token_expired" => {
                return ApiError::gone("obo_token_expired");
            }
            "obo_code_consumed" | "obo_request_decided" => {
                return ApiError::conflict("obo_authorization_consumed");
            }
            "obo_consent_required" => return ApiError::forbidden("obo_consent_required"),
            "obo_disclosure_review_required" => {
                return ApiError::forbidden("obo_disclosure_review_required");
            }
            "obo_token_revoked" | "obo_grant_revoked" => {
                return ApiError::gone("obo_token_revoked");
            }
            value if value.starts_with("obo_") => {
                return ApiError::forbidden("obo_authorization_denied");
            }
            _ => {}
        }
    }
    tracing::error!(%error,"OBO database operation failed");
    ApiError::internal("obo_token_database")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_exchange_cannot_mix_code_and_refresh_authority() {
        let valid = TokenRequest {
            grant_id: None,
            subject_token: None,
            authorization_id: Some(Id::now_v7()),
            authorization_code: Some("code".into()),
            refresh_token: None,
        };
        assert!(validate_token_request(&valid).is_ok());
        let mixed = TokenRequest {
            refresh_token: Some("refresh".into()),
            ..valid
        };
        assert!(validate_token_request(&mixed).is_err());
        assert!(
            serde_json::from_value::<TokenRequest>(json!({"refresh_token":"x","audience":"other"}))
                .is_err()
        );
    }

    #[test]
    fn endpoint_batches_reject_duplicates_and_invalid_action_paths() {
        let roots = vec![
            Endpoint {
                audience: "storage".into(),
                endpoint_id: "files.create".into(),
            },
            Endpoint {
                audience: "storage".into(),
                endpoint_id: "files.create".into(),
            },
        ];
        assert!(validate_roots(&roots).is_err());
        for path in [
            "//other.example",
            "/files?admin=true",
            "/files#delete",
            "/files\\delete",
        ] {
            assert!(
                validate_action(&Action {
                    method: "POST".into(),
                    path: path.into()
                })
                .is_err()
            );
        }
        assert!(
            validate_action(&Action {
                method: "POST".into(),
                path: "/files".into()
            })
            .is_ok()
        );
    }

    #[tokio::test]
    async fn legacy_proof_route_is_retired() {
        let response = retired()
            .await
            .err()
            .map(axum::response::IntoResponse::into_response);
        assert!(response.is_some_and(|response| response.status() == StatusCode::GONE));
    }
}

#[cfg(test)]
#[path = "obo_token_tests.rs"]
mod protocol_tests;

#[cfg(test)]
#[path = "obo_token_database_tests.rs"]
mod database_tests;
