//! Configurable action gates and exact-request manual approval.

use std::{borrow::Cow, collections::BTreeSet, str::FromStr as _};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{MatchedPath, Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{id::Id, organization::Capability},
    error::AppError,
    infrastructure::{
        crypto::{CryptoService, EncryptedValue, EncryptionContext, ProtectedField},
        postgres::{
            events::{self, AuditRecord},
            idempotency::IdempotencyKey,
        },
    },
};

use super::{
    support::{self, OrganizationTransaction},
    validation,
};

#[derive(Clone)]
struct MutationRequest {
    method: String,
    path: String,
    route: String,
    body: Value,
    expected_version: Option<String>,
    idempotency_key: Option<String>,
}

tokio::task_local! {
    static MUTATION_REQUEST: MutationRequest;
}

/// Capture the exact request before the handler starts its mutation transaction.
pub(super) async fn capture_request(request: Request, next: Next) -> Result<Response, AppError> {
    if matches!(request.method().as_str(), "GET" | "HEAD" | "OPTIONS") {
        return Ok(next.run(request).await);
    }
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1_048_576)
        .await
        .map_err(|_| AppError::PayloadTooLarge)?;
    let input = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body)
            .map_err(|_| AppError::invalid_field("body", "must be valid JSON"))?
    };
    let header = |name| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let context = MutationRequest {
        method: parts.method.to_string(),
        path: parts.uri.to_string(),
        route: parts
            .extensions
            .get::<MatchedPath>()
            .map_or_else(String::new, |path| path.as_str().to_owned()),
        body: input,
        expected_version: header("if-match"),
        idempotency_key: header("idempotency-key"),
    };
    Ok(MUTATION_REQUEST
        .scope(
            context,
            next.run(Request::from_parts(parts, Body::from(body))),
        )
        .await)
}

fn actions(request: &MutationRequest, actor_id: &str) -> Vec<&'static str> {
    let mut result = BTreeSet::new();
    let route = request
        .route
        .strip_prefix("/api/v1/organizations/{org_id}")
        .unwrap_or_default();
    match (request.method.as_str(), route) {
        ("POST", "/silicons" | "/carbon-invites") => {
            initial_assignment_actions(&request.body, &mut result);
        }
        ("PATCH", "") => {
            result.insert("organization.profile.update");
        }
        (
            "PUT",
            "/members/{membership_id}/job-role" | "/members/{membership_id}/job-description",
        ) => {
            result.insert("membership.job_description.update");
        }
        ("PUT", "/members/{membership_id}/tags") => {
            result.insert("membership.tags.update");
        }
        ("PATCH", "/members/{membership_id}") => {
            if request.body.get("tag_ids").is_some() {
                result.insert("membership.tags.update");
            }
            if request.body.get("default_trust").is_some() {
                result.insert("trust.default.update");
            }
            if request.body.get("reports_to_membership_id").is_some() {
                result.insert("silicon.hierarchy.update");
            }
            if request.body.get("profile_photo").is_some() {
                result.insert("silicon.profile.update");
            }
            if request.body.get("first_silicon_membership_id").is_some()
                || request.body.get("extra_silicon_membership_ids").is_some()
            {
                result.insert("membership.directory.update");
            }
        }
        ("PATCH", "/silicons/{silicon_id}") => {
            if request.body.get("reports_to_membership_id").is_some() {
                result.insert("silicon.hierarchy.update");
            }
            if request
                .body
                .as_object()
                .is_some_and(|body| body.keys().any(|key| key != "reports_to_membership_id"))
            {
                let segment = request
                    .path
                    .split('?')
                    .next()
                    .unwrap_or_default()
                    .rsplit('/')
                    .next()
                    .unwrap_or_default();
                let encoded = format!("id={segment}");
                let target = url::form_urlencoded::parse(encoded.as_bytes())
                    .next()
                    .map(|(_, value)| value.into_owned());
                result.insert(if target.as_deref() == Some(actor_id) {
                    "silicon.self_profile.update"
                } else {
                    "silicon.profile.update"
                });
            }
        }
        ("POST", "/tags") => {
            result.insert("tag.create");
        }
        ("PATCH", "/tags/{tag_id}") => {
            result.insert("tag.update");
        }
        ("DELETE", "/tags/{tag_id}") => {
            result.insert("tag.delete");
        }
        ("PUT", "/trust/default") => {
            result.insert("trust.default.update");
        }
        ("POST", "/trust/rules") => {
            result.insert("trust.rule.create");
        }
        ("PATCH", "/trust/rules/{rule_id}") => {
            result.insert("trust.rule.update");
        }
        ("DELETE", "/trust/rules/{rule_id}") => {
            result.insert("trust.rule.delete");
        }
        _ => {}
    }
    result.into_iter().collect()
}

fn initial_assignment_actions(body: &Value, result: &mut BTreeSet<&'static str>) {
    if body
        .get("job_description")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        result.insert("membership.job_description.update");
    }
    if nonempty_array(body, "tag_ids") {
        result.insert("membership.tags.update");
    }
    if body
        .get("reports_to_membership_id")
        .is_some_and(|value| !value.is_null())
    {
        result.insert("silicon.hierarchy.update");
    }
    if body
        .get("first_silicon_membership_id")
        .is_some_and(|value| !value.is_null())
        || nonempty_array(body, "extra_silicon_membership_ids")
    {
        result.insert("membership.directory.update");
    }
    if body
        .get("default_trust")
        .is_some_and(|value| !value.is_null())
    {
        result.insert("trust.default.update");
    }
    if nonempty_array(body, "tag_trust_overrides")
        || nonempty_array(body, "silicon_trust_overrides")
    {
        result.insert("trust.rule.create");
    }
}

fn nonempty_array(body: &Value, field: &str) -> bool {
    body.get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
}

pub(super) async fn authorize_scope<'a>(
    mut scope: OrganizationTransaction<'a>,
    actor: &Authenticated,
    crypto: &CryptoService,
) -> Result<OrganizationTransaction<'a>, AppError> {
    let Ok(request) = MUTATION_REQUEST.try_with(Clone::clone) else {
        return Ok(scope);
    };
    let actions = actions(&request, &actor.0.subject.id.to_string());
    if actions.is_empty() {
        return Ok(scope);
    }
    // Initial assignments obey the same field policies, but a field approval
    // never substitutes for authority to create an identity or invitation.
    match (request.method.as_str(), request.route.as_str()) {
        ("POST", "/api/v1/organizations/{org_id}/silicons") => {
            support::require_capability(&scope.access, Capability::SiliconsCreate)?;
        }
        ("POST", "/api/v1/organizations/{org_id}/carbon-invites") => {
            support::require_capability(&scope.access, Capability::MembersInvite)?;
        }
        _ => {}
    }
    validate_mutation_preconditions(&request)?;
    let mut scopes = actor.0.scopes.clone();
    scopes.sort();
    let payload = serde_json::to_vec(&json!({
        "method":request.method,"path":request.path,"body":request.body,
        "if_match":request.expected_version,"idempotency_key":request.idempotency_key,
        "application_id":actor.0.client_application_id,"session_id":actor.0.authentication_session_id,"scopes":scopes,
    })).map_err(|_| AppError::Internal { category: "action_request_digest" })?;
    let fingerprint = Sha256::digest(payload).to_vec();
    // Preflight every action before consuming any approval. A composite patch
    // can create several requests without spending another approved action.
    let mut pending = None;
    for action in &actions {
        let result = authorize(&mut scope, &request, action, &fingerprint, false, crypto).await?;
        if result.get("status").and_then(Value::as_str) == Some("pending") {
            pending = pending.or_else(|| {
                result
                    .get("request_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        }
    }
    if let Some(approval_request_id) = pending {
        scope
            .transaction
            .commit()
            .await
            .map_err(support::database)?;
        return Err(AppError::ApprovalRequired {
            approval_request_id,
            idempotency_key: request.idempotency_key.unwrap_or_default(),
        });
    }
    for action in &actions {
        let result = authorize(&mut scope, &request, action, &fingerprint, true, crypto).await?;
        for capability in result
            .get("capabilities")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(value) = capability.as_str() {
                scope
                    .access
                    .authority
                    .capabilities
                    .insert(Capability::from_str(value).map_err(|_| AppError::Internal {
                        category: "action_policy_capability",
                    })?);
            }
        }
    }
    Ok(scope)
}

async fn authorize(
    scope: &mut OrganizationTransaction<'_>,
    request: &MutationRequest,
    action: &str,
    fingerprint: &[u8],
    consume: bool,
    crypto: &CryptoService,
) -> Result<Value, AppError> {
    let request_id = Id::now_v7();
    let body = review_body(crypto, scope.access.organization_id, request_id, request)?;
    sqlx::query_scalar("SELECT iam_private.authorize_sensitive_action($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(scope.access.organization_id)
        .bind(action)
        .bind(fingerprint)
        .bind(&request.method)
        .bind(&request.path)
        .bind(body)
        .bind(request.expected_version.as_deref())
        .bind(request_id)
        .bind(consume)
        .fetch_one(&mut *scope.transaction)
        .await
        .map_err(database)
}

fn review_body(
    crypto: &CryptoService,
    organization: Id,
    request_id: Id,
    request: &MutationRequest,
) -> Result<Value, AppError> {
    let mut body = request.body.clone();
    if request.method == "POST"
        && request.route == "/api/v1/organizations/{org_id}/carbon-invites"
        && let Some(email) = body.get("email").and_then(Value::as_str)
    {
        let encrypted = crypto
            .encrypt(
                EncryptionContext::tenant(
                    ProtectedField::ActionApprovalEmail,
                    organization,
                    request_id,
                ),
                email.as_bytes(),
            )
            .map_err(|_| AppError::Internal {
                category: "action_approval_email_encrypt",
            })?;
        body["email"] = serde_json::to_value(encrypted).map_err(|_| AppError::Internal {
            category: "action_approval_email_encode",
        })?;
    }
    Ok(body)
}

/// Called only after the database has limited results to the requester or an
/// organization reviewer. The audit path omits request bodies entirely.
fn reveal_review_body(
    crypto: &CryptoService,
    organization: Id,
    approval: &mut Value,
) -> Result<(), AppError> {
    let Some(encrypted) = approval
        .pointer("/request_body/email")
        .filter(|email| email.is_object())
    else {
        return Ok(());
    };
    let encrypted: EncryptedValue =
        serde_json::from_value(encrypted.clone()).map_err(|_| AppError::Internal {
            category: "action_approval_email_shape",
        })?;
    let request_id = approval
        .get("id")
        .and_then(Value::as_str)
        .and_then(|id| Id::parse_str(id).ok())
        .ok_or(AppError::Internal {
            category: "action_approval_id_shape",
        })?;
    let plaintext = crypto
        .decrypt(
            EncryptionContext::tenant(
                ProtectedField::ActionApprovalEmail,
                organization,
                request_id,
            ),
            &encrypted,
        )
        .map_err(|_| AppError::Internal {
            category: "action_approval_email_decrypt",
        })?;
    approval["request_body"]["email"] = Value::String(
        String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Internal {
            category: "action_approval_email_encoding",
        })?,
    );
    Ok(())
}

fn validate_mutation_preconditions(request: &MutationRequest) -> Result<(), AppError> {
    let key = request
        .idempotency_key
        .as_deref()
        .ok_or_else(|| AppError::PreconditionRequired {
            code: "idempotency_key_required".into(),
        })?;
    IdempotencyKey::parse(key).map_err(|_| {
        AppError::invalid_field(
            "idempotency_key",
            "must contain 16 to 255 visible ASCII characters",
        )
    })?;
    if request.method != "POST" {
        let mut headers = HeaderMap::new();
        if let Some(version) = &request.expected_version {
            headers.insert(
                "if-match",
                version.parse().map_err(|_| {
                    AppError::invalid_field("if-match", "must be a quoted resource version")
                })?,
            );
        }
        validation::expected_version(&headers)?;
    }
    Ok(())
}

pub(super) async fn list_policies(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(org): Path<String>,
) -> Result<Response, AppError> {
    let org = validation::organization_id(&org)?.to_string();
    let mut scope = support::begin_organization(&state, &actor, &org).await?;
    let response: Value = sqlx::query_scalar("SELECT iam_private.list_action_policies($1)")
        .bind(scope.access.organization_id)
        .fetch_one(&mut *scope.transaction)
        .await
        .map_err(database)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &response, None)
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub(super) struct AutoApproval {
    #[serde(default)]
    carbon_ids: Vec<String>,
    #[serde(default)]
    silicon_ids: Vec<String>,
    #[serde(default)]
    tag_ids: Vec<Id>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyInput {
    allowed_actors: String,
    approval: String,
    #[serde(default)]
    auto_approve: AutoApproval,
}

pub(super) async fn update_policy(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path((org, action)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<PolicyInput>,
) -> Result<Response, AppError> {
    let org = validation::organization_id(&org)?.to_string();
    let expected_version = policy_version(&headers)?;
    if input
        .auto_approve
        .tag_ids
        .iter()
        .any(|id| !matches!(id, Id::Resource(_)))
    {
        return Err(AppError::invalid_field(
            "auto_approve.tag_ids",
            "must contain UUID tag IDs",
        ));
    }
    let mut scope = support::begin_organization(&state, &actor, &org).await?;
    let previous: Value = sqlx::query_scalar("SELECT iam_private.list_action_policies($1)")
        .bind(scope.access.organization_id)
        .fetch_one(&mut *scope.transaction)
        .await
        .map_err(database)?;
    let before = previous
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|item| item.get("action").and_then(Value::as_str) == Some(action.as_str()))
        .cloned();
    let response: Value =
        sqlx::query_scalar("SELECT iam_private.configure_action_policy($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(scope.access.organization_id)
            .bind(&action)
            .bind(expected_version)
            .bind(input.allowed_actors)
            .bind(input.approval)
            .bind(input.auto_approve.carbon_ids)
            .bind(input.auto_approve.silicon_ids)
            .bind(input.auto_approve.tag_ids)
            .fetch_one(&mut *scope.transaction)
            .await
            .map_err(database)?;
    record_audit(
        &mut scope,
        &actor,
        "action_policy.updated",
        before,
        response.clone(),
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(
        StatusCode::OK,
        &response,
        response.get("version").and_then(Value::as_i64),
    )
}

pub(super) async fn list_approvals(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path(org): Path<String>,
) -> Result<Response, AppError> {
    let org = validation::organization_id(&org)?.to_string();
    let mut scope = support::begin_organization(&state, &actor, &org).await?;
    let mut response: Value = sqlx::query_scalar("SELECT iam_private.list_action_approvals($1)")
        .bind(scope.access.organization_id)
        .fetch_one(&mut *scope.transaction)
        .await
        .map_err(database)?;
    if let Some(items) = response.get_mut("items").and_then(Value::as_array_mut) {
        for approval in items {
            reveal_review_body(&state.crypto, scope.access.organization_id, approval)?;
        }
    }
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(StatusCode::OK, &response, None)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionInput {
    decision: String,
}

pub(super) async fn decide_approval(
    State(state): State<ApiState>,
    actor: Authenticated,
    Path((org, request)): Path<(String, Id)>,
    headers: HeaderMap,
    Json(input): Json<DecisionInput>,
) -> Result<Response, AppError> {
    let org = validation::organization_id(&org)?.to_string();
    let expected_version = validation::expected_version(&headers)?;
    if !matches!(request, Id::Resource(_)) {
        return Err(AppError::invalid_field(
            "request_id",
            "must be a UUID approval request ID",
        ));
    }
    let mut scope = support::begin_organization(&state, &actor, &org).await?;
    let mut response: Value =
        sqlx::query_scalar("SELECT iam_private.decide_action_approval($1,$2,$3,$4)")
            .bind(scope.access.organization_id)
            .bind(request)
            .bind(expected_version)
            .bind(input.decision)
            .fetch_one(&mut *scope.transaction)
            .await
            .map_err(database)?;
    record_audit(
        &mut scope,
        &actor,
        "action_approval.decided",
        None,
        response.clone(),
    )
    .await?;
    reveal_review_body(&state.crypto, scope.access.organization_id, &mut response)?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json(
        StatusCode::OK,
        &response,
        response.get("version").and_then(Value::as_i64),
    )
}

fn policy_version(headers: &HeaderMap) -> Result<i64, AppError> {
    let value = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::PreconditionRequired {
            code: "if_match_required".into(),
        })?;
    value
        .trim_matches('"')
        .parse::<i64>()
        .ok()
        .filter(|version| *version >= 0)
        .ok_or_else(|| AppError::invalid_field("if-match", "must be a nonnegative policy version"))
}

async fn record_audit(
    scope: &mut OrganizationTransaction<'_>,
    actor: &Authenticated,
    action: &'static str,
    before: Option<Value>,
    mut after: Value,
) -> Result<(), AppError> {
    if let Some(fields) = after.as_object_mut() {
        fields.remove("request_body");
    }
    events::record_audit(
        &mut scope.transaction,
        AuditRecord {
            actor: Some(actor.0.subject),
            authentication_session_id: Some(actor.0.authentication_session_id),
            organization_id: Some(scope.access.organization_id),
            application_id: actor.0.client_application_id,
            action,
            target_type: "organization",
            target_id: Some(scope.access.organization_id),
            authentication_method: None,
            aggregate: None,
            before_state: before,
            after_state: Some(after),
            metadata: json!({}),
        },
    )
    .await
    .map_err(support::database)?;
    Ok(())
}

fn database(error: sqlx::Error) -> AppError {
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
    {
        Some("42501") => AppError::Forbidden,
        Some("P0002") => AppError::NotFound,
        Some("40001") => AppError::PreconditionFailed {
            code: Cow::Borrowed("version_mismatch"),
        },
        Some("22023") => AppError::invalid_field(
            "policy",
            "must use valid action rules and active organization identities or tags",
        ),
        _ => support::database(error),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
        middleware,
        routing::patch,
    };
    use serde_json::json;
    use tower::ServiceExt as _;

    use super::{
        MUTATION_REQUEST, MutationRequest, actions, capture_request, reveal_review_body,
        review_body, validate_mutation_preconditions,
    };

    fn request(path: &str, route: &str, body: serde_json::Value) -> MutationRequest {
        MutationRequest {
            method: "PATCH".into(),
            path: path.into(),
            route: route.into(),
            body,
            expected_version: Some("\"1\"".into()),
            idempotency_key: Some("profile-update".into()),
        }
    }

    #[test]
    fn silicon_self_profile_gate_keeps_hierarchy_separately_controlled() {
        let request = request(
            "/api/v1/organizations/bricks/silicons/si%3Achef",
            "/api/v1/organizations/{org_id}/silicons/{silicon_id}",
            json!({"timezone":"Asia/Kolkata"}),
        );
        assert_eq!(
            actions(&request, "si:chef"),
            vec!["silicon.self_profile.update"]
        );
        assert_eq!(
            actions(&request, "other:bricks"),
            vec!["silicon.profile.update"]
        );
        let composite = MutationRequest {
            body: json!({"timezone":"Asia/Kolkata","reports_to_membership_id":null}),
            ..request
        };
        assert_eq!(
            actions(&composite, "si:chef"),
            vec!["silicon.hierarchy.update", "silicon.self_profile.update"]
        );
    }

    #[test]
    fn member_patch_cannot_bypass_individual_sensitive_fields() {
        let request = request(
            "/api/v1/organizations/bricks/members/saket[bricks]",
            "/api/v1/organizations/{org_id}/members/{membership_id}",
            json!({"tag_ids":[],"default_trust":{"level":"trusted"},"extra_silicon_membership_ids":[],"reports_to_membership_id":null,"profile_photo":null}),
        );
        assert_eq!(
            actions(&request, "si:chef"),
            vec![
                "membership.directory.update",
                "membership.tags.update",
                "silicon.hierarchy.update",
                "silicon.profile.update",
                "trust.default.update"
            ]
        );
    }

    #[test]
    fn initial_assignments_obey_the_same_job_tag_hierarchy_and_trust_policies() {
        let mut creation = request(
            "/api/v1/organizations/bricks/silicons",
            "/api/v1/organizations/{org_id}/silicons",
            json!({"job_description":"Chef","tag_ids":["tag"],"reports_to_membership_id":"boss"}),
        );
        creation.method = "POST".into();
        assert_eq!(
            actions(&creation, "si:chef"),
            vec![
                "membership.job_description.update",
                "membership.tags.update",
                "silicon.hierarchy.update"
            ]
        );
        creation.route = "/api/v1/organizations/{org_id}/carbon-invites".into();
        creation.body = json!({"job_description":"Chef","tag_ids":[],"default_trust":{"level":"trusted"},"tag_trust_overrides":[{}],"extra_silicon_membership_ids":["chef"]});
        assert_eq!(
            actions(&creation, "saket"),
            vec![
                "membership.directory.update",
                "membership.job_description.update",
                "trust.default.update",
                "trust.rule.create"
            ]
        );
    }

    #[test]
    fn invitation_review_recipient_is_encrypted_and_bound_to_its_org_and_request()
    -> anyhow::Result<()> {
        use crate::{
            config::{KeyringSettings, SecuritySettings},
            domain::id::Id,
            infrastructure::crypto::CryptoService,
        };
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use secrecy::SecretString;
        use std::{collections::BTreeMap, time::Duration};

        let key = SecretString::from(URL_SAFE_NO_PAD.encode([17_u8; 32]));
        let keyring = KeyringSettings {
            current_version: 1,
            keys: BTreeMap::from([(1, key.clone())]),
        };
        let crypto = CryptoService::from_settings(&SecuritySettings {
            token_peppers: keyring.clone(),
            blind_index_keys: keyring.clone(),
            encryption_keys: keyring,
            cookie_key: key,
            access_token_ttl: Duration::from_mins(30),
            refresh_family_ttl: Duration::from_hours(24),
            authorization_code_ttl: Duration::from_secs(120),
            otp_ttl: Duration::from_secs(600),
            otp_max_attempts: 10,
        })?;
        let organization = Id::from_u128(1);
        let request_id = Id::from_u128(2);
        let mut input = request(
            "/api/v1/organizations/bricks/carbon-invites",
            "/api/v1/organizations/{org_id}/carbon-invites",
            json!({"email":"alice@example.com","job_description":"Chef"}),
        );
        input.method = "POST".into();
        let stored = review_body(&crypto, organization, request_id, &input)?;
        assert!(!stored.to_string().contains("alice@example.com"));
        assert!(stored["email"]["ciphertext"].is_array());
        assert_eq!(stored["job_description"], "Chef");
        let mut approval = json!({"id":request_id,"request_body":stored});
        assert!(reveal_review_body(&crypto, Id::from_u128(3), &mut approval.clone()).is_err());
        let mut other_request = approval.clone();
        other_request["id"] = json!(Id::from_u128(4));
        assert!(reveal_review_body(&crypto, organization, &mut other_request).is_err());
        reveal_review_body(&crypto, organization, &mut approval)?;
        assert_eq!(approval["request_body"], input.body);

        input.route = "/api/v1/organizations/{org_id}/silicons".into();
        assert_eq!(
            review_body(&crypto, organization, request_id, &input)?,
            input.body
        );
        Ok(())
    }

    #[test]
    fn approval_requests_cannot_be_created_without_valid_replay_preconditions() {
        let mut request = request(
            "/job-description",
            "/job-description",
            json!({"job_description":"Chef"}),
        );
        request.idempotency_key = Some("stable-request-key-123".into());
        assert!(validate_mutation_preconditions(&request).is_ok());
        request.idempotency_key = Some("short".into());
        assert!(validate_mutation_preconditions(&request).is_err());
        request.idempotency_key = Some("stable-request-key-123".into());
        request.expected_version = None;
        assert!(validate_mutation_preconditions(&request).is_err());
        request.expected_version = Some("\"0\"".into());
        assert!(validate_mutation_preconditions(&request).is_err());
        request.method = "POST".into();
        request.expected_version = None;
        assert!(validate_mutation_preconditions(&request).is_ok());
    }

    #[tokio::test]
    async fn router_middleware_retains_exact_body_path_and_retry_headers() -> anyhow::Result<()> {
        let app = Router::new().route("/api/v1/organizations/{org_id}/silicons/{silicon_id}", patch(|| async {
            let context = MUTATION_REQUEST.with(Clone::clone);
            axum::Json(json!({"actions":actions(&context,"si:chef"),"path":context.path,"body":context.body,
                "version":context.expected_version,"key":context.idempotency_key}))
        })).layer(middleware::from_fn(capture_request));
        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/organizations/bricks/silicons/si%3Achef")
                    .header("if-match", "\"1\"")
                    .header("idempotency-key", "timezone-retry")
                    .body(Body::from(r#"{"timezone":"Asia/Kolkata"}"#))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(
            value,
            json!({"actions":["silicon.self_profile.update"],"path":"/api/v1/organizations/bricks/silicons/si%3Achef",
            "body":{"timezone":"Asia/Kolkata"},"version":"\"1\"","key":"timezone-retry"})
        );
        Ok(())
    }
}
