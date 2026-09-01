use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize)]
pub(super) struct PageQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
    pub(super) status: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct PageInfo {
    pub(super) next_cursor: Option<String>,
    pub(super) has_more: bool,
}

impl PageInfo {
    pub(super) fn from_next_cursor(next_cursor: Option<String>) -> Self {
        Self {
            has_more: next_cursor.is_some(),
            next_cursor,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct AppPath {
    pub(super) app_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct AppRedirectPath {
    pub(super) app_id: String,
    pub(super) redirect_uri_id: Uuid,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationCreate {
    pub(super) app_id: String,
    pub(super) org_id: String,
    pub(super) app_name: Option<String>,
    #[serde(rename = "app_logo")]
    pub(super) app_logo_uri: Option<String>,
    pub(super) redirect_uris: Vec<String>,
    pub(super) webhook_url: String,
    pub(super) requested_scopes: Vec<String>,
    #[serde(default)]
    pub(super) obo_endpoints: Vec<ApplicationOboEndpoint>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationPatch {
    #[allow(clippy::option_option)]
    pub(super) app_name: Option<Option<String>>,
    #[serde(rename = "app_logo")]
    #[allow(clippy::option_option)]
    pub(super) app_logo_uri: Option<Option<String>>,
    pub(super) redirect_uris: Option<Vec<String>>,
    pub(super) requested_scopes: Option<Vec<String>>,
    pub(super) obo_endpoints: Option<Vec<ApplicationOboEndpoint>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedirectUriCreate {
    pub(super) redirect_uri: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
pub(super) struct RedirectUriView {
    pub(super) id: Uuid,
    pub(super) redirect_uri: String,
    pub(super) status: String,
    pub(super) version: i64,
    pub(super) created_at: OffsetDateTime,
    pub(super) approved_at: Option<OffsetDateTime>,
    pub(super) retired_at: Option<OffsetDateTime>,
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct RedirectUriPage {
    pub(super) items: Vec<RedirectUriView>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct RedirectUriMutation {
    pub(super) redirect_uri: RedirectUriView,
    pub(super) application_version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ApplicationSecretRotated {
    pub(super) app_id: String,
    pub(super) app_secret: String,
    pub(super) app_secret_version: i64,
    pub(super) application_version: i64,
    pub(super) secret_replay_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationOboEndpoint {
    pub(super) endpoint_id: String,
    pub(super) path: String,
    pub(super) metadata: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebhookReplace {
    pub(super) url: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationAdminDecision {
    pub(super) decision: String,
    pub(super) reason: Option<String>,
    pub(super) approved_scopes: Option<Vec<String>>,
    pub(super) notify_users: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
pub(super) struct ApplicationView {
    pub(super) id: Uuid,
    pub(super) app_id: String,
    pub(super) organization_id: Uuid,
    pub(super) org_id: String,
    pub(super) created_by_carbon_id: Uuid,
    pub(super) app_name: Option<String>,
    pub(super) app_logo_uri: Option<String>,
    pub(super) review_status: String,
    pub(super) version: i64,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ApplicationDetail {
    pub(super) id: Uuid,
    pub(super) app_id: String,
    pub(super) org_id: String,
    pub(super) created_by: PublicActor,
    pub(super) app_name: Option<String>,
    pub(super) app_logo: Option<String>,
    pub(super) redirect_uris: Vec<String>,
    pub(super) requested_scopes: Vec<String>,
    pub(super) approved_scopes: Vec<String>,
    pub(super) obo_endpoints: Vec<ApplicationOboEndpoint>,
    pub(super) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) notify_users: Option<bool>,
    pub(super) webhook: WebhookView,
    pub(super) has_pending_changes: bool,
    pub(super) version: i64,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ApplicationCreated {
    pub(super) application: ApplicationDetail,
    pub(super) app_secret: String,
    pub(super) app_secret_version: i64,
    pub(super) webhook_signing_secret: String,
    pub(super) webhook_secret_version: i64,
    pub(super) secret_replay_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ApplicationPage {
    pub(super) items: Vec<ApplicationDetail>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug)]
pub(super) struct WebhookEndpointView {
    pub(super) url: String,
    pub(super) status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct WebhookView {
    pub(super) active_url: Option<String>,
    pub(super) pending_url: Option<String>,
    pub(super) status: String,
    pub(super) secret_version: i64,
    pub(super) version: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct DeadLetterPageQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
pub(super) struct WebhookDeadLetterView {
    pub(super) delivery_id: Uuid,
    pub(super) event_id: Uuid,
    pub(super) event_type: String,
    pub(super) occurred_at: OffsetDateTime,
    pub(super) aggregate_type: String,
    pub(super) aggregate_id: Uuid,
    pub(super) aggregate_version: i64,
    pub(super) status: String,
    pub(super) attempt_count: i32,
    pub(super) cycle_attempt_count: i32,
    pub(super) manual_replay_count: i32,
    pub(super) last_http_status: Option<i16>,
    pub(super) last_error_code: Option<String>,
    pub(super) dead_lettered_at: Option<OffsetDateTime>,
    pub(super) version: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct WebhookDeadLetterPage {
    pub(super) items: Vec<WebhookDeadLetterView>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebhookReplayRequest {
    pub(super) delivery_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct WebhookReplayResponse {
    pub(super) deliveries: Vec<WebhookDeadLetterView>,
    pub(super) replayed_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
pub(super) struct PublicActor {
    pub(super) principal_id: Uuid,
    #[serde(rename = "type")]
    pub(super) actor_type: String,
    pub(super) public_id: String,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub(super) struct LoginEventView {
    pub(super) id: Uuid,
    #[sqlx(flatten)]
    pub(super) actor: PublicActor,
    pub(super) app_id: Option<String>,
    pub(super) org_id: Option<String>,
    pub(super) event_type: String,
    pub(super) success: bool,
    pub(super) ip_prefix: Option<String>,
    pub(super) user_agent_summary: Option<String>,
    pub(super) request_id: String,
    pub(super) occurred_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct LoginEventPage {
    pub(super) items: Vec<LoginEventView>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct AuthorizeQuery {
    pub(super) response_type: String,
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) scope: String,
    pub(super) state: String,
    pub(super) code_challenge: String,
    pub(super) code_challenge_method: String,
    pub(super) org_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConsentDecision {
    #[serde(rename = "authorization_transaction_id")]
    pub(super) authorization_request_id: Uuid,
    pub(super) decision: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct TokenForm {
    pub(super) grant_type: String,
    pub(super) client_id: Option<String>,
    pub(super) code: Option<String>,
    pub(super) redirect_uri: Option<String>,
    pub(super) code_verifier: Option<String>,
    pub(super) refresh_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct TokenResponse {
    pub(super) access_token: String,
    pub(super) token_type: String,
    pub(super) expires_in: u64,
    pub(super) scope: String,
    pub(super) refresh_token: String,
    pub(super) actor: PublicActor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) org_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct TokenInput {
    pub(super) token: String,
    pub(super) token_type_hint: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct IntrospectionResponse {
    pub(super) active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) principal_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) actor_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) membership_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) session_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) issued_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) authorization_epoch: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OboExchangeRequest {
    pub(super) subject_token: String,
    pub(super) audience: String,
    pub(super) endpoint_id: String,
    pub(super) metadata: serde_json::Value,
    pub(super) org_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct OboProofResponse {
    pub(super) access_proof: String,
    pub(super) proof_id: Uuid,
    pub(super) expires_in: u64,
    pub(super) expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OboVerifyRequest {
    pub(super) access_proof: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct OboEndpointReference {
    pub(super) endpoint_id: String,
    pub(super) path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct OboAccessResult {
    pub(super) valid: bool,
    pub(super) proof_id: Uuid,
    pub(super) issuer_app_id: String,
    pub(super) audience: String,
    pub(super) actor: PublicActor,
    pub(super) org_id: String,
    pub(super) endpoint: OboEndpointReference,
    pub(super) metadata: serde_json::Value,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use time::macros::datetime;

    use super::*;

    fn actor() -> PublicActor {
        PublicActor {
            principal_id: Uuid::nil(),
            actor_type: "carbon".to_owned(),
            public_id: "owner_1".to_owned(),
        }
    }

    fn application_detail(notify_users: Option<bool>) -> ApplicationDetail {
        ApplicationDetail {
            id: Uuid::nil(),
            app_id: "example-app".to_owned(),
            org_id: "example-org".to_owned(),
            created_by: actor(),
            app_name: Some("Example".to_owned()),
            app_logo: None,
            redirect_uris: vec!["https://example.test/callback".to_owned()],
            requested_scopes: vec!["organizations.read".to_owned()],
            approved_scopes: Vec::new(),
            obo_endpoints: Vec::new(),
            status: "under_review".to_owned(),
            notify_users,
            webhook: WebhookView {
                active_url: None,
                pending_url: Some("https://example.test/hook".to_owned()),
                status: "pending_review".to_owned(),
                secret_version: 1,
                version: 1,
            },
            has_pending_changes: true,
            version: 1,
            created_at: datetime!(2026-01-01 0:00 UTC),
            updated_at: datetime!(2026-01-01 0:00 UTC),
        }
    }

    fn assert_required(value: Value, keys: &[&str]) {
        let Value::Object(object) = value else {
            panic!("contract projection must serialize as an object");
        };
        for key in keys {
            assert!(object.contains_key(*key), "missing required field {key}");
        }
    }

    fn assert_nested_required(value: &Value, field: &str, keys: &[&str]) {
        let Some(Value::Object(object)) = value.get(field) else {
            panic!("required nested field {field} must be an object");
        };
        for key in keys {
            assert!(
                object.contains_key(*key),
                "missing required field {field}.{key}"
            );
        }
    }

    #[test]
    fn webhook_projection_distinguishes_initial_pending_from_active() {
        assert_required(
            serde_json::to_value(WebhookView {
                active_url: None,
                pending_url: Some("https://example.test/hook".to_owned()),
                status: "pending_review".to_owned(),
                secret_version: 1,
                version: 1,
            })
            .unwrap_or(Value::Null),
            &[
                "active_url",
                "pending_url",
                "status",
                "secret_version",
                "version",
            ],
        );
    }

    #[test]
    fn login_history_projection_contains_actor_and_request_outcome() {
        let value = serde_json::to_value(LoginEventView {
            id: Uuid::nil(),
            actor: actor(),
            app_id: Some("example-app".to_owned()),
            org_id: None,
            event_type: "oauth_token_exchange".to_owned(),
            success: true,
            ip_prefix: None,
            user_agent_summary: None,
            request_id: Uuid::nil().to_string(),
            occurred_at: datetime!(2026-01-01 0:00 UTC),
        })
        .unwrap_or(Value::Null);
        assert_required(
            value.clone(),
            &[
                "id",
                "actor",
                "event_type",
                "occurred_at",
                "success",
                "request_id",
            ],
        );
        assert_nested_required(&value, "actor", &["principal_id", "type", "public_id"]);
    }

    #[test]
    fn oauth_token_projection_always_contains_a_rotating_refresh_token() {
        let value = serde_json::to_value(TokenResponse {
            access_token: format!("oat_{}", "A".repeat(43)),
            token_type: "Bearer".to_owned(),
            expires_in: 1_800,
            scope: "organizations.read".to_owned(),
            refresh_token: format!("ort_{}", "B".repeat(43)),
            actor: actor(),
            org_id: None,
        })
        .unwrap_or(Value::Null);
        assert_required(
            value.clone(),
            &[
                "access_token",
                "refresh_token",
                "token_type",
                "expires_in",
                "scope",
                "actor",
            ],
        );
        assert_nested_required(&value, "actor", &["principal_id", "type", "public_id"]);
    }

    #[test]
    fn organization_application_projection_omits_backend_consent_policy() {
        let owner = serde_json::to_value(application_detail(None)).unwrap_or(Value::Null);
        assert!(owner.get("notify_users").is_none());

        let admin = serde_json::to_value(application_detail(Some(false))).unwrap_or(Value::Null);
        assert_eq!(admin.get("notify_users"), Some(&Value::Bool(false)));
    }
}
