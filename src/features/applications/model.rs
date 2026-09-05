use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize};
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

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationCreate {
    pub(super) app_id: String,
    pub(super) org_id: String,
    pub(super) base_url: String,
    pub(super) app_name: Option<String>,
    #[serde(rename = "app_logo")]
    pub(super) app_logo_uri: Option<String>,
    pub(super) webhook_url: String,
    #[serde(deserialize_with = "deserialize_secret_string")]
    pub(super) webhook_secret: SecretString,
    #[serde(default)]
    pub(super) obo_endpoints: Vec<ApplicationOboEndpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationPatch {
    pub(super) base_url: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_with::rust::double_option"
    )]
    #[allow(clippy::option_option)]
    pub(super) app_name: Option<Option<String>>,
    #[serde(rename = "app_logo")]
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_with::rust::double_option"
    )]
    #[allow(clippy::option_option)]
    pub(super) app_logo_uri: Option<Option<String>>,
    pub(super) obo_endpoints: Option<Vec<ApplicationOboEndpoint>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ApplicationSecretRotated {
    pub(super) app_id: String,
    pub(super) app_secret: String,
    pub(super) app_secret_version: i64,
    pub(super) application_version: i64,
    #[serde(with = "crate::wire_time")]
    pub(super) secret_replay_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct WebhookSecretRotated {
    pub(super) app_id: String,
    pub(super) webhook_signing_secret: String,
    pub(super) webhook_secret_version: i64,
    pub(super) application_version: i64,
    #[serde(with = "crate::wire_time")]
    pub(super) secret_replay_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub(super) struct ApplicationDirectoryEntry {
    pub(super) app_id: String,
    pub(super) base_url: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationOboEndpoint {
    pub(super) endpoint_id: String,
    pub(super) path: String,
    pub(super) metadata: serde_json::Value,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebhookSecretRotate {
    #[serde(deserialize_with = "deserialize_secret_string")]
    pub(super) webhook_secret: SecretString,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebhookReplace {
    pub(super) url: String,
    #[serde(default, deserialize_with = "deserialize_optional_secret_string")]
    pub(super) webhook_secret: Option<SecretString>,
}

fn deserialize_secret_string<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(SecretString::from)
}

fn deserialize_optional_secret_string<'de, D>(
    deserializer: D,
) -> Result<Option<SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|secret| secret.map(SecretString::from))
}

/// A platform decision about a live application.
///
/// Verification is no longer a gate an application waits behind -- one arrives
/// verified -- so this is what remains: suspending, rejecting or restoring one
/// that is already in use. There is no consent policy to set any more.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationAdminDecision {
    pub(super) decision: String,
    pub(super) reason: Option<String>,
    pub(super) approved_scopes: Option<Vec<String>>,
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
    pub(super) base_url: String,
    pub(super) review_status: String,
    pub(super) version: i64,
    #[serde(with = "crate::wire_time")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "crate::wire_time")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ApplicationDetail {
    pub(super) id: Uuid,
    pub(super) app_id: String,
    pub(super) org_id: String,
    pub(super) created_by: PublicActor,
    pub(super) app_name: Option<String>,
    pub(super) app_logo: Option<String>,
    pub(super) base_url: String,
    pub(super) requested_scopes: Vec<String>,
    pub(super) approved_scopes: Vec<String>,
    pub(super) obo_endpoints: Vec<ApplicationOboEndpoint>,
    pub(super) status: String,
    pub(super) webhook: WebhookView,
    pub(super) has_pending_changes: bool,
    pub(super) version: i64,
    #[serde(with = "crate::wire_time")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "crate::wire_time")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ApplicationCreated {
    pub(super) application: ApplicationDetail,
    pub(super) app_secret: String,
    pub(super) app_secret_version: i64,
    pub(super) webhook_signing_secret: String,
    pub(super) webhook_secret_version: i64,
    #[serde(with = "crate::wire_time")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) application_id: Option<Uuid>,
    pub(super) active_url: Option<String>,
    pub(super) pending_url: Option<String>,
    pub(super) status: String,
    pub(super) secret_version: i64,
    pub(super) version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) webhook_signing_secret: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::wire_time::option"
    )]
    pub(super) secret_replay_expires_at: Option<OffsetDateTime>,
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
    #[serde(with = "crate::wire_time")]
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
    #[serde(with = "crate::wire_time::option")]
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
    #[serde(with = "crate::wire_time")]
    pub(super) occurred_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct LoginEventPage {
    pub(super) items: Vec<LoginEventView>,
    pub(super) page: PageInfo,
}

/// The query a login arrives with.
///
/// `app_id` is what separates the two cases: named, this is a configured
/// application asking IAM to authenticate someone on its behalf; absent, it is
/// an ordinary Silicon IAM login and there is no token to hand anybody.
/// `redirect_uri` decides only how the token is delivered -- appended to that
/// URI, or shown on a page when there is nowhere to send it.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct LoginQuery {
    #[serde(default)]
    pub(super) app_id: Option<String>,
    #[serde(default)]
    pub(super) redirect_uri: Option<String>,
    #[serde(default)]
    pub(super) org_id: Option<String>,
}

/// What a signed-in caller asks a short-lived token for.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ShortLivedTokenRequest {
    pub(super) app_id: String,
    #[serde(default)]
    pub(super) org_id: Option<String>,
}

/// A short-lived token handed to a caller who is already signed in.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ShortLivedTokenResponse {
    pub(super) slt: String,
    pub(super) expires_in: i64,
}

/// Which login a token page is reporting on.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct LoginStatusQuery {
    pub(super) request: Uuid,
}

/// What an application presents to trade a credential for tokens.
///
/// Exactly one of `slt` and `refresh_token` is expected: the first completes a
/// login, the second renews one. The application authenticates itself the same
/// way in both cases, so there is no grant type left to name.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct AppTokenForm {
    pub(super) app_id: Option<String>,
    #[serde(default)]
    pub(super) slt: Option<String>,
    #[serde(default)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) authorization: Option<ApplicationAuthorization>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct AuthorizationTag {
    pub(super) id: Uuid,
    pub(super) name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ApplicationAuthorization {
    pub(super) principal_id: Uuid,
    pub(super) actor_type: String,
    pub(super) public_id: String,
    pub(super) organization_id: Uuid,
    pub(super) org_id: String,
    pub(super) membership_id: Uuid,
    pub(super) membership_version: i64,
    pub(super) authorization_epoch: i64,
    pub(super) audience: String,
    pub(super) testing_environment_id: Option<Uuid>,
    pub(super) scopes: Vec<String>,
    pub(super) org_role: Option<String>,
    pub(super) tags: Option<Vec<AuthorizationTag>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OboExchangeRequest {
    pub(super) subject_token: String,
    pub(super) audience: String,
    pub(super) endpoint_id: String,
    pub(super) metadata: serde_json::Value,
    pub(super) request: OboExchangeRequestBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OboExchangeRequestBinding {
    pub(super) method: String,
    pub(super) body_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct OboProofResponse {
    pub(super) access_proof: String,
    pub(super) proof_id: Uuid,
    pub(super) expires_in: u64,
    #[serde(with = "crate::wire_time")]
    pub(super) expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OboVerifyRequest {
    pub(super) access_proof: String,
    pub(super) request: OboVerifyRequestBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OboVerifyRequestBinding {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) body_sha256: String,
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
    pub(super) authorization: ApplicationAuthorization,
    pub(super) org_id: String,
    pub(super) endpoint: OboEndpointReference,
    pub(super) metadata: serde_json::Value,
    #[serde(with = "crate::wire_time")]
    pub(super) expires_at: OffsetDateTime,
    #[serde(with = "crate::wire_time")]
    pub(super) consumed_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use time::{OffsetDateTime, format_description::well_known::Rfc3339, macros::datetime};

    use super::*;

    fn actor() -> PublicActor {
        PublicActor {
            principal_id: Uuid::nil(),
            actor_type: "carbon".to_owned(),
            public_id: "owner_1".to_owned(),
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

    fn assert_rfc3339(value: &Value, field: &str) {
        let Some(encoded) = value.get(field).and_then(Value::as_str) else {
            panic!("{field} must be an RFC3339 string");
        };
        assert!(
            OffsetDateTime::parse(encoded, &Rfc3339).is_ok(),
            "{field} is not RFC3339: {encoded}"
        );
    }

    #[test]
    fn webhook_projection_distinguishes_initial_pending_from_active() {
        let value = serde_json::to_value(WebhookView {
            application_id: None,
            active_url: None,
            pending_url: Some("https://example.test/hook".to_owned()),
            status: "pending_review".to_owned(),
            secret_version: 1,
            version: 1,
            webhook_signing_secret: None,
            secret_replay_expires_at: None,
        })
        .unwrap_or(Value::Null);
        assert_required(
            value.clone(),
            &[
                "active_url",
                "pending_url",
                "status",
                "secret_version",
                "version",
            ],
        );
        let Value::Object(object) = value else {
            panic!("webhook projection must serialize as an object");
        };
        assert!(!object.contains_key("webhook_signing_secret"));
        assert!(!object.contains_key("secret_replay_expires_at"));
    }

    #[test]
    fn application_directory_discloses_only_the_qualified_id_and_base_url() {
        let value = serde_json::to_value(ApplicationDirectoryEntry {
            app_id: "tos>briefcase".to_owned(),
            base_url: "https://briefcase.example/api".to_owned(),
        })
        .unwrap_or(Value::Null);
        let Value::Object(object) = value else {
            panic!("directory entry must serialize as an object");
        };
        assert_eq!(object.len(), 2);
        assert_eq!(
            object.get("app_id").and_then(Value::as_str),
            Some("tos>briefcase")
        );
        assert_eq!(
            object.get("base_url").and_then(Value::as_str),
            Some("https://briefcase.example/api")
        );
        assert!(!object.contains_key("app_secret"));
        assert!(!object.contains_key("webhook_signing_secret"));
    }

    #[test]
    fn webhook_rotation_projects_the_new_secret_and_versions() {
        let value = serde_json::to_value(WebhookSecretRotated {
            app_id: "tos>briefcase".to_owned(),
            webhook_signing_secret: format!("whs_{}", "A".repeat(43)),
            webhook_secret_version: 2,
            application_version: 7,
            secret_replay_expires_at: datetime!(2026-01-01 0:10 UTC),
        })
        .unwrap_or(Value::Null);
        assert_required(
            value.clone(),
            &[
                "app_id",
                "webhook_signing_secret",
                "webhook_secret_version",
                "application_version",
                "secret_replay_expires_at",
            ],
        );
        assert_rfc3339(&value, "secret_replay_expires_at");
    }

    #[test]
    fn login_history_projection_contains_actor_and_request_outcome() {
        let value = serde_json::to_value(LoginEventView {
            id: Uuid::nil(),
            actor: actor(),
            app_id: Some("example>app".to_owned()),
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
        assert_rfc3339(&value, "occurred_at");
    }

    #[test]
    fn application_projection_uses_wire_compatible_timestamps() {
        let value = serde_json::to_value(ApplicationDetail {
            id: Uuid::nil(),
            app_id: "tos>briefcase".to_owned(),
            org_id: "tos".to_owned(),
            created_by: actor(),
            app_name: Some("Briefcase".to_owned()),
            app_logo: None,
            base_url: "https://briefcase.example".to_owned(),
            requested_scopes: Vec::new(),
            approved_scopes: Vec::new(),
            obo_endpoints: Vec::new(),
            status: "verified".to_owned(),
            webhook: WebhookView {
                application_id: None,
                active_url: Some("https://briefcase.example/webhooks/iam".to_owned()),
                pending_url: None,
                status: "active".to_owned(),
                secret_version: 1,
                version: 1,
                webhook_signing_secret: None,
                secret_replay_expires_at: None,
            },
            has_pending_changes: false,
            version: 1,
            created_at: datetime!(2026-01-01 0:00 UTC),
            updated_at: datetime!(2026-01-01 0:01 UTC),
        })
        .unwrap_or(Value::Null);

        assert_rfc3339(&value, "created_at");
        assert_rfc3339(&value, "updated_at");
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
}
