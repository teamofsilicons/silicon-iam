use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::auth::CarbonId;

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
pub(super) struct AvailabilityPath {
    pub(super) app_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct AppPath {
    pub(super) app_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct CollaboratorPath {
    pub(super) app_id: String,
    pub(super) principal_id: Uuid,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct GrantPath {
    pub(super) grant_id: Uuid,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct DeliveryPath {
    pub(super) app_id: String,
    pub(super) delivery_id: Uuid,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplicationCreate {
    pub(super) app_id: String,
    pub(super) app_name: Option<String>,
    #[serde(rename = "app_logo")]
    pub(super) app_logo_uri: Option<String>,
    pub(super) redirect_uris: Vec<String>,
    pub(super) webhook_url: String,
    pub(super) requested_scopes: Vec<String>,
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
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CollaboratorCreate {
    pub(super) carbon_id: CarbonId,
    pub(super) role: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecretRotationRequest {
    #[serde(default)]
    pub(super) overlap_seconds: u16,
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
    pub(super) owner_carbon_id: Uuid,
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
    pub(super) owner: PublicActor,
    pub(super) app_name: Option<String>,
    pub(super) app_logo: Option<String>,
    pub(super) redirect_uris: Vec<String>,
    pub(super) requested_scopes: Vec<String>,
    pub(super) approved_scopes: Vec<String>,
    pub(super) status: String,
    pub(super) notify_users: bool,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct CollaboratorView {
    pub(super) principal: PublicActor,
    pub(super) role: String,
    pub(super) created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct CollaboratorPage {
    pub(super) items: Vec<CollaboratorView>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ApplicationSecretRotated {
    pub(super) app_id: String,
    pub(super) app_secret: String,
    pub(super) secret_version: i64,
    pub(super) previous_valid_until: OffsetDateTime,
    pub(super) secret_replay_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct WebhookSecretRotated {
    pub(super) app_id: String,
    pub(super) webhook_signing_secret: String,
    pub(super) secret_version: i64,
    pub(super) previous_valid_until: OffsetDateTime,
    pub(super) secret_replay_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Availability {
    pub(super) available: bool,
}

#[derive(Clone, Debug)]
pub(super) struct WebhookEndpointView {
    pub(super) url: String,
    pub(super) status: String,
    pub(super) version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct WebhookView {
    pub(super) active_url: Option<String>,
    pub(super) pending_url: Option<String>,
    pub(super) status: String,
    pub(super) secret_version: i64,
    pub(super) version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
pub(super) struct PublicActor {
    pub(super) principal_id: Uuid,
    #[serde(rename = "type")]
    pub(super) actor_type: String,
    pub(super) public_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct DeliveryView {
    pub(super) id: Uuid,
    pub(super) destination_type: String,
    pub(super) destination_id: Uuid,
    pub(super) event_id: Uuid,
    pub(super) event_type: String,
    pub(super) aggregate_id: Uuid,
    pub(super) aggregate_version: i64,
    pub(super) status: String,
    pub(super) attempts: Vec<DeliveryAttemptView>,
    pub(super) next_attempt_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct DeliveryPage {
    pub(super) items: Vec<DeliveryView>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct DeliveryAttemptView {
    pub(super) attempt: i32,
    pub(super) started_at: OffsetDateTime,
    pub(super) duration_ms: Option<i32>,
    pub(super) outcome: String,
    pub(super) response_status: Option<i16>,
    pub(super) response_body_digest: Option<String>,
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
    pub(super) nonce: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) id_token: Option<String>,
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

#[derive(Clone, Debug, Serialize)]
pub(super) struct UserInfo {
    pub(super) sub: Uuid,
    pub(super) actor_type: String,
    pub(super) public_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) membership_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) org_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) job_role: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub(super) struct GrantView {
    pub(super) id: Uuid,
    pub(super) app_id: String,
    #[sqlx(flatten)]
    pub(super) actor: PublicActor,
    pub(super) org_id: Option<String>,
    pub(super) scopes: Vec<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct GrantPage {
    pub(super) items: Vec<GrantView>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OboExchangeRequest {
    pub(super) subject_token: String,
    pub(super) audience: String,
    pub(super) action: String,
    pub(super) resource: Option<String>,
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
    pub(super) audience: String,
    pub(super) action: String,
    pub(super) resource: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct OboAccessResult {
    pub(super) valid: bool,
    pub(super) proof_id: Uuid,
    pub(super) issuer_app_id: String,
    pub(super) audience: String,
    pub(super) actor: PublicActor,
    pub(super) org_id: String,
    pub(super) action: String,
    pub(super) resource: Option<String>,
    pub(super) expires_at: OffsetDateTime,
    pub(super) consumed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct DiscoveryDocument {
    pub(super) issuer: String,
    pub(super) authorization_endpoint: String,
    pub(super) token_endpoint: String,
    pub(super) userinfo_endpoint: String,
    pub(super) jwks_uri: String,
    pub(super) revocation_endpoint: String,
    pub(super) introspection_endpoint: String,
    pub(super) response_types_supported: Vec<&'static str>,
    pub(super) grant_types_supported: Vec<&'static str>,
    pub(super) subject_types_supported: Vec<&'static str>,
    pub(super) id_token_signing_alg_values_supported: Vec<String>,
    pub(super) code_challenge_methods_supported: Vec<&'static str>,
    pub(super) scopes_supported: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct JwkSet {
    pub(super) keys: Vec<serde_json::Value>,
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
    fn delivery_projection_contains_every_required_contract_field() {
        let value = serde_json::to_value(DeliveryView {
            id: Uuid::nil(),
            destination_type: "application".to_owned(),
            destination_id: Uuid::nil(),
            event_id: Uuid::nil(),
            event_type: "carbon.updated.v1".to_owned(),
            aggregate_id: Uuid::nil(),
            aggregate_version: 1,
            status: "pending".to_owned(),
            attempts: vec![DeliveryAttemptView {
                attempt: 1,
                started_at: datetime!(2026-01-01 0:00 UTC),
                duration_ms: Some(10),
                outcome: "success".to_owned(),
                response_status: Some(204),
                response_body_digest: None,
            }],
            next_attempt_at: Some(datetime!(2026-01-01 0:01 UTC)),
            created_at: datetime!(2026-01-01 0:00 UTC),
            updated_at: datetime!(2026-01-01 0:00 UTC),
        })
        .unwrap_or(Value::Null);
        assert_required(
            value.clone(),
            &[
                "id",
                "destination_type",
                "destination_id",
                "event_id",
                "event_type",
                "aggregate_id",
                "aggregate_version",
                "status",
                "attempts",
                "created_at",
                "updated_at",
            ],
        );
        let attempt = value
            .get("attempts")
            .and_then(Value::as_array)
            .and_then(|attempts| attempts.first())
            .cloned()
            .unwrap_or(Value::Null);
        assert_required(attempt, &["attempt", "started_at", "outcome"]);
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
    fn consent_grant_projection_contains_actor_and_lifecycle_timestamps() {
        let value = serde_json::to_value(GrantView {
            id: Uuid::nil(),
            app_id: "example-app".to_owned(),
            actor: actor(),
            org_id: None,
            scopes: vec!["openid".to_owned()],
            created_at: datetime!(2026-01-01 0:00 UTC),
            updated_at: datetime!(2026-01-01 0:00 UTC),
        })
        .unwrap_or(Value::Null);
        assert_required(
            value.clone(),
            &[
                "id",
                "app_id",
                "actor",
                "scopes",
                "created_at",
                "updated_at",
            ],
        );
        assert_nested_required(&value, "actor", &["principal_id", "type", "public_id"]);
    }

    #[test]
    fn oauth_token_projection_always_contains_a_rotating_refresh_token() {
        let value = serde_json::to_value(TokenResponse {
            access_token: format!("oat_{}", "A".repeat(43)),
            token_type: "Bearer".to_owned(),
            expires_in: 900,
            scope: "openid".to_owned(),
            id_token: Some("header.claims.signature".to_owned()),
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
