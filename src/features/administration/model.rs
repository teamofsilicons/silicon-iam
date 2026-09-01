//! Public administration response and request models.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// Public, contact-free principal reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct PublicActor {
    pub(super) principal_id: Uuid,
    #[serde(rename = "type")]
    pub(super) actor_type: String,
    pub(super) public_id: String,
}

/// Cursor pagination metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct PageInfo {
    pub(super) next_cursor: Option<String>,
    pub(super) has_more: bool,
}

/// Shared keyset pagination query.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
}

/// Body used to grant platform-administrator authority.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlatformAdministratorCreate {
    pub(super) carbon_id: String,
}

/// Active platform administrator and grant provenance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct PlatformAdministrator {
    pub(super) principal: PublicActor,
    pub(super) created_by: Option<PublicActor>,
    pub(super) created_at: OffsetDateTime,
}

/// Active platform-administrator page.
#[derive(Debug, Serialize)]
pub(super) struct PlatformAdministratorPage {
    pub(super) items: Vec<PlatformAdministrator>,
    pub(super) page: PageInfo,
}

/// Platform Carbon status mutation.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CarbonStatusReplace {
    pub(super) status: String,
    pub(super) reason: String,
}

/// Platform view of a Carbon's security status.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct CarbonAdminStatus {
    pub(super) principal: PublicActor,
    pub(super) status: String,
    pub(super) version: i64,
    pub(super) updated_at: OffsetDateTime,
}

/// Redacted append-only audit event.
#[derive(Clone, Debug, Serialize)]
pub(super) struct AuditEvent {
    pub(super) id: Uuid,
    pub(super) org_id: Option<String>,
    pub(super) app_id: Option<String>,
    pub(super) actor: Option<PublicActor>,
    pub(super) effective_actor: Option<PublicActor>,
    pub(super) action: String,
    pub(super) target_type: String,
    pub(super) target_id: Option<Uuid>,
    pub(super) request_id: String,
    pub(super) auth_method: Option<String>,
    pub(super) redacted_diff: Value,
    pub(super) occurred_at: OffsetDateTime,
}

/// Audit event keyset page.
#[derive(Debug, Serialize)]
pub(super) struct AuditEventPage {
    pub(super) items: Vec<AuditEvent>,
    pub(super) page: PageInfo,
}

/// Audit filters with bounded keyset pagination.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuditQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
    pub(super) action: Option<String>,
    pub(super) target_principal_id: Option<Uuid>,
    pub(super) from: Option<OffsetDateTime>,
    pub(super) to: Option<OffsetDateTime>,
}

/// One bounded outbound delivery attempt.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct WebhookDeliveryAttempt {
    pub(super) attempt: i32,
    pub(super) started_at: OffsetDateTime,
    pub(super) duration_ms: Option<i32>,
    pub(super) outcome: String,
    pub(super) response_status: Option<i16>,
    pub(super) response_body_digest: Option<String>,
}

/// Redacted outbound delivery state.
#[derive(Clone, Debug, Serialize)]
pub(super) struct WebhookDelivery {
    pub(super) id: Uuid,
    pub(super) destination_type: String,
    pub(super) destination_id: Uuid,
    pub(super) event_id: Uuid,
    pub(super) event_type: String,
    pub(super) aggregate_id: Uuid,
    pub(super) aggregate_version: i64,
    pub(super) status: String,
    pub(super) attempts: Vec<WebhookDeliveryAttempt>,
    pub(super) next_attempt_at: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

/// Outbound delivery keyset page.
#[derive(Debug, Serialize)]
pub(super) struct WebhookDeliveryPage {
    pub(super) items: Vec<WebhookDelivery>,
    pub(super) page: PageInfo,
}

/// Failed delivery list filters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeliveryQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
    pub(super) destination_type: Option<String>,
}
