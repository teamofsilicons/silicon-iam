use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
}

#[derive(Debug, Serialize)]
pub(super) struct PageInfo {
    pub(super) next_cursor: Option<String>,
    pub(super) has_more: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct AvailabilityResponse {
    pub(super) available: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OrganizationCreate {
    pub(super) org_id: String,
    pub(super) name: String,
    pub(super) logo: Option<String>,
    pub(super) description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::option_option)]
pub(super) struct OrganizationPatch {
    pub(super) name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) logo: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<Option<String>>,
    pub(super) join_method: Option<String>,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub(super) struct OrganizationResponse {
    pub(super) id: Uuid,
    pub(super) org_id: String,
    pub(super) name: String,
    pub(super) logo: Option<String>,
    pub(super) description: Option<String>,
    pub(super) owner_membership_id: Uuid,
    pub(super) join_method: String,
    pub(super) sso_status: String,
    pub(super) status: String,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct OrganizationPage {
    pub(super) items: Vec<OrganizationResponse>,
    pub(super) page: PageInfo,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwnershipTransfer {
    pub(super) new_owner_membership_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ActorResponse {
    pub(super) principal_id: Uuid,
    #[serde(rename = "type")]
    pub(super) actor_type: String,
    pub(super) public_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
pub(super) struct TagSummary {
    pub(super) id: Uuid,
    pub(super) name: String,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub(super) struct TagResponse {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) org_id: String,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct TagPage {
    pub(super) items: Vec<TagResponse>,
    pub(super) page: PageInfo,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TagInput {
    pub(super) name: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MemberQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
    pub(super) principal_type: Option<String>,
    pub(super) tag_id: Option<Uuid>,
    pub(super) status: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StatusPageQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
    pub(super) status: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SiliconQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
    pub(super) tag_id: Option<Uuid>,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub(super) struct MembershipResponse {
    pub(super) id: Uuid,
    pub(super) org_id: String,
    pub(super) principal: sqlx::types::Json<ActorResponse>,
    pub(super) status: String,
    pub(super) org_role: String,
    pub(super) job_role: String,
    pub(super) tags: sqlx::types::Json<Vec<TagSummary>>,
    pub(super) first_silicon_membership_id: Option<Uuid>,
    pub(super) extra_silicons: Vec<Uuid>,
    pub(super) default_trust: Option<sqlx::types::Json<TrustValue>>,
    pub(super) reports_to_membership_id: Option<Uuid>,
    pub(super) hierarchy_level: Option<i32>,
    pub(super) authorization_epoch: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) removed_at: Option<OffsetDateTime>,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct MembershipPage {
    pub(super) items: Vec<MembershipResponse>,
    pub(super) page: PageInfo,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::option_option)]
pub(super) struct MembershipDirectoryPatch {
    pub(super) tag_ids: Option<Vec<Uuid>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) first_silicon_membership_id: Option<Option<Uuid>>,
    pub(super) extra_silicon_membership_ids: Option<Vec<Uuid>>,
    pub(super) default_trust: Option<TrustValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reports_to_membership_id: Option<Option<Uuid>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) profile_photo: Option<Option<String>>,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub(super) struct MembershipAuthorizationResponse {
    pub(super) membership_id: Uuid,
    pub(super) org_role: String,
    pub(super) capabilities: Vec<String>,
    pub(super) authorization_epoch: i64,
    pub(super) version: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CapabilitiesReplace {
    pub(super) capabilities: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SiliconCreate {
    pub(super) silicon_id: String,
    pub(super) display_name: Option<String>,
    pub(super) timezone: Option<String>,
    pub(super) description: Option<String>,
    pub(super) profile_photo: Option<String>,
    pub(super) job_role: String,
    pub(super) reports_to_membership_id: Option<Uuid>,
    #[serde(default)]
    pub(super) tag_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::option_option)]
pub(super) struct SiliconPatch {
    pub(super) display_name: Option<String>,
    pub(super) timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) profile_photo: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reports_to_membership_id: Option<Option<Uuid>>,
    pub(super) tag_ids: Option<Vec<Uuid>>,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub(super) struct SiliconResponse {
    pub(super) principal_id: Uuid,
    pub(super) membership_id: Uuid,
    pub(super) silicon_id: String,
    pub(super) org_id: String,
    pub(super) display_name: String,
    pub(super) timezone: String,
    pub(super) description: Option<String>,
    pub(super) profile_photo: String,
    pub(super) job_role: String,
    pub(super) reports_to_membership_id: Option<Uuid>,
    pub(super) tags: sqlx::types::Json<Vec<TagSummary>>,
    pub(super) hierarchy_level: i32,
    pub(super) webhook_configured: bool,
    pub(super) status: String,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct SiliconPage {
    pub(super) items: Vec<SiliconResponse>,
    pub(super) page: PageInfo,
}

#[derive(Debug, Serialize)]
pub(super) struct SiliconCreatedResponse {
    pub(super) silicon: SiliconResponse,
    pub(super) silicon_token: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) secret_replay_expires_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SiliconWebhookReplace {
    pub(super) url: String,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct SiliconWebhookResponse {
    pub(super) silicon_id: String,
    pub(super) url: String,
    pub(super) status: String,
    pub(super) secret_version: i64,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct SiliconWebhookConfiguredResponse {
    pub(super) webhook: SiliconWebhookResponse,
    pub(super) webhook_signing_secret: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) secret_replay_expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct WebhookDeadLetterResponse {
    pub(super) delivery_id: Uuid,
    pub(super) event_id: Uuid,
    pub(super) event_type: String,
    #[serde(with = "time::serde::rfc3339")]
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
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) dead_lettered_at: Option<OffsetDateTime>,
    pub(super) version: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct WebhookDeadLetterPage {
    pub(super) items: Vec<WebhookDeadLetterResponse>,
    pub(super) page: PageInfo,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebhookReplayRequest {
    pub(super) delivery_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub(super) struct WebhookReplayResponse {
    pub(super) deliveries: Vec<WebhookDeadLetterResponse>,
    pub(super) replayed_count: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SiliconWebhookSubscriptionMode {
    All,
    Selected,
}

impl SiliconWebhookSubscriptionMode {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Selected => "selected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SiliconWebhookTopic {
    MembershipLifecycle,
    MemberUpdates,
    TrustUpdates,
}

impl SiliconWebhookTopic {
    pub(super) const ALL: [Self; 3] = [
        Self::MembershipLifecycle,
        Self::MemberUpdates,
        Self::TrustUpdates,
    ];

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::MembershipLifecycle => "membership_lifecycle",
            Self::MemberUpdates => "member_updates",
            Self::TrustUpdates => "trust_updates",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SiliconWebhookSubscriptionReplace {
    pub(super) mode: SiliconWebhookSubscriptionMode,
    #[serde(default)]
    pub(super) topics: Vec<SiliconWebhookTopic>,
    pub(super) tag_filter: Option<SiliconWebhookTagFilter>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SiliconWebhookTagFilter {
    #[serde(default)]
    pub(super) additional_tag_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct SiliconWebhookSubscriptionResponse {
    pub(super) silicon_id: String,
    pub(super) mode: SiliconWebhookSubscriptionMode,
    pub(super) topics: Vec<SiliconWebhookTopic>,
    pub(super) tag_filter: Option<SiliconWebhookTagFilter>,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct SiliconTokenRotatedResponse {
    pub(super) silicon_id: String,
    pub(super) credential_version: i64,
    pub(super) silicon_token: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) secret_replay_expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TrustBoundary {
    Internal,
    External,
}

impl TrustBoundary {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TrustLevel {
    NotTrusted,
    NeedsApproval,
    Trusted,
}

impl TrustLevel {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::NotTrusted => "not_trusted",
            Self::NeedsApproval => "needs_approval",
            Self::Trusted => "trusted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustValue {
    pub(super) boundary: TrustBoundary,
    pub(super) level: TrustLevel,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub(super) enum TrustSelector {
    Tag { tag_id: Uuid },
    Membership { membership_id: Uuid },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustRuleInput {
    pub(super) subject: TrustSelector,
    pub(super) target: TrustSelector,
    pub(super) trust: TrustValue,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustRulePatch {
    pub(super) subject: Option<TrustSelector>,
    pub(super) target: Option<TrustSelector>,
    pub(super) trust: Option<TrustValue>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustEvaluationInput {
    pub(super) subject_membership_id: Uuid,
    pub(super) target_silicon_membership_id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct TrustRuleResponse {
    pub(super) id: Uuid,
    pub(super) org_id: String,
    pub(super) subject: TrustSelector,
    pub(super) target: TrustSelector,
    pub(super) trust: TrustValue,
    pub(super) specificity: i16,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct TrustRulePage {
    pub(super) items: Vec<TrustRuleResponse>,
    pub(super) page: PageInfo,
}

#[derive(Debug, Serialize)]
pub(super) struct TrustEvaluationResponse {
    pub(super) trust: TrustValue,
    pub(super) source: String,
    pub(super) matching_rule_ids: Vec<Uuid>,
    pub(super) advisory: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleChangeRequestCreate {
    pub(super) target_membership_id: Uuid,
    pub(super) proposed_job_role: String,
    pub(super) reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TagChangeRequestCreate {
    #[serde(default)]
    pub(super) add_tag_ids: Vec<Uuid>,
    #[serde(default)]
    pub(super) remove_tag_ids: Vec<Uuid>,
    pub(super) reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectJobRoleReplace {
    pub(super) job_role: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectTagSetReplace {
    pub(super) tag_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalDecisionCreate {
    pub(super) decision: String,
    pub(super) comment: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
    pub(super) status: Option<String>,
    pub(super) kind: Option<String>,
    pub(super) actionable_by_me: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CarbonInviteCreate {
    pub(super) carbon_id: Option<String>,
    pub(super) email: Option<String>,
    pub(super) job_role: String,
    #[serde(default)]
    pub(super) tag_ids: Vec<Uuid>,
    pub(super) first_silicon_membership_id: Option<Uuid>,
    #[serde(default)]
    pub(super) extra_silicon_membership_ids: Vec<Uuid>,
    pub(super) default_trust: TrustValue,
    #[serde(default)]
    pub(super) tag_trust_overrides: Vec<InvitationTagTrustOverride>,
    #[serde(default)]
    pub(super) silicon_trust_overrides: Vec<InvitationSiliconTrustOverride>,
    pub(super) redirect_app_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InvitationTagTrustOverride {
    pub(super) tag_id: Uuid,
    pub(super) trust: TrustValue,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InvitationSiliconTrustOverride {
    pub(super) silicon_membership_id: Uuid,
    pub(super) trust: TrustValue,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InvitationAcceptance {
    pub(super) invite_id: Uuid,
    pub(super) verification_code: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InvitationEmailCodeRequest {
    pub(super) email: String,
}

#[derive(Debug, Serialize)]
pub(super) struct InvitationEmailCodeResponse {
    pub(super) accepted: bool,
    pub(super) invite_id: Uuid,
    pub(super) expires_in: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct CarbonPublicResponse {
    pub(super) principal_id: Uuid,
    pub(super) carbon_id: String,
    pub(super) display_name: String,
    pub(super) description: Option<String>,
    pub(super) profile_photo: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct InvitationResponse {
    pub(super) id: Uuid,
    pub(super) org_id: String,
    pub(super) target_carbon: CarbonPublicResponse,
    pub(super) masked_delivery_address: Option<String>,
    pub(super) org_role: String,
    pub(super) job_role: String,
    pub(super) tag_ids: Vec<Uuid>,
    pub(super) first_silicon_membership_id: Option<Uuid>,
    pub(super) extra_silicon_membership_ids: Vec<Uuid>,
    pub(super) default_trust: TrustValue,
    pub(super) tag_trust_overrides: Vec<InvitationTagTrustOverride>,
    pub(super) silicon_trust_overrides: Vec<InvitationSiliconTrustOverride>,
    pub(super) invited_by: ActorResponse,
    pub(super) status: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) expires_at: OffsetDateTime,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) accepted_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
pub(super) struct InvitationPage {
    pub(super) items: Vec<InvitationResponse>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ApprovalDecisionResponse {
    pub(super) id: Uuid,
    pub(super) approver: ActorResponse,
    pub(super) decision: String,
    pub(super) comment: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) decided_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ApprovalRequirementsResponse {
    pub(super) target_carbon: i16,
    pub(super) eligible_owner_or_admin: i16,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ApprovalRequestResponse {
    pub(super) id: Uuid,
    pub(super) org_id: String,
    pub(super) kind: String,
    pub(super) status: String,
    pub(super) requested_by: ActorResponse,
    pub(super) target_membership_id: Uuid,
    pub(super) immutable_payload: serde_json::Value,
    pub(super) required_approvals: ApprovalRequirementsResponse,
    pub(super) decisions: Vec<ApprovalDecisionResponse>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) completed_at: Option<OffsetDateTime>,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct ApprovalRequestPage {
    pub(super) items: Vec<ApprovalRequestResponse>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct RoleHistoryResponse {
    pub(super) id: Uuid,
    pub(super) membership_id: Uuid,
    pub(super) old_job_role: String,
    pub(super) new_job_role: String,
    pub(super) requested_by: ActorResponse,
    pub(super) approvers: Vec<ActorResponse>,
    pub(super) approval_request_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) applied_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct RoleHistoryPage {
    pub(super) items: Vec<RoleHistoryResponse>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct TagHistoryResponse {
    pub(super) id: Uuid,
    pub(super) membership_id: Uuid,
    pub(super) previous_tag_ids: Vec<Uuid>,
    pub(super) applied_tag_ids: Vec<Uuid>,
    pub(super) requested_by: ActorResponse,
    pub(super) approvers: Vec<ActorResponse>,
    pub(super) approval_request_id: Option<Uuid>,
    pub(super) membership_version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) applied_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub(super) struct TagHistoryPage {
    pub(super) items: Vec<TagHistoryResponse>,
    pub(super) page: PageInfo,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RemovalQuery {
    pub(super) reassign_reports_to: Option<Uuid>,
}
