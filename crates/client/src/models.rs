//! Wire types for the Silicon IAM contract.
//!
//! Generated from `docs/openapi.yaml` by `scripts/generate-client-models.rb`.
//! Edit the contract and regenerate rather than editing this file; the shapes
//! that a generator cannot express live in `models_manual` instead.
//!
//! Every string enum carries an `Other` variant, so a value the service adds
//! after this crate was published still deserializes.

// The doc comments here are the contract's own prose, which names fields and
// routes in running text. Rewriting it to satisfy a Rust documentation lint
// would mean the generated docs no longer match the contract they came from.
#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

pub use super::models_manual::*;

/// Canonical organization-qualified Application id, `{org_id}>{handle}`.
pub type AppId = String;

/// Local handle supplied at creation; the public id becomes
/// `{org_id}>{handle}`.
pub type ApplicationHandle = String;

/// Caller-chosen Application webhook signing secret containing only
/// non-whitespace ASCII characters. IAM encrypts it at rest and never
/// generates it.
pub type ApplicationWebhookSecret = String;

/// New immutable Carbon ID; zero is not admitted.
pub type CarbonId = String;

/// Existing Carbon lookup/projection, including immutable legacy IDs
/// containing zero.
pub type ExistingCarbonId = String;

/// Lowercase hexadecimal SHA-256 digest of the exact downstream request body
/// bytes.
pub type OboBodySha256 = String;

/// Canonical uppercase HTTP method included byte-for-byte in the OBO HMAC and
/// proof binding.
pub type OboRequestMethod = String;

/// Contract alias for `OrgId`.
pub type OrgId = String;

/// Contract alias for `SiliconGlobalId`.
pub type SiliconGlobalId = String;

/// Client-supplied handle component; only the resulting `{handle}:{org_id}`
/// Silicon ID is public.
pub type SiliconHandle = String;

/// Root authority for one environment. Anyone holding it can do anything
/// inside that environment.
pub type TestingEnvironmentKeyValue = String;

/// Exact identifier that must resolve in the IANA Time Zone Database, such as
/// UTC or Asia/Kolkata.
pub type TimeZoneId = String;

/// Six-digit code with a ten-minute expiry; ten failed verifications trigger
/// a 60-second reusable-challenge cooldown.
pub type VerificationCode = String;

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRefType {
    /// `carbon`
    Carbon,
    /// `silicon`
    Silicon,
    /// `application`
    Application,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationAuthorizationActorType {
    /// `carbon`
    Carbon,
    /// `silicon`
    Silicon,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationStatus {
    /// `under_review`
    UnderReview,
    /// `verified`
    Verified,
    /// `rejected`
    Rejected,
    /// `suspended`
    Suspended,
    /// `deleted`
    Deleted,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationWebhookStatus {
    /// `pending_review`
    PendingReview,
    /// `active`
    Active,
    /// `replacement_under_review`
    ReplacementUnderReview,
    /// `disabled`
    Disabled,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionCreateDecision {
    /// `approve`
    Approve,
    /// `reject`
    Reject,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionDecision {
    /// `approve`
    Approve,
    /// `reject`
    Reject,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// `carbon_job_role_change`
    CarbonJobRoleChange,
    /// `silicon_job_role_change`
    SiliconJobRoleChange,
    /// `carbon_tag_change`
    CarbonTagChange,
    /// `silicon_tag_change`
    SiliconTagChange,
    /// `silicon_token_rotation`
    SiliconTokenRotation,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// `pending`
    Pending,
    /// `approved`
    Approved,
    /// `rejected`
    Rejected,
    /// `completed`
    Completed,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarbonSelfStatus {
    /// `active`
    Active,
    /// `suspended`
    Suspended,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryRoleOrgRole {
    /// `owner`
    Owner,
    /// `admin`
    Admin,
    /// `member`
    Member,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteStatus {
    /// `pending`
    Pending,
    /// `accepted`
    Accepted,
    /// `revoked`
    Revoked,
    /// `expired`
    Expired,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginEventEventType {
    /// `login_challenge`
    LoginChallenge,
    /// `login_success`
    LoginSuccess,
    /// `login_failure`
    LoginFailure,
    /// `oauth_authorization`
    OauthAuthorization,
    /// `oauth_token_exchange`
    OauthTokenExchange,
    /// `logout`
    Logout,
    /// `refresh_replay`
    RefreshReplay,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogoutRequestMode {
    /// `current_session`
    CurrentSession,
    /// `all_sessions`
    AllSessions,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipAuthorizationOrgRole {
    /// `owner`
    Owner,
    /// `admin`
    Admin,
    /// `member`
    Member,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipOrgRole {
    /// `owner`
    Owner,
    /// `admin`
    Admin,
    /// `member`
    Member,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipStatus {
    /// `active`
    Active,
    /// `removed`
    Removed,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthRevocationRequestTokenTypeHint {
    /// `access_token`
    AccessToken,
    /// `refresh_token`
    RefreshToken,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationCapability {
    /// `organization.update`
    #[serde(rename = "organization.update")]
    OrganizationUpdate,
    /// `members.invite`
    #[serde(rename = "members.invite")]
    MembersInvite,
    /// `members.update_directory`
    #[serde(rename = "members.update_directory")]
    MembersUpdateDirectory,
    /// `members.remove`
    #[serde(rename = "members.remove")]
    MembersRemove,
    /// `silicons.create`
    #[serde(rename = "silicons.create")]
    SiliconsCreate,
    /// `silicons.update_directory`
    #[serde(rename = "silicons.update_directory")]
    SiliconsUpdateDirectory,
    /// `silicons.manage_hierarchy`
    #[serde(rename = "silicons.manage_hierarchy")]
    SiliconsManageHierarchy,
    /// `silicons.remove`
    #[serde(rename = "silicons.remove")]
    SiliconsRemove,
    /// `silicons.rotate_token`
    #[serde(rename = "silicons.rotate_token")]
    SiliconsRotateToken,
    /// `tags.manage`
    #[serde(rename = "tags.manage")]
    TagsManage,
    /// `trust.manage`
    #[serde(rename = "trust.manage")]
    TrustManage,
    /// `roles.request`
    #[serde(rename = "roles.request")]
    RolesRequest,
    /// `roles.approve`
    #[serde(rename = "roles.approve")]
    RolesApprove,
    /// `admins.create`
    #[serde(rename = "admins.create")]
    AdminsCreate,
    /// `admins.manage`
    #[serde(rename = "admins.manage")]
    AdminsManage,
    /// `sso.manage`
    #[serde(rename = "sso.manage")]
    SsoManage,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationJoinMethod {
    /// `email`
    Email,
    /// `sso`
    Sso,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationPatchJoinMethod {
    /// `email`
    Email,
    /// `sso`
    Sso,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationSsoStatus {
    /// `disabled`
    Disabled,
    /// `pending`
    Pending,
    /// `active`
    Active,
    /// `error`
    Error,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationStatus {
    /// `active`
    Active,
    /// `disabled`
    Disabled,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// `active`
    Active,
    /// `revoked`
    Revoked,
    /// `expired`
    Expired,
    /// `replay_revoked`
    ReplayRevoked,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Exact closed 38-event vocabulary delivered by Silicon mode=all
/// subscriptions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiliconFullEventType {
    /// `organization.membership.created.v1`
    #[serde(rename = "organization.membership.created.v1")]
    OrganizationMembershipCreatedV1,
    /// `organization.membership.reactivated.v1`
    #[serde(rename = "organization.membership.reactivated.v1")]
    OrganizationMembershipReactivatedV1,
    /// `organization.membership.removed.v1`
    #[serde(rename = "organization.membership.removed.v1")]
    OrganizationMembershipRemovedV1,
    /// `organization.silicon.created.v1`
    #[serde(rename = "organization.silicon.created.v1")]
    OrganizationSiliconCreatedV1,
    /// `organization.silicon.removed.v1`
    #[serde(rename = "organization.silicon.removed.v1")]
    OrganizationSiliconRemovedV1,
    /// `organization.membership.updated.v1`
    #[serde(rename = "organization.membership.updated.v1")]
    OrganizationMembershipUpdatedV1,
    /// `organization.membership.profile_updated.v1`
    #[serde(rename = "organization.membership.profile_updated.v1")]
    OrganizationMembershipProfileUpdatedV1,
    /// `organization.membership.authorization_updated.v1`
    #[serde(rename = "organization.membership.authorization_updated.v1")]
    OrganizationMembershipAuthorizationUpdatedV1,
    /// `organization.ownership_transferred.v1`
    #[serde(rename = "organization.ownership_transferred.v1")]
    OrganizationOwnershipTransferredV1,
    /// `organization.admin.promoted.v1`
    #[serde(rename = "organization.admin.promoted.v1")]
    OrganizationAdminPromotedV1,
    /// `organization.admin.demoted.v1`
    #[serde(rename = "organization.admin.demoted.v1")]
    OrganizationAdminDemotedV1,
    /// `organization.silicon.updated.v1`
    #[serde(rename = "organization.silicon.updated.v1")]
    OrganizationSiliconUpdatedV1,
    /// `organization.tag_updated.v1`
    #[serde(rename = "organization.tag_updated.v1")]
    OrganizationTagUpdatedV1,
    /// `organization.trust.default_updated.v1`
    #[serde(rename = "organization.trust.default_updated.v1")]
    OrganizationTrustDefaultUpdatedV1,
    /// `organization.trust.rule_created.v1`
    #[serde(rename = "organization.trust.rule_created.v1")]
    OrganizationTrustRuleCreatedV1,
    /// `organization.trust.rule_updated.v1`
    #[serde(rename = "organization.trust.rule_updated.v1")]
    OrganizationTrustRuleUpdatedV1,
    /// `organization.trust.rule_archived.v1`
    #[serde(rename = "organization.trust.rule_archived.v1")]
    OrganizationTrustRuleArchivedV1,
    /// `organization.created.v1`
    #[serde(rename = "organization.created.v1")]
    OrganizationCreatedV1,
    /// `organization.updated.v1`
    #[serde(rename = "organization.updated.v1")]
    OrganizationUpdatedV1,
    /// `organization.tag_created.v1`
    #[serde(rename = "organization.tag_created.v1")]
    OrganizationTagCreatedV1,
    /// `organization.invitation.created.v1`
    #[serde(rename = "organization.invitation.created.v1")]
    OrganizationInvitationCreatedV1,
    /// `organization.invitation.accepted.v1`
    #[serde(rename = "organization.invitation.accepted.v1")]
    OrganizationInvitationAcceptedV1,
    /// `organization.invitation.revoked.v1`
    #[serde(rename = "organization.invitation.revoked.v1")]
    OrganizationInvitationRevokedV1,
    /// `organization.role_change.requested.v1`
    #[serde(rename = "organization.role_change.requested.v1")]
    OrganizationRoleChangeRequestedV1,
    /// `organization.tag_change.requested.v1`
    #[serde(rename = "organization.tag_change.requested.v1")]
    OrganizationTagChangeRequestedV1,
    /// `organization.approval.decided.v1`
    #[serde(rename = "organization.approval.decided.v1")]
    OrganizationApprovalDecidedV1,
    /// `organization.silicon.rotation_requested.v1`
    #[serde(rename = "organization.silicon.rotation_requested.v1")]
    OrganizationSiliconRotationRequestedV1,
    /// `organization.silicon.credential_rotated.v1`
    #[serde(rename = "organization.silicon.credential_rotated.v1")]
    OrganizationSiliconCredentialRotatedV1,
    /// `organization.silicon.webhook.configured.v1`
    #[serde(rename = "organization.silicon.webhook.configured.v1")]
    OrganizationSiliconWebhookConfiguredV1,
    /// `organization.silicon.webhook.deleted.v1`
    #[serde(rename = "organization.silicon.webhook.deleted.v1")]
    OrganizationSiliconWebhookDeletedV1,
    /// `organization.silicon.webhook_subscription.updated.v1`
    #[serde(rename = "organization.silicon.webhook_subscription.updated.v1")]
    OrganizationSiliconWebhookSubscriptionUpdatedV1,
    /// `organization.silicon.webhook_subscription.deleted.v1`
    #[serde(rename = "organization.silicon.webhook_subscription.deleted.v1")]
    OrganizationSiliconWebhookSubscriptionDeletedV1,
    /// `sso.setup_link.created.v1`
    #[serde(rename = "sso.setup_link.created.v1")]
    SsoSetupLinkCreatedV1,
    /// `sso.configuration.disabled.v1`
    #[serde(rename = "sso.configuration.disabled.v1")]
    SsoConfigurationDisabledV1,
    /// `sso.entitlement.replaced.v1`
    #[serde(rename = "sso.entitlement.replaced.v1")]
    SsoEntitlementReplacedV1,
    /// `sso.connection.activated.v1`
    #[serde(rename = "sso.connection.activated.v1")]
    SsoConnectionActivatedV1,
    /// `sso.connection.deactivated.v1`
    #[serde(rename = "sso.connection.deactivated.v1")]
    SsoConnectionDeactivatedV1,
    /// `sso.connection.deleted.v1`
    #[serde(rename = "sso.connection.deleted.v1")]
    SsoConnectionDeletedV1,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiliconStatus {
    /// `active`
    Active,
    /// `removed`
    Removed,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiliconWebhookSubscriptionMode {
    /// `all`
    All,
    /// `selected`
    Selected,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiliconWebhookSubscriptionReplaceMode {
    /// `all`
    All,
    /// `selected`
    Selected,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiliconWebhookSubscriptionTopic {
    /// `membership_lifecycle`
    MembershipLifecycle,
    /// `member_updates`
    MemberUpdates,
    /// `trust_updates`
    TrustUpdates,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsoConfigurationJoinMethod {
    /// `email`
    Email,
    /// `sso`
    Sso,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsoConfigurationStatus {
    /// `disabled`
    Disabled,
    /// `pending`
    Pending,
    /// `active`
    Active,
    /// `error`
    Error,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed privileged-action catalog. account.session_revoke binds resource_id
/// to the target session UUID; account.sessions_revoke_all binds it to the
/// current Carbon principal UUID. The Silicon-webhook redirect action binds
/// it to the target Silicon membership UUID. The Application client-secret
/// rotation action binds it to the internal Application UUID. Every action
/// requires one non-null resource_id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpAction {
    /// `account.session_revoke`
    #[serde(rename = "account.session_revoke")]
    AccountSessionRevoke,
    /// `account.sessions_revoke_all`
    #[serde(rename = "account.sessions_revoke_all")]
    AccountSessionsRevokeAll,
    /// `organization.transfer_ownership`
    #[serde(rename = "organization.transfer_ownership")]
    OrganizationTransferOwnership,
    /// `organization.authorization_change`
    #[serde(rename = "organization.authorization_change")]
    OrganizationAuthorizationChange,
    /// `organization.sso_change`
    #[serde(rename = "organization.sso_change")]
    OrganizationSsoChange,
    /// `organization.silicon_webhook.redirect`
    #[serde(rename = "organization.silicon_webhook.redirect")]
    OrganizationSiliconWebhookRedirect,
    /// `application.client_secret.rotate`
    #[serde(rename = "application.client_secret.rotate")]
    ApplicationClientSecretRotate,
    /// `application.webhook_secret.rotate`
    #[serde(rename = "application.webhook_secret.rotate")]
    ApplicationWebhookSecretRotate,
    /// `silicon.rotate_token`
    #[serde(rename = "silicon.rotate_token")]
    SiliconRotateToken,
    /// `platform_admin.sso_entitlement`
    #[serde(rename = "platform_admin.sso_entitlement")]
    PlatformAdminSsoEntitlement,
    /// `platform_admin.application_review`
    #[serde(rename = "platform_admin.application_review")]
    PlatformAdminApplicationReview,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpChallengeCreateChannel {
    /// `email`
    Email,
    /// `phone_number`
    PhoneNumber,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpTokenResponseAssurance {
    /// `verified_channel`
    VerifiedChannel,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestingEnvironmentStatus {
    /// `active`
    Active,
    /// `deleted`
    Deleted,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestingEnvironmentWithKeyStatus {
    /// `active`
    Active,
    /// `deleted`
    Deleted,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenIntrospectionActorType {
    /// `carbon`
    Carbon,
    /// `silicon`
    Silicon,
    /// `application`
    Application,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenIntrospectionRequestTokenTypeHint {
    /// `access_token`
    AccessToken,
    /// `refresh_token`
    RefreshToken,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustEvaluationSource {
    /// `organization_default`
    OrganizationDefault,
    /// `tag_rule`
    TagRule,
    /// `exact_rule`
    ExactRule,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustValueBoundary {
    /// `internal`
    Internal,
    /// `external`
    External,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustValueLevel {
    /// `not_trusted`
    NotTrusted,
    /// `needs_approval`
    NeedsApproval,
    /// `trusted`
    Trusted,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Closed vocabulary from the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeadLetterStatus {
    /// `pending`
    Pending,
    /// `dead_letter`
    DeadLetter,
    /// A value this crate predates. Held verbatim rather than
    /// failing the response it arrived in.
    #[serde(untagged)]
    Other(String),
}

/// Contract type `ActorRef`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActorRef {
    /// The contract's `principal_id`.
    pub principal_id: Uuid,
    /// The contract's `type`.
    #[serde(rename = "type")]
    pub type_field: ActorRefType,
    /// The contract's `public_id`.
    pub public_id: String,
}

/// Contract type `ApiVersionNegotiation`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiVersionNegotiation {
    /// The contract's `service`.
    pub service: serde_json::Value,
    /// The contract's `selected_api_version`.
    pub selected_api_version: String,
    /// Server-supported API majors in descending preference order.
    pub supported_api_versions: Vec<String>,
    /// The contract's `build`.
    pub build: String,
    /// The contract's `commit`.
    pub commit: String,
}

/// Organization-owned Application. created_by is immutable provenance and
/// does not confer management authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Application {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `app_id`.
    pub app_id: AppId,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `created_by`.
    pub created_by: ActorRef,
    /// The contract's `app_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    /// The contract's `app_logo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_logo: Option<String>,
    /// Pathless backend origin without a trailing slash.
    pub base_url: String,
    /// The contract's `requested_scopes`.
    pub requested_scopes: Vec<String>,
    /// The contract's `approved_scopes`.
    pub approved_scopes: Vec<String>,
    /// The contract's `obo_endpoints`.
    pub obo_endpoints: Vec<ApplicationOboEndpoint>,
    /// The contract's `status`.
    pub status: ApplicationStatus,
    /// The contract's `webhook`.
    pub webhook: ApplicationWebhook,
    /// The contract's `has_pending_changes`.
    pub has_pending_changes: bool,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Current active membership bound to the authenticated token or verified
/// proof, audience, organization, principal and testing plane. Use on first
/// login and cache misses; webhook snapshots are asynchronous updates, not
/// prerequisites for initial access. org_role requires roles.read and tags
/// requires memberships.read. Null means undisclosed, not member or empty
/// tags. OBO disclosure uses the intersection of the parent token scopes and
/// recipient application's currently approved scopes. The binding authorizes
/// no action outside the verified proof's endpoint/request. Do not reuse it
/// for a different principal, membership, epoch, audience, organization,
/// environment or effective scope set. Never fill undisclosed fields from a
/// broader cached token. Introspect current bearer tokens again before
/// relying on cached authority; a consumed OBO proof is single-use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationAuthorization {
    /// The contract's `principal_id`.
    pub principal_id: Uuid,
    /// The contract's `actor_type`.
    pub actor_type: ApplicationAuthorizationActorType,
    /// The contract's `public_id`.
    pub public_id: String,
    /// The contract's `organization_id`.
    pub organization_id: Uuid,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `membership_id`.
    pub membership_id: Uuid,
    /// The contract's `membership_version`.
    pub membership_version: i64,
    /// The contract's `authorization_epoch`.
    pub authorization_epoch: i64,
    /// The contract's `audience`.
    pub audience: AppId,
    /// The contract's `testing_environment_id`.
    pub testing_environment_id: Option<Uuid>,
    /// The contract's `scopes`.
    pub scopes: Vec<String>,
    /// The contract's `org_role`.
    pub org_role: Option<String>,
    /// The contract's `tags`.
    pub tags: Option<Vec<AuthorizationTag>>,
}

/// Contract type `ApplicationBaseUrl`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationBaseUrl {
    /// The contract's `app_id`.
    pub app_id: AppId,
    /// Pathless backend origin without a trailing slash.
    pub base_url: String,
}

/// Requires the authenticated Carbon to be a current active owner/admin of
/// org_id.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationCreate {
    /// The contract's `app_id`.
    pub app_id: ApplicationHandle,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `app_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    /// The contract's `app_logo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_logo: Option<String>,
    /// The contract's `webhook_url`.
    pub webhook_url: String,
    /// The contract's `webhook_secret`.
    pub webhook_secret: ApplicationWebhookSecret,
    /// Pathless Application backend origin with no trailing slash,
    /// credentials, query or fragment. HTTPS is required except for literal
    /// loopback HTTP in local development.
    pub base_url: String,
    /// The contract's `obo_endpoints`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obo_endpoints: Option<Vec<ApplicationOboEndpoint>>,
}

/// Contract type `ApplicationCreated`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationCreated {
    /// The contract's `application`.
    pub application: Application,
    /// The contract's `app_secret`.
    pub app_secret: String,
    /// The contract's `app_secret_version`.
    pub app_secret_version: i64,
    /// The contract's `webhook_signing_secret`.
    pub webhook_signing_secret: ApplicationWebhookSecret,
    /// The contract's `webhook_secret_version`.
    pub webhook_secret_version: i64,
    /// The contract's `secret_replay_expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub secret_replay_expires_at: OffsetDateTime,
}

/// Callable endpoint definition configurable only by a current owner/admin of
/// the Application's organization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationOboEndpoint {
    /// Stable identifier; an existing identifier cannot be assigned a
    /// different path.
    pub endpoint_id: String,
    /// Stable absolute audience-application endpoint path.
    pub path: String,
    /// Each top-level key is required at exchange. A descriptor may declare
    /// type as string, number, integer, boolean, object, array, or null;
    /// size, nesting, and node count are bounded.
    pub metadata: serde_json::Value,
}

/// Contract type `ApplicationPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationPage {
    /// The contract's `items`.
    pub items: Vec<Application>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `ApplicationPatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch distinguishes omitted fields from explicit null"
)]
pub struct ApplicationPatch {
    /// The contract's `app_name`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub app_name: Option<Option<String>>,
    /// The contract's `app_logo`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub app_logo: Option<Option<String>>,
    /// Pathless backend origin without a trailing slash; HTTPS except for
    /// literal loopback development.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Full replacement. An empty array retires every active endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obo_endpoints: Option<Vec<ApplicationOboEndpoint>>,
}

/// Contract type `ApplicationSecretRotated`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationSecretRotated {
    /// The contract's `app_id`.
    pub app_id: AppId,
    /// The contract's `app_secret`.
    pub app_secret: String,
    /// The contract's `app_secret_version`.
    pub app_secret_version: i64,
    /// The contract's `application_version`.
    pub application_version: i64,
    /// The contract's `secret_replay_expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub secret_replay_expires_at: OffsetDateTime,
}

/// Contract type `ApplicationTokenRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationTokenRequest {
    /// The contract's `app_id`.
    pub app_id: AppId,
    /// The contract's `slt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slt: Option<String>,
    /// The contract's `refresh_token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Contract type `ApplicationWebhook`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationWebhook {
    /// Null until the application's initial destination passes platform
    /// review.
    pub active_url: Option<String>,
    /// The contract's `pending_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_url: Option<String>,
    /// The contract's `status`.
    pub status: ApplicationWebhookStatus,
    /// The contract's `secret_version`.
    pub secret_version: i64,
    /// Echoes a caller-supplied replacement secret for v1 compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_signing_secret: Option<ApplicationWebhookSecret>,
    /// Present exactly when webhook_signing_secret is present.
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub secret_replay_expires_at: Option<OffsetDateTime>,
    /// Application aggregate version; identical to the response ETag and the
    /// value required by If-Match for replacement.
    pub version: i64,
}

/// Replaces only the reviewed destination candidate. It normally reuses the
/// existing encrypted signing secret. An imported test Application still on
/// its inherited production key must provide a new test-only secret.
/// Supplying a secret for any replacement installs it for the new endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationWebhookReplace {
    /// The contract's `url`.
    pub url: String,
    /// The contract's `webhook_secret`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<ApplicationWebhookSecret>,
}

/// Contract type `ApplicationWebhookSecretRotate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationWebhookSecretRotate {
    /// The contract's `webhook_secret`.
    pub webhook_secret: ApplicationWebhookSecret,
}

/// Contract type `ApplicationWebhookSecretRotated`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplicationWebhookSecretRotated {
    /// The contract's `app_id`.
    pub app_id: AppId,
    /// The contract's `webhook_signing_secret`.
    pub webhook_signing_secret: ApplicationWebhookSecret,
    /// The contract's `webhook_secret_version`.
    pub webhook_secret_version: i64,
    /// The contract's `application_version`.
    pub application_version: i64,
    /// The contract's `secret_replay_expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub secret_replay_expires_at: OffsetDateTime,
}

/// Contract type `ApprovalDecision`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `approver`.
    pub approver: ActorRef,
    /// The contract's `decision`.
    pub decision: ApprovalDecisionDecision,
    /// The contract's `comment`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// The contract's `decided_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub decided_at: OffsetDateTime,
}

/// Contract type `ApprovalDecisionCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalDecisionCreate {
    /// The contract's `decision`.
    pub decision: ApprovalDecisionCreateDecision,
    /// The contract's `comment`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Contract type `ApprovalRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `kind`.
    pub kind: ApprovalKind,
    /// The contract's `status`.
    pub status: ApprovalStatus,
    /// The contract's `requested_by`.
    pub requested_by: ActorRef,
    /// The contract's `target_membership_id`.
    pub target_membership_id: Uuid,
    /// The contract's `immutable_payload`.
    pub immutable_payload: serde_json::Value,
    /// The contract's `required_approvals`.
    pub required_approvals: serde_json::Value,
    /// The contract's `decisions`.
    pub decisions: Vec<ApprovalDecision>,
    /// The contract's `completed_at`.
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<OffsetDateTime>,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Contract type `ApprovalRequestPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequestPage {
    /// The contract's `items`.
    pub items: Vec<ApprovalRequest>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `AuthSession`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthSession {
    /// The contract's `session_id`.
    pub session_id: Uuid,
    /// The contract's `expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Present only when the explicitly configured local-development provider
    /// exposes the generated code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_otp: Option<String>,
}

/// Contract type `AuthorizationTag`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationTag {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `name`.
    pub name: String,
}

/// Contract type `Availability`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Availability {
    /// The contract's `available`.
    pub available: bool,
}

/// Contract type `CarbonInviteCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarbonInviteCreate {
    /// The contract's `carbon_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carbon_id: Option<ExistingCarbonId>,
    /// The contract's `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The contract's `job_role`.
    pub job_role: String,
    /// The contract's `tag_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_ids: Option<Vec<Uuid>>,
    /// The contract's `first_silicon_membership_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_silicon_membership_id: Option<Uuid>,
    /// The contract's `extra_silicon_membership_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_silicon_membership_ids: Option<Vec<Uuid>>,
    /// The contract's `default_trust`.
    pub default_trust: TrustValue,
    /// At most one override per active organization tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_trust_overrides: Option<Vec<InvitationTagTrustOverride>>,
    /// At most one override per active Silicon membership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silicon_trust_overrides: Option<Vec<InvitationSiliconTrustOverride>>,
    /// Canonical organization-qualified Application id when the invitation
    /// should continue into an Application login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_app_id: Option<String>,
}

/// Contract type `CarbonProfilePatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch distinguishes omitted fields from explicit null"
)]
pub struct CarbonProfilePatch {
    /// The contract's `display_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The contract's `timezone`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<TimeZoneId>,
    /// The contract's `description`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<Option<String>>,
    /// The contract's `profile_photo`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub profile_photo: Option<Option<String>>,
}

/// Contract type `CarbonPublic`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarbonPublic {
    /// The contract's `principal_id`.
    pub principal_id: Uuid,
    /// The contract's `carbon_id`.
    pub carbon_id: ExistingCarbonId,
    /// The contract's `display_name`.
    pub display_name: String,
    /// The contract's `description`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The contract's `profile_photo`.
    pub profile_photo: String,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Contract type `CarbonResolution`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarbonResolution {
    /// The contract's `carbon_id`.
    pub carbon_id: ExistingCarbonId,
}

/// Contract type `CarbonSelf`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarbonSelf {
    /// The contract's `principal_id`.
    pub principal_id: Uuid,
    /// The contract's `carbon_id`.
    pub carbon_id: ExistingCarbonId,
    /// The contract's `display_name`.
    pub display_name: String,
    /// The contract's `description`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The contract's `profile_photo`.
    pub profile_photo: String,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `timezone`.
    pub timezone: TimeZoneId,
    /// The contract's `email`.
    pub email: String,
    /// The contract's `phone_number`.
    pub phone_number: String,
    /// The contract's `status`.
    pub status: CarbonSelfStatus,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Contract type `CarbonSignupComplete`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarbonSignupComplete {
    /// The contract's `carbon_id`.
    pub carbon_id: CarbonId,
    /// The contract's `display_name`.
    pub display_name: String,
    /// Defaults to UTC when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<TimeZoneId>,
    /// The contract's `description`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The contract's `profile_photo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_photo: Option<String>,
}

/// Contract type `CarbonSuggestion`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CarbonSuggestion {
    /// The contract's `carbon_id`.
    pub carbon_id: ExistingCarbonId,
}

/// Contract type `CodeDispatchResult`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeDispatchResult {
    /// The contract's `already_exists`.
    pub already_exists: bool,
    /// Present only when a new verification code was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    /// Present only when the explicitly configured local-development provider
    /// exposes the generated code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_otp: Option<String>,
}

/// Contract type `DirectJobRoleReplace`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectJobRoleReplace {
    /// The contract's `job_role`.
    pub job_role: String,
}

/// Contract type `DirectTagSetReplace`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectTagSetReplace {
    /// The contract's `tag_ids`.
    pub tag_ids: Vec<Uuid>,
}

/// Sparse organization-directory projection. Omitted fields were not
/// requested. trust is null when no Carbon-to-Silicon or
/// Silicon-to-Carbon/Silicon orientation exists, including Carbon-to-Carbon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryMember {
    /// The contract's `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Public Carbon ID or global Silicon ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The contract's `role`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<DirectoryRole>,
    /// The contract's `org`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<DirectoryOrganization>,
    /// The contract's `tags`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<TagSummary>>,
    /// The contract's `trust`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<serde_json::Value>,
}

/// Contract type `DirectoryOrganization`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryOrganization {
    /// The contract's `id`.
    pub id: OrgId,
    /// The contract's `name`.
    pub name: String,
}

/// Contract type `DirectoryPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryPage {
    /// The contract's `items`.
    pub items: Vec<DirectoryMember>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `DirectoryRole`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryRole {
    /// The contract's `org_role`.
    pub org_role: DirectoryRoleOrgRole,
    /// The contract's `job_role`.
    pub job_role: String,
}

/// Contract type `EmailInput`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailInput {
    /// The contract's `email`.
    pub email: String,
}

/// Contract type `IamTokenResponse`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IamTokenResponse {
    /// Carbon access tokens use cat_; Silicon access tokens use sat_.
    pub access_token: String,
    /// The contract's `refresh_token`.
    pub refresh_token: String,
    /// The contract's `token_type`.
    pub token_type: serde_json::Value,
    /// The contract's `expires_in`.
    pub expires_in: i64,
    /// Exactly 900 days from family creation.
    #[serde(with = "time::serde::rfc3339")]
    pub refresh_expires_at: OffsetDateTime,
    /// The contract's `actor`.
    pub actor: ActorRef,
    /// The contract's `session_id`.
    pub session_id: Uuid,
}

/// Contract type `InvitationAcceptance`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvitationAcceptance {
    /// The contract's `invite_id`.
    pub invite_id: Uuid,
    /// The contract's `verification_code`.
    pub verification_code: VerificationCode,
}

/// Contract type `InvitationEmailCodeResponse`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvitationEmailCodeResponse {
    /// The contract's `accepted`.
    pub accepted: serde_json::Value,
    /// The contract's `invite_id`.
    pub invite_id: Uuid,
    /// The contract's `expires_in`.
    pub expires_in: i64,
}

/// Contract type `InvitationSiliconTrustOverride`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvitationSiliconTrustOverride {
    /// The contract's `silicon_membership_id`.
    pub silicon_membership_id: Uuid,
    /// The contract's `trust`.
    pub trust: TrustValue,
}

/// Contract type `InvitationTagTrustOverride`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvitationTagTrustOverride {
    /// The contract's `tag_id`.
    pub tag_id: Uuid,
    /// The contract's `trust`.
    pub trust: TrustValue,
}

/// Contract type `Invite`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `target_carbon`.
    pub target_carbon: CarbonPublic,
    /// The contract's `masked_delivery_address`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked_delivery_address: Option<String>,
    /// The contract's `org_role`.
    pub org_role: serde_json::Value,
    /// The contract's `job_role`.
    pub job_role: String,
    /// The contract's `tag_ids`.
    pub tag_ids: Vec<Uuid>,
    /// The contract's `first_silicon_membership_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_silicon_membership_id: Option<Uuid>,
    /// The contract's `extra_silicon_membership_ids`.
    pub extra_silicon_membership_ids: Vec<Uuid>,
    /// The contract's `default_trust`.
    pub default_trust: TrustValue,
    /// The contract's `tag_trust_overrides`.
    pub tag_trust_overrides: Vec<InvitationTagTrustOverride>,
    /// The contract's `silicon_trust_overrides`.
    pub silicon_trust_overrides: Vec<InvitationSiliconTrustOverride>,
    /// The contract's `invited_by`.
    pub invited_by: ActorRef,
    /// The contract's `status`.
    pub status: InviteStatus,
    /// The contract's `expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `accepted_at`.
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub accepted_at: Option<OffsetDateTime>,
}

/// Contract type `InvitePage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvitePage {
    /// The contract's `items`.
    pub items: Vec<Invite>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `LoginChallengeCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginChallengeCreate {
    /// The contract's `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The contract's `phone_number`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// The contract's `carbon_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carbon_id: Option<ExistingCarbonId>,
}

/// Contract type `LoginEvent`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginEvent {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `actor`.
    pub actor: ActorRef,
    /// The contract's `app_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// The contract's `org_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// The contract's `event_type`.
    pub event_type: LoginEventEventType,
    /// The contract's `success`.
    pub success: bool,
    /// The contract's `ip_prefix`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_prefix: Option<String>,
    /// The contract's `user_agent_summary`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent_summary: Option<String>,
    /// The contract's `request_id`.
    pub request_id: String,
    /// The contract's `occurred_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
}

/// Contract type `LoginEventPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginEventPage {
    /// The contract's `items`.
    pub items: Vec<LoginEvent>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `LogoutRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogoutRequest {
    /// The contract's `mode`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<LogoutRequestMode>,
}

/// Contract type `Membership`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Membership {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `principal`.
    pub principal: ActorRef,
    /// The contract's `status`.
    pub status: MembershipStatus,
    /// The contract's `org_role`.
    pub org_role: MembershipOrgRole,
    /// The contract's `job_role`.
    pub job_role: String,
    /// The contract's `tags`.
    pub tags: Vec<TagSummary>,
    /// The contract's `first_silicon_membership_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_silicon_membership_id: Option<Uuid>,
    /// The contract's `extra_silicons`.
    pub extra_silicons: Vec<Uuid>,
    /// Carbon-wide advisory trust baseline; null for Silicon memberships.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_trust: Option<serde_json::Value>,
    /// The contract's `reports_to_membership_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reports_to_membership_id: Option<Uuid>,
    /// The contract's `hierarchy_level`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hierarchy_level: Option<i64>,
    /// The contract's `authorization_epoch`.
    pub authorization_epoch: i64,
    /// The contract's `removed_at`.
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub removed_at: Option<OffsetDateTime>,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Contract type `MembershipAuthorization`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipAuthorization {
    /// The contract's `membership_id`.
    pub membership_id: Uuid,
    /// The contract's `org_role`.
    pub org_role: MembershipAuthorizationOrgRole,
    /// The contract's `capabilities`.
    pub capabilities: Vec<OrganizationCapability>,
    /// The contract's `authorization_epoch`.
    pub authorization_epoch: i64,
    /// The contract's `version`.
    pub version: i64,
}

/// Contract type `MembershipDirectoryPatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch distinguishes omitted fields from explicit null"
)]
pub struct MembershipDirectoryPatch {
    /// The contract's `first_silicon_membership_id`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub first_silicon_membership_id: Option<Option<Uuid>>,
    /// The contract's `extra_silicon_membership_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_silicon_membership_ids: Option<Vec<Uuid>>,
    /// Carbon-only advisory trust baseline; requires trust.manage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_trust: Option<TrustValue>,
    /// The contract's `reports_to_membership_id`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reports_to_membership_id: Option<Option<Uuid>>,
    /// The contract's `profile_photo`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub profile_photo: Option<Option<String>>,
}

/// Contract type `MembershipPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipPage {
    /// The contract's `items`.
    pub items: Vec<Membership>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `OAuthRevocationRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuthRevocationRequest {
    /// The contract's `token`.
    pub token: String,
    /// The contract's `token_type_hint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<OAuthRevocationRequestTokenTypeHint>,
}

/// Contract type `OAuthTokenResponse`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    /// The contract's `access_token`.
    pub access_token: String,
    /// The contract's `refresh_token`.
    pub refresh_token: String,
    /// The contract's `token_type`.
    pub token_type: serde_json::Value,
    /// The contract's `expires_in`.
    pub expires_in: i64,
    /// The contract's `scope`.
    pub scope: String,
    /// The contract's `actor`.
    pub actor: ActorRef,
    /// The contract's `org_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

/// Contract type `OboAccessResult`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OboAccessResult {
    /// The contract's `valid`.
    pub valid: serde_json::Value,
    /// The contract's `proof_id`.
    pub proof_id: Uuid,
    /// The contract's `issuer_app_id`.
    pub issuer_app_id: AppId,
    /// The contract's `audience`.
    pub audience: AppId,
    /// The contract's `actor`.
    pub actor: ActorRef,
    /// The contract's `authorization`.
    pub authorization: ApplicationAuthorization,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `endpoint`.
    pub endpoint: OboEndpointReference,
    /// The contract's `metadata`.
    pub metadata: serde_json::Value,
    /// The contract's `expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// The contract's `consumed_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub consumed_at: OffsetDateTime,
}

/// Contract type `OboApplicationReference`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OboApplicationReference {
    /// The contract's `app_id`.
    pub app_id: AppId,
    /// The contract's `org_id`.
    pub org_id: OrgId,
}

/// Contract type `OboEndpointCatalog`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OboEndpointCatalog {
    /// The contract's `application`.
    pub application: OboApplicationReference,
    /// Active definitions ordered by endpoint_id.
    pub endpoints: Vec<ApplicationOboEndpoint>,
}

/// Contract type `OboEndpointReference`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OboEndpointReference {
    /// The contract's `endpoint_id`.
    pub endpoint_id: String,
    /// The contract's `path`.
    pub path: String,
}

/// Organization is derived from App A and App B; org_id and X-Org-ID are not
/// accepted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OboExchangeRequest {
    /// Actor-bound application access token issued to the calling app.
    pub subject_token: String,
    /// The contract's `audience`.
    pub audience: AppId,
    /// The contract's `endpoint_id`.
    pub endpoint_id: String,
    /// Exact metadata bound into the proof. It must contain every registered
    /// key, no unregistered keys, and values matching every declared type.
    pub metadata: serde_json::Value,
    /// The contract's `request`.
    pub request: OboExchangeRequestBinding,
}

/// Contract type `OboExchangeRequestBinding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OboExchangeRequestBinding {
    /// The contract's `method`.
    pub method: OboRequestMethod,
    /// The contract's `body_sha256`.
    pub body_sha256: OboBodySha256,
}

/// The idempotency replay envelope for this secret response expires no later
/// than expires_at.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OboProofResponse {
    /// The contract's `access_proof`.
    pub access_proof: String,
    /// The contract's `proof_id`.
    pub proof_id: Uuid,
    /// The contract's `expires_in`.
    pub expires_in: i64,
    /// The contract's `expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// Exact actual-request binding; successful verification is strictly
/// single-use and not idempotently replayable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OboVerifyRequest {
    /// The contract's `access_proof`.
    pub access_proof: String,
    /// The contract's `request`.
    pub request: OboVerifyRequestBinding,
}

/// Contract type `OboVerifyRequestBinding`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OboVerifyRequestBinding {
    /// The contract's `method`.
    pub method: OboRequestMethod,
    /// Exact registered path of the downstream request.
    pub path: String,
    /// The contract's `body_sha256`.
    pub body_sha256: OboBodySha256,
}

/// Contract type `Organization`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Organization {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `name`.
    pub name: String,
    /// The contract's `logo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    /// The contract's `description`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The contract's `owner_membership_id`.
    pub owner_membership_id: Uuid,
    /// The contract's `join_method`.
    pub join_method: OrganizationJoinMethod,
    /// The contract's `sso_status`.
    pub sso_status: OrganizationSsoStatus,
    /// The contract's `status`.
    pub status: OrganizationStatus,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Contract type `OrganizationCapabilitiesReplace`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationCapabilitiesReplace {
    /// The contract's `capabilities`.
    pub capabilities: Vec<OrganizationCapability>,
}

/// Contract type `OrganizationCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationCreate {
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `name`.
    pub name: String,
    /// The contract's `logo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    /// The contract's `description`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Contract type `OrganizationPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationPage {
    /// The contract's `items`.
    pub items: Vec<Organization>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `OrganizationPatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch distinguishes omitted fields from explicit null"
)]
pub struct OrganizationPatch {
    /// The contract's `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The contract's `logo`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub logo: Option<Option<String>>,
    /// The contract's `description`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<Option<String>>,
    /// The contract's `join_method`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_method: Option<OrganizationPatchJoinMethod>,
}

/// Contract type `OwnershipTransfer`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnershipTransfer {
    /// The contract's `new_owner_membership_id`.
    pub new_owner_membership_id: Uuid,
}

/// Contract type `PageInfo`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PageInfo {
    /// The contract's `next_cursor`.
    pub next_cursor: Option<String>,
    /// The contract's `has_more`.
    pub has_more: bool,
}

/// Contract type `PhoneInput`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhoneInput {
    /// The contract's `phone_number`.
    pub phone_number: String,
}

/// Contract type `RefreshTokenRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    /// The contract's `refresh_token`.
    pub refresh_token: String,
}

/// Contract type `RoleChangeRequestCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleChangeRequestCreate {
    /// The contract's `target_membership_id`.
    pub target_membership_id: Uuid,
    /// The contract's `proposed_job_role`.
    pub proposed_job_role: String,
    /// The contract's `reason`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Contract type `RoleHistory`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleHistory {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `membership_id`.
    pub membership_id: Uuid,
    /// The contract's `old_job_role`.
    pub old_job_role: String,
    /// The contract's `new_job_role`.
    pub new_job_role: String,
    /// The contract's `requested_by`.
    pub requested_by: ActorRef,
    /// The contract's `approvers`.
    pub approvers: Vec<ActorRef>,
    /// Null for an owner/admin direct change.
    pub approval_request_id: Option<Uuid>,
    /// The contract's `applied_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub applied_at: OffsetDateTime,
}

/// Contract type `RoleHistoryPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleHistoryPage {
    /// The contract's `items`.
    pub items: Vec<RoleHistory>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `Session`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    /// The contract's `session_id`.
    pub session_id: Uuid,
    /// The contract's `actor`.
    pub actor: ActorRef,
    /// The contract's `status`.
    pub status: SessionStatus,
    /// The contract's `user_agent_summary`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent_summary: Option<String>,
    /// The contract's `ip_prefix`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_prefix: Option<String>,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `last_used_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub last_used_at: OffsetDateTime,
    /// The contract's `absolute_expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub absolute_expires_at: OffsetDateTime,
    /// The contract's `revoked_at`.
    #[serde(
        with = "time::serde::rfc3339::option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked_at: Option<OffsetDateTime>,
}

/// Contract type `SessionPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionPage {
    /// The contract's `items`.
    pub items: Vec<Session>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `ShortLivedToken`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShortLivedToken {
    /// The contract's `slt`.
    pub slt: String,
    /// The contract's `expires_in`.
    pub expires_in: i64,
}

/// Contract type `ShortLivedTokenRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShortLivedTokenRequest {
    /// The contract's `app_id`.
    pub app_id: AppId,
    /// Optional organization membership to bind into the resulting
    /// Application tokens. Omit for an unscoped login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<OrgId>,
}

/// Contract type `Silicon`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Silicon {
    /// The contract's `principal_id`.
    pub principal_id: Uuid,
    /// The contract's `membership_id`.
    pub membership_id: Uuid,
    /// The contract's `silicon_id`.
    pub silicon_id: SiliconGlobalId,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `display_name`.
    pub display_name: String,
    /// The contract's `timezone`.
    pub timezone: TimeZoneId,
    /// The contract's `description`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The contract's `profile_photo`.
    pub profile_photo: String,
    /// The contract's `job_role`.
    pub job_role: String,
    /// The contract's `reports_to_membership_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reports_to_membership_id: Option<Uuid>,
    /// The contract's `tags`.
    pub tags: Vec<TagSummary>,
    /// The contract's `hierarchy_level`.
    pub hierarchy_level: i64,
    /// The contract's `webhook_configured`.
    pub webhook_configured: bool,
    /// The contract's `status`.
    pub status: SiliconStatus,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Contract type `SiliconAuthenticationRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconAuthenticationRequest {
    /// The contract's `silicon_id`.
    pub silicon_id: SiliconGlobalId,
    /// The contract's `silicon_token`.
    pub silicon_token: String,
}

/// Contract type `SiliconCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconCreate {
    /// The contract's `silicon_id`.
    pub silicon_id: SiliconHandle,
    /// Defaults to the immutable local Silicon handle when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Defaults to UTC when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<TimeZoneId>,
    /// The contract's `description`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The contract's `profile_photo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_photo: Option<String>,
    /// The contract's `job_role`.
    pub job_role: String,
    /// The contract's `reports_to_membership_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reports_to_membership_id: Option<Uuid>,
    /// The contract's `tag_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_ids: Option<Vec<Uuid>>,
}

/// Contract type `SiliconCreated`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconCreated {
    /// The contract's `silicon`.
    pub silicon: Silicon,
    /// The contract's `silicon_token`.
    pub silicon_token: String,
    /// The contract's `secret_replay_expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub secret_replay_expires_at: OffsetDateTime,
}

/// Contract type `SiliconPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconPage {
    /// The contract's `items`.
    pub items: Vec<Silicon>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `SiliconPatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch distinguishes omitted fields from explicit null"
)]
pub struct SiliconPatch {
    /// The contract's `display_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The contract's `timezone`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<TimeZoneId>,
    /// The contract's `description`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<Option<String>>,
    /// The contract's `profile_photo`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub profile_photo: Option<Option<String>>,
    /// The contract's `reports_to_membership_id`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reports_to_membership_id: Option<Option<Uuid>>,
}

/// Contract type `SiliconTokenRotated`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconTokenRotated {
    /// The contract's `silicon_id`.
    pub silicon_id: SiliconGlobalId,
    /// The contract's `credential_version`.
    pub credential_version: i64,
    /// The contract's `silicon_token`.
    pub silicon_token: String,
    /// The contract's `secret_replay_expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub secret_replay_expires_at: OffsetDateTime,
}

/// Contract type `SiliconWebhook`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconWebhook {
    /// The contract's `silicon_id`.
    pub silicon_id: SiliconGlobalId,
    /// The contract's `url`.
    pub url: String,
    /// The contract's `status`.
    pub status: serde_json::Value,
    /// The contract's `secret_version`.
    pub secret_version: i64,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Contract type `SiliconWebhookConfigured`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconWebhookConfigured {
    /// The contract's `webhook`.
    pub webhook: SiliconWebhook,
    /// The contract's `webhook_signing_secret`.
    pub webhook_signing_secret: String,
    /// The contract's `secret_replay_expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub secret_replay_expires_at: OffsetDateTime,
}

/// Contract type `SiliconWebhookEvent`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconWebhookEvent {
    /// The contract's `spec_version`.
    pub spec_version: serde_json::Value,
    /// The contract's `event_id`.
    pub event_id: Uuid,
    /// The contract's `event_type`.
    pub event_type: SiliconFullEventType,
    /// The contract's `occurred_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// The contract's `organization_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<Uuid>,
    /// The contract's `aggregate`.
    pub aggregate: serde_json::Value,
    /// Event-type-specific authorized projection; never contains credentials
    /// or raw provider records. For carbon.updated.v1, changed_fields and the
    /// complete current state are captured at the aggregate version and
    /// filtered per Application by its effective after-change profile, email,
    /// and phone consent scopes. The recipient union is authorized
    /// Applications immediately before or after the change, so a before-only
    /// recipient receives no fields it can no longer read. For the closed
    /// organization-member Application vocabulary (organization/ownership,
    /// tag, trust, membership/directory/authorization, and Silicon lifecycle
    /// or completed credential rotation events), recipient union, complete
    /// current state, and exact changed_fields are frozen in the domain
    /// transaction and filtered by profile, organizations.read,
    /// memberships.read, roles.read, and Carbon-only email/phone scopes.
    /// Member events always use current.members as an array;
    /// organization.updated uses current.organization and requires
    /// organizations.read; tag and trust events use current.resource plus
    /// current.members so their independently versioned aggregate is
    /// retained. Before-only recipients keep union-scope-filtered
    /// changed_fields but receive only stable resource/version authorization
    /// tombstones. Workers never hydrate these events from later state. An
    /// affected resource is an Application-readable principal or organization
    /// projection with an effective data scope; invitations, SSO/webhook
    /// configuration, administrative/protocol controls, and an unassigned tag
    /// creation have no Application projection.
    /// organization.membership.profile_updated.v1 and rotation-request,
    /// configuration, subscription, and protocol/control events are excluded
    /// from this Application projection vocabulary.
    /// organization.membership.profile_updated.v1 is the organization-bound
    /// Silicon projection of that mutation: it contains the changed
    /// non-contact profile fields, complete current membership state, and
    /// before/after affected tags captured at the same Carbon version.
    pub data: serde_json::Value,
}

/// Contract type `SiliconWebhookReplace`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconWebhookReplace {
    /// The contract's `url`.
    pub url: String,
}

/// Contract type `SiliconWebhookSubscription`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconWebhookSubscription {
    /// The contract's `silicon_id`.
    pub silicon_id: SiliconGlobalId,
    /// The contract's `mode`.
    pub mode: SiliconWebhookSubscriptionMode,
    /// The contract's `topics`.
    pub topics: Vec<SiliconWebhookSubscriptionTopic>,
    /// Null disables tag filtering. When present, organization-wide and
    /// unattributed events are suppressed; affected tags must intersect
    /// either the Silicon's immutable event-time own-tag audience or a
    /// currently configured additional tag.
    pub tag_filter: serde_json::Value,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// all receives every explicitly Silicon-routed organization event, including
/// Full-only metadata, catalog, invitation, governance, credential, and
/// configuration events, and canonicalizes the response to all three topic
/// values. selected requires at least one exact topic: membership_lifecycle
/// is actual creation/reactivation/removal, member_updates is applied
/// existing-member role/tag/profile/hierarchy/authorization/ownership change,
/// and trust_updates is trust state only. Optional tag_filter always includes
/// the Silicon's own event-time before/after tag audience and may add active
/// organization tags; later own-tag changes never alter an older event's
/// audience.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconWebhookSubscriptionReplace {
    /// The contract's `mode`.
    pub mode: SiliconWebhookSubscriptionReplaceMode,
    /// The contract's `topics`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<SiliconWebhookSubscriptionTopic>>,
    /// The contract's `tag_filter`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_filter: Option<serde_json::Value>,
}

/// Contract type `SiliconWebhookTagFilter`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiliconWebhookTagFilter {
    /// The contract's `additional_tag_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_tag_ids: Option<Vec<Uuid>>,
}

/// Contract type `SsoConfiguration`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsoConfiguration {
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `entitled`.
    pub entitled: bool,
    /// The contract's `status`.
    pub status: SsoConfigurationStatus,
    /// The contract's `join_method`.
    pub join_method: SsoConfigurationJoinMethod,
    /// The contract's `workos_organization_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workos_organization_id: Option<String>,
    /// The contract's `connection_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Contract type `SsoSetupLink`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsoSetupLink {
    /// The contract's `url`.
    pub url: String,
    /// The contract's `expires_in`.
    pub expires_in: i64,
    /// The contract's `expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// Contract type `StepUpChallengeCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepUpChallengeCreate {
    /// The contract's `channel`.
    pub channel: StepUpChallengeCreateChannel,
    /// The contract's `action`.
    pub action: StepUpAction,
    /// The contract's `resource_id`.
    pub resource_id: Uuid,
}

/// Contract type `StepUpTokenResponse`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepUpTokenResponse {
    /// The contract's `step_up_token`.
    pub step_up_token: String,
    /// The contract's `action`.
    pub action: StepUpAction,
    /// The contract's `assurance`.
    pub assurance: StepUpTokenResponseAssurance,
    /// The contract's `expires_in`.
    pub expires_in: i64,
}

/// Contract type `Tag`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tag {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `name`.
    pub name: String,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Contract type `TagChangeRequestCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagChangeRequestCreate {
    /// The contract's `add_tag_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_tag_ids: Option<Vec<Uuid>>,
    /// The contract's `remove_tag_ids`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_tag_ids: Option<Vec<Uuid>>,
    /// The contract's `reason`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Contract type `TagCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagCreate {
    /// The contract's `name`.
    pub name: String,
}

/// Contract type `TagHistory`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagHistory {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `membership_id`.
    pub membership_id: Uuid,
    /// The contract's `previous_tag_ids`.
    pub previous_tag_ids: Vec<Uuid>,
    /// The contract's `applied_tag_ids`.
    pub applied_tag_ids: Vec<Uuid>,
    /// The contract's `requested_by`.
    pub requested_by: ActorRef,
    /// The contract's `approvers`.
    pub approvers: Vec<ActorRef>,
    /// Null for an owner/admin direct change.
    pub approval_request_id: Option<Uuid>,
    /// The contract's `membership_version`.
    pub membership_version: i64,
    /// The contract's `applied_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub applied_at: OffsetDateTime,
}

/// Contract type `TagHistoryPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagHistoryPage {
    /// The contract's `items`.
    pub items: Vec<TagHistory>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `TagPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagPage {
    /// The contract's `items`.
    pub items: Vec<Tag>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `TagPatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagPatch {
    /// The contract's `name`.
    pub name: String,
}

/// Contract type `TagSummary`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagSummary {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `name`.
    pub name: String,
}

/// Contract type `TestResult`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestResult {
    /// The contract's `ok`.
    pub ok: bool,
    /// The contract's `message`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The contract's `checked_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
}

/// Contract type `TestingApplicationImport`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingApplicationImport {
    /// Canonical production Application id to copy.
    pub app_id: AppId,
}

/// Contract type `TestingApplicationImported`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingApplicationImported {
    /// The contract's `application`.
    pub application: Application,
    /// Fresh credential valid only inside this testing environment.
    pub app_secret: String,
    /// The contract's `app_secret_version`.
    pub app_secret_version: i64,
    /// Confirms that the production signing secret was inherited but not
    /// disclosed.
    pub webhook_secret_inherited: bool,
    /// The contract's `secret_replay_expires_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub secret_replay_expires_at: OffsetDateTime,
}

/// Contract type `TestingEnvironment`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingEnvironment {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `name`.
    pub name: String,
    /// The contract's `description`.
    pub description: Option<String>,
    /// The contract's `status`.
    pub status: TestingEnvironmentStatus,
    /// Membership that created the environment; it keeps administrative
    /// authority while active.
    pub created_by_membership_id: Uuid,
    /// Increments on every key rotation.
    pub key_generation: i64,
    /// The contract's `key_rotated_at`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub key_rotated_at: Option<OffsetDateTime>,
    /// Last accepted request in the environment; idleness beyond the
    /// configured window auto-deletes it.
    #[serde(with = "time::serde::rfc3339")]
    pub last_activity_at: OffsetDateTime,
    /// The contract's `cleaned_at`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub cleaned_at: Option<OffsetDateTime>,
    /// The contract's `deleted_at`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub deleted_at: Option<OffsetDateTime>,
    /// Deadline after which the environment and its data are destroyed
    /// permanently. Restorable until then.
    #[serde(with = "time::serde::rfc3339::option")]
    pub purge_after: Option<OffsetDateTime>,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Contract type `TestingEnvironmentCleaning`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingEnvironmentCleaning {
    /// The contract's `environment_id`.
    pub environment_id: Uuid,
    /// The contract's `erased_rows`.
    pub erased_rows: i64,
    /// The contract's `cleaned_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub cleaned_at: OffsetDateTime,
}

/// Contract type `TestingEnvironmentCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingEnvironmentCreate {
    /// The contract's `name`.
    pub name: String,
    /// The contract's `description`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Contract type `TestingEnvironmentKey`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingEnvironmentKey {
    /// The contract's `environment_id`.
    pub environment_id: Uuid,
    /// The contract's `key_generation`.
    pub key_generation: i64,
    /// The contract's `key_rotated_at`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub key_rotated_at: Option<OffsetDateTime>,
    /// The contract's `key`.
    pub key: TestingEnvironmentKeyValue,
}

/// Contract type `TestingEnvironmentPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingEnvironmentPage {
    /// The contract's `items`.
    pub items: Vec<TestingEnvironment>,
    /// The contract's `page`.
    pub page: serde_json::Value,
}

/// Contract type `TestingEnvironmentPatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch distinguishes omitted fields from explicit null"
)]
pub struct TestingEnvironmentPatch {
    /// The contract's `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The contract's `description`.
    /// `None` omits this field; `Some(None)` sends JSON null to clear it.
    #[serde(
        with = "serde_with::rust::double_option",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<Option<String>>,
}

/// What a key holder may see about the environment it holds a key to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingEnvironmentSelf {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `name`.
    pub name: String,
    /// The contract's `description`.
    pub description: Option<String>,
    /// The contract's `key_generation`.
    pub key_generation: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Contract type `TestingEnvironmentWithKey`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingEnvironmentWithKey {
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `name`.
    pub name: String,
    /// The contract's `description`.
    pub description: Option<String>,
    /// The contract's `status`.
    pub status: TestingEnvironmentWithKeyStatus,
    /// Membership that created the environment; it keeps administrative
    /// authority while active.
    pub created_by_membership_id: Uuid,
    /// Increments on every key rotation.
    pub key_generation: i64,
    /// The contract's `key_rotated_at`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub key_rotated_at: Option<OffsetDateTime>,
    /// Last accepted request in the environment; idleness beyond the
    /// configured window auto-deletes it.
    #[serde(with = "time::serde::rfc3339")]
    pub last_activity_at: OffsetDateTime,
    /// The contract's `cleaned_at`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub cleaned_at: Option<OffsetDateTime>,
    /// The contract's `deleted_at`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub deleted_at: Option<OffsetDateTime>,
    /// Deadline after which the environment and its data are destroyed
    /// permanently. Restorable until then.
    #[serde(with = "time::serde::rfc3339::option")]
    pub purge_after: Option<OffsetDateTime>,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// The contract's `key`.
    pub key: TestingEnvironmentKeyValue,
}

/// Explicit test-plane envelope. The signature covers these exact outer
/// bytes. testing_key is the environment root credential and must never be
/// logged or persisted with the event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestingWebhookEvent {
    /// The contract's `test`.
    pub test: serde_json::Value,
}

/// Live token state. An active organization-bound access token also returns
/// authorization, a synchronous bootstrap/resynchronization snapshot. No
/// directory mutation or webhook delivery is required. Refresh tokens and
/// unscoped access tokens do not carry organization authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenIntrospection {
    /// The contract's `active`.
    pub active: bool,
    /// The contract's `principal_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<Uuid>,
    /// The contract's `actor_type`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_type: Option<TokenIntrospectionActorType>,
    /// The contract's `client_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<AppId>,
    /// The contract's `org_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<OrgId>,
    /// The contract's `membership_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_id: Option<Uuid>,
    /// The contract's `session_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    /// The contract's `scope`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The contract's `audience`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The contract's `issued_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<i64>,
    /// The contract's `expires_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// The contract's `authorization_epoch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_epoch: Option<i64>,
    /// The contract's `authorization`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<ApplicationAuthorization>,
}

/// Contract type `TokenIntrospectionRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenIntrospectionRequest {
    /// The contract's `token`.
    pub token: String,
    /// The contract's `token_type_hint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<TokenIntrospectionRequestTokenTypeHint>,
}

/// Contract type `TrustEvaluation`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustEvaluation {
    /// The contract's `trust`.
    pub trust: TrustValue,
    /// The contract's `source`.
    pub source: TrustEvaluationSource,
    /// The contract's `matching_rule_ids`.
    pub matching_rule_ids: Vec<Uuid>,
    /// The contract's `advisory`.
    pub advisory: serde_json::Value,
}

/// Contract type `TrustEvaluationRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustEvaluationRequest {
    /// The contract's `subject_membership_id`.
    pub subject_membership_id: Uuid,
    /// The contract's `target_silicon_membership_id`.
    pub target_silicon_membership_id: Uuid,
}

/// Contract type `TrustRule`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRule {
    /// The contract's `subject`.
    pub subject: TrustSelector,
    /// The contract's `target`.
    pub target: TrustSelector,
    /// The contract's `trust`.
    pub trust: TrustValue,
    /// The contract's `id`.
    pub id: Uuid,
    /// The contract's `org_id`.
    pub org_id: OrgId,
    /// The contract's `specificity`.
    pub specificity: i64,
    /// The contract's `version`.
    pub version: i64,
    /// The contract's `created_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// The contract's `updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Contract type `TrustRuleCreate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRuleCreate {
    /// The contract's `subject`.
    pub subject: TrustSelector,
    /// The contract's `target`.
    pub target: TrustSelector,
    /// The contract's `trust`.
    pub trust: TrustValue,
}

/// Contract type `TrustRulePage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRulePage {
    /// The contract's `items`.
    pub items: Vec<TrustRule>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `TrustRulePatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRulePatch {
    /// The contract's `subject`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<TrustSelector>,
    /// The contract's `target`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TrustSelector>,
    /// The contract's `trust`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustValue>,
}

/// Contract type `TrustValue`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustValue {
    /// The contract's `boundary`.
    pub boundary: TrustValueBoundary,
    /// The contract's `level`.
    pub level: TrustValueLevel,
}

/// Contract type `VersionInfo`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionInfo {
    /// The contract's `service`.
    pub service: serde_json::Value,
    /// The contract's `api_version`.
    pub api_version: serde_json::Value,
    /// The contract's `build`.
    pub build: String,
    /// The contract's `commit`.
    pub commit: String,
}

/// Contract type `WebhookDeadLetter`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookDeadLetter {
    /// The contract's `delivery_id`.
    pub delivery_id: Uuid,
    /// The contract's `event_id`.
    pub event_id: Uuid,
    /// The contract's `event_type`.
    pub event_type: String,
    /// The contract's `occurred_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// The contract's `aggregate_type`.
    pub aggregate_type: String,
    /// The contract's `aggregate_id`.
    pub aggregate_id: Uuid,
    /// The contract's `aggregate_version`.
    pub aggregate_version: i64,
    /// The contract's `status`.
    pub status: WebhookDeadLetterStatus,
    /// The contract's `attempt_count`.
    pub attempt_count: i64,
    /// The contract's `cycle_attempt_count`.
    pub cycle_attempt_count: i64,
    /// The contract's `manual_replay_count`.
    pub manual_replay_count: i64,
    /// The contract's `last_http_status`.
    pub last_http_status: Option<i64>,
    /// The contract's `last_error_code`.
    pub last_error_code: Option<String>,
    /// The contract's `dead_lettered_at`.
    #[serde(with = "time::serde::rfc3339::option")]
    pub dead_lettered_at: Option<OffsetDateTime>,
    /// The contract's `version`.
    pub version: i64,
}

/// Contract type `WebhookDeadLetterPage`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookDeadLetterPage {
    /// The contract's `items`.
    pub items: Vec<WebhookDeadLetter>,
    /// The contract's `page`.
    pub page: PageInfo,
}

/// Contract type `WebhookEvent`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// The contract's `spec_version`.
    pub spec_version: serde_json::Value,
    /// The contract's `event_id`.
    pub event_id: Uuid,
    /// Stable dotted event name with its positive schema version suffix.
    pub event_type: String,
    /// The contract's `occurred_at`.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// The contract's `organization_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<Uuid>,
    /// The contract's `aggregate`.
    pub aggregate: serde_json::Value,
    /// Event-type-specific authorized projection; never contains credentials
    /// or raw provider records. For carbon.updated.v1, changed_fields and the
    /// complete current state are captured at the aggregate version and
    /// filtered per Application by its effective after-change profile, email,
    /// and phone consent scopes. The recipient union is authorized
    /// Applications immediately before or after the change, so a before-only
    /// recipient receives no fields it can no longer read. For the closed
    /// organization-member Application vocabulary (organization/ownership,
    /// tag, trust, membership/directory/authorization, and Silicon lifecycle
    /// or completed credential rotation events), recipient union, complete
    /// current state, and exact changed_fields are frozen in the domain
    /// transaction and filtered by profile, organizations.read,
    /// memberships.read, roles.read, and Carbon-only email/phone scopes.
    /// Member events always use current.members as an array;
    /// organization.updated uses current.organization and requires
    /// organizations.read; tag and trust events use current.resource plus
    /// current.members so their independently versioned aggregate is
    /// retained. Before-only recipients keep union-scope-filtered
    /// changed_fields but receive only stable resource/version authorization
    /// tombstones. Workers never hydrate these events from later state. An
    /// affected resource is an Application-readable principal or organization
    /// projection with an effective data scope; invitations, SSO/webhook
    /// configuration, administrative/protocol controls, and an unassigned tag
    /// creation have no Application projection.
    /// organization.membership.profile_updated.v1 and rotation-request,
    /// configuration, subscription, and protocol/control events are excluded
    /// from this Application projection vocabulary.
    /// organization.membership.profile_updated.v1 is the organization-bound
    /// Silicon projection of that mutation: it contains the changed
    /// non-contact profile fields, complete current membership state, and
    /// before/after affected tags captured at the same Carbon version.
    pub data: serde_json::Value,
}

/// Contract type `WebhookReplayRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookReplayRequest {
    /// The contract's `delivery_ids`.
    pub delivery_ids: Vec<Uuid>,
}

/// Contract type `WebhookReplayResponse`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookReplayResponse {
    /// The contract's `deliveries`.
    pub deliveries: Vec<WebhookDeadLetter>,
    /// The contract's `replayed_count`.
    pub replayed_count: i64,
}
