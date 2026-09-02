use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EmailInput {
    pub(super) email: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PhoneInput {
    pub(super) phone_number: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerificationInput {
    pub(super) code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignupCompletionInput {
    pub(super) carbon_id: String,
    pub(super) display_name: String,
    pub(super) timezone: Option<String>,
    pub(super) description: Option<String>,
    pub(super) profile_photo: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginChallengeInput {
    pub(super) email: Option<String>,
    pub(super) phone_number: Option<String>,
    pub(super) carbon_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefreshInput {
    pub(super) refresh_token: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LogoutMode {
    #[default]
    CurrentSession,
    AllSessions,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LogoutInput {
    #[serde(default)]
    pub(super) mode: LogoutMode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageQuery {
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct AuthSessionResponse {
    pub(super) session_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) expires_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) local_otp: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct CodeDispatchResponse {
    pub(super) already_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) local_otp: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct VerifiedResponse {
    pub(super) verified: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct AvailabilityResponse {
    pub(super) available: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ActorResponse {
    pub(super) principal_id: Uuid,
    #[serde(rename = "type")]
    pub(super) actor_type: String,
    pub(super) public_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct CarbonSelfResponse {
    pub(super) principal_id: Uuid,
    pub(super) carbon_id: String,
    pub(super) display_name: String,
    pub(super) timezone: String,
    pub(super) description: Option<String>,
    pub(super) profile_photo: String,
    pub(super) email: String,
    pub(super) phone_number: String,
    pub(super) status: String,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct TokenResponse {
    pub(super) access_token: String,
    pub(super) refresh_token: String,
    pub(super) token_type: String,
    pub(super) expires_in: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) refresh_expires_at: OffsetDateTime,
    pub(super) actor: ActorResponse,
    pub(super) session_id: Uuid,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct SessionResponse {
    pub(super) session_id: Uuid,
    pub(super) actor: ActorResponse,
    pub(super) status: String,
    pub(super) user_agent_summary: Option<String>,
    pub(super) ip_prefix: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) last_used_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) absolute_expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(super) revoked_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct LoginEventResponse {
    pub(super) id: Uuid,
    pub(super) actor: ActorResponse,
    pub(super) app_id: Option<String>,
    pub(super) org_id: Option<String>,
    pub(super) event_type: String,
    pub(super) success: bool,
    pub(super) ip_prefix: Option<String>,
    pub(super) user_agent_summary: Option<String>,
    pub(super) request_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) occurred_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct PageInfo {
    pub(super) next_cursor: Option<String>,
    pub(super) has_more: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct SessionPage {
    pub(super) items: Vec<SessionResponse>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct LoginEventPage {
    pub(super) items: Vec<LoginEventResponse>,
    pub(super) page: PageInfo,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ContactChannel {
    Email,
    #[serde(rename = "phone_number")]
    Phone,
}

impl ContactChannel {
    pub(super) const fn database_value(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
        }
    }

    pub(super) const fn authentication_method(self) -> &'static str {
        match self {
            Self::Email => "email_otp",
            Self::Phone => "phone_otp",
        }
    }
}

#[derive(Debug)]
pub(super) struct ValidatedContact {
    pub(super) channel: ContactChannel,
    pub(super) normalized: String,
    pub(super) presentation: SecretString,
}

#[derive(Debug)]
pub(super) enum ValidatedLoginIdentifier {
    Contact(ValidatedContact),
    CarbonId(crate::domain::auth::CarbonId),
}

impl ValidatedLoginIdentifier {
    pub(super) const fn database_value(&self) -> &'static str {
        match self {
            Self::Contact(contact) => contact.channel.database_value(),
            Self::CarbonId(_) => "carbon_id",
        }
    }
}

#[derive(Debug)]
pub(super) struct ValidatedSignupCompletion {
    pub(super) carbon_id: crate::domain::auth::CarbonId,
    pub(super) display_name: String,
    pub(super) timezone: String,
    pub(super) description: Option<String>,
    pub(super) profile_photo: Option<url::Url>,
}

#[derive(Debug)]
pub(super) struct Delivery {
    pub(super) channel: ContactChannel,
    pub(super) recipient: SecretString,
    pub(super) code: SecretString,
    pub(super) purpose: &'static str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum VerificationOutcome {
    Verified,
    Invalid,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum LoginVerificationOutcome {
    Success(TokenResponse),
    Invalid,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum RefreshMutationOutcome {
    Success(TokenResponse),
    ReplayRevoked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum EmptyMutationOutcome {
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum StepUpAction {
    #[serde(rename = "account.session_revoke")]
    AccountSessionRevoke,
    #[serde(rename = "account.sessions_revoke_all")]
    AccountSessionsRevokeAll,
    #[serde(rename = "application.client_secret.rotate")]
    ApplicationClientSecretRotate,
    #[serde(rename = "organization.transfer_ownership")]
    OrganizationTransferOwnership,
    #[serde(rename = "organization.authorization_change")]
    OrganizationAuthorizationChange,
    #[serde(rename = "organization.sso_change")]
    OrganizationSsoChange,
    #[serde(rename = "organization.silicon_webhook.redirect")]
    OrganizationSiliconWebhookRedirect,
    #[serde(rename = "silicon.rotate_token")]
    SiliconRotateToken,
    #[serde(rename = "platform_admin.sso_entitlement")]
    PlatformAdminSsoEntitlement,
    #[serde(rename = "platform_admin.application_review")]
    PlatformAdminApplicationReview,
}

impl StepUpAction {
    pub(super) const fn database_value(self) -> &'static str {
        match self {
            Self::AccountSessionRevoke => "account.session_revoke",
            Self::AccountSessionsRevokeAll => "account.sessions_revoke_all",
            Self::ApplicationClientSecretRotate => "application.client_secret.rotate",
            Self::OrganizationTransferOwnership => "organization.transfer_ownership",
            Self::OrganizationAuthorizationChange => "organization.authorization_change",
            Self::OrganizationSsoChange => "organization.sso_change",
            Self::OrganizationSiliconWebhookRedirect => "organization.silicon_webhook.redirect",
            Self::SiliconRotateToken => "silicon.rotate_token",
            Self::PlatformAdminSsoEntitlement => "platform_admin.sso_entitlement",
            Self::PlatformAdminApplicationReview => "platform_admin.application_review",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StepUpChallengeInput {
    pub(super) channel: ContactChannel,
    pub(super) action: StepUpAction,
    pub(super) resource_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct StepUpTokenResponse {
    pub(super) step_up_token: String,
    pub(super) action: StepUpAction,
    pub(super) assurance: String,
    pub(super) expires_in: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum StepUpVerificationOutcome {
    Success(StepUpTokenResponse),
    Invalid,
    Expired,
}
