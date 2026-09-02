//! Interfaces implemented by infrastructure adapters.

use async_trait::async_trait;
use secrecy::SecretString;
use thiserror::Error;
use url::Url;

/// Readiness contract for an external dependency.
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Confirms the dependency can serve requests.
    async fn check(&self) -> Result<(), anyhow::Error>;
}

/// Provider-safe receipt retained for delivery diagnostics.
#[derive(Clone, Debug)]
pub struct DeliveryReceipt {
    /// Provider-assigned message identifier; it is not recipient PII.
    pub provider_message_id: String,
}

/// Classified notification-provider failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DeliveryError {
    /// Transient failure eligible for bounded retry.
    #[error("notification provider is temporarily unavailable")]
    Unavailable,
    /// The provider permanently rejected the redacted request shape.
    #[error("notification provider rejected the request")]
    Rejected,
}

/// Email one-time-code delivery command.
pub struct EmailOtp<'a> {
    /// Recipient email address.
    pub recipient: &'a SecretString,
    /// Six-digit one-time code.
    pub code: &'a SecretString,
    /// Human-readable purpose such as signup or login.
    pub purpose: &'static str,
    /// Validity period in minutes.
    pub expires_in_minutes: u16,
}

/// SMS one-time-code delivery command.
pub struct SmsOtp<'a> {
    /// Recipient E.164 phone number.
    pub recipient: &'a SecretString,
    /// Six-digit one-time code.
    pub code: &'a SecretString,
    /// Validity period in minutes.
    pub expires_in_minutes: u16,
}

/// Managed phone one-time-code delivery command.
pub struct PhoneOtp<'a> {
    /// Recipient E.164 phone number.
    pub recipient: &'a SecretString,
}

/// Organization invitation email command.
pub struct InvitationEmail<'a> {
    /// Recipient email address.
    pub recipient: &'a SecretString,
    /// Non-sensitive organization display name.
    pub organization_name: &'a str,
    /// Short-lived join URL carrying no raw OTP.
    pub join_url: &'a Url,
}

/// Organization invitation SMS command.
pub struct InvitationSms<'a> {
    /// Recipient E.164 phone number.
    pub recipient: &'a SecretString,
    /// Non-sensitive organization display name.
    pub organization_name: &'a str,
    /// Short-lived join URL carrying no raw OTP.
    pub join_url: &'a Url,
}

/// Secret-free security notification reconstructed by the worker.
pub struct SecurityNotice<'a> {
    /// Verified destination contact.
    pub recipient: &'a SecretString,
    /// Short allowlisted subject used by email transports.
    pub subject: &'static str,
    /// Short allowlisted plain-text message.
    pub body: &'static str,
}

/// Transactional email provider boundary.
#[async_trait]
pub trait EmailDelivery: Send + Sync {
    /// Sends a signup or login OTP.
    async fn send_otp(&self, command: EmailOtp<'_>) -> Result<DeliveryReceipt, DeliveryError>;

    /// Sends an organization invitation.
    async fn send_invitation(
        &self,
        command: InvitationEmail<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError>;

    /// Sends a reconstructed, secret-free security notice.
    async fn send_security_notice(
        &self,
        command: SecurityNotice<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError>;
}

/// SMS provider boundary.
#[async_trait]
pub trait SmsDelivery: Send + Sync {
    /// Sends a signup, login, or invitation OTP.
    async fn send_otp(&self, command: SmsOtp<'_>) -> Result<DeliveryReceipt, DeliveryError>;

    /// Sends an organization invitation without embedding a credential.
    async fn send_invitation(
        &self,
        command: InvitationSms<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError>;

    /// Sends a reconstructed, secret-free security notice.
    async fn send_security_notice(
        &self,
        command: SecurityNotice<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError>;
}

/// Managed phone verification provider boundary.
#[async_trait]
pub trait PhoneOtpDelivery: Send + Sync {
    /// Starts a provider-generated SMS verification.
    async fn start(&self, command: PhoneOtp<'_>) -> Result<DeliveryReceipt, DeliveryError>;

    /// Checks a submitted code against one provider verification attempt.
    async fn check(
        &self,
        provider_verification_id: &str,
        code: &SecretString,
    ) -> Result<bool, DeliveryError>;
}
