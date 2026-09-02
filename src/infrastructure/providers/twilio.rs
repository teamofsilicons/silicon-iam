//! Twilio Messaging and Verify API adapters.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, redirect::Policy};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::application::ports::{
    DeliveryError, DeliveryReceipt, InvitationSms, PhoneOtp, PhoneOtpDelivery, SecurityNotice,
    SmsDelivery, SmsOtp,
};

use super::{ProviderBuildError, http};

pub(super) struct TwilioSms {
    client: Client,
    endpoint: String,
    account_sid: SecretString,
    auth_token: SecretString,
    messaging_service_sid: SecretString,
}

pub(super) struct TwilioVerify {
    client: Client,
    verification_endpoint: String,
    check_endpoint: String,
    account_sid: SecretString,
    auth_token: SecretString,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MessageRequest<'a> {
    to: &'a str,
    messaging_service_sid: &'a str,
    body: &'a str,
}

#[derive(Deserialize)]
struct MessageResponse {
    sid: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct VerificationRequest<'a> {
    to: &'a str,
    channel: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct VerificationCheckRequest<'a> {
    verification_sid: &'a str,
    code: &'a str,
}

#[derive(Deserialize)]
struct VerificationResponse {
    sid: String,
}

#[derive(Deserialize)]
struct VerificationCheckResponse {
    status: String,
}

impl TwilioSms {
    pub(super) fn new(
        account_sid: SecretString,
        auth_token: SecretString,
        messaging_service_sid: SecretString,
    ) -> Result<Self, ProviderBuildError> {
        if !valid_sid(account_sid.expose_secret(), "AC")
            || !valid_sid(messaging_service_sid.expose_secret(), "MG")
        {
            return Err(ProviderBuildError::InvalidConfiguration);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .user_agent(concat!("silicon-iam/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ProviderBuildError::InvalidConfiguration)?;
        let endpoint = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            account_sid.expose_secret()
        );
        Ok(Self {
            client,
            endpoint,
            account_sid,
            auth_token,
            messaging_service_sid,
        })
    }
}

impl TwilioVerify {
    pub(super) fn new(
        account_sid: SecretString,
        auth_token: SecretString,
        verify_service_sid: &SecretString,
    ) -> Result<Self, ProviderBuildError> {
        if !valid_sid(account_sid.expose_secret(), "AC")
            || !valid_sid(verify_service_sid.expose_secret(), "VA")
        {
            return Err(ProviderBuildError::InvalidConfiguration);
        }
        let client = provider_client()?;
        let base = format!(
            "https://verify.twilio.com/v2/Services/{}",
            verify_service_sid.expose_secret()
        );
        Ok(Self {
            client,
            verification_endpoint: format!("{base}/Verifications"),
            check_endpoint: format!("{base}/VerificationCheck"),
            account_sid,
            auth_token,
        })
    }
}

#[async_trait]
impl SmsDelivery for TwilioSms {
    async fn send_otp(&self, command: SmsOtp<'_>) -> Result<DeliveryReceipt, DeliveryError> {
        let message = Zeroizing::new(format!(
            "Your Silicon IAM verification code is {}. It expires in {} minutes.",
            command.code.expose_secret(),
            command.expires_in_minutes,
        ));
        self.send_message(command.recipient, message.as_str()).await
    }

    async fn send_security_notice(
        &self,
        command: SecurityNotice<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        self.send_message(command.recipient, command.body).await
    }

    async fn send_invitation(
        &self,
        command: InvitationSms<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        let message = Zeroizing::new(format!(
            "You have been invited to join {} in Silicon IAM. Review it at {}",
            command.organization_name, command.join_url,
        ));
        self.send_message(command.recipient, message.as_str()).await
    }
}

#[async_trait]
impl PhoneOtpDelivery for TwilioVerify {
    async fn start(&self, command: PhoneOtp<'_>) -> Result<DeliveryReceipt, DeliveryError> {
        let response = self
            .client
            .post(&self.verification_endpoint)
            .basic_auth(
                self.account_sid.expose_secret(),
                Some(self.auth_token.expose_secret()),
            )
            .form(&VerificationRequest {
                to: command.recipient.expose_secret(),
                channel: "sms",
            })
            .send()
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        if !response.status().is_success() {
            return Err(http::classify_status(response.status()));
        }
        let body: VerificationResponse = http::decode_json(response).await?;
        if !valid_sid(&body.sid, "VE") {
            return Err(DeliveryError::Unavailable);
        }
        Ok(DeliveryReceipt {
            provider_message_id: body.sid,
        })
    }

    async fn check(
        &self,
        provider_verification_id: &str,
        code: &SecretString,
    ) -> Result<bool, DeliveryError> {
        if !valid_sid(provider_verification_id, "VE") {
            return Err(DeliveryError::Rejected);
        }
        let response = self
            .client
            .post(&self.check_endpoint)
            .basic_auth(
                self.account_sid.expose_secret(),
                Some(self.auth_token.expose_secret()),
            )
            .form(&VerificationCheckRequest {
                verification_sid: provider_verification_id,
                code: code.expose_secret(),
            })
            .send()
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        if !response.status().is_success() {
            return if http::status_is_retryable(response.status()) {
                Err(DeliveryError::Unavailable)
            } else {
                Ok(false)
            };
        }
        let body: VerificationCheckResponse = http::decode_json(response).await?;
        Ok(body.status == "approved")
    }
}

impl TwilioSms {
    async fn send_message(
        &self,
        recipient: &SecretString,
        message: &str,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        let response = self
            .client
            .post(&self.endpoint)
            .basic_auth(
                self.account_sid.expose_secret(),
                Some(self.auth_token.expose_secret()),
            )
            .form(&MessageRequest {
                to: recipient.expose_secret(),
                messaging_service_sid: self.messaging_service_sid.expose_secret(),
                body: message,
            })
            .send()
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        if !response.status().is_success() {
            return Err(http::classify_status(response.status()));
        }
        let body: MessageResponse = http::decode_json(response).await?;
        if body.sid.is_empty() {
            return Err(DeliveryError::Unavailable);
        }
        Ok(DeliveryReceipt {
            provider_message_id: body.sid,
        })
    }
}

fn valid_sid(value: &str, prefix: &str) -> bool {
    value.len() == 34
        && value.starts_with(prefix)
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn provider_client() -> Result<Client, ProviderBuildError> {
    Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .redirect(Policy::none())
        .user_agent(concat!("silicon-iam/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| ProviderBuildError::InvalidConfiguration)
}

#[cfg(test)]
mod tests {
    use super::valid_sid;

    #[test]
    fn provider_sids_have_exact_type_and_shape() {
        assert!(valid_sid(&format!("AC{}", "a".repeat(32)), "AC"));
        assert!(!valid_sid(&format!("MG{}", "a".repeat(32)), "AC"));
        assert!(valid_sid(&format!("VA{}", "a".repeat(32)), "VA"));
        assert!(valid_sid(&format!("VE{}", "a".repeat(32)), "VE"));
        assert!(!valid_sid("ACshort", "AC"));
    }
}
