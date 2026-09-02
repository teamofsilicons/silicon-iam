//! Postmark transactional email adapter.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, redirect::Policy};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::application::ports::{
    DeliveryError, DeliveryReceipt, EmailDelivery, EmailOtp, InvitationEmail, SecurityNotice,
};

use super::{ProviderBuildError, http};

pub(super) struct PostmarkEmail {
    client: Client,
    server_token: SecretString,
    from: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct EmailRequest<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    text_body: &'a str,
    message_stream: &'static str,
    track_opens: bool,
    track_links: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EmailResponse {
    error_code: i64,
    #[serde(rename = "MessageID")]
    message_id: Option<String>,
}

impl PostmarkEmail {
    pub(super) fn new(
        server_token: SecretString,
        from: String,
    ) -> Result<Self, ProviderBuildError> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .user_agent(concat!("silicon-iam/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ProviderBuildError::InvalidConfiguration)?;
        Ok(Self {
            client,
            server_token,
            from,
        })
    }

    async fn send(
        &self,
        recipient: &SecretString,
        subject: &str,
        text_body: &str,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        let response = self
            .client
            .post("https://api.postmarkapp.com/email")
            .header("X-Postmark-Server-Token", self.server_token.expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&EmailRequest {
                from: &self.from,
                to: recipient.expose_secret(),
                subject,
                text_body,
                message_stream: "outbound",
                track_opens: false,
                track_links: "None",
            })
            .send()
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        if !response.status().is_success() {
            return Err(http::classify_status(response.status()));
        }
        let body: EmailResponse = http::decode_json(response).await?;
        if body.error_code != 0 {
            return Err(DeliveryError::Rejected);
        }
        let provider_message_id = body.message_id.ok_or(DeliveryError::Unavailable)?;
        Ok(DeliveryReceipt {
            provider_message_id,
        })
    }
}

#[async_trait]
impl EmailDelivery for PostmarkEmail {
    async fn send_otp(&self, command: EmailOtp<'_>) -> Result<DeliveryReceipt, DeliveryError> {
        let subject = "Your Silicon IAM verification code";
        let text_body = Zeroizing::new(format!(
            "Your Silicon IAM {} code is {}. It expires in {} minutes. If you did not request this, you can ignore this message.",
            command.purpose,
            command.code.expose_secret(),
            command.expires_in_minutes,
        ));
        self.send(command.recipient, subject, text_body.as_str())
            .await
    }

    async fn send_invitation(
        &self,
        command: InvitationEmail<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        let subject = "You have been invited to a Silicon organization";
        let text_body = Zeroizing::new(format!(
            "You have been invited to join {}. Open this link to review the invitation: {}",
            command.organization_name, command.join_url,
        ));
        self.send(command.recipient, subject, text_body.as_str())
            .await
    }

    async fn send_security_notice(
        &self,
        command: SecurityNotice<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        self.send(command.recipient, command.subject, command.body)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::EmailResponse;

    #[test]
    fn success_response_preserves_postmark_message_id_acronym() {
        let body = r#"{"ErrorCode":0,"Message":"OK","MessageID":"b7bc2f4a-95f9-4d67-bdf9-4ecb4f367add","SubmittedAt":"2026-09-02T07:46:36Z","To":"test@example.com"}"#;
        let Ok(response) = serde_json::from_str::<EmailResponse>(body) else {
            panic!("valid Postmark success response should deserialize");
        };

        assert_eq!(response.error_code, 0);
        assert_eq!(
            response.message_id.as_deref(),
            Some("b7bc2f4a-95f9-4d67-bdf9-4ecb4f367add")
        );
    }
}
