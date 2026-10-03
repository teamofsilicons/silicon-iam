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
    html_body: &'a str,
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
        html_body: &str,
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
                html_body,
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
        let subject = Zeroizing::new(format!(
            "Your verification code for IAM is: {}",
            command.code.expose_secret()
        ));
        let text_body = Zeroizing::new(format!(
            "Your Silicon IAM {} code is {}. It expires in {} minutes. If you did not request this, you can ignore this message.",
            command.purpose,
            command.code.expose_secret(),
            command.expires_in_minutes,
        ));
        let code = escape_html(command.code.expose_secret());
        let purpose = match command.purpose {
            "signup" => "Verify your email",
            "login" => "Sign in to IAM",
            _ => "Verify it’s you",
        };
        let html_body = Zeroizing::new(email_layout(
            purpose,
            &format!(
                "<p style=\"margin:0 0 24px\">Enter this code in the IAM window where you requested it.</p><div style=\"padding:24px 16px;text-align:center;background:#eff6ff;border:1px solid #dbeafe;border-radius:12px;font-family:monospace;font-size:34px;line-height:1.4;letter-spacing:8px;color:#1d4ed8\">{code}</div><p style=\"margin:24px 0 0\">This code expires in {} minutes. Keep it to yourself.</p>",
                command.expires_in_minutes
            ),
            "If you didn’t request this code, you can ignore this email.",
        ));
        self.send(command.recipient, &subject, &text_body, &html_body)
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
        let name = escape_html(command.organization_name);
        let href = escape_html(command.join_url.as_str());
        let html_body = Zeroizing::new(email_layout(
            "You’re invited",
            &format!(
                "<p style=\"margin:0 0 28px\">Join <strong>{name}</strong> on Silicon. Review the invitation to see the details before joining.</p><p style=\"margin:0 0 28px\"><a href=\"{href}\" style=\"display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:8px;padding:14px 22px;font-weight:600\">Review invitation</a></p><p style=\"font-size:13px;line-height:1.6;overflow-wrap:anywhere\">If the button doesn’t open, copy this link into your browser:<br><a href=\"{href}\" style=\"color:#2563eb\">{href}</a></p>"
            ),
            "This invitation is for you. If you weren’t expecting it, you can ignore this email.",
        ));
        self.send(command.recipient, subject, &text_body, &html_body)
            .await
    }

    async fn send_security_notice(
        &self,
        command: SecurityNotice<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        let body = escape_html(command.body).replace('\n', "<br>");
        let html_body = email_layout(command.subject, &body, "Silicon IAM · Account security");
        self.send(command.recipient, command.subject, command.body, &html_body)
            .await
    }
}

/// Text is escaped before entering the shared, email-client-compatible layout.
fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn email_layout(title: &str, content_html: &str, footer: &str) -> String {
    let title = escape_html(title);
    let footer = escape_html(footer);
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light\"><title>{title}</title></head><body style=\"margin:0;background:#f6f8fb;color:#334155;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif\"><table role=\"presentation\" style=\"width:100%;border-collapse:collapse\"><tr><td align=\"center\" style=\"padding:40px 16px\"><table role=\"presentation\" style=\"width:100%;max-width:520px;border-collapse:separate;border-spacing:0;background:#ffffff;border:1px solid #e2e8f0;border-radius:16px\"><tr><td style=\"padding:36px 32px 16px;font-size:13px;font-weight:700;letter-spacing:2px;color:#2563eb\">SILICON <span style=\"color:#94a3b8;font-weight:400\">/</span> IAM</td></tr><tr><td style=\"padding:0 32px 32px;font-size:15px;line-height:1.7\"><h1 style=\"font-size:26px;line-height:1.3;letter-spacing:-0.6px;font-weight:600;color:#0f172a;margin:12px 0 24px\">{title}</h1>{content_html}</td></tr></table><p style=\"max-width:440px;margin:24px auto 0;padding:0 16px;color:#64748b;font-size:12px;line-height:1.7\">{footer}</p></td></tr></table></body></html>"
    )
}

#[cfg(test)]
mod tests {
    use super::{EmailResponse, email_layout, escape_html};

    #[test]
    fn email_content_cannot_inject_markup_or_change_invitation_links() {
        assert_eq!(escape_html("<A & B>\"'"), "&lt;A &amp; B&gt;&quot;&#39;");
        let link = "https://iam.example/join/acme?invitation=abc&next=%2Fhome";
        assert_eq!(
            escape_html(link),
            "https://iam.example/join/acme?invitation=abc&amp;next=%2Fhome"
        );
        let html = email_layout("<untrusted>", "<p>Safe body</p>", "<footer>");
        assert!(!html.contains("<untrusted>"));
        assert!(!html.contains("<footer>"));
        assert!(html.contains("<p>Safe body</p>"));
    }

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
