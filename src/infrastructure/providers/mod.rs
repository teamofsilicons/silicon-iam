//! External notification-provider adapters.

pub(crate) mod hook;
mod http;
mod local;
mod postmark;
mod twilio;
pub(crate) mod webhook;
pub(crate) mod workos;

use std::sync::Arc;

use thiserror::Error;

use crate::{
    application::ports::{EmailDelivery, SmsDelivery},
    config::{ProviderSettings, WorkerProviderSettings},
};

use self::{local::LocalDelivery, postmark::PostmarkEmail, twilio::TwilioSms};

/// Notification providers selected from validated runtime settings.
#[derive(Clone)]
pub struct NotificationProviders {
    /// Transactional email delivery.
    pub email: Arc<dyn EmailDelivery>,
    /// Transactional SMS delivery.
    pub sms: Arc<dyn SmsDelivery>,
}

/// Notification-adapter construction failure.
#[derive(Debug, Error)]
pub enum ProviderBuildError {
    /// Required provider credentials are absent.
    #[error("notification providers are not configured")]
    MissingConfiguration,
    /// Provider client construction failed without exposing credentials.
    #[error("notification provider client configuration is invalid")]
    InvalidConfiguration,
}

impl NotificationProviders {
    /// Constructs real provider clients or deterministic local adapters.
    ///
    /// # Errors
    ///
    /// Returns an error when credentials are absent while local adapters are
    /// disabled, or a hardened HTTP client cannot be constructed.
    pub fn from_settings(settings: &ProviderSettings) -> Result<Self, ProviderBuildError> {
        Self::from_worker_settings(&WorkerProviderSettings {
            postmark_server_token: settings.postmark_server_token.clone(),
            postmark_from_email: settings.postmark_from_email.clone(),
            twilio_account_sid: settings.twilio_account_sid.clone(),
            twilio_auth_token: settings.twilio_auth_token.clone(),
            twilio_messaging_service_sid: settings.twilio_messaging_service_sid.clone(),
            hook_base_url: settings.hook_base_url.clone(),
            hook_service_token: settings.hook_service_token.clone(),
            iris_base_url: settings.iris_base_url.clone(),
            allow_local_providers: settings.allow_local_providers,
        })
    }

    /// Constructs notification adapters from the restricted worker provider
    /// settings, which contain no authentication-authority credentials.
    ///
    /// # Errors
    ///
    /// Returns an error when credentials are absent while local adapters are
    /// disabled, or a hardened HTTP client cannot be constructed.
    pub fn from_worker_settings(
        settings: &WorkerProviderSettings,
    ) -> Result<Self, ProviderBuildError> {
        let local = Arc::new(LocalDelivery);
        let email: Arc<dyn EmailDelivery> = if let Some(token) = &settings.postmark_server_token {
            Arc::new(PostmarkEmail::new(
                token.clone(),
                settings.postmark_from_email.clone(),
            )?)
        } else if settings.allow_local_providers {
            local.clone()
        } else {
            return Err(ProviderBuildError::MissingConfiguration);
        };

        let sms: Arc<dyn SmsDelivery> = match (
            &settings.twilio_account_sid,
            &settings.twilio_auth_token,
            &settings.twilio_messaging_service_sid,
        ) {
            (Some(account_sid), Some(auth_token), Some(messaging_service_sid)) => {
                Arc::new(TwilioSms::new(
                    account_sid.clone(),
                    auth_token.clone(),
                    messaging_service_sid.clone(),
                )?)
            }
            (None, None, None) if settings.allow_local_providers => local,
            _ => return Err(ProviderBuildError::MissingConfiguration),
        };

        Ok(Self { email, sms })
    }
}
