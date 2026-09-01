//! Silicon Hook provisioning adapter.

use std::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{application::ports::DeliveryError, config::WorkerProviderSettings};

use super::http;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct HookClient {
    client: reqwest::Client,
    endpoint: Url,
    expected_origin: String,
    service_token: Option<SecretString>,
    local: bool,
}

pub(crate) struct ProvisionedHook {
    pub(crate) provider_hook_id: String,
    pub(crate) url: SecretString,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum HookError {
    #[error("Silicon Hook is temporarily unavailable")]
    Unavailable,
    #[error("Silicon Hook rejected the provisioning request")]
    Rejected,
    #[error("Silicon Hook returned an invalid endpoint")]
    InvalidResponse,
}

impl HookError {
    pub(crate) const fn retryable(self) -> bool {
        matches!(self, Self::Unavailable)
    }

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "hook_unavailable",
            Self::Rejected => "hook_rejected",
            Self::InvalidResponse => "hook_invalid_response",
        }
    }
}

#[derive(Serialize)]
struct ProvisionRequest<'a> {
    name: &'static str,
    silicon_global_id: &'a str,
    organization_id: Uuid,
    idempotency_key: Uuid,
}

#[derive(Deserialize)]
struct ProvisionResponse {
    id: String,
    url: Url,
}

impl HookClient {
    pub(crate) fn from_settings(settings: &WorkerProviderSettings) -> Result<Self, HookError> {
        let endpoint = append_path(&settings.hook_base_url, "hooks");
        let expected_origin = settings.hook_base_url.origin().ascii_serialization();
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(settings.hook_base_url.scheme() == "https")
            .user_agent(concat!("silicon-iam/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| HookError::Unavailable)?;
        Ok(Self {
            client,
            endpoint,
            expected_origin,
            service_token: settings.hook_service_token.clone(),
            local: settings.allow_local_providers && settings.hook_service_token.is_none(),
        })
    }

    pub(crate) async fn provision(
        &self,
        hook_id: Uuid,
        organization_id: Uuid,
        silicon_global_id: &str,
    ) -> Result<ProvisionedHook, HookError> {
        if self.local {
            let suffix = &hook_id.simple().to_string()[..6];
            let mut url = self.endpoint.clone();
            url.set_path(&format!("/silicon/{silicon_global_id}/{suffix}"));
            return Ok(ProvisionedHook {
                provider_hook_id: format!("local-{hook_id}"),
                url: SecretString::from(url.to_string()),
            });
        }
        let service_token = self.service_token.as_ref().ok_or(HookError::Unavailable)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(service_token.expose_secret())
            .json(&ProvisionRequest {
                name: "Silicon IAM",
                silicon_global_id,
                organization_id,
                idempotency_key: hook_id,
            })
            .send()
            .await
            .map_err(|_| HookError::Unavailable)?;
        if !response.status().is_success() {
            return Err(map_delivery_error(http::classify_status(response.status())));
        }
        let provisioned = http::decode_json::<ProvisionResponse>(response)
            .await
            .map_err(map_delivery_error)?;
        validate_response(&self.expected_origin, silicon_global_id, &provisioned)?;
        Ok(ProvisionedHook {
            provider_hook_id: provisioned.id,
            url: SecretString::from(provisioned.url.to_string()),
        })
    }
}

fn validate_response(
    expected_origin: &str,
    silicon_global_id: &str,
    response: &ProvisionResponse,
) -> Result<(), HookError> {
    if response.id.is_empty()
        || response.id.len() > 255
        || response.url.origin().ascii_serialization() != expected_origin
        || !response.url.username().is_empty()
        || response.url.password().is_some()
        || response.url.query().is_some()
        || response.url.fragment().is_some()
    {
        return Err(HookError::InvalidResponse);
    }
    let segments = response
        .url
        .path_segments()
        .ok_or(HookError::InvalidResponse)?
        .collect::<Vec<_>>();
    let Some(silicon_position) = segments.iter().position(|segment| *segment == "silicon") else {
        return Err(HookError::InvalidResponse);
    };
    let id_matches = segments.get(silicon_position + 1) == Some(&silicon_global_id);
    let suffix_valid = segments.get(silicon_position + 2).is_some_and(|suffix| {
        suffix.len() >= 6 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    });
    if !id_matches || !suffix_valid {
        return Err(HookError::InvalidResponse);
    }
    Ok(())
}

fn append_path(base: &Url, suffix: &str) -> Url {
    let mut url = base.clone();
    let mut path = url.path().trim_end_matches('/').to_owned();
    path.push('/');
    path.push_str(suffix.trim_start_matches('/'));
    url.set_path(&path);
    url
}

const fn map_delivery_error(error: DeliveryError) -> HookError {
    match error {
        DeliveryError::Unavailable => HookError::Unavailable,
        DeliveryError::Rejected => HookError::Rejected,
    }
}
