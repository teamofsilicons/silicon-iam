//! Narrow, hardened `WorkOS` adapter for organization SSO.

use std::time::Duration;

use bytes::BytesMut;
use futures::StreamExt as _;
use hmac::{Hmac, Mac as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use url::Url;

use crate::config::ProviderSettings;

type HmacSha256 = Hmac<Sha256>;

const API_BASE: &str = "https://api.workos.com/";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_HEADER_BYTES: usize = 4_096;
const WEBHOOK_TOLERANCE_MILLISECONDS: u64 = 300_000;

/// Configured `WorkOS` API and webhook-verification client.
#[derive(Clone)]
pub(crate) struct WorkOsClient {
    client: reqwest::Client,
    api_base: Url,
    api_key: SecretString,
    client_id: String,
    webhook_secret: SecretString,
}

/// Stable subset of a `WorkOS` organization used by the IAM service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct WorkOsOrganization {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) external_id: Option<String>,
}

/// Stable connection fields used to verify the local organization mapping.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct WorkOsConnection {
    pub(crate) id: String,
    pub(crate) organization_id: String,
    pub(crate) state: String,
}

/// One-time Admin Portal link. The URL is intentionally secret-bearing.
pub(crate) struct WorkOsPortalLink {
    pub(crate) url: SecretString,
}

/// Stable subset of an SSO profile used to bind an existing Carbon.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct WorkOsProfile {
    pub(crate) id: String,
    pub(crate) organization_id: String,
    pub(crate) connection_id: String,
    pub(crate) email: String,
}

/// Evidence returned only after the raw webhook request is authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedWebhook {
    pub(crate) issued_at_milliseconds: i64,
}

/// Redacted provider failure classification.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum WorkOsError {
    #[error("WorkOS is not configured")]
    NotConfigured,
    #[error("WorkOS is temporarily unavailable")]
    Unavailable,
    #[error("WorkOS rejected the request")]
    Rejected,
    #[error("the WorkOS resource was not found")]
    NotFound,
    #[error("the WorkOS resource conflicts with existing state")]
    Conflict,
    #[error("WorkOS returned an invalid response")]
    InvalidResponse,
    #[error("the WorkOS webhook signature is invalid")]
    InvalidSignature,
    #[error("the WorkOS webhook signature is stale")]
    StaleSignature,
}

#[derive(Serialize)]
struct CreateOrganizationRequest<'a> {
    name: &'a str,
    external_id: &'a str,
}

#[derive(Serialize)]
struct PortalLinkRequest<'a> {
    organization: &'a str,
    intent: &'static str,
}

#[derive(Deserialize)]
struct PortalLinkResponse {
    link: Url,
}

#[derive(Serialize)]
struct TokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    grant_type: &'static str,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[allow(dead_code, reason = "deserializing it validates the provider contract")]
    #[serde(deserialize_with = "deserialize_secret_string")]
    access_token: SecretString,
    profile: WorkOsProfile,
}

fn deserialize_secret_string<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(SecretString::from)
}

impl WorkOsClient {
    /// Builds the adapter when the complete credential group is configured.
    pub(crate) fn from_settings(settings: &ProviderSettings) -> Result<Option<Self>, WorkOsError> {
        match (
            settings.workos_api_key.as_ref(),
            settings.workos_client_id.as_ref(),
            settings.workos_webhook_secret.as_ref(),
        ) {
            (None, None, None) => Ok(None),
            (Some(api_key), Some(client_id), Some(webhook_secret)) => {
                let api_base = Url::parse(API_BASE).map_err(|_| WorkOsError::NotConfigured)?;
                let client = reqwest::Client::builder()
                    .connect_timeout(CONNECT_TIMEOUT)
                    .timeout(REQUEST_TIMEOUT)
                    .redirect(reqwest::redirect::Policy::none())
                    .https_only(true)
                    .user_agent(concat!("silicon-iam/", env!("CARGO_PKG_VERSION")))
                    .build()
                    .map_err(|_| WorkOsError::NotConfigured)?;
                Ok(Some(Self {
                    client,
                    api_base,
                    api_key: api_key.clone(),
                    client_id: client_id.clone(),
                    webhook_secret: webhook_secret.clone(),
                }))
            }
            _ => Err(WorkOsError::NotConfigured),
        }
    }

    /// Gets or creates the unique provider organization for an IAM organization.
    ///
    /// A create request is never retried blindly. If its outcome is ambiguous,
    /// the external identifier is read once to reconcile provider state.
    pub(crate) async fn ensure_organization(
        &self,
        external_id: &str,
        name: &str,
    ) -> Result<WorkOsOrganization, WorkOsError> {
        match self.organization_by_external_id(external_id).await {
            Ok(organization) => return Ok(organization),
            Err(WorkOsError::NotFound) => {}
            Err(error) => return Err(error),
        }

        let result = self.create_organization(external_id, name).await;
        match result {
            Ok(organization) => Ok(organization),
            Err(error @ (WorkOsError::Conflict | WorkOsError::Unavailable)) => {
                match self.organization_by_external_id(external_id).await {
                    Ok(organization) => Ok(organization),
                    Err(WorkOsError::NotFound) => Err(error),
                    Err(reconciliation_error) => Err(reconciliation_error),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Fetches a provider organization by the immutable IAM organization ID.
    pub(crate) async fn organization_by_external_id(
        &self,
        external_id: &str,
    ) -> Result<WorkOsOrganization, WorkOsError> {
        let endpoint = self.endpoint(&["organizations", "external_id", external_id])?;
        let response = self
            .client
            .get(endpoint)
            .bearer_auth(self.api_key.expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| WorkOsError::Unavailable)?;
        decode_success(response)
            .await
            .and_then(validate_organization)
    }

    /// Fetches a provider organization by its provider-issued identifier.
    pub(crate) async fn organization(
        &self,
        organization_id: &str,
    ) -> Result<WorkOsOrganization, WorkOsError> {
        let endpoint = self.endpoint(&["organizations", organization_id])?;
        let response = self
            .client
            .get(endpoint)
            .bearer_auth(self.api_key.expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| WorkOsError::Unavailable)?;
        decode_success(response)
            .await
            .and_then(validate_organization)
    }

    /// Fetches a provider connection for an exact local mapping check.
    pub(crate) async fn connection(
        &self,
        connection_id: &str,
    ) -> Result<WorkOsConnection, WorkOsError> {
        let endpoint = self.endpoint(&["connections", connection_id])?;
        let response = self
            .client
            .get(endpoint)
            .bearer_auth(self.api_key.expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| WorkOsError::Unavailable)?;
        decode_success(response).await.and_then(validate_connection)
    }

    /// Generates a provider-controlled five-minute SSO Admin Portal link.
    pub(crate) async fn portal_link(
        &self,
        organization_id: &str,
    ) -> Result<WorkOsPortalLink, WorkOsError> {
        let endpoint = self.endpoint(&["portal", "generate_link"])?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.api_key.expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&PortalLinkRequest {
                organization: organization_id,
                intent: "sso",
            })
            .send()
            .await
            .map_err(|_| WorkOsError::Unavailable)?;
        let body = decode_success::<PortalLinkResponse>(response).await?;
        if body.link.scheme() != "https"
            || !body.link.username().is_empty()
            || body.link.password().is_some()
            || body.link.host_str().is_none()
            || body.link.fragment().is_some()
        {
            return Err(WorkOsError::InvalidResponse);
        }
        Ok(WorkOsPortalLink {
            url: SecretString::from(body.link.to_string()),
        })
    }

    /// Constructs the authorization endpoint with exactly one connection selector.
    pub(crate) fn authorization_url(
        &self,
        organization_id: &str,
        redirect_uri: &Url,
        state: &SecretString,
        nonce: &SecretString,
    ) -> Result<Url, WorkOsError> {
        if organization_id.is_empty()
            || organization_id.len() > 255
            || redirect_uri.fragment().is_some()
            || !redirect_uri.username().is_empty()
            || redirect_uri.password().is_some()
        {
            return Err(WorkOsError::Rejected);
        }
        let mut endpoint = self.endpoint(&["sso", "authorize"])?;
        endpoint
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair("state", state.expose_secret())
            .append_pair("nonce", nonce.expose_secret())
            .append_pair("organization", organization_id);
        Ok(endpoint)
    }

    /// Exchanges a single-use authorization code for its normalized SSO profile.
    pub(crate) async fn exchange_code(
        &self,
        code: &SecretString,
    ) -> Result<WorkOsProfile, WorkOsError> {
        let endpoint = self.endpoint(&["sso", "token"])?;
        let response = self
            .client
            .post(endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&TokenRequest {
                client_id: &self.client_id,
                client_secret: self.api_key.expose_secret(),
                code: code.expose_secret(),
                grant_type: "authorization_code",
            })
            .send()
            .await
            .map_err(|_| WorkOsError::Unavailable)?;
        let body = decode_success::<TokenResponse>(response).await?;
        validate_profile(body.profile)
    }

    /// Authenticates the exact raw webhook body and enforces a five-minute window.
    pub(crate) fn verify_webhook(
        &self,
        signature_header: &str,
        raw_body: &[u8],
        now_milliseconds: i64,
    ) -> Result<VerifiedWebhook, WorkOsError> {
        verify_webhook_signature(
            &self.webhook_secret,
            signature_header,
            raw_body,
            now_milliseconds,
        )
    }

    async fn create_organization(
        &self,
        external_id: &str,
        name: &str,
    ) -> Result<WorkOsOrganization, WorkOsError> {
        let endpoint = self.endpoint(&["organizations"])?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.api_key.expose_secret())
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&CreateOrganizationRequest { name, external_id })
            .send()
            .await
            .map_err(|_| WorkOsError::Unavailable)?;
        decode_success(response)
            .await
            .and_then(validate_organization)
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, WorkOsError> {
        let mut endpoint = self.api_base.clone();
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let mut path = endpoint
            .path_segments_mut()
            .map_err(|()| WorkOsError::NotConfigured)?;
        path.clear();
        path.extend(segments);
        drop(path);
        Ok(endpoint)
    }
}

async fn decode_success<T>(response: reqwest::Response) -> Result<T, WorkOsError>
where
    T: DeserializeOwned,
{
    let status = response.status();
    if !status.is_success() {
        return Err(classify_status(status));
    }
    let mut body = BytesMut::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| WorkOsError::Unavailable)?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(WorkOsError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| WorkOsError::InvalidResponse)
}

fn classify_status(status: reqwest::StatusCode) -> WorkOsError {
    match status {
        reqwest::StatusCode::NOT_FOUND => WorkOsError::NotFound,
        reqwest::StatusCode::CONFLICT => WorkOsError::Conflict,
        reqwest::StatusCode::REQUEST_TIMEOUT
        | reqwest::StatusCode::TOO_EARLY
        | reqwest::StatusCode::TOO_MANY_REQUESTS => WorkOsError::Unavailable,
        _ if status.is_server_error() => WorkOsError::Unavailable,
        _ => WorkOsError::Rejected,
    }
}

fn validate_organization(
    organization: WorkOsOrganization,
) -> Result<WorkOsOrganization, WorkOsError> {
    if !valid_provider_id(&organization.id, "org_")
        || organization.name.is_empty()
        || organization.name.len() > 255
        || organization
            .external_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 255)
    {
        return Err(WorkOsError::InvalidResponse);
    }
    Ok(organization)
}

fn validate_connection(connection: WorkOsConnection) -> Result<WorkOsConnection, WorkOsError> {
    if !valid_provider_id(&connection.id, "conn_")
        || !valid_provider_id(&connection.organization_id, "org_")
        || connection.state.is_empty()
        || connection.state.len() > 100
        || !connection.state.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(WorkOsError::InvalidResponse);
    }
    Ok(connection)
}

fn validate_profile(profile: WorkOsProfile) -> Result<WorkOsProfile, WorkOsError> {
    if !valid_provider_id(&profile.id, "prof_")
        || !valid_provider_id(&profile.organization_id, "org_")
        || !valid_provider_id(&profile.connection_id, "conn_")
        || profile.email.is_empty()
        || profile.email.len() > 254
    {
        return Err(WorkOsError::InvalidResponse);
    }
    Ok(profile)
}

fn valid_provider_id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() > prefix.len()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn verify_webhook_signature(
    secret: &SecretString,
    header: &str,
    raw_body: &[u8],
    now_milliseconds: i64,
) -> Result<VerifiedWebhook, WorkOsError> {
    if header.is_empty()
        || header.len() > MAX_SIGNATURE_HEADER_BYTES
        || std::str::from_utf8(raw_body).is_err()
        || now_milliseconds < 0
    {
        return Err(WorkOsError::InvalidSignature);
    }

    let mut timestamp = None;
    let mut signatures = Vec::new();
    for component in header.split(',') {
        let (key, value) = component
            .trim()
            .split_once('=')
            .ok_or(WorkOsError::InvalidSignature)?;
        match key {
            "t" if timestamp.is_none() => {
                timestamp = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| WorkOsError::InvalidSignature)?,
                );
            }
            "v1" => {
                let decoded = hex::decode(value).map_err(|_| WorkOsError::InvalidSignature)?;
                if decoded.len() != 32 {
                    return Err(WorkOsError::InvalidSignature);
                }
                signatures.push(decoded);
            }
            _ => return Err(WorkOsError::InvalidSignature),
        }
    }
    let timestamp = timestamp.ok_or(WorkOsError::InvalidSignature)?;
    if timestamp < 0 || signatures.is_empty() {
        return Err(WorkOsError::InvalidSignature);
    }
    if timestamp.abs_diff(now_milliseconds) > WEBHOOK_TOLERANCE_MILLISECONDS {
        return Err(WorkOsError::StaleSignature);
    }

    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(secret.expose_secret().as_bytes())
        .map_err(|_| WorkOsError::InvalidSignature)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    let expected = mac.finalize().into_bytes();
    let matches = signatures.iter().fold(0_u8, |matched, candidate| {
        matched | expected.ct_eq(candidate).unwrap_u8()
    });
    if matches != 1 {
        return Err(WorkOsError::InvalidSignature);
    }
    Ok(VerifiedWebhook {
        issued_at_milliseconds: timestamp,
    })
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, Mac as _};
    use secrecy::{ExposeSecret as _, SecretString};
    use sha2::Sha256;

    use super::{WorkOsConnection, WorkOsError, validate_connection, verify_webhook_signature};

    fn signature(secret: &SecretString, timestamp: i64, body: &[u8]) -> String {
        let result = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret.expose_secret().as_bytes());
        assert!(result.is_ok());
        let Ok(mut mac) = result else {
            unreachable!("HMAC accepts arbitrary key lengths");
        };
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        )
    }

    #[test]
    fn verifies_exact_body_with_millisecond_freshness() {
        let secret = SecretString::from("whsec_test_value".to_owned());
        let body = br#"{"event":"connection.activated"}"#;
        let header = signature(&secret, 1_700_000_000_000, body);
        let verified = verify_webhook_signature(&secret, &header, body, 1_700_000_250_000);
        assert_eq!(
            verified.map(|value| value.issued_at_milliseconds),
            Ok(1_700_000_000_000)
        );
        assert_eq!(
            verify_webhook_signature(
                &secret,
                &header,
                br#"{"event":"connection.deleted"}"#,
                1_700_000_250_000,
            ),
            Err(WorkOsError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_stale_and_malformed_signatures() {
        let secret = SecretString::from("whsec_test_value".to_owned());
        let body = br"{}";
        let header = signature(&secret, 1_700_000_000_000, body);
        assert_eq!(
            verify_webhook_signature(&secret, &header, body, 1_700_000_300_001),
            Err(WorkOsError::StaleSignature)
        );
        assert_eq!(
            verify_webhook_signature(&secret, "v1=00", body, 1_700_000_000_000),
            Err(WorkOsError::InvalidSignature)
        );
    }

    #[test]
    fn validates_tenant_bound_connection_fields() {
        let connection = WorkOsConnection {
            id: "conn_01E4ZCR3C56J083X43JQXF3JK5".to_owned(),
            organization_id: "org_01EHWNCE74X7JSDV0X3SZ3KJNY".to_owned(),
            state: "active".to_owned(),
        };
        assert!(validate_connection(connection.clone()).is_ok());
        assert!(
            validate_connection(WorkOsConnection {
                organization_id: "tenant-from-another-provider".to_owned(),
                ..connection
            })
            .is_err()
        );
    }
}
