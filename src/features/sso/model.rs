use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

#[derive(Clone, Debug, Serialize)]
pub(super) struct SsoConfiguration {
    pub(super) org_id: String,
    pub(super) entitled: bool,
    pub(super) status: String,
    pub(super) join_method: String,
    pub(super) workos_organization_id: Option<String>,
    pub(super) connection_id: Option<String>,
    pub(super) version: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SsoEntitlement {
    pub(super) enabled: bool,
    pub(super) reason: Option<String>,
    pub(super) version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct SsoEntitlementResponse {
    pub(super) enabled: bool,
    pub(super) reason: Option<String>,
    pub(super) version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct SsoSetupLink {
    pub(super) url: String,
    pub(super) expires_in: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct TestResult {
    pub(super) ok: bool,
    pub(super) message: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub(super) checked_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorizeQuery {
    pub(super) return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CallbackQuery {
    pub(super) code: String,
    pub(super) state: String,
}

pub(super) struct ValidatedAuthorize {
    pub(super) return_to: Url,
}

pub(super) struct CorrelationSecret {
    pub(super) state: SecretString,
    pub(super) nonce: SecretString,
    pub(super) wire_state: SecretString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProviderConnectionTransition {
    Activated,
    Deactivated,
    Deleted,
}

impl ProviderConnectionTransition {
    pub(super) const fn event_name(self) -> &'static str {
        match self {
            Self::Activated => "connection.activated",
            Self::Deactivated => "connection.deactivated",
            Self::Deleted => "connection.deleted",
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct WorkOsWebhookEnvelope {
    pub(super) id: String,
    pub(super) event: String,
    pub(super) data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub(super) struct WorkOsConnectionData {
    pub(super) object: String,
    pub(super) id: String,
    pub(super) organization_id: String,
    pub(super) connection_type: Option<String>,
    pub(super) state: Option<String>,
}
