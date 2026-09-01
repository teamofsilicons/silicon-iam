//! Typed runtime configuration loaded from environment variables.

use std::{
    collections::BTreeMap,
    env, fmt,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    str::FromStr,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const MAX_CORS_ORIGINS: usize = 16;
const MAX_KEYRING_KEYS: usize = 16;
const MAX_KEYRING_JSON_BYTES: usize = 4_096;
const MINIMUM_WORKER_LEASE_SECONDS: u64 = 20;
const WORKER_PROVIDER_DEADLINE_SECONDS: u64 = 10;
const WORKER_LEASE_COMPLETION_MARGIN_SECONDS: u64 = 5;
const MAXIMUM_RETENTION_DAYS: u16 = 36_500;
const MAXIMUM_RETENTION_BATCH_SIZE: usize = 1_000;

/// Fully validated process configuration.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Deployment environment and its safety policy.
    pub environment: RuntimeEnvironment,
    /// HTTP server settings.
    pub server: ServerSettings,
    /// PostgreSQL pool settings.
    pub database: DatabaseSettings,
    /// Optional Valkey/Redis settings.
    pub redis: Option<RedisSettings>,
    /// Credential and data-protection settings.
    pub security: SecuritySettings,
    /// External provider settings.
    pub providers: ProviderSettings,
    /// Outbox-worker settings.
    pub worker: WorkerSettings,
    /// Tracing filter directive.
    pub log_filter: String,
}

/// Minimal configuration accepted by the privileged migration process.
#[derive(Clone, Debug)]
pub struct MigrationSettings {
    /// Deployment environment and its transport policy.
    pub environment: RuntimeEnvironment,
    /// Privileged PostgreSQL connection used only for schema migrations.
    pub database: DatabaseSettings,
    /// Tracing filter directive.
    pub log_filter: String,
}

/// Minimal configuration accepted by the narrowly privileged key operator.
#[derive(Clone, Debug)]
pub struct KeyOperatorSettings {
    /// Deployment environment and its transport policy.
    pub environment: RuntimeEnvironment,
    /// Dedicated PostgreSQL connection with activation-function authority only.
    pub database: DatabaseSettings,
    /// Tracing filter directive.
    pub log_filter: String,
}

/// Minimal configuration and secrets available to the durable worker process.
///
/// This composition root intentionally cannot hold token peppers, contact
/// blind-index keys, browser-cookie keys, JWT signing material, Redis settings,
/// or `WorkOS` authority credentials.
#[derive(Clone, Debug)]
pub struct WorkerProcessSettings {
    /// Deployment environment and its safety policy.
    pub environment: RuntimeEnvironment,
    /// Restricted worker PostgreSQL connection.
    pub database: DatabaseSettings,
    /// Browser authentication frontend used to build invitation links.
    pub auth_base_url: Url,
    /// Graceful worker-drain deadline.
    pub shutdown_timeout: Duration,
    /// Contact and protected-field AEAD keyring used by delivery jobs.
    pub encryption_keys: KeyringSettings,
    /// Delivery and downstream provisioning providers used by the worker.
    pub providers: WorkerProviderSettings,
    /// Polling, retry, and retention policy.
    pub worker: WorkerSettings,
    /// Tracing filter directive.
    pub log_filter: String,
}

/// Deployment environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeEnvironment {
    /// Local developer process.
    Development,
    /// Automated test process.
    Test,
    /// Deployed production process.
    Production,
}

/// HTTP listener and request-policy settings.
#[derive(Clone, Debug)]
pub struct ServerSettings {
    /// Address on which the API listens.
    pub bind_addr: SocketAddr,
    /// Canonical externally visible backend URL.
    pub public_base_url: Url,
    /// Canonical browser authentication frontend URL.
    pub auth_base_url: Url,
    /// Maximum request processing duration.
    pub request_timeout: Duration,
    /// Maximum accepted HTTP body size.
    pub max_body_bytes: usize,
    /// Maximum requests admitted concurrently by one API process.
    pub max_concurrent_requests: usize,
    /// Exact browser origins allowed to call the API.
    pub cors_allowed_origins: Vec<Url>,
    /// Graceful shutdown deadline.
    pub shutdown_timeout: Duration,
}

/// PostgreSQL connection-pool settings.
#[derive(Clone, Debug)]
pub struct DatabaseSettings {
    /// PostgreSQL connection URL.
    pub url: SecretString,
    /// Maximum open connections per process.
    pub max_connections: NonZeroU32,
    /// Minimum idle connections per process.
    pub min_connections: u32,
    /// Pool acquisition deadline.
    pub acquire_timeout: Duration,
    /// Per-statement database deadline.
    pub statement_timeout: Duration,
}

/// Optional Redis-compatible coordination service settings.
#[derive(Clone, Debug)]
pub struct RedisSettings {
    /// Redis/Valkey connection URL.
    pub url: SecretString,
    /// Connection establishment deadline.
    pub connect_timeout: Duration,
    /// Individual command deadline.
    pub command_timeout: Duration,
}

/// Secrets and credential lifetime policy.
#[derive(Clone, Debug)]
pub struct SecuritySettings {
    /// Versioned keyed-digest secrets for opaque credentials.
    pub token_peppers: KeyringSettings,
    /// Versioned blind-index keys for normalized PII lookup.
    pub blind_index_keys: KeyringSettings,
    /// Versioned AES-256-GCM data-encryption keys.
    pub encryption_keys: KeyringSettings,
    /// Browser session cookie integrity key.
    pub cookie_key: SecretString,
    /// Ed25519 private signing key encoded as a raw 32-byte base64url seed.
    pub jwt_ed25519_private_key: SecretString,
    /// Public key identifier placed in signed tokens.
    pub jwt_key_id: String,
    /// Opaque access-token lifetime.
    pub access_token_ttl: Duration,
    /// Absolute refresh-family lifetime.
    pub refresh_family_ttl: Duration,
    /// Authorization-code lifetime.
    pub authorization_code_ttl: Duration,
    /// OTP lifetime.
    pub otp_ttl: Duration,
    /// Maximum verification attempts for one OTP.
    pub otp_max_attempts: u16,
}

/// Versioned secret material with one active write version.
#[derive(Clone, Debug)]
pub struct KeyringSettings {
    /// Version used for newly created values.
    pub current_version: i16,
    /// Current and retained historical keys indexed by positive version.
    pub keys: BTreeMap<i16, SecretString>,
}

struct UniqueStringMap(BTreeMap<String, SecretString>);

impl<'de> Deserialize<'de> for UniqueStringMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(UniqueStringMapVisitor)
    }
}

struct UniqueStringMapVisitor;

impl<'de> Visitor<'de> for UniqueStringMapVisitor {
    type Value = UniqueStringMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object with unique string keys and string values")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<String, String>()? {
            if values.insert(key, SecretString::from(value)).is_some() {
                return Err(serde::de::Error::custom("duplicate key version"));
            }
            if values.len() > MAX_KEYRING_KEYS {
                return Err(serde::de::Error::custom("too many key versions"));
            }
        }
        Ok(UniqueStringMap(values))
    }
}

/// External provider credentials and endpoints.
#[derive(Clone, Debug)]
pub struct ProviderSettings {
    /// Postmark server API token.
    pub postmark_server_token: Option<SecretString>,
    /// Verified transactional sender.
    pub postmark_from_email: String,
    /// Twilio account identifier.
    pub twilio_account_sid: Option<SecretString>,
    /// Twilio account authentication token.
    pub twilio_auth_token: Option<SecretString>,
    /// Twilio Messaging Service identifier used to deliver IAM-generated OTPs.
    pub twilio_messaging_service_sid: Option<SecretString>,
    /// `WorkOS` API key.
    pub workos_api_key: Option<SecretString>,
    /// `WorkOS` client identifier.
    pub workos_client_id: Option<String>,
    /// `WorkOS` webhook verification secret.
    pub workos_webhook_secret: Option<SecretString>,
    /// Silicon Hook API base URL.
    pub hook_base_url: Url,
    /// IAM service credential for Silicon Hook.
    pub hook_service_token: Option<SecretString>,
    /// Silicon Iris public base URL.
    pub iris_base_url: Url,
    /// Whether deterministic local provider implementations are allowed.
    pub allow_local_providers: bool,
    /// Whether local provider responses may reveal OTPs for developer tests.
    pub expose_local_otps: bool,
}

/// Provider configuration available to the durable worker process.
///
/// Authentication-authority providers such as `WorkOS` are intentionally
/// absent from this type.
#[derive(Clone, Debug)]
pub struct WorkerProviderSettings {
    /// Postmark server API token.
    pub postmark_server_token: Option<SecretString>,
    /// Verified transactional sender.
    pub postmark_from_email: String,
    /// Twilio account identifier.
    pub twilio_account_sid: Option<SecretString>,
    /// Twilio account authentication token.
    pub twilio_auth_token: Option<SecretString>,
    /// Twilio Messaging Service identifier used for notification delivery.
    pub twilio_messaging_service_sid: Option<SecretString>,
    /// Silicon Hook API base URL.
    pub hook_base_url: Url,
    /// IAM service credential for Silicon Hook.
    pub hook_service_token: Option<SecretString>,
    /// Silicon Iris public base URL.
    pub iris_base_url: Url,
    /// Whether deterministic local delivery adapters are allowed.
    pub allow_local_providers: bool,
}

/// Durable worker polling and retry policy.
#[derive(Clone, Debug)]
pub struct WorkerSettings {
    /// Maximum outbox jobs claimed in one batch.
    pub batch_size: NonZeroUsize,
    /// Maximum delivery jobs processed concurrently by one worker process.
    pub delivery_concurrency: NonZeroUsize,
    /// Idle polling interval.
    pub poll_interval: Duration,
    /// Duration of a claim lease.
    pub lease_duration: Duration,
    /// Maximum delivery attempts before dead-letter state.
    pub max_attempts: u16,
    /// Maximum retry delay.
    pub max_retry_delay: Duration,
    /// Bounded data-retention policy enforced by the worker.
    pub retention: RetentionSettings,
}

/// Configurable retention periods and sweep policy.
#[derive(Clone, Debug)]
pub struct RetentionSettings {
    /// Delay between bounded single-phase retention ticks.
    pub sweep_interval: Duration,
    /// Maximum root records processed in one phase.
    pub batch_size: NonZeroUsize,
    /// Login and authentication-history retention.
    pub login_history_days: u16,
    /// Expired challenge and abandoned transaction retention.
    pub ephemeral_security_days: u16,
    /// Expired or revoked token-metadata retention.
    pub token_metadata_days: u16,
    /// Compromised refresh-family retention.
    pub compromised_refresh_days: u16,
    /// Webhook-attempt telemetry retention.
    pub webhook_attempt_days: u16,
    /// Security audit-event retention.
    pub audit_event_days: u16,
}

/// Configuration loading or validation failure.
#[derive(Debug, Error)]
pub enum SettingsError {
    /// A required variable is absent.
    #[error("required environment variable {0} is missing")]
    Missing(&'static str),
    /// A variable cannot be parsed or violates a safety policy.
    #[error("invalid environment variable {name}: {reason}")]
    Invalid {
        /// Environment variable name.
        name: &'static str,
        /// Redacted reason that never contains the supplied secret.
        reason: String,
    },
}

impl Settings {
    /// Loads and validates settings from the current process environment.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when a required setting is missing, malformed,
    /// or violates the selected environment's safety policy.
    pub fn from_env() -> Result<Self, SettingsError> {
        let environment = parse_or("IAM_ENVIRONMENT", "development")?;
        let server = server_settings(environment)?;
        let database = database_settings()?;
        let redis = redis_settings()?;
        let security = security_settings(environment)?;
        let providers = provider_settings()?;
        let worker = worker_settings()?;

        validate_environment_safety(environment, &server, &database, redis.as_ref(), &providers)?;
        let log_filter = string_in_range(
            "IAM_LOG_FILTER",
            value_or("IAM_LOG_FILTER", "silicon_iam=info,tower_http=info"),
            1,
            2_048,
        )?;

        Ok(Self {
            environment,
            server,
            database,
            redis,
            security,
            providers,
            worker,
            log_filter,
        })
    }
}

impl WorkerProcessSettings {
    /// Loads the deliberately restricted worker-process settings.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when an intended worker variable is missing,
    /// malformed, incomplete, or unsafe for the selected environment.
    pub fn from_env() -> Result<Self, SettingsError> {
        let environment = parse_or("IAM_ENVIRONMENT", "development")?;
        let database = database_settings()?;
        let auth_base_url = parse_required("IAM_AUTH_BASE_URL")?;
        let shutdown_timeout = duration_secs_in_range("IAM_SHUTDOWN_TIMEOUT_SECONDS", 30, 1, 300)?;
        let encryption_keys = keyring("IAM_ENCRYPTION")?;
        let providers = worker_provider_settings()?;
        let worker = worker_settings()?;
        let log_filter = string_in_range(
            "IAM_LOG_FILTER",
            value_or("IAM_LOG_FILTER", "silicon_iam=info"),
            1,
            2_048,
        )?;

        validate_database_transport(environment, &database, "IAM_DATABASE_URL")?;
        validate_http_base_url("IAM_AUTH_BASE_URL", &auth_base_url, environment, &["/"])?;
        validate_worker_provider_settings(environment, &providers)?;
        validate_worker_database_lease_policy(
            worker.lease_duration,
            database.acquire_timeout,
            database.statement_timeout,
        )?;

        Ok(Self {
            environment,
            database,
            auth_base_url,
            shutdown_timeout,
            encryption_keys,
            providers,
            worker,
            log_filter,
        })
    }
}

fn server_settings(environment: RuntimeEnvironment) -> Result<ServerSettings, SettingsError> {
    let public_base_url = parse_required("IAM_PUBLIC_BASE_URL")?;
    let auth_base_url = parse_required("IAM_AUTH_BASE_URL")?;
    validate_http_base_url("IAM_PUBLIC_BASE_URL", &public_base_url, environment, &["/"])?;
    validate_http_base_url("IAM_AUTH_BASE_URL", &auth_base_url, environment, &["/"])?;
    let cors_allowed_origins =
        cors_origins("IAM_CORS_ALLOWED_ORIGINS", &auth_base_url, environment)?;
    let settings = ServerSettings {
        bind_addr: parse_or("IAM_BIND_ADDR", "127.0.0.1:8080")?,
        public_base_url,
        auth_base_url,
        request_timeout: duration_secs_in_range("IAM_REQUEST_TIMEOUT_SECONDS", 15, 1, 120)?,
        max_body_bytes: usize_in_range("IAM_MAX_BODY_BYTES", 65_536, 1_024, 1_048_576)?,
        max_concurrent_requests: usize_in_range("IAM_MAX_CONCURRENT_REQUESTS", 512, 1, 10_000)?,
        cors_allowed_origins,
        shutdown_timeout: duration_secs_in_range("IAM_SHUTDOWN_TIMEOUT_SECONDS", 30, 1, 300)?,
    };
    if settings.bind_addr.port() == 0 {
        return Err(invalid("IAM_BIND_ADDR", "port must be greater than zero"));
    }
    Ok(settings)
}

fn database_settings() -> Result<DatabaseSettings, SettingsError> {
    let max_connections = nonzero_u32_in_range("IAM_DATABASE_MAX_CONNECTIONS", 16, 256)?;
    Ok(DatabaseSettings {
        url: SecretString::from(required("IAM_DATABASE_URL")?),
        max_connections,
        min_connections: u32_in_range("IAM_DATABASE_MIN_CONNECTIONS", 1, 0, max_connections.get())?,
        acquire_timeout: duration_secs_in_range("IAM_DATABASE_ACQUIRE_TIMEOUT_SECONDS", 3, 1, 60)?,
        statement_timeout: duration_secs_in_range(
            "IAM_DATABASE_STATEMENT_TIMEOUT_SECONDS",
            10,
            1,
            300,
        )?,
    })
}

fn redis_settings() -> Result<Option<RedisSettings>, SettingsError> {
    optional("IAM_REDIS_URL")
        .map(|url| {
            Ok(RedisSettings {
                url: SecretString::from(url),
                connect_timeout: duration_millis_in_range(
                    "IAM_REDIS_CONNECT_TIMEOUT_MS",
                    500,
                    50,
                    30_000,
                )?,
                command_timeout: duration_millis_in_range(
                    "IAM_REDIS_COMMAND_TIMEOUT_MS",
                    750,
                    10,
                    30_000,
                )?,
            })
        })
        .transpose()
}

fn security_settings(environment: RuntimeEnvironment) -> Result<SecuritySettings, SettingsError> {
    let settings = SecuritySettings {
        token_peppers: keyring("IAM_TOKEN_PEPPER")?,
        blind_index_keys: keyring("IAM_BLIND_INDEX")?,
        encryption_keys: keyring("IAM_ENCRYPTION")?,
        cookie_key: validated_key("IAM_COOKIE_KEY", 32)?,
        jwt_ed25519_private_key: validated_key("IAM_JWT_ED25519_PRIVATE_KEY", 32)?,
        jwt_key_id: string_in_range("IAM_JWT_KEY_ID", required("IAM_JWT_KEY_ID")?, 8, 128)?,
        access_token_ttl: duration_secs_in_range("IAM_ACCESS_TOKEN_TTL_SECONDS", 900, 60, 900)?,
        refresh_family_ttl: duration_secs_in_range(
            "IAM_REFRESH_FAMILY_TTL_SECONDS",
            31_536_000,
            3_600,
            31_536_000,
        )?,
        authorization_code_ttl: duration_secs_in_range(
            "IAM_AUTHORIZATION_CODE_TTL_SECONDS",
            120,
            30,
            120,
        )?,
        otp_ttl: duration_secs_in_range("IAM_OTP_TTL_SECONDS", 600, 60, 600)?,
        otp_max_attempts: u16_in_range("IAM_OTP_MAX_ATTEMPTS", 5, 1, 5)?,
    };
    validate_security_settings(environment, &settings)?;
    Ok(settings)
}

fn provider_settings() -> Result<ProviderSettings, SettingsError> {
    Ok(ProviderSettings {
        postmark_server_token: optional_secret_in_range("IAM_POSTMARK_SERVER_TOKEN", 1, 4_096)?,
        postmark_from_email: string_in_range(
            "IAM_POSTMARK_FROM_EMAIL",
            value_or("IAM_POSTMARK_FROM_EMAIL", "auth@teamofsilicons.com"),
            3,
            254,
        )?,
        twilio_account_sid: optional_secret_in_range("IAM_TWILIO_ACCOUNT_SID", 1, 256)?,
        twilio_auth_token: optional_secret_in_range("IAM_TWILIO_AUTH_TOKEN", 1, 4_096)?,
        twilio_messaging_service_sid: optional_secret_in_range(
            "IAM_TWILIO_MESSAGING_SERVICE_SID",
            1,
            256,
        )?,
        workos_api_key: optional_secret_in_range("IAM_WORKOS_API_KEY", 1, 4_096)?,
        workos_client_id: optional_string_in_range("IAM_WORKOS_CLIENT_ID", 1, 256)?,
        workos_webhook_secret: optional_secret_in_range("IAM_WORKOS_WEBHOOK_SECRET", 1, 4_096)?,
        hook_base_url: parse_or(
            "IAM_HOOK_BASE_URL",
            "https://hook.teamofsilicons.com/api/v1",
        )?,
        hook_service_token: optional_secret_in_range("IAM_HOOK_SERVICE_TOKEN", 1, 4_096)?,
        iris_base_url: parse_or("IAM_IRIS_BASE_URL", "https://iris.teamofsilicons.com")?,
        allow_local_providers: parse_or("IAM_ALLOW_LOCAL_PROVIDERS", "false")?,
        expose_local_otps: parse_or("IAM_EXPOSE_LOCAL_OTPS", "false")?,
    })
}

fn worker_provider_settings() -> Result<WorkerProviderSettings, SettingsError> {
    Ok(WorkerProviderSettings {
        postmark_server_token: optional_secret_in_range("IAM_POSTMARK_SERVER_TOKEN", 1, 4_096)?,
        postmark_from_email: string_in_range(
            "IAM_POSTMARK_FROM_EMAIL",
            value_or("IAM_POSTMARK_FROM_EMAIL", "auth@teamofsilicons.com"),
            3,
            254,
        )?,
        twilio_account_sid: optional_secret_in_range("IAM_TWILIO_ACCOUNT_SID", 1, 256)?,
        twilio_auth_token: optional_secret_in_range("IAM_TWILIO_AUTH_TOKEN", 1, 4_096)?,
        twilio_messaging_service_sid: optional_secret_in_range(
            "IAM_TWILIO_MESSAGING_SERVICE_SID",
            1,
            256,
        )?,
        hook_base_url: parse_or(
            "IAM_HOOK_BASE_URL",
            "https://hook.teamofsilicons.com/api/v1",
        )?,
        hook_service_token: optional_secret_in_range("IAM_HOOK_SERVICE_TOKEN", 1, 4_096)?,
        iris_base_url: parse_or("IAM_IRIS_BASE_URL", "https://iris.teamofsilicons.com")?,
        allow_local_providers: parse_or("IAM_ALLOW_LOCAL_PROVIDERS", "false")?,
    })
}

fn worker_settings() -> Result<WorkerSettings, SettingsError> {
    let settings = WorkerSettings {
        batch_size: nonzero_usize_in_range("IAM_WORKER_BATCH_SIZE", 100, 1_000)?,
        delivery_concurrency: nonzero_usize_in_range("IAM_WORKER_DELIVERY_CONCURRENCY", 16, 256)?,
        poll_interval: duration_millis_in_range("IAM_WORKER_POLL_INTERVAL_MS", 500, 50, 60_000)?,
        lease_duration: duration_secs_in_range("IAM_WORKER_LEASE_SECONDS", 60, 1, 3_600)?,
        max_attempts: u16_in_range("IAM_WORKER_MAX_ATTEMPTS", 20, 1, 100)?,
        max_retry_delay: duration_secs_in_range(
            "IAM_WORKER_MAX_RETRY_DELAY_SECONDS",
            300,
            1,
            86_400,
        )?,
        retention: retention_settings()?,
    };
    validate_worker_lease_policy(settings.lease_duration, settings.poll_interval)?;
    Ok(settings)
}

fn validate_worker_lease_policy(
    lease_duration: Duration,
    poll_interval: Duration,
) -> Result<(), SettingsError> {
    if lease_duration < Duration::from_secs(MINIMUM_WORKER_LEASE_SECONDS) {
        return Err(invalid(
            "IAM_WORKER_LEASE_SECONDS",
            format!(
                "must be at least {MINIMUM_WORKER_LEASE_SECONDS} seconds to exceed the longest provider request deadline"
            ),
        ));
    }
    if lease_duration <= poll_interval {
        return Err(invalid(
            "IAM_WORKER_LEASE_SECONDS",
            "must be longer than IAM_WORKER_POLL_INTERVAL_MS",
        ));
    }
    Ok(())
}

fn validate_worker_database_lease_policy(
    lease_duration: Duration,
    database_acquire_timeout: Duration,
    database_statement_timeout: Duration,
) -> Result<(), SettingsError> {
    let required_duration = database_acquire_timeout
        .saturating_add(database_statement_timeout)
        .saturating_add(Duration::from_secs(WORKER_PROVIDER_DEADLINE_SECONDS))
        .saturating_add(Duration::from_secs(WORKER_LEASE_COMPLETION_MARGIN_SECONDS));
    if lease_duration <= required_duration {
        return Err(invalid(
            "IAM_WORKER_LEASE_SECONDS",
            format!(
                "must exceed {} seconds: database acquisition, one statement, provider delivery, and completion margin",
                required_duration.as_secs()
            ),
        ));
    }
    Ok(())
}

fn retention_settings() -> Result<RetentionSettings, SettingsError> {
    let settings = RetentionSettings {
        sweep_interval: duration_secs_in_range(
            "IAM_RETENTION_SWEEP_INTERVAL_SECONDS",
            30,
            10,
            3_600,
        )?,
        batch_size: nonzero_usize_in_range(
            "IAM_RETENTION_BATCH_SIZE",
            1_000,
            MAXIMUM_RETENTION_BATCH_SIZE,
        )?,
        login_history_days: u16_in_range(
            "IAM_RETENTION_LOGIN_HISTORY_DAYS",
            365,
            1,
            MAXIMUM_RETENTION_DAYS,
        )?,
        ephemeral_security_days: u16_in_range(
            "IAM_RETENTION_EPHEMERAL_SECURITY_DAYS",
            30,
            1,
            MAXIMUM_RETENTION_DAYS,
        )?,
        token_metadata_days: u16_in_range(
            "IAM_RETENTION_TOKEN_METADATA_DAYS",
            90,
            1,
            MAXIMUM_RETENTION_DAYS,
        )?,
        compromised_refresh_days: u16_in_range(
            "IAM_RETENTION_COMPROMISED_REFRESH_DAYS",
            365,
            1,
            MAXIMUM_RETENTION_DAYS,
        )?,
        webhook_attempt_days: u16_in_range(
            "IAM_RETENTION_WEBHOOK_ATTEMPT_DAYS",
            45,
            1,
            MAXIMUM_RETENTION_DAYS,
        )?,
        audit_event_days: u16_in_range(
            "IAM_RETENTION_AUDIT_EVENT_DAYS",
            2_555,
            1,
            MAXIMUM_RETENTION_DAYS,
        )?,
    };
    validate_retention_policy(
        settings.token_metadata_days,
        settings.compromised_refresh_days,
    )?;
    Ok(settings)
}

fn validate_retention_policy(
    token_metadata_days: u16,
    compromised_refresh_days: u16,
) -> Result<(), SettingsError> {
    if compromised_refresh_days < token_metadata_days {
        return Err(invalid(
            "IAM_RETENTION_COMPROMISED_REFRESH_DAYS",
            "must be greater than or equal to IAM_RETENTION_TOKEN_METADATA_DAYS",
        ));
    }
    Ok(())
}

impl MigrationSettings {
    /// Loads the isolated migration-process settings.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the migrator URL or a pool setting is
    /// missing, malformed, or insecure for production.
    pub fn from_env() -> Result<Self, SettingsError> {
        let environment = parse_or("IAM_ENVIRONMENT", "development")?;
        let database = DatabaseSettings {
            url: SecretString::from(required("IAM_MIGRATOR_DATABASE_URL")?),
            max_connections: nonzero_u32_in_range("IAM_MIGRATOR_DATABASE_MAX_CONNECTIONS", 2, 16)?,
            min_connections: 0,
            acquire_timeout: duration_secs_in_range(
                "IAM_MIGRATOR_DATABASE_ACQUIRE_TIMEOUT_SECONDS",
                10,
                1,
                300,
            )?,
            statement_timeout: duration_secs_in_range(
                "IAM_MIGRATOR_DATABASE_STATEMENT_TIMEOUT_SECONDS",
                120,
                1,
                86_400,
            )?,
        };
        validate_database_transport(environment, &database, "IAM_MIGRATOR_DATABASE_URL")?;
        let log_filter = string_in_range(
            "IAM_LOG_FILTER",
            value_or("IAM_LOG_FILTER", "silicon_iam=info"),
            1,
            2_048,
        )?;

        Ok(Self {
            environment,
            database,
            log_filter,
        })
    }
}

impl KeyOperatorSettings {
    /// Loads the isolated key-operator process settings.
    ///
    /// The pool is intentionally fixed to one connection and a short statement
    /// deadline because this process performs exactly one transition.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the dedicated operator URL is missing,
    /// malformed, or insecure for production.
    pub fn from_env() -> Result<Self, SettingsError> {
        let environment = parse_or("IAM_ENVIRONMENT", "development")?;
        let database = DatabaseSettings {
            url: SecretString::from(required("IAM_KEY_OPERATOR_DATABASE_URL")?),
            max_connections: NonZeroU32::MIN,
            min_connections: 0,
            acquire_timeout: Duration::from_secs(10),
            statement_timeout: Duration::from_secs(30),
        };
        validate_database_transport(environment, &database, "IAM_KEY_OPERATOR_DATABASE_URL")?;
        let log_filter = string_in_range(
            "IAM_LOG_FILTER",
            value_or("IAM_LOG_FILTER", "silicon_iam=info"),
            1,
            2_048,
        )?;

        Ok(Self {
            environment,
            database,
            log_filter,
        })
    }
}

impl FromStr for RuntimeEnvironment {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            "production" | "prod" => Ok(Self::Production),
            _ => Err("must be development, test, or production".to_owned()),
        }
    }
}

fn validate_environment_safety(
    environment: RuntimeEnvironment,
    server: &ServerSettings,
    database: &DatabaseSettings,
    redis: Option<&RedisSettings>,
    providers: &ProviderSettings,
) -> Result<(), SettingsError> {
    validate_http_base_url(
        "IAM_PUBLIC_BASE_URL",
        &server.public_base_url,
        environment,
        &["/"],
    )?;
    validate_http_base_url(
        "IAM_AUTH_BASE_URL",
        &server.auth_base_url,
        environment,
        &["/"],
    )?;
    validate_database_transport(environment, database, "IAM_DATABASE_URL")?;
    if let Some(redis) = redis {
        validate_redis_url(environment, redis)?;
    }

    validate_provider_settings(environment, providers)?;

    if environment == RuntimeEnvironment::Production {
        let auth_origin = server.auth_base_url.origin().ascii_serialization();
        let includes_auth_origin = server
            .cors_allowed_origins
            .iter()
            .any(|origin| origin.origin().ascii_serialization() == auth_origin);
        if !includes_auth_origin {
            return Err(invalid(
                "IAM_CORS_ALLOWED_ORIGINS",
                "must include IAM_AUTH_BASE_URL in production",
            ));
        }
    }

    Ok(())
}

fn validate_database_transport(
    environment: RuntimeEnvironment,
    database: &DatabaseSettings,
    variable_name: &'static str,
) -> Result<(), SettingsError> {
    let database_url = Url::parse(database.url.expose_secret())
        .map_err(|_| invalid(variable_name, "must be a valid PostgreSQL URL"))?;
    if !matches!(database_url.scheme(), "postgres" | "postgresql") {
        return Err(invalid(
            variable_name,
            "scheme must be postgres:// or postgresql://",
        ));
    }
    if database_url.fragment().is_some() {
        return Err(invalid(variable_name, "must not contain a fragment"));
    }
    if database_url.port() == Some(0) {
        return Err(invalid(variable_name, "port must be greater than zero"));
    }

    let database_name = database_url.path().strip_prefix('/').unwrap_or_default();
    if database_name.is_empty() || database_name.contains('/') {
        return Err(invalid(
            variable_name,
            "path must contain exactly one database name",
        ));
    }

    let ssl_modes = database_url
        .query_pairs()
        .filter_map(|(key, value)| (key == "sslmode").then_some(value.into_owned()))
        .collect::<Vec<_>>();
    if ssl_modes.len() > 1 {
        return Err(invalid(
            variable_name,
            "must contain at most one sslmode parameter",
        ));
    }

    if environment == RuntimeEnvironment::Production {
        if database_url.host_str().is_none() {
            return Err(invalid(
                variable_name,
                "must contain a hostname in production",
            ));
        }
        if ssl_modes.first().map(String::as_str) != Some("verify-full") {
            return Err(invalid(
                variable_name,
                "must set sslmode=verify-full in production",
            ));
        }
    }

    Ok(())
}

fn validate_redis_url(
    environment: RuntimeEnvironment,
    redis: &RedisSettings,
) -> Result<(), SettingsError> {
    let redis_url = Url::parse(redis.url.expose_secret())
        .map_err(|_| invalid("IAM_REDIS_URL", "must be a valid Redis URL"))?;
    if !matches!(redis_url.scheme(), "redis" | "rediss") {
        return Err(invalid(
            "IAM_REDIS_URL",
            "scheme must be redis:// or rediss://",
        ));
    }
    if redis_url.host_str().is_none() {
        return Err(invalid("IAM_REDIS_URL", "must contain a hostname"));
    }
    if redis_url.port() == Some(0) {
        return Err(invalid("IAM_REDIS_URL", "port must be greater than zero"));
    }
    if redis_url.fragment().is_some() {
        return Err(invalid("IAM_REDIS_URL", "must not contain a fragment"));
    }
    if environment == RuntimeEnvironment::Production && redis_url.scheme() != "rediss" {
        return Err(invalid("IAM_REDIS_URL", "must use rediss:// in production"));
    }
    Ok(())
}

fn validate_provider_settings(
    environment: RuntimeEnvironment,
    providers: &ProviderSettings,
) -> Result<(), SettingsError> {
    validate_http_base_url(
        "IAM_HOOK_BASE_URL",
        &providers.hook_base_url,
        environment,
        &["/api/v1", "/api/v1/"],
    )?;
    validate_http_base_url(
        "IAM_IRIS_BASE_URL",
        &providers.iris_base_url,
        environment,
        &["/"],
    )?;
    validate_email("IAM_POSTMARK_FROM_EMAIL", &providers.postmark_from_email)?;

    let twilio = [
        (
            "IAM_TWILIO_ACCOUNT_SID",
            providers.twilio_account_sid.is_some(),
        ),
        (
            "IAM_TWILIO_AUTH_TOKEN",
            providers.twilio_auth_token.is_some(),
        ),
        (
            "IAM_TWILIO_MESSAGING_SERVICE_SID",
            providers.twilio_messaging_service_sid.is_some(),
        ),
    ];
    let workos = [
        ("IAM_WORKOS_API_KEY", providers.workos_api_key.is_some()),
        ("IAM_WORKOS_CLIENT_ID", providers.workos_client_id.is_some()),
        (
            "IAM_WORKOS_WEBHOOK_SECRET",
            providers.workos_webhook_secret.is_some(),
        ),
    ];
    validate_credential_group("IAM_TWILIO_ACCOUNT_SID", &twilio)?;
    validate_credential_group("IAM_WORKOS_API_KEY", &workos)?;

    if providers.expose_local_otps && !providers.allow_local_providers {
        return Err(invalid(
            "IAM_EXPOSE_LOCAL_OTPS",
            "requires IAM_ALLOW_LOCAL_PROVIDERS=true",
        ));
    }

    if environment == RuntimeEnvironment::Production {
        if providers.allow_local_providers {
            return Err(invalid(
                "IAM_ALLOW_LOCAL_PROVIDERS",
                "must be false in production",
            ));
        }
        if providers.expose_local_otps {
            return Err(invalid(
                "IAM_EXPOSE_LOCAL_OTPS",
                "must be false in production",
            ));
        }
        require_configured(
            "IAM_POSTMARK_SERVER_TOKEN",
            providers.postmark_server_token.is_some(),
        )?;
        require_credential_group(&twilio)?;
        require_credential_group(&workos)?;
        require_configured(
            "IAM_HOOK_SERVICE_TOKEN",
            providers.hook_service_token.is_some(),
        )?;
    }

    Ok(())
}

fn validate_worker_provider_settings(
    environment: RuntimeEnvironment,
    providers: &WorkerProviderSettings,
) -> Result<(), SettingsError> {
    validate_http_base_url(
        "IAM_HOOK_BASE_URL",
        &providers.hook_base_url,
        environment,
        &["/api/v1", "/api/v1/"],
    )?;
    validate_http_base_url(
        "IAM_IRIS_BASE_URL",
        &providers.iris_base_url,
        environment,
        &["/"],
    )?;
    validate_email("IAM_POSTMARK_FROM_EMAIL", &providers.postmark_from_email)?;

    let twilio = [
        (
            "IAM_TWILIO_ACCOUNT_SID",
            providers.twilio_account_sid.is_some(),
        ),
        (
            "IAM_TWILIO_AUTH_TOKEN",
            providers.twilio_auth_token.is_some(),
        ),
        (
            "IAM_TWILIO_MESSAGING_SERVICE_SID",
            providers.twilio_messaging_service_sid.is_some(),
        ),
    ];
    validate_credential_group("IAM_TWILIO_ACCOUNT_SID", &twilio)?;

    if environment == RuntimeEnvironment::Production {
        if providers.allow_local_providers {
            return Err(invalid(
                "IAM_ALLOW_LOCAL_PROVIDERS",
                "must be false in production",
            ));
        }
        require_configured(
            "IAM_POSTMARK_SERVER_TOKEN",
            providers.postmark_server_token.is_some(),
        )?;
        require_credential_group(&twilio)?;
        require_configured(
            "IAM_HOOK_SERVICE_TOKEN",
            providers.hook_service_token.is_some(),
        )?;
    }

    Ok(())
}

fn validate_credential_group(
    group_name: &'static str,
    fields: &[(&'static str, bool)],
) -> Result<(), SettingsError> {
    let configured = fields.iter().filter(|(_, is_set)| *is_set).count();
    if configured != 0 && configured != fields.len() {
        return Err(invalid(
            group_name,
            "credential group must be either fully configured or fully absent",
        ));
    }
    Ok(())
}

fn require_credential_group(fields: &[(&'static str, bool)]) -> Result<(), SettingsError> {
    for (name, is_set) in fields {
        require_configured(name, *is_set)?;
    }
    Ok(())
}

fn require_configured(name: &'static str, is_set: bool) -> Result<(), SettingsError> {
    if is_set {
        Ok(())
    } else {
        Err(SettingsError::Missing(name))
    }
}

fn validate_http_base_url(
    name: &'static str,
    url: &Url,
    environment: RuntimeEnvironment,
    allowed_paths: &[&str],
) -> Result<(), SettingsError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid(name, "scheme must be http:// or https://"));
    }
    if environment == RuntimeEnvironment::Production && url.scheme() != "https" {
        return Err(invalid(name, "must use https:// in production"));
    }
    if url.host_str().is_none() {
        return Err(invalid(name, "must contain a hostname"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(name, "must not contain embedded credentials"));
    }
    if url.port() == Some(0) {
        return Err(invalid(name, "port must be greater than zero"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(name, "must not contain a query string or fragment"));
    }
    if !allowed_paths.contains(&url.path()) {
        return Err(invalid(name, "contains an unsupported base path"));
    }
    Ok(())
}

fn validate_email(name: &'static str, email: &str) -> Result<(), SettingsError> {
    if email.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(invalid(name, "must not contain whitespace"));
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err(invalid(name, "must be a valid email address"));
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
        || email.matches('@').count() != 1
    {
        return Err(invalid(name, "must be a valid email address"));
    }
    Ok(())
}

fn cors_origins(
    name: &'static str,
    auth_base_url: &Url,
    environment: RuntimeEnvironment,
) -> Result<Vec<Url>, SettingsError> {
    let default = auth_base_url.origin().ascii_serialization();
    let raw = value_or(name, &default);
    parse_cors_origins(name, &raw, environment)
}

fn parse_cors_origins(
    name: &'static str,
    raw: &str,
    environment: RuntimeEnvironment,
) -> Result<Vec<Url>, SettingsError> {
    let mut origins = Vec::new();
    for value in raw.split(',').map(str::trim) {
        if value.is_empty() {
            return Err(invalid(name, "must not contain an empty origin"));
        }
        if origins.len() == MAX_CORS_ORIGINS {
            return Err(invalid(
                name,
                format!("must contain at most {MAX_CORS_ORIGINS} origins"),
            ));
        }
        let origin = Url::parse(value).map_err(|_| invalid(name, "contains an invalid URL"))?;
        validate_http_base_url(name, &origin, environment, &["/"])?;
        let serialized = origin.origin().ascii_serialization();
        if origins
            .iter()
            .any(|existing: &Url| existing.origin().ascii_serialization() == serialized)
        {
            return Err(invalid(name, "must not contain duplicate origins"));
        }
        origins.push(origin);
    }
    if origins.is_empty() {
        return Err(invalid(name, "must contain at least one origin"));
    }
    Ok(origins)
}

fn validate_security_settings(
    environment: RuntimeEnvironment,
    security: &SecuritySettings,
) -> Result<(), SettingsError> {
    if !security
        .jwt_key_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid(
            "IAM_JWT_KEY_ID",
            "may contain only ASCII letters, digits, hyphens, and underscores",
        ));
    }
    if security.refresh_family_ttl <= security.access_token_ttl {
        return Err(invalid(
            "IAM_REFRESH_FAMILY_TTL_SECONDS",
            "must be longer than IAM_ACCESS_TOKEN_TTL_SECONDS",
        ));
    }
    if environment == RuntimeEnvironment::Production {
        validate_production_key_separation(security)?;
    }
    Ok(())
}

fn validate_production_key_separation(security: &SecuritySettings) -> Result<(), SettingsError> {
    let mut seen: Vec<(&'static str, Zeroizing<Vec<u8>>)> = Vec::new();
    for (name, keyring) in [
        ("IAM_TOKEN_PEPPER_KEYRING", &security.token_peppers),
        ("IAM_BLIND_INDEX_KEYRING", &security.blind_index_keys),
        ("IAM_ENCRYPTION_KEYRING", &security.encryption_keys),
    ] {
        for key in keyring.keys.values() {
            add_distinct_key(&mut seen, name, key)?;
        }
    }
    add_distinct_key(&mut seen, "IAM_COOKIE_KEY", &security.cookie_key)?;
    add_distinct_key(
        &mut seen,
        "IAM_JWT_ED25519_PRIVATE_KEY",
        &security.jwt_ed25519_private_key,
    )?;
    Ok(())
}

fn add_distinct_key(
    seen: &mut Vec<(&'static str, Zeroizing<Vec<u8>>)>,
    name: &'static str,
    key: &SecretString,
) -> Result<(), SettingsError> {
    let decoded = decode_encoded_key(name, key, 32)?;
    if seen
        .iter()
        .any(|(_, existing)| existing.as_slice() == decoded.as_slice())
    {
        return Err(invalid(
            name,
            "must not reuse key material from another purpose or version in production",
        ));
    }
    seen.push((name, decoded));
    Ok(())
}

fn validated_key(name: &'static str, expected_len: usize) -> Result<SecretString, SettingsError> {
    let value = SecretString::from(required(name)?);
    let _validated = decode_encoded_key(name, &value, expected_len)?;
    Ok(value)
}

fn keyring(prefix: &'static str) -> Result<KeyringSettings, SettingsError> {
    let current_name = match prefix {
        "IAM_TOKEN_PEPPER" => "IAM_TOKEN_PEPPER_CURRENT_VERSION",
        "IAM_BLIND_INDEX" => "IAM_BLIND_INDEX_CURRENT_VERSION",
        "IAM_ENCRYPTION" => "IAM_ENCRYPTION_CURRENT_VERSION",
        _ => return Err(invalid(prefix, "unsupported keyring prefix")),
    };
    let keys_name = match prefix {
        "IAM_TOKEN_PEPPER" => "IAM_TOKEN_PEPPER_KEYRING",
        "IAM_BLIND_INDEX" => "IAM_BLIND_INDEX_KEYRING",
        "IAM_ENCRYPTION" => "IAM_ENCRYPTION_KEYRING",
        _ => return Err(invalid(prefix, "unsupported keyring prefix")),
    };
    let current_version = parse_required(current_name)?;
    if current_version <= 0 {
        return Err(invalid(current_name, "must be a positive small integer"));
    }

    let raw = Zeroizing::new(string_in_range(
        keys_name,
        required(keys_name)?,
        2,
        MAX_KEYRING_JSON_BYTES,
    )?);
    let UniqueStringMap(parsed) = serde_json::from_str(raw.as_str())
        .map_err(|_| invalid(keys_name, "must be a JSON object with unique key versions"))?;
    if parsed.is_empty() {
        return Err(invalid(keys_name, "must contain at least one key"));
    }
    let mut keys = BTreeMap::new();
    let mut decoded_keys: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    for (version, key) in parsed {
        let version = version
            .parse::<i16>()
            .map_err(|_| invalid(keys_name, "key versions must be positive small integers"))?;
        if version <= 0 || keys.contains_key(&version) {
            return Err(invalid(
                keys_name,
                "key versions must be unique positive small integers",
            ));
        }
        let decoded = decode_encoded_key(keys_name, &key, 32)?;
        if decoded_keys
            .iter()
            .any(|existing| existing.as_slice() == decoded.as_slice())
        {
            return Err(invalid(
                keys_name,
                "must not reuse key material across versions",
            ));
        }
        decoded_keys.push(decoded);
        keys.insert(version, key);
    }
    if !keys.contains_key(&current_version) {
        return Err(invalid(
            current_name,
            "current version must exist in the configured keyring",
        ));
    }

    Ok(KeyringSettings {
        current_version,
        keys,
    })
}

fn decode_encoded_key(
    name: &'static str,
    value: &SecretString,
    expected_len: usize,
) -> Result<Zeroizing<Vec<u8>>, SettingsError> {
    let expected_encoded_len = expected_len.saturating_mul(4).div_ceil(3);
    if value.expose_secret().len() != expected_encoded_len {
        return Err(invalid(
            name,
            format!("every key must be exactly {expected_encoded_len} base64url characters"),
        ));
    }
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value.expose_secret())
            .map_err(|_| invalid(name, "keys must be unpadded base64url"))?,
    );
    if bytes.len() != expected_len {
        return Err(invalid(
            name,
            format!("every key must decode to exactly {expected_len} bytes"),
        ));
    }
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()));
    if canonical.as_str() != value.expose_secret() {
        return Err(invalid(name, "keys must use canonical unpadded base64url"));
    }
    Ok(bytes)
}

fn required(name: &'static str) -> Result<String, SettingsError> {
    optional(name).ok_or(SettingsError::Missing(name))
}

fn optional(name: &'static str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn optional_secret_in_range(
    name: &'static str,
    min_len: usize,
    max_len: usize,
) -> Result<Option<SecretString>, SettingsError> {
    optional(name)
        .map(|value| string_in_range(name, value, min_len, max_len).map(SecretString::from))
        .transpose()
}

fn optional_string_in_range(
    name: &'static str,
    min_len: usize,
    max_len: usize,
) -> Result<Option<String>, SettingsError> {
    optional(name)
        .map(|value| string_in_range(name, value, min_len, max_len))
        .transpose()
}

fn string_in_range(
    name: &'static str,
    value: String,
    min_len: usize,
    max_len: usize,
) -> Result<String, SettingsError> {
    if !(min_len..=max_len).contains(&value.len()) {
        return Err(invalid(
            name,
            format!("length must be between {min_len} and {max_len} bytes"),
        ));
    }
    Ok(value)
}

fn value_or(name: &'static str, default: &str) -> String {
    optional(name).unwrap_or_else(|| default.to_owned())
}

fn parse_required<T>(name: &'static str) -> Result<T, SettingsError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let value = required(name)?;
    parse(name, &value)
}

fn parse_or<T>(name: &'static str, default: &str) -> Result<T, SettingsError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let value = value_or(name, default);
    parse(name, &value)
}

fn parse<T>(name: &'static str, value: &str) -> Result<T, SettingsError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|error| invalid(name, error.to_string()))
}

fn usize_in_range(
    name: &'static str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, SettingsError> {
    let value = parse_or(name, &default.to_string())?;
    ensure_range(name, value, min, max)
}

fn u32_in_range(
    name: &'static str,
    default: u32,
    min: u32,
    max: u32,
) -> Result<u32, SettingsError> {
    let value = parse_or(name, &default.to_string())?;
    ensure_range(name, value, min, max)
}

fn u16_in_range(
    name: &'static str,
    default: u16,
    min: u16,
    max: u16,
) -> Result<u16, SettingsError> {
    let value = parse_or(name, &default.to_string())?;
    ensure_range(name, value, min, max)
}

fn nonzero_u32_in_range(
    name: &'static str,
    default: u32,
    max: u32,
) -> Result<NonZeroU32, SettingsError> {
    let value = u32_in_range(name, default, 1, max)?;
    NonZeroU32::new(value).ok_or_else(|| invalid(name, "must be greater than zero"))
}

fn nonzero_usize_in_range(
    name: &'static str,
    default: usize,
    max: usize,
) -> Result<NonZeroUsize, SettingsError> {
    let value = usize_in_range(name, default, 1, max)?;
    NonZeroUsize::new(value).ok_or_else(|| invalid(name, "must be greater than zero"))
}

fn duration_secs_in_range(
    name: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<Duration, SettingsError> {
    let seconds = parse_or(name, &default.to_string())?;
    ensure_range(name, seconds, min, max).map(Duration::from_secs)
}

fn duration_millis_in_range(
    name: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<Duration, SettingsError> {
    let milliseconds = parse_or(name, &default.to_string())?;
    ensure_range(name, milliseconds, min, max).map(Duration::from_millis)
}

fn ensure_range<T>(name: &'static str, value: T, min: T, max: T) -> Result<T, SettingsError>
where
    T: Copy + fmt::Display + PartialOrd,
{
    if value < min || value > max {
        return Err(invalid(
            name,
            format!("must be between {min} and {max}, inclusive"),
        ));
    }
    Ok(value)
}

fn invalid(name: &'static str, reason: impl Into<String>) -> SettingsError {
    SettingsError::Invalid {
        name,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap, num::NonZeroU32, path::Path, process::Command, time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use secrecy::SecretString;
    use url::Url;

    use super::{
        DatabaseSettings, RuntimeEnvironment, SettingsError, UniqueStringMap,
        WorkerProcessSettings, add_distinct_key, ensure_range, parse_cors_origins,
        validate_credential_group, validate_database_transport, validate_http_base_url,
        validate_retention_policy, validate_worker_database_lease_policy,
        validate_worker_lease_policy,
    };

    #[test]
    fn runtime_environment_is_case_insensitive() {
        assert_eq!(
            "PrOd".parse::<RuntimeEnvironment>(),
            Ok(RuntimeEnvironment::Production)
        );
    }

    #[test]
    fn bounded_values_reject_both_edges() {
        assert!(ensure_range("TEST", 0_u16, 1, 5).is_err());
        assert!(matches!(ensure_range("TEST", 5_u16, 1, 5), Ok(5)));
        assert!(ensure_range("TEST", 6_u16, 1, 5).is_err());
    }

    #[test]
    fn cors_origins_are_exact_and_unique() {
        let origins = parse_cors_origins(
            "IAM_CORS_ALLOWED_ORIGINS",
            "https://auth.example.com,https://console.example.com:8443",
            RuntimeEnvironment::Production,
        );
        assert!(matches!(origins, Ok(values) if values.len() == 2));
        assert!(
            parse_cors_origins(
                "IAM_CORS_ALLOWED_ORIGINS",
                "https://auth.example.com/path",
                RuntimeEnvironment::Production,
            )
            .is_err()
        );
        assert!(
            parse_cors_origins(
                "IAM_CORS_ALLOWED_ORIGINS",
                "https://auth.example.com,https://auth.example.com/",
                RuntimeEnvironment::Production,
            )
            .is_err()
        );
    }

    #[test]
    fn http_base_urls_reject_credentials_and_queries() {
        let Ok(with_credentials) = Url::parse("https://user@example.com/") else {
            panic!("test URL must parse");
        };
        let Ok(with_query) = Url::parse("https://example.com/?code=secret") else {
            panic!("test URL must parse");
        };
        assert!(
            validate_http_base_url(
                "TEST_URL",
                &with_credentials,
                RuntimeEnvironment::Production,
                &["/"],
            )
            .is_err()
        );
        assert!(
            validate_http_base_url(
                "TEST_URL",
                &with_query,
                RuntimeEnvironment::Production,
                &["/"],
            )
            .is_err()
        );
    }

    #[test]
    fn one_shot_database_errors_name_the_credential_variable() {
        let database = DatabaseSettings {
            url: SecretString::from("https://example.com/database"),
            max_connections: NonZeroU32::MIN,
            min_connections: 0,
            acquire_timeout: Duration::from_secs(1),
            statement_timeout: Duration::from_secs(1),
        };
        assert!(matches!(
            validate_database_transport(
                RuntimeEnvironment::Production,
                &database,
                "IAM_MIGRATOR_DATABASE_URL",
            ),
            Err(SettingsError::Invalid {
                name: "IAM_MIGRATOR_DATABASE_URL",
                ..
            })
        ));
        assert!(matches!(
            validate_database_transport(
                RuntimeEnvironment::Production,
                &database,
                "IAM_KEY_OPERATOR_DATABASE_URL",
            ),
            Err(SettingsError::Invalid {
                name: "IAM_KEY_OPERATOR_DATABASE_URL",
                ..
            })
        ));
    }

    #[test]
    fn provider_groups_are_all_or_none() {
        assert!(
            validate_credential_group(
                "GROUP",
                &[("FIRST", true), ("SECOND", false), ("THIRD", true)],
            )
            .is_err()
        );
        assert!(
            validate_credential_group(
                "GROUP",
                &[("FIRST", true), ("SECOND", true), ("THIRD", true)],
            )
            .is_ok()
        );
    }

    #[test]
    fn worker_lease_safely_exceeds_provider_deadlines_and_polling() {
        assert!(
            validate_worker_lease_policy(Duration::from_secs(19), Duration::from_millis(500))
                .is_err()
        );
        assert!(
            validate_worker_lease_policy(Duration::from_secs(20), Duration::from_secs(20)).is_err()
        );
        assert!(
            validate_worker_lease_policy(Duration::from_secs(20), Duration::from_millis(500))
                .is_ok()
        );
    }

    #[test]
    fn worker_lease_covers_database_and_delivery_deadlines() {
        assert!(
            validate_worker_database_lease_policy(
                Duration::from_secs(28),
                Duration::from_secs(3),
                Duration::from_secs(10),
            )
            .is_err()
        );
        assert!(
            validate_worker_database_lease_policy(
                Duration::from_secs(29),
                Duration::from_secs(3),
                Duration::from_secs(10),
            )
            .is_ok()
        );
    }

    #[test]
    fn worker_process_settings_child() {
        if std::env::var_os("SILICON_IAM_WORKER_SETTINGS_CHILD").is_none() {
            return;
        }
        if let Ok(expected_name) = std::env::var("SILICON_IAM_WORKER_SETTINGS_EXPECT_INVALID_NAME")
        {
            match WorkerProcessSettings::from_env() {
                Err(SettingsError::Invalid { name, .. }) if name == expected_name => {
                    println!("SILICON_IAM_WORKER_SETTINGS_CHILD_OK");
                    return;
                }
                result => {
                    panic!("expected a redacted {expected_name} validation error: {result:?}")
                }
            }
        }

        let Ok(settings) = WorkerProcessSettings::from_env() else {
            panic!("minimal worker settings must load without authority secrets");
        };
        assert_eq!(settings.encryption_keys.current_version, 1);
        assert!(settings.providers.allow_local_providers);
        assert_eq!(settings.worker.delivery_concurrency.get(), 16);
        let retention = &settings.worker.retention;
        assert_eq!(retention.sweep_interval, Duration::from_secs(30));
        assert_eq!(retention.batch_size.get(), 1_000);
        assert_eq!(retention.login_history_days, 365);
        assert_eq!(retention.ephemeral_security_days, 30);
        assert_eq!(retention.token_metadata_days, 90);
        assert_eq!(retention.compromised_refresh_days, 365);
        assert_eq!(retention.webhook_attempt_days, 45);
        assert_eq!(retention.audit_event_days, 2_555);
        println!("SILICON_IAM_WORKER_SETTINGS_CHILD_OK");
    }

    #[test]
    fn worker_process_settings_load_from_minimal_allowlist() -> anyhow::Result<()> {
        let mut command = worker_settings_child_command()?;
        assert_worker_settings_child_succeeds(&mut command)
    }

    #[test]
    fn worker_process_settings_ignore_forbidden_secrets() -> anyhow::Result<()> {
        let mut command = worker_settings_child_command()?;
        let output = command
            .env("IAM_REDIS_URL", "not-a-redis-url")
            .env("IAM_TOKEN_PEPPER_CURRENT_VERSION", "not-a-version")
            .env("IAM_TOKEN_PEPPER_KEYRING", "not-json")
            .env("IAM_BLIND_INDEX_CURRENT_VERSION", "not-a-version")
            .env("IAM_BLIND_INDEX_KEYRING", "not-json")
            .env("IAM_COOKIE_KEY", "not-a-key")
            .env("IAM_JWT_ED25519_PRIVATE_KEY", "not-a-key")
            .env("IAM_JWT_KEY_ID", "bad")
            .env("IAM_WORKOS_API_KEY", "partial-workos-credentials")
            .env("IAM_EXPOSE_LOCAL_OTPS", "not-a-boolean")
            .env("IAM_PUBLIC_BASE_URL", "not-a-url")
            .env("IAM_ACCESS_TOKEN_TTL_SECONDS", "not-a-duration")
            .output()?;
        assert_worker_settings_child_output(&output)
    }

    #[test]
    fn worker_delivery_concurrency_is_bounded() -> anyhow::Result<()> {
        let mut command = worker_settings_child_command()?;
        command.env("IAM_WORKER_DELIVERY_CONCURRENCY", "257").env(
            "SILICON_IAM_WORKER_SETTINGS_EXPECT_INVALID_NAME",
            "IAM_WORKER_DELIVERY_CONCURRENCY",
        );
        assert_worker_settings_child_succeeds(&mut command)
    }

    #[test]
    fn retention_batch_size_is_bounded() -> anyhow::Result<()> {
        let mut command = worker_settings_child_command()?;
        command.env("IAM_RETENTION_BATCH_SIZE", "1001").env(
            "SILICON_IAM_WORKER_SETTINGS_EXPECT_INVALID_NAME",
            "IAM_RETENTION_BATCH_SIZE",
        );
        assert_worker_settings_child_succeeds(&mut command)
    }

    fn worker_settings_child_command() -> anyhow::Result<Command> {
        let executable = std::env::current_exe()?;
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "config::tests::worker_process_settings_child",
                "--nocapture",
            ])
            .env_clear()
            .env("SILICON_IAM_WORKER_SETTINGS_CHILD", "1")
            .env("IAM_ENVIRONMENT", "test")
            .env(
                "IAM_DATABASE_URL",
                "postgres://worker:worker-password@localhost/silicon_iam",
            )
            .env("IAM_AUTH_BASE_URL", "http://localhost:3000")
            .env("IAM_ENCRYPTION_CURRENT_VERSION", "1")
            .env(
                "IAM_ENCRYPTION_KEYRING",
                r#"{"1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM"}"#,
            )
            .env("IAM_ALLOW_LOCAL_PROVIDERS", "true")
            .env("IAM_WORKER_DELIVERY_CONCURRENCY", "16");
        Ok(command)
    }

    fn assert_worker_settings_child_succeeds(command: &mut Command) -> anyhow::Result<()> {
        let output = command.output()?;
        assert_worker_settings_child_output(&output)
    }

    fn assert_worker_settings_child_output(output: &std::process::Output) -> anyhow::Result<()> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() || !stdout.contains("SILICON_IAM_WORKER_SETTINGS_CHILD_OK") {
            anyhow::bail!(
                "isolated worker settings child failed: {}{}",
                stdout,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    #[test]
    fn compromised_refresh_history_cannot_be_shorter_than_other_token_history() {
        assert!(validate_retention_policy(90, 365).is_ok());
        assert!(matches!(
            validate_retention_policy(365, 90),
            Err(SettingsError::Invalid {
                name: "IAM_RETENTION_COMPROMISED_REFRESH_DAYS",
                ..
            })
        ));
    }

    #[test]
    fn keyring_json_rejects_duplicate_versions() {
        let parsed = serde_json::from_str::<UniqueStringMap>(r#"{"1":"first","1":"second"}"#);
        assert!(parsed.is_err());
    }

    #[test]
    fn example_keyrings_remain_valid_json_after_dotenv_parsing() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env.example");
        let Ok(entries) = dotenvy::from_path_iter(path) else {
            panic!(".env.example must be readable");
        };
        let Ok(values) = entries.collect::<Result<BTreeMap<_, _>, _>>() else {
            panic!(".env.example must use valid dotenv syntax");
        };

        for name in [
            "IAM_TOKEN_PEPPER_KEYRING",
            "IAM_BLIND_INDEX_KEYRING",
            "IAM_ENCRYPTION_KEYRING",
        ] {
            let Some(raw) = values.get(name) else {
                panic!(".env.example must contain {name}");
            };
            assert!(serde_json::from_str::<UniqueStringMap>(raw).is_ok());
        }
    }

    #[test]
    fn production_key_separation_rejects_reuse() {
        let key = SecretString::from(URL_SAFE_NO_PAD.encode([7_u8; 32]));
        let mut seen = Vec::new();
        assert!(add_distinct_key(&mut seen, "FIRST_KEY", &key).is_ok());
        assert!(add_distinct_key(&mut seen, "SECOND_KEY", &key).is_err());
    }
}
