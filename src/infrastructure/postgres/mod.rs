//! PostgreSQL pool, migration, and readiness utilities.

use std::str::FromStr as _;

use secrecy::ExposeSecret as _;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use time::OffsetDateTime;

use crate::config::{DatabaseSettings, KeyringSettings, SecuritySettings};

pub mod authorization;
pub mod context;
pub mod events;
pub mod idempotency;
pub mod rate_limit;
pub mod step_up;
pub mod tokens;

#[cfg(test)]
mod key_rotation_tests;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Creates and verifies a bounded PostgreSQL pool.
///
/// # Errors
///
/// Returns an error when the URL is invalid, the connection cannot be
/// established, or required session settings cannot be applied.
pub async fn connect(
    settings: &DatabaseSettings,
    application_name: &str,
) -> anyhow::Result<PgPool> {
    let options = PgConnectOptions::from_str(settings.url.expose_secret())?
        .application_name(application_name);
    let statement_timeout_ms = i64::try_from(settings.statement_timeout.as_millis())?;

    let pool = PgPoolOptions::new()
        .max_connections(settings.max_connections.get())
        .min_connections(settings.min_connections)
        .acquire_timeout(settings.acquire_timeout)
        .idle_timeout(Some(std::time::Duration::from_secs(300)))
        .max_lifetime(Some(std::time::Duration::from_mins(30)))
        .test_before_acquire(true)
        .after_connect(move |connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('timezone', 'UTC', false)")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                    .bind(statement_timeout_ms.to_string())
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await?;

    Ok(pool)
}

/// Executes all embedded forward migrations.
///
/// # Errors
///
/// Returns an error if migration locking or a migration statement fails.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR.run(pool).await?;
    Ok(())
}

/// Reconciles non-secret database metadata for configured runtime keyrings.
///
/// The runtime role must receive an explicit `EXECUTE` grant on
/// `iam_private.reconcile_runtime_keyring(text, smallint, smallint[])`. Actual
/// key material never crosses this boundary or enters PostgreSQL. Existing
/// metadata is verification-only: startup can initialize an empty purpose and
/// stage future versions, but it cannot change the database-active version.
///
/// # Errors
///
/// Returns an error if a configured version is retired, unsupported, or cannot
/// be registered. Startup must fail closed in that case.
pub async fn register_runtime_key_versions(
    pool: &PgPool,
    settings: &SecuritySettings,
) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    register_keyring(&mut transaction, "token_hmac", &settings.token_peppers).await?;
    register_keyring(
        &mut transaction,
        "contact_lookup_hmac",
        &settings.blind_index_keys,
    )
    .await?;
    register_keyring(&mut transaction, "contact_aead", &settings.encryption_keys).await?;
    transaction.commit().await?;
    Ok(())
}

/// Reconciles only contact-AEAD metadata for a restricted worker process.
///
/// The worker deliberately has no token-pepper or contact blind-index keyring
/// and receives only a worker-attested, contact-AEAD-fixed database wrapper, so
/// its startup cannot register or reason about those purposes.
///
/// # Errors
///
/// Returns an error if the database-active encryption version differs from
/// the configured current version or a retained database version is missing
/// locally. Worker startup must fail closed in either case.
pub async fn register_runtime_encryption_key_versions(
    pool: &PgPool,
    encryption_keys: &KeyringSettings,
) -> anyhow::Result<()> {
    let local_versions = encryption_keys.keys.keys().copied().collect::<Vec<_>>();
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT iam_private.reconcile_worker_contact_aead_keyring($1, $2)")
        .bind(encryption_keys.current_version)
        .bind(local_versions)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// One supported application-managed runtime-key purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKeyPurpose {
    /// HMAC pepper for opaque bearer credentials.
    TokenHmac,
    /// HMAC key for contact blind indexes.
    ContactLookupHmac,
    /// AEAD key for encrypted contact and protected-field values.
    ContactAead,
}

impl RuntimeKeyPurpose {
    /// Returns the closed database purpose identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenHmac => "token_hmac",
            Self::ContactLookupHmac => "contact_lookup_hmac",
            Self::ContactAead => "contact_aead",
        }
    }
}

/// Metadata returned by a successful operator key activation.
#[derive(Debug, sqlx::FromRow)]
pub struct RuntimeKeyActivation {
    /// Append-only activation-history identifier.
    pub activation_id: i64,
    /// Version that was active before the transition.
    pub previous_version: i16,
    /// Version made active by the transition.
    pub active_version: i16,
    /// Database transaction timestamp of the transition.
    pub activated_at: OffsetDateTime,
}

/// Atomically activates one preloaded runtime-key version.
///
/// This is an operator-only compare-and-swap transition. Both Rust and the
/// fixed-search-path database function reject non-positive, same-version, and
/// downgrade requests. The database serializes it with startup reconciliation
/// and appends operator metadata in the same transaction.
///
/// # Errors
///
/// Returns an error if the transition is invalid, the expected active version
/// is stale, the target is not preloaded as decrypt-only, or the transaction
/// cannot commit.
pub async fn activate_runtime_key_version(
    pool: &PgPool,
    purpose: RuntimeKeyPurpose,
    expected_current_version: i16,
    new_version: i16,
) -> anyhow::Result<RuntimeKeyActivation> {
    anyhow::ensure!(
        expected_current_version > 0 && new_version > expected_current_version,
        "runtime key activation versions must be positive and strictly increasing"
    );

    let mut transaction = pool.begin().await?;
    let activation = sqlx::query_as::<_, RuntimeKeyActivation>(
        "SELECT * FROM iam_private.activate_runtime_key_version($1, $2, $3)",
    )
    .bind(purpose.as_str())
    .bind(expected_current_version)
    .bind(new_version)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(activation)
}

/// Confirms the database accepts a trivial query.
pub async fn ready(pool: &PgPool) -> bool {
    if sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(pool)
        .await
        .is_err()
    {
        return false;
    }
    schema_is_current(pool).await.unwrap_or(false)
}

async fn schema_is_current(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let applied = sqlx::query_as::<_, (i64, Vec<u8>, bool)>(
        "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await?;
    if applied.len() != MIGRATOR.iter().count() {
        return Ok(false);
    }
    Ok(applied
        .iter()
        .zip(MIGRATOR.iter())
        .all(|((version, checksum, success), migration)| {
            *success
                && *version == migration.version
                && checksum.as_slice() == migration.checksum.as_ref()
        }))
}

async fn register_keyring(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    purpose: &'static str,
    settings: &KeyringSettings,
) -> Result<(), sqlx::Error> {
    let local_versions = settings.keys.keys().copied().collect::<Vec<_>>();
    sqlx::query("SELECT iam_private.reconcile_runtime_keyring($1, $2, $3)")
        .bind(purpose)
        .bind(settings.current_version)
        .bind(local_versions)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}
