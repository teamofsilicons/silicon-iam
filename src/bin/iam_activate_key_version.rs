//! One-shot operator activation for a preloaded runtime-key version.

use clap::{Parser, ValueEnum};
use silicon_iam::{
    config::KeyOperatorSettings,
    infrastructure::postgres::{self, RuntimeKeyPurpose},
    telemetry,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OperatorKeyPurpose {
    TokenHmac,
    ContactLookupHmac,
    ContactAead,
}

impl From<OperatorKeyPurpose> for RuntimeKeyPurpose {
    fn from(value: OperatorKeyPurpose) -> Self {
        match value {
            OperatorKeyPurpose::TokenHmac => Self::TokenHmac,
            OperatorKeyPurpose::ContactLookupHmac => Self::ContactLookupHmac,
            OperatorKeyPurpose::ContactAead => Self::ContactAead,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "iam-activate-key-version",
    about = "Atomically activate one preloaded Silicon IAM runtime-key version"
)]
struct Arguments {
    /// Closed key purpose to activate.
    #[arg(long, value_enum)]
    purpose: OperatorKeyPurpose,
    /// Database-active version expected before the transition.
    #[arg(long)]
    expected_current_version: i16,
    /// Preloaded decrypt-only version to make active.
    #[arg(long)]
    new_version: i16,
}

impl Arguments {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.expected_current_version > 0,
            "expected current version must be positive"
        );
        anyhow::ensure!(
            self.new_version > self.expected_current_version,
            "new version must be strictly greater than expected current version"
        );
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let arguments = Arguments::parse();
    arguments.validate()?;
    let settings = KeyOperatorSettings::from_env()?;
    telemetry::init_process(settings.environment, &settings.log_filter)?;

    let purpose = RuntimeKeyPurpose::from(arguments.purpose);
    let pool = postgres::connect(&settings.database, "iam-activate-key-version").await?;
    let activation = postgres::activate_runtime_key_version(
        &pool,
        purpose,
        arguments.expected_current_version,
        arguments.new_version,
    )
    .await?;
    tracing::info!(
        purpose = purpose.as_str(),
        activation_id = activation.activation_id,
        previous_version = activation.previous_version,
        active_version = activation.active_version,
        activated_at = %activation.activated_at,
        "runtime key version activated"
    );
    pool.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::ensure;
    use clap::Parser as _;

    use super::Arguments;

    #[test]
    fn parser_accepts_only_closed_monotonic_transitions() -> anyhow::Result<()> {
        let valid = Arguments::try_parse_from([
            "iam-activate-key-version",
            "--purpose",
            "token-hmac",
            "--expected-current-version",
            "1",
            "--new-version",
            "2",
        ])?;
        valid.validate()?;

        let downgrade = Arguments::try_parse_from([
            "iam-activate-key-version",
            "--purpose",
            "contact-aead",
            "--expected-current-version",
            "2",
            "--new-version",
            "1",
        ])?;
        ensure!(downgrade.validate().is_err(), "downgrade was accepted");
        ensure!(
            Arguments::try_parse_from([
                "iam-activate-key-version",
                "--purpose",
                "unknown-purpose",
                "--expected-current-version",
                "1",
                "--new-version",
                "2",
            ])
            .is_err(),
            "unknown key purpose was accepted"
        );
        Ok(())
    }
}
