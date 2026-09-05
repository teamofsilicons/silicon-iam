//! Opportunistic maintenance after an `iam` command has finished.

use time::{Duration, OffsetDateTime};

use silicon_iam_client::update::{Release, Version, check, install_binary};

use crate::{
    cli::{Command, ConfigCommand, SystemCommand},
    error::Result,
    store::{self, UpdateState},
};

pub const CLI_CRATE: &str = "silicon-iam-cli";
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
const CHECK_INTERVAL: Duration = Duration::hours(1);

/// Result of checking or applying a CLI release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Maintenance is disabled, not due, or already running elsewhere.
    Skipped,
    /// This binary is already the newest stable release.
    Current {
        /// Current installed version.
        version: Version,
    },
    /// Cargo replaced the installed binary for the next invocation.
    Updated {
        /// Version that completed the command.
        from: Version,
        /// Version installed for the next command.
        to: Version,
    },
}

/// Whether normal command completion may trigger automatic maintenance.
pub fn follows(command: &Command) -> bool {
    !matches!(
        command,
        Command::Docs { .. } | Command::Commands | Command::System(SystemCommand::Update)
    ) && !matches!(
        command,
        Command::Config(ConfigCommand::Set { key, .. } | ConfigCommand::Unset { key })
            if key == "auto-update"
    )
}

/// Checks on use, at most hourly, only after the command result is reported.
///
/// No background task or daemon is left running. Failure remains a warning:
/// it must not replace the completed command's result or exit code.
pub async fn automatic() -> Result<Outcome> {
    let config = store::load_config()?;
    if !environment_switch().unwrap_or(config.auto_update) {
        return Ok(Outcome::Skipped);
    }
    update_if_due(false).await
}

async fn update_if_due(force: bool) -> Result<Outcome> {
    let Some(_check_lock) = store::try_lock_updater_check()? else {
        return Ok(Outcome::Skipped);
    };
    let state = store::load_update_state()?;
    let now = OffsetDateTime::now_utc();
    if !force && !check_is_due(&state, now) {
        return Ok(Outcome::Skipped);
    }
    // Persist the attempt BEFORE the registry/Cargo work. Registry outages and
    // failed installations must not retry on every subsequent command. The
    // dedicated cross-process lock covers this reservation and installation.
    store::save_update_state(&UpdateState {
        checked_version: Some(CLI_VERSION.to_owned()),
        checked_at: Some(now),
    })?;
    let release = check(CLI_CRATE, CLI_VERSION).await?;
    apply_release(&release)
}

/// Checks and installs immediately for the explicit `iam system update` command.
pub async fn update_now() -> Result<Outcome> {
    update_if_due(true).await
}

fn apply_release(release: &Release) -> Result<Outcome> {
    if !release.update_available() {
        return Ok(Outcome::Current {
            version: release.current.clone(),
        });
    }
    install_binary(CLI_CRATE, &release.latest)?;
    Ok(Outcome::Updated {
        from: release.current.clone(),
        to: release.latest.clone(),
    })
}

fn check_is_due(state: &UpdateState, now: OffsetDateTime) -> bool {
    state
        .checked_at
        .is_none_or(|checked_at| checked_at > now || now - checked_at >= CHECK_INTERVAL)
}

fn environment_switch() -> Option<bool> {
    let value = std::env::var("SILICON_IAM_AUTO_UPDATE").ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Some(true),
        "off" | "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::store::UpdateState;

    use super::{CHECK_INTERVAL, CLI_VERSION, check_is_due};

    #[test]
    fn checks_immediately_then_at_most_hourly() {
        let now = OffsetDateTime::now_utc();
        assert!(check_is_due(&UpdateState::default(), now));
        let fresh = UpdateState {
            checked_version: Some(CLI_VERSION.to_owned()),
            checked_at: Some(now),
        };
        assert!(!check_is_due(&fresh, now));
        assert!(check_is_due(&fresh, now + CHECK_INTERVAL));
    }

    #[test]
    fn installing_a_new_version_does_not_reset_the_hourly_throttle() {
        let state = UpdateState {
            checked_version: Some("0.0.1".to_owned()),
            checked_at: Some(OffsetDateTime::now_utc()),
        };
        assert!(!check_is_due(&state, OffsetDateTime::now_utc()));
    }
}
