//! Automatic maintenance of the installed `iam` binary.

use time::{Duration, OffsetDateTime};

use silicon_iam_client::update::{Release, Version, check, install_binary};

use crate::{
    cli::{Command, ConfigCommand, SystemCommand},
    error::Result,
    store::{self, UpdateState},
};

pub const CLI_CRATE: &str = "silicon-iam-cli";
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
const CHECK_INTERVAL: Duration = Duration::days(1);

/// Result of checking or applying a CLI release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Automatic maintenance is disabled or not due yet.
    Skipped,
    /// This binary is already the newest stable release.
    Current {
        /// Current installed version.
        version: Version,
    },
    /// Cargo replaced the installed binary for the next invocation.
    Updated {
        /// Version executing this command.
        from: Version,
        /// Version installed for the next command.
        to: Version,
    },
}

/// Runs the daily default-on update before a normal command.
///
/// # Errors
///
/// Returns a non-fatal error when settings, crates.io, or Cargo cannot be used.
pub async fn automatic(command: &Command) -> Result<Outcome> {
    if command_controls_updater(command) {
        return Ok(Outcome::Skipped);
    }
    let config = store::load_config()?;
    if !environment_switch().unwrap_or(config.auto_update) {
        return Ok(Outcome::Skipped);
    }
    let state = store::load_update_state()?;
    if !check_is_due(&state, OffsetDateTime::now_utc()) {
        return Ok(Outcome::Skipped);
    }
    update_now().await
}

/// Checks immediately, even when automatic maintenance is disabled or cached.
///
/// # Errors
///
/// Returns an error when crates.io or Cargo cannot be used, or state cannot be
/// saved.
pub async fn update_now() -> Result<Outcome> {
    let release = check(CLI_CRATE, CLI_VERSION).await?;
    let outcome = apply_release(&release)?;
    let recorded_version = match &outcome {
        Outcome::Updated { to, .. } => to.to_string(),
        Outcome::Current { version } => version.to_string(),
        Outcome::Skipped => CLI_VERSION.to_owned(),
    };
    store::save_update_state(&UpdateState {
        checked_version: Some(recorded_version),
        checked_at: Some(OffsetDateTime::now_utc()),
    })?;
    Ok(outcome)
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

fn command_controls_updater(command: &Command) -> bool {
    matches!(command, Command::System(SystemCommand::Update))
        || matches!(
            command,
            Command::Config(ConfigCommand::Set { key, .. }) if key == "auto-update"
        )
}

fn check_is_due(state: &UpdateState, now: OffsetDateTime) -> bool {
    if state.checked_version.as_deref() != Some(CLI_VERSION) {
        return true;
    }
    state
        .checked_at
        .is_none_or(|checked_at| now - checked_at >= CHECK_INTERVAL)
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
    fn checks_immediately_then_at_most_daily() {
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
    fn a_newly_installed_version_gets_its_own_check() {
        let state = UpdateState {
            checked_version: Some("0.0.1".to_owned()),
            checked_at: Some(OffsetDateTime::now_utc()),
        };
        assert!(check_is_due(&state, OffsetDateTime::now_utc()));
    }
}
