//! What the CLI remembers between invocations.
//!
//! The client crate is stateless by design, so everything durable lives here:
//! which service to talk to, which profile is current, and the tokens for
//! each. All of it sits under `~/.silicon-iam/`, and the file holding tokens is
//! created `0600` and re-checked on every write, because a credential readable
//! by other users on the machine is not a credential.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{CliError, Result};

const APP_DIRECTORY: &str = ".silicon-iam";
const CONFIG_FILE: &str = "config.json";
const CREDENTIALS_FILE: &str = "credentials.json";
const UPDATE_FILE: &str = "update.json";

/// Settings that are not secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Whether the installed CLI maintains itself from crates.io.
    #[serde(default = "enabled")]
    pub auto_update: bool,
    /// Profile used when `--profile` is not given.
    #[serde(default)]
    pub current_profile: Option<String>,
    /// Per-profile settings.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auto_update: true,
            current_profile: None,
            profiles: BTreeMap::new(),
        }
    }
}

/// Non-secret throttle state for the crates.io updater.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateState {
    /// Compiled version for which the last successful check was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_version: Option<String>,
    /// Time of the last successful check.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub checked_at: Option<OffsetDateTime>,
}

/// One named service and the defaults that go with it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Profile {
    /// Base URL of the service.
    pub url: String,
    /// Organization assumed when a command does not name one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// Organization defaults inside isolated testing environments.
    ///
    /// Production and every testing plane have independent data, so carrying
    /// a production handle into a test plane only manufactures misleading
    /// not-found responses.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub test_orgs: BTreeMap<Uuid, String>,
}

/// Tokens, kept apart from the settings so the secret file can be locked down
/// on its own and pointed at in a bug report without it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Credentials {
    /// Production sessions, keyed by profile.
    #[serde(default)]
    pub sessions: BTreeMap<String, Session>,
    /// Testing-environment sessions, partitioned by profile and environment.
    #[serde(default)]
    pub test_sessions: BTreeMap<String, BTreeMap<Uuid, Session>>,
    /// Testing root keys, partitioned by profile and addressed by public UUID.
    #[serde(default)]
    pub testing_environment_keys: BTreeMap<String, BTreeMap<Uuid, String>>,
}

impl Credentials {
    /// Finds the session for exactly one production or testing scope.
    pub fn session(&self, profile: &str, environment_id: Option<Uuid>) -> Option<&Session> {
        match environment_id {
            Some(id) => self.test_sessions.get(profile)?.get(&id),
            None => self.sessions.get(profile),
        }
    }

    /// Replaces the session for exactly one production or testing scope.
    pub fn set_session(&mut self, profile: &str, environment_id: Option<Uuid>, session: Session) {
        match environment_id {
            Some(id) => {
                self.test_sessions
                    .entry(profile.to_owned())
                    .or_default()
                    .insert(id, session);
            }
            None => {
                self.sessions.insert(profile.to_owned(), session);
            }
        }
    }

    /// Removes the session for exactly one production or testing scope.
    pub fn remove_session(&mut self, profile: &str, environment_id: Option<Uuid>) -> bool {
        match environment_id {
            Some(id) => self
                .test_sessions
                .get_mut(profile)
                .and_then(|sessions| sessions.remove(&id))
                .is_some(),
            None => self.sessions.remove(profile).is_some(),
        }
    }

    /// Finds the secret root key behind a public environment id.
    pub fn testing_environment_key(&self, profile: &str, environment_id: Uuid) -> Option<&str> {
        self.testing_environment_keys
            .get(profile)?
            .get(&environment_id)
            .map(String::as_str)
    }

    /// Stores or replaces the root key behind a public environment id.
    pub fn set_testing_environment_key(
        &mut self,
        profile: &str,
        environment_id: Uuid,
        key: String,
    ) {
        self.testing_environment_keys
            .entry(profile.to_owned())
            .or_default()
            .insert(environment_id, key);
    }
}

/// The actor represented by a stored session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionActor {
    /// A person signing in through a verified contact challenge.
    #[default]
    Carbon,
    /// A service identity signing in with its Silicon credential.
    Silicon,
}

/// A remote logout that may have committed even if its response was lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingLogoutMode {
    /// Revoke only the session represented by the stored credential.
    CurrentSession,
    /// Revoke every session owned by the Carbon.
    AllSessions,
}

/// Durable retry identity for a remote logout.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingLogout {
    /// Scope bound into the original logout request.
    pub mode: PendingLogoutMode,
    /// Idempotency key reserved before the request was sent.
    pub idempotency_key: String,
}

/// One signed-in session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    /// Short-lived credential presented on each request.
    pub access_token: String,
    /// Rotating credential used to obtain the next access token.
    pub refresh_token: String,
    /// When the access token stops being accepted.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Which kind of principal owns the tokens.
    #[serde(default)]
    pub actor_type: SessionActor,
    /// Public Carbon or Silicon identifier for display and refresh continuity.
    #[serde(alias = "carbon_id")]
    pub actor_id: String,
    /// Key reserved before a rotating refresh request is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_refresh_key: Option<String>,
    /// Request identity retained until remote logout is confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_logout: Option<PendingLogout>,
}

impl Session {
    /// Whether the access token is close enough to expiry to renew now.
    ///
    /// Renews a minute early: a token that expires while a request is in
    /// flight fails the request, and the margin costs nothing.
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.expires_at <= OffsetDateTime::now_utc() + time::Duration::minutes(1)
    }
}

/// The directory everything is stored under.
///
/// # Errors
///
/// Returns an error when the home directory cannot be determined.
pub fn home() -> Result<PathBuf> {
    let home = std::env::var_os("SILICON_IAM_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(APP_DIRECTORY)))
        .ok_or_else(|| {
            CliError::Config(
                "cannot locate a home directory; set SILICON_IAM_HOME to choose one".to_owned(),
            )
        })?;
    Ok(home)
}

/// Reads the settings, or an empty set when none have been written yet.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read or parsed.
pub fn load_config() -> Result<Config> {
    read_json(&home()?.join(CONFIG_FILE))
}

/// Writes the settings.
///
/// # Errors
///
/// Returns an error when the directory or file cannot be written.
pub fn save_config(config: &Config) -> Result<()> {
    write_json(&home()?.join(CONFIG_FILE), config, false)
}

/// Reads automatic-update throttle state, or an empty value.
///
/// # Errors
///
/// Returns an error when the state exists but cannot be read or parsed.
pub fn load_update_state() -> Result<UpdateState> {
    read_json(&home()?.join(UPDATE_FILE))
}

/// Stores automatic-update throttle state without any credentials.
///
/// # Errors
///
/// Returns an error when the state cannot be written.
pub fn save_update_state(state: &UpdateState) -> Result<()> {
    write_json(&home()?.join(UPDATE_FILE), state, false)
}

/// Reads stored sessions, or an empty set.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read or parsed.
pub fn load_credentials() -> Result<Credentials> {
    read_json(&home()?.join(CREDENTIALS_FILE))
}

/// Writes stored sessions with owner-only permissions.
///
/// # Errors
///
/// Returns an error when the directory or file cannot be written.
pub fn save_credentials(credentials: &Credentials) -> Result<()> {
    write_json(&home()?.join(CREDENTIALS_FILE), credentials, true)
}

fn read_json<T: Default + serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
            CliError::Config(format!("{} is not readable: {error}", path.display()))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(CliError::Config(format!(
            "cannot read {}: {error}",
            path.display()
        ))),
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T, private: bool) -> Result<()> {
    let Some(directory) = path.parent() else {
        return Err(CliError::Config(format!(
            "{} has no parent directory",
            path.display()
        )));
    };
    fs::create_dir_all(directory).map_err(|error| {
        CliError::Config(format!("cannot create {}: {error}", directory.display()))
    })?;
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| CliError::Config(format!("cannot encode {}: {error}", path.display())))?;
    encoded.push(b'\n');
    fs::write(path, &encoded)
        .map_err(|error| CliError::Config(format!("cannot write {}: {error}", path.display())))?;
    if private {
        restrict(path)?;
    }
    Ok(())
}

const fn enabled() -> bool {
    true
}

/// Makes a file readable and writable by its owner only.
///
/// Applied on every write, not only at creation: a file whose permissions were
/// widened after the fact is exactly the case worth catching.
#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        CliError::Config(format!(
            "cannot restrict permissions on {}: {error}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    // Nothing portable to do here. The directory sits under the user's own
    // profile, which is the platform's own boundary.
    Ok(())
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::{Config, Credentials, Profile, Session, SessionActor};

    #[test]
    fn automatic_updates_default_on_for_new_and_old_configs() {
        assert!(Config::default().auto_update);
        let decoded = serde_json::from_str::<Config>("{}");
        assert!(decoded.is_ok_and(|config| config.auto_update));
    }

    #[test]
    fn old_profiles_load_without_test_environment_defaults() {
        let decoded =
            serde_json::from_str::<Profile>(r#"{"url":"https://example.test","org":"production"}"#);
        assert!(decoded.is_ok_and(|profile| profile.test_orgs.is_empty()));
    }

    fn session(expires_in: Duration) -> Session {
        Session {
            access_token: "cat_x".to_owned(),
            refresh_token: "rft_x".to_owned(),
            expires_at: OffsetDateTime::now_utc() + expires_in,
            actor_type: SessionActor::Carbon,
            actor_id: "founder".to_owned(),
            pending_refresh_key: None,
            pending_logout: None,
        }
    }

    #[test]
    fn old_carbon_sessions_keep_their_identity() {
        let decoded = serde_json::from_str::<Credentials>(
            r#"{
                "sessions": {
                    "default": {
                        "access_token":"cat_x",
                        "refresh_token":"rft_x",
                        "expires_at":"2026-09-04T00:00:00Z",
                        "carbon_id":"founder"
                    }
                }
            }"#,
        );
        let Ok(credentials) = decoded else {
            panic!("the old credentials-file shape must remain readable");
        };
        let Some(session) = credentials.session("default", None) else {
            panic!("the old Carbon session must remain present");
        };
        assert_eq!(session.actor_type, SessionActor::Carbon);
        assert_eq!(session.actor_id, "founder");
    }

    #[test]
    fn silicon_sessions_round_trip_with_their_actor_kind() {
        let mut credentials = Credentials::default();
        let mut silicon = session(Duration::minutes(30));
        silicon.access_token = "sat_x".to_owned();
        silicon.actor_type = SessionActor::Silicon;
        silicon.actor_id = "builder:tos".to_owned();
        credentials.set_session("default", None, silicon);

        let encoded = serde_json::to_vec(&credentials);
        let Ok(encoded) = encoded else {
            panic!("credentials must serialize");
        };
        let decoded = serde_json::from_slice::<Credentials>(&encoded);
        let Ok(decoded) = decoded else {
            panic!("credentials must deserialize");
        };
        let Some(session) = decoded.session("default", None) else {
            panic!("the Silicon session must remain present");
        };
        assert_eq!(session.actor_type, SessionActor::Silicon);
        assert_eq!(session.actor_id, "builder:tos");
        assert_eq!(session.access_token, "sat_x");
    }

    #[test]
    fn a_session_is_renewed_before_it_actually_expires() {
        assert!(!session(Duration::minutes(30)).needs_refresh());
        // Inside the margin: renewing now avoids failing a request that is
        // about to be sent.
        assert!(session(Duration::seconds(30)).needs_refresh());
        assert!(session(Duration::seconds(-1)).needs_refresh());
    }

    #[test]
    fn production_and_each_test_environment_have_independent_sessions() {
        let first_id = Uuid::from_u128(1);
        let second_id = Uuid::from_u128(2);
        let mut credentials = Credentials::default();
        credentials.set_session("default", None, session(Duration::minutes(5)));
        let mut first = session(Duration::minutes(6));
        first.actor_id = "first-test".to_owned();
        credentials.set_session("default", Some(first_id), first);
        let mut second = session(Duration::minutes(7));
        second.actor_id = "second-test".to_owned();
        credentials.set_session("default", Some(second_id), second);

        assert_eq!(
            credentials
                .session("default", None)
                .map(|value| value.actor_id.as_str()),
            Some("founder")
        );
        assert_eq!(
            credentials
                .session("default", Some(first_id))
                .map(|value| value.actor_id.as_str()),
            Some("first-test")
        );
        assert_eq!(
            credentials
                .session("default", Some(second_id))
                .map(|value| value.actor_id.as_str()),
            Some("second-test")
        );
    }

    #[test]
    fn environment_keys_are_looked_up_by_public_id_and_profile() {
        let id = Uuid::from_u128(7);
        let mut credentials = Credentials::default();
        credentials.set_testing_environment_key("work", id, "a".repeat(32));

        assert_eq!(
            credentials.testing_environment_key("work", id),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(credentials.testing_environment_key("other", id), None);
    }
}
