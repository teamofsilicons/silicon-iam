//! What the CLI remembers between invocations.
//!
//! The client crate is stateless by design, so everything durable lives here:
//! which service to talk to, which profile is current, and the tokens for
//! each. All of it sits under `~/.silicon-iam/`, and the file holding tokens is
//! created `0600` and re-checked on every write, because a credential readable
//! by other users on the machine is not a credential.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{CliError, Result};

#[cfg(not(unix))]
use std::fs::OpenOptions;

const APP_DIRECTORY: &str = ".silicon-iam";
const CONFIG_FILE: &str = "config.json";
const CREDENTIALS_FILE: &str = "credentials.json";
const UPDATE_FILE: &str = "update.json";
const STORE_LOCK: &str = "credentials.lock";

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
    /// Compiled version for which the last check was attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_version: Option<String>,
    /// Time of the last check attempt, including a registry/install failure.
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
    StoreDirectory::open()?.read_json(CONFIG_FILE)
}

/// Holds the shared read/modify/write lock for local state.
///
/// The lock file is permanent: unlinking it would let concurrent processes
/// acquire locks on different inodes. Dropping this value releases the lock.
pub struct LockedStore {
    directory: StoreDirectory,
    _lock: File,
}

/// Locks local state before reading a snapshot that will be modified.
///
/// # Errors
///
/// Returns an error for unsafe paths or unreadable/unlockable local state.
pub fn lock() -> Result<LockedStore> {
    let directory = StoreDirectory::open()?;
    let lock = directory.lock(STORE_LOCK)?;
    Ok(LockedStore {
        directory,
        _lock: lock,
    })
}

impl LockedStore {
    /// Reads settings while excluding other state writers.
    ///
    /// # Errors
    ///
    /// Returns an error when the settings are unsafe, unreadable or invalid.
    pub fn load_config(&self) -> Result<Config> {
        self.directory.read_json(CONFIG_FILE)
    }

    /// Atomically replaces settings while retaining the state lock.
    ///
    /// # Errors
    ///
    /// Returns an error when the settings cannot be safely persisted.
    pub fn save_config(&self, config: &Config) -> Result<()> {
        self.directory.write_json(CONFIG_FILE, config)
    }

    fn load_credentials(&self) -> Result<Credentials> {
        self.directory.read_json(CREDENTIALS_FILE)
    }

    fn save_credentials(&self, credentials: &Credentials) -> Result<()> {
        self.directory.write_json(CREDENTIALS_FILE, credentials)
    }
}

/// Reads automatic-update throttle state, or an empty value.
///
/// # Errors
///
/// Returns an error when the state exists but cannot be read or parsed.
pub fn load_update_state() -> Result<UpdateState> {
    StoreDirectory::open()?.read_json(UPDATE_FILE)
}

/// Stores automatic-update throttle state without any credentials.
///
/// # Errors
///
/// Returns an error when the state cannot be written.
pub fn save_update_state(state: &UpdateState) -> Result<()> {
    let store = lock()?;
    let previous: UpdateState = store.directory.read_json(UPDATE_FILE)?;
    // A slower concurrent check must not move the last-attempt clock
    // backwards. A future value, however, must be repairable after clock skew.
    if previous.checked_at > state.checked_at
        && previous.checked_at <= Some(OffsetDateTime::now_utc())
    {
        return Ok(());
    }
    store.directory.write_json(UPDATE_FILE, state)
}

/// Attempts to serialize an updater check and installation for this home.
///
/// # Errors
///
/// Returns an error for an unsafe home/lock path or an operating-system failure.
pub fn try_lock_updater_check() -> Result<Option<File>> {
    StoreDirectory::open()?.try_lock("updater-check.lock")
}

/// Reads stored sessions, or an empty set.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read or parsed.
pub fn load_credentials() -> Result<Credentials> {
    StoreDirectory::open()?.read_json(CREDENTIALS_FILE)
}

/// Serializes one profile/environment's complete session transitions.
///
/// Unlike the short state-file lock, this lock can span a network refresh or
/// logout. Independent sessions continue working, and login/logout cannot race
/// a refresh commit for the same session.
pub struct LockedSession {
    directory: StoreDirectory,
    _lock: File,
    profile: String,
    environment_id: Option<Uuid>,
}

/// Acquires the session lock before re-reading its current credentials.
///
/// # Errors
///
/// Returns an error for an unsafe home, or an unsafe/unlockable lock file.
pub fn lock_session(profile: &str, environment_id: Option<Uuid>) -> Result<LockedSession> {
    let directory = StoreDirectory::open()?;
    let mut digest = Sha256::new();
    digest.update(profile.as_bytes());
    digest.update([0]);
    if let Some(id) = environment_id {
        digest.update(id.as_bytes());
    }
    let name = format!("session-{:x}.lock", digest.finalize());
    let lock = directory.lock(&name)?;
    Ok(LockedSession {
        directory,
        _lock: lock,
        profile: profile.to_owned(),
        environment_id,
    })
}

impl LockedSession {
    /// Reads the latest session after its transition lock has been acquired.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe or unreadable state, or when signed out.
    pub fn session(&self) -> Result<Session> {
        let credentials: Credentials = self.directory.read_json(CREDENTIALS_FILE)?;
        credentials
            .session(&self.profile, self.environment_id)
            .cloned()
            .ok_or(CliError::NotSignedIn)
    }

    /// Merges this session into the latest document, preserving other sessions.
    ///
    /// # Errors
    ///
    /// Returns an error when state cannot be safely locked, read or persisted.
    pub fn remember(&self, session: Session) -> Result<()> {
        let _lock = self.directory.lock(STORE_LOCK)?;
        let mut credentials: Credentials = self.directory.read_json(CREDENTIALS_FILE)?;
        credentials.set_session(&self.profile, self.environment_id, session);
        self.directory.write_json(CREDENTIALS_FILE, &credentials)
    }

    /// Removes only this session from the latest document.
    ///
    /// # Errors
    ///
    /// Returns an error when state cannot be safely locked, read or persisted.
    pub fn forget(&self) -> Result<bool> {
        let _lock = self.directory.lock(STORE_LOCK)?;
        let mut credentials: Credentials = self.directory.read_json(CREDENTIALS_FILE)?;
        let existed = credentials.remove_session(&self.profile, self.environment_id);
        self.directory.write_json(CREDENTIALS_FILE, &credentials)?;
        Ok(existed)
    }
}

/// Merges an environment key into the latest credential document.
///
/// # Errors
///
/// Returns an error when state cannot be safely locked, read or persisted.
pub fn remember_testing_environment(
    profile: &str,
    environment_id: Uuid,
    key: String,
) -> Result<()> {
    let store = lock()?;
    let mut credentials = store.load_credentials()?;
    credentials.set_testing_environment_key(profile, environment_id, key);
    store.save_credentials(&credentials)
}

struct StoreDirectory {
    path: PathBuf,
    // Pin the verified directory so renaming its path cannot redirect writes.
    #[cfg(unix)]
    file: File,
}

impl StoreDirectory {
    fn open() -> Result<Self> {
        let path = home()?;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .map_err(|error| state_error(&path, error))?;
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, open};
            use std::os::unix::fs::MetadataExt as _;

            let file = File::from(
                open(
                    &path,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| state_error(&path, error))?,
            );
            let metadata = file.metadata().map_err(|error| state_error(&path, error))?;
            if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0
            {
                return Err(CliError::Config(format!(
                    "{} must be owned by the current user and private (0700); use chmod 700 on your IAM home",
                    path.display()
                )));
            }
            Ok(Self { path, file })
        }
        #[cfg(not(unix))]
        {
            let metadata =
                fs::symlink_metadata(&path).map_err(|error| state_error(&path, error))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(state_error(
                    &path,
                    "the IAM home must be a real directory, not a link",
                ));
            }
            Ok(Self { path })
        }
    }

    fn open_file(&self, name: &str, create: bool, exclusive: bool) -> std::io::Result<File> {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};

            let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
            flags |= if create {
                OFlags::RDWR | OFlags::CREATE
            } else {
                OFlags::RDONLY
            };
            if exclusive {
                flags |= OFlags::EXCL;
            }
            Ok(File::from(openat(
                &self.file,
                name,
                flags,
                Mode::from_raw_mode(0o600),
            )?))
        }
        #[cfg(not(unix))]
        {
            let path = self.path.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(std::io::Error::other(
                        "symbolic links are not allowed in IAM state",
                    ));
                }
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(create)
                .create(create)
                .create_new(exclusive);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                // Open the reparse point itself; never follow a swapped link.
                options.custom_flags(0x0020_0000);
            }
            options.open(path)
        }
    }

    fn validate_file(&self, name: &str, file: &File) -> Result<()> {
        let path = self.path.join(name);
        let metadata = file.metadata().map_err(|error| state_error(&path, error))?;
        if !metadata.is_file() {
            return Err(state_error(
                &path,
                "IAM state must be a regular file, not a link or device",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o022 != 0
                || metadata.nlink() > 1
            {
                return Err(state_error(
                    &path,
                    "IAM state must be owned by the current user, not writable by others, and not hard-linked",
                ));
            }
        }
        Ok(())
    }

    fn lock(&self, name: &str) -> Result<File> {
        let file = self.open_file(name, true, false).map_err(|error| {
            state_error(&self.path.join(name), format!("cannot open lock: {error}"))
        })?;
        self.validate_file(name, &file)?;
        file.lock().map_err(|error| {
            state_error(
                &self.path.join(name),
                format!("cannot acquire lock: {error}"),
            )
        })?;
        Ok(file)
    }

    fn try_lock(&self, name: &str) -> Result<Option<File>> {
        let file = self
            .open_file(name, true, false)
            .map_err(|error| state_error(&self.path.join(name), error))?;
        self.validate_file(name, &file)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(error) => Err(state_error(&self.path.join(name), error)),
        }
    }

    fn read_json<T: Default + serde::de::DeserializeOwned>(&self, name: &str) -> Result<T> {
        let mut file = match self.open_file(name, false, false) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
            Err(error) => return Err(state_error(&self.path.join(name), error)),
        };
        self.validate_file(name, &file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| state_error(&self.path.join(name), error))?;
        serde_json::from_slice(&bytes).map_err(|error| state_error(&self.path.join(name), error))
    }

    fn write_json<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        // Explicitly reject an existing symlink instead of replacing it. All
        // operations below are relative to the same private, pinned directory.
        match self.open_file(name, false, false) {
            Ok(file) => self.validate_file(name, &file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(state_error(&self.path.join(name), error)),
        }
        let temporary = format!(".{name}.{}.tmp", Uuid::now_v7());
        self.write_temporary(name, &temporary, value)
    }

    fn write_temporary<T: Serialize>(&self, name: &str, temporary: &str, value: &T) -> Result<()> {
        let path = self.path.join(name);
        let mut encoded =
            serde_json::to_vec_pretty(value).map_err(|error| state_error(&path, error))?;
        encoded.push(b'\n');
        let mut file = self
            .open_file(temporary, true, true)
            .map_err(|error| state_error(&path, error))?;
        // Only clean up after exclusive creation succeeded: a name collision
        // must never remove a file that this operation did not create.
        let result = (|| {
            file.write_all(&encoded)
                .map_err(|error| state_error(&path, error))?;
            file.sync_all().map_err(|error| state_error(&path, error))?;
            drop(file);
            #[cfg(unix)]
            {
                rustix::fs::renameat(&self.file, temporary, &self.file, name)
                    .map_err(|error| state_error(&path, error))?;
                self.file
                    .sync_all()
                    .map_err(|error| state_error(&path, error))?;
            }
            #[cfg(not(unix))]
            fs::rename(self.path.join(temporary), &path)
                .map_err(|error| state_error(&path, error))?;
            Ok(())
        })();
        if result.is_err() {
            #[cfg(unix)]
            let _ = rustix::fs::unlinkat(&self.file, temporary, rustix::fs::AtFlags::empty());
            #[cfg(not(unix))]
            let _ = fs::remove_file(self.path.join(temporary));
        }
        result
    }
}

fn state_error(path: &Path, error: impl std::fmt::Display) -> CliError {
    CliError::Config(format!("cannot access {}: {error}", path.display()))
}

const fn enabled() -> bool {
    true
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
