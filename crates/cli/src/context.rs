//! Everything one invocation needs, resolved once.
//!
//! Turns stored settings, environment variables and command-line flags into a
//! client, in that order of increasing precedence, and owns the one piece of
//! behaviour the client crate deliberately refuses to have: renewing an access
//! token that is about to expire.

use silicon_iam_client::{Client, Credential, EnvironmentKey, IdempotencyKey, Mutation};
use uuid::Uuid;

use crate::{
    error::{CliError, Result},
    output::Format,
    store::{self, Profile, Session},
};

/// The default profile name, used when none is configured or given.
pub const DEFAULT_PROFILE: &str = "default";

/// The default service, so a first run has somewhere to point.
pub const DEFAULT_URL: &str = "https://backend.iam.teamofsilicons.com";

/// One invocation's resolved settings.
pub struct Context {
    /// How results are rendered.
    pub format: Format,
    /// Which stored profile this invocation is using.
    pub profile_name: String,
    /// The resolved profile.
    pub profile: Profile,
    /// Step-up assertion supplied for this invocation, if any.
    pub step_up: Option<String>,
    request_key: Option<IdempotencyKey>,
    organization: Option<String>,
    testing_environment_id: Option<Uuid>,
    client: Client,
}

impl Context {
    /// Resolves settings and builds the client.
    ///
    /// # Errors
    ///
    /// Returns an error when stored settings are unreadable, or the resolved
    /// service URL is unusable.
    pub fn new(
        format: Format,
        profile: Option<String>,
        url: Option<String>,
        organization: Option<String>,
        no_organization: bool,
        testing_environment_id: Option<Uuid>,
        step_up: Option<String>,
    ) -> Result<Self> {
        let config = store::load_config()?;
        let profile_name = profile
            .or_else(|| std::env::var("SILICON_IAM_PROFILE").ok())
            .or_else(|| config.current_profile.clone())
            .unwrap_or_else(|| DEFAULT_PROFILE.to_owned());
        let mut stored = config
            .profiles
            .get(&profile_name)
            .cloned()
            .unwrap_or_default();
        if stored.url.is_empty() {
            DEFAULT_URL.clone_into(&mut stored.url);
        }
        if let Some(url) = url.or_else(|| std::env::var("SILICON_IAM_URL").ok()) {
            stored.url = url;
        }

        let organization = if no_organization {
            None
        } else {
            organization
                .or_else(|| std::env::var("SILICON_IAM_ORG").ok())
                .or_else(|| match testing_environment_id {
                    Some(environment_id) => stored.test_orgs.get(&environment_id).cloned(),
                    None => stored.org.clone(),
                })
        };

        let mut builder = Client::builder(&stored.url)?
            .user_agent(concat!("iam/", env!("CARGO_PKG_VERSION")))
            // The CLI updates its whole installed crate after dispatch. Its
            // embedded client must not separately mutate this source tree.
            .auto_update(false)
            .telemetry(config.telemetry);
        if let Some(environment_id) = testing_environment_id {
            let credentials = store::load_credentials()?;
            let Some(key) = credentials.testing_environment_key(&profile_name, environment_id)
            else {
                return Err(CliError::UnknownTestingEnvironment(environment_id));
            };
            builder = builder.environment(EnvironmentKey::new(key.to_owned())?);
        }

        Ok(Self {
            format,
            profile_name,
            profile: stored,
            step_up,
            request_key: None,
            organization,
            testing_environment_id,
            client: builder.build()?,
        })
    }

    /// A client carrying no credential, for signup, login and health.
    #[must_use]
    pub const fn anonymous(&self) -> &Client {
        &self.client
    }

    /// The testing environment this invocation is inside, if any.
    #[must_use]
    pub const fn testing_environment_id(&self) -> Option<Uuid> {
        self.testing_environment_id
    }

    /// Ensures a test-only operation cannot accidentally run in production.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::TestEnvironmentRequired`] outside `--test`.
    pub fn require_test(&self) -> Result<Uuid> {
        self.testing_environment_id
            .ok_or(CliError::TestEnvironmentRequired)
    }

    /// A client carrying the stored session, renewing it first if it is close
    /// to expiry.
    ///
    /// This is the CLI's whole reason to be stateful. The client crate will
    /// not refresh a token behind a caller's back, and here the CLI *is* the
    /// caller: it owns the store, so it can renew and persist.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NotSignedIn`] when there is no session for this
    /// profile, or a client error when renewal is refused.
    pub async fn authenticated(&self) -> Result<Client> {
        let session = self.session()?;
        let session = if session.needs_refresh() {
            self.renew().await?
        } else {
            session
        };
        Ok(self
            .client
            .with_credential(Credential::bearer(session.access_token)))
    }

    /// A credentialed client suitable for retrying remote logout.
    ///
    /// Once logout has been sent, its bearer may already be revoked. In that
    /// state the only valid follow-up is an exact idempotent replay, so an
    /// implicit refresh would destroy the ability to confirm the outcome.
    pub async fn authenticated_for_logout(&self, stored: &store::LockedSession) -> Result<Client> {
        let session = stored.session()?;
        let session = if session.pending_logout.is_some() {
            session
        } else if session.needs_refresh() {
            self.renew_locked(stored).await?
        } else {
            session
        };
        Ok(self
            .client
            .with_credential(Credential::bearer(session.access_token)))
    }

    /// The stored session for this profile.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NotSignedIn`] when there is none.
    pub fn session(&self) -> Result<Session> {
        store::load_credentials()?
            .session(&self.profile_name, self.testing_environment_id)
            .cloned()
            .ok_or(CliError::NotSignedIn)
    }

    /// Stores a session for this profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential file cannot be written.
    pub fn remember(&self, session: Session) -> Result<()> {
        self.lock_session()?.remember(session)
    }

    /// Forgets this profile's session.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential file cannot be written.
    pub fn forget(&self) -> Result<bool> {
        self.lock_session()?.forget()
    }

    /// Serializes login, refresh and logout for this exact stored session.
    ///
    /// # Errors
    ///
    /// Returns an error when the home or session lock is unsafe or unavailable.
    pub fn lock_session(&self) -> Result<store::LockedSession> {
        store::lock_session(&self.profile_name, self.testing_environment_id)
    }

    /// Securely remembers the key behind an environment's public id.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner-only credential file cannot be saved.
    pub fn remember_testing_environment(&self, environment_id: Uuid, key: String) -> Result<()> {
        store::remember_testing_environment(&self.profile_name, environment_id, key)
    }

    /// The organization a command should act on.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NoOrganization`] when none was given or configured.
    pub fn organization(&self) -> Result<&str> {
        self.organization.as_deref().ok_or(CliError::NoOrganization)
    }

    /// The effective organization for this exact production or test scope.
    #[must_use]
    pub fn organization_if_set(&self) -> Option<&str> {
        self.organization.as_deref()
    }

    /// The organization a command should act on, preferring an explicit one.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NoOrganization`] when neither is available.
    pub fn organization_or<'a>(&'a self, explicit: Option<&'a str>) -> Result<&'a str> {
        match explicit {
            Some(org) => Ok(org),
            None => self.organization(),
        }
    }

    /// Validates an immutable bare Application identifier.
    /// # Errors
    /// Rejects qualified or malformed application identifiers.
    #[allow(clippy::unused_self)]
    pub fn application_id(&self, value: &str) -> Result<String> {
        if !(1..=80).contains(&value.len())
            || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
        {
            return Err(CliError::Usage("Application ID must be a bare lowercase handle; pass the owning organization separately with --org".to_owned()));
        }
        Ok(value.to_owned())
    }

    /// Resolves a bundle's unchanged organization-qualified ID.
    /// # Errors
    /// Rejects malformed bundle identifiers or missing organization selection.
    pub fn bundle_id(&self, value: &str) -> Result<String> {
        if let Some((org, handle)) = value.split_once('>') {
            if !(3..=50).contains(&org.len())
                || !org.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                })
            {
                return Err(CliError::Usage(
                    "Bundle ID must be organization>bundle".to_owned(),
                ));
            }
            self.application_id(handle)?;
            Ok(value.to_owned())
        } else {
            Ok(format!(
                "{}>{}",
                self.organization()?,
                self.application_id(value)?
            ))
        }
    }

    /// Returns the bundle handle and its explicit owning organization.
    /// # Errors
    /// Rejects a bundle outside the selected organization.
    pub fn bundle_creation_identity(&self, value: &str) -> Result<(String, String)> {
        let id = self.bundle_id(value)?;
        let (org, handle) = id
            .split_once('>')
            .ok_or_else(|| CliError::Usage("Bundle ID must be organization>bundle".to_owned()))?;
        if self
            .organization_if_set()
            .is_some_and(|selected| selected != org)
        {
            return Err(CliError::Usage(
                "Bundle organization differs from --org".to_owned(),
            ));
        }
        Ok((handle.to_owned(), org.to_owned()))
    }

    /// Returns the application handle and separately selected owning organization.
    /// # Errors
    /// Requires --org or a configured organization for creation.
    pub fn application_creation_identity(&self, value: &str) -> Result<(String, String)> {
        Ok((self.application_id(value)?, self.organization()?.to_owned()))
    }

    /// Converts a creation handle to a canonical Silicon ID; ownership stays separate.
    /// # Errors
    /// Rejects malformed and legacy organization-suffixed Silicon identifiers.
    #[allow(clippy::unused_self)]
    pub fn silicon_id(&self, value: &str, _organization: &str) -> Result<String> {
        let handle = value.strip_prefix("si:").unwrap_or(value);
        if !(3..=50).contains(&handle.len())
            || !handle
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
        {
            return Err(CliError::Usage("Silicon ID must be si:<handle>".to_owned()));
        }
        Ok(format!("si:{handle}"))
    }

    /// Returns the Silicon ID and separately selected organization for management.
    /// # Errors
    /// Requires an explicit organization and a valid Silicon handle.
    pub fn silicon_identity(&self, value: &str) -> Result<(String, String)> {
        let org = self.organization()?;
        Ok((self.silicon_id(value, org)?, org.to_owned()))
    }

    /// Returns the creation handle without its si: prefix.
    /// # Errors
    /// Rejects malformed Silicon IDs.
    pub fn local_silicon_id(&self, value: &str, organization: &str) -> Result<String> {
        Ok(self
            .silicon_id(value, organization)?
            .trim_start_matches("si:")
            .to_owned())
    }

    /// Select an exact retry key for this invocation.
    pub fn set_request_key(&mut self, key: Option<String>) -> Result<()> {
        self.request_key = key.map(IdempotencyKey::parse).transpose()?;
        Ok(())
    }

    /// A mutation carrying the supplied retry key or a fresh key, and step-up token.
    #[must_use]
    pub fn mutation(&self) -> Mutation {
        let mutation = self
            .request_key
            .clone()
            .map_or_else(Mutation::new, Mutation::with_key);
        match &self.step_up {
            Some(token) => mutation.step_up(token.clone()),
            None => mutation,
        }
    }

    /// Exchanges the refresh token for a new session and stores it.
    async fn renew(&self) -> Result<Session> {
        let stored = self.lock_session()?;
        self.renew_locked(&stored).await
    }

    async fn renew_locked(&self, stored: &store::LockedSession) -> Result<Session> {
        // Another process may have refreshed, logged in, or logged out while
        // this invocation waited. Never rotate an earlier snapshot's token.
        let mut session = stored.session()?;
        // A replay can contain an already expired access token. Commit the rotated
        // refresh token first, then recover once using that new generation.
        for _ in 0..2 {
            if !session.needs_refresh() {
                return Ok(session);
            }
            if session.pending_logout.is_some() {
                return Err(CliError::Usage(
                    "a remote logout is pending; retry that logout before using this session"
                        .to_owned(),
                ));
            }
            let key = if let Some(key) = session.pending_refresh_key.as_deref() {
                IdempotencyKey::parse(key.to_owned())?
            } else {
                let key = IdempotencyKey::generate();
                session.pending_refresh_key = Some(key.as_str().to_owned());
                session.pending_refresh_started_at = Some(time::OffsetDateTime::now_utc());
                stored.remember(session.clone())?;
                key
            };
            let tokens = self
                .client
                .auth()
                .refresh(&session.refresh_token, &Mutation::with_key(key))
                .await?;
            session = renewed_session(&tokens, &session);
            stored.remember(session.clone())?;
        }
        Ok(session)
    }
}

fn renewed_session(
    tokens: &silicon_iam_client::models::IamTokenResponse,
    previous: &Session,
) -> Session {
    let mut renewed =
        crate::commands::auth::session_from_actor(tokens, &previous.actor_id, previous.actor_type);
    // Old pending records have no trusted start time. Preserve the rotated
    // credential but renew it immediately instead of extending an old reply.
    renewed.expires_at = previous
        .pending_refresh_started_at
        .map_or_else(time::OffsetDateTime::now_utc, |started| {
            started + time::Duration::seconds(tokens.expires_in)
        });
    renewed
}

#[cfg(test)]
mod tests {
    use silicon_iam_client::models;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{Context, DEFAULT_PROFILE, DEFAULT_URL, renewed_session};
    use crate::{
        error::CliError,
        output::Format,
        store::{Profile, Session, SessionActor},
    };

    fn context(testing_environment_id: Option<Uuid>) -> Context {
        let Ok(client) = silicon_iam_client::Client::new(DEFAULT_URL) else {
            panic!("the default URL must build");
        };
        Context {
            format: Format::Text,
            profile_name: DEFAULT_PROFILE.to_owned(),
            profile: Profile {
                url: DEFAULT_URL.to_owned(),
                org: None,
                test_orgs: std::collections::BTreeMap::new(),
            },
            step_up: None,
            request_key: None,
            organization: None,
            testing_environment_id,
            client,
        }
    }

    #[test]
    fn test_only_actions_fail_clearly_without_test_context() {
        assert!(matches!(
            context(None).require_test(),
            Err(CliError::TestEnvironmentRequired)
        ));
        let id = Uuid::from_u128(17);
        assert_eq!(context(Some(id)).require_test().ok(), Some(id));
    }

    #[test]
    fn identifiers_keep_organization_separate() {
        let mut context = context(None);
        assert_eq!(
            context.application_id("space-station").ok().as_deref(),
            Some("space-station")
        );
        assert!(context.application_id("other>space-station").is_err());
        assert_eq!(
            context.silicon_id("si:builder", "").ok().as_deref(),
            Some("si:builder")
        );
        assert!(matches!(
            context.silicon_identity("si:builder"),
            Err(CliError::NoOrganization)
        ));
        context.organization = Some("tos".to_owned());
        assert_eq!(
            context.silicon_identity("builder").ok(),
            Some(("si:builder".to_owned(), "tos".to_owned()))
        );
        assert_eq!(
            context.application_creation_identity("space-station").ok(),
            Some(("space-station".to_owned(), "tos".to_owned()))
        );
        assert!(context.local_silicon_id("builder:other", "tos").is_err());
        assert_eq!(
            context
                .local_silicon_id("si:builder", "tos")
                .ok()
                .as_deref(),
            Some("builder")
        );
    }

    #[test]
    fn refresh_replacement_preserves_a_silicon_session_actor() {
        let mut previous = Session {
            access_token: "sat_old".to_owned(),
            refresh_token: "rft_old".to_owned(),
            expires_at: OffsetDateTime::now_utc(),
            actor_type: SessionActor::Silicon,
            actor_id: "si:builder".to_owned(),
            pending_refresh_key: None,
            pending_refresh_started_at: None,
            pending_logout: None,
        };
        let tokens = models::IamTokenResponse {
            access_token: "sat_new".to_owned(),
            refresh_token: "rft_new".to_owned(),
            token_type: serde_json::json!("Bearer"),
            expires_in: 1_800,
            refresh_expires_at: OffsetDateTime::now_utc() + time::Duration::days(900),
            actor: models::ActorRef {
                type_field: models::ActorRefType::Silicon,
                public_id: "si:builder".to_owned(),
            },
            session_id: Uuid::from_u128(2),
        };

        let renewed = renewed_session(&tokens, &previous);
        assert_eq!(renewed.actor_type, SessionActor::Silicon);
        assert_eq!(renewed.actor_id, "si:builder");
        assert_eq!(renewed.access_token, "sat_new");
        assert_eq!(renewed.refresh_token, "rft_new");
        assert!(renewed.needs_refresh());
        let started = OffsetDateTime::now_utc() - time::Duration::hours(1);
        previous.pending_refresh_started_at = Some(started);
        let replayed = renewed_session(&tokens, &previous);
        assert_eq!(
            replayed.expires_at,
            started + time::Duration::seconds(1_800)
        );
        assert!(replayed.needs_refresh());
        assert!(replayed.pending_refresh_key.is_none());
        assert!(replayed.pending_refresh_started_at.is_none());
    }
}
