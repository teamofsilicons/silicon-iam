//! Everything one invocation needs, resolved once.
//!
//! Turns stored settings, environment variables and command-line flags into a
//! client, in that order of increasing precedence, and owns the one piece of
//! behaviour the client crate deliberately refuses to have: renewing an access
//! token that is about to expire.

use silicon_iam_client::{Client, Credential, EnvironmentKey, Mutation};

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
    organization: Option<String>,
    environment: Option<String>,
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
        environment: Option<String>,
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

        let environment = environment
            .or_else(|| std::env::var("SILICON_IAM_ENVIRONMENT").ok())
            .or_else(|| stored.environment.clone());
        let organization = organization
            .or_else(|| std::env::var("SILICON_IAM_ORG").ok())
            .or_else(|| stored.org.clone());

        let mut builder =
            Client::builder(&stored.url)?.user_agent(concat!("siam/", env!("CARGO_PKG_VERSION")));
        if let Some(key) = &environment {
            builder = builder.environment(EnvironmentKey::new(key.clone())?);
        }

        Ok(Self {
            format,
            profile_name,
            profile: stored,
            step_up,
            organization,
            environment,
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
    pub fn environment(&self) -> Option<&str> {
        self.environment.as_deref()
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
            self.renew(&session).await?
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
            .sessions
            .get(&self.profile_name)
            .cloned()
            .ok_or(CliError::NotSignedIn)
    }

    /// Stores a session for this profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential file cannot be written.
    pub fn remember(&self, session: Session) -> Result<()> {
        let mut credentials = store::load_credentials()?;
        credentials
            .sessions
            .insert(self.profile_name.clone(), session);
        store::save_credentials(&credentials)
    }

    /// Forgets this profile's session.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential file cannot be written.
    pub fn forget(&self) -> Result<bool> {
        let mut credentials = store::load_credentials()?;
        let existed = credentials.sessions.remove(&self.profile_name).is_some();
        store::save_credentials(&credentials)?;
        Ok(existed)
    }

    /// The organization a command should act on.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NoOrganization`] when none was given or configured.
    pub fn organization(&self) -> Result<&str> {
        self.organization.as_deref().ok_or(CliError::NoOrganization)
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

    /// A mutation carrying a fresh key, and this invocation's step-up token.
    #[must_use]
    pub fn mutation(&self) -> Mutation {
        let mutation = Mutation::new();
        match &self.step_up {
            Some(token) => mutation.step_up(token.clone()),
            None => mutation,
        }
    }

    /// Exchanges the refresh token for a new session and stores it.
    async fn renew(&self, session: &Session) -> Result<Session> {
        let tokens = self
            .client
            .auth()
            .refresh(&session.refresh_token, &Mutation::new())
            .await?;
        let renewed = crate::commands::auth::session_from(&tokens, &session.carbon_id);
        self.remember(renewed.clone())?;
        Ok(renewed)
    }
}
