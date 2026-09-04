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
            // The CLI updates its whole installed crate before dispatch. Its
            // embedded client must not separately mutate this source tree.
            .auto_update(false);
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
            self.renew(&session).await?
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
    pub async fn authenticated_for_logout(&self) -> Result<Client> {
        let session = self.session()?;
        let session = if session.pending_logout.is_some() {
            session
        } else if session.needs_refresh() {
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
        let mut credentials = store::load_credentials()?;
        credentials.set_session(&self.profile_name, self.testing_environment_id, session);
        store::save_credentials(&credentials)
    }

    /// Forgets this profile's session.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential file cannot be written.
    pub fn forget(&self) -> Result<bool> {
        let mut credentials = store::load_credentials()?;
        let existed = credentials.remove_session(&self.profile_name, self.testing_environment_id);
        store::save_credentials(&credentials)?;
        Ok(existed)
    }

    /// Securely remembers the key behind an environment's public id.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner-only credential file cannot be saved.
    pub fn remember_testing_environment(&self, environment_id: Uuid, key: String) -> Result<()> {
        let mut credentials = store::load_credentials()?;
        credentials.set_testing_environment_key(&self.profile_name, environment_id, key);
        store::save_credentials(&credentials)
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

    /// Resolves a local or already-qualified Application identifier.
    ///
    /// A person working inside one organization should not have to remember
    /// that create accepts `billing` while every later command historically
    /// required `acme>billing`. Qualified identifiers remain unchanged for
    /// cross-organization protocol calls; local ones use the active org.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NoOrganization`] when `value` is local and no
    /// organization is selected.
    pub fn application_id(&self, value: &str) -> Result<String> {
        if value.contains('>') {
            Ok(value.to_owned())
        } else {
            Ok(format!("{}>{value}", self.organization()?))
        }
    }

    /// Returns the local part accepted by Application creation.
    ///
    /// # Errors
    ///
    /// Returns a usage error when a supplied qualified id names a different
    /// organization than the create request.
    #[allow(
        clippy::unused_self,
        reason = "identifier normalization belongs to the invocation context API"
    )]
    pub fn local_application_id(&self, value: &str, organization: &str) -> Result<String> {
        let Some((qualified_org, local_id)) = value.split_once('>') else {
            return Ok(value.to_owned());
        };
        if value.matches('>').count() != 1 || qualified_org != organization {
            return Err(CliError::Usage(format!(
                "Application ID `{value}` does not belong to organization `{organization}`"
            )));
        }
        Ok(local_id.to_owned())
    }

    /// Resolves the local handle and owning organization used for Application
    /// creation.
    ///
    /// A canonical `organization>application` identifier supplies its own
    /// organization on a fresh profile. When an organization is selected, it
    /// remains a guard against creating the Application in the wrong tenant.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NoOrganization`] for a local handle without an active
    /// organization, or a usage error for a malformed or mismatched canonical
    /// identifier.
    pub fn application_creation_identity(&self, value: &str) -> Result<(String, String)> {
        let Some((organization, local_id)) = value.split_once('>') else {
            return Ok((value.to_owned(), self.organization()?.to_owned()));
        };
        if value.matches('>').count() != 1 || organization.is_empty() || local_id.is_empty() {
            return Err(CliError::Usage(format!(
                "Application ID `{value}` must have the form organization>application"
            )));
        }
        if let Some(selected) = self.organization_if_set()
            && selected != organization
        {
            return Err(CliError::Usage(format!(
                "Application ID `{value}` does not belong to organization `{selected}`"
            )));
        }
        let local_id = self.local_application_id(value, organization)?;
        Ok((local_id, organization.to_owned()))
    }

    /// Resolves a local or global Silicon identifier inside `organization`.
    ///
    /// # Errors
    ///
    /// Returns a usage error when a global id carries a different org suffix.
    #[allow(
        clippy::unused_self,
        reason = "identifier normalization belongs to the invocation context API"
    )]
    pub fn silicon_id(&self, value: &str, organization: &str) -> Result<String> {
        let Some((handle, suffix)) = value.rsplit_once(':') else {
            return Ok(format!("{value}:{organization}"));
        };
        if value.matches(':').count() != 1 || suffix != organization {
            return Err(CliError::Usage(format!(
                "Silicon ID `{value}` does not belong to organization `{organization}`"
            )));
        }
        Ok(format!("{handle}:{suffix}"))
    }

    /// Resolves the Silicon ID and organization needed for authentication.
    ///
    /// A canonical Silicon ID already contains its organization, so a fresh
    /// profile does not need a separately configured `--org` merely to sign
    /// that Silicon in. When an organization is active, it remains an
    /// important guard against accidentally using a credential in the wrong
    /// scope.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NoOrganization`] for a local handle without an
    /// active organization, or a usage error for a malformed or mismatched
    /// canonical ID.
    pub fn silicon_identity(&self, value: &str) -> Result<(String, String)> {
        let Some((handle, suffix)) = value.rsplit_once(':') else {
            let organization = self.organization()?;
            return Ok((
                self.silicon_id(value, organization)?,
                organization.to_owned(),
            ));
        };
        if value.matches(':').count() != 1 || handle.is_empty() || suffix.is_empty() {
            return Err(CliError::Usage(format!(
                "Silicon ID `{value}` must have the form handle:organization"
            )));
        }
        if let Some(organization) = self.organization_if_set() {
            return Ok((
                self.silicon_id(value, organization)?,
                organization.to_owned(),
            ));
        }
        Ok((value.to_owned(), suffix.to_owned()))
    }

    /// Returns the local handle accepted by Silicon creation.
    ///
    /// # Errors
    ///
    /// Returns a usage error when a supplied global id carries a different
    /// organization suffix.
    pub fn local_silicon_id(&self, value: &str, organization: &str) -> Result<String> {
        let global = self.silicon_id(value, organization)?;
        global
            .rsplit_once(':')
            .map(|(handle, _)| handle.to_owned())
            .ok_or_else(|| CliError::Usage(format!("Silicon ID `{value}` is invalid")))
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
        let key = if let Some(key) = session.pending_refresh_key.as_deref() {
            IdempotencyKey::parse(key.to_owned())?
        } else {
            let key = IdempotencyKey::generate();
            let mut pending = session.clone();
            pending.pending_refresh_key = Some(key.as_str().to_owned());
            self.remember(pending)?;
            key
        };
        let tokens = self
            .client
            .auth()
            .refresh(&session.refresh_token, &Mutation::with_key(key))
            .await?;
        let renewed = renewed_session(&tokens, session);
        self.remember(renewed.clone())?;
        Ok(renewed)
    }
}

fn renewed_session(
    tokens: &silicon_iam_client::models::IamTokenResponse,
    previous: &Session,
) -> Session {
    crate::commands::auth::session_from_actor(tokens, &previous.actor_id, previous.actor_type)
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
    fn local_resource_ids_are_qualified_from_the_active_organization() {
        let mut context = context(None);
        context.organization = Some("tos".to_owned());

        assert_eq!(
            context.application_id("space-station").ok().as_deref(),
            Some("tos>space-station")
        );
        assert_eq!(
            context
                .application_id("other>space-station")
                .ok()
                .as_deref(),
            Some("other>space-station")
        );
        assert_eq!(
            context.silicon_id("builder", "tos").ok().as_deref(),
            Some("builder:tos")
        );
        assert_eq!(
            context.silicon_id("builder:tos", "tos").ok().as_deref(),
            Some("builder:tos")
        );
    }

    #[test]
    fn mismatched_qualified_creation_ids_fail_before_a_request() {
        let context = context(None);
        assert!(
            context
                .local_application_id("other>space-station", "tos")
                .is_err()
        );
        assert!(context.local_silicon_id("builder:other", "tos").is_err());
    }

    #[test]
    fn canonical_silicon_ids_supply_their_org_on_a_fresh_profile() {
        let context = context(None);
        assert_eq!(
            context.silicon_identity("builder:tos").ok(),
            Some(("builder:tos".to_owned(), "tos".to_owned()))
        );
        assert!(matches!(
            context.silicon_identity("builder"),
            Err(CliError::NoOrganization)
        ));
    }

    #[test]
    fn active_org_rejects_a_canonical_silicon_from_another_org() {
        let mut context = context(None);
        context.organization = Some("tos".to_owned());

        assert!(context.silicon_identity("builder:other").is_err());
        assert_eq!(
            context.silicon_identity("builder").ok(),
            Some(("builder:tos".to_owned(), "tos".to_owned()))
        );
    }

    #[test]
    fn refresh_replacement_preserves_a_silicon_session_actor() {
        let previous = Session {
            access_token: "sat_old".to_owned(),
            refresh_token: "rft_old".to_owned(),
            expires_at: OffsetDateTime::now_utc(),
            actor_type: SessionActor::Silicon,
            actor_id: "builder:tos".to_owned(),
            pending_refresh_key: None,
            pending_logout: None,
        };
        let tokens = models::IamTokenResponse {
            access_token: "sat_new".to_owned(),
            refresh_token: "rft_new".to_owned(),
            token_type: serde_json::json!("Bearer"),
            expires_in: 1_800,
            refresh_expires_at: OffsetDateTime::now_utc() + time::Duration::days(900),
            actor: models::ActorRef {
                principal_id: Uuid::from_u128(1),
                type_field: models::ActorRefType::Silicon,
                public_id: "builder:tos".to_owned(),
            },
            session_id: Uuid::from_u128(2),
        };

        let renewed = renewed_session(&tokens, &previous);
        assert_eq!(renewed.actor_type, SessionActor::Silicon);
        assert_eq!(renewed.actor_id, "builder:tos");
        assert_eq!(renewed.access_token, "sat_new");
        assert_eq!(renewed.refresh_token, "rft_new");
    }
}
