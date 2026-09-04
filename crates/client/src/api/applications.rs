//! Applications: their public base URLs, credentials, OBO surface, and webhook.

use crate::{Client, Error, Mutation, Paging, Result, models};

/// Application management. Applications are organization-owned, and these
/// routes need a direct Carbon token with owner or admin membership in the
/// owning organization.
pub struct Applications<'a>(pub(super) &'a Client);

impl Applications<'_> {
    /// Applications the caller can administer.
    ///
    /// # Errors
    ///
    /// Returns an error when the request fails.
    pub async fn list(
        &self,
        status: Option<&str>,
        paging: &Paging,
    ) -> Result<models::ApplicationPage> {
        let mut query = paging.query();
        if let Some(status) = status {
            query.push(("status", status.to_owned()));
        }
        self.0.get_with(&["applications"], &query).await
    }

    /// Registers an immediately usable application, returning both one-time secrets.
    ///
    /// In production, only the submitted webhook destination remains pending
    /// platform review. A testing environment activates it immediately because
    /// that isolated plane has no platform reviewer. Store the returned client
    /// and webhook signing secrets before their ten-minute replay window closes.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier is taken or a field is rejected.
    pub async fn create(
        &self,
        input: &models::ApplicationCreate,
        mutation: &Mutation,
    ) -> Result<models::ApplicationCreated> {
        self.0.post(&["applications"], input, mutation).await
    }

    /// One application.
    ///
    /// # Errors
    ///
    /// Returns an error when the application does not exist, or the caller
    /// cannot administer it.
    pub async fn get(&self, app_id: &str) -> Result<models::Application> {
        self.0.get(&["applications", app_id]).await
    }

    /// Discovers a verified application's public backend base URL.
    ///
    /// This intentionally crosses organization boundaries. The client must
    /// carry the requesting application's own
    /// [`Credential::Application`](crate::Credential::Application); the
    /// target is the canonical `{org_id}>{handle}` id.
    ///
    /// Inside a testing environment, both the requesting credential and the
    /// target resolve only in that environment.
    ///
    /// # Errors
    ///
    /// Returns an error when the requesting application cannot authenticate,
    /// or the target is not a verified application in the selected plane.
    pub async fn discover_base_url(&self, app_id: &str) -> Result<models::ApplicationBaseUrl> {
        self.0.get(&["application-directory", app_id]).await
    }

    /// Updates an application's configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when `version` is stale or a field is rejected.
    pub async fn update(
        &self,
        app_id: &str,
        version: i64,
        patch: &models::ApplicationPatch,
        mutation: &Mutation,
    ) -> Result<models::Application> {
        self.0
            .patch(&["applications", app_id], version, patch, mutation)
            .await
    }

    /// Rotates the client secret, returning the new one once.
    ///
    /// Requires a step-up assertion. The previous secret stops working when
    /// the response is committed, so store the new one before reconfiguring
    /// anything that uses it.
    ///
    /// # Errors
    ///
    /// Returns an error when `version` is stale or the step-up is missing.
    pub async fn rotate_secret(
        &self,
        app_id: &str,
        version: i64,
        mutation: &Mutation,
    ) -> Result<models::ApplicationSecretRotated> {
        self.0
            .post_versioned(
                &["applications", app_id, "client-secret-rotations"],
                version,
                &serde_json::json!({}),
                mutation,
            )
            .await
    }

    /// Rotates the webhook signing secret, returning its successor once.
    ///
    /// Requires a verified-channel step-up assertion for
    /// `application.webhook_secret.rotate`. New deliveries use the returned
    /// version; keep older versions until their in-flight delivery window has
    /// closed.
    ///
    /// # Errors
    ///
    /// Returns an error when `version` is stale or the step-up is missing.
    pub async fn rotate_webhook_secret(
        &self,
        app_id: &str,
        version: i64,
        mutation: &Mutation,
    ) -> Result<models::ApplicationWebhookSecretRotated> {
        self.0
            .post_versioned(
                &["applications", app_id, "webhook-secret-rotations"],
                version,
                &serde_json::json!({}),
                mutation,
            )
            .await
    }

    /// Imports a production application into the selected testing environment.
    ///
    /// This route exists only in a testing context. The production application
    /// contributes its canonical id, base URL, webhook URL, and OBO surface;
    /// the response never exposes its production webhook signing secret.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] before sending when this client was not
    /// configured with [`Client::with_environment`].
    pub async fn import_from_production(
        &self,
        app_id: &str,
        mutation: &Mutation,
    ) -> Result<models::TestingApplicationImported> {
        if self.0.environment().is_none() {
            return Err(Error::Invalid(
                "application import is only possible in a testing environment; configure the client with Client::with_environment".to_owned(),
            ));
        }
        self.0
            .post(
                &["testing-environment", "applications", "imports"],
                &models::TestingApplicationImport {
                    app_id: app_id.to_owned(),
                },
                mutation,
            )
            .await
    }

    /// The application's webhook endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when no endpoint is configured.
    pub async fn webhook(&self, app_id: &str) -> Result<models::ApplicationWebhook> {
        self.0.get(&["applications", app_id, "webhook"]).await
    }

    /// Replaces a webhook endpoint.
    ///
    /// Production proposes it for platform review; a testing environment
    /// activates it immediately because that isolated plane has no reviewer.
    ///
    /// The response normally contains no secret. When this is the first URL
    /// replacement for an imported test application still using an inherited
    /// production key, `webhook_signing_secret` and
    /// `secret_replay_expires_at` contain its new test-only key once.
    ///
    /// # Errors
    ///
    /// Returns an error when `version` is stale or the URL is rejected.
    pub async fn replace_webhook(
        &self,
        app_id: &str,
        version: i64,
        input: &models::ApplicationWebhookReplace,
        mutation: &Mutation,
    ) -> Result<models::ApplicationWebhook> {
        self.0
            .put(
                &["applications", app_id, "webhook"],
                version,
                input,
                mutation,
            )
            .await
    }

    /// Deliveries that exhausted their retries.
    ///
    /// # Errors
    ///
    /// Returns an error when no endpoint is configured.
    pub async fn dead_letters(
        &self,
        app_id: &str,
        paging: &Paging,
    ) -> Result<models::WebhookDeadLetterPage> {
        self.0
            .get_with(
                &["applications", app_id, "webhook", "dead-letters"],
                &paging.query(),
            )
            .await
    }

    /// Re-queues dead-lettered deliveries.
    ///
    /// # Errors
    ///
    /// Returns an error when a named delivery is not dead-lettered here.
    pub async fn replay_dead_letters(
        &self,
        app_id: &str,
        request: &models::WebhookReplayRequest,
        mutation: &Mutation,
    ) -> Result<models::WebhookReplayResponse> {
        self.0
            .post(
                &["applications", app_id, "webhook", "dead-letters", "replays"],
                request,
                mutation,
            )
            .await
    }

    /// Logins performed through this application.
    ///
    /// # Errors
    ///
    /// Returns an error when the caller cannot administer the application.
    pub async fn login_history(
        &self,
        app_id: &str,
        paging: &Paging,
    ) -> Result<models::LoginEventPage> {
        self.0
            .get_with(&["applications", app_id, "login-history"], &paging.query())
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::{Client, Error, Mutation};

    #[tokio::test]
    async fn production_clients_refuse_the_test_only_import_before_sending() {
        let Ok(client) = Client::new("https://example.test") else {
            panic!("a valid client must build");
        };
        let error = client
            .applications()
            .import_from_production("acme>billing", &Mutation::new())
            .await;
        assert!(
            matches!(error, Err(Error::Invalid(message)) if message.contains("only possible in a testing environment"))
        );
    }
}
