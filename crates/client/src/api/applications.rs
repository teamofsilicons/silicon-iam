//! Applications: their registration, secrets, redirect URIs, and webhook.

use uuid::Uuid;

use crate::{Client, Mutation, Paging, Result, models};

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

    /// Registers an application, returning its one-time client secret.
    ///
    /// The application starts under review; it cannot complete a login until
    /// the platform verifies it.
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

    /// The application's registered redirect URIs.
    ///
    /// # Errors
    ///
    /// Returns an error when the caller cannot administer the application.
    pub async fn redirect_uris(
        &self,
        app_id: &str,
        paging: &Paging,
    ) -> Result<models::ApplicationRedirectUriPage> {
        self.0
            .get_with(&["applications", app_id, "redirect-uris"], &paging.query())
            .await
    }

    /// Registers a redirect URI.
    ///
    /// # Errors
    ///
    /// Returns an error when `version` is stale or the URI is rejected.
    pub async fn add_redirect_uri(
        &self,
        app_id: &str,
        version: i64,
        input: &models::ApplicationRedirectUriCreate,
        mutation: &Mutation,
    ) -> Result<models::ApplicationRedirectUriMutation> {
        self.0
            .post_versioned(
                &["applications", app_id, "redirect-uris"],
                version,
                input,
                mutation,
            )
            .await
    }

    /// Retires a redirect URI.
    ///
    /// # Errors
    ///
    /// Returns an error when `version` is stale or the URI is already retired.
    pub async fn retire_redirect_uri(
        &self,
        app_id: &str,
        redirect_uri_id: Uuid,
        version: i64,
        mutation: &Mutation,
    ) -> Result<models::ApplicationRedirectUriMutation> {
        let request = mutation
            .apply(self.0.route(
                reqwest::Method::DELETE,
                &[
                    "applications",
                    app_id,
                    "redirect-uris",
                    &redirect_uri_id.to_string(),
                ],
            )?)
            .header(reqwest::header::IF_MATCH, format!("\"{version}\""));
        self.0.send_json(request).await
    }

    /// The application's webhook endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when no endpoint is configured.
    pub async fn webhook(&self, app_id: &str) -> Result<models::ApplicationWebhook> {
        self.0.get(&["applications", app_id, "webhook"]).await
    }

    /// Proposes a webhook endpoint. The service verifies it before activating.
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
