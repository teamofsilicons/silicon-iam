//! The OAuth endpoints an application calls as itself.
//!
//! All three authenticate with the application's own credential, so build the
//! client with [`Credential::application`](crate::Credential::application).
//! The browser-facing authorization screen is deliberately absent: it belongs
//! to the browser, not to an API caller.

use crate::{Client, Mutation, Result, models};

/// Token exchange, introspection, and revocation.
pub struct OAuth<'a>(pub(super) &'a Client);

impl OAuth<'_> {
    /// Exchanges an authorization code or refresh token for tokens.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant is invalid, expired, or already used.
    pub async fn token(
        &self,
        request: &models::OAuthTokenRequest,
        mutation: &Mutation,
    ) -> Result<models::OAuthTokenResponse> {
        self.0.post(&["oauth", "token"], request, mutation).await
    }

    /// Asks the service what a token currently authorizes.
    ///
    /// Authoritative and live: it reflects revocation immediately, which is
    /// why a consumer should introspect rather than trust a cached claim.
    ///
    /// # Errors
    ///
    /// Returns an error when the request fails. An unknown or revoked token is
    /// not an error -- it answers with `active: false`.
    pub async fn introspect(
        &self,
        request: &models::TokenIntrospectionRequest,
        org_context: Option<&str>,
    ) -> Result<models::TokenIntrospection> {
        let mut built = self
            .0
            .route(reqwest::Method::POST, &["oauth", "introspect"])?;
        if let Some(org_id) = org_context {
            built = built.header("x-org-id", org_id);
        }
        self.0.send_json(built.json(request)).await
    }

    /// Revokes a token, and the family it belongs to.
    ///
    /// # Errors
    ///
    /// Returns an error when the request fails. Revoking an unknown token is
    /// deliberately not an error.
    pub async fn revoke(
        &self,
        request: &models::OAuthRevocationRequest,
        mutation: &Mutation,
    ) -> Result<()> {
        self.0
            .post_empty(&["oauth", "revoke"], request, mutation)
            .await
    }
}
