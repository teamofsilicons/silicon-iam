//! The endpoints an application calls as itself.
//!
//! All three authenticate with the application's own credential, so build the
//! client with [`Credential::application`](crate::Credential::application).
//! The browser-facing login screen is deliberately absent: it belongs to the
//! browser, not to an API caller.

use crate::{Client, Mutation, Result, models};

/// Token exchange, introspection, and revocation.
pub struct OAuth<'a>(pub(super) &'a Client);

impl OAuth<'_> {
    /// Logs a principal in to this Application with a short-lived token.
    ///
    /// This is the only Application-login entry point. The Application never
    /// receives or submits the principal's OTP or any other authentication
    /// credential; IAM completes that ceremony and hands the Application the
    /// single-use `slt`.
    ///
    /// # Errors
    ///
    /// Returns an error when the short-lived token is invalid, expired, spent,
    /// or was issued for a different Application.
    pub async fn login(
        &self,
        app_id: &str,
        slt: &str,
        mutation: &Mutation,
    ) -> Result<models::OAuthTokenResponse> {
        self.exchange(&application_login_request(app_id, slt), mutation)
            .await
    }

    /// Rotates an Application refresh token after a successful login.
    ///
    /// Refresh is deliberately separate from [`Self::login`]: a refresh token
    /// can continue an existing session, but it cannot begin an Application
    /// login and is never accepted in the login method.
    ///
    /// # Errors
    ///
    /// Returns an error when the refresh token is invalid, expired, spent, or
    /// belongs to a different Application.
    pub async fn refresh(
        &self,
        app_id: &str,
        refresh_token: &str,
        mutation: &Mutation,
    ) -> Result<models::OAuthTokenResponse> {
        self.exchange(
            &application_refresh_request(app_id, refresh_token),
            mutation,
        )
        .await
    }

    /// Asks the service what a token currently authorizes.
    ///
    /// Authoritative and live: it reflects revocation immediately, which is
    /// why a consumer should introspect rather than trust a cached claim. When
    /// supplied, `org_context` must be one valid organization handle and an
    /// exact match for the token; a mismatch answers with `active: false`.
    ///
    /// # Errors
    ///
    /// Returns an error when the request fails or `org_context` is malformed.
    /// An unknown, revoked, or organization-mismatched token is not an error --
    /// it answers with `active: false`.
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
        self.0.send_json(built.form(request)).await
    }

    /// Fetches the live authorization snapshot for an Application access token.
    ///
    /// Call immediately after login, or to rebuild an empty local projection.
    /// No directory edit or webhook arrival is necessary. `None` means there
    /// is no current organization authority (inactive, wrong application or
    /// organization, refresh token, or unscoped session). Undisclosed roles or
    /// tags remain `None`; never turn them into extra privileges.
    ///
    /// # Errors
    ///
    /// Returns an error when introspection fails or its response is malformed.
    pub async fn authorization(
        &self,
        access_token: &str,
        org_context: Option<&str>,
    ) -> Result<Option<models::ApplicationAuthorization>> {
        let inspected = self
            .introspect(
                &models::TokenIntrospectionRequest {
                    token: access_token.to_owned(),
                    token_type_hint: Some(
                        models::TokenIntrospectionRequestTokenTypeHint::AccessToken,
                    ),
                },
                org_context,
            )
            .await?;
        if inspected.active
            && access_token.starts_with("oat_")
            && inspected.membership_id.is_some()
            && inspected.authorization.is_none()
        {
            return Err(crate::Error::Decode(
                "IAM returned an active organization-bound access token without its authorization snapshot; deploy an API version supporting authorization snapshots before using this method".to_owned(),
            ));
        }
        Ok(if inspected.active {
            inspected.authorization
        } else {
            None
        })
    }

    /// Revokes one access token, or the complete family of a refresh token.
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
        let request = mutation
            .apply(self.0.route(reqwest::Method::POST, &["oauth", "revoke"])?)
            .form(request);
        self.0.send_empty(request).await
    }

    async fn exchange(
        &self,
        request: &models::ApplicationTokenRequest,
        mutation: &Mutation,
    ) -> Result<models::OAuthTokenResponse> {
        let request = mutation
            .apply(
                self.0
                    .route(reqwest::Method::POST, &["app-auth", "tokens"])?,
            )
            .form(request);
        self.0.send_json(request).await
    }
}

fn application_login_request(app_id: &str, slt: &str) -> models::ApplicationTokenRequest {
    models::ApplicationTokenRequest {
        app_id: app_id.to_owned(),
        slt: Some(slt.to_owned()),
        refresh_token: None,
    }
}

fn application_refresh_request(
    app_id: &str,
    refresh_token: &str,
) -> models::ApplicationTokenRequest {
    models::ApplicationTokenRequest {
        app_id: app_id.to_owned(),
        slt: None,
        refresh_token: Some(refresh_token.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{application_login_request, application_refresh_request};

    #[test]
    fn application_login_can_only_submit_an_slt() {
        let request = application_login_request("acme>checkout", "slt_example");
        assert_eq!(request.app_id, "acme>checkout");
        assert_eq!(request.slt.as_deref(), Some("slt_example"));
        assert_eq!(request.refresh_token, None);
    }

    #[test]
    fn application_refresh_cannot_begin_a_login() {
        let request = application_refresh_request("acme>checkout", "ort_example");
        assert_eq!(request.app_id, "acme>checkout");
        assert_eq!(request.slt, None);
        assert_eq!(request.refresh_token.as_deref(), Some("ort_example"));
    }
}
