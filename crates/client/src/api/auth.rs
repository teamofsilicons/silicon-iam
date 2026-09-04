//! Logging in, refreshing, logging out, and stepping up.

use uuid::Uuid;

use crate::{Client, Mutation, Result, models};

/// Direct IAM session maintenance and step-up.
///
/// Application login is deliberately not part of this group. Applications
/// use [`crate::api::oauth::OAuth::login`], whose only login credential is an
/// SLT. The IAM CLI's own first-party session ceremony is compiled separately
/// behind the `cli-session` feature.
pub struct Auth<'a>(pub(super) &'a Client);

impl Auth<'_> {
    #[cfg(feature = "cli-session")]
    #[doc(hidden)]
    /// Starts a Carbon login by email, phone number, or Carbon ID.
    ///
    /// Answers with a challenge session, not a token. An unknown identity is
    /// reported as not found; callers must not use this route as a public
    /// account-discovery surface.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier is malformed or the request fails.
    pub async fn start_login(
        &self,
        identity: &models::LoginChallengeCreate,
        mutation: &Mutation,
    ) -> Result<models::AuthSession> {
        self.0
            .post(&["login", "challenges"], identity, mutation)
            .await
    }

    #[cfg(feature = "cli-session")]
    #[doc(hidden)]
    /// Completes a login, exchanging the code for tokens.
    ///
    /// # Errors
    ///
    /// Returns an error when the code is wrong, expired, or exhausted.
    pub async fn verify_login(
        &self,
        session: Uuid,
        code: &str,
        mutation: &Mutation,
    ) -> Result<models::IamTokenResponse> {
        self.0
            .post(
                &["login", "challenges", &session.to_string(), "verify"],
                &serde_json::json!({ "code": code }),
                mutation,
            )
            .await
    }

    /// Exchanges a refresh token for a new pair.
    ///
    /// Refresh tokens rotate: the presented one is consumed. Store the new one
    /// before using the access token, or a crash in between loses the session.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is unknown, already used, or revoked.
    pub async fn refresh(
        &self,
        refresh_token: &str,
        mutation: &Mutation,
    ) -> Result<models::IamTokenResponse> {
        self.0
            .post(
                &["auth", "tokens", "refresh"],
                &models::RefreshTokenRequest {
                    refresh_token: refresh_token.to_owned(),
                },
                mutation,
            )
            .await
    }

    /// Authenticates a Silicon with its own long-lived credential.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential is unknown or revoked.
    pub async fn authenticate_silicon(
        &self,
        request: &models::SiliconAuthenticationRequest,
        mutation: &Mutation,
    ) -> Result<models::IamTokenResponse> {
        self.0
            .post(&["silicon-auth", "token"], request, mutation)
            .await
    }

    /// Ends the current session, or every session, per the request's mode.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential is not one logout accepts.
    pub async fn logout(&self, request: &models::LogoutRequest, mutation: &Mutation) -> Result<()> {
        self.0.post_empty(&["logout"], request, mutation).await
    }

    /// Starts a step-up challenge for one action.
    ///
    /// The routes that change authority or reveal a credential require the
    /// assertion this produces. It is bound to the action and resource asked
    /// for here, so it cannot be spent on a different one.
    ///
    /// # Errors
    ///
    /// Returns an error when the action is not one that supports step-up.
    pub async fn start_step_up(
        &self,
        request: &models::StepUpChallengeCreate,
        mutation: &Mutation,
    ) -> Result<models::AuthSession> {
        self.0
            .post(&["step-up", "challenges"], request, mutation)
            .await
    }

    /// Completes a step-up challenge, yielding a short-lived assertion.
    ///
    /// Pass the token to [`Mutation::step_up`] on the
    /// call that needs it.
    ///
    /// # Errors
    ///
    /// Returns an error when the code is wrong, expired, or exhausted.
    pub async fn verify_step_up(
        &self,
        session: Uuid,
        code: &str,
        mutation: &Mutation,
    ) -> Result<models::StepUpTokenResponse> {
        self.0
            .post(
                &["step-up", "challenges", &session.to_string(), "verify"],
                &serde_json::json!({ "code": code }),
                mutation,
            )
            .await
    }

    /// Gets a short-lived token for an application while already signed in.
    ///
    /// A Silicon has no browser to be redirected in, and a Carbon that already
    /// holds a session should not have to start another one. The application
    /// completes the login with this token exactly as it would one delivered
    /// through a redirect.
    ///
    /// # Errors
    ///
    /// Returns an error when the application is unknown or the caller may not
    /// sign in to it.
    pub async fn short_lived_token(
        &self,
        app_id: &str,
        mutation: &Mutation,
    ) -> Result<models::ShortLivedToken> {
        self.short_lived_token_in_organization(app_id, None, mutation)
            .await
    }

    /// Gets a short-lived token bound to an optional organization membership.
    ///
    /// Supplying `org_id` makes the exchanged Application tokens usable only
    /// in that exact organization and is required before issuing OBO proofs.
    /// The authenticated principal must have an active membership there.
    /// When omitted, the resulting login preserves any organization already
    /// carried by the bearer. A global Carbon session therefore stays
    /// unscoped, while an organization-bound Silicon session stays bound.
    ///
    /// # Errors
    ///
    /// Returns an error when the application is unknown, the organization
    /// handle is invalid, or the caller is not an active member.
    pub async fn short_lived_token_in_organization(
        &self,
        app_id: &str,
        org_id: Option<&str>,
        mutation: &Mutation,
    ) -> Result<models::ShortLivedToken> {
        self.0
            .post(
                &["app-auth", "short-lived-tokens"],
                &models::ShortLivedTokenRequest {
                    app_id: app_id.to_owned(),
                    org_id: org_id.map(ToOwned::to_owned),
                },
                mutation,
            )
            .await
    }
}
