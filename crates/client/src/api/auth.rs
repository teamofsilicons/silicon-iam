//! Logging in, refreshing, logging out, and stepping up.

use uuid::Uuid;

use crate::{Client, Mutation, Result, models};

/// Authentication. The login and refresh routes need no credential; step-up
/// and logout act on an existing session.
pub struct Auth<'a>(pub(super) &'a Client);

impl Auth<'_> {
    /// Starts a Carbon login by email, phone number, or Carbon ID.
    ///
    /// Answers with a challenge session, not a token. The response is
    /// deliberately identical whether or not the identity exists, so it says
    /// nothing about who is registered.
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
    /// Pass the token to [`Mutation::step_up`](crate::Mutation::step_up) on the
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
}
