//! Creating a Carbon.
//!
//! Signup binds a verified email and a verified phone number to one temporary
//! session, then exchanges that session for an account:
//!
//! ```text
//! start -> send email code -> verify -> send phone code -> verify -> complete
//! ```
//!
//! Each send reports whether the identity already belongs to a Carbon; when it
//! does, no code is sent and there is nothing to verify.

use serde::Serialize;
use uuid::Uuid;

use crate::{Client, Mutation, Result, models};

/// The signup flow. None of these routes need a credential.
pub struct Signup<'a>(pub(super) &'a Client);

#[derive(Serialize)]
struct Code<'a> {
    code: &'a str,
}

impl Signup<'_> {
    /// Whether a Carbon ID can still be claimed.
    ///
    /// A positive answer reserves nothing; the claim happens at completion.
    ///
    /// # Errors
    ///
    /// Returns an error when the request fails.
    pub async fn carbon_id_available(&self, carbon_id: &str) -> Result<models::Availability> {
        self.0.get(&["carbon-ids", carbon_id, "availability"]).await
    }

    /// Opens a signup session. It lives for 48 hours.
    ///
    /// # Errors
    ///
    /// Returns an error when the request fails.
    pub async fn start(&self, mutation: &Mutation) -> Result<models::AuthSession> {
        self.0
            .post(&["signup", "sessions"], &serde_json::json!({}), mutation)
            .await
    }

    /// Sends a verification code to an email address.
    ///
    /// # Errors
    ///
    /// Returns an error when the address is rejected or delivery fails.
    pub async fn send_email_code(
        &self,
        session: Uuid,
        email: &str,
        mutation: &Mutation,
    ) -> Result<models::CodeDispatchResult> {
        self.0
            .post(
                &["signup", "sessions", &session.to_string(), "email"],
                &models::EmailInput {
                    email: email.to_owned(),
                },
                mutation,
            )
            .await
    }

    /// Verifies the emailed code.
    ///
    /// # Errors
    ///
    /// Returns an error when the code is wrong, expired, or exhausted.
    pub async fn verify_email(&self, session: Uuid, code: &str, mutation: &Mutation) -> Result<()> {
        self.0
            .post_empty(
                &[
                    "signup",
                    "sessions",
                    &session.to_string(),
                    "email",
                    "verify",
                ],
                &Code { code },
                mutation,
            )
            .await
    }

    /// Sends a verification code to a phone number, in E.164 form.
    ///
    /// # Errors
    ///
    /// Returns an error when the number is rejected or delivery fails.
    pub async fn send_phone_code(
        &self,
        session: Uuid,
        phone_number: &str,
        mutation: &Mutation,
    ) -> Result<models::CodeDispatchResult> {
        self.0
            .post(
                &["signup", "sessions", &session.to_string(), "phone"],
                &models::PhoneInput {
                    phone_number: phone_number.to_owned(),
                },
                mutation,
            )
            .await
    }

    /// Verifies the texted code.
    ///
    /// # Errors
    ///
    /// Returns an error when the code is wrong, expired, or exhausted.
    pub async fn verify_phone(&self, session: Uuid, code: &str, mutation: &Mutation) -> Result<()> {
        self.0
            .post_empty(
                &[
                    "signup",
                    "sessions",
                    &session.to_string(),
                    "phone",
                    "verify",
                ],
                &Code { code },
                mutation,
            )
            .await
    }

    /// Creates the Carbon. Both contacts must already be verified.
    ///
    /// # Errors
    ///
    /// Returns an error when a contact is unverified, or the Carbon ID was
    /// taken between the availability check and here.
    pub async fn complete(
        &self,
        session: Uuid,
        profile: &models::CarbonSignupComplete,
        mutation: &Mutation,
    ) -> Result<models::CarbonSelf> {
        self.0
            .post(
                &["signup", "sessions", &session.to_string(), "complete"],
                profile,
                mutation,
            )
            .await
    }
}
