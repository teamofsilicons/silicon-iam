//! Carbon signup, passwordless authentication, and session lifecycle.

mod contact_change;
mod contacts;
mod database;
mod directory;
mod events;
mod http;
mod idempotency;
mod login;
mod model;
mod otp;
mod passkeys;
mod refresh;
mod sessions;
mod signup;
mod silicon;
mod step_up;
mod token_management;
mod tokens;
mod validation;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::api::ApiState;

/// Builds the Carbon authentication feature router.
pub(crate) fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/signup/sessions", post(http::create_signup_session))
        .route(
            "/api/v1/signup/sessions/{session_id}/email",
            post(http::start_signup_email),
        )
        .route(
            "/api/v1/signup/sessions/{session_id}/email/verify",
            post(http::verify_signup_email),
        )
        .route(
            "/api/v1/signup/sessions/{session_id}/phone",
            post(http::start_signup_phone),
        )
        .route(
            "/api/v1/signup/sessions/{session_id}/phone/verify",
            post(http::verify_signup_phone),
        )
        .route(
            "/api/v1/signup/sessions/{session_id}/complete",
            post(http::complete_signup),
        )
        .route(
            "/api/v1/carbon-ids/{carbon_id}/availability",
            get(http::carbon_id_availability),
        )
        .route("/api/v1/carbons/search", get(directory::search))
        .route(
            "/api/v1/login/challenges",
            post(http::create_login_challenge),
        )
        .route(
            "/api/v1/login/challenges/{session_id}/verify",
            post(http::verify_login_challenge),
        )
        .route(
            "/api/v1/step-up/challenges",
            post(http::create_step_up_challenge),
        )
        .route(
            "/api/v1/step-up/challenges/{session_id}/verify",
            post(http::verify_step_up_challenge),
        )
        .route("/api/v1/auth/tokens/refresh", post(http::refresh_tokens))
        .route(
            "/api/v1/auth/tokens/introspect",
            post(token_management::introspect),
        )
        .route("/api/v1/auth/tokens/revoke", post(token_management::revoke))
        .route("/api/v1/silicon-auth/token", post(silicon::authenticate))
        .route("/api/v1/me/passkeys", get(passkeys::list))
        .route(
            "/api/v1/me/passkeys/registration-options",
            post(passkeys::registration_options),
        )
        .route(
            "/api/v1/me/passkeys/registrations",
            post(passkeys::complete_registration),
        )
        .route(
            "/api/v1/me/passkeys/{credential_id}",
            delete(passkeys::revoke),
        )
        .route(
            "/api/v1/step-up/passkey/options",
            post(passkeys::step_up_options),
        )
        .route(
            "/api/v1/step-up/passkey/verify",
            post(passkeys::verify_step_up),
        )
        .route("/api/v1/logout", post(http::logout))
        .route("/api/v1/me/sessions", get(http::list_sessions))
        .route(
            "/api/v1/me/sessions/{session_id}",
            delete(http::revoke_session),
        )
        .route("/api/v1/me/login-history", get(http::login_history))
        .route(
            "/api/v1/me/email-change/sessions",
            post(contact_change::start_email),
        )
        .route(
            "/api/v1/me/email-change/sessions/{session_id}/verify",
            post(contact_change::verify_email),
        )
        .route(
            "/api/v1/me/phone-change/sessions",
            post(contact_change::start_phone),
        )
        .route(
            "/api/v1/me/phone-change/sessions/{session_id}/verify",
            post(contact_change::verify_phone),
        )
}
