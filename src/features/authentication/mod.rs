//! Carbon signup, passwordless authentication, and session lifecycle.

mod contacts;
mod database;
mod delivery;
mod directory;
mod events;
mod http;
mod idempotency;
mod login;
mod model;
mod otp;
mod refresh;
mod sessions;
mod signup;
mod silicon;
mod step_up;
mod tokens;
mod validation;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::api::ApiState;

/// Credential class that legitimately initiated a Carbon's global logout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogoutTrigger {
    /// The Carbon used an IAM bearer or browser session directly.
    FirstPartyCarbon,
    /// A reviewed Application used its Carbon-bound OAuth access token.
    Application {
        application_id: uuid::Uuid,
        access_token_id: uuid::Uuid,
    },
}

/// Whether the presented logout credential can execute a fresh mutation or
/// can only locate an exact response committed while it was authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogoutCredentialState {
    Active,
    ReplayOnly,
}

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
            "/api/v1/carbons/resolve/email",
            post(directory::resolve_email),
        )
        .route(
            "/api/v1/carbons/resolve/phone",
            post(directory::resolve_phone),
        )
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
        .route("/api/v1/silicon-auth/token", post(silicon::authenticate))
        .route("/api/v1/logout", post(http::logout))
        .route("/api/v1/me/sessions", get(http::list_sessions))
        .route(
            "/api/v1/me/sessions/{session_id}",
            delete(http::revoke_session),
        )
        .route("/api/v1/me/login-history", get(http::login_history))
}
