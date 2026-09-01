use std::{num::NonZeroU32, str::FromStr as _, time::Duration};

use axum::{
    Json,
    extract::{Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse as _, Response},
};
use secrecy::SecretString;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    application::ports::{EmailOtp, SmsOtp},
    domain::auth::CarbonId,
    error::AppError,
    infrastructure::{
        browser_session,
        postgres::rate_limit::{self, RateLimitPolicy},
    },
};

use super::{
    contacts,
    database::expired,
    idempotency::IdempotencyKey,
    login,
    model::{
        AvailabilityResponse, ContactChannel, EmailInput, LoginChallengeInput, LoginEventPage,
        LoginVerificationOutcome, LogoutInput, PageQuery, PhoneInput, RefreshInput,
        RefreshMutationOutcome, SessionPage, SignupCompletionInput, StepUpChallengeInput,
        StepUpVerificationOutcome, TokenResponse, VerificationInput, VerificationOutcome,
        VerifiedResponse,
    },
    refresh, sessions, signup, step_up, validation,
};

pub(super) async fn create_signup_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    enforce_limit(
        &state,
        "signup_session_create",
        key.as_secret(),
        20,
        Duration::from_hours(1),
    )
    .await?;
    let response = signup::create_session(&state, &key).await?;
    Ok(no_store_json(StatusCode::CREATED, response))
}

pub(super) async fn start_signup_email(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<EmailInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let contact = validation::email(json_body(payload)?.email)?;
    enforce_contact_limit(&state, "signup_email_start", session_id, &contact).await?;
    let result = signup::start_contact(&state, &key, session_id, contact).await?;
    deliver_one(&state, result.delivery.as_ref()).await;
    Ok(no_store_json(StatusCode::ACCEPTED, result.response))
}

pub(super) async fn start_signup_phone(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<PhoneInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let contact = validation::phone(json_body(payload)?.phone_number)?;
    enforce_contact_limit(&state, "signup_phone_start", session_id, &contact).await?;
    let result = signup::start_contact(&state, &key, session_id, contact).await?;
    deliver_one(&state, result.delivery.as_ref()).await;
    Ok(no_store_json(StatusCode::ACCEPTED, result.response))
}

pub(super) async fn verify_signup_email(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<VerificationInput>, JsonRejection>,
) -> Result<Json<VerifiedResponse>, AppError> {
    verify_signup(
        &state,
        &headers,
        session_id,
        ContactChannel::Email,
        json_body(payload)?,
    )
    .await
}

pub(super) async fn verify_signup_phone(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<VerificationInput>, JsonRejection>,
) -> Result<Json<VerifiedResponse>, AppError> {
    verify_signup(
        &state,
        &headers,
        session_id,
        ContactChannel::Phone,
        json_body(payload)?,
    )
    .await
}

pub(super) async fn complete_signup(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<SignupCompletionInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let input = validation::signup_completion(
        json_body(payload)?,
        state.settings.environment == crate::config::RuntimeEnvironment::Production,
    )?;
    let scope = SecretString::from(session_id.to_string());
    enforce_limit(
        &state,
        "signup_complete",
        &scope,
        10,
        Duration::from_hours(1),
    )
    .await?;
    let response = signup::complete_signup(&state, &key, session_id, input).await?;
    Ok(no_store_json(StatusCode::CREATED, response))
}

pub(super) async fn carbon_id_availability(
    State(state): State<ApiState>,
    Path(value): Path<String>,
) -> Result<Json<AvailabilityResponse>, AppError> {
    let carbon_id = CarbonId::from_str(&value)
        .map_err(|_| validation::validation("carbon_id", "has an invalid format"))?;
    let scope = SecretString::from(carbon_id.as_str().to_owned());
    enforce_limit(
        &state,
        "carbon_id_availability",
        &scope,
        60,
        Duration::from_mins(1),
    )
    .await?;
    let mut transaction = state.pool.begin().await.map_err(|_| AppError::Internal {
        category: "carbon_id_availability_transaction",
    })?;
    let available = contacts::carbon_id_available(&mut transaction, carbon_id.as_str()).await?;
    transaction.commit().await.map_err(|_| AppError::Internal {
        category: "carbon_id_availability_commit",
    })?;
    Ok(Json(AvailabilityResponse { available }))
}

pub(super) async fn create_login_challenge(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: Result<Json<LoginChallengeInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let identifier = validation::login_identifier(json_body(payload)?)?;
    let scope = login_scope(&identifier);
    enforce_limit(
        &state,
        "login_challenge_create",
        &scope,
        5,
        Duration::from_mins(10),
    )
    .await?;
    let result = login::create_challenge(&state, &key, identifier).await?;
    deliver_many(&state, &result.deliveries).await;
    Ok(no_store_json(StatusCode::CREATED, result.response))
}

pub(super) async fn verify_login_challenge(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<VerificationInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let code = validation::verification_code(json_body(payload)?.code)?;
    let scope = SecretString::from(session_id.to_string());
    enforce_limit(
        &state,
        "login_challenge_verify",
        &scope,
        5,
        Duration::from_mins(10),
    )
    .await?;
    match login::verify_challenge(&state, &key, session_id, code).await? {
        LoginVerificationOutcome::Success(response) => login_success_response(&state, response),
        LoginVerificationOutcome::Invalid => Err(invalid_code()),
        LoginVerificationOutcome::Expired => Err(expired()),
    }
}

pub(super) async fn create_step_up_challenge(
    State(state): State<ApiState>,
    Authenticated(context): Authenticated,
    headers: HeaderMap,
    payload: Result<Json<StepUpChallengeInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let input = json_body(payload)?;
    let scope = SecretString::from(format!(
        "{}:{}:{}:{}",
        context.subject.id,
        context.authentication_session_id,
        input.action.database_value(),
        input.channel.database_value(),
    ));
    enforce_limit(
        &state,
        "step_up_challenge_create",
        &scope,
        5,
        Duration::from_mins(10),
    )
    .await?;
    let result = step_up::create_challenge(&state, &context, &key, input).await?;
    deliver_one(&state, result.delivery.as_ref()).await;
    Ok(no_store_json(StatusCode::CREATED, result.response))
}

pub(super) async fn verify_step_up_challenge(
    State(state): State<ApiState>,
    Authenticated(context): Authenticated,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<VerificationInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let code = validation::verification_code(json_body(payload)?.code)?;
    let scope = SecretString::from(format!(
        "{}:{}:{}",
        context.subject.id, context.authentication_session_id, session_id,
    ));
    enforce_limit(
        &state,
        "step_up_challenge_verify",
        &scope,
        5,
        Duration::from_mins(10),
    )
    .await?;
    match step_up::verify_challenge(&state, &context, &key, session_id, code).await? {
        StepUpVerificationOutcome::Success(response) => Ok(no_store_json(StatusCode::OK, response)),
        StepUpVerificationOutcome::Invalid => Err(invalid_code()),
        StepUpVerificationOutcome::Expired => Err(expired()),
    }
}

pub(super) async fn refresh_tokens(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: Result<Json<RefreshInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let token = validation::refresh_token(json_body(payload)?.refresh_token)?;
    enforce_limit(
        &state,
        "refresh_token_rotate",
        &token,
        30,
        Duration::from_mins(1),
    )
    .await?;
    match refresh::rotate(&state, &key, token).await? {
        RefreshMutationOutcome::Success(response) => Ok(no_store_json(StatusCode::OK, response)),
        RefreshMutationOutcome::ReplayRevoked => Err(AppError::Unauthenticated),
    }
}

pub(super) async fn logout(
    State(state): State<ApiState>,
    Authenticated(context): Authenticated,
    headers: HeaderMap,
    payload: Result<Option<Json<LogoutInput>>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let mode = payload
        .map_err(|_| validation::validation("body", "must match the documented JSON schema"))?
        .map_or_default(|Json(input)| input)
        .mode;
    sessions::logout(&state, &context, &key, mode).await?;
    Ok(cleared_browser_session_response())
}

pub(super) async fn list_sessions(
    State(state): State<ApiState>,
    Authenticated(context): Authenticated,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<SessionPage>, AppError> {
    let Query(query) = query.map_err(|_| malformed_query())?;
    let (cursor, limit) = validation::page(query)?;
    Ok(Json(
        sessions::list_sessions(&state, &context, cursor, limit).await?,
    ))
}

pub(super) async fn revoke_session(
    State(state): State<ApiState>,
    Authenticated(context): Authenticated,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    sessions::revoke_session(&state, &context, &key, session_id).await?;
    if session_id == context.authentication_session_id {
        Ok(cleared_browser_session_response())
    } else {
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}

pub(super) async fn login_history(
    State(state): State<ApiState>,
    Authenticated(context): Authenticated,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<LoginEventPage>, AppError> {
    let Query(query) = query.map_err(|_| malformed_query())?;
    let (cursor, limit) = validation::page(query)?;
    Ok(Json(
        sessions::list_login_history(&state, &context, cursor, limit).await?,
    ))
}

async fn verify_signup(
    state: &ApiState,
    headers: &HeaderMap,
    session_id: Uuid,
    channel: ContactChannel,
    input: VerificationInput,
) -> Result<Json<VerifiedResponse>, AppError> {
    let key = IdempotencyKey::from_headers(headers)?;
    let code = validation::verification_code(input.code)?;
    let scope = SecretString::from(format!("{}:{}", session_id, channel.database_value()));
    enforce_limit(
        state,
        "signup_contact_verify",
        &scope,
        5,
        Duration::from_mins(10),
    )
    .await?;
    match signup::verify_contact(state, &key, session_id, channel, code).await? {
        VerificationOutcome::Verified => Ok(Json(VerifiedResponse { verified: true })),
        VerificationOutcome::Invalid => Err(invalid_code()),
        VerificationOutcome::Expired => Err(expired()),
    }
}

async fn enforce_contact_limit(
    state: &ApiState,
    name: &'static str,
    session_id: Uuid,
    contact: &super::model::ValidatedContact,
) -> Result<(), AppError> {
    let (contact_scope, session_scope) = contact_limit_scopes(session_id, contact);
    enforce_limit(
        state,
        name,
        &SecretString::from(contact_scope),
        5,
        Duration::from_mins(10),
    )
    .await?;
    enforce_limit(
        state,
        "signup_contact_start_session",
        &SecretString::from(session_scope),
        5,
        Duration::from_mins(10),
    )
    .await
}

fn contact_limit_scopes(
    session_id: Uuid,
    contact: &super::model::ValidatedContact,
) -> (String, String) {
    let contact_scope = format!(
        "{}:{}",
        contact.channel.database_value(),
        contact.normalized,
    );
    let session_scope = format!(
        "{}:{}:{}",
        session_id,
        contact.channel.database_value(),
        contact.normalized,
    );
    (contact_scope, session_scope)
}

async fn enforce_limit(
    state: &ApiState,
    name: &'static str,
    scope: &SecretString,
    maximum: u32,
    window: Duration,
) -> Result<(), AppError> {
    let maximum = NonZeroU32::new(maximum).ok_or(AppError::Internal {
        category: "rate_limit_policy",
    })?;
    let policy = RateLimitPolicy::new(maximum, window, window).map_err(|_| AppError::Internal {
        category: "rate_limit_policy",
    })?;
    rate_limit::enforce(&state.pool, &state.crypto, name, scope, policy).await?;
    Ok(())
}

async fn deliver_many(state: &ApiState, deliveries: &[super::model::Delivery]) {
    futures::future::join_all(deliveries.iter().map(|delivery| deliver(state, delivery))).await;
}

async fn deliver_one(state: &ApiState, delivery: Option<&super::model::Delivery>) {
    if let Some(delivery) = delivery {
        deliver(state, delivery).await;
    }
}

async fn deliver(state: &ApiState, delivery: &super::model::Delivery) {
    let minutes = state.settings.security.otp_ttl.as_secs().div_ceil(60);
    let expires_in_minutes = u16::try_from(minutes).unwrap_or(u16::MAX);
    let result = match delivery.channel {
        ContactChannel::Email => {
            state
                .notifications
                .email
                .send_otp(EmailOtp {
                    recipient: &delivery.recipient,
                    code: &delivery.code,
                    purpose: delivery.purpose,
                    expires_in_minutes,
                })
                .await
        }
        ContactChannel::Phone => {
            state
                .notifications
                .sms
                .send_otp(SmsOtp {
                    recipient: &delivery.recipient,
                    code: &delivery.code,
                    expires_in_minutes,
                })
                .await
        }
    };
    if result.is_err() {
        tracing::warn!(
            channel = delivery.channel.database_value(),
            purpose = delivery.purpose,
            "OTP delivery did not complete"
        );
    }
}

fn login_scope(identifier: &super::model::ValidatedLoginIdentifier) -> SecretString {
    match identifier {
        super::model::ValidatedLoginIdentifier::Contact(contact) => SecretString::from(format!(
            "{}:{}",
            contact.channel.database_value(),
            contact.normalized,
        )),
        super::model::ValidatedLoginIdentifier::CarbonId(carbon_id) => {
            SecretString::from(format!("carbon_id:{}", carbon_id.as_str()))
        }
    }
}

fn json_body<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, AppError> {
    payload
        .map(|Json(value)| value)
        .map_err(|_| validation::validation("body", "must match the documented JSON schema"))
}

fn malformed_query() -> AppError {
    validation::validation("query", "contains an invalid value")
}

fn invalid_code() -> AppError {
    validation::validation("code", "is invalid")
}

fn no_store_json<T: Serialize>(status: StatusCode, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(http::header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn login_success_response(state: &ApiState, body: TokenResponse) -> Result<Response, AppError> {
    let cookie = browser_session::issue(
        body.session_id,
        body.refresh_expires_at,
        &state.settings.security.cookie_key,
    )
    .map_err(|_| AppError::Internal {
        category: "browser_session_cookie_issue",
    })?;
    let mut response = no_store_json(StatusCode::OK, body);
    response
        .headers_mut()
        .insert(http::header::SET_COOKIE, cookie);
    Ok(response)
}

fn cleared_browser_session_response() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(http::header::SET_COOKIE, browser_session::clear());
    response
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::{contact_limit_scopes, login_scope, no_store_json};
    use crate::features::authentication::model::{
        ContactChannel, ValidatedContact, ValidatedLoginIdentifier,
    };
    use secrecy::{ExposeSecret as _, SecretString};

    #[test]
    fn rate_limit_scopes_include_identifier_kind() {
        let identifier = ValidatedLoginIdentifier::Contact(ValidatedContact {
            channel: ContactChannel::Email,
            normalized: "person@example.com".to_owned(),
            presentation: SecretString::from("Person@example.com".to_owned()),
        });
        assert_eq!(
            login_scope(&identifier).expose_secret(),
            "email:person@example.com"
        );
    }

    #[test]
    fn signup_contact_bucket_does_not_depend_on_temporary_session() {
        let contact = ValidatedContact {
            channel: ContactChannel::Email,
            normalized: "person@example.com".to_owned(),
            presentation: SecretString::from("Person@example.com".to_owned()),
        };
        let (first_contact, first_session) =
            contact_limit_scopes(uuid::Uuid::from_u128(1), &contact);
        let (second_contact, second_session) =
            contact_limit_scopes(uuid::Uuid::from_u128(2), &contact);

        assert_eq!(first_contact, second_contact);
        assert_ne!(first_session, second_session);
    }

    #[test]
    fn secret_responses_disable_http_caching() {
        let response = no_store_json(StatusCode::OK, serde_json::json!({ "token": "secret" }));
        assert_eq!(
            response.headers().get(http::header::CACHE_CONTROL),
            Some(&http::HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            response.headers().get(http::header::PRAGMA),
            Some(&http::HeaderValue::from_static("no-cache"))
        );
    }
}
