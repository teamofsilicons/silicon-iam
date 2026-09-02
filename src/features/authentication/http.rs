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
    api::{
        ApiState,
        authentication::{Authenticated, LogoutAuthenticated},
    },
    domain::auth::CarbonId,
    error::AppError,
    infrastructure::{
        browser_session,
        postgres::{
            rate_limit::{self, RateLimitPolicy},
            step_up::StepUpToken,
        },
    },
};

use super::{
    LogoutTrigger, contacts,
    database::expired,
    idempotency::{IdempotencyKey, Outcome},
    login,
    model::{
        AvailabilityResponse, ContactChannel, EmailInput, LoginChallengeInput, LoginEventPage,
        LoginVerificationOutcome, LogoutInput, LogoutMode, PageQuery, PhoneInput, RefreshInput,
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
    idempotent_no_store_json(signup::create_session(&state, &key).await?)
}

pub(super) async fn start_signup_email(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<EmailInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let contact = validation::email(json_body(payload)?.email)?;
    idempotent_no_store_json(signup::start_contact(&state, &key, session_id, contact).await?)
}

pub(super) async fn start_signup_phone(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<PhoneInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let contact = validation::phone(json_body(payload)?.phone_number)?;
    idempotent_no_store_json(signup::start_contact(&state, &key, session_id, contact).await?)
}

pub(super) async fn verify_signup_email(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<VerificationInput>, JsonRejection>,
) -> Result<Response, AppError> {
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
) -> Result<Response, AppError> {
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
    idempotent_no_store_json(signup::complete_signup(&state, &key, session_id, input).await?)
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
    idempotent_no_store_json(login::create_challenge(&state, &key, identifier).await?)
}

pub(super) async fn verify_login_challenge(
    State(state): State<ApiState>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
    payload: Result<Json<VerificationInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let code = validation::verification_code(json_body(payload)?.code)?;
    let outcome = login::verify_challenge(&state, &key, session_id, code).await?;
    let status = outcome.status;
    let replayed = outcome.replayed;
    match outcome.value {
        LoginVerificationOutcome::Success(response) => {
            login_success_response(&state, status, response, replayed)
        }
        LoginVerificationOutcome::Invalid => idempotent_error(invalid_code(), status, replayed),
        LoginVerificationOutcome::Expired => idempotent_error(expired(), status, replayed),
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
    idempotent_no_store_json(step_up::create_challenge(&state, &context, &key, input).await?)
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
    let outcome = step_up::verify_challenge(&state, &context, &key, session_id, code).await?;
    let status = outcome.status;
    let replayed = outcome.replayed;
    match outcome.value {
        StepUpVerificationOutcome::Success(response) => idempotent_no_store_json(Outcome {
            status,
            value: response,
            replayed,
        }),
        StepUpVerificationOutcome::Invalid => idempotent_error(invalid_code(), status, replayed),
        StepUpVerificationOutcome::Expired => idempotent_error(expired(), status, replayed),
    }
}

pub(super) async fn refresh_tokens(
    State(state): State<ApiState>,
    headers: HeaderMap,
    payload: Result<Json<RefreshInput>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let token = validation::refresh_token(json_body(payload)?.refresh_token)?;
    let outcome = refresh::rotate(&state, &key, token).await?;
    let status = outcome.status;
    let replayed = outcome.replayed;
    match outcome.value {
        RefreshMutationOutcome::Success(response) => idempotent_no_store_json(Outcome {
            status,
            value: response,
            replayed,
        }),
        RefreshMutationOutcome::ReplayRevoked => {
            idempotent_error(AppError::Unauthenticated, status, replayed)
        }
    }
}

pub(super) async fn logout(
    State(state): State<ApiState>,
    identity: LogoutAuthenticated,
    headers: HeaderMap,
    payload: Result<Option<Json<LogoutInput>>, JsonRejection>,
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(&headers)?;
    let mode = payload
        .map_err(|_| validation::validation("body", "must match the documented JSON schema"))?
        .map_or_default(|Json(input)| input)
        .mode;
    let step_up_token = if matches!(mode, LogoutMode::AllSessions)
        && matches!(identity.trigger, LogoutTrigger::FirstPartyCarbon)
    {
        optional_step_up_token(&headers)?
    } else {
        None
    };
    let outcome = sessions::logout(
        &state,
        sessions::LogoutCommand {
            principal_id: identity.principal_id,
            authentication_session_id: identity.authentication_session_id,
            trigger: identity.trigger,
            credential_state: identity.credential_state,
            key: &key,
            step_up_token: step_up_token.as_ref(),
            mode,
        },
    )
    .await?;
    cleared_browser_session_response(outcome.status, outcome.replayed)
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
    let step_up_token = optional_step_up_token(&headers)?;
    let outcome =
        sessions::revoke_session(&state, &context, &key, step_up_token.as_ref(), session_id)
            .await?;
    if session_id == context.authentication_session_id {
        cleared_browser_session_response(outcome.status, outcome.replayed)
    } else {
        empty_idempotent_response(outcome.status, outcome.replayed)
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
) -> Result<Response, AppError> {
    let key = IdempotencyKey::from_headers(headers)?;
    let code = validation::verification_code(input.code)?;
    let outcome = signup::verify_contact(state, &key, session_id, channel, code).await?;
    let status = outcome.status;
    let replayed = outcome.replayed;
    match outcome.value {
        VerificationOutcome::Verified => idempotent_json(Outcome {
            status,
            value: VerifiedResponse { verified: true },
            replayed,
        }),
        VerificationOutcome::Invalid => idempotent_error(invalid_code(), status, replayed),
        VerificationOutcome::Expired => idempotent_error(expired(), status, replayed),
    }
}

pub(super) async fn enforce_contact_limit(
    state: &ApiState,
    name: &'static str,
    session_id: Uuid,
    contact: &super::model::ValidatedContact,
) -> Result<(), AppError> {
    let (contact_scope, session_scope) = contact_limit_scopes(session_id, contact);
    enforce_burst_limit(
        state,
        name,
        &SecretString::from(contact_scope),
        10,
        Duration::from_mins(10),
    )
    .await?;
    enforce_burst_limit(
        state,
        "signup_contact_start_session",
        &SecretString::from(session_scope),
        10,
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
    let session_scope = format!("{}:{}", session_id, contact.channel.database_value());
    (contact_scope, session_scope)
}

pub(super) async fn enforce_limit(
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

async fn enforce_burst_limit(
    state: &ApiState,
    name: &'static str,
    scope: &SecretString,
    maximum: u32,
    cooldown: Duration,
) -> Result<(), AppError> {
    let maximum = NonZeroU32::new(maximum).ok_or(AppError::Internal {
        category: "rate_limit_policy",
    })?;
    let policy =
        RateLimitPolicy::new(maximum, cooldown, cooldown).map_err(|_| AppError::Internal {
            category: "rate_limit_policy",
        })?;
    rate_limit::enforce_burst_cooldown(&state.pool, &state.crypto, name, scope, policy).await?;
    Ok(())
}

pub(super) fn login_scope(identifier: &super::model::ValidatedLoginIdentifier) -> SecretString {
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
        .map_err(|rejection| AppError::from_json_rejection(&rejection))
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

fn idempotent_json<T: Serialize>(outcome: Outcome<T>) -> Result<Response, AppError> {
    let status = idempotency_status(outcome.status)?;
    let mut response = (status, Json(outcome.value)).into_response();
    mark_replayed(&mut response, outcome.replayed);
    Ok(response)
}

fn idempotent_no_store_json<T: Serialize>(outcome: Outcome<T>) -> Result<Response, AppError> {
    let status = idempotency_status(outcome.status)?;
    let mut response = no_store_json(status, outcome.value);
    mark_replayed(&mut response, outcome.replayed);
    Ok(response)
}

fn idempotent_error(error: AppError, status: u16, replayed: bool) -> Result<Response, AppError> {
    if !replayed {
        return Err(error);
    }
    let expected_status = idempotency_status(status)?;
    let mut response = error.into_response();
    if response.status() != expected_status {
        return Err(AppError::Internal {
            category: "authentication_idempotency_error_status",
        });
    }
    mark_replayed(&mut response, true);
    Ok(response)
}

fn empty_idempotent_response(status: u16, replayed: bool) -> Result<Response, AppError> {
    let mut response = idempotency_status(status)?.into_response();
    mark_replayed(&mut response, replayed);
    Ok(response)
}

fn login_success_response(
    state: &ApiState,
    status: u16,
    body: TokenResponse,
    replayed: bool,
) -> Result<Response, AppError> {
    let cookie = browser_session::issue(
        body.session_id,
        body.refresh_expires_at,
        &state.settings.security.cookie_key,
    )
    .map_err(|_| AppError::Internal {
        category: "browser_session_cookie_issue",
    })?;
    let mut response = no_store_json(idempotency_status(status)?, body);
    response
        .headers_mut()
        .insert(http::header::SET_COOKIE, cookie);
    mark_replayed(&mut response, replayed);
    Ok(response)
}

fn cleared_browser_session_response(status: u16, replayed: bool) -> Result<Response, AppError> {
    let mut response = idempotency_status(status)?.into_response();
    response
        .headers_mut()
        .insert(http::header::SET_COOKIE, browser_session::clear());
    mark_replayed(&mut response, replayed);
    Ok(response)
}

fn idempotency_status(status: u16) -> Result<StatusCode, AppError> {
    StatusCode::from_u16(status).map_err(|_| AppError::Internal {
        category: "authentication_idempotency_status",
    })
}

fn mark_replayed(response: &mut Response, replayed: bool) {
    if replayed {
        response.headers_mut().insert(
            http::HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
}

fn optional_step_up_token(headers: &HeaderMap) -> Result<Option<StepUpToken>, AppError> {
    headers
        .get("x-step-up-token")
        .map(|value| {
            let raw = value.to_str().map_err(|_| AppError::PreconditionFailed {
                code: "step_up_invalid".into(),
            })?;
            StepUpToken::parse(raw).map_err(|_| AppError::PreconditionFailed {
                code: "step_up_invalid".into(),
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::{
        cleared_browser_session_response, contact_limit_scopes, empty_idempotent_response,
        idempotent_error, idempotent_json, login_scope, no_store_json, optional_step_up_token,
    };
    use crate::{
        error::AppError,
        features::authentication::{
            idempotency::Outcome,
            model::{ContactChannel, ValidatedContact, ValidatedLoginIdentifier},
        },
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

        let other_contact = ValidatedContact {
            channel: ContactChannel::Email,
            normalized: "other@example.com".to_owned(),
            presentation: SecretString::from("other@example.com".to_owned()),
        };
        let (other_contact_scope, same_session_scope) =
            contact_limit_scopes(uuid::Uuid::from_u128(1), &other_contact);
        assert_ne!(first_contact, other_contact_scope);
        assert_eq!(first_session, same_session_scope);
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

    #[test]
    fn replay_responses_preserve_status_and_emit_the_marker() {
        let response = idempotent_json(Outcome::replay(
            StatusCode::CREATED.as_u16(),
            serde_json::json!({ "created": true }),
        ));
        let Ok(response) = response else {
            panic!("a valid stored status must build a response");
        };
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers().get("idempotency-replayed"),
            Some(&http::HeaderValue::from_static("true"))
        );

        let response = empty_idempotent_response(StatusCode::NO_CONTENT.as_u16(), true);
        let Ok(response) = response else {
            panic!("a stored 204 must replay");
        };
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers().get("idempotency-replayed"),
            Some(&http::HeaderValue::from_static("true"))
        );
    }

    #[test]
    fn replayed_error_and_cookie_clear_responses_are_marked() {
        let response = idempotent_error(
            AppError::Unauthenticated,
            StatusCode::UNAUTHORIZED.as_u16(),
            true,
        );
        let Ok(response) = response else {
            panic!("a stored authentication error must replay");
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("idempotency-replayed"),
            Some(&http::HeaderValue::from_static("true"))
        );

        let response = cleared_browser_session_response(StatusCode::NO_CONTENT.as_u16(), true);
        let Ok(response) = response else {
            panic!("a stored logout must replay");
        };
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.headers().contains_key(http::header::SET_COOKIE));
        assert_eq!(
            response.headers().get("idempotency-replayed"),
            Some(&http::HeaderValue::from_static("true"))
        );
    }

    #[test]
    fn session_revocation_step_up_header_is_optional_and_shape_checked() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(matches!(optional_step_up_token(&headers), Ok(None)));

        headers.insert(
            "x-step-up-token",
            axum::http::HeaderValue::from_static("sup_too-short"),
        );
        assert!(optional_step_up_token(&headers).is_err());

        headers.insert(
            "x-step-up-token",
            axum::http::HeaderValue::from_static("sup_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        );
        assert!(matches!(optional_step_up_token(&headers), Ok(Some(_))));
    }
}
