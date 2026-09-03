use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::ApiState,
    domain::actor::ActorType,
    error::AppError,
    infrastructure::{
        crypto::CryptoService,
        postgres::{
            step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
            tokens::AccessContext,
        },
    },
};

use super::{
    LogoutCredentialState, LogoutTrigger,
    database::{database_conflict, serializable, set_principal_context},
    events::{self, SecurityMutation},
    idempotency::{self, Claim, IdempotencyKey, Outcome},
    model::{
        ActorResponse, EmptyMutationOutcome, LoginEventPage, LoginEventResponse, LogoutMode,
        PageInfo, SessionPage, SessionResponse, StepUpAction,
    },
};

const SESSION_ROUTE: &str = "DELETE /api/v1/me/sessions/{session_id}";
const LOGOUT_ROUTE: &str = "POST /api/v1/logout";
const IAM_AUDIENCE: &str = "silicon-iam";
const SESSION_REVOCATION_MIN_AGE_SECONDS: i64 = 12 * 60 * 60;
const SESSION_REVOKE_ACTION: &str = StepUpAction::AccountSessionRevoke.database_value();
const SESSIONS_REVOKE_ALL_ACTION: &str = StepUpAction::AccountSessionsRevokeAll.database_value();
const MATURE_TARGET_SESSION_QUERY: &str = r"
    SELECT session.created_at <= transaction_timestamp()
            - ($3::bigint * interval '1 second')
    FROM iam.authentication_sessions AS session
    WHERE session.id = $1
      AND session.subject_principal_id = $2
    ";
const MATURE_CURRENT_SESSION_QUERY: &str = r"
    SELECT session.created_at <= transaction_timestamp()
            - ($3::bigint * interval '1 second')
    FROM iam.authentication_sessions AS session
    JOIN iam.principals AS principal
      ON principal.id = session.subject_principal_id
     AND principal.kind = session.subject_kind
    WHERE session.id = $1
      AND session.subject_principal_id = $2
      AND session.status = 'active'
      AND session.idle_expires_at > transaction_timestamp()
      AND session.absolute_expires_at > transaction_timestamp()
      AND principal.status = 'active'
      AND principal.auth_epoch = session.subject_auth_epoch
    ";
const OTHER_ACTIVE_SESSIONS_MATURITY_QUERY: &str = r"
    SELECT bool_and(
        session.created_at <= transaction_timestamp()
            - ($3::bigint * interval '1 second')
    )
    FROM iam.authentication_sessions AS session
    WHERE session.subject_principal_id = $1
      AND session.subject_kind = 'carbon'
      AND session.id <> $2
      AND session.status = 'active'
      AND session.idle_expires_at > transaction_timestamp()
      AND session.absolute_expires_at > transaction_timestamp()
    ";
const APPLICATION_LOGOUT_AUTHORITY_QUERY: &str = r"
    SELECT token.id
    FROM iam.access_tokens AS token
    JOIN iam.authentication_sessions AS session
      ON session.id = token.authentication_session_id
     AND session.subject_principal_id = token.subject_principal_id
     AND session.subject_kind = token.subject_kind
     AND session.subject_auth_epoch = token.subject_auth_epoch
     AND session.status = 'active'
     AND session.idle_expires_at > transaction_timestamp()
     AND session.absolute_expires_at > transaction_timestamp()
    JOIN iam.principals AS subject
      ON subject.id = token.subject_principal_id
     AND subject.kind = 'carbon'
     AND subject.status = 'active'
     AND subject.auth_epoch = token.subject_auth_epoch
    JOIN iam.applications AS application
      ON application.id = token.client_application_id
     AND application.id = token.audience_application_id
     AND application.app_id = token.audience
     AND application.review_status = 'verified'
     AND application.deleted_at IS NULL
    JOIN iam.principals AS application_principal
      ON application_principal.id = application.id
     AND application_principal.kind = 'application'
     AND application_principal.status = 'active'
     AND application_principal.auth_epoch = token.client_auth_epoch
    LEFT JOIN iam.organizations AS organization
      ON organization.id = token.organization_id
    LEFT JOIN iam.organization_memberships AS membership
      ON membership.organization_id = token.organization_id
     AND membership.id = token.membership_id
     AND membership.principal_id = token.subject_principal_id
     AND membership.principal_kind = token.subject_kind
    WHERE token.id = $1
      AND token.token_class = 'application_access'
      AND token.authentication_session_id = $2
      AND token.subject_principal_id = $3
      AND token.subject_kind = 'carbon'
      AND token.client_application_id = $4
      AND token.revoked_at IS NULL
      AND token.expires_at > transaction_timestamp()
      AND (
          token.organization_id IS NULL
          OR (
              organization.status = 'active'
              AND membership.status = 'active'
              AND membership.authz_epoch = token.membership_authz_epoch
          )
      )
    FOR UPDATE OF token, session
    FOR SHARE OF subject, application, application_principal
    ";

struct LogoutRequestBinding {
    caller_scope: Vec<u8>,
    request_digest: [u8; 32],
}

pub(super) struct LogoutCommand<'a> {
    pub(super) principal_id: Uuid,
    pub(super) authentication_session_id: Uuid,
    pub(super) trigger: LogoutTrigger,
    pub(super) credential_state: LogoutCredentialState,
    pub(super) key: &'a IdempotencyKey,
    pub(super) step_up_token: Option<&'a StepUpToken>,
    pub(super) mode: LogoutMode,
}

struct LogoutExecution<'a> {
    principal_id: Uuid,
    authentication_session_id: Uuid,
    trigger: LogoutTrigger,
    step_up_token: Option<&'a StepUpToken>,
    mode: LogoutMode,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
struct PageCursor {
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
    id: Uuid,
}

#[derive(FromRow)]
struct SessionRow {
    session_id: Uuid,
    status: String,
    revocation_reason: Option<String>,
    created_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    idle_expires_at: OffsetDateTime,
    absolute_expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

#[derive(FromRow)]
struct LoginEventRow {
    id: Uuid,
    event_type: String,
    outcome: String,
    app_id: Option<String>,
    org_id: Option<String>,
    request_id: Uuid,
    occurred_at: OffsetDateTime,
}

#[derive(FromRow)]
struct RevokedSessionRow {
    session_id: Uuid,
    version: i64,
    revocation_reason: String,
}

pub(super) fn carbon_context(context: &AccessContext) -> Result<Uuid, AppError> {
    if context.subject.actor_type != ActorType::Carbon
        || context.audience != IAM_AUDIENCE
        || context.client_application_id.is_some()
        || context.organization_id.is_some()
        || context.membership_id.is_some()
        || !context.scopes.iter().any(|scope| scope == "iam.self")
    {
        return Err(AppError::Forbidden);
    }
    Ok(context.subject.id)
}

pub(super) async fn list_sessions(
    state: &ApiState,
    context: &AccessContext,
    cursor: Option<String>,
    limit: i64,
) -> Result<SessionPage, AppError> {
    let principal_id = carbon_context(context)?;
    let cursor = cursor.map(|value| decode_cursor(&value)).transpose()?;
    let fetch_limit = limit.checked_add(1).ok_or(AppError::Internal {
        category: "session_page_limit",
    })?;
    let mut transaction = crate::infrastructure::postgres::context::begin_scoped(state.db())
        .await
        .map_err(|_| AppError::Internal {
            category: "session_list_transaction",
        })?;
    set_principal_context(&mut transaction, principal_id).await?;
    let carbon_id = carbon_handle(&mut transaction, principal_id).await?;
    let rows = sqlx::query_as::<_, SessionRow>(
        r"
        SELECT
            id AS session_id,
            status,
            revocation_reason,
            created_at,
            last_seen_at,
            idle_expires_at,
            absolute_expires_at,
            revoked_at
        FROM iam.authentication_sessions
        WHERE subject_principal_id = $1
          AND subject_kind = 'carbon'
          AND (
              $2::timestamptz IS NULL
              OR (created_at, id) < ($2, $3)
          )
        ORDER BY created_at DESC, id DESC
        LIMIT $4
        ",
    )
    .bind(principal_id)
    .bind(cursor.map(|value| value.occurred_at))
    .bind(cursor.map(|value| value.id))
    .bind(fetch_limit)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_list",
    })?;
    transaction.commit().await.map_err(|_| AppError::Internal {
        category: "session_list_commit",
    })?;

    let has_more = i64::try_from(rows.len()).is_ok_and(|length| length > limit);
    let visible_count = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "session_page_limit",
    })?;
    let items = rows
        .into_iter()
        .take(visible_count)
        .map(|row| session_response(&row, principal_id, &carbon_id))
        .collect::<Vec<_>>();
    let next_cursor = if has_more {
        items
            .last()
            .map(|item| encode_cursor(item.created_at, item.session_id))
            .transpose()?
    } else {
        None
    };
    Ok(SessionPage {
        items,
        page: PageInfo {
            next_cursor,
            has_more,
        },
    })
}

/// Every selected column is qualified.
///
/// `iam.authentication_events`, `iam.applications` and `iam.organizations` all
/// have an `id`, so a bare one is ambiguous and PostgreSQL rejects the
/// statement at parse time — the endpoint answered 500 for every request until
/// this was qualified. The alias is cheap insurance on the columns that happen
/// to be unique today, too: adding a column to either joined table must not be
/// able to break this query.
const LOGIN_HISTORY_QUERY: &str = r"
    SELECT
        event.id,
        event.event_type,
        event.outcome,
        application.app_id,
        organization.org_id,
        event.request_id,
        event.occurred_at
    FROM iam.authentication_events AS event
    LEFT JOIN iam.applications AS application ON application.id = event.application_id
    LEFT JOIN iam.organizations AS organization ON organization.id = event.organization_id
    WHERE event.subject_principal_id = $1
      AND event.event_type = ANY($2::text[])
      AND (
          $3::timestamptz IS NULL
          OR (event.occurred_at, event.id) < ($3, $4)
      )
    ORDER BY event.occurred_at DESC, event.id DESC
    LIMIT $5
";

pub(super) async fn list_login_history(
    state: &ApiState,
    context: &AccessContext,
    cursor: Option<String>,
    limit: i64,
) -> Result<LoginEventPage, AppError> {
    let principal_id = carbon_context(context)?;
    let cursor = cursor.map(|value| decode_cursor(&value)).transpose()?;
    let fetch_limit = limit.checked_add(1).ok_or(AppError::Internal {
        category: "login_history_page_limit",
    })?;
    let mut transaction = crate::infrastructure::postgres::context::begin_scoped(state.db())
        .await
        .map_err(|_| AppError::Internal {
            category: "login_history_transaction",
        })?;
    set_principal_context(&mut transaction, principal_id).await?;
    let carbon_id = carbon_handle(&mut transaction, principal_id).await?;
    let rows = sqlx::query_as::<_, LoginEventRow>(LOGIN_HISTORY_QUERY)
        .bind(principal_id)
        .bind([
            "login.challenge",
            "login.success",
            "login.failure",
            "logout.success",
            "refresh.replay",
            "oauth.authorization",
            "oauth.token_exchange",
        ])
        .bind(cursor.map(|value| value.occurred_at))
        .bind(cursor.map(|value| value.id))
        .bind(fetch_limit)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "login_history_list",
        })?;
    transaction.commit().await.map_err(|_| AppError::Internal {
        category: "login_history_commit",
    })?;

    let has_more = i64::try_from(rows.len()).is_ok_and(|length| length > limit);
    let visible_count = usize::try_from(limit).map_err(|_| AppError::Internal {
        category: "login_history_page_limit",
    })?;
    let items = rows
        .into_iter()
        .take(visible_count)
        .map(|row| login_event_response(&row, principal_id, &carbon_id))
        .collect::<Result<Vec<_>, AppError>>()?;
    let next_cursor = if has_more {
        items
            .last()
            .map(|item| encode_cursor(item.occurred_at, item.id))
            .transpose()?
    } else {
        None
    };
    Ok(LoginEventPage {
        items,
        page: PageInfo {
            next_cursor,
            has_more,
        },
    })
}

pub(super) async fn revoke_session(
    state: &ApiState,
    context: &AccessContext,
    key: &IdempotencyKey,
    step_up_token: Option<&StepUpToken>,
    session_id: Uuid,
) -> Result<Outcome<()>, AppError> {
    let principal_id = carbon_context(context)?;
    let request_digest = idempotency::digest_parts(
        b"session-revoke",
        &[principal_id.as_bytes(), session_id.as_bytes()],
    );
    let mut transaction = serializable(state.db(), "session_revoke_transaction").await?;
    let record_id = match idempotency::begin::<EmptyMutationOutcome>(
        &mut transaction,
        &state.crypto,
        key,
        principal_id.as_bytes(),
        SESSION_ROUTE,
        request_digest,
        false,
    )
    .await?
    {
        Claim::Replay { status, .. } => {
            transaction.commit().await.map_err(|error| {
                database_conflict(&error, "session_revoke_serialization_conflict")
            })?;
            return Ok(Outcome::replay(status, ()));
        }
        Claim::Acquired { record_id } => record_id,
    };
    let step_up_token = step_up_token.ok_or_else(|| AppError::PreconditionRequired {
        code: "step_up_required".into(),
    })?;
    consume_verified_channel_step_up(
        &mut transaction,
        state,
        principal_id,
        context.authentication_session_id,
        step_up_token,
        SESSION_REVOKE_ACTION,
        session_id,
    )
    .await?;
    let owned_session_id = sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT id
        FROM iam.authentication_sessions
        WHERE id = $1
          AND subject_principal_id = $2
          AND subject_kind = 'carbon'
        FOR UPDATE
        ",
    )
    .bind(session_id)
    .bind(principal_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_revoke_lookup",
    })?;
    if owned_session_id.is_none() {
        return Err(AppError::NotFound);
    }
    authorize_session_revocation(
        &mut transaction,
        principal_id,
        context.authentication_session_id,
        session_id,
    )
    .await?;
    if let Some(revoked) =
        revoke_one(&mut transaction, principal_id, session_id, "user_revoked").await?
    {
        record_revocation(
            &mut transaction,
            principal_id,
            context.authentication_session_id,
            revoked,
            None,
            "session.revoked",
        )
        .await?;
    }
    let outcome = EmptyMutationOutcome::Completed;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        204,
        &outcome,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "session_revoke_serialization_conflict"))?;
    Ok(Outcome::fresh(204, ()))
}

pub(super) async fn logout(
    state: &ApiState,
    command: LogoutCommand<'_>,
) -> Result<Outcome<()>, AppError> {
    validate_logout_trigger_mode(command.trigger, command.mode)?;
    let binding = logout_request_binding(
        command.principal_id,
        command.authentication_session_id,
        command.trigger,
        command.mode,
    );
    let mut transaction = serializable(state.db(), "logout_transaction").await?;

    if matches!(command.credential_state, LogoutCredentialState::ReplayOnly) {
        return replay_completed_logout(transaction, &state.crypto, command.key, &binding).await;
    }

    let record_id = match idempotency::begin::<EmptyMutationOutcome>(
        &mut transaction,
        &state.crypto,
        command.key,
        &binding.caller_scope,
        LOGOUT_ROUTE,
        binding.request_digest,
        false,
    )
    .await?
    {
        Claim::Replay { status, .. } => {
            transaction
                .commit()
                .await
                .map_err(|error| database_conflict(&error, "logout_serialization_conflict"))?;
            return Ok(Outcome::replay(status, ()));
        }
        Claim::Acquired { record_id } => record_id,
    };

    let execution = LogoutExecution {
        principal_id: command.principal_id,
        authentication_session_id: command.authentication_session_id,
        trigger: command.trigger,
        step_up_token: command.step_up_token,
        mode: command.mode,
    };
    execute_logout(&mut transaction, state, execution).await?;
    let outcome = EmptyMutationOutcome::Completed;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        record_id,
        204,
        &outcome,
        false,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "logout_serialization_conflict"))?;
    Ok(Outcome::fresh(204, ()))
}

fn logout_request_binding(
    principal_id: Uuid,
    authentication_session_id: Uuid,
    trigger: LogoutTrigger,
    mode: LogoutMode,
) -> LogoutRequestBinding {
    let mode_value = match mode {
        LogoutMode::CurrentSession => b"current".as_slice(),
        LogoutMode::AllSessions => b"all".as_slice(),
    };
    match trigger {
        LogoutTrigger::FirstPartyCarbon => LogoutRequestBinding {
            caller_scope: principal_id.as_bytes().to_vec(),
            request_digest: idempotency::digest_parts(
                b"logout",
                &[
                    principal_id.as_bytes(),
                    authentication_session_id.as_bytes(),
                    mode_value,
                ],
            ),
        },
        LogoutTrigger::Application { application_id, .. } => LogoutRequestBinding {
            caller_scope: idempotency::digest_parts(
                b"application-triggered-logout-caller",
                &[principal_id.as_bytes(), application_id.as_bytes()],
            )
            .to_vec(),
            request_digest: idempotency::digest_parts(
                b"application-triggered-logout",
                &[
                    principal_id.as_bytes(),
                    authentication_session_id.as_bytes(),
                    application_id.as_bytes(),
                    mode_value,
                ],
            ),
        },
    }
}

async fn replay_completed_logout(
    mut transaction: Transaction<'_, Postgres>,
    crypto: &CryptoService,
    key: &IdempotencyKey,
    binding: &LogoutRequestBinding,
) -> Result<Outcome<()>, AppError> {
    let replay = idempotency::replay_if_present::<EmptyMutationOutcome>(
        &mut transaction,
        crypto,
        key,
        &binding.caller_scope,
        LOGOUT_ROUTE,
        binding.request_digest,
        false,
    )
    .await?;
    let Some(replay) = replay else {
        transaction
            .rollback()
            .await
            .map_err(|_| AppError::Internal {
                category: "logout_replay_rollback",
            })?;
        return Err(AppError::Unauthenticated);
    };
    transaction
        .commit()
        .await
        .map_err(|error| database_conflict(&error, "logout_serialization_conflict"))?;
    Ok(Outcome::replay(replay.status, ()))
}

async fn execute_logout(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    execution: LogoutExecution<'_>,
) -> Result<(), AppError> {
    if let LogoutTrigger::Application {
        application_id,
        access_token_id,
    } = execution.trigger
    {
        lock_application_logout_authority(
            transaction,
            access_token_id,
            execution.authentication_session_id,
            execution.principal_id,
            application_id,
        )
        .await?;
    }
    let revokes_other_sessions = authorize_logout_scope(
        transaction,
        state,
        execution.principal_id,
        execution.authentication_session_id,
        execution.step_up_token,
        execution.mode,
    )
    .await?;
    let revoked = if revokes_other_sessions {
        revoke_all(transaction, execution.principal_id).await?
    } else {
        revoke_one(
            transaction,
            execution.principal_id,
            execution.authentication_session_id,
            "user_logout",
        )
        .await?
        .into_iter()
        .collect()
    };
    let application_id = match execution.trigger {
        LogoutTrigger::FirstPartyCarbon => None,
        LogoutTrigger::Application { application_id, .. } => Some(application_id),
    };
    for session in revoked {
        record_revocation(
            transaction,
            execution.principal_id,
            execution.authentication_session_id,
            session,
            application_id,
            "session.logout",
        )
        .await?;
    }
    Ok(())
}

async fn authorize_logout_scope(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    principal_id: Uuid,
    authentication_session_id: Uuid,
    step_up_token: Option<&StepUpToken>,
    mode: LogoutMode,
) -> Result<bool, AppError> {
    if !matches!(mode, LogoutMode::AllSessions) {
        return Ok(false);
    }
    let revokes_other_sessions =
        authorize_all_sessions_logout(transaction, principal_id, authentication_session_id).await?;
    if !revokes_other_sessions {
        return Ok(false);
    }
    let token = step_up_token.ok_or_else(|| AppError::PreconditionRequired {
        code: "step_up_required".into(),
    })?;
    consume_verified_channel_step_up(
        transaction,
        state,
        principal_id,
        authentication_session_id,
        token,
        SESSIONS_REVOKE_ALL_ACTION,
        principal_id,
    )
    .await?;
    Ok(true)
}

fn validate_logout_trigger_mode(trigger: LogoutTrigger, mode: LogoutMode) -> Result<(), AppError> {
    if matches!(trigger, LogoutTrigger::Application { .. })
        && matches!(mode, LogoutMode::AllSessions)
    {
        Err(AppError::Forbidden)
    } else {
        Ok(())
    }
}

async fn lock_application_logout_authority(
    transaction: &mut Transaction<'_, Postgres>,
    access_token_id: Uuid,
    authentication_session_id: Uuid,
    principal_id: Uuid,
    application_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query_scalar::<_, Uuid>(APPLICATION_LOGOUT_AUTHORITY_QUERY)
        .bind(access_token_id)
        .bind(authentication_session_id)
        .bind(principal_id)
        .bind(application_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| database_conflict(&error, "logout_serialization_conflict"))?
        .ok_or(AppError::Forbidden)
        .map(|_| ())
}

pub(super) async fn authorize_session_revocation(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    current_session_id: Uuid,
    target_session_id: Uuid,
) -> Result<(), AppError> {
    require_mature_target_session(transaction, principal_id, target_session_id).await?;
    if revocation_targets_another_session(current_session_id, target_session_id) {
        require_mature_current_session(transaction, principal_id, current_session_id).await?;
    }
    Ok(())
}

async fn require_mature_target_session(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    target_session_id: Uuid,
) -> Result<(), AppError> {
    let mature = sqlx::query_scalar::<_, bool>(MATURE_TARGET_SESSION_QUERY)
        .bind(target_session_id)
        .bind(principal_id)
        .bind(SESSION_REVOCATION_MIN_AGE_SECONDS)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "session_revocation_target_age",
        })?;

    match mature {
        Some(true) => Ok(()),
        Some(false) => Err(AppError::Forbidden),
        None => Err(AppError::NotFound),
    }
}

async fn require_mature_current_session(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    current_session_id: Uuid,
) -> Result<(), AppError> {
    let mature = sqlx::query_scalar::<_, bool>(MATURE_CURRENT_SESSION_QUERY)
        .bind(current_session_id)
        .bind(principal_id)
        .bind(SESSION_REVOCATION_MIN_AGE_SECONDS)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "session_revocation_authority",
        })?;

    match mature {
        Some(true) => Ok(()),
        Some(false) => Err(AppError::Forbidden),
        None => Err(AppError::Unauthenticated),
    }
}

async fn authorize_all_sessions_logout(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    current_session_id: Uuid,
) -> Result<bool, AppError> {
    let all_other_sessions_mature =
        sqlx::query_scalar::<_, Option<bool>>(OTHER_ACTIVE_SESSIONS_MATURITY_QUERY)
            .bind(principal_id)
            .bind(current_session_id)
            .bind(SESSION_REVOCATION_MIN_AGE_SECONDS)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| AppError::Internal {
                category: "session_revoke_all_target_ages",
            })?;
    let Some(all_other_sessions_mature) = all_other_sessions_mature else {
        return Ok(false);
    };
    if !all_other_sessions_mature {
        return Err(AppError::Forbidden);
    }
    require_mature_current_session(transaction, principal_id, current_session_id).await?;
    Ok(true)
}

async fn consume_verified_channel_step_up(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    principal_id: Uuid,
    authentication_session_id: Uuid,
    token: &StepUpToken,
    action: &'static str,
    resource_id: Uuid,
) -> Result<(), AppError> {
    step_up::consume(
        transaction,
        &state.crypto,
        token,
        StepUpExpectation {
            carbon_id: principal_id,
            authentication_session_id,
            action,
            resource_id: Some(resource_id),
            required_assurance: RequiredAssurance::VerifiedChannel,
        },
    )
    .await
    .map(|_| ())
}

fn revocation_targets_another_session(current_session_id: Uuid, target_session_id: Uuid) -> bool {
    current_session_id != target_session_id
}

async fn revoke_one(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    session_id: Uuid,
    reason: &'static str,
) -> Result<Option<RevokedSessionRow>, AppError> {
    let row = sqlx::query_as::<_, RevokedSessionRow>(
        r"
        UPDATE iam.authentication_sessions
        SET status = 'revoked',
            revoked_at = transaction_timestamp(),
            revocation_reason = $3,
            version = version + 1
        WHERE id = $1
          AND subject_principal_id = $2
          AND subject_kind = 'carbon'
          AND status = 'active'
          AND idle_expires_at > transaction_timestamp()
          AND absolute_expires_at > transaction_timestamp()
        RETURNING id AS session_id, version, revocation_reason
        ",
    )
    .bind(session_id)
    .bind(principal_id)
    .bind(reason)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_revoke",
    })?;
    if row.is_some() {
        revoke_session_authority(transaction, session_id, reason).await?;
    }
    Ok(row)
}

async fn revoke_all(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
) -> Result<Vec<RevokedSessionRow>, AppError> {
    let rows = sqlx::query_as::<_, RevokedSessionRow>(
        r"
        UPDATE iam.authentication_sessions
        SET status = 'revoked',
            revoked_at = transaction_timestamp(),
            revocation_reason = 'user_logout_all',
            version = version + 1
        WHERE subject_principal_id = $1
          AND subject_kind = 'carbon'
          AND status = 'active'
          AND idle_expires_at > transaction_timestamp()
          AND absolute_expires_at > transaction_timestamp()
        RETURNING id AS session_id, version, revocation_reason
        ",
    )
    .bind(principal_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_revoke_all",
    })?;
    for row in &rows {
        revoke_session_authority(transaction, row.session_id, "user_logout_all").await?;
    }
    Ok(rows)
}

async fn revoke_session_authority(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
    reason: &'static str,
) -> Result<(), AppError> {
    revoke_session_token_authority(transaction, session_id, reason).await?;
    revoke_session_oauth_authority(transaction, session_id).await?;
    revoke_session_obo_authority(transaction, session_id).await
}

async fn revoke_session_token_authority(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
    reason: &'static str,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'revoked',
            revoked_at = transaction_timestamp(),
            revocation_reason = $2
        WHERE authentication_session_id = $1 AND status = 'active'
        ",
    )
    .bind(session_id)
    .bind(reason)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_refresh_family_revoke",
    })?;
    sqlx::query(
        r"
        UPDATE iam.refresh_tokens AS token
        SET revoked_at = COALESCE(token.revoked_at, transaction_timestamp())
        FROM iam.refresh_token_families AS family
        WHERE token.family_id = family.id
          AND family.authentication_session_id = $1
        ",
    )
    .bind(session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_refresh_token_revoke",
    })?;
    sqlx::query(
        r"
        UPDATE iam.access_tokens
        SET revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = COALESCE(revocation_reason, $2)
        WHERE authentication_session_id = $1
        ",
    )
    .bind(session_id)
    .bind(reason)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_access_token_revoke",
    })?;
    Ok(())
}

async fn revoke_session_oauth_authority(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.oauth_authorization_codes AS code
        SET consumed_at = COALESCE(code.consumed_at, transaction_timestamp())
        FROM iam.oauth_authorization_requests AS request
        WHERE request.id = code.authorization_request_id
          AND request.authentication_session_id = $1
          AND code.consumed_at IS NULL
        ",
    )
    .bind(session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_authorization_code_revoke",
    })?;
    sqlx::query(
        r"
        UPDATE iam.oauth_authorization_requests
        SET status = 'denied',
            decided_at = COALESCE(decided_at, transaction_timestamp())
        WHERE authentication_session_id = $1
          AND status IN ('pending', 'approved')
        ",
    )
    .bind(session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_authorization_request_revoke",
    })?;
    sqlx::query(
        r"
        UPDATE iam.oauth_consent_grants
        SET status = 'revoked',
            revoked_at = transaction_timestamp()
        WHERE parent_authentication_session_id = $1
          AND status = 'active'
        ",
    )
    .bind(session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_consent_grant_revoke",
    })?;
    Ok(())
}

async fn revoke_session_obo_authority(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        r"
        UPDATE iam.obo_proofs AS proof
        SET revoked_at = transaction_timestamp()
        FROM iam.access_tokens AS parent
        WHERE parent.id = proof.parent_access_token_id
          AND parent.authentication_session_id = $1
          AND proof.consumed_at IS NULL
          AND proof.revoked_at IS NULL
        ",
    )
    .bind(session_id)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_obo_proof_revoke",
    })?;
    Ok(())
}

async fn record_revocation(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    actor_authentication_session_id: Uuid,
    session: RevokedSessionRow,
    application_id: Option<Uuid>,
    outbox_event: &'static str,
) -> Result<(), AppError> {
    let metadata = revocation_event_payload(
        principal_id,
        actor_authentication_session_id,
        application_id,
        &session,
    );
    events::record(
        transaction,
        SecurityMutation {
            authentication_event: "logout.success",
            authentication_outcome: "success",
            audit_action: "session.revoke",
            audit_result: "success",
            outbox_event,
            subject_id: Some(principal_id),
            actor_id: Some(principal_id),
            authentication_session_id: Some(actor_authentication_session_id),
            application_id,
            aggregate_type: "authentication_session",
            aggregate_id: session.session_id,
            aggregate_version: session.version,
            failure_code: None,
            metadata,
        },
    )
    .await
}

fn revocation_event_payload(
    principal_id: Uuid,
    actor_authentication_session_id: Uuid,
    application_id: Option<Uuid>,
    session: &RevokedSessionRow,
) -> serde_json::Value {
    json!({
        // Top-level routing identity lets the outbox worker resolve every
        // Application authorized immediately before or after this mutation.
        "subject_principal_id": principal_id,
        "actor": {
            "type": "carbon",
            "principal_id": principal_id,
            "authentication_session_id": actor_authentication_session_id,
            "application_id": application_id,
        },
        "changed_fields": ["status"],
        "authorized_state": {
            "subject": {
                "type": "carbon",
                "principal_id": principal_id,
            },
            "authentication_session": {
                "session_id": session.session_id,
                "status": "revoked",
                "revocation_reason": session.revocation_reason,
                "version": session.version,
            },
        },
    })
}

async fn carbon_handle(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
) -> Result<String, AppError> {
    sqlx::query_scalar::<_, String>(
        "SELECT carbon_id FROM iam.carbons WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "session_carbon_handle",
    })?
    .ok_or(AppError::Unauthenticated)
}

fn session_response(row: &SessionRow, principal_id: Uuid, carbon_id: &str) -> SessionResponse {
    let status = if row.revocation_reason.as_deref() == Some("refresh_replay") {
        "replay_revoked"
    } else if row.status == "active"
        && (row.idle_expires_at <= OffsetDateTime::now_utc()
            || row.absolute_expires_at <= OffsetDateTime::now_utc())
    {
        "expired"
    } else {
        row.status.as_str()
    };
    SessionResponse {
        session_id: row.session_id,
        actor: actor_response(principal_id, carbon_id),
        status: status.to_owned(),
        user_agent_summary: None,
        ip_prefix: None,
        created_at: row.created_at,
        last_used_at: row.last_seen_at,
        absolute_expires_at: row.absolute_expires_at,
        revoked_at: row.revoked_at,
    }
}

fn login_event_response(
    row: &LoginEventRow,
    principal_id: Uuid,
    carbon_id: &str,
) -> Result<LoginEventResponse, AppError> {
    let event_type = match row.event_type.as_str() {
        "login.challenge" => "login_challenge",
        "login.success" => "login_success",
        "login.failure" => "login_failure",
        "logout.success" => "logout",
        "refresh.replay" => "refresh_replay",
        "oauth.authorization" => "oauth_authorization",
        "oauth.token_exchange" => "oauth_token_exchange",
        _ => {
            return Err(AppError::Internal {
                category: "login_history_event_type",
            });
        }
    };
    Ok(LoginEventResponse {
        id: row.id,
        actor: actor_response(principal_id, carbon_id),
        app_id: row.app_id.clone(),
        org_id: row.org_id.clone(),
        event_type: event_type.to_owned(),
        success: row.outcome == "success",
        ip_prefix: None,
        user_agent_summary: None,
        request_id: row.request_id.to_string(),
        occurred_at: row.occurred_at,
    })
}

fn actor_response(principal_id: Uuid, carbon_id: &str) -> ActorResponse {
    ActorResponse {
        principal_id,
        actor_type: "carbon".to_owned(),
        public_id: carbon_id.to_owned(),
    }
}

fn encode_cursor(occurred_at: OffsetDateTime, id: Uuid) -> Result<String, AppError> {
    let serialized =
        serde_json::to_vec(&PageCursor { occurred_at, id }).map_err(|_| AppError::Internal {
            category: "page_cursor_encode",
        })?;
    Ok(URL_SAFE_NO_PAD.encode(serialized))
}

fn decode_cursor(value: &str) -> Result<PageCursor, AppError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| super::validation::validation("cursor", "has an invalid format"))?;
    serde_json::from_slice(&decoded)
        .map_err(|_| super::validation::validation("cursor", "has an invalid format"))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use anyhow::ensure;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use http::{HeaderMap, HeaderValue};
    use secrecy::SecretString;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres;
    use time::macros::datetime;
    use uuid::Uuid;

    use crate::{
        config::{KeyringSettings, SecuritySettings},
        domain::actor::{ActorRef, ActorType},
        features::authentication::LogoutTrigger,
        infrastructure::{
            crypto::{CryptoService, DigestPurpose},
            postgres::tokens::{self, AccessContext},
        },
    };

    use super::{
        APPLICATION_LOGOUT_AUTHORITY_QUERY, MATURE_CURRENT_SESSION_QUERY,
        MATURE_TARGET_SESSION_QUERY, OTHER_ACTIVE_SESSIONS_MATURITY_QUERY,
        SESSION_REVOCATION_MIN_AGE_SECONDS, SESSION_REVOKE_ACTION, SESSIONS_REVOKE_ALL_ACTION,
        carbon_context, decode_cursor, encode_cursor, logout_request_binding,
        revocation_event_payload, revocation_targets_another_session, validate_logout_trigger_mode,
    };

    fn logout_test_crypto() -> anyhow::Result<CryptoService> {
        let keyring = |byte| KeyringSettings {
            current_version: 1,
            keys: BTreeMap::from([(1, SecretString::from(URL_SAFE_NO_PAD.encode([byte; 32])))]),
        };
        Ok(CryptoService::from_settings(&SecuritySettings {
            token_peppers: keyring(11),
            blind_index_keys: keyring(21),
            encryption_keys: keyring(31),
            cookie_key: SecretString::from(URL_SAFE_NO_PAD.encode([41_u8; 32])),
            access_token_ttl: Duration::from_mins(30),
            refresh_family_ttl: Duration::from_hours(21_600),
            authorization_code_ttl: Duration::from_secs(120),
            otp_ttl: Duration::from_secs(600),
            otp_max_attempts: 10,
        })?)
    }

    fn logout_idempotency_key(value: &'static str) -> anyhow::Result<super::IdempotencyKey> {
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", HeaderValue::from_static(value));
        super::IdempotencyKey::from_headers(&headers)
            .map_err(|error| anyhow::anyhow!("logout idempotency key failed: {error:?}"))
    }

    #[test]
    fn pagination_cursor_round_trips_and_rejects_malformed_input() {
        let id = Uuid::from_u128(7);
        let timestamp = datetime!(2026-01-02 03:04:05 UTC);
        let encoded = encode_cursor(timestamp, id);
        assert!(matches!(
            encoded.and_then(|value| decode_cursor(&value)),
            Ok(cursor) if cursor.id == id && cursor.occurred_at == timestamp
        ));
        assert!(decode_cursor("not+base64").is_err());
    }

    #[test]
    fn self_service_rejects_delegated_application_tokens() {
        let principal_id = Uuid::from_u128(7);
        let mut context = AccessContext {
            token_id: Uuid::from_u128(1),
            authentication_session_id: Uuid::from_u128(2),
            subject: ActorRef {
                actor_type: ActorType::Carbon,
                id: principal_id,
            },
            client_application_id: None,
            audience_application_id: None,
            audience: "silicon-iam".to_owned(),
            organization_id: None,
            membership_id: None,
            scopes: vec!["iam.self".to_owned()],
            assurance_level: 1,
        };
        assert!(matches!(carbon_context(&context), Ok(id) if id == principal_id));

        context.client_application_id = Some(Uuid::from_u128(3));
        assert!(carbon_context(&context).is_err());
    }

    #[test]
    fn session_revocation_requires_mature_targets_and_cross_session_authority() {
        let current_session_id = Uuid::from_u128(1);

        assert_eq!(SESSION_REVOCATION_MIN_AGE_SECONDS, 12 * 60 * 60);
        assert_eq!(SESSION_REVOKE_ACTION, "account.session_revoke");
        assert_eq!(SESSIONS_REVOKE_ALL_ACTION, "account.sessions_revoke_all");
        assert!(!revocation_targets_another_session(
            current_session_id,
            current_session_id,
        ));
        assert!(revocation_targets_another_session(
            current_session_id,
            Uuid::from_u128(2),
        ));
        assert!(MATURE_TARGET_SESSION_QUERY.contains("session.created_at <="));
        assert!(MATURE_CURRENT_SESSION_QUERY.contains("session.status = 'active'"));
        assert!(MATURE_CURRENT_SESSION_QUERY.contains("session.idle_expires_at >"));
        assert!(MATURE_CURRENT_SESSION_QUERY.contains("session.absolute_expires_at >"));
        assert!(MATURE_CURRENT_SESSION_QUERY.contains("principal.status = 'active'"));
        assert!(
            MATURE_CURRENT_SESSION_QUERY
                .contains("principal.auth_epoch = session.subject_auth_epoch")
        );
        assert!(OTHER_ACTIVE_SESSIONS_MATURITY_QUERY.contains("bool_and"));
        assert!(OTHER_ACTIVE_SESSIONS_MATURITY_QUERY.contains("session.id <> $2"));
        assert!(OTHER_ACTIVE_SESSIONS_MATURITY_QUERY.contains("session.status = 'active'"));
    }

    #[test]
    fn revocation_event_is_routable_and_contains_only_secret_free_state() {
        let principal_id = Uuid::from_u128(7);
        let actor_session_id = Uuid::from_u128(8);
        let revoked = super::RevokedSessionRow {
            session_id: Uuid::from_u128(9),
            version: 2,
            revocation_reason: "user_logout".to_owned(),
        };
        let application_id = Uuid::from_u128(10);
        let payload = revocation_event_payload(
            principal_id,
            actor_session_id,
            Some(application_id),
            &revoked,
        );

        assert_eq!(
            payload
                .get("subject_principal_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok()),
            Some(principal_id)
        );
        assert_eq!(
            payload["authorized_state"]["authentication_session"]["status"],
            "revoked"
        );
        assert_eq!(
            payload["actor"]["application_id"]
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok()),
            Some(application_id)
        );
        for forbidden in [
            "access_token",
            "refresh_token",
            "otp",
            "credential",
            "secret",
        ] {
            assert!(!payload.to_string().contains(forbidden));
        }
    }

    #[test]
    fn application_logout_authority_is_bound_to_the_exact_reviewed_client_token() {
        for predicate in [
            "token.token_class = 'application_access'",
            "token.authentication_session_id = $2",
            "token.subject_principal_id = $3",
            "token.subject_kind = 'carbon'",
            "token.client_application_id = $4",
            "application.id = token.audience_application_id",
            "application.app_id = token.audience",
            "application.review_status = 'verified'",
            "application.deleted_at IS NULL",
            "application_principal.status = 'active'",
            "application_principal.auth_epoch = token.client_auth_epoch",
            "session.subject_auth_epoch = token.subject_auth_epoch",
            "membership.authz_epoch = token.membership_authz_epoch",
            "token.revoked_at IS NULL",
        ] {
            assert!(
                APPLICATION_LOGOUT_AUTHORITY_QUERY.contains(predicate),
                "missing application logout authority predicate: {predicate}"
            );
        }
    }

    #[test]
    fn application_logout_is_global_for_its_bound_session_not_the_whole_account() {
        let trigger = LogoutTrigger::Application {
            application_id: Uuid::from_u128(1),
            access_token_id: Uuid::from_u128(2),
        };
        assert!(validate_logout_trigger_mode(trigger, super::LogoutMode::CurrentSession).is_ok());
        assert!(matches!(
            validate_logout_trigger_mode(trigger, super::LogoutMode::AllSessions),
            Err(crate::error::AppError::Forbidden)
        ));
        assert!(
            validate_logout_trigger_mode(
                LogoutTrigger::FirstPartyCarbon,
                super::LogoutMode::AllSessions
            )
            .is_ok()
        );
    }

    #[test]
    fn logout_replay_binding_is_exact_to_actor_session_and_mode() {
        let carbon_id = Uuid::from_u128(1);
        let session_id = Uuid::from_u128(2);
        let application_id = Uuid::from_u128(3);
        let token_id = Uuid::from_u128(4);
        let application_trigger = LogoutTrigger::Application {
            application_id,
            access_token_id: token_id,
        };
        let application = logout_request_binding(
            carbon_id,
            session_id,
            application_trigger,
            super::LogoutMode::CurrentSession,
        );
        let same_actor_other_token = logout_request_binding(
            carbon_id,
            session_id,
            LogoutTrigger::Application {
                application_id,
                access_token_id: Uuid::from_u128(5),
            },
            super::LogoutMode::CurrentSession,
        );
        assert_eq!(
            application.caller_scope,
            same_actor_other_token.caller_scope
        );
        assert_eq!(
            application.request_digest,
            same_actor_other_token.request_digest
        );

        let other_session = logout_request_binding(
            carbon_id,
            Uuid::from_u128(6),
            application_trigger,
            super::LogoutMode::CurrentSession,
        );
        let other_application = logout_request_binding(
            carbon_id,
            session_id,
            LogoutTrigger::Application {
                application_id: Uuid::from_u128(7),
                access_token_id: token_id,
            },
            super::LogoutMode::CurrentSession,
        );
        let first_party = logout_request_binding(
            carbon_id,
            session_id,
            LogoutTrigger::FirstPartyCarbon,
            super::LogoutMode::CurrentSession,
        );
        assert_ne!(application.request_digest, other_session.request_digest);
        assert_ne!(application.caller_scope, other_application.caller_scope);
        assert_ne!(application.caller_scope, first_party.caller_scope);
    }

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    #[allow(
        clippy::too_many_lines,
        reason = "one fresh-database test proves complete session-wide Application authority revocation"
    )]
    async fn application_logout_revokes_every_authority_bound_to_the_parent_session()
    -> anyhow::Result<()> {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        crate::infrastructure::postgres::migrate(&pool).await?;
        let crypto = logout_test_crypto()?;
        let raw_app_a_token = SecretString::from(format!("oat_{}", "A".repeat(43)));
        let app_a_token_digest = crypto
            .digest_secret(DigestPurpose::ApplicationAccessToken, &raw_app_a_token)
            .map_err(|error| anyhow::anyhow!("logout test token digest failed: {error}"))?;

        let carbon_id = Uuid::from_u128(0x36_01);
        let session_id = Uuid::from_u128(0x36_02);
        let app_a = Uuid::from_u128(0x36_03);
        let app_b = Uuid::from_u128(0x36_04);
        let token_a = Uuid::from_u128(0x36_05);
        let token_b = Uuid::from_u128(0x36_06);
        let grant_a = Uuid::from_u128(0x36_07);
        let grant_b = Uuid::from_u128(0x36_08);
        let family_a = Uuid::from_u128(0x36_09);
        let family_b = Uuid::from_u128(0x36_0a);
        let refresh_a = Uuid::from_u128(0x36_0b);
        let refresh_b = Uuid::from_u128(0x36_0c);
        let redirect_b = Uuid::from_u128(0x36_0d);
        let request_b = Uuid::from_u128(0x36_0e);
        let code_b = Uuid::from_u128(0x36_0f);
        let endpoint_b = Uuid::from_u128(0x36_10);
        let signing_key_b = Uuid::from_u128(0x36_11);
        let organization_id = Uuid::from_u128(0x36_14);
        let owner_membership_id = Uuid::from_u128(0x36_15);

        sqlx::query(
            r"
            INSERT INTO iam.cryptographic_key_versions (purpose, key_version)
            VALUES ('token_hmac', 1), ('contact_aead', 1)
            ",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.principals (id, kind, status, activated_at)
            VALUES
                ($1, 'carbon', 'provisioning', NULL),
                ($2, 'application', 'provisioning', NULL),
                ($3, 'application', 'provisioning', NULL)
            ",
        )
        .bind(carbon_id)
        .bind(app_a)
        .bind(app_b)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO iam.carbons (id, carbon_id, display_name) VALUES ($1, 'logout-carbon', 'Logout Carbon')",
        )
        .bind(carbon_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.carbon_contacts (
                id, carbon_id, kind, ciphertext, nonce,
                encryption_key_version, verified_at
            ) VALUES
                ($1, $3, 'email', decode(repeat('e1', 17), 'hex'),
                    decode(repeat('e2', 12), 'hex'), 1, transaction_timestamp()),
                ($2, $3, 'phone', decode(repeat('f1', 17), 'hex'),
                    decode(repeat('f2', 12), 'hex'), 1, transaction_timestamp())
            ",
        )
        .bind(Uuid::from_u128(0x36_12))
        .bind(Uuid::from_u128(0x36_13))
        .bind(carbon_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            UPDATE iam.principals
            SET status = 'active', activated_at = transaction_timestamp()
            WHERE id = $1 AND kind = 'carbon' AND status = 'provisioning'
            ",
        )
        .bind(carbon_id)
        .execute(&pool)
        .await?;
        let mut setup = pool.begin().await?;
        sqlx::query(
            r"
            INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
            VALUES ($1, 'logout-org', $2, 'Logout Organization')
            ",
        )
        .bind(organization_id)
        .bind(carbon_id)
        .execute(&mut *setup)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.organization_memberships (
                id, organization_id, principal_id, principal_kind, org_role
            ) VALUES ($1, $2, $3, 'carbon', 'owner')
            ",
        )
        .bind(owner_membership_id)
        .bind(organization_id)
        .bind(carbon_id)
        .execute(&mut *setup)
        .await?;
        setup.commit().await?;
        sqlx::query(
            r"
            INSERT INTO iam.applications (
                id, app_id, organization_id, created_by_carbon_id,
                app_name, review_status
            ) VALUES
                ($1, 'logout-app-a', $4, $3, 'Logout App A', 'verified'),
                ($2, 'logout-app-b', $4, $3, 'Logout App B', 'verified')
            ",
        )
        .bind(app_a)
        .bind(app_b)
        .bind(carbon_id)
        .bind(organization_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            UPDATE iam.principals
            SET status = 'active', activated_at = transaction_timestamp()
            WHERE id IN ($1, $2) AND kind = 'application' AND status = 'provisioning'
            ",
        )
        .bind(app_a)
        .bind(app_b)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.application_webhook_endpoints (
                id, application_id, url_ciphertext, url_nonce,
                encryption_key_version, url_digest, status, activated_at
            ) VALUES (
                $1, $2, decode(repeat('d1', 17), 'hex'),
                decode(repeat('d2', 12), 'hex'), 1,
                decode(repeat('d3', 32), 'hex'), 'active', transaction_timestamp()
            )
            ",
        )
        .bind(endpoint_b)
        .bind(app_b)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.application_webhook_signing_keys (
                id, application_id, endpoint_id, secret_version, key_prefix,
                secret_ciphertext, secret_nonce, encryption_key_version
            ) VALUES (
                $1, $2, $3, 1, 'whs_DDDDDDDD',
                decode(repeat('d4', 17), 'hex'),
                decode(repeat('d5', 12), 'hex'), 1
            )
            ",
        )
        .bind(signing_key_b)
        .bind(app_b)
        .bind(endpoint_b)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.authentication_sessions (
                id, subject_principal_id, subject_kind, authentication_method,
                assurance_level, subject_auth_epoch, idle_expires_at,
                absolute_expires_at
            ) VALUES (
                $1, $2, 'carbon', 'email_otp', 1, 1,
                transaction_timestamp() + interval '900 days',
                transaction_timestamp() + interval '900 days'
            )
            ",
        )
        .bind(session_id)
        .bind(carbon_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.oauth_consent_grants (
                id, application_id, subject_principal_id, subject_kind,
                parent_authentication_session_id
            ) VALUES
                ($1, $3, $5, 'carbon', $6),
                ($2, $4, $5, 'carbon', $6)
            ",
        )
        .bind(grant_a)
        .bind(grant_b)
        .bind(app_a)
        .bind(app_b)
        .bind(carbon_id)
        .bind(session_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.refresh_token_families (
                id, authentication_session_id, subject_principal_id,
                client_application_id, oauth_consent_grant_id,
                absolute_expires_at
            ) VALUES
                ($1, $5, $6, $3, $7, transaction_timestamp() + interval '900 days'),
                ($2, $5, $6, $4, $8, transaction_timestamp() + interval '900 days')
            ",
        )
        .bind(family_a)
        .bind(family_b)
        .bind(app_a)
        .bind(app_b)
        .bind(session_id)
        .bind(carbon_id)
        .bind(grant_a)
        .bind(grant_b)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.refresh_tokens (
                id, family_id, token_digest, digest_key_version,
                token_prefix, expires_at
            ) VALUES
                ($1, $3, decode(repeat('a1', 32), 'hex'), 1,
                    'ort_AAAAAAAA', transaction_timestamp() + interval '900 days'),
                ($2, $4, decode(repeat('b1', 32), 'hex'), 1,
                    'ort_BBBBBBBB', transaction_timestamp() + interval '900 days')
            ",
        )
        .bind(refresh_a)
        .bind(refresh_b)
        .bind(family_a)
        .bind(family_b)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.access_tokens (
                id, token_class, token_digest, digest_key_version, token_prefix,
                authentication_session_id, subject_principal_id, subject_kind,
                client_application_id, audience, audience_application_id,
                subject_auth_epoch, client_auth_epoch, created_at, expires_at
            ) VALUES
                ($1, 'application_access', $7, 1,
                    'oat_AAAAAAAA', $5, $6, 'carbon', $3, 'logout-app-a', $3,
                    1, 1, transaction_timestamp(),
                    transaction_timestamp() + interval '30 minutes'),
                ($2, 'application_access', decode(repeat('b2', 32), 'hex'), 1,
                    'oat_BBBBBBBB', $5, $6, 'carbon', $4, 'logout-app-b', $4,
                    1, 1, transaction_timestamp() - interval '1 hour',
                    transaction_timestamp() - interval '30 minutes')
            ",
        )
        .bind(token_a)
        .bind(token_b)
        .bind(app_a)
        .bind(app_b)
        .bind(session_id)
        .bind(carbon_id)
        .bind(app_a_token_digest.as_bytes().as_slice())
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.access_token_scopes (access_token_id, scope)
            VALUES ($1, 'profile'), ($2, 'profile')
            ",
        )
        .bind(token_a)
        .bind(token_b)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.application_redirect_uris (
                id, application_id, redirect_uri, uri_digest,
                status, approved_at
            ) VALUES (
                $1, $2, 'https://logout-app-b.example/callback',
                decode(repeat('c1', 32), 'hex'), 'active', transaction_timestamp()
            )
            ",
        )
        .bind(redirect_b)
        .bind(app_b)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.oauth_authorization_requests (
                id, application_id, redirect_uri_id, authentication_session_id,
                subject_principal_id, subject_kind, state_digest,
                state_ciphertext, state_encryption_nonce, encryption_key_version,
                pkce_code_challenge, status, expires_at, decided_at
            ) VALUES (
                $1, $2, $3, $4, $5, 'carbon',
                decode(repeat('c2', 32), 'hex'), decode(repeat('c3', 17), 'hex'),
                decode(repeat('c4', 12), 'hex'), 1,
                repeat('A', 43), 'approved',
                transaction_timestamp() + interval '2 minutes', transaction_timestamp()
            )
            ",
        )
        .bind(request_b)
        .bind(app_b)
        .bind(redirect_b)
        .bind(session_id)
        .bind(carbon_id)
        .execute(&pool)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.oauth_authorization_codes (
                id, authorization_request_id, application_id, code_digest,
                digest_key_version, code_prefix, expires_at
            ) VALUES (
                $1, $2, $3, decode(repeat('c5', 32), 'hex'), 1,
                'oac_CCCCCCCC', transaction_timestamp() + interval '2 minutes'
            )
            ",
        )
        .bind(code_b)
        .bind(request_b)
        .bind(app_b)
        .execute(&pool)
        .await?;

        let replay_key = logout_idempotency_key("logout-replay-018f47ac-75c7-7f84")?;
        let replay_binding = logout_request_binding(
            carbon_id,
            session_id,
            LogoutTrigger::Application {
                application_id: app_a,
                access_token_id: token_a,
            },
            super::LogoutMode::CurrentSession,
        );
        let mut idempotency_transaction = pool.begin().await?;
        let replay_lease = match super::idempotency::begin::<super::EmptyMutationOutcome>(
            &mut idempotency_transaction,
            &crypto,
            &replay_key,
            &replay_binding.caller_scope,
            super::LOGOUT_ROUTE,
            replay_binding.request_digest,
            false,
        )
        .await?
        {
            super::Claim::Acquired { record_id } => record_id,
            super::Claim::Replay { .. } => {
                anyhow::bail!("fresh logout replay fixture unexpectedly replayed")
            }
        };
        super::idempotency::complete(
            &mut idempotency_transaction,
            &crypto,
            replay_lease,
            204,
            &super::EmptyMutationOutcome::Completed,
            false,
        )
        .await?;
        idempotency_transaction.commit().await?;

        let mut transaction = pool.begin().await?;
        super::lock_application_logout_authority(
            &mut transaction,
            token_a,
            session_id,
            carbon_id,
            app_a,
        )
        .await
        .map_err(|error| anyhow::anyhow!("application logout authority failed: {error:?}"))?;
        let revoked = super::revoke_one(&mut transaction, carbon_id, session_id, "user_logout")
            .await
            .map_err(|error| anyhow::anyhow!("global logout failed: {error:?}"))?
            .ok_or_else(|| anyhow::anyhow!("active parent session was not revoked"))?;
        super::record_revocation(
            &mut transaction,
            carbon_id,
            session_id,
            revoked,
            Some(app_a),
            "session.logout",
        )
        .await
        .map_err(|error| anyhow::anyhow!("logout evidence failed: {error:?}"))?;
        transaction.commit().await?;

        ensure!(
            tokens::authenticate(&pool, &crypto, &raw_app_a_token)
                .await?
                .is_none(),
            "revoked Application token remained normally authenticatable"
        );
        let replay_identity = tokens::identify_for_logout_replay(&pool, &crypto, &raw_app_a_token)
            .await?
            .ok_or_else(|| anyhow::anyhow!("revoked token lost immutable replay identity"))?;
        ensure!(
            replay_identity.token_id == token_a
                && replay_identity.authentication_session_id == session_id,
            "logout replay identity was not bound to the revoked credential"
        );
        let replay = super::replay_completed_logout(
            pool.begin().await?,
            &crypto,
            &replay_key,
            &replay_binding,
        )
        .await
        .map_err(|error| anyhow::anyhow!("completed inactive logout did not replay: {error:?}"))?;
        ensure!(
            replay.status == 204 && replay.replayed,
            "inactive logout replay did not preserve the committed response"
        );
        let fresh_key = logout_idempotency_key("logout-fresh-018f47ac-75c7-7f84a")?;
        let fresh = super::replay_completed_logout(
            pool.begin().await?,
            &crypto,
            &fresh_key,
            &replay_binding,
        )
        .await;
        ensure!(
            matches!(fresh, Err(crate::error::AppError::Unauthenticated)),
            "inactive credential was allowed to reserve or execute a fresh logout"
        );
        let logout_records = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam.idempotency_records WHERE route = $1",
        )
        .bind(super::LOGOUT_ROUTE)
        .fetch_one(&pool)
        .await?;
        ensure!(
            logout_records == 1,
            "inactive fresh logout created an idempotency reservation"
        );

        let globally_revoked = sqlx::query_scalar::<_, bool>(
            r"
            SELECT
                (SELECT status = 'revoked' FROM iam.authentication_sessions WHERE id = $1)
                AND NOT EXISTS (
                    SELECT 1 FROM iam.access_tokens
                    WHERE authentication_session_id = $1 AND revoked_at IS NULL
                )
                AND NOT EXISTS (
                    SELECT 1 FROM iam.refresh_token_families
                    WHERE authentication_session_id = $1 AND status = 'active'
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM iam.refresh_tokens AS token
                    JOIN iam.refresh_token_families AS family ON family.id = token.family_id
                    WHERE family.authentication_session_id = $1 AND token.revoked_at IS NULL
                )
                AND NOT EXISTS (
                    SELECT 1 FROM iam.oauth_consent_grants
                    WHERE parent_authentication_session_id = $1 AND status = 'active'
                )
                AND (SELECT status = 'denied' FROM iam.oauth_authorization_requests WHERE id = $2)
                AND (SELECT consumed_at IS NOT NULL FROM iam.oauth_authorization_codes WHERE id = $3)
                AND (SELECT application_id = $4 FROM iam.authentication_events
                     WHERE authentication_session_id = $1 AND event_type = 'logout.success')
                AND (SELECT event_type = 'session.logout' FROM iam.outbox_events
                     WHERE aggregate_type = 'authentication_session' AND aggregate_id = $1)
            ",
        )
        .bind(session_id)
        .bind(request_b)
        .bind(code_b)
        .bind(app_a)
        .fetch_one(&pool)
        .await?;
        ensure!(
            globally_revoked,
            "application logout did not revoke all session-bound IAM and Application authority"
        );
        let event_occurred_at = sqlx::query_scalar::<_, time::OffsetDateTime>(
            r"
            SELECT created_at
            FROM iam.outbox_events
            WHERE aggregate_type = 'authentication_session'
              AND aggregate_id = $1
              AND event_type = 'session.logout'
            ",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await?;
        let recipient_endpoint_ids = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT endpoint_id
            FROM iam_private.list_worker_application_webhook_recipients(
                NULL, $1, NULL, $2
            )
            ",
        )
        .bind(carbon_id)
        .bind(event_occurred_at)
        .fetch_all(&pool)
        .await?;
        ensure!(
            recipient_endpoint_ids.contains(&endpoint_b),
            "refresh-authorized Application with an expired access token missed global logout"
        );
        Ok(())
    }

    /// Executes the login-history statement against a migrated schema.
    ///
    /// Nothing but a real server catches this class of fault. The statement
    /// type-checked, compiled, and passed review while selecting a bare `id`
    /// that three joined tables each define, so PostgreSQL rejected it at parse
    /// time and `/api/v1/me/login-history` answered 500 to every request. An
    /// empty database is enough: ambiguity is resolved during analysis, long
    /// before a row is read.
    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    async fn the_login_history_statement_is_accepted_by_postgres() -> anyhow::Result<()> {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        crate::infrastructure::postgres::migrate(&pool).await?;

        let rows = sqlx::query(super::LOGIN_HISTORY_QUERY)
            .bind(Uuid::from_u128(0x5e_01))
            .bind(["login.success".to_owned(), "login.failure".to_owned()])
            .bind(None::<time::OffsetDateTime>)
            .bind(None::<Uuid>)
            .bind(51_i64)
            .fetch_all(&pool)
            .await?;

        ensure!(rows.is_empty(), "the fixture database has no events");

        // The cursor branch plans a different comparison, so it is exercised too.
        let paged = sqlx::query(super::LOGIN_HISTORY_QUERY)
            .bind(Uuid::from_u128(0x5e_01))
            .bind(["login.success".to_owned()])
            .bind(Some(datetime!(2026-09-02 12:00 UTC)))
            .bind(Some(Uuid::from_u128(0x5e_02)))
            .bind(51_i64)
            .fetch_all(&pool)
            .await?;

        ensure!(paged.is_empty(), "the fixture database has no events");

        Ok(())
    }
}
