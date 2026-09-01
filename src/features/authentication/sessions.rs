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
    infrastructure::postgres::{
        step_up::{self, RequiredAssurance, StepUpExpectation, StepUpToken},
        tokens::AccessContext,
    },
};

use super::{
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
    let mut transaction = state.pool.begin().await.map_err(|_| AppError::Internal {
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
    let mut transaction = state.pool.begin().await.map_err(|_| AppError::Internal {
        category: "login_history_transaction",
    })?;
    set_principal_context(&mut transaction, principal_id).await?;
    let carbon_id = carbon_handle(&mut transaction, principal_id).await?;
    let rows = sqlx::query_as::<_, LoginEventRow>(
        r"
        SELECT
            id,
            event_type,
            outcome,
            application.app_id,
            organization.org_id,
            request_id,
            occurred_at
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
        ",
    )
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
    let mut transaction = serializable(&state.pool, "session_revoke_transaction").await?;
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
    principal_id: Uuid,
    authentication_session_id: Uuid,
    key: &IdempotencyKey,
    step_up_token: Option<&StepUpToken>,
    mode: LogoutMode,
) -> Result<Outcome<()>, AppError> {
    let mode_value = match mode {
        LogoutMode::CurrentSession => b"current".as_slice(),
        LogoutMode::AllSessions => b"all".as_slice(),
    };
    let request_digest = idempotency::digest_parts(
        b"logout",
        &[
            principal_id.as_bytes(),
            authentication_session_id.as_bytes(),
            mode_value,
        ],
    );
    let mut transaction = serializable(&state.pool, "logout_transaction").await?;
    let record_id = match idempotency::begin::<EmptyMutationOutcome>(
        &mut transaction,
        &state.crypto,
        key,
        principal_id.as_bytes(),
        LOGOUT_ROUTE,
        request_digest,
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

    let revokes_other_sessions = if matches!(mode, LogoutMode::AllSessions) {
        authorize_all_sessions_logout(&mut transaction, principal_id, authentication_session_id)
            .await?
    } else {
        false
    };
    if revokes_other_sessions {
        let token = step_up_token.ok_or_else(|| AppError::PreconditionRequired {
            code: "step_up_required".into(),
        })?;
        consume_verified_channel_step_up(
            &mut transaction,
            state,
            principal_id,
            authentication_session_id,
            token,
            SESSIONS_REVOKE_ALL_ACTION,
            principal_id,
        )
        .await?;
    }

    let revoked = if revokes_other_sessions {
        revoke_all(&mut transaction, principal_id).await?
    } else {
        revoke_one(
            &mut transaction,
            principal_id,
            authentication_session_id,
            "user_logout",
        )
        .await?
        .into_iter()
        .collect()
    };
    for session in revoked {
        record_revocation(
            &mut transaction,
            principal_id,
            authentication_session_id,
            session,
            "logout.completed",
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
        .map_err(|error| database_conflict(&error, "logout_serialization_conflict"))?;
    Ok(Outcome::fresh(204, ()))
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
        revoke_session_credentials(transaction, session_id, reason).await?;
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
        revoke_session_credentials(transaction, row.session_id, "user_logout_all").await?;
    }
    Ok(rows)
}

async fn revoke_session_credentials(
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

async fn record_revocation(
    transaction: &mut Transaction<'_, Postgres>,
    principal_id: Uuid,
    actor_authentication_session_id: Uuid,
    session: RevokedSessionRow,
    outbox_event: &'static str,
) -> Result<(), AppError> {
    let metadata =
        revocation_event_payload(principal_id, actor_authentication_session_id, &session);
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
    use time::macros::datetime;
    use uuid::Uuid;

    use crate::{
        domain::actor::{ActorRef, ActorType},
        infrastructure::postgres::tokens::AccessContext,
    };

    use super::{
        MATURE_CURRENT_SESSION_QUERY, MATURE_TARGET_SESSION_QUERY,
        OTHER_ACTIVE_SESSIONS_MATURITY_QUERY, SESSION_REVOCATION_MIN_AGE_SECONDS,
        SESSION_REVOKE_ACTION, SESSIONS_REVOKE_ALL_ACTION, carbon_context, decode_cursor,
        encode_cursor, revocation_event_payload, revocation_targets_another_session,
    };

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
        let payload = revocation_event_payload(principal_id, actor_session_id, &revoked);

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
}
