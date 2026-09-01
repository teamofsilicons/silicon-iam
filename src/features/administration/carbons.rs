//! Platform-managed Carbon security status transitions.

use std::{borrow::Cow, str::FromStr as _};

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Serialize;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::{
        actor::{ActorRef, ActorType},
        auth::CarbonId,
    },
    error::AppError,
    infrastructure::postgres::{
        events::{self, AggregateVersion, AuditRecord, OutboxRecord},
        idempotency::{self, IdempotencyClaim},
    },
};

use super::{
    access,
    model::{CarbonAdminStatus, CarbonStatusReplace, PublicActor},
};

const CAPABILITY: &str = "carbons.status_manage";
const ACTION: &str = "platform_admin.manage";
const ROUTE: &str = "/api/v1/admin/carbons/{carbon_id}/status";

#[derive(Serialize)]
struct StatusRequest<'a> {
    carbon_id: &'a str,
    status: &'a str,
    reason: &'a str,
    expected_version: i64,
}

#[derive(FromRow)]
struct StatusRow {
    principal_id: Uuid,
    carbon_id: String,
    status: String,
    version: i64,
    updated_at: OffsetDateTime,
}

impl StatusRow {
    fn into_public(self) -> CarbonAdminStatus {
        CarbonAdminStatus {
            principal: PublicActor {
                principal_id: self.principal_id,
                actor_type: "carbon".to_owned(),
                public_id: self.carbon_id,
            },
            status: self.status,
            version: self.version,
            updated_at: self.updated_at,
        }
    }
}

pub(super) async fn replace_status(
    State(state): State<ApiState>,
    Authenticated(access_context): Authenticated,
    Path(raw_carbon_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CarbonStatusReplace>,
) -> Result<Response, AppError> {
    let actor_id = access::require_carbon(&access_context)?;
    let carbon_id = CarbonId::from_str(&raw_carbon_id)
        .map_err(|_| validation("carbon_id", "has an invalid format"))?;
    validate_input(&input)?;
    let expected_version = access::expected_version(&headers)?;
    let request = StatusRequest {
        carbon_id: carbon_id.as_str(),
        status: &input.status,
        reason: &input.reason,
        expected_version,
    };

    let mut transaction = access::begin_serializable(&state, actor_id).await?;
    access::require_platform_capability(&mut transaction, actor_id, CAPABILITY).await?;
    let claim = access::claim(
        &mut transaction,
        &state,
        &headers,
        actor_id,
        ROUTE,
        &request,
    )
    .await?;
    if let IdempotencyClaim::Replay(response) = claim {
        let prior = serde_json::from_slice::<CarbonAdminStatus>(&response.body).map_err(|_| {
            AppError::Internal {
                category: "carbon_status_replay_decode",
            }
        })?;
        transaction.commit().await?;
        return access::replay(response, Some(prior.version));
    }
    let IdempotencyClaim::Acquired(lease) = claim else {
        return Err(AppError::Internal {
            category: "carbon_status_claim",
        });
    };

    let target_id = resolve_target_id(&mut transaction, carbon_id.as_str()).await?;
    access::consume_step_up(
        &mut transaction,
        &state,
        &headers,
        &access_context,
        ACTION,
        Some(target_id),
    )
    .await?;
    let row = sqlx::query_as::<_, StatusRow>(
        r"
        SELECT principal_id, carbon_id, status, version, updated_at
        FROM iam_private.replace_carbon_status($1, $2, $3, $4)
        ",
    )
    .bind(carbon_id.as_str())
    .bind(expected_version)
    .bind(&input.status)
    .bind(&input.reason)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(status_error)?
    .ok_or(AppError::NotFound)?;
    let before_status = if row.status == "suspended" {
        "active"
    } else {
        "suspended"
    };
    record_event(
        &mut transaction,
        &access_context,
        &row,
        before_status,
        &input.reason,
    )
    .await?;
    let response = row.into_public();
    let (body, http_response) = access::json(StatusCode::OK, &response, Some(response.version))?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        lease,
        StatusCode::OK.as_u16(),
        &body,
    )
    .await?;
    transaction.commit().await.map_err(commit_error)?;
    Ok(http_response)
}

async fn resolve_target_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    carbon_id: &str,
) -> Result<Uuid, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT principal_id
        FROM iam_private.get_platform_carbon($1)
        ",
    )
    .bind(carbon_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AppError::NotFound)
}

async fn record_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    access_context: &crate::infrastructure::postgres::tokens::AccessContext,
    row: &StatusRow,
    before_status: &str,
    reason: &str,
) -> Result<(), AppError> {
    let (action, event_type) = if row.status == "suspended" {
        ("platform.carbon.suspended", "carbon.updated.v1")
    } else {
        ("platform.carbon.reactivated", "carbon.updated.v1")
    };
    let aggregate = AggregateVersion {
        aggregate_type: "carbon",
        aggregate_id: row.principal_id,
        version: row.version,
    };
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: ActorType::Carbon,
                id: access_context.subject.id,
            }),
            authentication_session_id: Some(access_context.authentication_session_id),
            organization_id: None,
            application_id: access_context.client_application_id,
            action,
            target_type: "carbon",
            target_id: Some(row.principal_id),
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state: Some(serde_json::json!({ "status": before_status })),
            after_state: Some(serde_json::json!({ "status": row.status })),
            metadata: serde_json::json!({ "reason": reason }),
        },
    )
    .await?;
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: None,
            aggregate,
            event_ordinal: 1,
            event_type,
            schema_version: 1,
            payload: serde_json::json!({
                "principal_id": row.principal_id,
                "carbon_id": row.carbon_id,
                "status": row.status
            }),
        },
    )
    .await?;
    Ok(())
}

fn validate_input(input: &CarbonStatusReplace) -> Result<(), AppError> {
    if !matches!(input.status.as_str(), "active" | "suspended") {
        return Err(validation("status", "must be active or suspended"));
    }
    if input.reason != input.reason.trim()
        || !(1..=2000).contains(&input.reason.chars().count())
        || input.reason.chars().any(char::is_control)
    {
        return Err(validation(
            "reason",
            "must contain 1 to 2000 non-control characters without surrounding whitespace",
        ));
    }
    Ok(())
}

fn validation(field: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: serde_json::json!({ "field": field, "message": message }),
    }
}

fn status_error(error: sqlx::Error) -> AppError {
    let message = error
        .as_database_error()
        .map(sqlx::error::DatabaseError::message);
    match message {
        Some("carbon_version_mismatch") => AppError::PreconditionFailed {
            code: Cow::Borrowed("version_mismatch"),
        },
        Some("carbon_owns_active_organization") => AppError::Conflict {
            code: Cow::Borrowed("ownership_transfer_required"),
        },
        Some("carbon_status_unchanged") => AppError::Conflict {
            code: Cow::Borrowed("carbon_status_unchanged"),
        },
        Some("carbon_status_transition_forbidden") => AppError::Conflict {
            code: Cow::Borrowed("carbon_status_transition_forbidden"),
        },
        _ => AppError::from(error),
    }
}

fn commit_error(error: sqlx::Error) -> AppError {
    if error
        .as_database_error()
        .is_some_and(|database| database.code().as_deref() == Some("23514"))
    {
        AppError::Conflict {
            code: Cow::Borrowed("last_platform_administrator"),
        }
    } else {
        AppError::from(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ambiguous_reason_whitespace() {
        let result = validate_input(&CarbonStatusReplace {
            status: "suspended".to_owned(),
            reason: " incident ".to_owned(),
        });
        assert!(matches!(result, Err(AppError::Validation { .. })));
    }

    #[test]
    fn accepts_closed_status_vocabulary() {
        assert!(
            validate_input(&CarbonStatusReplace {
                status: "active".to_owned(),
                reason: "review completed".to_owned(),
            })
            .is_ok()
        );
    }

    #[test]
    fn carbon_status_idempotency_route_follows_the_shared_contract() {
        assert!(crate::infrastructure::postgres::idempotency::validate_route(ROUTE).is_ok());
    }
}
