//! Platform-administrator grant lifecycle.

use std::{borrow::Cow, str::FromStr as _};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Serialize;
use sqlx::{FromRow, Postgres, Transaction};
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
    model::{
        PageQuery, PlatformAdministrator, PlatformAdministratorCreate, PlatformAdministratorPage,
        PublicActor,
    },
    pagination::{self, Cursor},
};

const CAPABILITY: &str = "platform.admins_manage";
const ACTION: &str = "platform_admin.manage";
const CREATE_ROUTE: &str = "/api/v1/admin/platform-administrators";
const REMOVE_ROUTE: &str = "/api/v1/admin/platform-administrators/{principal_id}";

#[derive(FromRow)]
struct AdministratorRow {
    grant_id: Uuid,
    principal_id: Uuid,
    carbon_id: String,
    created_by_principal_id: Option<Uuid>,
    created_by_carbon_id: Option<String>,
    granted_at: OffsetDateTime,
}

impl AdministratorRow {
    fn into_public(self) -> PlatformAdministrator {
        PlatformAdministrator {
            principal: carbon_actor(self.principal_id, self.carbon_id),
            created_by: self
                .created_by_principal_id
                .zip(self.created_by_carbon_id)
                .map(|(id, carbon_id)| carbon_actor(id, carbon_id)),
            created_at: self.granted_at,
        }
    }
}

#[derive(FromRow)]
struct CarbonRow {
    principal_id: Uuid,
    carbon_id: String,
    status: String,
}

#[derive(FromRow)]
struct GrantRow {
    id: Uuid,
    version: i64,
    granted_at: OffsetDateTime,
}

#[derive(Serialize)]
struct RemoveRequest {
    principal_id: Uuid,
}

pub(super) async fn list(
    State(state): State<ApiState>,
    Authenticated(access_context): Authenticated,
    Query(query): Query<PageQuery>,
) -> Result<Json<PlatformAdministratorPage>, AppError> {
    let carbon_id = access::require_carbon(&access_context)?;
    let limit = pagination::limit(query.limit)?;
    let cursor = pagination::decode(query.cursor.as_deref())?;
    let mut transaction = access::begin_serializable(&state, carbon_id).await?;
    access::require_platform_capability(&mut transaction, carbon_id, CAPABILITY).await?;

    let (cursor_at, cursor_id) =
        cursor.map_or((None, None), |cursor| (Some(cursor.at), Some(cursor.id)));
    let mut rows = sqlx::query_as::<_, AdministratorRow>(
        r"
        SELECT
            role_grant.id AS grant_id,
            role_grant.carbon_id AS principal_id,
            carbon.carbon_id,
            role_grant.granted_by_carbon_id AS created_by_principal_id,
            grantor.carbon_id AS created_by_carbon_id,
            role_grant.granted_at
        FROM iam.platform_role_grants AS role_grant
        JOIN iam.carbons AS carbon ON carbon.id = role_grant.carbon_id
        JOIN iam.principals AS principal
          ON principal.id = role_grant.carbon_id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        LEFT JOIN iam.carbons AS grantor
          ON grantor.id = role_grant.granted_by_carbon_id
        WHERE role_grant.role = 'platform_administrator'
          AND role_grant.revoked_at IS NULL
          AND (
              $1::timestamptz IS NULL
              OR (role_grant.granted_at, role_grant.id) < ($1, $2)
          )
        ORDER BY role_grant.granted_at DESC, role_grant.id DESC
        LIMIT $3
        ",
    )
    .bind(cursor_at)
    .bind(cursor_id)
    .bind(limit + 1)
    .fetch_all(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let page = pagination::page(&mut rows, limit, |row| Cursor {
        at: row.granted_at,
        id: row.grant_id,
    })?;
    Ok(Json(PlatformAdministratorPage {
        items: rows
            .into_iter()
            .map(AdministratorRow::into_public)
            .collect(),
        page,
    }))
}

pub(super) async fn create(
    State(state): State<ApiState>,
    Authenticated(access_context): Authenticated,
    headers: HeaderMap,
    Json(input): Json<PlatformAdministratorCreate>,
) -> Result<Response, AppError> {
    let actor_id = access::require_carbon(&access_context)?;
    let target_carbon_id =
        CarbonId::from_str(&input.carbon_id).map_err(|_| AppError::Validation {
            details: serde_json::json!({
                "field": "carbon_id",
                "message": "has an invalid format"
            }),
        })?;
    let mut transaction = access::begin_serializable(&state, actor_id).await?;
    access::require_platform_capability(&mut transaction, actor_id, CAPABILITY).await?;
    let claim = access::claim(
        &mut transaction,
        &state,
        &headers,
        actor_id,
        CREATE_ROUTE,
        &input,
    )
    .await?;
    if let IdempotencyClaim::Replay(response) = claim {
        transaction.commit().await?;
        return access::replay(response, None);
    }
    let IdempotencyClaim::Acquired(lease) = claim else {
        return Err(AppError::Internal {
            category: "platform_admin_create_claim",
        });
    };

    let target = lock_active_carbon(&mut transaction, target_carbon_id.as_str()).await?;
    access::consume_step_up(
        &mut transaction,
        &state,
        &headers,
        &access_context,
        ACTION,
        Some(target.principal_id),
    )
    .await?;
    let actor = carbon_by_id(&mut transaction, actor_id).await?;
    let grant_id = Uuid::now_v7();
    let grant = sqlx::query_as::<_, GrantRow>(
        r"
        INSERT INTO iam.platform_role_grants (
            id, carbon_id, role, grant_source, granted_by_carbon_id, reason
        ) VALUES ($1, $2, 'platform_administrator', 'administrator', $3, $4)
        RETURNING id, version, granted_at
        ",
    )
    .bind(grant_id)
    .bind(target.principal_id)
    .bind(actor_id)
    .bind("granted through the platform administration API")
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| conflict(error, "platform_administrator_already_exists"))?;

    let response = PlatformAdministrator {
        principal: carbon_actor(target.principal_id, target.carbon_id),
        created_by: Some(carbon_actor(actor.principal_id, actor.carbon_id)),
        created_at: grant.granted_at,
    };
    record_grant_event(
        &mut transaction,
        &access_context,
        grant.id,
        grant.version,
        target.principal_id,
        "platform.administrator.granted",
        "platform_administrator.granted.v1",
        None,
        Some(serde_json::json!({ "status": "active" })),
    )
    .await?;
    let (body, http_response) = access::json(StatusCode::CREATED, &response, None)?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        lease,
        StatusCode::CREATED.as_u16(),
        &body,
    )
    .await?;
    transaction.commit().await.map_err(commit_conflict)?;
    Ok(http_response)
}

pub(super) async fn remove(
    State(state): State<ApiState>,
    Authenticated(access_context): Authenticated,
    Path(principal_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let actor_id = access::require_carbon(&access_context)?;
    let request = RemoveRequest { principal_id };
    let mut transaction = access::begin_serializable(&state, actor_id).await?;
    access::require_platform_capability(&mut transaction, actor_id, CAPABILITY).await?;
    let claim = access::claim(
        &mut transaction,
        &state,
        &headers,
        actor_id,
        REMOVE_ROUTE,
        &request,
    )
    .await?;
    if let IdempotencyClaim::Replay(_) = claim {
        transaction.commit().await?;
        return access::empty(StatusCode::NO_CONTENT, true);
    }
    let IdempotencyClaim::Acquired(lease) = claim else {
        return Err(AppError::Internal {
            category: "platform_admin_remove_claim",
        });
    };
    access::consume_step_up(
        &mut transaction,
        &state,
        &headers,
        &access_context,
        ACTION,
        Some(principal_id),
    )
    .await?;

    let grant = sqlx::query_as::<_, GrantRow>(
        r"
        UPDATE iam.platform_role_grants
        SET revoked_by_carbon_id = $2,
            revoked_at = transaction_timestamp(),
            reason = 'revoked through the platform administration API'
        WHERE carbon_id = $1
          AND role = 'platform_administrator'
          AND revoked_at IS NULL
        RETURNING id, version, granted_at
        ",
    )
    .bind(principal_id)
    .bind(actor_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AppError::NotFound)?;
    record_grant_event(
        &mut transaction,
        &access_context,
        grant.id,
        grant.version,
        principal_id,
        "platform.administrator.revoked",
        "platform_administrator.revoked.v1",
        Some(serde_json::json!({ "status": "active" })),
        Some(serde_json::json!({ "status": "revoked" })),
    )
    .await?;
    idempotency::complete(
        &mut transaction,
        &state.crypto,
        lease,
        StatusCode::NO_CONTENT.as_u16(),
        &[],
    )
    .await?;
    transaction.commit().await.map_err(commit_conflict)?;
    access::empty(StatusCode::NO_CONTENT, false)
}

async fn lock_active_carbon(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: &str,
) -> Result<CarbonRow, AppError> {
    let row = sqlx::query_as::<_, CarbonRow>(
        r"
        SELECT carbon.id AS principal_id, carbon.carbon_id, principal.status
        FROM iam.carbons AS carbon
        JOIN iam.principals AS principal
          ON principal.id = carbon.id AND principal.kind = 'carbon'
        WHERE carbon.carbon_id = $1 AND carbon.deleted_at IS NULL
        ",
    )
    .bind(carbon_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AppError::NotFound)?;
    if row.status != "active" {
        return Err(AppError::Conflict {
            code: Cow::Borrowed("carbon_not_active"),
        });
    }
    Ok(row)
}

async fn carbon_by_id(
    transaction: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<CarbonRow, AppError> {
    sqlx::query_as::<_, CarbonRow>(
        r"
        SELECT carbon.id AS principal_id, carbon.carbon_id, principal.status
        FROM iam.carbons AS carbon
        JOIN iam.principals AS principal
          ON principal.id = carbon.id AND principal.kind = 'carbon'
        WHERE carbon.id = $1 AND carbon.deleted_at IS NULL
        ",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AppError::Unauthenticated)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the event boundary is explicit and auditable"
)]
async fn record_grant_event(
    transaction: &mut Transaction<'_, Postgres>,
    access_context: &crate::infrastructure::postgres::tokens::AccessContext,
    grant_id: Uuid,
    version: i64,
    target_id: Uuid,
    action: &'static str,
    event_type: &'static str,
    before_state: Option<serde_json::Value>,
    after_state: Option<serde_json::Value>,
) -> Result<(), AppError> {
    let aggregate = AggregateVersion {
        aggregate_type: "platform_role_grant",
        aggregate_id: grant_id,
        version,
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
            target_type: "platform_administrator",
            target_id: Some(target_id),
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state,
            after_state,
            metadata: serde_json::json!({ "role": "platform_administrator" }),
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
                "platform_principal_id": target_id,
                "role": "platform_administrator"
            }),
        },
    )
    .await?;
    Ok(())
}

fn carbon_actor(principal_id: Uuid, carbon_id: String) -> PublicActor {
    PublicActor {
        principal_id,
        actor_type: "carbon".to_owned(),
        public_id: carbon_id,
    }
}

fn conflict(error: sqlx::Error, code: &'static str) -> AppError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|state| state == "23505")
    {
        AppError::Conflict {
            code: Cow::Borrowed(code),
        }
    } else {
        AppError::from(error)
    }
}

fn commit_conflict(error: sqlx::Error) -> AppError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|state| state == "23514")
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
    fn bootstrap_provenance_is_truthfully_nullable() {
        let row = AdministratorRow {
            grant_id: Uuid::nil(),
            principal_id: Uuid::nil(),
            carbon_id: "root_admin".to_owned(),
            created_by_principal_id: None,
            created_by_carbon_id: None,
            granted_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(row.into_public().created_by.is_none());
    }

    #[test]
    fn platform_admin_idempotency_routes_follow_the_shared_contract() {
        for route in [CREATE_ROUTE, REMOVE_ROUTE] {
            assert!(crate::infrastructure::postgres::idempotency::validate_route(route).is_ok());
        }
    }
}
