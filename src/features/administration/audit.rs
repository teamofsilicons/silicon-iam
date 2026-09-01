//! Redacted organization and global audit history.

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde_json::Value;
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    error::AppError,
};

use super::{
    access,
    model::{AuditEvent, AuditEventPage, AuditQuery, PublicActor},
    pagination::{self, Cursor},
};

const GLOBAL_CAPABILITY: &str = "audit.read_global";
const ORGANIZATION_CAPABILITY: &str = "audit.read";

#[derive(FromRow)]
struct AuditRow {
    id: Uuid,
    organization_public_id: Option<String>,
    application_public_id: Option<String>,
    actor_principal_id: Option<Uuid>,
    actor_kind: Option<String>,
    actor_public_id: Option<String>,
    action: String,
    target_type: String,
    target_id: Option<Uuid>,
    request_id: Uuid,
    authentication_method: Option<String>,
    result: String,
    before_state: Option<Value>,
    after_state: Option<Value>,
    metadata: Value,
    occurred_at: OffsetDateTime,
}

impl AuditRow {
    fn into_public(self) -> AuditEvent {
        let actor = self
            .actor_principal_id
            .zip(self.actor_kind)
            .zip(self.actor_public_id)
            .map(|((principal_id, actor_type), public_id)| PublicActor {
                principal_id,
                actor_type,
                public_id,
            });
        let mut redacted_diff = BTreeMap::new();
        redacted_diff.insert("result", Value::String(self.result));
        if let Some(before) = self.before_state {
            redacted_diff.insert("before", redact(before));
        }
        if let Some(after) = self.after_state {
            redacted_diff.insert("after", redact(after));
        }
        redacted_diff.insert("metadata", redact(self.metadata));
        AuditEvent {
            id: self.id,
            org_id: self.organization_public_id,
            app_id: self.application_public_id,
            actor,
            effective_actor: None,
            action: self.action,
            target_type: self.target_type,
            target_id: self.target_id,
            request_id: self.request_id.to_string(),
            auth_method: self.authentication_method,
            redacted_diff: serde_json::to_value(redacted_diff)
                .unwrap_or_else(|_| serde_json::json!({ "result": "unavailable" })),
            occurred_at: self.occurred_at,
        }
    }
}

pub(super) async fn list_organization(
    State(state): State<ApiState>,
    Authenticated(access_context): Authenticated,
    Path(org_id): Path<String>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditEventPage>, AppError> {
    validate_org_id(&org_id)?;
    validate_query(&query)?;
    let principal_id = access::require_carbon(&access_context)?;
    let mut transaction = access::begin_serializable(&state, principal_id).await?;
    let organization_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM iam.organizations WHERE org_id = $1 AND status = 'active'",
    )
    .bind(&org_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AppError::NotFound)?;
    let allowed =
        sqlx::query_scalar::<_, bool>("SELECT iam_private.has_organization_capability($1, $2, $3)")
            .bind(organization_id)
            .bind(principal_id)
            .bind(ORGANIZATION_CAPABILITY)
            .fetch_one(&mut *transaction)
            .await?;
    if !allowed {
        return Err(AppError::Forbidden);
    }
    sqlx::query("SELECT set_config('iam.organization_id', $1, true)")
        .bind(organization_id.to_string())
        .execute(&mut *transaction)
        .await?;
    let page = list_page(&mut transaction, query, Some(organization_id)).await?;
    transaction.commit().await?;
    Ok(Json(page))
}

pub(super) async fn list_global(
    State(state): State<ApiState>,
    Authenticated(access_context): Authenticated,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditEventPage>, AppError> {
    validate_query(&query)?;
    let carbon_id = access::require_carbon(&access_context)?;
    let mut transaction = access::begin_serializable(&state, carbon_id).await?;
    access::require_platform_capability(&mut transaction, carbon_id, GLOBAL_CAPABILITY).await?;
    let page = list_page(&mut transaction, query, None).await?;
    transaction.commit().await?;
    Ok(Json(page))
}

async fn list_page(
    transaction: &mut Transaction<'_, Postgres>,
    query: AuditQuery,
    organization_id: Option<Uuid>,
) -> Result<AuditEventPage, AppError> {
    let limit = pagination::limit(query.limit)?;
    let cursor = pagination::decode(query.cursor.as_deref())?;
    let mut builder = QueryBuilder::<Postgres>::new(
        r"
        SELECT
            audit.id,
            identifiers.organization_public_id,
            identifiers.application_public_id,
            audit.actor_principal_id,
            audit.actor_kind::text AS actor_kind,
            identifiers.actor_public_id,
            audit.action,
            audit.target_type,
            audit.target_id,
            audit.request_id,
            audit.authentication_method,
            audit.result,
            audit.before_state,
            audit.after_state,
            audit.metadata,
            audit.occurred_at
        FROM iam.audit_events AS audit
        LEFT JOIN LATERAL iam_private.get_audit_public_identifiers(
            audit.actor_principal_id,
            audit.actor_kind,
            audit.organization_id,
            audit.application_id
        ) AS identifiers ON TRUE
        WHERE TRUE
        ",
    );
    if let Some(organization_id) = organization_id {
        builder.push(" AND audit.organization_id = ");
        builder.push_bind(organization_id);
    }
    if let Some(action) = query.action {
        builder.push(" AND audit.action = ");
        builder.push_bind(action);
    }
    if let Some(target_id) = query.target_principal_id {
        builder.push(" AND audit.target_id = ");
        builder.push_bind(target_id);
    }
    if let Some(from) = query.from {
        builder.push(" AND audit.occurred_at >= ");
        builder.push_bind(from);
    }
    if let Some(to) = query.to {
        builder.push(" AND audit.occurred_at <= ");
        builder.push_bind(to);
    }
    if let Some(cursor) = cursor {
        builder.push(" AND (audit.occurred_at, audit.id) < (");
        builder.push_bind(cursor.at);
        builder.push(", ");
        builder.push_bind(cursor.id);
        builder.push(")");
    }
    builder.push(" ORDER BY audit.occurred_at DESC, audit.id DESC LIMIT ");
    builder.push_bind(limit + 1);
    let mut rows = builder
        .build_query_as::<AuditRow>()
        .fetch_all(&mut **transaction)
        .await?;
    let page = pagination::page(&mut rows, limit, |row| Cursor {
        at: row.occurred_at,
        id: row.id,
    })?;
    Ok(AuditEventPage {
        items: rows.into_iter().map(AuditRow::into_public).collect(),
        page,
    })
}

fn validate_org_id(value: &str) -> Result<(), AppError> {
    if !(3..=50).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(validation("org_id", "has an invalid format"));
    }
    Ok(())
}

fn validate_query(query: &AuditQuery) -> Result<(), AppError> {
    if query.action.as_ref().is_some_and(|action| {
        action.is_empty() || action.len() > 200 || action.contains(char::is_whitespace)
    }) {
        return Err(validation("action", "has an invalid format"));
    }
    if query.from.zip(query.to).is_some_and(|(from, to)| from > to) {
        return Err(validation("from", "must not be later than to"));
    }
    Ok(())
}

fn redact(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let value = if sensitive_key(&key) {
                        Value::String("[REDACTED]".to_owned())
                    } else {
                        redact(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact).collect()),
        scalar => scalar,
    }
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "password",
        "secret",
        "token",
        "otp",
        "code",
        "email",
        "phone",
        "contact",
        "ciphertext",
        "nonce",
        "signature",
        "credential",
    ]
    .iter()
    .any(|fragment| key.contains(fragment))
}

fn validation(field: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        details: serde_json::json!({ "field": field, "message": message }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursively_redacts_secret_shaped_keys() {
        let value = serde_json::json!({
            "safe": "visible",
            "nested": { "access_token": "never", "count": 2 },
            "items": [{ "email": "private@example.test" }]
        });
        let redacted = redact(value);
        assert_eq!(redacted["safe"], "visible");
        assert_eq!(redacted["nested"]["access_token"], "[REDACTED]");
        assert_eq!(redacted["items"][0]["email"], "[REDACTED]");
    }

    #[test]
    fn validates_bounded_time_window() {
        let query = AuditQuery {
            cursor: None,
            limit: None,
            action: None,
            target_principal_id: None,
            from: Some(OffsetDateTime::UNIX_EPOCH + time::Duration::SECOND),
            to: Some(OffsetDateTime::UNIX_EPOCH),
        };
        assert!(matches!(
            validate_query(&query),
            Err(AppError::Validation { .. })
        ));
    }
}
