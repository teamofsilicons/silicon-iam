//! Declared scope configuration and version-bound, explicit application consent.
use super::{
    error::ApiError,
    model::{ApplicationScope, ExternalScope, ScopeDefinition},
    security::Bearer,
    validation,
};
use crate::api::ApiState;
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction, types::Json as SqlJson};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Deserialize)]
pub(super) struct CatalogQuery {
    app_id: Option<String>,
}
#[derive(Serialize)]
pub(super) struct Catalog {
    items: Vec<ScopeDefinition>,
}
#[derive(Deserialize)]
pub(super) struct LoginPolicy {
    pub(super) scope_version: i64,
    pub(super) consent_required: bool,
    pub(super) scopes: Vec<ScopeDefinition>,
}
pub(super) fn names(scope: &ApplicationScope) -> Vec<String> {
    let mut names = scope.iam.clone();
    names.extend(
        scope
            .external
            .iter()
            .map(|item| format!("obo:{}:{}", item.app_id, item.endpoint_id)),
    );
    names.sort();
    names
}
pub(super) fn from_names(names: &[String]) -> ApplicationScope {
    let mut result = ApplicationScope {
        iam: Vec::new(),
        external: Vec::new(),
    };
    for name in names {
        if let Some((app_id, endpoint_id)) = name
            .strip_prefix("obo:")
            .and_then(|value| value.split_once(':'))
        {
            result.external.push(ExternalScope {
                app_id: app_id.into(),
                endpoint_id: endpoint_id.into(),
            });
        } else {
            result.iam.push(name.clone());
        }
    }
    result
}
pub(super) fn validate(scope: &ApplicationScope) -> Result<(), ApiError> {
    let all = names(scope);
    if all.is_empty() || all.len() > 100 || all.iter().collect::<BTreeSet<_>>().len() != all.len() {
        return Err(ApiError::validation(
            "app_scope",
            "must declare 1-100 unique permissions",
        ));
    }
    for scope in &scope.iam {
        if !IAM_SCOPES.contains(&scope.as_str()) {
            return Err(ApiError::validation(
                "app_scope.iam",
                format!("unknown IAM permission: {scope}"),
            ));
        }
    }
    for external in &scope.external {
        validation::app_id(&external.app_id)?;
        if external.endpoint_id.is_empty()
            || external.endpoint_id.len() > 128
            || !external.endpoint_id.bytes().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
            })
        {
            return Err(ApiError::validation(
                "app_scope.external",
                "endpoint_id must name a published endpoint",
            ));
        }
    }
    Ok(())
}
pub(super) fn validate_webhook(values: &[String]) -> Result<(), ApiError> {
    if values.is_empty()
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
        || values
            .iter()
            .any(|v| !matches!(v.as_str(), "full" | "membership" | "updates" | "trust"))
    {
        return Err(ApiError::validation(
            "webhook_scope",
            "select unique categories: full, membership, updates, trust",
        ));
    }
    Ok(())
}
pub(super) async fn configure(
    tx: &mut Transaction<'_, Postgres>,
    app: Uuid,
    scope: &ApplicationScope,
    actor: Uuid,
) -> Result<(), ApiError> {
    validate(scope)?;
    sqlx::query("SELECT iam_private.configure_application_scopes($1,$2,$3)")
        .bind(app)
        .bind(SqlJson(scope))
        .bind(actor)
        .execute(&mut **tx)
        .await
        .map_err(|error| database_error(&error))?;
    Ok(())
}
pub(super) async fn policy(
    tx: &mut Transaction<'_, Postgres>,
    app: Uuid,
) -> Result<LoginPolicy, ApiError> {
    sqlx::query_scalar::<_, Option<SqlJson<LoginPolicy>>>(
        "SELECT iam_private.application_login_scope_policy($1)",
    )
    .bind(app)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::internal("application_scope_policy"))?
    .map(|value| value.0)
    .ok_or_else(|| ApiError::forbidden("application_not_verified"))
}
pub(super) fn validate_consent(
    policy: &LoginPolicy,
    version: i64,
    approved: &[String],
) -> Result<Vec<String>, ApiError> {
    if version != policy.scope_version {
        return Err(ApiError::precondition_failed());
    }
    let expected = policy
        .scopes
        .iter()
        .map(|s| s.scope.clone())
        .collect::<BTreeSet<_>>();
    let submitted = approved.iter().cloned().collect::<BTreeSet<_>>();
    if submitted.len() != approved.len() || submitted != expected {
        return Err(ApiError::validation(
            "approved_scopes",
            "explicitly approve the current application permissions before selecting organizations",
        ));
    }
    Ok(expected.into_iter().collect())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IamCatalogQuery {}

/// IAM-only permission discovery for the scoped backend.
pub(crate) fn scoped_router() -> axum::Router<ApiState> {
    axum::Router::new().route(
        "/api/v1/application-scopes",
        axum::routing::get(iam_catalog),
    )
}

/// The application-only surface never exposes external OBO endpoint discovery.
pub(super) async fn iam_catalog(
    State(state): State<ApiState>,
    bearer: Bearer,
    Query(_query): Query<IamCatalogQuery>,
) -> Result<Json<Catalog>, ApiError> {
    catalog(State(state), bearer, Query(CatalogQuery { app_id: None })).await
}

pub(super) async fn catalog(
    State(state): State<ApiState>,
    Bearer(access): Bearer,
    Query(query): Query<CatalogQuery>,
) -> Result<Json<Catalog>, ApiError> {
    if let Some(app) = &query.app_id {
        validation::app_id(app)?;
    }
    let mut tx = crate::infrastructure::postgres::context::begin(
        state.db(),
        crate::infrastructure::postgres::context::DatabaseContext {
            principal_id: Some(access.subject.id),
            application_id: access.client_application_id,
            organization_id: None,
            signup_session_id: None,
        },
    )
    .await
    .map_err(|_| ApiError::internal("scope_catalog_context"))?;
    let items = catalog_items(&mut tx, query.app_id.as_deref()).await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("scope_catalog_commit"))?;
    Ok(Json(Catalog { items }))
}

/// Resolves public scope descriptors and target visibility in the same snapshot.
/// An empty published catalog is distinct from an unavailable application.
pub(super) async fn catalog_items(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Option<&str>,
) -> Result<Vec<ScopeDefinition>, ApiError> {
    sqlx::query_scalar::<_, Option<SqlJson<Vec<ScopeDefinition>>>>(
        r"
        SELECT CASE WHEN $1::text IS NULL THEN (
            SELECT COALESCE(jsonb_agg(to_jsonb(catalog) ORDER BY catalog.scope), '[]'::jsonb)
            FROM iam_private.iam_scope_catalog() AS catalog
        ) WHEN EXISTS (
            SELECT 1
            FROM iam.applications AS application
            JOIN iam.principals AS principal
              ON principal.id = application.id
             AND principal.kind = 'application'
             AND principal.status = 'active'
            WHERE application.app_id = $1
              AND application.review_status = 'verified'
              AND application.deleted_at IS NULL
              AND iam_private.application_is_discoverable(application.id,NULL)
        ) THEN (
            SELECT COALESCE(jsonb_agg(to_jsonb(catalog) ORDER BY catalog.scope), '[]'::jsonb)
            FROM iam_private.application_scope_catalog($1) AS catalog
        ) END
        ",
    )
    .bind(app_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::internal("scope_catalog"))?
    .map(|items| items.0)
    .ok_or_else(ApiError::not_found)
}
pub(super) fn database_error(error: &sqlx::Error) -> ApiError {
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
    {
        Some("42501") => ApiError::forbidden("scope_request_forbidden"),
        Some("40001") => ApiError::precondition_failed(),
        Some("22023" | "23514") => {
            ApiError::validation("app_scope", "invalid permission, endpoint or review state")
        }
        Some("23505") => ApiError::conflict("scope_request_conflict"),
        _ => ApiError::internal("application_scope_database"),
    }
}
pub(super) const IAM_SCOPES: &[&str] = &[
    "self.identity.read",
    "self.profile.read",
    "self.email.read",
    "self.phone.read",
    "self.organizations.read",
    "self.membership.read",
    "self.capabilities.read",
    "self.job_role.read",
    "self.tags.read",
    "self.silicon_access.read",
    "self.hierarchy.read",
    "self.trust.read",
    "directory.carbons.read",
    "directory.silicons.read",
    "directory.profiles.read",
    "directory.memberships.read",
    "directory.capabilities.read",
    "directory.job_roles.read",
    "directory.tags.read",
    "directory.silicon_access.read",
    "directory.hierarchy.read",
    "organization.tags.read",
    "organization.trust.read",
    "organization.invitations.read",
    "organization.governance.read",
    "organizations.create",
    "organization.profile.update",
    "organization.invitations.create",
    "organization.invitations.revoke",
    "organization.silicons.create",
    "organization.testing_environments.create",
    "organization.silicons.update",
    "organization.carbons.remove",
    "organization.silicons.remove",
    "organization.tags.create",
    "organization.tags.update",
    "organization.tags.delete",
    "organization.member_tags.update",
    "organization.job_roles.update",
    "organization.silicon_access.update",
    "organization.trust.update",
    "organization.admins.promote",
    "organization.admins.demote",
    "organization.capabilities.update",
    "organization.change_requests.read",
    "organization.job_role_changes.request",
    "organization.tag_changes.request",
    "organization.change_requests.decide",
    "organization.job_role_history.read",
    "organization.tag_history.read",
    "organizations.join",
    "organization.sso.read",
    "organization.sso.manage",
    "organization.silicons.credentials.rotate",
];
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_implicit_or_stale_consent() {
        let policy = LoginPolicy {
            scope_version: 3,
            consent_required: true,
            scopes: vec![ScopeDefinition {
                scope: "self.identity.read".into(),
                description: "Identity".into(),
                critical: false,
                app_id: None,
            }],
        };
        assert!(validate_consent(&policy, 3, &[]).is_err());
        assert!(validate_consent(&policy, 2, &["self.identity.read".into()]).is_err());
        assert!(validate_consent(&policy, 3, &["self.identity.read".into()]).is_ok());
        assert!(
            validate_consent(
                &policy,
                3,
                &["self.identity.read".into(), "self.email.read".into()]
            )
            .is_err()
        );
    }
    #[test]
    fn external_permissions_round_trip_without_collisions() {
        let scope = ApplicationScope {
            iam: vec!["self.identity.read".into()],
            external: vec![ExternalScope {
                app_id: "vendor>files".into(),
                endpoint_id: "files.read".into(),
            }],
        };
        assert_eq!(from_names(&names(&scope)), scope);
        let mut duplicate = scope.clone();
        duplicate.external.push(scope.external[0].clone());
        assert!(validate(&duplicate).is_err());
        assert!(
            validate(&ApplicationScope {
                iam: vec!["profile".into()],
                external: vec![]
            })
            .is_err()
        );
    }
}
