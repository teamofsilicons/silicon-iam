use std::time::Duration;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use serde_json::json;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    error::AppError,
    infrastructure::{
        postgres::idempotency::OneTimeResponseReplayTtl,
        providers::workos::{WorkOsConnection, WorkOsOrganization},
    },
};

use super::{
    model::{SsoConfiguration, SsoEntitlement, SsoEntitlementResponse, SsoSetupLink, TestResult},
    support::{self, Claim, MutationEvent},
    validation,
};

const CONFIG_ROUTE: &str = "DELETE /api/v1/organizations/{org_id}/sso";
const SETUP_ROUTE: &str = "POST /api/v1/organizations/{org_id}/sso/setup-link";
const TEST_ROUTE: &str = "POST /api/v1/organizations/{org_id}/sso/test";
const ENTITLEMENT_ROUTE: &str = "PUT /api/v1/admin/organizations/{org_id}/sso-entitlement";
const SETUP_TTL_SECONDS: u64 = 300;
const SETUP_TTL_SECONDS_I64: i64 = 300;

#[derive(FromRow)]
struct ConfigurationRow {
    org_id: String,
    platform_enabled: bool,
    status: String,
    join_method: String,
    provider_organization_id: Option<String>,
    provider_connection_id: Option<String>,
    version: i64,
    updated_at: OffsetDateTime,
}

#[derive(FromRow)]
struct SetupContextRow {
    organization_id: Uuid,
    organization_name: String,
    platform_enabled: bool,
    provider_organization_id: Option<String>,
}

#[derive(FromRow)]
#[allow(
    clippy::struct_field_names,
    reason = "row fields deliberately preserve the local and provider identifier distinction"
)]
struct TestContextRow {
    organization_id: Uuid,
    provider_organization_id: String,
    provider_connection_id: String,
}

#[derive(FromRow)]
struct EntitlementMutationRow {
    organization_id: Uuid,
    enabled: bool,
    status: String,
    version: i64,
}

#[derive(FromRow)]
struct DisabledConnectionRow {
    id: Uuid,
    status: String,
    version: i64,
}

#[derive(Serialize)]
struct VersionRequest<'a> {
    org_id: &'a str,
}

#[derive(Serialize)]
struct SetupRequest<'a> {
    org_id: &'a str,
}

#[derive(Serialize)]
struct TestRequest<'a> {
    org_id: &'a str,
}

#[derive(Serialize)]
struct EntitlementRequest<'a> {
    org_id: &'a str,
    version: i64,
    enabled: bool,
    reason: &'a Option<String>,
}

pub(super) async fn get(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(raw_org_id): Path<String>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&raw_org_id)?;
    let mut scope = support::begin_organization(&state, &authenticated, &org_id, false).await?;
    support::require_manage(&scope.access)?;
    let row = fetch_configuration(&mut scope.transaction, scope.access.organization_id).await?;
    let configuration = configuration_from_row(row);
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::json_response(
        StatusCode::OK,
        &configuration,
        Some(configuration.version),
        false,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "provider I/O is deliberately outside both idempotency/domain transactions"
)]
pub(super) async fn create_setup_link(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(raw_org_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&raw_org_id)?;
    let request = SetupRequest {
        org_id: org_id.as_str(),
    };
    let mut preflight = support::begin_organization(&state, &authenticated, &org_id, false).await?;
    support::require_manage(&preflight.access)?;
    let lease = match support::claim(
        &mut preflight.transaction,
        &state,
        &authenticated,
        &headers,
        SETUP_ROUTE,
        org_id.as_str(),
        &request,
        true,
    )
    .await?
    {
        Claim::Replay(response) => {
            preflight
                .transaction
                .commit()
                .await
                .map_err(support::database)?;
            return Ok(response);
        }
        Claim::Acquired(lease) => lease,
    };
    let context =
        fetch_setup_context(&mut preflight.transaction, preflight.access.organization_id).await?;
    if !context.platform_enabled {
        return Err(AppError::Conflict {
            code: "sso_entitlement_required".into(),
        });
    }
    support::enforce_rate_limit(
        &state,
        "workos_setup_link",
        SecretString::from(format!(
            "{}:{}",
            context.organization_id, authenticated.0.subject.id
        )),
        5,
        Duration::from_mins(10),
    )
    .await?;
    let workos = support::workos(&state)?;
    // Commit the request-bound reservation before the provider side effect.
    // A concurrent identical request now observes `processing`, while a later
    // request replays the encrypted response completed below.
    preflight
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let external_id = context.organization_id.to_string();
    let provider_organization = workos
        .ensure_organization(&external_id, &context.organization_name)
        .await
        .map_err(support::map_workos)?;
    if provider_organization.external_id.as_deref() != Some(external_id.as_str()) {
        return Err(AppError::ProviderUnavailable);
    }
    if context
        .provider_organization_id
        .as_ref()
        .is_some_and(|existing| existing != &provider_organization.id)
    {
        return Err(AppError::Conflict {
            code: "sso_provider_organization_conflict".into(),
        });
    }
    let portal_link = workos
        .portal_link(&provider_organization.id)
        .await
        .map_err(support::map_workos)?;
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(SETUP_TTL_SECONDS_I64);
    let response_value = SsoSetupLink {
        url: portal_link.url.expose_secret().to_owned(),
        expires_in: SETUP_TTL_SECONDS,
        expires_at,
    };

    let mut scope = support::begin_organization(&state, &authenticated, &org_id, true).await?;
    support::require_manage(&scope.access)?;
    let row = sqlx::query_as::<_, (i64,)>(
        r"
        UPDATE iam.organization_sso_configs
        SET provider_organization_id = $2,
            status = CASE WHEN status = 'active' THEN 'active' ELSE 'pending' END,
            last_error_code = NULL,
            updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND platform_enabled
        RETURNING version
        ",
    )
    .bind(scope.access.organization_id)
    .bind(&provider_organization.id)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(|error| support::database_conflict(error, "sso_provider_organization_conflict"))?
    .ok_or_else(|| AppError::Conflict {
        code: "sso_entitlement_required".into(),
    })?;
    let setup_session_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.sso_setup_sessions (
            id, organization_id, requested_by_membership_id, expires_at
        ) VALUES ($1, $2, $3, $4)
        ",
    )
    .bind(setup_session_id)
    .bind(scope.access.organization_id)
    .bind(scope.access.membership_id)
    .bind(expires_at)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        Some(scope.access.organization_id),
        MutationEvent {
            action: "sso.setup_link.create",
            target_type: "sso_setup_session",
            target_id: Some(setup_session_id),
            aggregate_type: "organization_sso_config",
            aggregate_id: scope.access.organization_id,
            aggregate_version: row.0,
            event_type: "sso.setup_link.created.v1",
            before_state: None,
            after_state: None,
            metadata: json!({ "expires_in": SETUP_TTL_SECONDS }),
        },
    )
    .await?;
    let replay_ttl = OneTimeResponseReplayTtl::new(Duration::from_secs(SETUP_TTL_SECONDS))
        .map_err(|_| AppError::Internal {
            category: "sso_setup_replay_ttl",
        })?;
    let body = support::complete_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &response_value,
        Some(replay_ttl),
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(|error| support::database_conflict(error, "sso_setup_conflict"))?;
    support::stored_json_response(StatusCode::CREATED, body, None, true)
}

#[allow(
    clippy::too_many_lines,
    reason = "disable performs one explicit authorization, concurrency, state transition, and audit workflow"
)]
pub(super) async fn disable(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(raw_org_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&raw_org_id)?;
    let request = VersionRequest {
        org_id: org_id.as_str(),
    };
    let mut scope = support::begin_organization(&state, &authenticated, &org_id, true).await?;
    support::require_manage(&scope.access)?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        CONFIG_ROUTE,
        org_id.as_str(),
        &request,
        false,
    )
    .await?
    {
        Claim::Replay(response) => {
            scope
                .transaction
                .commit()
                .await
                .map_err(support::database)?;
            return Ok(response);
        }
        Claim::Acquired(lease) => lease,
    };
    let expected_version = support::expected_version(&headers)?;
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        support::SSO_CHANGE_ACTION,
        scope.access.organization_id,
    )
    .await?;
    let join_method = sqlx::query_scalar::<_, String>(
        "SELECT join_method::text FROM iam.organizations WHERE id = $1 FOR UPDATE",
    )
    .bind(scope.access.organization_id)
    .fetch_one(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    if join_method == "sso" {
        return Err(AppError::Conflict {
            code: "sso_join_method_active".into(),
        });
    }
    let version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.organization_sso_configs
        SET status = 'disabled', last_error_code = NULL,
            updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND version = $2
        RETURNING version
        ",
    )
    .bind(scope.access.organization_id)
    .bind(expected_version)
    .fetch_optional(&mut *scope.transaction)
    .await
    .map_err(support::database)?
    .ok_or_else(|| AppError::PreconditionFailed {
        code: "etag_mismatch".into(),
    })?;

    let disabled_connections = sqlx::query_as::<_, DisabledConnectionRow>(
        r"
        SELECT id, status, version
        FROM iam.sso_connections
        WHERE organization_id = $1 AND status <> 'disabled'
        ORDER BY id
        FOR UPDATE
        ",
    )
    .bind(scope.access.organization_id)
    .fetch_all(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        UPDATE iam.sso_connections
        SET status = 'disabled', disabled_at = transaction_timestamp(),
            updated_at = transaction_timestamp()
        WHERE organization_id = $1
          AND id = ANY($2::uuid[])
          AND status <> 'disabled'
        ",
    )
    .bind(scope.access.organization_id)
    .bind(
        disabled_connections
            .iter()
            .map(|connection| connection.id)
            .collect::<Vec<_>>(),
    )
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        "UPDATE iam.sso_setup_sessions SET status = 'cancelled' WHERE organization_id = $1 AND status IN ('created', 'opened')",
    )
    .bind(scope.access.organization_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        "UPDATE iam.sso_authorization_transactions SET status = 'cancelled' WHERE organization_id = $1 AND status = 'pending'",
    )
    .bind(scope.access.organization_id)
    .execute(&mut *scope.transaction)
    .await
    .map_err(support::database)?;
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        Some(scope.access.organization_id),
        MutationEvent {
            action: "sso.configuration.disable",
            target_type: "organization_sso_config",
            target_id: Some(scope.access.organization_id),
            aggregate_type: "organization_sso_config",
            aggregate_id: scope.access.organization_id,
            aggregate_version: version,
            event_type: "sso.configuration.disabled.v1",
            before_state: None,
            after_state: Some(json!({ "status": "disabled" })),
            metadata: json!({}),
        },
    )
    .await?;
    for connection in &disabled_connections {
        support::record_mutation(
            &mut scope.transaction,
            &authenticated,
            Some(scope.access.organization_id),
            MutationEvent {
                action: "sso.connection.deactivate",
                target_type: "sso_connection",
                target_id: Some(connection.id),
                aggregate_type: "sso_connection",
                aggregate_id: connection.id,
                aggregate_version: next_connection_version(connection.version)?,
                event_type: "sso.connection.deactivated.v1",
                before_state: Some(json!({ "status": connection.status })),
                after_state: Some(json!({ "status": "disabled" })),
                metadata: json!({ "cause": "sso_configuration_disabled" }),
            },
        )
        .await?;
    }
    support::complete_empty(&mut scope.transaction, &state, lease).await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(|error| support::database_conflict(error, "sso_disable_conflict"))?;
    Ok(support::empty_response())
}

#[allow(
    clippy::too_many_lines,
    reason = "provider I/O is deliberately outside both idempotency/domain transactions"
)]
pub(super) async fn test(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(raw_org_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&raw_org_id)?;
    let request = TestRequest {
        org_id: org_id.as_str(),
    };
    let mut preflight = support::begin_organization(&state, &authenticated, &org_id, false).await?;
    support::require_manage(&preflight.access)?;
    let lease = match support::claim(
        &mut preflight.transaction,
        &state,
        &authenticated,
        &headers,
        TEST_ROUTE,
        org_id.as_str(),
        &request,
        false,
    )
    .await?
    {
        Claim::Replay(response) => {
            preflight
                .transaction
                .commit()
                .await
                .map_err(support::database)?;
            return Ok(response);
        }
        Claim::Acquired(lease) => lease,
    };
    let context =
        fetch_test_context(&mut preflight.transaction, preflight.access.organization_id).await?;
    support::enforce_rate_limit(
        &state,
        "workos_configuration_test",
        SecretString::from(format!(
            "{}:{}",
            context.organization_id, authenticated.0.subject.id
        )),
        10,
        Duration::from_mins(10),
    )
    .await?;
    let workos = support::workos(&state)?;
    preflight
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    let (provider_organization, provider_connection) = tokio::try_join!(
        workos.organization(&context.provider_organization_id),
        workos.connection(&context.provider_connection_id),
    )
    .map_err(support::map_workos)?;
    let ok = configuration_matches_provider(&context, &provider_organization, &provider_connection);
    let result = TestResult {
        ok,
        message: Some(if ok {
            format!(
                "Active WorkOS organization and connection {} are consistent.",
                context.provider_connection_id
            )
        } else {
            "The WorkOS organization or active connection mapping does not match this organization."
                .to_owned()
        }),
        checked_at: OffsetDateTime::now_utc(),
    };
    let mut scope = support::begin_organization(&state, &authenticated, &org_id, true).await?;
    support::require_manage(&scope.access)?;
    let body = support::complete_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &result,
        None,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(support::database)?;
    support::stored_json_response(StatusCode::OK, body, None, false)
}

#[allow(
    clippy::too_many_lines,
    reason = "platform entitlement replacement keeps authorization, step-up, mutation, and audit visibly ordered"
)]
pub(super) async fn replace_entitlement(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(raw_org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<SsoEntitlement>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&raw_org_id)?;
    let input_version = input.version;
    let enabled = input.enabled;
    let reason = validation::entitlement_reason(input.reason)?;
    let request = EntitlementRequest {
        org_id: org_id.as_str(),
        version: input_version,
        enabled,
        reason: &reason,
    };
    let (mut transaction, carbon_id) = support::begin_platform(&state, &authenticated).await?;
    let lease = match support::claim(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        ENTITLEMENT_ROUTE,
        org_id.as_str(),
        &request,
        false,
    )
    .await?
    {
        Claim::Replay(response) => {
            transaction.commit().await.map_err(support::database)?;
            return Ok(response);
        }
        Claim::Acquired(lease) => lease,
    };
    let expected_version = support::expected_version(&headers)?;
    if input_version != expected_version {
        return Err(AppError::PreconditionFailed {
            code: "etag_body_version_mismatch".into(),
        });
    }
    let organization_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT iam_private.resolve_platform_sso_organization($1)",
    )
    .bind(org_id.as_str())
    .fetch_one(&mut *transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    let _assertion_id = support::consume_step_up(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        support::PLATFORM_ADMIN_ACTION,
        organization_id,
    )
    .await?;
    let row = sqlx::query_as::<_, EntitlementMutationRow>(
        r"
        SELECT organization_id, enabled, status, version
        FROM iam_private.replace_organization_sso_entitlement($1, $2, $3, $4)
        ",
    )
    .bind(org_id.as_str())
    .bind(expected_version)
    .bind(enabled)
    .bind(reason.as_deref())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(map_entitlement_error)?
    .ok_or(AppError::NotFound)?;
    let response_value = SsoEntitlementResponse {
        enabled: row.enabled,
        reason: reason.clone(),
        version: row.version,
    };
    support::record_mutation(
        &mut transaction,
        &authenticated,
        Some(row.organization_id),
        MutationEvent {
            action: "sso.entitlement.replace",
            target_type: "organization_sso_config",
            target_id: Some(row.organization_id),
            aggregate_type: "organization_sso_config",
            aggregate_id: row.organization_id,
            aggregate_version: row.version,
            event_type: "sso.entitlement.replaced.v1",
            before_state: None,
            after_state: Some(json!({ "enabled": row.enabled, "status": row.status })),
            metadata: json!({ "reason_present": reason.is_some(), "actor_id": carbon_id }),
        },
    )
    .await?;
    let body = support::complete_json(
        &mut transaction,
        &state,
        lease,
        StatusCode::OK,
        &response_value,
        None,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(|error| support::database_conflict(error, "sso_entitlement_conflict"))?;
    support::stored_json_response(StatusCode::OK, body, Some(row.version), false)
}

async fn fetch_configuration(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<ConfigurationRow, AppError> {
    sqlx::query_as::<_, ConfigurationRow>(
        r"
        SELECT
            organization.org_id,
            config.platform_enabled,
            config.status,
            organization.join_method::text AS join_method,
            config.provider_organization_id,
            connection.provider_connection_id,
            config.version,
            config.updated_at
        FROM iam.organizations AS organization
        JOIN iam.organization_sso_configs AS config
          ON config.organization_id = organization.id
        LEFT JOIN LATERAL (
            SELECT candidate.provider_connection_id
            FROM iam.sso_connections AS candidate
            WHERE candidate.organization_id = organization.id
            ORDER BY (candidate.status = 'active') DESC, candidate.updated_at DESC, candidate.id
            LIMIT 1
        ) AS connection ON true
        WHERE organization.id = $1
        ",
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn fetch_setup_context(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<SetupContextRow, AppError> {
    sqlx::query_as::<_, SetupContextRow>(
        r"
        SELECT
            organization.id AS organization_id,
            organization.name AS organization_name,
            config.platform_enabled,
            config.provider_organization_id
        FROM iam.organizations AS organization
        JOIN iam.organization_sso_configs AS config
          ON config.organization_id = organization.id
        WHERE organization.id = $1 AND organization.status = 'active'
        ",
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)
}

async fn fetch_test_context(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<TestContextRow, AppError> {
    sqlx::query_as::<_, TestContextRow>(
        r"
        SELECT
            config.organization_id,
            config.provider_organization_id,
            connection.provider_connection_id
        FROM iam.organization_sso_configs AS config
        JOIN iam.sso_connections AS connection
          ON connection.organization_id = config.organization_id
         AND connection.status = 'active'
        WHERE config.organization_id = $1
          AND config.platform_enabled
          AND config.status = 'active'
        ",
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?
    .ok_or_else(|| AppError::Conflict {
        code: "sso_not_active".into(),
    })
}

fn configuration_from_row(row: ConfigurationRow) -> SsoConfiguration {
    SsoConfiguration {
        org_id: row.org_id,
        entitled: row.platform_enabled,
        status: row.status,
        join_method: row.join_method,
        workos_organization_id: row.provider_organization_id,
        connection_id: row.provider_connection_id,
        version: row.version,
        updated_at: row.updated_at,
    }
}

fn configuration_matches_provider(
    context: &TestContextRow,
    organization: &WorkOsOrganization,
    connection: &WorkOsConnection,
) -> bool {
    let expected_external_id = context.organization_id.to_string();
    organization.id == context.provider_organization_id
        && organization.external_id.as_deref() == Some(expected_external_id.as_str())
        && connection.id == context.provider_connection_id
        && connection.organization_id == context.provider_organization_id
        && connection.state == "active"
}

fn next_connection_version(version: i64) -> Result<i64, AppError> {
    version
        .checked_add(1)
        .filter(|version| *version > 0)
        .ok_or(AppError::Internal {
            category: "sso_connection_version",
        })
}

fn map_entitlement_error(error: sqlx::Error) -> AppError {
    if error
        .as_database_error()
        .is_some_and(|value| value.message() == "sso_config_version_mismatch")
    {
        AppError::PreconditionFailed {
            code: "etag_mismatch".into(),
        }
    } else {
        support::database(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{TestContextRow, configuration_matches_provider, next_connection_version};
    use crate::infrastructure::providers::workos::{WorkOsConnection, WorkOsOrganization};
    use uuid::Uuid;

    #[test]
    fn provider_test_requires_the_exact_active_connection_mapping() {
        let context = TestContextRow {
            organization_id: Uuid::nil(),
            provider_organization_id: "org_local_mapping".to_owned(),
            provider_connection_id: "conn_local_mapping".to_owned(),
        };
        let organization = WorkOsOrganization {
            id: "org_local_mapping".to_owned(),
            name: "Example".to_owned(),
            external_id: Some(Uuid::nil().to_string()),
        };
        let connection = WorkOsConnection {
            id: "conn_local_mapping".to_owned(),
            organization_id: "org_local_mapping".to_owned(),
            state: "active".to_owned(),
        };
        assert!(configuration_matches_provider(
            &context,
            &organization,
            &connection
        ));
        assert!(!configuration_matches_provider(
            &context,
            &organization,
            &WorkOsConnection {
                state: "inactive".to_owned(),
                ..connection
            }
        ));
    }

    #[test]
    fn configuration_disable_advances_each_connection_aggregate() {
        assert_eq!(next_connection_version(1).ok(), Some(2));
        assert!(next_connection_version(i64::MAX).is_err());
    }
}
