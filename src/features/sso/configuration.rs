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
    domain::organization::{TrustBoundary, TrustLevel},
    error::AppError,
    infrastructure::postgres::idempotency::OneTimeResponseReplayTtl,
};

use super::{
    model::{
        AdmissionMode, SsoAdmissionPolicy, SsoConfiguration, SsoEntitlement,
        SsoEntitlementResponse, SsoSetupLink, TestResult, TrustValue,
    },
    support::{self, Claim, MutationEvent},
    validation,
};

const CONFIG_ROUTE: &str = "/api/v1/organizations/{org_id}/sso";
const SETUP_ROUTE: &str = "/api/v1/organizations/{org_id}/sso/setup-link";
const POLICY_ROUTE: &str = "/api/v1/organizations/{org_id}/sso/policy";
const TEST_ROUTE: &str = "/api/v1/organizations/{org_id}/sso/test";
const ENTITLEMENT_ROUTE: &str = "/api/v1/admin/organizations/{org_id}/sso-entitlement";
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
    allow_policy_admission: bool,
    default_job_role: String,
    first_silicon_membership_id: Option<Uuid>,
    default_trust_boundary: String,
    default_trust_level: String,
    allowed_domains: Vec<String>,
    allowed_groups: Vec<String>,
    default_tag_ids: Vec<Uuid>,
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

#[derive(Serialize)]
struct VersionRequest<'a> {
    org_id: &'a str,
    expected_version: i64,
}

#[derive(Serialize)]
struct SetupRequest<'a> {
    org_id: &'a str,
}

#[derive(Serialize)]
struct PolicyRequest<'a> {
    org_id: &'a str,
    expected_version: i64,
    policy: &'a SsoAdmissionPolicy,
}

#[derive(Serialize)]
struct TestRequest<'a> {
    org_id: &'a str,
}

#[derive(Serialize)]
struct EntitlementRequest<'a> {
    org_id: &'a str,
    expected_version: i64,
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
    let configuration = configuration_from_row(row)?;
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
    let preflight_claim = support::claim(
        &mut preflight.transaction,
        &state,
        &authenticated,
        &headers,
        SETUP_ROUTE,
        &request,
        true,
    )
    .await?;
    if let Claim::Replay(response) = preflight_claim {
        preflight
            .transaction
            .commit()
            .await
            .map_err(support::database)?;
        return Ok(response);
    }
    let context =
        fetch_setup_context(&mut preflight.transaction, preflight.access.organization_id).await?;
    if !context.platform_enabled {
        return Err(AppError::Conflict {
            code: "sso_entitlement_required".into(),
        });
    }
    preflight
        .transaction
        .rollback()
        .await
        .map_err(support::database)?;

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
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        SETUP_ROUTE,
        &request,
        true,
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
    reason = "policy replacement validates every tenant-qualified reference atomically"
)]
pub(super) async fn replace_policy(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    Path(raw_org_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<SsoAdmissionPolicy>,
) -> Result<Response, AppError> {
    let org_id = validation::organization_id(&raw_org_id)?;
    let policy = validation::policy(input)?;
    let expected_version = support::expected_version(&headers)?;
    let request = PolicyRequest {
        org_id: org_id.as_str(),
        expected_version,
        policy: &policy,
    };
    let mut scope = support::begin_organization(&state, &authenticated, &org_id, true).await?;
    support::require_manage(&scope.access)?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        POLICY_ROUTE,
        &request,
        false,
    )
    .await?
    {
        Claim::Replay(mut response) => {
            scope
                .transaction
                .commit()
                .await
                .map_err(support::database)?;
            let replay_version = expected_version.checked_add(1).ok_or(AppError::Internal {
                category: "sso_policy_version",
            })?;
            support::insert_etag(&mut response, replay_version)?;
            return Ok(response);
        }
        Claim::Acquired(lease) => lease,
    };
    support::consume_step_up(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        support::SSO_CHANGE_ACTION,
        scope.access.organization_id,
    )
    .await?;
    validate_policy_references(
        &mut scope.transaction,
        scope.access.organization_id,
        &policy,
    )
    .await?;
    let allow_policy_admission = policy.mode == AdmissionMode::VerifiedIdentityPolicy;
    sqlx::query(
        r"
        INSERT INTO iam.sso_membership_policies (
            organization_id, allow_policy_admission, default_job_role,
            first_silicon_membership_id, default_trust_boundary,
            default_trust_level, allowed_domains, allowed_groups
        ) VALUES ($1, $2, $3, $4, $5::iam.trust_boundary, $6::iam.trust_level, $7, $8)
        ON CONFLICT (organization_id) DO UPDATE SET
            allow_policy_admission = EXCLUDED.allow_policy_admission,
            default_job_role = EXCLUDED.default_job_role,
            first_silicon_membership_id = EXCLUDED.first_silicon_membership_id,
            default_trust_boundary = EXCLUDED.default_trust_boundary,
            default_trust_level = EXCLUDED.default_trust_level,
            allowed_domains = EXCLUDED.allowed_domains,
            allowed_groups = EXCLUDED.allowed_groups,
            updated_at = transaction_timestamp()
        ",
    )
    .bind(scope.access.organization_id)
    .bind(allow_policy_admission)
    .bind(&policy.default_job_role)
    .bind(policy.first_silicon_membership_id)
    .bind(trust_boundary_value(policy.default_trust.boundary))
    .bind(trust_level_value(policy.default_trust.level))
    .bind(&policy.allowed_email_domains)
    .bind(&policy.allowed_groups)
    .execute(&mut *scope.transaction)
    .await
    .map_err(|error| support::database_conflict(error, "sso_policy_conflict"))?;
    sqlx::query("DELETE FROM iam.sso_membership_policy_tags WHERE organization_id = $1")
        .bind(scope.access.organization_id)
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    for tag_id in &policy.default_tag_ids {
        sqlx::query(
            "INSERT INTO iam.sso_membership_policy_tags (organization_id, tag_id) VALUES ($1, $2)",
        )
        .bind(scope.access.organization_id)
        .bind(tag_id)
        .execute(&mut *scope.transaction)
        .await
        .map_err(support::database)?;
    }
    let version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.organization_sso_configs
        SET updated_at = transaction_timestamp()
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
    support::record_mutation(
        &mut scope.transaction,
        &authenticated,
        Some(scope.access.organization_id),
        MutationEvent {
            action: "sso.policy.replace",
            target_type: "sso_membership_policy",
            target_id: Some(scope.access.organization_id),
            aggregate_type: "organization_sso_config",
            aggregate_id: scope.access.organization_id,
            aggregate_version: version,
            event_type: "sso.policy.replaced.v1",
            before_state: None,
            after_state: Some(redacted_policy(&policy)),
            metadata: json!({ "mode": admission_mode_value(policy.mode) }),
        },
    )
    .await?;
    let body = support::complete_json(
        &mut scope.transaction,
        &state,
        lease,
        StatusCode::OK,
        &policy,
        None,
    )
    .await?;
    scope
        .transaction
        .commit()
        .await
        .map_err(|error| support::database_conflict(error, "sso_policy_conflict"))?;
    support::stored_json_response(StatusCode::OK, body, Some(version), false)
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
    let expected_version = support::expected_version(&headers)?;
    let request = VersionRequest {
        org_id: org_id.as_str(),
        expected_version,
    };
    let mut scope = support::begin_organization(&state, &authenticated, &org_id, true).await?;
    support::require_manage(&scope.access)?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        CONFIG_ROUTE,
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
    sqlx::query(
        r"
        UPDATE iam.sso_connections
        SET status = 'disabled', disabled_at = transaction_timestamp(),
            updated_at = transaction_timestamp()
        WHERE organization_id = $1 AND status <> 'disabled'
        ",
    )
    .bind(scope.access.organization_id)
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
    let claim = support::claim(
        &mut preflight.transaction,
        &state,
        &authenticated,
        &headers,
        TEST_ROUTE,
        &request,
        false,
    )
    .await?;
    if let Claim::Replay(response) = claim {
        preflight
            .transaction
            .commit()
            .await
            .map_err(support::database)?;
        return Ok(response);
    }
    let context =
        fetch_test_context(&mut preflight.transaction, preflight.access.organization_id).await?;
    preflight
        .transaction
        .rollback()
        .await
        .map_err(support::database)?;
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
    let provider = support::workos(&state)?
        .organization(&context.provider_organization_id)
        .await
        .map_err(support::map_workos)?;
    let expected_external_id = context.organization_id.to_string();
    let ok = provider.id == context.provider_organization_id
        && provider.external_id.as_deref() == Some(expected_external_id.as_str());
    let result = TestResult {
        ok,
        message: Some(if ok {
            format!(
                "Active WorkOS organization and connection {} are consistent.",
                context.provider_connection_id
            )
        } else {
            "The WorkOS organization mapping does not match this organization.".to_owned()
        }),
        checked_at: OffsetDateTime::now_utc(),
    };
    let mut scope = support::begin_organization(&state, &authenticated, &org_id, true).await?;
    support::require_manage(&scope.access)?;
    let lease = match support::claim(
        &mut scope.transaction,
        &state,
        &authenticated,
        &headers,
        TEST_ROUTE,
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
    let expected_version = support::expected_version(&headers)?;
    if input.version != expected_version {
        return Err(AppError::PreconditionFailed {
            code: "etag_body_version_mismatch".into(),
        });
    }
    let reason = validation::entitlement_reason(input.reason)?;
    let request = EntitlementRequest {
        org_id: org_id.as_str(),
        expected_version,
        enabled: input.enabled,
        reason: &reason,
    };
    let (mut transaction, carbon_id) = support::begin_platform(&state, &authenticated).await?;
    let organization_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT iam_private.resolve_platform_sso_organization($1)",
    )
    .bind(org_id.as_str())
    .fetch_one(&mut *transaction)
    .await
    .map_err(support::database)?
    .ok_or(AppError::NotFound)?;
    let lease = match support::claim(
        &mut transaction,
        &state,
        &authenticated,
        &headers,
        ENTITLEMENT_ROUTE,
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
    .bind(input.enabled)
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
            config.updated_at,
            COALESCE(policy.allow_policy_admission, false) AS allow_policy_admission,
            COALESCE(policy.default_job_role, '') AS default_job_role,
            policy.first_silicon_membership_id,
            COALESCE(policy.default_trust_boundary::text, 'internal') AS default_trust_boundary,
            COALESCE(policy.default_trust_level::text, 'not_trusted') AS default_trust_level,
            COALESCE(policy.allowed_domains, '{}'::text[]) AS allowed_domains,
            COALESCE(policy.allowed_groups, '{}'::text[]) AS allowed_groups,
            COALESCE(
                ARRAY(
                    SELECT policy_tag.tag_id
                    FROM iam.sso_membership_policy_tags AS policy_tag
                    WHERE policy_tag.organization_id = organization.id
                    ORDER BY policy_tag.tag_id
                ),
                '{}'::uuid[]
            ) AS default_tag_ids
        FROM iam.organizations AS organization
        JOIN iam.organization_sso_configs AS config
          ON config.organization_id = organization.id
        LEFT JOIN iam.sso_membership_policies AS policy
          ON policy.organization_id = organization.id
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

async fn validate_policy_references(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    policy: &SsoAdmissionPolicy,
) -> Result<(), AppError> {
    let active_tag_count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM iam.organization_tags
        WHERE organization_id = $1 AND id = ANY($2::uuid[]) AND status = 'active'
        ",
    )
    .bind(organization_id)
    .bind(&policy.default_tag_ids)
    .fetch_one(&mut **transaction)
    .await
    .map_err(support::database)?;
    if usize::try_from(active_tag_count).ok() != Some(policy.default_tag_ids.len()) {
        return Err(validation::field(
            "default_tag_ids",
            "must reference active tags in this organization",
        ));
    }
    if let Some(first_silicon_id) = policy.first_silicon_membership_id {
        let active = sqlx::query_scalar::<_, bool>(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM iam.silicons AS silicon
                JOIN iam.organization_memberships AS membership
                  ON membership.organization_id = silicon.organization_id
                 AND membership.id = silicon.membership_id
                 AND membership.status = 'active'
                WHERE silicon.organization_id = $1
                  AND silicon.membership_id = $2
                  AND silicon.provisioning_status = 'active'
            )
            ",
        )
        .bind(organization_id)
        .bind(first_silicon_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(support::database)?;
        if !active {
            return Err(validation::field(
                "first_silicon_membership_id",
                "must reference an active Silicon in this organization",
            ));
        }
    }
    Ok(())
}

fn configuration_from_row(row: ConfigurationRow) -> Result<SsoConfiguration, AppError> {
    let default_trust = TrustValue {
        boundary: match row.default_trust_boundary.as_str() {
            "internal" => TrustBoundary::Internal,
            "external" => TrustBoundary::External,
            _ => {
                return Err(AppError::Internal {
                    category: "sso_trust_boundary",
                });
            }
        },
        level: match row.default_trust_level.as_str() {
            "not_trusted" => TrustLevel::NotTrusted,
            "needs_approval" => TrustLevel::NeedsApproval,
            "trusted" => TrustLevel::Trusted,
            _ => {
                return Err(AppError::Internal {
                    category: "sso_trust_level",
                });
            }
        },
    };
    Ok(SsoConfiguration {
        org_id: row.org_id,
        entitled: row.platform_enabled,
        status: row.status,
        join_method: row.join_method,
        workos_organization_id: row.provider_organization_id,
        connection_id: row.provider_connection_id,
        policy: SsoAdmissionPolicy {
            mode: if row.allow_policy_admission {
                AdmissionMode::VerifiedIdentityPolicy
            } else {
                AdmissionMode::InvitationRequired
            },
            allowed_email_domains: row.allowed_domains,
            allowed_groups: row.allowed_groups,
            default_job_role: row.default_job_role,
            default_tag_ids: row.default_tag_ids,
            first_silicon_membership_id: row.first_silicon_membership_id,
            default_trust,
        },
        version: row.version,
        updated_at: row.updated_at,
    })
}

const fn trust_boundary_value(value: TrustBoundary) -> &'static str {
    match value {
        TrustBoundary::Internal => "internal",
        TrustBoundary::External => "external",
    }
}

const fn trust_level_value(value: TrustLevel) -> &'static str {
    match value {
        TrustLevel::NotTrusted => "not_trusted",
        TrustLevel::NeedsApproval => "needs_approval",
        TrustLevel::Trusted => "trusted",
    }
}

const fn admission_mode_value(value: AdmissionMode) -> &'static str {
    match value {
        AdmissionMode::InvitationRequired => "invitation_required",
        AdmissionMode::VerifiedIdentityPolicy => "verified_identity_policy",
    }
}

fn redacted_policy(policy: &SsoAdmissionPolicy) -> serde_json::Value {
    json!({
        "mode": admission_mode_value(policy.mode),
        "allowed_domain_count": policy.allowed_email_domains.len(),
        "allowed_group_count": policy.allowed_groups.len(),
        "default_tag_count": policy.default_tag_ids.len(),
        "has_first_silicon": policy.first_silicon_membership_id.is_some(),
        "default_trust": policy.default_trust,
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
    use crate::{
        domain::organization::{TrustBoundary, TrustLevel},
        features::sso::{
            model::{AdmissionMode, SsoAdmissionPolicy, TrustValue},
            validation,
        },
    };

    #[test]
    fn verified_identity_policy_needs_an_explicit_rule() {
        let policy = SsoAdmissionPolicy {
            mode: AdmissionMode::VerifiedIdentityPolicy,
            allowed_email_domains: Vec::new(),
            allowed_groups: Vec::new(),
            default_job_role: String::new(),
            default_tag_ids: Vec::new(),
            first_silicon_membership_id: None,
            default_trust: TrustValue {
                boundary: TrustBoundary::Internal,
                level: TrustLevel::NotTrusted,
            },
        };
        assert!(validation::policy(policy).is_err());
    }
}
