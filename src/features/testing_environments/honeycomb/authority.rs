//! Production application authority is separate from a test key or service identity.
use super::{Instruction, Service, database};
use crate::domain::id::Id;
use crate::{
    api::ApiState,
    features::applications::{error::ApiError, security::ApplicationClient},
    infrastructure::crypto::{DigestPurpose, SecretDigest},
};
use axum::{
    extract::FromRequestParts as _,
    http::{HeaderMap, Request, header},
};
use secrecy::SecretString;
use sqlx::{Postgres, Transaction};

pub(super) async fn production_application(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<Option<ApplicationClient>, ApiError> {
    const HEADER: &str = "x-honeycomb-application-authorization";
    let Some(value) = headers.get(HEADER) else {
        return Ok(None);
    };
    if headers.get_all(HEADER).iter().count() != 1
        || headers.contains_key("x-honeycomb-actor-token")
    {
        return Err(ApiError::invalid_client());
    }
    let mut request = Request::new(());
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, value.clone());
    let (mut parts, ()) = request.into_parts();
    ApplicationClient::from_request_parts(&mut parts, state)
        .await
        .map(Some)
}

/// Locks current authority before replay as well as before new effects. Possessing
/// another environment's shared key permits attachment of only the caller's app.
pub(super) async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    service: &Service,
    client: &ApplicationClient,
    input: &Instruction,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    if input.operation == "import" && input.app_id.as_deref() != Some(client.app_id.as_str()) {
        return Err(ApiError::forbidden("testing_application_identity_required"));
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("testing-runtime:{}", input.environment_id))
        .execute(&mut **tx)
        .await
        .map_err(database)?;
    sqlx::query("SELECT set_config('iam.application_id',$1,true)")
        .bind(client.application_id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(database)?;
    let digests = key_digests(state, headers)?;
    let allowed: bool = sqlx::query_scalar(
        "SELECT iam_private.honeycomb_testing_application_authority($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(service.application_id)
    .bind(client.application_id)
    .bind(input.environment_id)
    .bind(&input.org_id)
    .bind(&input.operation)
    .bind(&input.app_id)
    .bind(digests)
    .bind(input.operation_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(database)?;
    if !allowed {
        return Err(ApiError::forbidden("testing_application_owner_required"));
    }
    Ok(())
}

pub(super) async fn private_import_allowed(
    tx: &mut Transaction<'_, Postgres>,
    actor: Id,
    org: &str,
) -> Result<bool, ApiError> {
    sqlx::query_scalar("SELECT iam_private.honeycomb_testing_application_import_allowed($1,$2)")
        .bind(actor)
        .bind(org)
        .fetch_one(&mut **tx)
        .await
        .map_err(database)
}

pub(super) fn key_digests(state: &ApiState, headers: &HeaderMap) -> Result<Vec<Vec<u8>>, ApiError> {
    Ok(if let Some(key) = headers.get("x-honeycomb-testing-key") {
        if headers.get_all("x-honeycomb-testing-key").iter().count() != 1 {
            return Err(ApiError::forbidden("testing_key_invalid"));
        }
        let key = key
            .to_str()
            .map_err(|_| ApiError::forbidden("testing_key_invalid"))?;
        if key.len() != 32 || !key.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(ApiError::forbidden("testing_key_invalid"));
        }
        state
            .crypto
            .digest_secrets(
                DigestPurpose::TestingEnvironmentKey,
                &SecretString::from(key.to_owned()),
            )
            .map_err(|_| ApiError::internal("testing_key_digest"))?
            .iter()
            .map(SecretDigest::as_bytes)
            .map(|digest| digest.to_vec())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    })
}

/// The service records the operation, while a verified per-environment root key
/// grants only the explicit root-holder actions. It does not identify a user
/// or grant a production application identity.
pub(super) async fn authorize_root(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    service: &Service,
    input: &Instruction,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    if !matches!(input.operation.as_str(), "import" | "rotate-key" | "clean") {
        return Err(ApiError::forbidden("testing_root_operation_forbidden"));
    }
    let version = input.expected_key_version.ok_or_else(|| {
        ApiError::validation(
            "expected_key_version",
            "required with testing root authority",
        )
    })?;
    let digests = key_digests(state, headers)?;
    if digests.is_empty() {
        return Err(ApiError::forbidden("testing_key_invalid"));
    }
    let allowed: bool = sqlx::query_scalar(
        "SELECT iam_private.honeycomb_testing_root_authority($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(service.application_id)
    .bind(input.environment_id)
    .bind(input.operation_id)
    .bind(&input.operation)
    .bind(input.generation)
    .bind(input.expected_iam_revision)
    .bind(version)
    .bind(digests)
    .fetch_one(&mut **tx)
    .await
    .map_err(database)?;
    if !allowed {
        return Err(ApiError::forbidden("testing_key_invalid"));
    }
    Ok(())
}
