//! Durable, actor-bound accepted configuration. HTTP retries never rotate twice.
#![allow(clippy::too_many_lines, clippy::too_many_arguments)]

mod bundles;
mod decisions;
mod publication;
#[cfg(test)]
pub(super) mod publication_tests;
mod webhook_secret;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
    routing::{post, put},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};
use subtle::ConstantTimeEq as _;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{
    super::{
        applications,
        error::ApiError,
        idempotency,
        model::{ApplicationOboEndpoint, ApplicationScope},
        scopes, security, validation,
    },
    Service,
};
use crate::{
    api::ApiState,
    infrastructure::{
        crypto::{DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField, SecretKind},
        postgres::{
            context::{self, DatabaseContext},
            tokens::AccessContext,
        },
    },
};

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AcceptedConfiguration {
    operation_id: Uuid,
    expected_iam_revision: i64,
    configuration_revision: i64,
    /// Production is explicit. Test configuration uses the lifecycle API.
    environment_id: Option<Uuid>,
    app_id: String,
    org_id: String,
    name: Option<String>,
    logo_url: Option<String>,
    base_url: Option<String>,
    visibility: String,
    availability: String,
    #[serde(default)]
    publication_approved: bool,
    webhook: Webhook,
    app_scope: ApplicationScope,
    #[serde(default)]
    obo_endpoints: Vec<ApplicationOboEndpoint>,
    obo_review_message: Option<String>,
    #[serde(default = "default_idle_days")]
    testing_idle_days: i32,
}

const fn default_idle_days() -> i32 {
    30
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Webhook {
    url: String,
    secret: Option<String>,
    scope: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rotation {
    operation_id: Uuid,
    expected_iam_revision: i64,
    environment_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct StoredOperation {
    operation_id: Uuid,
    actor_principal_id: Uuid,
    operation_kind: String,
    resource_id: String,
    request_digest: Vec<u8>,
    idempotency_digest: Vec<u8>,
    completed: bool,
    result: sqlx::types::Json<Value>,
    response_ciphertext: Option<Vec<u8>>,
    response_nonce: Option<Vec<u8>>,
    response_key_version: Option<i16>,
    response_expires_at: Option<OffsetDateTime>,
}

pub(super) fn router() -> Router<ApiState> {
    Router::new()
        .merge(decisions::router())
        .merge(publication::router())
        .merge(bundles::router())
        .merge(webhook_secret::router())
        .route(
            "/api/v1/honeycomb/applications/{app_id}/configuration",
            put(configure),
        )
        .route(
            "/api/v1/honeycomb/applications/{app_id}/secret-rotations",
            post(rotate),
        )
}

pub(crate) fn management_response(value: Value, replayed: bool) -> Response {
    let mut response = (StatusCode::OK, Json(value)).into_response();
    response.headers_mut().insert(
        "idempotency-replayed",
        axum::http::HeaderValue::from_static(if replayed { "true" } else { "false" }),
    );
    response
}

fn decode<T: for<'a> Deserialize<'a>>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| {
        ApiError::bad_request(
            "invalid_management_request",
            "The management body does not match the documented contract.",
        )
    })
}

async fn begin<'a>(
    state: &'a ApiState,
    actor: &AccessContext,
) -> Result<Transaction<'a, Postgres>, ApiError> {
    context::begin(&state.pool, DatabaseContext::principal(actor.subject.id))
        .await
        .map_err(|_| ApiError::internal("honeycomb_transaction"))
}

async fn manager(
    tx: &mut Transaction<'_, Postgres>,
    actor: &AccessContext,
    org_id: &str,
) -> Result<Uuid, ApiError> {
    let organization =
        applications::resolve_creation_organization(tx, actor.subject.id, org_id).await?;
    context::select_organization(tx, organization)
        .await
        .map_err(|_| ApiError::internal("honeycomb_actor_organization"))?;
    applications::lock_current_application_manager(tx, organization, actor.subject.id).await?;
    let selected = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM iam.organization_memberships member WHERE member.organization_id=$1 AND member.principal_id=$2 AND iam_private.application_token_allows_membership($3,member.id))")
        .bind(organization).bind(actor.subject.id).bind(actor.token_id).fetch_one(&mut **tx).await.map_err(|_| ApiError::internal("honeycomb_actor_grant"))?;
    if !selected {
        return Err(ApiError::forbidden("honeycomb_organization_not_granted"));
    }
    context::select_organization(tx, organization)
        .await
        .map_err(|_| ApiError::internal("honeycomb_actor_organization"))?;
    Ok(organization)
}

pub(crate) async fn claim(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    service: &Service,
    actor: &crate::domain::actor::ActorRef,
    headers: &HeaderMap,
    operation: Uuid,
    kind: &str,
    resource: &str,
    body: &[u8],
) -> Result<Option<Value>, ApiError> {
    let key = idempotency::required_key(headers)?;
    let key_digest = Sha256::digest(key.as_bytes()).to_vec();
    let request_digest = Sha256::digest(body).to_vec();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "honeycomb:{}:{}",
            service.application_id,
            hex::encode(&key_digest)
        ))
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::internal("honeycomb_operation_lock"))?;
    let existing = sqlx::query_as::<_, StoredOperation>("SELECT operation_id,actor_principal_id,operation_kind,resource_id,request_digest,idempotency_digest,completed,result,response_ciphertext,response_nonce,response_key_version,response_expires_at FROM iam.honeycomb_operations WHERE service_application_id=$1 AND (operation_id=$2 OR idempotency_digest=$3) FOR UPDATE")
        .bind(service.application_id).bind(operation).bind(&key_digest).fetch_optional(&mut **tx).await.map_err(|_| ApiError::internal("honeycomb_operation_read"))?;
    if let Some(row) = existing {
        if row.operation_id != operation
            || row.actor_principal_id != actor.id
            || row.operation_kind != kind
            || row.resource_id != resource
            || row.request_digest != request_digest
            || row.idempotency_digest != key_digest
        {
            return Err(ApiError::conflict("honeycomb_operation_conflict"));
        }
        if row.completed {
            if row
                .response_expires_at
                .is_some_and(|expiry| expiry > OffsetDateTime::now_utc())
            {
                let nonce: [u8; 12] = row
                    .response_nonce
                    .as_deref()
                    .and_then(|nonce| nonce.try_into().ok())
                    .ok_or_else(|| ApiError::internal("honeycomb_replay_nonce"))?;
                let encrypted = EncryptedValue {
                    key_version: row
                        .response_key_version
                        .ok_or_else(|| ApiError::internal("honeycomb_replay_key"))?,
                    nonce,
                    ciphertext: row
                        .response_ciphertext
                        .ok_or_else(|| ApiError::internal("honeycomb_replay_ciphertext"))?,
                };
                let response = state
                    .crypto
                    .decrypt(
                        EncryptionContext::global(
                            ProtectedField::IdempotencySecretResponse,
                            operation,
                        ),
                        &encrypted,
                    )
                    .map_err(|_| ApiError::internal("honeycomb_replay_decrypt"))?;
                return serde_json::from_slice(&response)
                    .map(Some)
                    .map_err(|_| ApiError::internal("honeycomb_replay_json"));
            }
            // The operation stays completed indefinitely. The secret is never
            // regenerated merely because the replay ciphertext has expired.
            let mut result = row.result.0;
            if row.response_expires_at.is_some() {
                result["secret_replay_expired"] = json!(true);
            }
            return Ok(Some(result));
        }
        return Ok(None);
    }
    sqlx::query("INSERT INTO iam.honeycomb_operations(operation_id,service_application_id,actor_principal_id,operation_kind,resource_id,idempotency_digest,request_digest,state) VALUES($1,$2,$3,$4,$5,$6,$7,'pending')")
        .bind(operation).bind(service.application_id).bind(actor.id).bind(kind).bind(resource).bind(key_digest).bind(request_digest)
        .execute(&mut **tx).await.map_err(|_| ApiError::conflict("honeycomb_operation_conflict"))?;
    Ok(None)
}

pub(crate) async fn complete(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    service: &Service,
    operation: Uuid,
    resource: &str,
    revision: i64,
    response: &Value,
    secret: bool,
) -> Result<(), ApiError> {
    let mut public = response.clone();
    if let Some(object) = public.as_object_mut() {
        object.remove("app_secret");
        object.remove("key");
    }
    let (encrypted, expiry) = if secret {
        let bytes = serde_json::to_vec(response)
            .map_err(|_| ApiError::internal("honeycomb_response_encode"))?;
        (
            Some(
                state
                    .crypto
                    .encrypt(
                        EncryptionContext::global(
                            ProtectedField::IdempotencySecretResponse,
                            operation,
                        ),
                        &bytes,
                    )
                    .map_err(|_| ApiError::internal("honeycomb_response_encrypt"))?,
            ),
            Some(OffsetDateTime::now_utc() + Duration::minutes(10)),
        )
    } else {
        (None, None)
    };
    let status = response["state"].as_str().unwrap_or("accepted");
    sqlx::query("UPDATE iam.honeycomb_operations SET state=$2,completed=true,iam_revision=$3,result=$4,response_ciphertext=$5,response_nonce=$6,response_key_version=$7,response_expires_at=$8,updated_at=transaction_timestamp() WHERE operation_id=$1")
        .bind(operation).bind(status).bind(revision).bind(sqlx::types::Json(&public))
        .bind(encrypted.as_ref().map(|value| &value.ciphertext)).bind(encrypted.as_ref().map(|value| value.nonce.as_slice()))
        .bind(encrypted.as_ref().map(|value| value.key_version)).bind(expiry).execute(&mut **tx).await.map_err(|_| ApiError::internal("honeycomb_operation_complete"))?;
    let (kind, actor, actor_kind):(String,Uuid,String)=sqlx::query_as("SELECT operation_kind,actor_principal_id,principal.kind::text FROM iam.honeycomb_operations operation JOIN iam.principals principal ON principal.id=operation.actor_principal_id WHERE operation_id=$1").bind(operation).fetch_one(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_operation_audit"))?;
    let event_type = match kind.as_str() {
        "configure" if status == "pending" => "application.configuration.pending",
        "configure" => "application.configuration.accepted",
        "bundle-configure" => "bundle.configuration.accepted",
        "rotate-secret" => "application.credential.rotated",
        "rotate-webhook-secret" => "application.webhook_secret.rotated",
        "scope-decision" => "application.scope.decided",
        "webhook-approval" => "application.webhook.activated",
        _ => "management.operation.completed",
    };
    crate::infrastructure::postgres::events::record_audit(tx, crate::infrastructure::postgres::events::AuditRecord{
        actor:Some(crate::domain::actor::ActorRef{actor_type:if actor_kind=="application" {crate::domain::actor::ActorType::Application} else {crate::domain::actor::ActorType::Carbon},id:actor}),
        authentication_session_id:None,organization_id:None,application_id:None,
        action:"honeycomb.operation.completed",target_type:"honeycomb_operation",target_id:Some(operation),
        authentication_method:Some("honeycomb_service_and_actor"),aggregate:None,before_state:None,after_state:None,
        metadata:json!({"operation_id":operation,"operation_kind":kind,"resource_id":resource,"iam_revision":revision,"state":status})
    }).await.map_err(|_|ApiError::internal("honeycomb_audit"))?;
    sqlx::query("INSERT INTO iam.honeycomb_management_events(event_id,operation_id,service_application_id,resource_id,revision,event_type,payload,environment_id) VALUES($1,$2,$3,$4,$5,$6,$7,(SELECT environment_id FROM iam.honeycomb_operations WHERE operation_id=$2)) ON CONFLICT DO NOTHING")
        .bind(Uuid::now_v7()).bind(operation).bind(service.application_id).bind(resource).bind(revision).bind(event_type).bind(sqlx::types::Json(public))
        .execute(&mut **tx).await.map_err(|_| ApiError::internal("honeycomb_management_event"))?;

    Ok(())
}

fn validate_configuration(path: &str, input: &AcceptedConfiguration) -> Result<(), ApiError> {
    validation::app_id(path)?;
    validation::org_id(&input.org_id)?;
    validation::optional_text("name", input.name.as_deref(), 1, 200)?;
    validation::optional_https_uri("logo_url", input.logo_url.as_deref(), 2048)?;
    validation::optional_text(
        "obo_review_message",
        input.obo_review_message.as_deref(),
        1,
        10000,
    )?;
    if input.app_id != path
        || path.split_once('>').map(|(org, _)| org) != Some(input.org_id.as_str())
    {
        return Err(ApiError::conflict("application_identity_immutable"));
    }
    if input.environment_id.is_some() {
        return Err(ApiError::forbidden("use_testing_lifecycle_integration"));
    }
    if input.configuration_revision <= 0 || input.expected_iam_revision < 0 {
        return Err(ApiError::validation(
            "revision",
            "configuration revision must be positive and expected IAM revision nonnegative",
        ));
    }
    if !matches!(input.visibility.as_str(), "private" | "public")
        || !matches!(input.availability.as_str(), "active" | "disabled")
    {
        return Err(ApiError::validation(
            "configuration",
            "unsupported visibility or availability",
        ));
    }
    if let Some(url) = &input.base_url {
        validation::base_url(url)?;
    }
    if !input.obo_endpoints.is_empty() && input.base_url.is_none() {
        return Err(ApiError::validation(
            "base_url",
            "required when exposing OBO endpoints",
        ));
    }
    validation::obo_endpoints(&input.obo_endpoints)?;
    scopes::validate(&input.app_scope)?;
    scopes::validate_webhook(&input.webhook.scope)?;
    validation::webhook_url(&input.webhook.url)?;
    if !(1..=36500).contains(&input.testing_idle_days) {
        return Err(ApiError::validation(
            "testing_idle_days",
            "must be between 1 and 36500",
        ));
    }
    if let Some(secret) = &input.webhook.secret {
        validation::webhook_secret(secret)?;
    }
    Ok(())
}

async fn configure(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let input: AcceptedConfiguration = decode(&body)?;
    validate_configuration(&path, &input)?;
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    let organization = manager(&mut tx, &actor, &input.org_id).await?;
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.operation_id,
        "configure",
        &path,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("honeycomb_replay_commit"))?;
        return Ok(management_response(response, true));
    }
    let existing=sqlx::query_as::<_,(Uuid,i64,String)>("SELECT id,version,visibility FROM iam.applications WHERE app_id=$1 AND organization_id=$2 AND deleted_at IS NULL FOR UPDATE")
        .bind(&path).bind(organization).fetch_optional(&mut *tx).await.map_err(|_|ApiError::internal("honeycomb_configuration_read"))?;
    if let Some((id, _, _)) = &existing {
        let previous: i64 = sqlx::query_scalar(
            "SELECT honeycomb_configuration_revision FROM iam.applications WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ApiError::internal("honeycomb_configuration_revision_read"))?;
        if input.configuration_revision <= previous {
            return Err(ApiError::conflict("configuration_revision_conflict"));
        }
    }
    if existing.as_ref().map_or(0, |row| row.1) != input.expected_iam_revision {
        return Err(ApiError::conflict("iam_revision_conflict"));
    }
    if let Some((app, _, visibility)) = &existing {
        let missing = if input.visibility == "public" && visibility == "private" {
            sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT catalog.scope FROM iam_private.application_scope_catalog(NULL) catalog WHERE catalog.critical AND catalog.scope=ANY(iam_private.application_scope_names($2)) EXCEPT SELECT scope FROM iam.application_approved_scopes WHERE application_id=$1 AND revoked_at IS NULL AND approval_basis='provider_approval')").bind(app).bind(sqlx::types::Json(&input.app_scope)).fetch_one(&mut *tx).await.map_err(|_|ApiError::internal("honeycomb_public_scope_gate"))?
        } else {
            false
        };
        if input.visibility == "public" {
            let snapshot: sqlx::types::Json<Value> =
                sqlx::query_scalar("SELECT iam_private.honeycomb_application_record($1,$2)")
                    .bind(service.application_id)
                    .bind(&path)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| ApiError::internal("honeycomb_pending_record"))?;
            let revision = snapshot.0["iam_revision"]
                .as_i64()
                .ok_or_else(|| ApiError::internal("honeycomb_pending_revision"))?;
            let response = json!({"operation_id":input.operation_id,"state":"pending","configuration_revision":input.configuration_revision,"iam_revision":revision,"effective_configuration":snapshot.0,"configuration_digest":hex::encode(publication::configuration_digest(&input)?),"required_approvals":{"publication":true,"critical_scopes":missing}});
            complete(
                &mut tx,
                &state,
                &service,
                input.operation_id,
                &path,
                revision,
                &response,
                false,
            )
            .await?;
            tx.commit()
                .await
                .map_err(|_| ApiError::internal("honeycomb_pending_commit"))?;
            return Ok(management_response(response, false));
        }
    }
    if input.visibility == "public" && existing.is_none() {
        return Err(ApiError::conflict("create_private_before_publication"));
    }
    let (app_id, new_secret) =
        apply_configuration(&mut tx, &state, &actor, organization, &input, existing).await?;
    let snapshot = sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "SELECT iam_private.honeycomb_application_record($1,$2)",
    )
    .bind(service.application_id)
    .bind(&path)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ApiError::internal("honeycomb_effective_configuration"))?
    .0;
    let revision = snapshot["iam_revision"]
        .as_i64()
        .ok_or_else(|| ApiError::internal("honeycomb_effective_revision"))?;
    let mut response = json!({"operation_id":input.operation_id,"state":if snapshot["availability"]=="under_review" {"pending"} else {"accepted"},"configuration_revision":input.configuration_revision,"iam_revision":revision,"application_id":app_id,"effective_configuration":snapshot});
    if let Some(secret) = &new_secret {
        response["app_secret"] = json!(secret.expose_secret());
    }
    complete(
        &mut tx,
        &state,
        &service,
        input.operation_id,
        &path,
        revision,
        &response,
        new_secret.is_some(),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("honeycomb_configuration_commit"))?;
    Ok(management_response(response, false))
}

async fn apply_configuration(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    actor: &AccessContext,
    organization: Uuid,
    input: &AcceptedConfiguration,
    existing: Option<(Uuid, i64, String)>,
) -> Result<(Uuid, Option<SecretString>), ApiError> {
    let fresh = existing.is_none();
    let previously_public = if let Some((id, _, _)) = &existing {
        sqlx::query_scalar::<_,bool>("SELECT visibility='public' AND review_status='verified' FROM iam.applications WHERE id=$1").bind(id).fetch_one(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_previous_activation"))?
    } else {
        false
    };
    let app = existing.as_ref().map_or_else(Uuid::now_v7, |row| row.0);
    if !fresh
        && input.visibility == "public"
        && existing.as_ref().is_some_and(|row| row.2 == "private")
    {
        if !input.publication_approved {
            return Err(ApiError::conflict("publication_approval_required"));
        }
        let missing=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT catalog.scope FROM iam_private.application_scope_catalog(NULL) catalog WHERE catalog.critical AND catalog.scope=ANY(iam_private.application_scope_names($2)) EXCEPT SELECT scope FROM iam.application_approved_scopes WHERE application_id=$1 AND revoked_at IS NULL AND approval_basis='provider_approval')")
            .bind(app).bind(sqlx::types::Json(&input.app_scope)).fetch_one(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_public_scope_gate"))?;
        if missing {
            return Err(ApiError::conflict("public_scope_approval_required"));
        }
    }
    if fresh {
        sqlx::query("INSERT INTO iam.principals(id,kind,status,activated_at) VALUES($1,'application','active',transaction_timestamp())")
            .bind(app).execute(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_application_principal"))?;
        sqlx::query("INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,review_status,visibility) VALUES($1,$2,$3,$4,CASE WHEN $5='private' THEN 'verified' ELSE 'under_review' END,$5)")
            .bind(app).bind(&input.app_id).bind(organization).bind(actor.subject.id).bind(&input.visibility).execute(&mut **tx).await.map_err(|_|ApiError::conflict("application_already_exists"))?;
    }
    // Remove withdrawn exemptions before the visibility transition. The whole
    // configuration, gate and notification commit together.
    scopes::configure(tx, app, &input.app_scope, actor.subject.id).await?;
    sqlx::query("UPDATE iam.applications SET app_name=$2,app_logo_uri=$3,base_url=$4,webhook_scope=$5,obo_review_message=$6,testing_idle_days=$7,visibility=$8 WHERE id=$1")
        .bind(app).bind(&input.name).bind(&input.logo_url).bind(input.base_url.as_deref().unwrap_or("")).bind(&input.webhook.scope)
        .bind(&input.obo_review_message).bind(input.testing_idle_days).bind(&input.visibility).execute(&mut **tx).await.map_err(|_|ApiError::validation("configuration","invalid accepted configuration"))?;
    applications::replace_obo_endpoints(tx, app, &input.obo_endpoints).await?;
    scopes::configure(tx, app, &input.app_scope, actor.subject.id).await?;
    let fully_approved = sqlx::query_scalar::<_,bool>("SELECT NOT EXISTS(SELECT unnest(iam_private.application_scope_names(app_scope)) FROM iam.applications WHERE id=$1 EXCEPT SELECT scope FROM iam.application_approved_scopes WHERE application_id=$1 AND revoked_at IS NULL AND approval_basis<>'private_exemption')")
        .bind(app).fetch_one(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_public_approval_gate"))?;
    if input.availability == "disabled"
        || (input.visibility == "public"
            && (!input.publication_approved || (!previously_public && !fully_approved)))
    {
        sqlx::query("UPDATE iam.applications SET review_status=$2 WHERE id=$1")
            .bind(app)
            .bind(if input.availability == "disabled" {
                "suspended"
            } else {
                "under_review"
            })
            .execute(&mut **tx)
            .await
            .map_err(|_| ApiError::internal("honeycomb_availability"))?;
    } else if input.visibility == "private" || input.publication_approved {
        // Only currently effective scopes can be issued. Unapproved additions
        // stay requested and do not replace previous active grants.
        sqlx::query("UPDATE iam.applications SET review_status='verified' WHERE id=$1")
            .bind(app)
            .execute(&mut **tx)
            .await
            .map_err(|_| ApiError::internal("honeycomb_activation"))?;
    }
    configure_webhook(tx, state, app, &input.webhook).await?;
    let secret = if fresh {
        Some(replace_secret(tx, state, app, actor.subject.id).await?)
    } else {
        None
    };
    sqlx::query("UPDATE iam.applications SET honeycomb_configuration_revision=$2 WHERE id=$1")
        .bind(app)
        .bind(input.configuration_revision)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError::internal("honeycomb_configuration_revision_write"))?;
    applications::bump_application(tx, app).await?;
    Ok((app, secret))
}

async fn configure_webhook(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    app: Uuid,
    webhook: &Webhook,
) -> Result<(), ApiError> {
    let digest = Sha256::digest(webhook.url.as_bytes()).to_vec();
    let unchanged=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM iam.application_webhook_endpoints WHERE application_id=$1 AND url_digest=$2 AND status IN ('active','pending_review'))")
        .bind(app).bind(&digest).fetch_one(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_read"))?;
    if unchanged {
        if let Some(presented) = &webhook.secret {
            let (key_id,ciphertext,nonce,version):(Uuid,Vec<u8>,Vec<u8>,i16)=sqlx::query_as("SELECT key.id,key.secret_ciphertext,key.secret_nonce,key.encryption_key_version FROM iam.application_webhook_signing_keys key JOIN iam.application_webhook_endpoints endpoint ON endpoint.id=key.endpoint_id WHERE endpoint.application_id=$1 AND endpoint.url_digest=$2 AND endpoint.status IN ('active','pending_review') AND key.status='active'").bind(app).bind(&digest).fetch_one(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_existing_key"))?;
            let encrypted = EncryptedValue {
                key_version: version,
                ciphertext,
                nonce: nonce
                    .try_into()
                    .map_err(|_| ApiError::internal("honeycomb_webhook_nonce"))?,
            };
            let stored = state
                .crypto
                .decrypt(
                    EncryptionContext::tenant(
                        ProtectedField::ApplicationWebhookSigningSecret,
                        app,
                        key_id,
                    ),
                    &encrypted,
                )
                .map_err(|_| ApiError::internal("honeycomb_webhook_existing_secret"))?;
            if !bool::from(stored.as_slice().ct_eq(presented.as_bytes())) {
                return Err(ApiError::conflict("webhook_secret_rotation_required"));
            }
        }
        return Ok(());
    }
    let secret = webhook.secret.as_ref().ok_or_else(|| {
        ApiError::validation(
            "webhook.secret",
            "a signing secret is required for a new destination",
        )
    })?;
    let endpoint = sqlx::query_scalar::<_,Uuid>("SELECT id FROM iam.application_webhook_endpoints WHERE application_id=$1 AND url_digest=$2 FOR UPDATE").bind(app).bind(&digest).fetch_optional(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_destination"))?.unwrap_or_else(Uuid::now_v7);
    let signing = Uuid::now_v7();
    let url = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(ProtectedField::ApplicationWebhookUrl, app, endpoint),
            webhook.url.as_bytes(),
        )
        .map_err(|_| ApiError::internal("honeycomb_webhook_url"))?;
    let fingerprint = applications::webhook_secret_fingerprint(secret);
    let secret = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                app,
                signing,
            ),
            secret.as_bytes(),
        )
        .map_err(|_| ApiError::internal("honeycomb_webhook_secret"))?;
    // A changed destination remains pending; never send it production events
    // before a separate, stepped-up activation decision.
    sqlx::query("UPDATE iam.application_webhook_endpoints SET status='retired',retired_at=transaction_timestamp() WHERE application_id=$1 AND status='pending_review'").bind(app).execute(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_pending"))?;
    sqlx::query("INSERT INTO iam.application_webhook_endpoints(id,application_id,url_ciphertext,url_nonce,encryption_key_version,url_digest,status) VALUES($1,$2,$3,$4,$5,$6,'pending_review') ON CONFLICT(id) DO UPDATE SET status='pending_review',activated_at=NULL,retired_at=NULL,url_ciphertext=EXCLUDED.url_ciphertext,url_nonce=EXCLUDED.url_nonce,encryption_key_version=EXCLUDED.encryption_key_version")
        .bind(endpoint).bind(app).bind(url.ciphertext).bind(url.nonce.as_slice()).bind(url.key_version).bind(digest).execute(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_insert"))?;
    sqlx::query("UPDATE iam.application_webhook_signing_keys SET status='retired',retired_at=transaction_timestamp(),retires_at=NULL WHERE endpoint_id=$1 AND status IN ('active','retiring')").bind(endpoint).execute(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_retire_key"))?;
    let version=sqlx::query_scalar::<_,i64>("SELECT COALESCE(max(secret_version),0)+1 FROM iam.application_webhook_signing_keys WHERE application_id=$1").bind(app).fetch_one(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_version"))?;
    sqlx::query("INSERT INTO iam.application_webhook_signing_keys(id,application_id,endpoint_id,secret_version,key_prefix,secret_ciphertext,secret_nonce,encryption_key_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(signing).bind(app).bind(endpoint).bind(version).bind(fingerprint).bind(secret.ciphertext).bind(secret.nonce.as_slice()).bind(secret.key_version)
        .execute(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_webhook_key"))?;
    Ok(())
}

async fn replace_secret(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    app: Uuid,
    actor: Uuid,
) -> Result<SecretString, ApiError> {
    let secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)
        .map_err(|_| ApiError::internal("honeycomb_secret_generate"))?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationSecret, &secret)
        .map_err(|_| ApiError::internal("honeycomb_secret_digest"))?;
    let version=sqlx::query_scalar::<_,i64>("SELECT COALESCE(max(secret_version),0)+1 FROM iam.application_secrets WHERE application_id=$1").bind(app).fetch_one(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_secret_version"))?;
    sqlx::query("UPDATE iam.application_secrets SET status='retired',retired_at=transaction_timestamp(),retires_at=NULL WHERE application_id=$1 AND status IN ('active','retiring')")
        .bind(app).execute(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_secret_revoke"))?;
    sqlx::query("INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(Uuid::now_v7()).bind(app).bind(version).bind(applications::secret_prefix(secret.expose_secret())).bind(digest.as_bytes().as_slice()).bind(digest.key_version()).bind(actor)
        .execute(&mut **tx).await.map_err(|_|ApiError::internal("honeycomb_secret_insert"))?;
    Ok(secret)
}

async fn rotate(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    validation::app_id(&path)?;
    let input: Rotation = decode(&body)?;
    if input.environment_id.is_some() {
        return Err(ApiError::forbidden("use_testing_lifecycle_integration"));
    }
    let actor = service.actor(&state, &headers).await?;
    let mut tx = begin(&state, &actor).await?;
    security::lock_step_up_actor(&mut tx, actor.subject.id).await?;
    let org = path
        .split_once('>')
        .map(|(org, _)| org)
        .ok_or_else(ApiError::not_found)?;
    manager(&mut tx, &actor, org).await?;
    if let Some(response) = claim(
        &mut tx,
        &state,
        &service,
        &actor.subject,
        &headers,
        input.operation_id,
        "rotate-secret",
        &path,
        &body,
    )
    .await?
    {
        tx.commit()
            .await
            .map_err(|_| ApiError::internal("honeycomb_rotation_replay"))?;
        return Ok(management_response(response, true));
    }
    let app = applications::resolve_technical_app(&mut tx, actor.subject.id, &path, true).await?;
    if app.version != input.expected_iam_revision {
        return Err(ApiError::conflict("iam_revision_conflict"));
    }
    security::require_step_up(
        &mut tx,
        &state.crypto,
        &headers,
        &actor,
        "application.client_secret.rotate",
        app.id,
        crate::infrastructure::postgres::step_up::RequiredAssurance::VerifiedChannel,
    )
    .await?;
    let secret = replace_secret(&mut tx, &state, app.id, actor.subject.id).await?;
    let revision = applications::bump_application(&mut tx, app.id).await?;
    let credential_version:i64=sqlx::query_scalar("SELECT max(secret_version) FROM iam.application_secrets WHERE application_id=$1 AND status='active'").bind(app.id).fetch_one(&mut *tx).await.map_err(|_|ApiError::internal("honeycomb_credential_version"))?;
    let response = json!({"operation_id":input.operation_id,"state":"accepted","iam_revision":revision,"app_id":path,"app_secret":secret.expose_secret(),"credential_version":credential_version});
    complete(
        &mut tx,
        &state,
        &service,
        input.operation_id,
        &path,
        revision,
        &response,
        true,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| ApiError::internal("honeycomb_rotation_commit"))?;
    Ok(management_response(response, false))
}

/// Test-plane management validates the same accepted configuration shape.
pub(crate) fn validate_test_configuration(value: &Value) -> Result<(), ApiError> {
    let mut value = value.clone();
    value["environment_id"] = Value::Null;
    let input: AcceptedConfiguration = serde_json::from_value(value)
        .map_err(|_| ApiError::validation("configuration", "invalid accepted configuration"))?;
    validate_configuration(&input.app_id, &input)
}
