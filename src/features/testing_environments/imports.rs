//! Test-only import of a production Application configuration.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::{ActorRef, ActorType},
    error::AppError,
    features::applications::{ApplicationDetail, load_detail},
    infrastructure::{
        postgres::{
            context::{self, DatabaseContext},
            events::{self, AggregateVersion, AuditRecord, OutboxRecord},
        },
        testing_plane,
    },
};

use super::support::{self, Claim};

const IMPORT_ROUTE: &str = "POST /api/v1/testing-environment/applications/imports";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestingApplicationImport {
    app_id: String,
}

#[derive(Debug, Serialize)]
pub(super) struct TestingApplicationImported {
    application: ApplicationDetail,
    app_secret: String,
    app_secret_version: i64,
    webhook_secret_inherited: bool,
    #[serde(with = "time::serde::rfc3339")]
    secret_replay_expires_at: OffsetDateTime,
}

#[derive(sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub(super) struct ProductionApplication {
    pub(super) source_revision: i64,
    pub(super) visibility: String,
    pub(super) source_application_id: Uuid,
    pub(super) source_webhook_endpoint_id: Uuid,
    pub(super) source_webhook_signing_key_id: Uuid,
    pub(super) app_id: String,
    pub(super) org_id: String,
    pub(super) organization_name: String,
    pub(super) organization_logo_uri: Option<String>,
    pub(super) organization_description: Option<String>,
    pub(super) app_name: Option<String>,
    pub(super) app_logo_uri: Option<String>,
    pub(super) base_url: String,
    pub(super) webhook_url_ciphertext: Vec<u8>,
    pub(super) webhook_url_nonce: Vec<u8>,
    pub(super) webhook_url_encryption_key_version: i16,
    pub(super) webhook_secret_ciphertext: Vec<u8>,
    pub(super) webhook_secret_nonce: Vec<u8>,
    pub(super) webhook_secret_encryption_key_version: i16,
    pub(super) webhook_secret_version: i64,
    pub(super) obo_endpoints: Value,
    pub(super) app_scope: Value,
    pub(super) webhook_scope: Vec<String>,
    pub(super) testing_idle_days: i32,
}

/// Imports one verified production Application into the selected environment.
///
/// Its public configuration and active OBO surface are snapshots. The webhook
/// URL and signing secret are decrypted only long enough to rebind them to
/// fresh test row identities. The inherited signing secret is deliberately
/// absent from the response; the Application receives a fresh client secret
/// whose digest is bound to this environment.
#[allow(
    clippy::too_many_lines,
    reason = "the cross-plane copy and every secret rebind commit as one test-plane mutation"
)]
pub(super) async fn import_application(
    State(state): State<ApiState>,
    authenticated: Authenticated,
    headers: HeaderMap,
    Json(input): Json<TestingApplicationImport>,
) -> Result<Response, AppError> {
    let selected = testing_plane::current().ok_or_else(|| AppError::Conflict {
        code: "testing_environment_required".into(),
    })?;
    let carbon_id = require_direct_carbon(&authenticated)?;
    // Validate into a separate lookup value. The idempotency digest below is
    // intentionally computed from the request exactly as submitted, so a
    // differently cased or spaced body cannot replay another body's result.
    let qualified_app_id = qualified_app_id(&input.app_id)?;

    // Claim before reading production so an exact retry can replay the
    // original one-time app secret even if the source is changed or retired
    // after the import committed.
    let mut transaction = context::begin(state.db(), DatabaseContext::principal(carbon_id))
        .await
        .map_err(support::database)?;
    let import_scope = import_idempotency_scope(selected.id);
    let lease = match support::claim(
        &mut transaction,
        &state,
        authenticated.0.subject,
        &headers,
        IMPORT_ROUTE,
        &import_scope,
        &input,
        true,
    )
    .await?
    {
        Claim::Replay(response) => return Ok(response),
        Claim::Acquired(lease) => lease,
    };

    let graph = super::graph::load(&state, &qualified_app_id).await?;
    let imported =
        super::graph::import_all(&mut transaction, &state, &graph, &qualified_app_id).await?;
    let imported_root = imported.get(&qualified_app_id).ok_or(AppError::NotFound)?;
    let source = graph.get(&qualified_app_id).ok_or(AppError::NotFound)?;
    let application_id = imported_root.application_id;
    let organization_id =
        sqlx::query_scalar::<_, Uuid>("SELECT organization_id FROM iam.applications WHERE id=$1")
            .bind(application_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(support::database)?;
    context::select_organization(&mut transaction, organization_id)
        .await
        .map_err(support::database)?;
    let (version, app_secret_version) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT app.version, secret.secret_version FROM iam.applications app JOIN iam.application_secrets secret ON secret.application_id=app.id AND secret.status='active' WHERE app.id=$1",
    )
    .bind(application_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(support::database)?;
    record_import(
        &mut transaction,
        &authenticated,
        selected.id,
        organization_id,
        AggregateVersion {
            aggregate_type: "application",
            aggregate_id: application_id,
            version,
        },
        source,
        imported_root.created,
    )
    .await?;
    let application = load_detail(&mut transaction, &state, application_id, false)
        .await
        .map_err(|_| AppError::Internal {
            category: "testing_application_import_detail",
        })?;
    let secret_replay_expires_at = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT transaction_timestamp() + interval '10 minutes'",
    )
    .fetch_one(&mut *transaction)
    .await
    .map_err(support::database)?;
    let response = TestingApplicationImported {
        application,
        app_secret: imported_root.app_secret.expose_secret().to_owned(),
        app_secret_version,
        webhook_secret_inherited: true,
        secret_replay_expires_at,
    };
    let body = support::finish(
        &mut transaction,
        &state,
        lease,
        StatusCode::CREATED,
        &response,
        true,
    )
    .await?;
    transaction.commit().await.map_err(support::database)?;
    support::json_response(StatusCode::CREATED, body, Some(version), true)
}

async fn record_import(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    testing_environment_id: Uuid,
    organization_id: Uuid,
    aggregate: AggregateVersion<'_>,
    source: &ProductionApplication,
    created: bool,
) -> Result<(), AppError> {
    let application_id = aggregate.aggregate_id;
    let metadata = json!({
        "application_id": application_id,
        "app_id": source.app_id,
        "organization_id": organization_id,
        "org_id": source.org_id,
        "testing_environment_id": testing_environment_id,
        "imported_from_production": true,
    });
    events::record_audit(
        transaction,
        AuditRecord {
            actor: Some(ActorRef {
                actor_type: ActorType::Carbon,
                id: authenticated.0.subject.id,
            }),
            authentication_session_id: Some(authenticated.0.authentication_session_id),
            organization_id: Some(organization_id),
            application_id: Some(application_id),
            action: "application.import",
            target_type: "application",
            target_id: Some(application_id),
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state: None,
            after_state: Some(json!({
                "app_id": source.app_id,
                "base_url": source.base_url,
                "review_status": "verified",
                "imported_from_production": true,
            })),
            metadata: metadata.clone(),
        },
    )
    .await
    .map_err(support::database)?;
    if !created {
        return Ok(());
    }
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: Some(organization_id),
            aggregate,
            event_ordinal: 1,
            event_type: "application.created",
            schema_version: 1,
            payload: metadata,
            silicon_webhook_routing: None,
        },
    )
    .await
    .map(|_| ())
    .map_err(support::database)
}

fn require_direct_carbon(authenticated: &Authenticated) -> Result<Uuid, AppError> {
    let access = &authenticated.0;
    if access.subject.actor_type == ActorType::Carbon
        && access.audience == "silicon-iam"
        && access.client_application_id.is_none()
        && access.organization_id.is_none()
        && access.membership_id.is_none()
        && access.scopes.iter().any(|scope| scope == "iam.self")
    {
        Ok(access.subject.id)
    } else {
        Err(AppError::Forbidden)
    }
}

fn import_idempotency_scope(environment_id: Uuid) -> String {
    format!("environment:{environment_id}:application_import")
}

fn qualified_app_id(value: &str) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    let Some((organization, local)) = normalized.split_once('>') else {
        return Err(AppError::invalid_field(
            "app_id",
            "must be a qualified production Application id",
        ));
    };
    let valid_organization = (3..=50).contains(&organization.len())
        && organization.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte)
        });
    let valid_local = (1..=80).contains(&local.len())
        && local.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && local.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte)
        });
    if !valid_organization || !valid_local || local.contains('>') {
        return Err(AppError::invalid_field(
            "app_id",
            "must be a qualified production Application id",
        ));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{import_idempotency_scope, qualified_app_id};

    #[test]
    fn import_requires_a_canonical_qualified_application_id() {
        assert_eq!(
            qualified_app_id(" TOS>Briefcase ").ok().as_deref(),
            Some("tos>briefcase")
        );
        for invalid in ["briefcase", "to>briefcase", "tos>>briefcase", "tos>2fa"] {
            assert!(qualified_app_id(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn import_idempotency_scope_is_environment_bound_but_body_independent() {
        let environment_id = Uuid::from_u128(7);
        assert_eq!(
            import_idempotency_scope(environment_id),
            format!("environment:{environment_id}:application_import")
        );
    }
}
