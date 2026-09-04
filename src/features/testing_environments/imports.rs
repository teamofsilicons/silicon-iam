//! Test-only import of a production Application configuration.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    api::{ApiState, authentication::Authenticated},
    domain::actor::{ActorRef, ActorType},
    error::AppError,
    features::applications::{ApplicationDetail, load_detail, webhook_secret_fingerprint},
    infrastructure::{
        crypto::{DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField, SecretKind},
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

#[derive(sqlx::FromRow)]
struct ProductionApplication {
    source_application_id: Uuid,
    source_webhook_endpoint_id: Uuid,
    source_webhook_signing_key_id: Uuid,
    app_id: String,
    org_id: String,
    organization_name: String,
    organization_logo_uri: Option<String>,
    organization_description: Option<String>,
    app_name: Option<String>,
    app_logo_uri: Option<String>,
    base_url: String,
    webhook_url_ciphertext: Vec<u8>,
    webhook_url_nonce: Vec<u8>,
    webhook_url_encryption_key_version: i16,
    webhook_secret_ciphertext: Vec<u8>,
    webhook_secret_nonce: Vec<u8>,
    webhook_secret_encryption_key_version: i16,
    webhook_secret_version: i64,
    obo_endpoints: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedOboEndpoint {
    endpoint_id: String,
    path: String,
    metadata: Value,
}

#[derive(sqlx::FromRow)]
struct ExistingOrganization {
    organization_id: Uuid,
    org_role: String,
}

struct ResolvedOrganization {
    id: Uuid,
    created: bool,
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
        &authenticated,
        &headers,
        IMPORT_ROUTE,
        &import_scope,
        &input,
        true,
    )
    .await?
    {
        Claim::Replay(mut response) => {
            response
                .headers_mut()
                .insert(header::ETAG, HeaderValue::from_static("\"1\""));
            return Ok(response);
        }
        Claim::Acquired(lease) => lease,
    };

    // This call always uses the production control-plane pool, even though the
    // request-local database selection points every ordinary query at test.
    let source = sqlx::query_as::<_, ProductionApplication>(
        "SELECT * FROM iam_private.get_testing_application_import($1)",
    )
    .bind(&qualified_app_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| AppError::Internal {
        category: "testing_application_import_source",
    })?
    .ok_or(AppError::NotFound)?;

    let webhook_url = state
        .crypto
        .decrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookUrl,
                source.source_application_id,
                source.source_webhook_endpoint_id,
            ),
            &encrypted_value(
                source.webhook_url_encryption_key_version,
                &source.webhook_url_nonce,
                source.webhook_url_ciphertext.clone(),
            )?,
        )
        .map_err(|_| AppError::Internal {
            category: "testing_application_import_webhook_url",
        })?;
    let webhook_url_text = std::str::from_utf8(&webhook_url).map_err(|_| AppError::Internal {
        category: "testing_application_import_webhook_url",
    })?;
    let webhook_secret = state
        .crypto
        .decrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                source.source_application_id,
                source.source_webhook_signing_key_id,
            ),
            &encrypted_value(
                source.webhook_secret_encryption_key_version,
                &source.webhook_secret_nonce,
                source.webhook_secret_ciphertext.clone(),
            )?,
        )
        .map_err(|_| AppError::Internal {
            category: "testing_application_import_webhook_secret",
        })?;
    let webhook_secret_text =
        std::str::from_utf8(&webhook_secret).map_err(|_| AppError::Internal {
            category: "testing_application_import_webhook_secret",
        })?;
    let obo_endpoints = serde_json::from_value::<Vec<ImportedOboEndpoint>>(
        source.obo_endpoints.clone(),
    )
    .map_err(|_| AppError::Internal {
        category: "testing_application_import_obo",
    })?;

    let organization = resolve_or_create_organization(&mut transaction, carbon_id, &source).await?;
    context::select_organization(&mut transaction, organization.id)
        .await
        .map_err(support::database)?;
    if organization.created {
        record_created_organization(
            &mut transaction,
            &authenticated,
            selected.id,
            organization.id,
            &source,
        )
        .await?;
    }

    let application_id = Uuid::now_v7();
    let webhook_endpoint_id = Uuid::now_v7();
    let webhook_key_id = Uuid::now_v7();
    let client_secret_id = Uuid::now_v7();
    let app_secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)
        .map_err(|_| AppError::Internal {
            category: "testing_application_import_secret_generate",
        })?;
    let app_secret_digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationSecret, &app_secret)
        .map_err(|_| AppError::Internal {
            category: "testing_application_import_secret_digest",
        })?;
    let rebound_url = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookUrl,
                application_id,
                webhook_endpoint_id,
            ),
            webhook_url_text.as_bytes(),
        )
        .map_err(|_| AppError::Internal {
            category: "testing_application_import_webhook_url_rebind",
        })?;
    let rebound_webhook_secret = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                application_id,
                webhook_key_id,
            ),
            webhook_secret_text.as_bytes(),
        )
        .map_err(|_| AppError::Internal {
            category: "testing_application_import_webhook_secret_rebind",
        })?;

    sqlx::query(
        "INSERT INTO iam.principals (id, kind, status, activated_at) VALUES ($1, 'application', 'active', transaction_timestamp())",
    )
    .bind(application_id)
    .execute(&mut *transaction)
    .await
    .map_err(|error| import_conflict(error, "testing_application_already_exists"))?;
    sqlx::query(
        r"
        INSERT INTO iam.applications (
            id, app_id, organization_id, created_by_carbon_id,
            app_name, app_logo_uri, base_url, review_status,
            test_imported_from_production
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'verified', true)
        ",
    )
    .bind(application_id)
    .bind(&source.app_id)
    .bind(organization.id)
    .bind(carbon_id)
    .bind(&source.app_name)
    .bind(&source.app_logo_uri)
    .bind(&source.base_url)
    .execute(&mut *transaction)
    .await
    .map_err(|error| import_conflict(error, "testing_application_already_exists"))?;
    sqlx::query("SELECT iam_private.grant_application_scope_catalogue($1, $2)")
        .bind(application_id)
        .bind(carbon_id)
        .execute(&mut *transaction)
        .await
        .map_err(support::database)?;
    for endpoint in &obo_endpoints {
        sqlx::query(
            r"
            INSERT INTO iam.application_obo_endpoints (
                organization_id, application_id, endpoint_id, path,
                metadata_definition
            ) VALUES ($1, $2, $3, $4, $5)
            ",
        )
        .bind(organization.id)
        .bind(application_id)
        .bind(&endpoint.endpoint_id)
        .bind(&endpoint.path)
        .bind(sqlx::types::Json(&endpoint.metadata))
        .execute(&mut *transaction)
        .await
        .map_err(support::database)?;
    }
    sqlx::query(
        r"
        INSERT INTO iam.application_secrets (
            id, application_id, secret_version, secret_prefix, secret_digest,
            pepper_key_version, created_by_carbon_id
        ) VALUES ($1, $2, 1, $3, $4, $5, $6)
        ",
    )
    .bind(client_secret_id)
    .bind(application_id)
    .bind(secret_prefix(app_secret.expose_secret()))
    .bind(app_secret_digest.as_bytes().as_slice())
    .bind(app_secret_digest.key_version())
    .bind(carbon_id)
    .execute(&mut *transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_endpoints (
            id, application_id, url_ciphertext, url_nonce,
            encryption_key_version, url_digest, status, activated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, 'active', transaction_timestamp())
        ",
    )
    .bind(webhook_endpoint_id)
    .bind(application_id)
    .bind(rebound_url.ciphertext)
    .bind(rebound_url.nonce.as_slice())
    .bind(rebound_url.key_version)
    .bind(Sha256::digest(webhook_url_text.as_bytes()).as_slice())
    .execute(&mut *transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version,
            test_inherited_from_production
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)
        ",
    )
    .bind(webhook_key_id)
    .bind(application_id)
    .bind(webhook_endpoint_id)
    .bind(source.webhook_secret_version)
    .bind(webhook_secret_fingerprint(webhook_secret_text))
    .bind(rebound_webhook_secret.ciphertext)
    .bind(rebound_webhook_secret.nonce.as_slice())
    .bind(rebound_webhook_secret.key_version)
    .execute(&mut *transaction)
    .await
    .map_err(support::database)?;

    record_import(
        &mut transaction,
        &authenticated,
        selected.id,
        organization.id,
        application_id,
        &source,
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
        app_secret: app_secret.expose_secret().to_owned(),
        app_secret_version: 1,
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
    support::json_response(StatusCode::CREATED, body, Some(1), true)
}

async fn resolve_or_create_organization(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: Uuid,
    source: &ProductionApplication,
) -> Result<ResolvedOrganization, AppError> {
    let existing = sqlx::query_as::<_, ExistingOrganization>(
        r"
        SELECT organization.id AS organization_id, membership.org_role
        FROM iam.organizations AS organization
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = organization.id
         AND membership.principal_id = $2
         AND membership.principal_kind = 'carbon'
         AND membership.status = 'active'
        WHERE organization.org_id = $1
          AND organization.status = 'active'
        ",
    )
    .bind(&source.org_id)
    .bind(carbon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(support::database)?;
    if let Some(existing) = existing {
        if !matches!(existing.org_role.as_str(), "owner" | "admin") {
            return Err(AppError::Forbidden);
        }
        return Ok(ResolvedOrganization {
            id: existing.organization_id,
            created: false,
        });
    }

    let available =
        sqlx::query_scalar::<_, bool>("SELECT iam_private.organization_handle_is_available($1)")
            .bind(&source.org_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(support::database)?;
    if !available {
        return Err(AppError::Conflict {
            code: "testing_import_organization_not_managed".into(),
        });
    }

    let organization_id = Uuid::now_v7();
    let membership_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.organizations (
            id, org_id, created_by_carbon_id, name, logo_uri, description
        ) VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(organization_id)
    .bind(&source.org_id)
    .bind(carbon_id)
    .bind(&source.organization_name)
    .bind(&source.organization_logo_uri)
    .bind(&source.organization_description)
    .execute(&mut **transaction)
    .await
    .map_err(|error| import_conflict(error, "testing_import_organization_exists"))?;
    context::select_organization(transaction, organization_id)
        .await
        .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.organization_memberships (
            id, organization_id, principal_id, principal_kind, org_role
        ) VALUES ($1, $2, $3, 'carbon', 'owner')
        ",
    )
    .bind(membership_id)
    .bind(organization_id)
    .bind(carbon_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    sqlx::query(
        r"
        INSERT INTO iam.carbon_membership_settings (
            organization_id, membership_id, carbon_id
        ) VALUES ($1, $2, $3)
        ",
    )
    .bind(organization_id)
    .bind(membership_id)
    .bind(carbon_id)
    .execute(&mut **transaction)
    .await
    .map_err(support::database)?;
    Ok(ResolvedOrganization {
        id: organization_id,
        created: true,
    })
}

async fn record_created_organization(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    testing_environment_id: Uuid,
    organization_id: Uuid,
    source: &ProductionApplication,
) -> Result<(), AppError> {
    let aggregate = AggregateVersion {
        aggregate_type: "organization",
        aggregate_id: organization_id,
        version: 1,
    };
    let after_state = json!({
        "id": organization_id,
        "org_id": source.org_id,
        "name": source.organization_name,
        "logo": source.organization_logo_uri,
        "description": source.organization_description,
        "status": "active",
        "version": 1,
    });
    let metadata = json!({
        "org_id": source.org_id,
        "testing_environment_id": testing_environment_id,
        "created_for_application_import": true,
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
            application_id: None,
            action: "organization.created",
            target_type: "organization",
            target_id: Some(organization_id),
            authentication_method: None,
            aggregate: Some(aggregate),
            before_state: None,
            after_state: Some(after_state.clone()),
            metadata: metadata.clone(),
        },
    )
    .await
    .map_err(support::database)?;
    let mut payload = metadata.as_object().cloned().unwrap_or_default();
    payload.insert("change".into(), json!("organization.created"));
    payload.insert(
        "target".into(),
        json!({ "type": "organization", "id": organization_id }),
    );
    payload.insert("before".into(), Value::Null);
    payload.insert("after".into(), after_state);
    events::enqueue_outbox(
        transaction,
        OutboxRecord {
            organization_id: Some(organization_id),
            aggregate,
            event_ordinal: 1,
            event_type: "organization.created.v1",
            schema_version: 1,
            payload: Value::Object(payload),
            silicon_webhook_routing: None,
        },
    )
    .await
    .map(|_| ())
    .map_err(support::database)
}

async fn record_import(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated: &Authenticated,
    testing_environment_id: Uuid,
    organization_id: Uuid,
    application_id: Uuid,
    source: &ProductionApplication,
) -> Result<(), AppError> {
    let aggregate = AggregateVersion {
        aggregate_type: "application",
        aggregate_id: application_id,
        version: 1,
    };
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
    let valid_local = (3..=80).contains(&local.len())
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

fn encrypted_value(
    key_version: i16,
    nonce: &[u8],
    ciphertext: Vec<u8>,
) -> Result<EncryptedValue, AppError> {
    Ok(EncryptedValue {
        key_version,
        nonce: nonce.try_into().map_err(|_| AppError::Internal {
            category: "testing_application_import_nonce",
        })?,
        ciphertext,
    })
}

fn secret_prefix(secret: &str) -> String {
    secret.chars().take(12).collect()
}

fn import_conflict(error: sqlx::Error, code: &'static str) -> AppError {
    support::conflict_from_database(error, code)
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
