//! Explicit control-plane administration of applications in one isolated database.
#![allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::struct_field_names
)]
use super::{ApiError, ApiState, Instruction, Service, authority, database};
use crate::{
    domain::actor::{ActorRef, ActorType},
    features::applications::honeycomb::operations,
    infrastructure::{
        crypto::{DigestPurpose, EncryptedValue, EncryptionContext, ProtectedField, SecretKind},
        postgres::context::{self, DatabaseContext},
        testing_plane::{self, SelectedEnvironment},
    },
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post, put},
};
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Version {
    generation: i64,
    key_version: i32,
    expected_environment_revision: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    operation_id: Uuid,
    environment_id: Uuid,
    generation: i64,
    key_version: i32,
    expected_environment_revision: i64,
    #[serde(default)]
    expected_iam_revision: i64,
    #[serde(default)]
    configuration_revision: i64,
    configuration: Option<Value>,
}
pub(super) fn router() -> Router<ApiState> {
    Router::new()
 .route("/api/v1/honeycomb/testing-environments",get(list))
 .route("/api/v1/honeycomb/application-identity",get(application_identity))
 .route("/api/v1/honeycomb/testing-environments/{environment_id}/applications/{app_id}/credential-recovery",post(recover))
 .route("/api/v1/honeycomb/testing-environments/{environment_id}/applications/{app_id}",get(read))
 .route("/api/v1/honeycomb/testing-environments/{environment_id}/applications/{app_id}/configuration",put(configure))
 .route("/api/v1/honeycomb/testing-environments/{environment_id}/applications/{app_id}/secret-rotations",post(rotate))
}

async fn authorize<'a>(
    state: &'a ApiState,
    service: &Service,
    headers: &HeaderMap,
    environment: Uuid,
    app: &str,
    version: &Version,
    service_read: bool,
) -> Result<
    (
        Transaction<'a, Postgres>,
        SelectedEnvironment,
        ActorRef,
        Option<Uuid>,
    ),
    ApiError,
> {
    if version.generation <= 0
        || version.key_version <= 0
        || version.expected_environment_revision <= 0
    {
        return Err(ApiError::validation(
            "version",
            "positive lifecycle versions required",
        ));
    }
    let client = authority::production_application(state, headers).await?;
    if client.as_ref().is_some_and(|client| client.app_id != app) {
        return Err(ApiError::forbidden("testing_application_identity_required"));
    }
    let root_authority = client.is_none()
        && !headers.contains_key("x-honeycomb-actor-token")
        && headers.contains_key("x-honeycomb-testing-key");
    let access = if client.is_none()
        && !root_authority
        && (!service_read || headers.contains_key("x-honeycomb-actor-token"))
    {
        Some(service.actor(state, headers).await?)
    } else {
        None
    };
    let actor = if let Some(client) = &client {
        ActorRef {
            actor_type: ActorType::Application,
            id: client.application_id,
        }
    } else if root_authority {
        ActorRef {
            actor_type: ActorType::Service,
            id: service.application_id,
        }
    } else {
        access.as_ref().map_or(
            ActorRef {
                actor_type: ActorType::Application,
                id: service.application_id,
            },
            |access| access.subject,
        )
    };
    let mut tx = context::begin(&state.pool, DatabaseContext::principal(actor.id))
        .await
        .map_err(database)?;
    // Same lock as clean/purge. No lifecycle change can race target-plane writes.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("testing-runtime:{environment}"))
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    if root_authority {
        let allowed: bool = sqlx::query_scalar(
            "SELECT iam_private.honeycomb_testing_root_app_authority($1,$2,$3,$4,$5)",
        )
        .bind(service.application_id)
        .bind(environment)
        .bind(version.generation)
        .bind(version.key_version)
        .bind(authority::key_digests(state, headers)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(database)?;
        if !allowed {
            return Err(ApiError::forbidden("testing_key_invalid"));
        }
    }
    if let Some(client) = &client {
        let instruction:Instruction=serde_json::from_value(json!({"operation_id":Uuid::nil(),"expected_iam_revision":version.expected_environment_revision,"environment_id":environment,"generation":version.generation,"operation":if client.app_id==app {"import"}else{"test-app"},"app_id":app})).map_err(|_|ApiError::internal("testing_app_authority_instruction"))?;
        authority::authorize(&mut tx, state, service, client, &instruction, headers).await?;
    } else if access.is_some() {
        let allowed: bool =
            sqlx::query_scalar("SELECT iam_private.honeycomb_testing_actor($1,$2,$3,NULL)")
                .bind(environment)
                .bind(actor.id)
                .bind(access.as_ref().map(|a| a.token_id))
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        if !allowed {
            return Err(ApiError::forbidden("testing_manager_required"));
        }
    }
    let record: Option<sqlx::types::Json<Value>> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_testing_record($1,$2)")
            .bind(service.application_id)
            .bind(environment)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    let record = record.ok_or_else(ApiError::not_found)?.0;
    let ready: bool =
        sqlx::query_scalar("SELECT iam_private.honeycomb_testing_app_control_ready($1,$2)")
            .bind(service.application_id)
            .bind(environment)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    if !ready {
        return Err(ApiError::conflict("testing_operation_in_progress"));
    }

    if record["generation"] != version.generation
        || record["key_version"] != version.key_version
        || (service_read && record["iam_revision"] != version.expected_environment_revision)
        || !matches!(
            record["state"].as_str(),
            Some("active" | "prepared" | "cleaned")
        )
    {
        return Err(ApiError::conflict("testing_revision_or_state_conflict"));
    }
    let organization: Uuid =
        sqlx::query_scalar("SELECT iam_private.honeycomb_testing_organization($1,NULL)")
            .bind(environment)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    Ok((
        tx,
        SelectedEnvironment {
            id: environment,
            organization_id: organization,
        },
        actor,
        client.as_ref().map(|client| client.application_id),
    ))
}
async fn snapshot(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    app: &str,
) -> Result<Value, ApiError> {
    let record: Option<sqlx::types::Json<Value>> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_testing_application_record($1)")
            .bind(app)
            .fetch_one(&mut **tx)
            .await
            .map_err(database)?;
    let mut record = record.ok_or_else(ApiError::not_found)?.0;
    if let Some(row) = webhook(tx, app).await? {
        record["webhook_url"] = json!(decrypt(
            state,
            row.application_id,
            row.endpoint_id,
            ProtectedField::ApplicationWebhookUrl,
            row.url_ciphertext,
            row.url_nonce,
            row.url_key_version
        )?);
    }
    Ok(record)
}
async fn read(
    State(state): State<ApiState>,
    service: Service,
    Path((env, app)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Query(version): Query<Version>,
) -> Result<Json<Value>, ApiError> {
    let (tx, selected, _, client) =
        authorize(&state, &service, &headers, env, &app, &version, true).await?;
    let plane = state
        .testing
        .as_ref()
        .ok_or_else(|| ApiError::internal("testing_not_configured"))?;
    let value = testing_plane::scope(selected, async {
        let mut test = context::begin(&plane.pool, DatabaseContext::anonymous())
            .await
            .map_err(database)?;
        check_source(&mut test, &app, client).await?;
        let value = snapshot(&mut test, &state, &app).await?;
        test.commit().await.map_err(database)?;
        Ok::<_, ApiError>(value)
    })
    .await?;
    tx.commit().await.map_err(database)?;
    Ok(Json(value))
}
async fn configure(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<(Uuid, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, ApiError> {
    mutate(state, service, path, headers, body, MutationKind::Configure).await
}
async fn rotate(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<(Uuid, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, ApiError> {
    mutate(state, service, path, headers, body, MutationKind::Rotate).await
}
#[derive(Clone, Copy, PartialEq)]
enum MutationKind {
    Configure,
    Rotate,
    Recover,
}
async fn recover(
    State(state): State<ApiState>,
    service: Service,
    Path(path): Path<(Uuid, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, ApiError> {
    if !headers.contains_key("x-honeycomb-application-authorization") {
        return Err(ApiError::invalid_client());
    }
    mutate(state, service, path, headers, body, MutationKind::Recover).await
}
async fn mutate(
    state: ApiState,
    service: Service,
    (env, app): (Uuid, String),
    headers: HeaderMap,
    body: Bytes,
    mode: MutationKind,
) -> Result<axum::response::Response, ApiError> {
    let rotation = mode == MutationKind::Rotate;
    let recovery = mode == MutationKind::Recover;
    let input: Mutation = serde_json::from_slice(&body)
        .map_err(|_| ApiError::validation("instruction", "invalid test application request"))?;
    if input.environment_id != env
        || (!recovery && input.configuration_revision <= 0)
        || input.expected_iam_revision < 0
        || (rotation || recovery) && input.configuration.is_some()
    {
        return Err(ApiError::validation(
            "instruction",
            "invalid application identity or revision",
        ));
    }
    let version = Version {
        generation: input.generation,
        key_version: input.key_version,
        expected_environment_revision: input.expected_environment_revision,
    };
    let (mut tx, selected, actor, client) =
        authorize(&state, &service, &headers, env, &app, &version, false).await?;
    if !rotation && !recovery && input.expected_iam_revision == 0 {
        let production: Option<Uuid> =
            sqlx::query_scalar("SELECT iam_private.resolve_honeycomb_application($1)")
                .bind(&app)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        if production.is_some() {
            return Err(ApiError::conflict("testing_application_import_required"));
        }
        let environment: Option<sqlx::types::Json<Value>> =
            sqlx::query_scalar("SELECT iam_private.honeycomb_testing_record($1,$2)")
                .bind(service.application_id)
                .bind(env)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        if input.configuration.as_ref().and_then(|v| v.get("org_id"))
            != environment.as_ref().and_then(|v| v.0.get("org_id"))
        {
            return Err(ApiError::forbidden(
                "testing_application_organization_required",
            ));
        }
    }
    let resource = format!("{env}/{app}");
    let kind = match mode {
        MutationKind::Configure => "testing-app-configure",
        MutationKind::Rotate => "testing-app-rotate",
        MutationKind::Recover => "testing-app-recover",
    };
    if let Some(result) = operations::claim(
        &mut tx,
        &state,
        &service,
        &actor,
        &headers,
        input.operation_id,
        kind,
        &resource,
        &body,
    )
    .await?
    {
        tx.commit().await.map_err(database)?;
        return Ok(operations::management_response(result, true));
    }
    let current_revision: Option<i64> = sqlx::query_scalar(
        "SELECT (iam_private.honeycomb_testing_record($1,$2)->>'iam_revision')::bigint",
    )
    .bind(service.application_id)
    .bind(env)
    .fetch_one(&mut *tx)
    .await
    .map_err(database)?;
    if current_revision != Some(input.expected_environment_revision) {
        return Err(ApiError::conflict("testing_revision_or_state_conflict"));
    }
    sqlx::query("UPDATE iam.honeycomb_operations SET environment_id=$2 WHERE operation_id=$1")
        .bind(input.operation_id)
        .bind(env)
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    let plane = state
        .testing
        .as_ref()
        .ok_or_else(|| ApiError::internal("testing_not_configured"))?;
    let response = testing_plane::scope(selected, async {
        let mut test = context::begin(&plane.pool, DatabaseContext::anonymous())
            .await
            .map_err(database)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("testing-import:{env}"))
            .execute(&mut *test)
            .await
            .map_err(database)?;
        // A target-plane receipt survives a failed production commit. Bind it
        // to the same service, actor, operation kind and resource as claim().
        let mut fingerprint = Sha256::new();
        fingerprint.update(service.application_id.as_bytes());
        fingerprint.update(actor.id.as_bytes());
        fingerprint.update(kind.as_bytes());
        fingerprint.update([0]);
        fingerprint.update(resource.as_bytes());
        fingerprint.update([0]);
        fingerprint.update(&body);
        let digest = fingerprint.finalize().to_vec();
        check_source(&mut test, &app, client).await?;
        let receipt: Option<(sqlx::types::Json<Value>, Vec<u8>, Vec<u8>, i16, bool)> =
            sqlx::query_as("SELECT * FROM iam_private.honeycomb_test_app_receipt($1,$2)")
                .bind(input.operation_id)
                .bind(&digest)
                .fetch_optional(&mut *test)
                .await
                .map_err(database)?;
        if let Some((public, ciphertext, nonce, key_version, unexpired)) = receipt {
            let response = if unexpired {
                let plaintext = state
                    .crypto
                    .decrypt(
                        EncryptionContext::tenant(
                            ProtectedField::IdempotencySecretResponse,
                            env,
                            input.operation_id,
                        ),
                        &EncryptedValue {
                            ciphertext,
                            nonce: nonce
                                .try_into()
                                .map_err(|_| ApiError::internal("testing_receipt_nonce"))?,
                            key_version,
                        },
                    )
                    .map_err(|_| ApiError::internal("testing_receipt_decrypt"))?;
                serde_json::from_slice(&plaintext)
                    .map_err(|_| ApiError::internal("testing_receipt_decode"))?
            } else {
                let mut v = public.0;
                v["secret_replay_expired"] = json!(true);
                v
            };
            test.commit().await.map_err(database)?;
            return Ok::<_, ApiError>(response);
        }
        let response = if recovery {
            recover_in_test(&mut test, &state, &app, &input).await?
        } else if rotation {
            rotate_in_test(&mut test, &state, &app, &input).await?
        } else {
            configure_in_test(&mut test, &state, &app, &input).await?
        };
        let mut public = response.clone();
        public
            .as_object_mut()
            .ok_or_else(|| ApiError::internal("testing_receipt_shape"))?
            .remove("app_secret");
        let encrypted = state
            .crypto
            .encrypt(
                EncryptionContext::tenant(
                    ProtectedField::IdempotencySecretResponse,
                    env,
                    input.operation_id,
                ),
                &serde_json::to_vec(&response)
                    .map_err(|_| ApiError::internal("testing_receipt_encode"))?,
            )
            .map_err(|_| ApiError::internal("testing_receipt_encrypt"))?;
        sqlx::query("SELECT iam_private.honeycomb_test_app_complete($1,$2,$3,$4,$5,$6)")
            .bind(input.operation_id)
            .bind(digest)
            .bind(sqlx::types::Json(public))
            .bind(encrypted.ciphertext)
            .bind(encrypted.nonce.as_slice())
            .bind(encrypted.key_version)
            .execute(&mut *test)
            .await
            .map_err(database)?;
        test.commit().await.map_err(database)?;
        Ok(response)
    })
    .await?;
    let revision = response["iam_revision"]
        .as_i64()
        .ok_or_else(|| ApiError::internal("testing_app_revision"))?;
    operations::complete(
        &mut tx,
        &state,
        &service,
        input.operation_id,
        &resource,
        revision,
        &response,
        response.get("app_secret").is_some(),
    )
    .await?;
    tx.commit().await.map_err(database)?;
    Ok(operations::management_response(response, false))
}
#[derive(sqlx::FromRow)]
struct WebhookRow {
    application_id: Uuid,
    endpoint_id: Uuid,
    signing_key_id: Uuid,
    url_ciphertext: Vec<u8>,
    url_nonce: Vec<u8>,
    url_key_version: i16,
    secret_ciphertext: Vec<u8>,
    secret_nonce: Vec<u8>,
    secret_key_version: i16,
    inherited: bool,
}
async fn webhook(
    tx: &mut Transaction<'_, Postgres>,
    app: &str,
) -> Result<Option<WebhookRow>, ApiError> {
    sqlx::query_as("SELECT * FROM iam_private.honeycomb_testing_application_webhook($1)")
        .bind(app)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database)
}
fn decrypt(
    state: &ApiState,
    app: Uuid,
    id: Uuid,
    field: ProtectedField,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    key_version: i16,
) -> Result<String, ApiError> {
    let bytes = state
        .crypto
        .decrypt(
            EncryptionContext::tenant(field, app, id),
            &EncryptedValue {
                ciphertext,
                nonce: nonce
                    .try_into()
                    .map_err(|_| ApiError::internal("testing_webhook_nonce"))?,
                key_version,
            },
        )
        .map_err(|_| ApiError::internal("testing_webhook_decrypt"))?;
    String::from_utf8(bytes.to_vec()).map_err(|_| ApiError::internal("testing_webhook_encoding"))
}
fn secret(state: &ApiState) -> Result<(secrecy::SecretString, Value), ApiError> {
    let secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)
        .map_err(|_| ApiError::internal("testing_app_secret_generate"))?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationSecret, &secret)
        .map_err(|_| ApiError::internal("testing_app_secret_digest"))?;
    let value = json!({"secret_id":Uuid::now_v7(),"secret_digest":hex::encode(digest.as_bytes()),"secret_digest_version":digest.key_version(),"secret_prefix":secret.expose_secret().chars().take(12).collect::<String>()});
    Ok((secret, value))
}
async fn rotate_in_test(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    app: &str,
    input: &Mutation,
) -> Result<Value, ApiError> {
    let before = snapshot(tx, state, app).await?;
    if before["configuration_revision"] != input.configuration_revision {
        return Err(ApiError::conflict("configuration_revision_conflict"));
    }
    let id: Uuid = serde_json::from_value(before["application_id"].clone())
        .map_err(|_| ApiError::internal("testing_application_id"))?;
    let (secret, value) = secret(state)?;
    let credential: i64 = sqlx::query_scalar(
        "SELECT iam_private.honeycomb_rotate_testing_application_secret($1,$2,$3)",
    )
    .bind(app)
    .bind(input.expected_iam_revision)
    .bind(sqlx::types::Json(value))
    .fetch_one(&mut **tx)
    .await
    .map_err(database)?;
    super::super::graph::record_rotated_application_secret(tx, state, id, &secret)
        .await
        .map_err(|_| ApiError::internal("testing_secret_record"))?;
    let record = snapshot(tx, state, app).await?;
    Ok(
        json!({"operation_id":input.operation_id,"state":"accepted","environment_id":input.environment_id,"app_id":app,"configuration_revision":input.configuration_revision,"iam_revision":record["iam_revision"],"credential_version":credential,"app_secret":secret.expose_secret(),"effective_configuration":record}),
    )
}
async fn configure_in_test(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    app: &str,
    input: &Mutation,
) -> Result<Value, ApiError> {
    let mut config = input
        .configuration
        .clone()
        .ok_or_else(|| ApiError::validation("configuration", "required"))?;
    let object = config
        .as_object_mut()
        .ok_or_else(|| ApiError::validation("configuration", "object required"))?;
    object.insert("operation_id".into(), json!(input.operation_id));
    object.insert("app_id".into(), json!(app));
    object.insert(
        "expected_iam_revision".into(),
        json!(input.expected_iam_revision),
    );
    object.insert(
        "configuration_revision".into(),
        json!(input.configuration_revision),
    );
    if config["visibility"] != "private" {
        return Err(ApiError::validation(
            "configuration",
            "test configurations require private visibility",
        ));
    }
    operations::validate_test_configuration(&config)?;
    let existing: Option<sqlx::types::Json<Value>> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_testing_application_record($1)")
            .bind(app)
            .fetch_one(&mut **tx)
            .await
            .map_err(database)?;
    let fresh = existing.is_none();
    let id = if let Some(existing) = &existing {
        serde_json::from_value(existing.0["application_id"].clone())
            .map_err(|_| ApiError::internal("testing_app_id"))?
    } else {
        Uuid::now_v7()
    };
    let prior = webhook(tx, app).await?;
    let url = config["webhook"]["url"]
        .as_str()
        .ok_or_else(|| ApiError::validation("webhook.url", "required"))?;
    let mut endpoint = Uuid::now_v7();
    let supplied = config["webhook"]["secret"].as_str().map(str::to_owned);
    let mut inherited = false;
    let signing = if let Some(prior) = prior {
        let old_url = decrypt(
            state,
            id,
            prior.endpoint_id,
            ProtectedField::ApplicationWebhookUrl,
            prior.url_ciphertext,
            prior.url_nonce,
            prior.url_key_version,
        )?;
        if old_url == url {
            endpoint = prior.endpoint_id;
        }
        if let Some(supplied) = supplied {
            supplied
        } else if old_url == url {
            inherited = prior.inherited;
            decrypt(
                state,
                id,
                prior.signing_key_id,
                ProtectedField::ApplicationWebhookSigningSecret,
                prior.secret_ciphertext,
                prior.secret_nonce,
                prior.secret_key_version,
            )?
        } else {
            return Err(ApiError::validation(
                "webhook.secret",
                "required for new destination",
            ));
        }
    } else {
        supplied
            .ok_or_else(|| ApiError::validation("webhook.secret", "required for new application"))?
    };
    let signing_id = Uuid::now_v7();
    let enc_url = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(ProtectedField::ApplicationWebhookUrl, id, endpoint),
            url.as_bytes(),
        )
        .map_err(|_| ApiError::internal("testing_webhook_encrypt"))?;
    let enc_signing = state
        .crypto
        .encrypt(
            EncryptionContext::tenant(
                ProtectedField::ApplicationWebhookSigningSecret,
                id,
                signing_id,
            ),
            signing.as_bytes(),
        )
        .map_err(|_| ApiError::internal("testing_signing_encrypt"))?;
    let (new_secret, secret_fields) = secret(state)?;
    let enc_secret = state
        .crypto
        .encrypt(
            super::super::graph::secret_context(input.environment_id, id),
            new_secret.expose_secret().as_bytes(),
        )
        .map_err(|_| ApiError::internal("testing_secret_encrypt"))?;
    let org = config["org_id"]
        .as_str()
        .ok_or_else(|| ApiError::validation("org_id", "required"))?;
    let mut payload = json!({"application_id":id,"source_application_id":id,"source_revision":input.configuration_revision,
 "configuration_revision":input.configuration_revision,"expected_iam_revision":input.expected_iam_revision,
 "app_id":app,"org_id":org,"organization_name":org,"organization_logo":null,"organization_description":null,
 "app_name":config["name"],"app_logo":config["logo_url"],"base_url":config["base_url"].as_str().unwrap_or(""),
 "app_scope":config["app_scope"],"webhook_scope":config["webhook"]["scope"],"testing_idle_days":config["testing_idle_days"].as_i64().unwrap_or(30),"visibility":"private",
 "obo_endpoints":config.get("obo_endpoints").cloned().unwrap_or_else(||json!([])),"endpoint_id":endpoint,"signing_key_id":signing_id,
 "webhook_secret_version":1,"webhook_fingerprint":crate::features::applications::webhook_secret_fingerprint(&signing),
 "url_ciphertext":hex::encode(enc_url.ciphertext),"url_nonce":hex::encode(enc_url.nonce),"url_key_version":enc_url.key_version,"url_digest":hex::encode(Sha256::digest(url.as_bytes())),
 "signing_ciphertext":hex::encode(enc_signing.ciphertext),"signing_nonce":hex::encode(enc_signing.nonce),"signing_key_version":enc_signing.key_version,
 "secret_ciphertext":hex::encode(enc_secret.ciphertext),"secret_nonce":hex::encode(enc_secret.nonce),"secret_key_version":enc_secret.key_version,
 "replace_secret":fresh,"local_registration":fresh,"availability":config["availability"],"webhook_inherited":inherited});
    for (key, value) in secret_fields
        .as_object()
        .ok_or_else(|| ApiError::internal("testing_secret_shape"))?
    {
        payload[key] = value.clone();
    }
    sqlx::query("SELECT iam_private.honeycomb_configure_testing_application($1)")
        .bind(sqlx::types::Json(payload))
        .execute(&mut **tx)
        .await
        .map_err(database)?;
    super::super::scope_policy::synchronize(tx, &state.pool)
        .await
        .map_err(|_| ApiError::conflict("testing_scope_policy_unavailable"))?;
    sqlx::query("SELECT iam_private.activate_testing_application_scopes($1)")
        .bind(vec![id])
        .execute(&mut **tx)
        .await
        .map_err(database)?;
    sqlx::query("SELECT iam_private.honeycomb_testing_app_readiness($1,false)")
        .bind(vec![id])
        .execute(&mut **tx)
        .await
        .map_err(database)?;
    if fresh {
        super::super::graph::record_rotated_application_secret(tx, state, id, &new_secret)
            .await
            .map_err(|_| ApiError::internal("testing_secret_record"))?;
    }
    let record = snapshot(tx, state, app).await?;
    let mut response = json!({"operation_id":input.operation_id,"state":"accepted","environment_id":input.environment_id,"app_id":app,"configuration_revision":input.configuration_revision,"iam_revision":record["iam_revision"],"ready":false,"effective_configuration":record});
    if fresh {
        response["app_secret"] = json!(new_secret.expose_secret());
    }
    Ok(response)
}

#[cfg(test)]
pub(crate) mod tests;

async fn list(
    State(state): State<ApiState>,
    service: Service,
    headers: HeaderMap,
    Query(query): Query<super::super::model::PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let client = authority::production_application(&state, &headers)
        .await?
        .ok_or_else(ApiError::invalid_client)?;
    let (cursor, limit, status) = super::super::validation::page(&query).map_err(|_| {
        ApiError::validation(
            "page",
            "limit must be 1-100 and status active, deleted, or all",
        )
    })?;
    let mut tx = context::begin(
        &state.pool,
        DatabaseContext {
            principal_id: Some(client.application_id),
            application_id: Some(client.application_id),
            organization_id: Some(client.organization_id),
            signup_session_id: None,
        },
    )
    .await
    .map_err(database)?;
    let mut items:Vec<sqlx::types::Json<Value>>=sqlx::query_scalar("SELECT to_jsonb(item) FROM iam_private.list_application_testing_environments($1,$2,$3) item").bind(cursor).bind(i32::try_from(limit+1).map_err(|_|ApiError::validation("limit","invalid limit"))?).bind(status).fetch_all(&mut *tx).await.map_err(database)?;
    let has_more = items.len()
        > usize::try_from(limit).map_err(|_| ApiError::validation("limit", "invalid limit"))?;
    if has_more {
        items.pop();
    }
    for item in &mut items {
        if item.0["purge_after"] == "infinity" {
            item.0["purge_after"] = Value::Null;
        }
        let id: Uuid = serde_json::from_value(item.0["environment_id"].clone())
            .map_err(|_| ApiError::internal("testing_list_identity"))?;
        let record: Option<sqlx::types::Json<Value>> =
            sqlx::query_scalar("SELECT iam_private.honeycomb_testing_record($1,$2)")
                .bind(service.application_id)
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        if let Some(record) = record {
            for field in ["state", "generation", "key_version", "iam_revision"] {
                item.0[field] = record.0[field].clone();
            }
        }
    }
    let next = has_more
        .then(|| {
            items
                .last()
                .and_then(|item| item.0.get("environment_id"))
                .cloned()
        })
        .flatten();
    tx.commit().await.map_err(database)?;
    Ok(Json(
        json!({"items":items.into_iter().map(|item|item.0).collect::<Vec<_>>(),"page":{"has_more":has_more,"next_cursor":next}}),
    ))
}

async fn application_identity(
    State(state): State<ApiState>,
    service: Service,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let client = authority::production_application(&state, &headers)
        .await?
        .ok_or_else(ApiError::invalid_client)?;
    let mut tx = context::begin(
        &state.pool,
        DatabaseContext {
            principal_id: Some(client.application_id),
            application_id: Some(client.application_id),
            organization_id: Some(client.organization_id),
            signup_session_id: None,
        },
    )
    .await
    .map_err(database)?;
    let record: Option<sqlx::types::Json<Value>> =
        sqlx::query_scalar("SELECT iam_private.honeycomb_application_record($1,$2)")
            .bind(service.application_id)
            .bind(&client.app_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
    let record = record.ok_or_else(ApiError::invalid_client)?.0;
    let org_id = &record["org_id"];
    let revision = &record["iam_revision"];
    tx.commit().await.map_err(database)?;
    Ok(Json(
        json!({"application_id":client.application_id,"app_id":client.app_id,"organization_id":client.organization_id,"org_id":org_id,"iam_revision":revision}),
    ))
}

async fn check_source(
    tx: &mut Transaction<'_, Postgres>,
    app: &str,
    client: Option<Uuid>,
) -> Result<(), ApiError> {
    let Some(client) = client else {
        return Ok(());
    };
    let source: Option<(Uuid, Uuid, bool, bool)> =
        sqlx::query_as("SELECT * FROM iam_private.honeycomb_testing_application_source($1)")
            .bind(app)
            .fetch_optional(&mut **tx)
            .await
            .map_err(database)?;
    if !source
        .is_some_and(|(_, source, imported, retired)| source == client && imported && !retired)
    {
        return Err(ApiError::forbidden(
            "testing_application_source_identity_required",
        ));
    }
    Ok(())
}
async fn recover_in_test(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    app: &str,
    input: &Mutation,
) -> Result<Value, ApiError> {
    let (id, ciphertext, nonce, key_version): (Uuid, Vec<u8>, Vec<u8>, i16) =
        sqlx::query_as("SELECT * FROM iam_private.get_testing_application_secret($1)")
            .bind(app)
            .fetch_one(&mut **tx)
            .await
            .map_err(database)?;
    let plaintext = state
        .crypto
        .decrypt(
            super::super::graph::secret_context(input.environment_id, id),
            &EncryptedValue {
                ciphertext,
                nonce: nonce
                    .try_into()
                    .map_err(|_| ApiError::internal("testing_secret_nonce"))?,
                key_version,
            },
        )
        .map_err(|_| ApiError::internal("testing_secret_decrypt"))?;
    let secret = std::str::from_utf8(&plaintext)
        .map_err(|_| ApiError::internal("testing_secret_encoding"))?;
    let record = snapshot(tx, state, app).await?;
    Ok(
        json!({"operation_id":input.operation_id,"state":"accepted","environment_id":input.environment_id,"app_id":app,"application_id":id,"configuration_revision":record["configuration_revision"],"iam_revision":record["iam_revision"],"credential_version":record["credential_version"],"app_secret":secret}),
    )
}
