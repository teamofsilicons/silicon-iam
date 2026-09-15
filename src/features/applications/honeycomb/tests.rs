//! Exercise management through HTTP and the restricted database runtime role.
#![allow(clippy::too_many_lines)]

use crate::{
    api::ApiState,
    config::{HoneycombSettings, Settings},
    infrastructure::{
        crypto::{CryptoService, DigestPurpose, SecretKind},
        postgres,
        providers::NotificationProviders,
    },
};
use anyhow::ensure;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use tower::ServiceExt as _;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires Docker and synthetic development IAM settings"]
async fn management_is_authenticated_revision_bound_and_durably_replayable() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_test_writer()
        .try_init();
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let url = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    let admin = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await?;
    sqlx::raw_sql("CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN;").execute(&admin).await?;
    postgres::migrate(&admin).await?;
    super::super::live_tests::seed_protocol_rows(&admin).await?;
    let grants = include_str!("../../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
        .execute(&admin)
        .await?;
    let runtime = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE silicon_iam_api")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    let mut settings = Settings::from_env()?;
    settings.providers.allow_local_providers = true;
    let service_secret = format!("hck_{}", "a".repeat(43));
    settings.honeycomb = Some(HoneycombSettings {
        app_id: "test_org>app-alpha".into(),
        credential_sha256: hex::encode(Sha256::digest(service_secret.as_bytes())).into(),
        scheduled_testing: false,
        retire_legacy_writers: false,
    });
    let crypto = Arc::new(CryptoService::from_settings(&settings.security)?);
    let actor = crypto.generate_secret(SecretKind::ApplicationAccessToken)?;
    let digest = crypto.digest_secret(DigestPurpose::ApplicationAccessToken, &actor)?;
    sqlx::query("UPDATE iam.access_tokens SET token_digest=$1,digest_key_version=$2 WHERE id=$3")
        .bind(digest.as_bytes().as_slice())
        .bind(digest.key_version())
        .bind(Uuid::from_u128(0x101))
        .execute(&admin)
        .await?;
    sqlx::query("CREATE DATABASE testing")
        .execute(&admin)
        .await?;
    let testing_url = url
        .strip_suffix("/postgres")
        .ok_or_else(|| anyhow::anyhow!("test URL"))?
        .to_owned()
        + "/testing";
    let test_admin = PgPoolOptions::new()
        .max_connections(4)
        .connect(&testing_url)
        .await?;
    postgres::migrate_testing(&test_admin).await?;
    postgres::register_runtime_key_versions(&test_admin, &settings.security).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
        .execute(&test_admin)
        .await?;
    let test_runtime = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE silicon_iam_api")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&testing_url)
        .await?;
    let test_settings = crate::config::TestingSettings {
        database: settings.database.clone(),
        idle_days: 30,
        recovery_days: 30,
        max_per_organization: 25,
    };
    let state = ApiState {
        pool: runtime,
        crypto,
        notifications: NotificationProviders::from_settings(&settings.providers)?,
        workos: None,
        testing: Some(crate::api::TestingPlane {
            pool: test_runtime,
            settings: Arc::new(test_settings),
        }),
        settings: Arc::new(settings),
    };
    for retired in [false, true] {
        let mut cutover_state = state.clone();
        Arc::make_mut(&mut cutover_state.settings)
            .honeycomb
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("integration settings"))?
            .retire_legacy_writers = retired;
        let legacy = axum::Router::new()
            .route(
                "/api/v1/applications",
                axum::routing::post(|| async { StatusCode::OK }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                cutover_state,
                super::legacy_writer_guard,
            ));
        let response = legacy
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/applications")
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            response.status()
                == if retired {
                    StatusCode::GONE
                } else {
                    StatusCode::OK
                },
            "service provisioning must not implicitly cut over legacy writers"
        );
    }
    let app = super::router().with_state(state.clone());
    let id = Uuid::now_v7();
    let configuration = json!({"operation_id":id,"expected_iam_revision":0,"configuration_revision":1,"environment_id":null,
        "app_id":"test_org>managed-app","org_id":"test_org","name":"Managed","logo_url":null,"base_url":null,
        "visibility":"private","availability":"active","webhook":{"url":"https://managed.example.test/webhook","secret":"a".repeat(48),"scope":["membership"]},
        "app_scope":{"iam":["self.identity.read","directory.carbons.read"],"external":[]},"obo_endpoints":[],"obo_review_message":null});
    let path = "/api/v1/honeycomb/applications/test_org%3Emanaged-app/configuration";
    let request = |credential: &str,
                   actor_token: Option<&str>,
                   value: &Value,
                   key: &str|
     -> anyhow::Result<Request<Body>> {
        let mut builder = Request::builder()
            .method("PUT")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {credential}"))
            .header("idempotency-key", key);
        if let Some(actor) = actor_token {
            builder = builder.header("x-honeycomb-actor-token", actor);
        }
        Ok(builder.body(Body::from(serde_json::to_vec(value)?))?)
    };
    let key = id.to_string();
    ensure!(
        app.clone()
            .oneshot(request(
                actor.expose_secret(),
                Some(actor.expose_secret()),
                &configuration,
                &key
            )?)
            .await?
            .status()
            == StatusCode::UNAUTHORIZED,
        "ordinary application user tokens must not become service credentials"
    );
    ensure!(
        app.clone()
            .oneshot(request(&service_secret, None, &configuration, &key)?)
            .await?
            .status()
            == StatusCode::UNAUTHORIZED,
        "a service credential alone cannot configure an app"
    );
    let response = app
        .clone()
        .oneshot(request(
            &service_secret,
            Some(actor.expose_secret()),
            &configuration,
            &key,
        )?)
        .await?;
    let status = response.status();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
    ensure!(status == StatusCode::OK, "configuration failed: {body}");
    ensure!(
        body["state"] == "accepted" && body["app_secret"].as_str().is_some(),
        "private app should be accepted with a one-time secret"
    );
    let replay = app
        .clone()
        .oneshot(request(
            &service_secret,
            Some(actor.expose_secret()),
            &configuration,
            &key,
        )?)
        .await?;
    let replay: Value = serde_json::from_slice(&to_bytes(replay.into_body(), 1024 * 1024).await?)?;
    ensure!(
        replay == body,
        "lost-response replay changed the credential or effective configuration"
    );
    let basis:String=sqlx::query_scalar("SELECT approved.approval_basis FROM iam.application_approved_scopes approved JOIN iam.applications app ON app.id=approved.application_id WHERE app.app_id='test_org>managed-app' AND approved.scope='directory.carbons.read' AND approved.revoked_at IS NULL").fetch_one(&admin).await?;
    ensure!(
        basis == "private_exemption",
        "private scope must not be recorded as provider approval"
    );
    let mut changed = configuration.clone();
    changed["name"] = json!("Different");
    ensure!(
        app.clone()
            .oneshot(request(
                &service_secret,
                Some(actor.expose_secret()),
                &changed,
                &key
            )?)
            .await?
            .status()
            == StatusCode::CONFLICT,
        "same operation cannot change its body"
    );
    sqlx::query("UPDATE iam.honeycomb_operations SET response_expires_at=transaction_timestamp()-interval '1 second' WHERE operation_id=$1").bind(id).execute(&admin).await?;
    let expired = app
        .clone()
        .oneshot(request(
            &service_secret,
            Some(actor.expose_secret()),
            &configuration,
            &key,
        )?)
        .await?;
    let expired: Value =
        serde_json::from_slice(&to_bytes(expired.into_body(), 1024 * 1024).await?)?;
    ensure!(
        expired.get("app_secret").is_none() && expired["secret_replay_expired"] == true,
        "expired replay must not reveal or regenerate the secret"
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM iam.application_secrets secret JOIN iam.applications app ON app.id=secret.application_id WHERE app.app_id='test_org>managed-app'").fetch_one(&admin).await?;
    ensure!(count == 1, "replay created a second secret");
    let status_request = Request::builder()
        .uri(format!("/api/v1/honeycomb/operations/{id}"))
        .header("authorization", format!("Bearer {service_secret}"))
        .body(Body::empty())?;
    let receipt = app.clone().oneshot(status_request).await?;
    ensure!(
        receipt.status() == StatusCode::OK,
        "reconciliation must work without a retained actor token"
    );
    let receipt: String =
        String::from_utf8(to_bytes(receipt.into_body(), 1024 * 1024).await?.to_vec())?;
    ensure!(
        !receipt.contains(body["app_secret"].as_str().unwrap_or("missing")),
        "status leaked a credential"
    );
    let events: String = sqlx::query_scalar(
        "SELECT payload::text FROM iam.honeycomb_management_events WHERE operation_id=$1",
    )
    .bind(id)
    .fetch_one(&admin)
    .await?;
    ensure!(
        !events.contains(body["app_secret"].as_str().unwrap_or("missing")),
        "notification stored a credential"
    );
    sensitive_operations(&app, &state, &admin, &service_secret, actor.expose_secret()).await?;
    lifecycle(
        &app,
        &state,
        &admin,
        &test_admin,
        &service_secret,
        actor.expose_secret(),
    )
    .await?;
    publication(
        &app,
        &admin,
        &service_secret,
        actor.expose_secret(),
        &configuration,
    )
    .await?;
    bundles_and_reconciliation(&app, &admin, &service_secret, actor.expose_secret()).await?;
    Ok(())
}

async fn lifecycle(
    app: &axum::Router,
    state: &ApiState,
    admin: &sqlx::PgPool,
    test_admin: &sqlx::PgPool,
    credential: &str,
    actor: &str,
) -> anyhow::Result<()> {
    let environment = Uuid::now_v7();
    let mut revision = 0;
    let mut generation = 1;
    let mut key = String::new();
    let mut prepare = Value::Null;
    let mut first_import = String::new();
    let mut imported_id = None;
    let mut import_count = 0;
    for operation in [
        "prepare",
        "import",
        "import",
        "activate",
        "rotate-key",
        "clean",
        "import",
        "activate",
        "disable",
        "restore",
        "activate",
        "disable",
        "purge",
    ] {
        let id = Uuid::now_v7();
        let mut input = json!({"operation_id":id,"environment_id":environment,"expected_iam_revision":revision,"generation":generation,"operation":operation,"org_id":"test_org","name":"Managed test","description":null});
        if operation == "import" {
            if import_count == 1 {
                sqlx::query("UPDATE iam.applications SET app_name='Refreshed source',version=version+1 WHERE app_id='test_org>managed-app'").execute(admin).await?;
            }
            let source: i64 = sqlx::query_scalar(
                "SELECT version FROM iam.applications WHERE app_id='test_org>managed-app'",
            )
            .fetch_one(admin)
            .await?;
            input["app_id"] = json!("test_org>managed-app");
            input["source_revisions"] = json!({"test_org>managed-app":source});
        }
        let request = || {
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/honeycomb/testing-environments/{environment}/operations"
                ))
                .header("authorization", format!("Bearer {credential}"))
                .header("x-honeycomb-actor-token", actor)
                .header("idempotency-key", id.to_string())
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&input).unwrap_or_default()))
        };
        let result = app.clone().oneshot(request()?).await?;
        let status = result.status();
        let result: Value =
            serde_json::from_slice(&to_bytes(result.into_body(), 1024 * 1024).await?)?;
        ensure!(status == StatusCode::OK, "{operation} failed: {result}");
        let replay = app.clone().oneshot(request()?).await?;
        let replay: Value =
            serde_json::from_slice(&to_bytes(replay.into_body(), 1024 * 1024).await?)?;
        ensure!(result == replay, "{operation} replay changed result");
        revision = result["iam_revision"].as_i64().unwrap_or_default();
        generation = result["environment"]["generation"]
            .as_i64()
            .unwrap_or_default();
        if operation == "import" {
            let current = result["app_secret"].as_str().unwrap_or_default();
            let row: (Uuid,String,i64) = sqlx::query_as("SELECT app.id,app.app_name,import.source_revision FROM iam.applications app JOIN iam.testing_application_imports import ON import.application_id=app.id WHERE app.app_id='test_org>managed-app' AND app.testing_environment_id=$1").bind(environment).fetch_one(test_admin).await?;
            if import_count == 1 {
                ensure!(
                    imported_id == Some(row.0),
                    "configuration refresh changed app identity"
                );
                ensure!(
                    row.1 == "Refreshed source",
                    "configuration refresh retained stale metadata"
                );
                ensure!(
                    Some(row.2) == input["source_revisions"]["test_org>managed-app"].as_i64(),
                    "source revision not recorded"
                );
            }
            imported_id = Some(row.0);
            import_count += 1;
            ensure!(!current.is_empty(), "import omitted secret");
            if first_import.is_empty() {
                first_import = current.into();
            } else {
                ensure!(
                    first_import != current,
                    "post-clean import reused credential"
                );
            }
        }
        if operation == "prepare" {
            prepare = result.clone();
            key = result["key"].as_str().unwrap_or_default().into();
        }
        if operation == "rotate-key" {
            ensure!(
                key != result["key"].as_str().unwrap_or_default(),
                "rotation kept old key"
            );
            let old = state
                .crypto
                .digest_secrets(
                    crate::infrastructure::crypto::DigestPurpose::TestingEnvironmentKey,
                    &key.clone().into(),
                )?
                .into_iter()
                .map(|value| value.as_bytes().to_vec())
                .collect::<Vec<_>>();
            let old_valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM iam_private.resolve_testing_environment_v2($1))",
            )
            .bind(old)
            .fetch_one(admin)
            .await?;
            ensure!(!old_valid, "old root key still authenticates");
            key = result["key"].as_str().unwrap_or_default().into();
        }
        let active = result["environment"]["state"] == "active";
        // Verify production lookup and the independent testing transaction fence.
        let digests = state
            .crypto
            .digest_secrets(
                crate::infrastructure::crypto::DigestPurpose::TestingEnvironmentKey,
                &key.clone().into(),
            )?
            .into_iter()
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let resolves: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM iam_private.resolve_testing_environment_v2($1))",
        )
        .bind(digests)
        .fetch_one(admin)
        .await?;
        ensure!(
            resolves == active,
            "{operation} exposed the wrong access state"
        );
        let mut tx = test_admin.begin().await?;
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(environment.to_string())
            .execute(&mut *tx)
            .await?;
        let allowed = sqlx::query("SELECT iam_private.lock_testing_runtime_state($1,$2,$3)")
            .bind(environment)
            .bind(generation)
            .bind(i32::try_from(
                result["environment"]["key_version"]
                    .as_i64()
                    .unwrap_or_default(),
            )?)
            .execute(&mut *tx)
            .await
            .is_ok();
        tx.rollback().await?;
        ensure!(
            allowed == active,
            "{operation} has an incorrect data-plane fence"
        );
        if operation == "clean" {
            ensure!(
                generation == 2 && result.get("key").is_none(),
                "clean did not advance exactly one generation"
            );
        }
    }
    let key_erased:bool=sqlx::query_scalar("SELECT key_ciphertext IS NULL AND key_digest IS NULL FROM iam.testing_environments WHERE id=$1").bind(environment).fetch_one(admin).await?;
    ensure!(key_erased, "purge retained the root key");
    ensure!(
        prepare["environment"]["generation"] == 1,
        "initial generation changed"
    );
    Ok(())
}

async fn publication(
    app: &axum::Router,
    admin: &sqlx::PgPool,
    credential: &str,
    actor: &str,
    private: &Value,
) -> anyhow::Result<()> {
    let name = "test_org>managed-app";
    let revision: i64 = sqlx::query_scalar("SELECT version FROM iam.applications WHERE app_id=$1")
        .bind(name)
        .fetch_one(admin)
        .await?;
    let mut proposal = private.clone();
    proposal["configuration_revision"] = json!(2);
    proposal["expected_iam_revision"] = json!(revision);
    proposal["visibility"] = json!("public");
    proposal["webhook"]["secret"] = json!("b".repeat(48));
    proposal["publication_approved"] = json!(true);
    proposal["operation_id"] = json!(Uuid::now_v7());
    let send = |path: String, body: &Value, method: &str| -> anyhow::Result<Request<Body>> {
        Ok(Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {credential}"))
            .header("x-honeycomb-actor-token", actor)
            .header("content-type", "application/json")
            .header(
                "idempotency-key",
                body["operation_id"].as_str().unwrap_or_default(),
            )
            .body(Body::from(serde_json::to_vec(body)?))?)
    };
    let path = "/api/v1/honeycomb/applications/test_org%3Emanaged-app/configuration";
    let pending = app
        .clone()
        .oneshot(send(path.into(), &proposal, "PUT")?)
        .await?;
    let status = pending.status();
    let pending: Value =
        serde_json::from_slice(&to_bytes(pending.into_body(), 1024 * 1024).await?)?;
    ensure!(
        status == StatusCode::OK
            && pending["state"] == "pending"
            && pending["effective_configuration"]["visibility"] == "private",
        "public activation reused a private exemption: {pending}"
    );
    let current: i64 = sqlx::query_scalar("SELECT version FROM iam.applications WHERE app_id=$1")
        .bind(name)
        .fetch_one(admin)
        .await?;
    ensure!(
        current == revision,
        "pending public proposal changed the accepted record"
    );
    sqlx::query("INSERT INTO iam.platform_role_grants(id,carbon_id,role,grant_source) VALUES($1,$2,'application_reviewer','bootstrap')").bind(Uuid::now_v7()).bind(Uuid::from_u128(1)).execute(admin).await?;
    let decision = json!({"operation_id":Uuid::now_v7(),"expected_iam_revision":revision,"environment_id":null,"scopes":["directory.carbons.read"],"decision":"approve"});
    let accepted = app
        .clone()
        .oneshot(send(
            "/api/v1/honeycomb/applications/test_org%3Emanaged-app/scope-decisions".into(),
            &decision,
            "POST",
        )?)
        .await?;
    let status = accepted.status();
    let accepted: Value =
        serde_json::from_slice(&to_bytes(accepted.into_body(), 1024 * 1024).await?)?;
    ensure!(
        status == StatusCode::OK,
        "scope approval failed: {accepted}"
    );
    proposal["operation_id"] = json!(Uuid::now_v7());
    proposal["expected_iam_revision"] = accepted["iam_revision"].clone();
    let public = app
        .clone()
        .oneshot(send(path.into(), &proposal, "PUT")?)
        .await?;
    let status = public.status();
    let public: Value = serde_json::from_slice(&to_bytes(public.into_body(), 1024 * 1024).await?)?;
    ensure!(
        status == StatusCode::OK && public["effective_configuration"]["visibility"] == "public",
        "approved activation failed: {public}"
    );
    let event_count:i64=sqlx::query_scalar("SELECT count(*) FROM iam.honeycomb_management_events WHERE event_type='application.scope.decided'").fetch_one(admin).await?;
    ensure!(
        event_count == 1,
        "scope decision notification not committed atomically"
    );
    Ok(())
}

async fn sensitive_operations(
    app: &axum::Router,
    state: &ApiState,
    admin: &sqlx::PgPool,
    credential: &str,
    actor: &str,
) -> anyhow::Result<()> {
    for (suffix, action) in [
        ("webhook-approvals", "application.webhook.approve"),
        ("secret-rotations", "application.client_secret.rotate"),
        (
            "webhook-secret-rotations",
            "application.webhook_secret.rotate",
        ),
    ] {
        let (resource, revision): (Uuid, i64) = sqlx::query_as(
            "SELECT id,version FROM iam.applications WHERE app_id='test_org>managed-app'",
        )
        .fetch_one(admin)
        .await?;
        let id = Uuid::now_v7();
        let mut input = json!({"operation_id":id,"expected_iam_revision":revision});
        if suffix == "webhook-approvals" {
            let pending:Uuid=sqlx::query_scalar("SELECT id FROM iam.application_webhook_endpoints WHERE application_id=$1 AND status='pending_review'").bind(resource).fetch_one(admin).await?;
            input["pending_endpoint_id"] = json!(pending);
        }
        if suffix == "webhook-secret-rotations" {
            input["webhook_secret"] = json!("b".repeat(48));
        }
        let request = |proof: Option<&str>| -> anyhow::Result<Request<Body>> {
            let mut builder = Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/honeycomb/applications/test_org%3Emanaged-app/{suffix}"
                ))
                .header("authorization", format!("Bearer {credential}"))
                .header("x-honeycomb-actor-token", actor)
                .header("idempotency-key", id.to_string())
                .header("content-type", "application/json");
            if let Some(proof) = proof {
                builder = builder.header("x-step-up-token", proof);
            }
            Ok(builder.body(Body::from(serde_json::to_vec(&input)?))?)
        };
        let denied = app.clone().oneshot(request(None)?).await?;
        ensure!(
            denied.status() == StatusCode::PRECONDITION_REQUIRED,
            "{suffix} did not require step-up: {}",
            denied.status()
        );
        let secret = state.crypto.generate_secret(SecretKind::StepUpAssertion)?;
        let digest = state
            .crypto
            .digest_secret(DigestPurpose::StepUpAssertion, &secret)?;
        let challenge = Uuid::now_v7();
        sqlx::query("INSERT INTO iam.step_up_challenges(id,authentication_session_id,carbon_id,purpose,resource_id,channel,challenge_digest,digest_key_version,status,expires_at,consumed_at) VALUES($1,$2,$3,$4,$5,'email',$6,1,'completed',transaction_timestamp()+interval '5 minutes',transaction_timestamp())").bind(challenge).bind(Uuid::from_u128(0x41)).bind(Uuid::from_u128(1)).bind(action).bind(resource).bind(vec![3u8;32]).execute(admin).await?;
        let assertion = Uuid::now_v7();
        sqlx::query("INSERT INTO iam.step_up_assertions(id,step_up_challenge_id,authentication_session_id,carbon_id,purpose,token_prefix,token_digest,digest_key_version,assurance_level,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,2,transaction_timestamp()+interval '5 minutes')").bind(assertion).bind(challenge).bind(Uuid::from_u128(0x41)).bind(Uuid::from_u128(1)).bind(action).bind(secret.expose_secret().chars().take(12).collect::<String>()).bind(digest.as_bytes().as_slice()).bind(digest.key_version()).execute(admin).await?;
        let result = app
            .clone()
            .oneshot(request(Some(secret.expose_secret()))?)
            .await?;
        let status = result.status();
        let result: Value =
            serde_json::from_slice(&to_bytes(result.into_body(), 1024 * 1024).await?)?;
        ensure!(status == StatusCode::OK, "{suffix} failed: {result}");
        let replay = app.clone().oneshot(request(None)?).await?;
        ensure!(
            replay.status() == StatusCode::OK,
            "{suffix} replay required a second step-up"
        );
        let replay: Value =
            serde_json::from_slice(&to_bytes(replay.into_body(), 1024 * 1024).await?)?;
        ensure!(result == replay, "{suffix} replay changed receipt");
        let consumed: bool = sqlx::query_scalar(
            "SELECT consumed_at IS NOT NULL FROM iam.step_up_assertions WHERE id=$1",
        )
        .bind(assertion)
        .fetch_one(admin)
        .await?;
        ensure!(consumed, "step-up was not consumed");
    }
    Ok(())
}
async fn bundles_and_reconciliation(
    app: &axum::Router,
    admin: &sqlx::PgPool,
    credential: &str,
    actor: &str,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE iam.organizations SET trusted_org=true,allow_bundled_applications=true WHERE org_id='test_org'").execute(admin).await?;
    let id = Uuid::now_v7();
    let body = json!({"operation_id":id,"expected_iam_revision":0,"configuration_revision":1,"app_name":"Bundle","app_ids":["test_org>managed-app"]});
    let request = || -> anyhow::Result<Request<Body>> {
        Ok(Request::builder()
            .method("PUT")
            .uri("/api/v1/honeycomb/bundles/test_org%3Emanaged-bundle/configuration")
            .header("authorization", format!("Bearer {credential}"))
            .header("x-honeycomb-actor-token", actor)
            .header("idempotency-key", id.to_string())
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body)?))?)
    };
    let response = app.clone().oneshot(request()?).await?;
    let status = response.status();
    let response: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
    ensure!(
        status == StatusCode::OK,
        "bundle mutation failed: {response}"
    );
    ensure!(
        app.clone().oneshot(request()?).await?.status() == StatusCode::OK,
        "bundle replay failed"
    );
    for path in [
        "/api/v1/honeycomb/bundles/test_org%3Emanaged-bundle",
        "/api/v1/honeycomb/inventory?kind=applications",
        "/api/v1/honeycomb/inventory?kind=bundles",
        "/api/v1/honeycomb/inventory?kind=testing-environments",
        "/api/v1/honeycomb/scope-catalog?org_id=test_org",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("authorization", format!("Bearer {credential}"))
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "reconcile failed: {path}"
        );
    }
    let mut tx = admin.begin().await?;
    sqlx::query("SET LOCAL ROLE silicon_iam_worker")
        .execute(&mut *tx)
        .await?;
    let events: Vec<(Uuid, i32, sqlx::types::Json<Value>)> = sqlx::query_as(
        "SELECT * FROM iam_private.claim_honeycomb_management_events('test_org>app-alpha')",
    )
    .fetch_all(&mut *tx)
    .await?;
    ensure!(
        !events.is_empty(),
        "management notifications were not queued"
    );
    for (event, attempt, envelope) in &events {
        ensure!(
            envelope.0.get("event_id").is_some(),
            "missing stable event ID"
        );
        sqlx::query("SELECT iam_private.finish_honeycomb_management_event($1,$2,true)")
            .bind(event)
            .bind(attempt)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let event = events[0].0;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/honeycomb/events/{event}/replay"))
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == StatusCode::OK, "event replay failed");
    let pending: bool = sqlx::query_scalar(
        "SELECT delivered_at IS NULL FROM iam.honeycomb_management_events WHERE event_id=$1",
    )
    .bind(event)
    .fetch_one(admin)
    .await?;
    ensure!(pending, "replay did not queue the same event");
    Ok(())
}
