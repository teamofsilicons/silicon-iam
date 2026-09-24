#![allow(clippy::too_many_lines)]

use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, ensure};
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{FromRequestParts as _, State},
    http::{Request, StatusCode},
    response::IntoResponse as _,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt as _;

use super::{ApplicationClient, IssueRequest, VerifyRequest};
use crate::{
    api::ApiState,
    config::Settings,
    domain::id::Id,
    infrastructure::{
        crypto::{CryptoService, DigestPurpose, SecretKind},
        postgres::{
            self,
            context::{self, DatabaseContext},
        },
        providers::NotificationProviders,
    },
};

const APP_A: &str = "app-alpha";
const APP_B: &str = "app-beta";

#[test]
fn key_requests_require_integer_lifetimes_and_redact_invalid_results() -> anyhow::Result<()> {
    ensure!(serde_json::from_value::<IssueRequest>(json!({}))?.ttl_seconds == 300);
    for value in [
        Value::Null,
        json!("60"),
        json!(60.5),
        json!(true),
        json!(2_147_483_648_i64),
    ] {
        ensure!(serde_json::from_value::<IssueRequest>(json!({"ttl_seconds":value})).is_err());
    }
    ensure!(
        serde_json::to_value(super::Verification {
            valid_key: false,
            key: None
        })? == json!({"valid_key":false})
    );
    for key in ["", "aak_", "oat_secret", "aak_🌈"] {
        ensure!(!super::key_format_is_valid(key));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or local PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL"]
async fn application_access_keys_enforce_identity_lifetime_rotation_and_atomic_revocation()
-> anyhow::Result<()> {
    let database = crate::test_database::TestDatabase::start().await?;
    postgres::migrate(&database.pool).await?;
    super::super::live_tests::seed_protocol_rows(&database.pool).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.as_str()))
        .execute(&database.pool)
        .await?;
    let state = state(&database.url).await?;
    let a = credentials(&database.pool, &state, APP_A).await?;
    let b = credentials(&database.pool, &state, APP_B).await?;
    let first = issue(&state, APP_A, &a, json!({})).await?;
    ensure!(
        first["app_id"] == APP_A
            && first["app_access_key"]
                .as_str()
                .is_some_and(super::key_format_is_valid)
    );
    let key = first["app_access_key"].as_str().context("issued key")?;
    let row = sqlx::query_as::<_,(i64,Vec<u8>,String)>("SELECT extract(epoch FROM expires_at-issued_at)::bigint,key_digest,application_id FROM iam.application_access_keys")
        .fetch_one(&database.pool).await?;
    ensure!(row.0 == 300 && row.1.len() == 32 && row.2 == APP_A);
    ensure!(row.1 != key.as_bytes(), "only a keyed digest is stored");
    let (status, result) = request(
        &state,
        "verify",
        Some((APP_B, &b)),
        json!({"app_id":APP_A,"app_access_key":key}),
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && result == json!({"valid_key":true,"app_id":APP_A,"valid_till":first["valid_till"]}),
        "{result}"
    );
    for body in [
        json!({"app_id":APP_B,"app_access_key":key}),
        json!({"app_id":"","app_access_key":key}),
        json!({"app_id":APP_A,"app_access_key":""}),
        json!({"app_id":APP_A,"app_access_key":format!("aak_{}","x".repeat(43))}),
    ] {
        ensure!(
            request(&state, "verify", Some((APP_B, &b)), body).await?.1
                == json!({"valid_key":false})
        );
    }
    for path in ["keys", "verify"] {
        let body = if path == "keys" {
            json!({})
        } else {
            json!({"app_id":APP_A,"app_access_key":key})
        };
        ensure!(request(&state, path, None, body.clone()).await?.0 == StatusCode::UNAUTHORIZED);
        ensure!(
            request(&state, path, Some((APP_B, "invalid")), body)
                .await?
                .0
                == StatusCode::UNAUTHORIZED
        );
    }
    for ttl in [59, 3601, -1, 0] {
        ensure!(
            request(
                &state,
                "keys",
                Some((APP_A, &a)),
                json!({"ttl_seconds":ttl})
            )
            .await?
            .0 == StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    for ttl in [60, 3600] {
        let issued = issue(&state, APP_A, &a, json!({"ttl_seconds":ttl})).await?;
        ensure!(issued["app_access_key"] != first["app_access_key"]);
    }
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam.application_access_keys WHERE revoked_at IS NULL"
        )
        .fetch_one(&database.pool)
        .await?
            == 3
    );
    ensure!(verify(&state, &b, APP_A, key).await?);
    // The capability does not become a user bearer or OAuth introspection token.
    let response = super::super::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/applications")
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == StatusCode::UNAUTHORIZED);
    ensure!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT has_table_privilege('silicon_iam_api','iam.application_access_keys','SELECT')"
        )
        .fetch_one(&database.pool)
        .await?
    );
    sqlx::query("UPDATE iam.applications SET visibility='private' WHERE id=$1")
        .bind(APP_A)
        .execute(&database.pool)
        .await?;
    ensure!(
        verify(&state, &b, APP_A, key).await?,
        "private application identity does not need user consent"
    );
    // Expired and explicitly revoked keys both redact identity details.
    sqlx::query("UPDATE iam.application_access_keys SET issued_at=clock_timestamp()-interval '6 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE application_id=$1").bind(APP_A).execute(&database.pool).await?;
    ensure!(!verify(&state, &b, APP_A, key).await?);
    let active = issue(&state, APP_A, &a, json!({})).await?;
    let active_key = active["app_access_key"].as_str().context("active key")?;
    let old_client = authenticate(&state, APP_A, &a).await?;
    sqlx::query("UPDATE iam.application_secrets SET status='retired',retired_at=clock_timestamp() WHERE application_id=$1 AND status='active'").bind(APP_A).execute(&database.pool).await?;
    ensure!(!verify(&state, &b, APP_A, active_key).await?);
    let rejected = super::issue(
        State(state.clone()),
        old_client,
        Json(IssueRequest { ttl_seconds: 300 }),
    )
    .await;
    ensure!(
        rejected.is_err_and(|error| error.into_response().status() == StatusCode::UNAUTHORIZED),
        "rotation wins after credential extraction"
    );
    let a = credentials(&database.pool, &state, APP_A).await?;
    let active = issue(&state, APP_A, &a, json!({})).await?;
    let active_key = active["app_access_key"].as_str().context("new key")?;
    for query in [
        "UPDATE iam.applications SET review_status='suspended' WHERE id=$1",
        "UPDATE iam.applications SET review_status='verified' WHERE id=$1",
    ] {
        sqlx::query(query)
            .bind(APP_A)
            .execute(&database.pool)
            .await?;
    }
    ensure!(
        !verify(&state, &b, APP_A, active_key).await?,
        "restore cannot revive disabled keys"
    );
    let active = issue(&state, APP_A, &a, json!({})).await?;
    let active_key = active["app_access_key"].as_str().context("principal key")?;
    sqlx::query(
        "UPDATE iam.principals SET status='suspended',suspended_at=clock_timestamp() WHERE id=$1",
    )
    .bind(APP_A)
    .execute(&database.pool)
    .await?;
    sqlx::query("UPDATE iam.principals SET status='active',suspended_at=NULL WHERE id=$1")
        .bind(APP_A)
        .execute(&database.pool)
        .await?;
    ensure!(
        !verify(&state, &b, APP_A, active_key).await?,
        "principal restoration cannot revive keys"
    );
    authentication_lock_order(&database.pool, &state, &a).await?;
    retention(&database.pool, &state, &a, &b).await?;
    atomic_revocation(&database.pool, &state, &a, &b).await?;
    expired_while_locked(&database.pool, &state, &a, &b).await?;
    let receiver = authenticate(&state, APP_B, &b).await?;
    sqlx::query("UPDATE iam.application_secrets SET status='retired',retired_at=clock_timestamp() WHERE application_id=$1 AND status='active'").bind(APP_B).execute(&database.pool).await?;
    let rejected = super::verify(
        State(state.clone()),
        receiver,
        Json(VerifyRequest {
            app_id: APP_A.into(),
            app_access_key: SecretString::from(key.to_owned()),
        }),
    )
    .await;
    ensure!(
        rejected.is_err_and(|error| error.into_response().status() == StatusCode::UNAUTHORIZED),
        "receiver rotation wins after extraction"
    );
    Ok(())
}

async fn state(url: &str) -> anyhow::Result<ApiState> {
    let settings = Settings::from_env()?;
    Ok(ApiState {
        pool: PgPoolOptions::new()
            .max_connections(4)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET ROLE silicon_iam_api")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(url)
            .await?,
        testing: None,
        crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
        notifications: NotificationProviders::from_settings(&settings.providers)?,
        workos: None,
        settings: Arc::new(settings),
    })
}

async fn credentials(pool: &PgPool, state: &ApiState, app: &str) -> anyhow::Result<String> {
    let secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)?;
    let digest = state
        .crypto
        .digest_secret(DigestPurpose::ApplicationSecret, &secret)?;
    sqlx::query("UPDATE iam.application_secrets AS secret SET status='retired',retired_at=clock_timestamp() WHERE application_id=$1 AND status IN('active','retiring') AND (to_jsonb(secret)->>'testing_environment_id') IS NOT DISTINCT FROM NULLIF(current_setting('iam.testing_environment_id',true),'')").bind(app).execute(pool).await?;
    sqlx::query("INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id) SELECT $1,$2,COALESCE(max(secret_version),0)+1,'ask_testing0',$3,$4,'c:test_carbon' FROM iam.application_secrets secret WHERE application_id=$2 AND (to_jsonb(secret)->>'testing_environment_id') IS NOT DISTINCT FROM NULLIF(current_setting('iam.testing_environment_id',true),'')")
        .bind(Id::now_v7()).bind(app).bind(digest.as_bytes().as_slice()).bind(digest.key_version()).execute(pool).await?;
    Ok(secret.expose_secret().to_owned())
}

async fn request(
    state: &ApiState,
    operation: &str,
    client: Option<(&str, &str)>,
    body: Value,
) -> anyhow::Result<(StatusCode, Value)> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/app-verification/{operation}"))
        .header("content-type", "application/json");
    if let Some((app, secret)) = client {
        builder = builder.header(
            "authorization",
            format!("Basic {}", STANDARD.encode(format!("{app}:{secret}"))),
        );
    }
    let response = super::super::router()
        .with_state(state.clone())
        .oneshot(builder.body(Body::from(body.to_string()))?)
        .await?;
    let status = response.status();
    if status == StatusCode::OK {
        ensure!(
            response.headers()["cache-control"] == "no-store"
                && response.headers()["pragma"] == "no-cache"
        );
    }
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)}));
    Ok((status, body))
}

async fn issue(state: &ApiState, app: &str, secret: &str, body: Value) -> anyhow::Result<Value> {
    let (status, body) = request(state, "keys", Some((app, secret)), body).await?;
    ensure!(status == StatusCode::OK, "issuance failed: {status} {body}");
    Ok(body)
}
async fn verify(state: &ApiState, receiver: &str, app: &str, key: &str) -> anyhow::Result<bool> {
    let (status, body) = request(
        state,
        "verify",
        Some((APP_B, receiver)),
        json!({"app_id":app,"app_access_key":key}),
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "verification failed: {status} {body}"
    );
    if body["valid_key"] == false {
        ensure!(body == json!({"valid_key":false}));
    }
    Ok(body["valid_key"] == true)
}
async fn authenticate(
    state: &ApiState,
    app: &str,
    secret: &str,
) -> anyhow::Result<ApplicationClient> {
    let (mut parts, ()) = Request::builder()
        .uri("/api/v1/app-verification/keys")
        .header(
            "authorization",
            format!("Basic {}", STANDARD.encode(format!("{app}:{secret}"))),
        )
        .body(())?
        .into_parts();
    ApplicationClient::from_request_parts(&mut parts, state)
        .await
        .map_err(|_| anyhow::anyhow!("fixture client rejected"))
}

async fn atomic_revocation(
    pool: &PgPool,
    state: &ApiState,
    a: &str,
    b: &str,
) -> anyhow::Result<()> {
    let issued = issue(state, APP_A, a, json!({})).await?;
    let key = issued["app_access_key"]
        .as_str()
        .context("atomic key")?
        .to_owned();
    let receiver = authenticate(state, APP_B, b).await?;
    let mut disabling = pool.begin().await?;
    sqlx::query("UPDATE iam.applications SET review_status='suspended' WHERE id=$1")
        .bind(APP_A)
        .execute(&mut *disabling)
        .await?;
    let state = state.clone();
    let task = tokio::spawn(async move {
        super::verify(
            State(state),
            receiver,
            Json(VerifyRequest {
                app_id: APP_A.into(),
                app_access_key: SecretString::from(key),
            }),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    ensure!(
        !task.is_finished(),
        "verification must wait for issuer authority"
    );
    disabling.commit().await?;
    let response = task
        .await?
        .map_err(|_| anyhow::anyhow!("verification failed after revoke"))?;
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1024).await?)?;
    ensure!(body == json!({"valid_key":false}));
    sqlx::query("UPDATE iam.applications SET review_status='verified' WHERE id=$1")
        .bind(APP_A)
        .execute(pool)
        .await?;
    Ok(())
}

async fn expired_while_locked(
    pool: &PgPool,
    state: &ApiState,
    a: &str,
    b: &str,
) -> anyhow::Result<()> {
    let issued = issue(state, APP_A, a, json!({})).await?;
    let key = issued["app_access_key"]
        .as_str()
        .context("expiry key")?
        .to_owned();
    let digest = state.crypto.digest_secret(
        DigestPurpose::ApplicationAccessKey,
        &SecretString::from(key.clone()),
    )?;
    sqlx::query("UPDATE iam.application_access_keys SET issued_at=clock_timestamp()-interval '59 seconds',expires_at=clock_timestamp()+interval '1 second' WHERE key_digest=$1")
        .bind(digest.as_bytes().as_slice()).execute(pool).await?;
    let receiver = authenticate(state, APP_B, b).await?;
    let mut blocker = pool.begin().await?;
    sqlx::query("SELECT id FROM iam.application_access_keys WHERE key_digest=$1 FOR UPDATE")
        .bind(digest.as_bytes().as_slice())
        .fetch_one(&mut *blocker)
        .await?;
    let state = state.clone();
    let task = tokio::spawn(async move {
        super::verify(
            State(state),
            receiver,
            Json(VerifyRequest {
                app_id: APP_A.into(),
                app_access_key: SecretString::from(key),
            }),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1200)).await;
    ensure!(!task.is_finished(), "verification must lock its stored key");
    blocker.commit().await?;
    let response = task
        .await?
        .map_err(|_| anyhow::anyhow!("expiry verification failed"))?;
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1024).await?)?;
    ensure!(
        body == json!({"valid_key":false}),
        "key must expire across a lock wait"
    );
    Ok(())
}

async fn retention(pool: &PgPool, state: &ApiState, a: &str, b: &str) -> anyhow::Result<()> {
    let issued = issue(state, APP_A, a, json!({})).await?;
    let key = issued["app_access_key"].as_str().context("retained key")?;
    sqlx::query("UPDATE iam.application_access_keys SET issued_at=clock_timestamp()-interval '92 days',expires_at=clock_timestamp()-interval '92 days'+interval '5 minutes' WHERE revoked_at IS NOT NULL").execute(pool).await?;
    let old=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM iam.application_access_keys WHERE expires_at<clock_timestamp()-interval '90 days'").fetch_one(pool).await?;
    ensure!(old > 0);
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE silicon_iam_worker")
        .execute(&mut *tx)
        .await?;
    let removed=sqlx::query_as::<_,(String,i64)>("SELECT * FROM iam_private.run_worker_retention_maintenance('application_access_keys',365,30,90,365,45,2555,1000)").fetch_one(&mut *tx).await?;
    tx.commit().await?;
    ensure!(removed == ("application_access_keys".into(), old));
    ensure!(
        verify(state, b, APP_A, key).await?,
        "retention must preserve live keys"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or local PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL"]
async fn application_access_keys_preserve_testing_environment_and_generation() -> anyhow::Result<()>
{
    use crate::infrastructure::testing_plane::{self, SelectedEnvironment};
    let database = crate::test_database::TestDatabase::start().await?;
    postgres::migrate_testing(&database.pool).await?;
    let selected = SelectedEnvironment {
        id: Id::from_u128(0x900),
        organization_id: Id::from_u128(0x21),
    };
    let admin = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                    .bind(selected.id.to_string())
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&database.url)
        .await?;
    super::super::live_tests::seed_protocol_rows(&admin).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.as_str()))
        .execute(&admin)
        .await?;
    sqlx::query("SELECT iam_private.set_testing_runtime_state($1,1,1,true)")
        .bind(selected.id)
        .execute(&admin)
        .await?;
    let state = state(&database.url).await?;
    let (a, b, key) = testing_plane::scope_runtime(selected, Some((1, 1)), async {
        let a = credentials(&admin, &state, APP_A).await?;
        let b = credentials(&admin, &state, APP_B).await?;
        let issued = issue(&state, APP_A, &a, json!({})).await?;
        let key = issued["app_access_key"]
            .as_str()
            .context("testing key")?
            .to_owned();
        ensure!(verify(&state, &b, APP_A, &key).await?);
        anyhow::Ok((a, b, key))
    })
    .await?;
    let stored = sqlx::query_as::<_, (Id, i64, Vec<u8>)>(
        "SELECT environment_id,testing_generation,key_digest FROM iam.application_access_keys",
    )
    .fetch_one(&admin)
    .await?;
    ensure!(stored.0 == selected.id && stored.1 == 1);
    let production_digest = state.crypto.digest_secret(
        DigestPurpose::ApplicationAccessKey,
        &SecretString::from(key.clone()),
    )?;
    ensure!(
        production_digest.as_bytes().as_slice() != stored.2,
        "testing key digest cannot resolve in production"
    );
    let other_selected = SelectedEnvironment {
        id: Id::from_u128(0x901),
        organization_id: Id::from_u128(0x902),
    };
    let other_admin =
        clone_environment_identity(&admin, &database.url, &selected, &other_selected).await?;
    testing_plane::scope_runtime(other_selected, Some((1, 1)), async {
        let other = state.crypto.digest_secret(
            DigestPurpose::ApplicationAccessKey,
            &SecretString::from(key.clone()),
        )?;
        ensure!(
            other.as_bytes().as_slice() != stored.2,
            "testing environment domains must differ"
        );
        let other_a = credentials(&other_admin, &state, APP_A).await?;
        let other_b = credentials(&other_admin, &state, APP_B).await?;
        let issued = issue(&state, APP_A, &other_a, json!({})).await?;
        ensure!(
            verify(
                &state,
                &other_b,
                APP_A,
                issued["app_access_key"]
                    .as_str()
                    .context("other environment key")?
            )
            .await?
        );
        ensure!(
            !verify(&state, &other_b, APP_A, &key).await?,
            "valid receiver with the same app identities cannot verify another environment's key"
        );
        anyhow::Ok(())
    })
    .await?;
    // Deliberately retain rows while advancing the generation: verification must
    // reject stale proofs even independently of the lifecycle erasure mechanism.
    sqlx::query("SELECT iam_private.set_testing_runtime_state($1,2,1,true)")
        .bind(selected.id)
        .execute(&admin)
        .await?;
    testing_plane::scope_runtime(selected, Some((2, 1)), async {
        ensure!(
            !verify(&state, &b, APP_A, &key).await?,
            "previous generation fails closed"
        );
        let issued = issue(&state, APP_A, &a, json!({})).await?;
        ensure!(
            verify(
                &state,
                &b,
                APP_A,
                issued["app_access_key"]
                    .as_str()
                    .context("generation2 key")?
            )
            .await?
        );
        anyhow::Ok(())
    })
    .await?;
    Box::pin(testing_plane::scope_runtime(
        selected,
        Some((1, 1)),
        async {
            ensure!(
                context::begin(
                    state.db(),
                    DatabaseContext::application(Id::fixture(APP_A), Id::fixture(APP_A))
                )
                .await
                .is_err(),
                "stale request generation cannot acquire runtime authority"
            );
            anyhow::Ok(())
        },
    ))
    .await?;
    let mut tx = admin.begin().await?;
    sqlx::query("SELECT iam_private.erase_testing_environment($1)")
        .bind(selected.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam.application_access_keys WHERE testing_environment_id=$1"
        )
        .bind(selected.id)
        .fetch_one(&admin)
        .await?
            == 0,
        "cleaning erases the new token table"
    );
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam.application_access_keys WHERE testing_environment_id=$1"
        )
        .bind(other_selected.id)
        .fetch_one(&admin)
        .await?
            > 0,
        "cleaning preserves keys in other environments"
    );
    Ok(())
}

async fn clone_environment_identity(
    admin: &PgPool,
    url: &str,
    source: &crate::infrastructure::testing_plane::SelectedEnvironment,
    destination: &crate::infrastructure::testing_plane::SelectedEnvironment,
) -> anyhow::Result<PgPool> {
    let mut tx = admin.begin().await?;
    sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true),set_config('fixture.source_environment',$2,true),set_config('fixture.destination_organization',$3,true)")
        .bind(destination.id.to_string()).bind(source.id.to_string()).bind(destination.organization_id.to_string()).execute(&mut *tx).await?;
    // Copy only the fixture's identity graph; both environments retain the same
    // canonical application IDs while surrogate contacts/organizations differ.
    sqlx::raw_sql(r"
        DO $fixture$
        DECLARE relation text; columns text; projection text; patch jsonb;
          source_env uuid:=current_setting('fixture.source_environment')::uuid;
          destination_env uuid:=current_setting('iam.testing_environment_id')::uuid;
          destination_org uuid:=current_setting('fixture.destination_organization')::uuid;
        BEGIN
          FOREACH relation IN ARRAY ARRAY['principals','carbons','carbon_contacts','organizations','organization_memberships','applications'] LOOP
            SELECT string_agg(quote_ident(attname),',' ORDER BY attnum),string_agg('copied.'||quote_ident(attname),',' ORDER BY attnum)
            INTO columns,projection FROM pg_attribute WHERE attrelid=('iam.'||relation)::regclass
            AND attnum>0 AND NOT attisdropped AND attgenerated='';
            patch:=jsonb_build_object('testing_environment_id',destination_env,'organization_id',destination_org);
            IF relation='organizations' THEN patch:=patch||jsonb_build_object('id',destination_org); END IF;
            EXECUTE format('INSERT INTO iam.%I(%s) SELECT %s FROM iam.%I original CROSS JOIN LATERAL jsonb_populate_record(NULL::iam.%I,replace(replace((to_jsonb(original)||$1||CASE WHEN $3=''carbon_contacts'' THEN jsonb_build_object(''id'',gen_random_uuid()) ELSE ''{}''::jsonb END)::text,''00000000-0000-0000-0000-000000000031'',''00000000-0000-0000-0000-000000000931''),''00000000-0000-0000-0000-000000000032'',''00000000-0000-0000-0000-000000000932'')::jsonb) copied WHERE original.testing_environment_id=$2',relation,columns,projection,relation,relation)
            USING patch,source_env,relation;
          END LOOP;
        END $fixture$;
    ").execute(&mut *tx).await?;
    sqlx::query("SELECT iam_private.set_testing_runtime_state($1,1,1,true)")
        .bind(destination.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let destination_id = destination.id;
    Ok(PgPoolOptions::new()
        .max_connections(3)
        .after_connect(move |connection, _| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                    .bind(destination_id.to_string())
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await?)
}

async fn authentication_lock_order(
    pool: &PgPool,
    state: &ApiState,
    secret: &str,
) -> anyhow::Result<()> {
    let client = authenticate(state, APP_A, secret).await?;
    let mut tx = super::application_transaction(state, &client)
        .await
        .map_err(|_| anyhow::anyhow!("fixture verification transaction"))?;
    let holder = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("SELECT iam_private.lock_current_application_client($1,$2)")
        .bind(client.application_id)
        .bind(client.auth_epoch)
        .execute(&mut *tx)
        .await?;
    let concurrent_state = state.clone();
    let concurrent_secret = secret.to_owned();
    let authentication =
        tokio::spawn(
            async move { authenticate(&concurrent_state, APP_A, &concurrent_secret).await },
        );
    // Observe the exact authentication request waiting for this transaction's
    // application lock before acquiring the verification credential lock.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)))")
                .bind(holder).fetch_one(pool).await? { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        anyhow::Ok(())
    }).await.context("concurrent authentication did not reach application lock")??;
    sqlx::query("SET LOCAL lock_timeout='500ms'")
        .execute(&mut *tx)
        .await?;
    let locked = super::lock_client(&mut tx, state, &client).await;
    ensure!(
        locked.is_ok(),
        "Basic authentication must not hold the secret while awaiting application authority"
    );
    tx.commit().await?;
    authentication.await??;
    Ok(())
}
