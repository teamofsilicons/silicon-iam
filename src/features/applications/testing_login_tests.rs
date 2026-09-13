//! The actor shortcut is confined to a verified testing database and creates
//! the same revocable Application session graph as ordinary IAM login.
use std::sync::Arc;

use anyhow::ensure;
use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres as PostgresImage;

use super::*;
use crate::{
    api::TestingPlane,
    config::{Settings, TestingSettings},
    infrastructure::{
        crypto::CryptoService,
        providers::NotificationProviders,
        testing_plane::{self, SelectedEnvironment},
    },
};

const APP: Uuid = Uuid::from_u128(0x11);
const ENVIRONMENT: Uuid = Uuid::from_u128(0x801);

#[tokio::test]
#[ignore = "requires Docker and development IAM settings with synthetic keyrings"]
async fn testing_login_accepts_actor_ids_and_issued_codes_without_production_fallback()
-> anyhow::Result<()> {
    let container = PostgresImage::default()
        .with_tag("16-alpine")
        .start()
        .await?;
    let url = format!(
        "postgres://postgres:postgres@{}:{}",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    let production = PgPoolOptions::new()
        .max_connections(3)
        .connect(&format!("{url}/postgres"))
        .await?;
    sqlx::raw_sql("CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN;").execute(&production).await?;
    crate::infrastructure::postgres::migrate(&production).await?;
    super::super::live_tests::seed_protocol_rows(&production).await?;
    sqlx::query("CREATE DATABASE testing")
        .execute(&production)
        .await?;
    let testing = PgPoolOptions::new()
        .max_connections(3)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('iam.testing_environment_id', $1, false)")
                    .bind(ENVIRONMENT.to_string())
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&format!("{url}/testing"))
        .await?;
    crate::infrastructure::postgres::migrate_testing(&testing).await?;
    super::super::live_tests::seed_protocol_rows(&testing).await?;
    sqlx::raw_sql(r"
        INSERT INTO iam.principals (id,kind,status,activated_at) VALUES ('00000000-0000-0000-0000-000000000003','carbon','active',transaction_timestamp());
        INSERT INTO iam.carbons (id,carbon_id,display_name) VALUES ('00000000-0000-0000-0000-000000000003','oac_test_admin','Prefix test actor');
        INSERT INTO iam.carbon_contacts (id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at)
        SELECT CASE WHEN kind='email' THEN '00000000-0000-0000-0000-000000000202'::uuid ELSE '00000000-0000-0000-0000-000000000203'::uuid END, '00000000-0000-0000-0000-000000000003'::uuid, kind, ciphertext, nonce, encryption_key_version, verified_at FROM iam.carbon_contacts WHERE carbon_id='00000000-0000-0000-0000-000000000001';
        INSERT INTO iam.principals (id,kind,status,activated_at) VALUES
            ('00000000-0000-0000-0000-000000000501','silicon','active',transaction_timestamp());
        INSERT INTO iam.organization_memberships (id,organization_id,principal_id,principal_kind,org_role)
        VALUES ('00000000-0000-0000-0000-000000000531','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000501','silicon','member');
        INSERT INTO iam.silicons (id,organization_id,membership_id,organization_handle,silicon_handle,display_name,provisioning_status)
        VALUES ('00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000531','test_org','worker','Worker','active');
        INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES ('00000000-0000-0000-0000-000000000011','self.identity.read') ON CONFLICT DO NOTHING;
        INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES ('00000000-0000-0000-0000-000000000011','self.identity.read','00000000-0000-0000-0000-000000000001') ON CONFLICT DO NOTHING;
    ").execute(&testing).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    for pool in [&production, &testing] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
            .execute(pool)
            .await?;
    }
    let restricted = |database: String| async move {
        PgPoolOptions::new()
            .max_connections(3)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET ROLE silicon_iam_api")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database)
            .await
    };
    let mut settings = Settings::from_env()?;
    settings.providers.allow_local_providers = true;
    let crypto = Arc::new(CryptoService::from_settings(&settings.security)?);
    let state = ApiState {
        pool: restricted(format!("{url}/postgres")).await?,
        testing: Some(TestingPlane {
            pool: restricted(format!("{url}/testing")).await?,
            settings: Arc::new(TestingSettings {
                database: settings.database.clone(),
                idle_days: 30,
                recovery_days: 30,
                max_per_organization: 25,
            }),
        }),
        crypto,
        notifications: NotificationProviders::from_settings(&settings.providers)?,
        workos: None,
        settings: Arc::new(settings),
    };
    ensure!(
        exchange(&state, "test_carbon", "production-actor-login")
            .await?
            .0
            == StatusCode::BAD_REQUEST
    );
    // Even a forged DB selection cannot turn the production stub into login.
    let mut tx = production.begin().await?;
    sqlx::query("SELECT set_config('iam.testing_environment_id', $1, true)")
        .bind(ENVIRONMENT.to_string())
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM iam_private.create_testing_actor_login($1,1,'test_carbon',$2,$3,1800)")
        .bind(APP).bind(Uuid::now_v7()).bind(Uuid::now_v7()).fetch_one(&mut *tx).await?;
    ensure!(count == 0);
    tx.rollback().await?;
    testing_plane::scope(
        SelectedEnvironment {
            id: ENVIRONMENT,
            organization_id: Uuid::from_u128(0x21),
        },
        async {
            for actor in ["test_carbon", "worker:test_org", "oac_test_admin"] {
                let key = format!("actor-login-{actor}");
                let (status, tokens) = exchange(&state, actor, &key).await?;
                ensure!(status == StatusCode::OK, "actor exchange failed: {tokens}");
                ensure!(tokens["actor"]["public_id"] == actor);
                ensure!(
                    tokens["access_token"]
                        .as_str()
                        .is_some_and(|v| v.starts_with("oat_"))
                );
                ensure!(
                    tokens["refresh_token"]
                        .as_str()
                        .is_some_and(|v| v.starts_with("ort_"))
                );
                ensure!(
                    exchange(&state, actor, &key).await?.1 == tokens,
                    "exact retry must recover tokens"
                );
                let (refresh_status, refreshed) = request_tokens(
                    &state,
                    AppTokenForm {
                        app_id: Some("test_org>app-alpha".to_owned()),
                        slt: None,
                        refresh_token: tokens["refresh_token"].as_str().map(str::to_owned),
                    },
                    &format!("refresh-actor-{actor}"),
                )
                .await?;
                ensure!(
                    refresh_status == StatusCode::OK,
                    "test refresh failed: {refreshed}"
                );
                ensure!(refreshed["actor"]["public_id"] == actor);
                ensure!(refreshed["refresh_token"] != tokens["refresh_token"]);
            }
            for (index, invalid) in [
                "unknown",
                "other:world",
                "oac_bad",
                "ort_bad",
                " test_carbon",
            ]
            .into_iter()
            .enumerate()
            {
                ensure!(
                    exchange(&state, invalid, &format!("invalid-login-{index:04}"))
                        .await?
                        .0
                        == StatusCode::BAD_REQUEST
                );
            }
            // Mint a real one-time code through the existing IAM path and exchange it.
            let mut tx =
                context::begin(state.db(), DatabaseContext::principal(Uuid::from_u128(1))).await?;
            let scopes = vec!["self.identity.read".to_owned()];
            let (_, code) = mint_short_lived_token(
                &mut tx,
                &state,
                MintSubject {
                    application_id: APP,
                    session_id: Uuid::from_u128(0x41),
                    principal_id: Uuid::from_u128(1),
                    subject_kind: "carbon",
                    organization_id: None,
                    membership_id: None,
                    redirect_uri: None,
                    selected_membership_ids: &[Uuid::from_u128(0x31)],
                },
                &scopes,
            )
            .await
            .map_err(api_error)?;
            tx.commit().await?;
            let (status, tokens) =
                exchange(&state, code.expose_secret(), "real-slt-exchange-0001").await?;
            ensure!(
                status == StatusCode::OK,
                "issued-code exchange failed: {tokens}"
            );
            ensure!(
                exchange(&state, code.expose_secret(), "real-slt-exchange-0001")
                    .await?
                    .1
                    == tokens
            );
            ensure!(
                exchange(&state, code.expose_secret(), "spent-slt-exchange-0002")
                    .await?
                    .0
                    == StatusCode::BAD_REQUEST
            );
            sqlx::query("UPDATE iam.principals SET status = 'suspended', suspended_at = transaction_timestamp() WHERE id = $1")
                .bind(Uuid::from_u128(1)).execute(&testing).await?;
            ensure!(exchange(&state, "test_carbon", "suspended-actor-login").await?.0 == StatusCode::BAD_REQUEST);
            anyhow::Ok(())
        },
    )
    .await?;
    testing_plane::scope(
        SelectedEnvironment {
            id: Uuid::from_u128(0x802),
            organization_id: Uuid::from_u128(0x21),
        },
        async {
            ensure!(
                exchange(&state, "test_carbon", "other-environment-login")
                    .await?
                    .0
                    == StatusCode::BAD_REQUEST
            );
            anyhow::Ok(())
        },
    )
    .await?;
    Ok(())
}

fn api_error(error: ApiError) -> anyhow::Error {
    anyhow::anyhow!("IAM refused test setup: {}", error.into_response().status())
}

async fn exchange(state: &ApiState, slt: &str, key: &str) -> anyhow::Result<(StatusCode, Value)> {
    request_tokens(
        state,
        AppTokenForm {
            app_id: Some("test_org>app-alpha".to_owned()),
            slt: Some(slt.to_owned()),
            refresh_token: None,
        },
        key,
    )
    .await
}

async fn request_tokens(
    state: &ApiState,
    input: AppTokenForm,
    key: &str,
) -> anyhow::Result<(StatusCode, Value)> {
    let mut headers = HeaderMap::new();
    headers.insert("idempotency-key", key.parse()?);
    let client = ApplicationClient {
        application_id: APP,
        app_id: "test_org>app-alpha".to_owned(),
        organization_id: Uuid::from_u128(0x21),
        auth_epoch: 1,
        authenticated_secret: SecretString::from("synthetic-secret".to_owned()),
    };
    let response = app_tokens(State(state.clone()), client, headers, Form(input))
        .await
        .unwrap_or_else(IntoResponse::into_response);
    let status = response.status();
    let body = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&body).unwrap_or(json!({}))))
}
