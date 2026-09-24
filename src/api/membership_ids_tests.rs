//! Disposable-database migration and public transport regression checks.
#![allow(clippy::too_many_lines)]

use super::*;
use anyhow::{Context as _, ensure};
use axum::{Extension, Router, body::Body, middleware};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt as _;

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL plus synthetic IAM test settings"]
async fn migrates_existing_memberships_and_serves_complete_directory() -> anyhow::Result<()> {
    let database = crate::test_database::TestDatabase::start().await?;
    let pool = database.pool.clone();
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NULL THEN CREATE ROLE silicon_iam_api NOLOGIN; END IF; IF to_regrole('silicon_iam_worker') IS NULL THEN CREATE ROLE silicon_iam_worker NOLOGIN; END IF; IF to_regrole('silicon_iam_key_operator') IS NULL THEN CREATE ROLE silicon_iam_key_operator NOLOGIN; END IF; END $$;")
        .execute(&pool).await?;
    // Upgrade a populated old schema, rather than only testing a fresh install.
    let migrations = sqlx::migrate!("./migrations");
    let old_schema = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            migrations
                .iter()
                .filter(|migration| migration.version < 108)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    old_schema.run(&pool).await?;
    crate::features::applications::live_tests::seed_protocol_rows(&pool).await?;
    sqlx::raw_sql(include_str!(
        "../infrastructure/postgres/membership_planning_seed.sql"
    ))
    .execute(&pool)
    .await?;
    sqlx::query("UPDATE iam.organization_memberships SET status='removed',removed_at=now() WHERE id='00000000-0000-0000-0000-000000000032'")
        .execute(&pool).await?;
    migrations.run(&pool).await?;
    migrations.run(&pool).await?;
    let rows: Vec<(Id, String)> = sqlx::query_as("SELECT membership_key,membership_id FROM iam_private.membership_identifiers ORDER BY membership_id")
        .fetch_all(&pool).await?;
    ensure!(rows.len() == 3);
    ensure!(
        rows.iter().any(|(_, id)| id == "c:test_admin[test_org]"),
        "removed membership was not migrated"
    );
    ensure!(
        rows.iter()
            .any(|(_, id)| id == "si:planner_silicon[test_org]")
    );
    let key = Id::from_u128(0x31);
    let mut tx = pool.begin().await?;
    let mut body = json!({"membership_id": "c:test_carbon[test_org]", "extra_silicon_membership_ids": ["si:planner_silicon[test_org]"], "first_silicon_membership_id": null});
    decode(&mut tx, &mut body).await?;
    ensure!(body["membership_id"] == key.to_string());
    encode(&mut tx, &mut body).await?;
    ensure!(body["membership_id"] == "c:test_carbon[test_org]");
    ensure!(body["extra_silicon_membership_ids"][0] == "si:planner_silicon[test_org]");
    ensure!(
        decode(&mut tx, &mut json!({"membership_id": key}))
            .await
            .is_err()
    );
    sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-00000000a001',true)").execute(&mut *tx).await?;
    ensure!(
        resolve(&mut tx, &["c:test_carbon[test_org]".into()], &[key])
            .await?
            .is_empty()
    );
    tx.rollback().await?;
    sqlx::raw_sql(r"
        BEGIN;
        INSERT INTO iam.principals(id,kind,status,activated_at)
          SELECT 'c:extra_' || translate(n::text, '0', 'a'),'carbon','active',now() FROM generate_series(1,105) n;
        INSERT INTO iam.carbons(id,carbon_id,display_name)
          SELECT 'c:extra_' || translate(n::text, '0', 'a'),'c:extra_' || translate(n::text, '0', 'a'),'Extra Person ' || n FROM generate_series(1,105) n;
        INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at)
          SELECT md5('extra-contact-' || n || kind::text)::uuid,'c:extra_' || translate(n::text, '0', 'a'),kind,
            decode(repeat('02',17),'hex'),decode(repeat('12',12),'hex'),1,now()
          FROM generate_series(1,105) n CROSS JOIN (VALUES ('email'::iam.contact_kind),('phone'::iam.contact_kind)) channels(kind);
        INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role)
          SELECT md5('extra-membership-' || n)::uuid,'00000000-0000-0000-0000-000000000021',
            'c:extra_' || translate(n::text, '0', 'a'),'carbon','member' FROM generate_series(1,105) n;
        COMMIT;
    ").execute(&pool).await?;
    let grants = include_str!("../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(&pool)
        .await?;
    let runtime = PgPoolOptions::new()
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE silicon_iam_api")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&database.url)
        .await?;
    check_http(runtime).await?;

    // Fresh testing installs stamp each canonical ID with its isolated world.
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let world = Id::from_u128(0xa001);
    let testing = PgPoolOptions::new()
        .after_connect(move |connection, _| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                    .bind(world.to_string())
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&testing_database.url)
        .await?;
    crate::infrastructure::postgres::migrate_testing(&testing).await?;
    crate::features::applications::live_tests::seed_protocol_rows(&testing).await?;
    sqlx::raw_sql(include_str!(
        "../infrastructure/postgres/membership_planning_seed.sql"
    ))
    .execute(&testing)
    .await?;
    let mut tx = testing.begin().await?;
    ensure!(
        resolve(&mut tx, &["c:test_carbon[test_org]".into()], &[])
            .await?
            .len()
            == 1
    );
    sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-00000000a002',true)").execute(&mut *tx).await?;
    ensure!(
        resolve(&mut tx, &["c:test_carbon[test_org]".into()], &[key])
            .await?
            .is_empty()
    );
    tx.rollback().await?;
    Ok(())
}

async fn check_http(pool: PgPool) -> anyhow::Result<()> {
    use crate::{
        api::authentication::Authenticated,
        config::{RuntimeEnvironment, Settings},
        domain::actor::{ActorRef, ActorType},
        infrastructure::{
            crypto::CryptoService, postgres::tokens::AccessContext,
            providers::NotificationProviders,
        },
    };
    let settings = Settings::from_env()?;
    ensure!(settings.environment == RuntimeEnvironment::Test);
    let state = ApiState {
        pool,
        crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
        notifications: NotificationProviders::from_settings(&settings.providers)?,
        settings: Arc::new(settings),
        workos: None,
        testing: None,
    };
    let actor = Authenticated(AccessContext {
        token_id: Id::from_u128(0x101),
        authentication_session_id: Id::from_u128(0x41),
        subject: ActorRef {
            actor_type: ActorType::Carbon,
            id: Id::fixture("c:test_carbon"),
        },
        client_application_id: None,
        audience_application_id: None,
        audience: "silicon-iam".into(),
        organization_id: None,
        membership_id: None,
        scopes: vec!["iam.self".into()],
        assurance_level: 1,
    });
    let make_app = |actor| -> Router {
        crate::features::organizations::router()
            .layer(middleware::from_fn_with_state(state.clone(), transport))
            .layer(Extension(actor))
            .with_state(state.clone())
    };
    let app = make_app(actor.clone());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/test_org/directory/details")
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    ensure!(status.is_success(), "directory details: {status} {body}");
    ensure!(body.as_object().is_some_and(|value| value.len() == 107));
    ensure!(body["c:test_carbon"]["membership_id"] == "c:test_carbon[test_org]");
    ensure!(body["c:test_carbon"]["display_name"] == "Test Carbon");
    ensure!(body["c:extra_1a5"]["display_name"] == "Extra Person 105");
    ensure!(body["c:test_carbon"]["trust"].is_null());
    ensure!(body["si:planner_silicon"]["display_name"] == "Planner Silicon");
    ensure!(body["si:planner_silicon"]["trust"].is_object());
    for path in [
        "c:test_carbon%5Btest_org%5D",
        "si:planner_silicon%5Btest_org%5D",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/organizations/test_org/members/{path}"))
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(
            response.status().is_success(),
            "canonical member lookup failed: {}",
            response.status()
        );
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/test_org/members/00000000-0000-0000-0000-000000000031")
                .header(
                    header::USER_AGENT,
                    "silicon-iam-client/1.8.0 silicon-briefcase/0.5.0",
                )
                .body(Body::empty())?,
        )
        .await?;
    ensure!(
        response.status().is_success(),
        "legacy member lookup failed"
    );
    ensure!(response.headers()["silicon-iam-membership-format"] == "uuid-legacy");
    let legacy: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    ensure!(legacy["id"] == "00000000-0000-0000-0000-000000000031");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/test_org/members/00000000-0000-0000-0000-000000000031")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(
        response.status().is_client_error(),
        "modern requests must use canonical IDs"
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/test_org/members/test_carbon%5Bwrong_org%5D")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status().is_client_error());
    let mut application = actor;
    application.0.client_application_id = Some(Id::fixture("app-alpha"));
    application.0.audience_application_id = Some(Id::fixture("app-alpha"));
    application.0.audience = "app-alpha".into();
    application.0.scopes = vec!["directory.carbons.read".into()];
    let response = make_app(application.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/test_org/directory/details")
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    let limited: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await?)?;
    ensure!(status.is_success(), "scoped directory: {status} {limited}");
    ensure!(
        limited
            .as_object()
            .is_some_and(|members| members.len() == 106)
    );
    ensure!(limited.get("si:planner_silicon").is_none());
    for member in limited
        .as_object()
        .context("directory dictionary")?
        .values()
    {
        for private in [
            "display_name",
            "profile",
            "role",
            "org_role",
            "job_description",
            "tags",
            "trust",
            "capabilities",
            "default_trust",
        ] {
            ensure!(member.get(private).is_none(), "ungranted field {private}");
        }
    }
    application.0.scopes = vec!["self.profile.read".into()];
    let response = make_app(application)
        .oneshot(
            Request::builder()
                .uri("/api/v1/organizations/test_org/directory/details")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == http::StatusCode::FORBIDDEN);
    Ok(())
}
