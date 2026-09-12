//! Scope discovery must distinguish an empty public catalog from an invalid ID.

use anyhow::{Context as _, ensure};
use axum::{http::StatusCode, response::IntoResponse as _};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres as PostgresImage;

use super::scopes::catalog_items;

#[tokio::test]
#[ignore = "requires Docker; checks production and testing runtime permissions"]
async fn scope_catalog_validates_applications_without_disclosing_other_environments()
-> anyhow::Result<()> {
    let container = PostgresImage::default()
        .with_tag("16-alpine")
        .start()
        .await?;
    let base_url = format!(
        "postgres://postgres:postgres@{}:{}",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    let production = PgPoolOptions::new()
        .max_connections(3)
        .connect(&format!("{base_url}/postgres"))
        .await?;
    sqlx::raw_sql("CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN;")
        .execute(&production).await?;
    crate::infrastructure::postgres::migrate(&production).await?;
    seed_catalog(&production).await?;
    assert_catalog_choices(&production).await?;

    sqlx::query("CREATE DATABASE testing")
        .execute(&production)
        .await?;
    let testing = PgPoolOptions::new()
        .max_connections(3)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-000000000801',false)")
                    .execute(connection).await?;
                Ok(())
            })
        })
        .connect(&format!("{base_url}/testing"))
        .await?;
    crate::infrastructure::postgres::migrate_testing(&testing).await?;
    seed_catalog(&testing).await?;
    assert_catalog_choices(&testing).await?;
    let mut tx = testing.begin().await?;
    select_runtime_actor(&mut tx).await?;
    for environment in ["00000000-0000-0000-0000-000000000802", ""] {
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(environment)
            .execute(&mut *tx)
            .await?;
        assert_not_found(&mut tx, "test_org>app-beta").await?;
        let iam = catalog_items(&mut tx, None).await.map_err(catalog_error)?;
        ensure!(iam.len() == 25 && iam.iter().all(|scope| scope.app_id.is_none()));
    }
    tx.rollback().await?;
    assert_catalog_upgrade(&production, &base_url).await?;
    testing.close().await;
    production.close().await;
    Ok(())
}

async fn assert_catalog_upgrade(admin: &PgPool, base_url: &str) -> anyhow::Result<()> {
    let base = sqlx::migrate::Migrator::with_migrations(
        sqlx::migrate!("./migrations")
            .iter()
            .filter(|migration| migration.version <= 82)
            .cloned()
            .collect(),
    );
    for testing in [false, true] {
        let database = if testing {
            "testing_upgrade"
        } else {
            "production_upgrade"
        };
        // Both names are closed literals, never request input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(admin)
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    if testing {
                        sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-000000000801',false)")
                            .execute(connection).await?;
                    }
                    Ok(())
                })
            })
            .connect(&format!("{base_url}/{database}")).await?;
        base.run(&pool).await?;
        if testing {
            let mut overlay = sqlx::migrate!("./migrations/testing");
            overlay.set_ignore_missing(true).run(&pool).await?;
        }
        super::live_tests::seed_protocol_rows(&pool).await?;
        if testing {
            crate::infrastructure::postgres::migrate_testing(&pool).await?;
        } else {
            crate::infrastructure::postgres::migrate(&pool).await?;
        }
        seed_catalog_endpoints_and_grants(&pool).await?;
        assert_catalog_choices(&pool).await?;
        pool.close().await;
    }
    Ok(())
}

async fn seed_catalog(pool: &PgPool) -> anyhow::Result<()> {
    super::live_tests::seed_protocol_rows(pool).await?;
    seed_catalog_endpoints_and_grants(pool).await
}

async fn seed_catalog_endpoints_and_grants(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(
        r"
        INSERT INTO iam.application_obo_endpoints (
            organization_id, application_id, endpoint_id, path, critical, status, retired_at
        ) VALUES
          ('00000000-0000-0000-0000-000000000021',
           '00000000-0000-0000-0000-000000000012', 'files.delete', '/files/delete', true, 'active', NULL),
          ('00000000-0000-0000-0000-000000000021',
           '00000000-0000-0000-0000-000000000012', 'files.legacy', '/files/legacy', false, 'retired', transaction_timestamp());
        ",
    )
    .execute(pool)
    .await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(pool)
        .await
        .context("scope catalog restricted runtime grants")?;
    Ok(())
}

async fn assert_catalog_choices(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    select_runtime_actor(&mut tx).await?;
    let table_visible = sqlx::query_scalar::<_, bool>(
        "SELECT has_table_privilege(current_user,'iam.oauth_scope_catalog','SELECT')",
    )
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        !table_visible,
        "shared external scope history must remain private"
    );
    let iam = catalog_items(&mut tx, None).await.map_err(catalog_error)?;
    ensure!(iam.len() == 25 && iam.iter().all(|scope| scope.app_id.is_none()));
    let empty = catalog_items(&mut tx, Some("test_org>app-alpha"))
        .await
        .map_err(catalog_error)?;
    ensure!(
        empty.is_empty(),
        "valid empty catalog must remain a success"
    );
    assert_not_found(&mut tx, "test_org>missing-app").await?;
    let external = catalog_items(&mut tx, Some("test_org>app-beta"))
        .await
        .map_err(catalog_error)?;
    ensure!(
        external.len() == 2,
        "retired scopes must not be discoverable"
    );
    ensure!(
        external
            .iter()
            .all(|scope| scope.app_id.as_deref() == Some("test_org>app-beta"))
    );
    ensure!(external[0].scope == "obo:test_org>app-beta:files.delete" && external[0].critical);
    ensure!(external[1].scope == "obo:test_org>app-beta:trust.manage" && !external[1].critical);
    tx.rollback().await?;

    for state in ["under_review", "suspended", "deleted"] {
        let mut tx = pool.begin().await?;
        sqlx::query("UPDATE iam.applications SET review_status=$1, deleted_at=CASE WHEN $1='deleted' THEN transaction_timestamp() END WHERE app_id='test_org>app-beta'")
            .bind(state).execute(&mut *tx).await?;
        select_runtime_actor(&mut tx).await?;
        assert_not_found(&mut tx, "test_org>app-beta").await?;
        tx.rollback().await?;
    }
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE iam.principals SET status='suspended', suspended_at=transaction_timestamp() WHERE id='00000000-0000-0000-0000-000000000012'")
        .execute(&mut *tx).await?;
    select_runtime_actor(&mut tx).await?;
    assert_not_found(&mut tx, "test_org>app-beta").await?;
    tx.rollback().await?;
    Ok(())
}

async fn select_runtime_actor(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT set_config('iam.principal_id','00000000-0000-0000-0000-000000000001',true),set_config('iam.organization_id','',true)")
        .execute(&mut **tx).await?;
    Ok(())
}

async fn assert_not_found(tx: &mut Transaction<'_, Postgres>, app_id: &str) -> anyhow::Result<()> {
    let Err(error) = catalog_items(tx, Some(app_id)).await else {
        anyhow::bail!("unavailable application must not return a successful empty catalog");
    };
    ensure!(error.into_response().status() == StatusCode::NOT_FOUND);
    Ok(())
}

fn catalog_error(error: super::error::ApiError) -> anyhow::Error {
    anyhow::anyhow!("scope catalog failed: {}", error.into_response().status())
}
