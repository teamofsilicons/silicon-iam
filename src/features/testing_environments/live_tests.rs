//! Disposable PostgreSQL coverage of cross-organization delegation and app test layers.

use sqlx::postgres::PgPoolOptions;
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;

#[tokio::test]
#[ignore = "requires Docker; creates isolated production and testing databases"]
async fn application_obo_and_testing_layer_security() -> anyhow::Result<()> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(5432).await?;
    let base_url = format!("postgres://postgres:postgres@{host}:{port}");
    let production = PgPoolOptions::new()
        .max_connections(3)
        .connect(&format!("{base_url}/postgres"))
        .await?;
    sqlx::raw_sql("CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN;")
        .execute(&production).await?;
    crate::infrastructure::postgres::migrate(&production).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
        .execute(&production)
        .await?;
    sqlx::raw_sql(include_str!("../../../tests/sql/application_obo_v1.sql"))
        .execute(&production)
        .await?;
    sqlx::raw_sql(include_str!("../../../tests/sql/contract_lifecycle.sql"))
        .execute(&production)
        .await?;
    sqlx::query("CREATE DATABASE testing")
        .execute(&production)
        .await?;
    let testing = PgPoolOptions::new()
        .max_connections(3)
        .connect(&format!("{base_url}/testing"))
        .await?;
    crate::infrastructure::postgres::migrate_testing(&testing).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
        .execute(&testing)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/application_testing_layer.sql"
    ))
    .execute(&testing)
    .await?;
    production.close().await;
    testing.close().await;
    Ok(())
}
