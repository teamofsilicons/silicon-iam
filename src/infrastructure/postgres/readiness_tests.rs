//! Live checks for the two distinct migration ledgers accepted by readiness.

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;

#[tokio::test]
#[ignore = "requires a local Docker daemon"]
async fn testing_readiness_requires_the_base_and_overlay_ledgers() -> anyhow::Result<()> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(5432).await?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&format!(
            "postgres://postgres:postgres@{host}:{port}/postgres"
        ))
        .await?;

    super::migrate(&pool).await?;
    assert!(super::ready(&pool).await);
    assert!(!super::ready_testing(&pool).await);

    super::migrate_testing(&pool).await?;
    assert!(!super::ready(&pool).await);

    // Migrations need the administrator, but runtime readiness deliberately
    // rejects that login. Exercise the positive check as a restricted API user.
    sqlx::raw_sql(
        "CREATE ROLE silicon_iam_api NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
           NOREPLICATION NOBYPASSRLS; \
         CREATE ROLE readiness_test_api LOGIN PASSWORD 'readiness-test-password' \
           NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS \
           IN ROLE silicon_iam_api; \
         GRANT SELECT ON public._sqlx_migrations TO silicon_iam_api;",
    )
    .execute(&pool)
    .await?;
    let runtime_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::new()
                .host(&host.to_string())
                .port(port)
                .database("postgres")
                .username("readiness_test_api")
                .password("readiness-test-password"),
        )
        .await?;
    assert!(super::ready_testing(&runtime_pool).await);
    Ok(())
}
