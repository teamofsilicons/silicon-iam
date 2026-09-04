//! Live checks for the two distinct migration ledgers accepted by readiness.

use sqlx::postgres::PgPoolOptions;
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
    assert!(super::ready_testing(&pool).await);
    Ok(())
}
