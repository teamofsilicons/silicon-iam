//! Live checks for the two distinct migration ledgers accepted by readiness.

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr as _;

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL"]
async fn testing_readiness_requires_the_base_and_overlay_ledgers() -> anyhow::Result<()> {
    let database = crate::test_database::TestDatabase::start().await?;
    let pool = database.pool.clone();
    super::migrate(&pool).await?;
    assert!(super::ready(&pool).await);
    assert!(!super::ready_testing(&pool).await);

    // A testing plane is independently migrated; overlays precede canonical keys.
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let pool = testing_database.pool.clone();
    super::migrate_testing(&pool).await?;
    assert!(!super::ready(&pool).await);

    // Migrations need the administrator, but runtime readiness deliberately
    // rejects that login. Exercise the positive check as a restricted API user.
    sqlx::raw_sql("DO $$ BEGIN CREATE ROLE silicon_iam_api NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; EXCEPTION WHEN duplicate_object THEN NULL; END $$; DO $$ BEGIN CREATE ROLE readiness_test_api LOGIN PASSWORD 'readiness-test-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS IN ROLE silicon_iam_api; EXCEPTION WHEN duplicate_object THEN NULL; END $$; GRANT SELECT ON public._sqlx_migrations TO silicon_iam_api;").execute(&pool).await?;
    let runtime_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            PgConnectOptions::from_str(&testing_database.url)?
                .username("readiness_test_api")
                .password("readiness-test-password"),
        )
        .await?;
    assert!(super::ready_testing(&runtime_pool).await);
    Ok(())
}
