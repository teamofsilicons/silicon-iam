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
    assert_shared_contract_catalog(&testing).await?;

    // Production already applied the historical overlay. Preserve its exact
    // checksums and prove that newly introduced tables are scoped on upgrade.
    sqlx::query("CREATE DATABASE testing_upgrade")
        .execute(&production)
        .await?;
    let upgrade = PgPoolOptions::new()
        .max_connections(3)
        .connect(&format!("{base_url}/testing_upgrade"))
        .await?;
    let historical_base = sqlx::migrate::Migrator::with_migrations(
        sqlx::migrate!("./migrations")
            .iter()
            .filter(|migration| migration.version <= 76)
            .cloned()
            .collect(),
    );
    historical_base.run(&upgrade).await?;
    let mut historical_overlay = sqlx::migrate::Migrator::with_migrations(
        sqlx::migrate!("./migrations/testing")
            .iter()
            .filter(|migration| migration.version <= 9003)
            .cloned()
            .collect(),
    );
    historical_overlay
        .set_ignore_missing(true)
        .run(&upgrade)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/application_v1_upgrade_seed.sql"
    ))
    .execute(&upgrade)
    .await?;
    crate::infrastructure::postgres::migrate_testing(&upgrade).await?;
    assert_legacy_upgrade(&upgrade).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(&upgrade)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/application_testing_layer.sql"
    ))
    .execute(&upgrade)
    .await?;
    assert_shared_contract_catalog(&upgrade).await?;
    upgrade.close().await;
    check_production_upgrade(&production, &base_url).await?;
    production.close().await;
    testing.close().await;
    Ok(())
}

async fn check_production_upgrade(admin: &sqlx::PgPool, base_url: &str) -> anyhow::Result<()> {
    sqlx::query("CREATE DATABASE production_upgrade")
        .execute(admin)
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&format!("{base_url}/production_upgrade"))
        .await?;
    let base = sqlx::migrate::Migrator::with_migrations(
        sqlx::migrate!("./migrations")
            .iter()
            .filter(|migration| migration.version <= 76)
            .cloned()
            .collect(),
    );
    base.run(&pool).await?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/application_v1_upgrade_seed.sql"
    ))
    .execute(&pool)
    .await?;
    crate::infrastructure::postgres::migrate(&pool).await?;
    assert_legacy_upgrade(&pool).await?;
    pool.close().await;
    Ok(())
}

async fn assert_legacy_upgrade(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/application_v1_upgrade_assert.sql"
    ))
    .execute(pool)
    .await?;
    // Once explicit v1 declarations exist, the cutover must leave every
    // aggregate version and grant untouched if accidentally invoked again.
    sqlx::raw_sql(include_str!(
        "../../../migrations/0082_legacy_application_v1_reconsent.sql"
    ))
    .execute(pool)
    .await?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/application_v1_upgrade_assert.sql"
    ))
    .execute(pool)
    .await?;
    Ok(())
}

async fn assert_shared_contract_catalog(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut *transaction)
        .await?;
    for environment_id in [uuid::Uuid::now_v7(), uuid::Uuid::now_v7()] {
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(environment_id.to_string())
            .execute(&mut *transaction)
            .await?;
        let status =
            sqlx::query_scalar::<_, String>("SELECT iam_private.record_contract_request('v1')")
                .fetch_one(&mut *transaction)
                .await?;
        anyhow::ensure!(
            status == "current",
            "contract catalogue was environment-scoped"
        );
        let can_read_table = sqlx::query_scalar::<_, bool>(
            "SELECT has_table_privilege(current_user,'iam_private.contract_versions','SELECT')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        anyhow::ensure!(
            !can_read_table,
            "runtime received direct private catalogue access"
        );
    }
    transaction.rollback().await?;
    Ok(())
}
