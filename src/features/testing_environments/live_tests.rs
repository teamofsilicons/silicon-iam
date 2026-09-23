//! Disposable PostgreSQL coverage of cross-organization delegation and app test layers.

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL or Docker"]
async fn application_obo_and_testing_layer_security() -> anyhow::Result<()> {
    let production_database = crate::test_database::TestDatabase::start().await?;
    let production = production_database.pool.clone();
    sqlx::raw_sql("DO $$ DECLARE role_name text; BEGIN
      FOREACH role_name IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator'] LOOP
        IF to_regrole(role_name) IS NULL THEN EXECUTE format('CREATE ROLE %I NOLOGIN',role_name); END IF;
      END LOOP;
    END $$;").execute(&production).await?;
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
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let testing = testing_database.pool.clone();
    crate::infrastructure::postgres::migrate_testing(&testing).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
        .execute(&testing)
        .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(canonical_testing_layer_fixture()))
        .execute(&testing)
        .await?;
    assert_shared_contract_catalog(&testing).await?;

    // Production already applied the historical overlay. Preserve its exact
    // checksums and prove that newly introduced tables are scoped on upgrade.
    let upgrade_database = crate::test_database::TestDatabase::start().await?;
    let upgrade = upgrade_database.pool.clone();
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
    sqlx::raw_sql(sqlx::AssertSqlSafe(canonical_testing_layer_fixture()))
        .execute(&upgrade)
        .await?;
    assert_shared_contract_catalog(&upgrade).await?;
    upgrade.close().await;
    check_production_upgrade().await?;
    production.close().await;
    testing.close().await;
    Ok(())
}

async fn check_production_upgrade() -> anyhow::Result<()> {
    let database = crate::test_database::TestDatabase::start().await?;
    let pool = database.pool.clone();
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
    for environment_id in [
        crate::domain::id::Id::now_v7(),
        crate::domain::id::Id::now_v7(),
    ] {
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

/// The shared SQL remains the historical pre-0111 fixture used by upgrade
/// tests. Current-schema callers substitute only the known identity keys;
/// endpoint, signing-key, secret and environment UUIDs remain unchanged.
pub(super) fn canonical_testing_layer_fixture() -> String {
    include_str!("../../../tests/sql/application_testing_layer.sql")
        .replace("alpha>test", "test")
        .replace("beta>test", "test-beta")
        .replace("00000000-0000-0000-0000-00000000b001", "test")
        .replace("00000000-0000-0000-0000-00000000b002", "test-beta")
        .replace("00000000-0000-0000-0000-000000000011", "app-alpha")
        .replace("00000000-0000-0000-0000-000000000012", "app-beta")
        .replace(
            "ARRAY['test','test-beta']::uuid[]",
            "ARRAY['test','test-beta']::text[]",
        )
        .replace("ARRAY['test-beta']::uuid[]", "ARRAY['test-beta']::text[]")
}
