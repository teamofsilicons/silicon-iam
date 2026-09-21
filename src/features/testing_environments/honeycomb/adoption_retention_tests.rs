//! Restricted-role integration checks for protected transfer and exact erasure.
use crate::domain::id::Id;
use crate::infrastructure::postgres;
use anyhow::ensure;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL or Docker"]
async fn adoption_preserves_identity_and_retention_erases_only_exact_apps() -> anyhow::Result<()> {
    let database = crate::test_database::TestDatabase::start().await?;
    let pool = database.pool.clone();
    sqlx::raw_sql("DO $$ DECLARE role_name text; BEGIN
      FOREACH role_name IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator'] LOOP
        IF to_regrole(role_name) IS NULL THEN EXECUTE format('CREATE ROLE %I NOLOGIN',role_name); END IF;
      END LOOP;
    END $$;").execute(&pool).await?;
    postgres::migrate(&pool).await?;
    let grants = include_str!("../../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
        .execute(&pool)
        .await?;
    crate::features::applications::live_tests::seed_protocol_rows(&pool).await?;
    let adoption = include_str!("../../../../tests/sql/honeycomb_adoption.sql")
        .replace("00000000-0000-0000-0000-000000000001", "test_carbon")
        .replace("00000000-0000-0000-0000-000000000011", "test_org>app-alpha")
        .replace("00000000-0000-0000-0000-00000000b001", "test_org>app-alpha");
    sqlx::raw_sql(sqlx::AssertSqlSafe(adoption))
        .execute(&pool)
        .await?;
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let test_pool = testing_database.pool.clone();
    postgres::migrate_testing(&test_pool).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
        .execute(&test_pool)
        .await?;
    let fixture =
        crate::features::testing_environments::live_tests::canonical_testing_layer_fixture();
    let setup = fixture
        .split("UPDATE iam.testing_application_imports")
        .next()
        .ok_or_else(|| anyhow::anyhow!("import fixture"))?;
    let mut connection = test_pool.acquire().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(setup.to_owned()))
        .execute(&mut *connection)
        .await?;
    let import_json = fixture
        .split("import_testing_application_configuration('")
        .nth(1)
        .and_then(|rest| rest.split("'::jsonb)").next())
        .ok_or_else(|| anyhow::anyhow!("source import"))?;
    let original: serde_json::Value = serde_json::from_str(import_json)?;
    let mut other = original.clone();
    for field in ["endpoint_id", "signing_key_id", "secret_id"] {
        other[field] = serde_json::json!(Id::now_v7());
    }
    other["secret_digest"] = serde_json::json!("36".repeat(32));
    other["url_digest"] = serde_json::json!("37".repeat(32));
    sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-00000000a002',true)").execute(&mut *connection).await?;
    sqlx::query("SELECT iam_private.import_testing_application_configuration($1)")
        .bind(sqlx::types::Json(&other))
        .execute(&mut *connection)
        .await?;
    sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-00000000a001',true)").execute(&mut *connection).await?;
    sqlx::raw_sql("SELECT iam_private.set_testing_runtime_state('00000000-0000-0000-0000-00000000a001',1,1,true); SET LOCAL ROLE silicon_iam_api;").execute(&mut *connection).await?;
    let environment = Id::from_u128(0xa001);
    let operation = Id::from_u128(0xf001);
    let sql = "SELECT iam_private.erase_testing_applications($1,$2,ARRAY['alpha>test'],1,1)";
    let count: i64 = sqlx::query_scalar(sql)
        .bind(environment)
        .bind(operation)
        .fetch_one(&mut *connection)
        .await?;
    ensure!(count > 0, "retired application had rows");
    let replay: i64 = sqlx::query_scalar(sql)
        .bind(environment)
        .bind(operation)
        .fetch_one(&mut *connection)
        .await?;
    ensure!(replay == count, "same operation replays receipt");
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *connection)
        .await?;
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam.applications WHERE app_id='alpha>test' AND testing_environment_id='00000000-0000-0000-0000-00000000a001'"
        )
        .fetch_one(&mut *connection)
        .await?
            == 0,
        "exact retired app erased"
    );
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam.applications WHERE app_id='beta>test'"
        )
        .fetch_one(&mut *connection)
        .await?
            == 1,
        "other application survives"
    );
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam.application_secrets WHERE application_id='beta>test'"
        )
        .fetch_one(&mut *connection)
        .await?
            == 1,
        "other app credential survives"
    );
    ensure!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM iam.applications WHERE app_id='alpha>test' AND testing_environment_id='00000000-0000-0000-0000-00000000a002'").fetch_one(&mut *connection).await?==1,"same app handle in another environment survives");
    sqlx::query("SELECT iam_private.import_testing_application_configuration($1)")
        .bind(sqlx::types::Json(&original))
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut *connection)
        .await?;
    ensure!(
        sqlx::query_scalar::<_, i64>(sql)
            .bind(environment)
            .bind(operation)
            .fetch_one(&mut *connection)
            .await?
            == count,
        "late retry replays durable test-plane receipt"
    );
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *connection)
        .await?;
    ensure!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM iam.applications WHERE app_id='alpha>test' AND testing_environment_id='00000000-0000-0000-0000-00000000a001'").fetch_one(&mut *connection).await?==1,"late retry cannot erase a fresh import");
    sqlx::raw_sql("ROLLBACK").execute(&mut *connection).await?;
    Ok(())
}
