//! Restricted-role integration checks for protected transfer and exact erasure.
use crate::infrastructure::postgres;
use anyhow::ensure;
use sqlx::postgres::PgPoolOptions;
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires Docker"]
async fn adoption_preserves_identity_and_retention_erases_only_exact_apps() -> anyhow::Result<()> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let url = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await?;
    sqlx::raw_sql("CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN;").execute(&pool).await?;
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
    sqlx::raw_sql(include_str!("../../../../tests/sql/honeycomb_adoption.sql"))
        .execute(&pool)
        .await?;
    sqlx::query("CREATE DATABASE testing")
        .execute(&pool)
        .await?;
    let testing_url = format!("{}/testing", url.trim_end_matches("/postgres"));
    let test_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&testing_url)
        .await?;
    postgres::migrate_testing(&test_pool).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
        .execute(&test_pool)
        .await?;
    let fixture = include_str!("../../../../tests/sql/application_testing_layer.sql");
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
    for field in [
        "application_id",
        "endpoint_id",
        "signing_key_id",
        "secret_id",
    ] {
        other[field] = serde_json::json!(Uuid::now_v7());
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
    let environment = Uuid::from_u128(0xa001);
    let operation = Uuid::from_u128(0xf001);
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
    ensure!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM iam.application_secrets WHERE application_id='00000000-0000-0000-0000-00000000b002'").fetch_one(&mut *connection).await?==1,"other app credential survives");
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
