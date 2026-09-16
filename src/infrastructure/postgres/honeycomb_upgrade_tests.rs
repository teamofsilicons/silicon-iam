//! Upgrade the previously deployed ledgers with existing production/test rows.
#![allow(clippy::too_many_lines)]
use super::*;
use anyhow::ensure;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use std::borrow::Cow;
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires Docker"]
async fn honeycomb_upgrade_preserves_deployed_state_and_scopes_new_tables() -> anyhow::Result<()> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let url = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    let production = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await?;
    sqlx::raw_sql("CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN; CREATE ROLE iam_upgrade_runtime LOGIN PASSWORD 'synthetic-local-only'; GRANT silicon_iam_api TO iam_upgrade_runtime;").execute(&production).await?;
    let mut old_base = sqlx::migrate!("./migrations");
    old_base.migrations = Cow::Owned(
        old_base
            .iter()
            .filter(|migration| migration.version <= 99)
            .cloned()
            .collect(),
    );
    old_base.run(&production).await?;
    crate::features::applications::live_tests::seed_protocol_rows(&production).await?;
    let legacy = include_str!("../../../tests/sql/honeycomb_adoption.sql")
        .split("SELECT set_config")
        .next()
        .ok_or_else(|| anyhow::anyhow!("legacy fixture"))?
        .to_owned()
        + "COMMIT;";
    sqlx::raw_sql(sqlx::AssertSqlSafe(legacy))
        .execute(&production)
        .await?;
    let before = production_snapshot(&production).await?;
    ensure!(
        !schema_is_current(&production).await?,
        "old production ledger unexpectedly current"
    );
    sqlx::query("CREATE DATABASE testing")
        .execute(&production)
        .await?;
    let testing_url = format!("{}/testing", url.trim_end_matches("/postgres"));
    let testing = PgPoolOptions::new()
        .max_connections(2)
        .connect(&testing_url)
        .await?;
    old_base.run(&testing).await?;
    let mut old_overlay = sqlx::migrate!("./migrations/testing");
    old_overlay.migrations = Cow::Owned(
        old_overlay
            .iter()
            .filter(|migration| migration.version <= 9009)
            .cloned()
            .collect(),
    );
    old_overlay.set_ignore_missing(true);
    old_overlay.run(&testing).await?;
    let ledger: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(&testing)
        .await?;
    ensure!(
        ledger == 108,
        "upgrade fixture must start from deployed 99+9 ledger"
    );
    let fixture = include_str!("../../../tests/sql/application_testing_layer.sql");
    let setup = fixture
        .split("UPDATE iam.testing_application_imports")
        .next()
        .ok_or_else(|| anyhow::anyhow!("test fixture"))?
        .to_owned()
        + "COMMIT;";
    sqlx::raw_sql(sqlx::AssertSqlSafe(setup))
        .execute(&testing)
        .await?;
    let raw = fixture
        .split("import_testing_application_configuration('")
        .nth(1)
        .and_then(|part| part.split("'::jsonb)").next())
        .ok_or_else(|| anyhow::anyhow!("test import fixture"))?;
    let mut other: Value = serde_json::from_str(raw)?;
    for field in [
        "application_id",
        "endpoint_id",
        "signing_key_id",
        "secret_id",
    ] {
        other[field] = json!(Uuid::now_v7());
    }
    other["app_scope"] = json!({"iam":["self.identity.read"],"external":[]});
    let second_app: Uuid = serde_json::from_value(other["application_id"].clone())?;
    let mut tx = testing.begin().await?;
    sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
        .bind(Uuid::from_u128(0xa002).to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT iam_private.import_testing_application_configuration($1)")
        .bind(sqlx::types::Json(other))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let before_test = testing_snapshot(&testing).await?;
    ensure!(
        !testing_schema_is_current(&testing).await?,
        "old test ledger unexpectedly current"
    );
    migrate(&production).await?;
    migrate_testing(&testing).await?;
    ensure!(
        production_snapshot(&production).await? == before,
        "upgrade changed production identity, key, credential, or link"
    );
    ensure!(
        testing_snapshot(&testing).await? == before_test,
        "upgrade changed existing tenant identity/source UUID/test credentials"
    );
    ensure!(
        schema_is_current(&production).await? && testing_schema_is_current(&testing).await?,
        "full migration checksum ledger must match after upgrade"
    );
    ensure!(
        testing_security_is_current(&testing).await?,
        "upgraded helper/table isolation audit failed"
    );
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
        .execute(&production)
        .await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(&testing)
        .await?;
    let runtime_url = testing_url.replacen(
        "postgres:postgres@",
        "iam_upgrade_runtime:synthetic-local-only@",
        1,
    );
    let runtime = PgPoolOptions::new()
        .max_connections(2)
        .connect(&runtime_url)
        .await?;
    ensure!(
        ready_testing(&runtime).await,
        "real nonprivileged runtime readiness must pass after upgrade"
    );
    let plan = Uuid::now_v7();
    seed_plan(
        &testing,
        Uuid::from_u128(0xa001),
        Uuid::from_u128(0xb001),
        plan,
    )
    .await?;
    seed_plan(
        &testing,
        Uuid::from_u128(0xa002),
        second_app,
        Uuid::now_v7(),
    )
    .await?;
    for (env, visible) in [
        (Uuid::from_u128(0xa001), true),
        (Uuid::from_u128(0xa002), false),
    ] {
        let mut tx = runtime.begin().await?;
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(env.to_string())
            .execute(&mut *tx)
            .await?;
        let record: Option<sqlx::types::Json<Value>> =
            sqlx::query_scalar("SELECT iam_private.honeycomb_publication_read($1,$2)")
                .bind(Uuid::from_u128(0xb001))
                .bind(plan)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            record.is_some() == visible,
            "new publication plan crossed tenant boundary"
        );
        if let Some(record) = record {
            ensure!(
                record.0["plan_id"] == json!(plan),
                "wrong publication plan returned"
            );
        }
        tx.commit().await?;
        // Exercise FORCE RLS under the helper's restricted owner independently
        // of the helper's own application/service predicates.
        let mut tx = testing.begin().await?;
        sqlx::query("SET LOCAL ROLE silicon_iam_testing_definer")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(env.to_string())
            .execute(&mut *tx)
            .await?;
        let plans: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM iam.honeycomb_publication_plans WHERE plan_id=$1",
        )
        .bind(plan)
        .fetch_one(&mut *tx)
        .await?;
        let decisions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM iam.honeycomb_publication_decisions WHERE plan_id=$1",
        )
        .bind(plan)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(
            plans == i64::from(visible) && decisions == i64::from(visible),
            "publication plan or decision escaped helper-owner tenant isolation"
        );
        tx.commit().await?;
    }
    let can_direct:bool=sqlx::query_scalar("SELECT has_table_privilege(current_user,'iam.honeycomb_publication_plans','SELECT') OR has_table_privilege(current_user,'iam.honeycomb_publication_decisions','SELECT')").fetch_one(&runtime).await?;
    ensure!(!can_direct, "runtime gained direct publication table reads");
    let definer_membership: bool = sqlx::query_scalar(
        "SELECT pg_has_role(current_user,'silicon_iam_testing_definer','member')",
    )
    .fetch_one(&runtime)
    .await?;
    ensure!(!definer_membership, "runtime can assume test definer role");
    // A changed checksum and an unknown extra entry each invalidate readiness.
    let checksum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=99")
            .fetch_one(&testing)
            .await?;
    sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=99")
        .bind(vec![0_u8; 48])
        .execute(&testing)
        .await?;
    ensure!(!ready_testing(&runtime).await, "checksum drift accepted");
    sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=99")
        .bind(checksum)
        .execute(&testing)
        .await?;
    sqlx::query("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES(99999,'unexpected',true,$1,0)").bind(vec![0_u8;48]).execute(&testing).await?;
    ensure!(
        !ready_testing(&runtime).await,
        "unknown migration ledger entry accepted"
    );
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version=99999")
        .execute(&testing)
        .await?;
    ensure!(
        ready_testing(&runtime).await,
        "restored exact ledger failed readiness"
    );
    Ok(())
}

async fn production_snapshot(pool: &PgPool) -> anyhow::Result<Value> {
    let value:sqlx::types::Json<Value>=sqlx::query_scalar("SELECT jsonb_build_object('environments',(SELECT jsonb_agg(to_jsonb(env) ORDER BY id) FROM iam.testing_environments env),'links',(SELECT jsonb_agg(to_jsonb(link) ORDER BY environment_id,source_application_id) FROM iam.application_testing_environments link),'applications',(SELECT jsonb_agg(jsonb_build_object('id',id,'app_id',app_id,'organization_id',organization_id,'version',version,'scope',app_scope) ORDER BY id) FROM iam.applications),'secrets',(SELECT jsonb_agg(to_jsonb(secret) ORDER BY id) FROM iam.application_secrets secret))").fetch_one(pool).await?;
    Ok(value.0)
}
async fn testing_snapshot(pool: &PgPool) -> anyhow::Result<Value> {
    let value:sqlx::types::Json<Value>=sqlx::query_scalar("SELECT jsonb_build_object('imports',(SELECT jsonb_agg(to_jsonb(source) ORDER BY testing_environment_id,application_id) FROM iam.testing_application_imports source),'apps',(SELECT jsonb_agg(jsonb_build_object('id',id,'app_id',app_id,'org',organization_id,'env',testing_environment_id,'version',version,'source',test_imported_from_production) ORDER BY testing_environment_id,id) FROM iam.applications),'secrets',(SELECT jsonb_agg(to_jsonb(secret) ORDER BY testing_environment_id,id) FROM iam.application_secrets secret))").fetch_one(pool).await?;
    Ok(value.0)
}
async fn seed_plan(pool: &PgPool, env: Uuid, app: Uuid, plan: Uuid) -> anyhow::Result<()> {
    let operation = Uuid::now_v7();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
        .bind(env.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO iam.honeycomb_publication_plans(plan_id,service_application_id,request_id,application_id,configuration_revision,configuration_digest,requested_scope,catalog_gates,reused_approvals,gates,created_by_carbon_id) VALUES($1,$2,$3,$2,1,$4,'{\"iam\":[\"self.identity.read\"],\"external\":[]}','[]','[]','[]',$5)").bind(plan).bind(app).bind(Uuid::now_v7()).bind(vec![42_u8;32]).bind(env).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO iam.honeycomb_operations(operation_id,service_application_id,actor_principal_id,operation_kind,resource_id,idempotency_digest,request_digest,state) VALUES($1,$2,$3,'publication-decision',$4,$5,$6,'accepted')").bind(operation).bind(app).bind(env).bind(plan.to_string()).bind(vec![42_u8;32]).bind(vec![43_u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO iam.honeycomb_publication_decisions(decision_id,plan_id,provider,scopes,decision,reviewer_carbon_id) VALUES($1,$2,'honeycomb','{}','approve',$3)").bind(operation).bind(plan).bind(env).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
