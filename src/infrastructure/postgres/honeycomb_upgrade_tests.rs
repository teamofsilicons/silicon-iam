//! Upgrade the previously deployed ledgers with existing production/test rows.
#![allow(clippy::too_many_lines)]
use super::*;
use crate::domain::id::Id;
use anyhow::ensure;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use std::borrow::Cow;

#[tokio::test]
#[ignore = "requires Docker or local PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL"]
async fn honeycomb_upgrade_preserves_deployed_state_and_scopes_new_tables() -> anyhow::Result<()> {
    let production_database = crate::test_database::TestDatabase::start().await?;
    let production = production_database.pool.clone();
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let testing = testing_database.pool.clone();
    let runtime_role = format!("iam_upgrade_{}", uuid::Uuid::now_v7().simple());
    for pool in [&production, &testing] {
        sqlx::raw_sql("DO $$ DECLARE name text; BEGIN FOREACH name IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator'] LOOP IF to_regrole(name) IS NULL THEN EXECUTE format('CREATE ROLE %I NOLOGIN',name); END IF; END LOOP; END $$;").execute(pool).await?;
    }
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE ROLE {runtime_role} LOGIN PASSWORD 'synthetic-local-only'; GRANT silicon_iam_api TO {runtime_role};"))).execute(&testing).await?;
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
    let before = expected_public_ids(production_snapshot(&production).await?);
    ensure!(
        !schema_is_current(&production).await?,
        "old production ledger unexpectedly current"
    );
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
    // Distinct app handles keep this upgrade free of the separately tested
    // cross-organization collision rejection. Both start in the old schema.
    let fixture = include_str!("../../../tests/sql/application_testing_layer.sql")
        .replace("beta>test", "beta>test-beta");
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
        other[field] = json!(Id::now_v7());
    }
    other["app_scope"] = json!({"iam":["self.identity.read"],"external":[]});
    let second_app = Id::fixture("test");
    let mut tx = testing.begin().await?;
    sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
        .bind(Id::from_u128(0xa002).to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT iam_private.import_testing_application_configuration($1)")
        .bind(sqlx::types::Json(other))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let before_test = expected_public_ids(testing_snapshot(&testing).await?);
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
        "upgrade changed canonical tenant identity or existing test credentials: before={before_test}, after={}",
        testing_snapshot(&testing).await?
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
    let mut runtime_url = url::Url::parse(&testing_database.url)?;
    runtime_url
        .set_username(&runtime_role)
        .map_err(|()| anyhow::anyhow!("runtime username"))?;
    runtime_url
        .set_password(Some("synthetic-local-only"))
        .map_err(|()| anyhow::anyhow!("runtime password"))?;
    let runtime = PgPoolOptions::new()
        .max_connections(2)
        .connect(runtime_url.as_str())
        .await?;
    ensure!(
        ready_testing(&runtime).await,
        "real nonprivileged runtime readiness must pass after upgrade"
    );
    let plan = Id::now_v7();
    seed_plan(&testing, Id::from_u128(0xa001), Id::fixture("test"), plan).await?;
    seed_plan(&testing, Id::from_u128(0xa002), second_app, Id::now_v7()).await?;
    for (env, visible) in [
        (Id::from_u128(0xa001), true),
        (Id::from_u128(0xa002), false),
    ] {
        let mut tx = runtime.begin().await?;
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(env.to_string())
            .execute(&mut *tx)
            .await?;
        let record: Option<sqlx::types::Json<Value>> =
            sqlx::query_scalar("SELECT iam_private.honeycomb_publication_read($1,$2)")
                .bind(Id::fixture("test"))
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
    runtime.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE {runtime_role}")))
        .execute(&testing)
        .await?;
    Ok(())
}

// Compare identity semantics across the UUID-to-canonical storage conversion,
// retaining every credential byte, resource UUID, version and lifecycle field.
async fn production_snapshot(pool: &PgPool) -> anyhow::Result<Value> {
    let value: sqlx::types::Json<Value> = sqlx::query_scalar(r"
      SELECT jsonb_build_object(
       'environments',(SELECT jsonb_agg(to_jsonb(env) ORDER BY id) FROM iam.testing_environments env),
       'links',(SELECT jsonb_agg(to_jsonb(link)||jsonb_build_object('source_application_id',app.app_id,'target_application_id',app.app_id) ORDER BY environment_id,app.app_id)
        FROM iam.application_testing_environments link JOIN iam.applications app ON app.id=link.source_application_id),
       'applications',(SELECT jsonb_agg(jsonb_build_object('id',app_id,'app_id',app_id,'organization_id',organization_id,'version',version,'scope',app_scope) ORDER BY app_id) FROM iam.applications),
       'secrets',(SELECT jsonb_agg(to_jsonb(secret)||jsonb_build_object('application_id',app.app_id,'created_by_carbon_id',carbon.carbon_id) ORDER BY secret.id)
        FROM iam.application_secrets secret JOIN iam.applications app ON app.id=secret.application_id
        LEFT JOIN iam.carbons carbon ON carbon.id=secret.created_by_carbon_id))
    ").fetch_one(pool).await?;
    Ok(value.0)
}
async fn testing_snapshot(pool: &PgPool) -> anyhow::Result<Value> {
    let value: sqlx::types::Json<Value> = sqlx::query_scalar(r"
      SELECT jsonb_build_object(
       'imports',(SELECT jsonb_agg(to_jsonb(source)||jsonb_build_object('application_id',app.app_id,'source_application_id',app.app_id) ORDER BY source.testing_environment_id,app.app_id)
        FROM iam.testing_application_imports source JOIN iam.applications app ON app.id=source.application_id AND app.testing_environment_id=source.testing_environment_id),
       'apps',(SELECT jsonb_agg(jsonb_build_object('id',app_id,'app_id',app_id,'org',organization_id,'env',testing_environment_id,'version',version,'source',test_imported_from_production) ORDER BY testing_environment_id,app_id) FROM iam.applications),
       'secrets',(SELECT jsonb_agg(to_jsonb(secret)||jsonb_build_object('application_id',app.app_id,'created_by_carbon_id',carbon.carbon_id) ORDER BY secret.testing_environment_id,secret.id)
        FROM iam.application_secrets secret JOIN iam.applications app ON app.id=secret.application_id AND app.testing_environment_id=secret.testing_environment_id
        LEFT JOIN iam.carbons carbon ON carbon.id=secret.created_by_carbon_id AND carbon.testing_environment_id=secret.testing_environment_id))
    ").fetch_one(pool).await?;
    Ok(value.0)
}
async fn seed_plan(pool: &PgPool, env: Id, app: Id, plan: Id) -> anyhow::Result<()> {
    let operation = Id::now_v7();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
        .bind(env.to_string())
        .execute(&mut *tx)
        .await?;
    let owner: Id = sqlx::query_scalar("SELECT created_by_carbon_id FROM iam.applications WHERE id=$1 AND testing_environment_id=$2").bind(app).bind(env).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO iam.honeycomb_publication_plans(plan_id,service_application_id,request_id,application_id,configuration_revision,configuration_digest,requested_scope,catalog_gates,reused_approvals,gates,created_by_carbon_id) VALUES($1,$2,$3,$2,1,$4,'{\"iam\":[\"self.identity.read\"],\"external\":[]}','[]','[]','[]',$5)").bind(plan).bind(app).bind(Id::now_v7()).bind(vec![42_u8;32]).bind(owner).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO iam.honeycomb_operations(operation_id,service_application_id,actor_principal_id,operation_kind,resource_id,idempotency_digest,request_digest,state) VALUES($1,$2,$3,'publication-decision',$4,$5,$6,'accepted')").bind(operation).bind(app).bind(owner).bind(plan.to_string()).bind(vec![42_u8;32]).bind(vec![43_u8;32]).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO iam.honeycomb_publication_decisions(decision_id,plan_id,provider,scopes,decision,reviewer_carbon_id) VALUES($1,$2,'honeycomb','{}','approve',$3)").bind(operation).bind(plan).bind(owner).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

// Snapshot fields contain identity references; compare the explicit public-ID
// projection while retaining every credential byte and unrelated resource UUID.
fn expected_public_ids(value: Value) -> Value {
    match value {
        Value::String(value) => {
            let mapped = match value.as_str() {
                "test_org>app-alpha" => "app-alpha",
                "test_org>app-beta" => "app-beta",
                "alpha>test" => "test",
                "beta>test-beta" => "test-beta",
                "test_carbon" => "c:test_carbon",
                "test_admin" => "c:test_admin",
                "test_gggggggggggggggggggggggg" => "c:test_gggggggggggggggggggggggg",
                _ => return Value::String(value),
            };
            json!(mapped)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(expected_public_ids).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, expected_public_ids(value)))
                .collect(),
        ),
        value => value,
    }
}
