//! The UI eligibility hint must respect the same tenant and authority boundary as bundles.

use anyhow::{Context as _, ensure};
use axum::{http::StatusCode, response::IntoResponse as _};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres as PostgresImage;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    applications::APPLICATION_LIST_QUERY,
    bundles::{BUNDLE_AVAILABILITY_QUERY, BUNDLE_LIST_QUERY},
    model::ApplicationView,
    security::organization_filter,
};

#[tokio::test]
#[ignore = "requires Docker; checks fresh and upgraded production/testing runtime roles"]
async fn bundle_availability_and_organization_pages_preserve_authority() -> anyhow::Result<()> {
    let container = PostgresImage::default()
        .with_tag("16-alpine")
        .start()
        .await?;
    let base_url = format!(
        "postgres://postgres:postgres@{}:{}",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect(&format!("{base_url}/postgres"))
        .await?;
    sqlx::raw_sql("CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN; CREATE ROLE bundle_runtime LOGIN PASSWORD 'bundle-test-only' IN ROLE silicon_iam_api;").execute(&admin).await?;
    for (database, testing, upgrade) in [
        ("bundle_production", false, false),
        ("bundle_testing", true, false),
        ("bundle_production_upgrade", false, true),
        ("bundle_testing_upgrade", true, true),
    ] {
        // Database identifiers are the four closed literals above.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(&admin)
            .await?;
        let pool = PgPoolOptions::new().max_connections(3).after_connect(move |connection, _| Box::pin(async move {
            if testing {
                sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-000000000801',false)").execute(connection).await?;
            }
            Ok(())
        })).connect(&format!("{base_url}/{database}")).await?;
        if upgrade {
            let base = sqlx::migrate::Migrator::with_migrations(
                sqlx::migrate!("./migrations")
                    .iter()
                    .filter(|migration| migration.version <= 83)
                    .cloned()
                    .collect(),
            );
            base.run(&pool).await?;
            if testing {
                // Freeze the overlay alongside the historical base schema.
                sqlx::migrate::Migrator::with_migrations(
                    sqlx::migrate!("./migrations/testing")
                        .iter()
                        .filter(|migration| migration.version <= 9004)
                        .cloned()
                        .collect(),
                )
                .set_ignore_missing(true)
                .run(&pool)
                .await?;
            }
            seed(&pool).await?;
        }
        if testing {
            crate::infrastructure::postgres::migrate_testing(&pool).await?;
        } else {
            crate::infrastructure::postgres::migrate(&pool).await?;
        }
        if !upgrade {
            seed(&pool).await?;
        }
        let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
            .execute(&pool)
            .await?;
        assert_eligibility(&pool)
            .await
            .with_context(|| format!("eligibility in {database}"))?;
        assert_pages(&pool)
            .await
            .with_context(|| format!("pagination in {database}"))?;
        if testing {
            let runtime_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&format!(
                    "{}/{database}",
                    base_url.replace("postgres:postgres@", "bundle_runtime:bundle-test-only@")
                ))
                .await?;
            assert_testing_boundary(&runtime_pool)
                .await
                .with_context(|| format!("isolation in {database}"))?;
            runtime_pool.close().await;
        }
        pool.close().await;
    }
    admin.close().await;
    Ok(())
}

async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    super::live_tests::seed_protocol_rows(pool).await?;
    sqlx::raw_sql(r"
        BEGIN;
        INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES
          ('00000000-0000-0000-0000-000000000022','pagination_org','00000000-0000-0000-0000-000000000001','Pagination'),
          ('00000000-0000-0000-0000-000000000023','outside_org','00000000-0000-0000-0000-000000000002','Outside');
        INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role,job_role) VALUES
          ('00000000-0000-0000-0000-000000000033','00000000-0000-0000-0000-000000000022','00000000-0000-0000-0000-000000000001','carbon','owner',''),
          ('00000000-0000-0000-0000-000000000034','00000000-0000-0000-0000-000000000023','00000000-0000-0000-0000-000000000002','carbon','owner','');
        INSERT INTO iam.principals(id,kind,status,activated_at) VALUES
          ('00000000-0000-0000-0000-000000000013','application','active',transaction_timestamp());
        INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,review_status,base_url) VALUES
          ('00000000-0000-0000-0000-000000000013','pagination_org>app-gamma','00000000-0000-0000-0000-000000000022','00000000-0000-0000-0000-000000000001','verified','https://gamma.example.test/api');
        INSERT INTO iam.application_bundles(id,organization_id,bundle_id,created_by_carbon_id,created_at) VALUES
          ('00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000021','test_org>bundle-one','00000000-0000-0000-0000-000000000001','2026-01-01'),
          ('00000000-0000-0000-0000-000000000502','00000000-0000-0000-0000-000000000021','test_org>bundle-two','00000000-0000-0000-0000-000000000001','2026-01-02'),
          ('00000000-0000-0000-0000-000000000503','00000000-0000-0000-0000-000000000022','pagination_org>bundle-three','00000000-0000-0000-0000-000000000001','2026-01-03');
        INSERT INTO iam.application_bundle_members(bundle_id,organization_id,application_id,position) VALUES
          ('00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000011',0),
          ('00000000-0000-0000-0000-000000000502','00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000012',0),
          ('00000000-0000-0000-0000-000000000503','00000000-0000-0000-0000-000000000022','00000000-0000-0000-0000-000000000013',0);
        COMMIT;
    ").execute(pool).await?;
    Ok(())
}

async fn runtime(tx: &mut Transaction<'_, Postgres>, actor: u128) -> anyhow::Result<()> {
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT set_config('iam.principal_id',$1,true),set_config('iam.organization_id','',true),set_config('iam.application_id','',true)").bind(Uuid::from_u128(actor).to_string()).execute(&mut **tx).await?;
    Ok(())
}

async fn availability(
    tx: &mut Transaction<'_, Postgres>,
    org: &str,
) -> anyhow::Result<Option<bool>> {
    Ok(sqlx::query_scalar(BUNDLE_AVAILABILITY_QUERY)
        .bind(org)
        .fetch_one(&mut **tx)
        .await?)
}

async fn assert_eligibility(pool: &PgPool) -> anyhow::Result<()> {
    // A new statement must observe administrative flag changes without reconnecting.
    let mut reader = pool.begin().await?;
    runtime(&mut reader, 1).await?;
    for (trusted, bundled, skip, expected) in [
        (false, false, false, false),
        (true, false, false, false),
        (false, true, false, false),
        (true, true, false, true),
        (true, true, true, true),
        (false, false, false, false),
    ] {
        sqlx::query("UPDATE iam.organizations SET trusted_org=$1,allow_bundled_applications=$2,skip_application_consent=$3 WHERE org_id='test_org'").bind(trusted).bind(bundled).bind(skip).execute(pool).await?;
        ensure!(
            availability(&mut reader, "test_org").await? == Some(expected),
            "eligibility must use both current flags"
        );
    }
    for org in ["outside_org", "missing_org"] {
        ensure!(availability(&mut reader, org).await?.is_none());
    }
    reader.rollback().await?;
    sqlx::query("UPDATE iam.organizations SET trusted_org=true,allow_bundled_applications=true WHERE org_id='test_org'").execute(pool).await?;
    for actor in [1, 2] {
        let mut tx = pool.begin().await?;
        runtime(&mut tx, actor).await?;
        ensure!(
            availability(&mut tx, "test_org").await? == Some(true),
            "owner and admin are eligible"
        );
        tx.rollback().await?;
    }
    for (mutation, expected) in [
        (
            "UPDATE iam.organization_memberships SET org_role='member',role_granted_by_membership_id=NULL WHERE id='00000000-0000-0000-0000-000000000032'",
            Some(false),
        ),
        (
            "UPDATE iam.organizations SET status='suspended' WHERE org_id='test_org'",
            Some(false),
        ),
        (
            "UPDATE iam.organizations SET status='deleted',deleted_at=transaction_timestamp() WHERE org_id='test_org'",
            Some(false),
        ),
        (
            "UPDATE iam.organization_memberships SET status='suspended',suspended_at=transaction_timestamp() WHERE id='00000000-0000-0000-0000-000000000032'",
            None,
        ),
        (
            "UPDATE iam.organization_memberships SET status='removed',removed_at=transaction_timestamp() WHERE id='00000000-0000-0000-0000-000000000032'",
            None,
        ),
        (
            "UPDATE iam.principals SET status='suspended',suspended_at=transaction_timestamp() WHERE id='00000000-0000-0000-0000-000000000002'",
            None,
        ),
    ] {
        let mut tx = pool.begin().await?;
        sqlx::query(mutation).execute(&mut *tx).await?;
        runtime(&mut tx, 2).await?;
        ensure!(
            availability(&mut tx, "test_org").await? == expected,
            "authority change: {mutation}"
        );
        tx.rollback().await?;
    }
    let mut tx = pool.begin().await?;
    runtime(&mut tx, 1).await?;
    sqlx::query(
        "SELECT set_config('iam.application_id','00000000-0000-0000-0000-000000000011',true)",
    )
    .execute(&mut *tx)
    .await?;
    ensure!(
        availability(&mut tx, "test_org").await?.is_none(),
        "delegated applications cannot inspect eligibility"
    );
    sqlx::query("SELECT set_config('iam.application_id','',true),set_config('iam.organization_id','00000000-0000-0000-0000-000000000022',true)").execute(&mut *tx).await?;
    ensure!(
        availability(&mut tx, "test_org").await?.is_none(),
        "selected organization must match"
    );
    tx.rollback().await?;
    Ok(())
}

async fn assert_pages(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    runtime(&mut tx, 1).await?;
    let org = organization_filter(&mut tx, Some("test_org"))
        .await
        .map_err(api_error)?;
    ensure!(org == Some(Uuid::from_u128(0x21)));
    let mut cursor: Option<(OffsetDateTime, Uuid)> = None;
    for expected in ["test_org>app-beta", "test_org>app-alpha"] {
        let rows = sqlx::query_as::<_, ApplicationView>(APPLICATION_LIST_QUERY)
            .bind(Uuid::from_u128(1))
            .bind(None::<String>)
            .bind(cursor.map(|value| value.0))
            .bind(cursor.map(|value| value.1))
            .bind(1_i64)
            .bind(org)
            .fetch_all(&mut *tx)
            .await?;
        ensure!(
            rows.len() == 1 && rows[0].app_id == expected,
            "application filtering must precede pagination"
        );
        cursor = Some((rows[0].created_at, rows[0].id));
    }
    cursor = None;
    for expected in ["test_org>bundle-two", "test_org>bundle-one"] {
        let rows = sqlx::query_as::<_, (Uuid, OffsetDateTime, String)>(BUNDLE_LIST_QUERY)
            .bind(cursor.map(|value| value.0))
            .bind(cursor.map(|value| value.1))
            .bind(1_i64)
            .bind(org)
            .fetch_all(&mut *tx)
            .await?;
        ensure!(
            rows.len() == 1 && rows[0].2 == expected,
            "bundle filtering must precede pagination"
        );
        cursor = Some((rows[0].1, rows[0].0));
    }
    for inaccessible in ["outside_org", "missing_org"] {
        assert_filter_not_found(&mut tx, inaccessible).await?;
    }
    tx.rollback().await?;
    Ok(())
}

async fn assert_testing_boundary(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    runtime(&mut tx, 1).await?;
    for environment in ["00000000-0000-0000-0000-000000000802", ""] {
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(environment)
            .execute(&mut *tx)
            .await?;
        ensure!(
            availability(&mut tx, "test_org").await?.is_none(),
            "bundle availability cannot cross testing environments"
        );
        assert_filter_not_found(&mut tx, "test_org").await?;
    }
    tx.rollback().await?;
    Ok(())
}

async fn assert_filter_not_found(
    tx: &mut Transaction<'_, Postgres>,
    org: &str,
) -> anyhow::Result<()> {
    let Err(error) = organization_filter(tx, Some(org)).await else {
        anyhow::bail!("inaccessible organization must return404");
    };
    ensure!(error.into_response().status() == StatusCode::NOT_FOUND);
    Ok(())
}
fn api_error(error: super::error::ApiError) -> anyhow::Error {
    anyhow::anyhow!("API error: {}", error.into_response().status())
}
