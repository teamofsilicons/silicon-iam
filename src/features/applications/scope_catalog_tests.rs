//! Scope discovery must distinguish an empty public catalog from an invalid ID.

use std::time::Duration;

use anyhow::{Context as _, ensure};
use axum::{http::StatusCode, response::IntoResponse as _};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres as PostgresImage;
use uuid::Uuid;

use super::scopes::catalog_items;

#[tokio::test]
#[ignore = "requires Docker; checks production and testing runtime permissions"]
async fn scope_catalog_validates_applications_without_disclosing_other_environments()
-> anyhow::Result<()> {
    let container = PostgresImage::default()
        .with_tag("16-alpine")
        .start()
        .await?;
    let base_url = format!(
        "postgres://postgres:postgres@{}:{}",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    let production = PgPoolOptions::new()
        .max_connections(3)
        .connect(&format!("{base_url}/postgres"))
        .await?;
    sqlx::raw_sql("CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN;")
        .execute(&production).await?;
    crate::infrastructure::postgres::migrate(&production).await?;
    seed_catalog(&production).await?;
    assert_catalog_choices(&production).await?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/iam_mutation_scope_policy.sql"
    ))
    .execute(&production)
    .await
    .context("IAM mutation scope policy")?;
    assert_policy_concurrency(&production)
        .await
        .context("production IAM policy concurrency")?;

    sqlx::query("CREATE DATABASE testing")
        .execute(&production)
        .await?;
    let testing = PgPoolOptions::new()
        .max_connections(3)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-000000000801',false)")
                    .execute(connection).await?;
                Ok(())
            })
        })
        .connect(&format!("{base_url}/testing"))
        .await?;
    crate::infrastructure::postgres::migrate_testing(&testing).await?;
    seed_catalog(&testing).await?;
    assert_catalog_choices(&testing).await?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/iam_mutation_scope_policy.sql"
    ))
    .execute(&testing)
    .await
    .context("testing IAM mutation scope policy")?;
    assert_policy_concurrency(&testing)
        .await
        .context("testing IAM policy concurrency")?;
    let mut tx = testing.begin().await?;
    select_runtime_actor(&mut tx).await?;
    for environment in ["00000000-0000-0000-0000-000000000802", ""] {
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(environment)
            .execute(&mut *tx)
            .await?;
        assert_not_found(&mut tx, "test_org>app-beta").await?;
        let iam = catalog_items(&mut tx, None).await.map_err(catalog_error)?;
        ensure!(
            iam.len() == super::scopes::IAM_SCOPES.len()
                && iam.iter().all(|scope| scope.app_id.is_none())
        );
    }
    tx.rollback().await?;
    assert_catalog_upgrade(&production, &base_url).await?;
    testing.close().await;
    production.close().await;
    Ok(())
}

async fn assert_catalog_upgrade(admin: &PgPool, base_url: &str) -> anyhow::Result<()> {
    let base = sqlx::migrate::Migrator::with_migrations(
        sqlx::migrate!("./migrations")
            .iter()
            .filter(|migration| migration.version <= 82)
            .cloned()
            .collect(),
    );
    for testing in [false, true] {
        let database = if testing {
            "testing_upgrade"
        } else {
            "production_upgrade"
        };
        // Both names are closed literals, never request input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
            .execute(admin)
            .await?;
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    if testing {
                        sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-000000000801',false)")
                            .execute(connection).await?;
                    }
                    Ok(())
                })
            })
            .connect(&format!("{base_url}/{database}")).await?;
        base.run(&pool).await?;
        if testing {
            let mut overlay = sqlx::migrate!("./migrations/testing");
            overlay.set_ignore_missing(true).run(&pool).await?;
        }
        super::live_tests::seed_protocol_rows(&pool).await?;
        if testing {
            crate::infrastructure::postgres::migrate_testing(&pool).await?;
        } else {
            crate::infrastructure::postgres::migrate(&pool).await?;
        }
        seed_catalog_endpoints_and_grants(&pool).await?;
        assert_catalog_choices(&pool).await?;
        pool.close().await;
    }
    Ok(())
}

async fn seed_catalog(pool: &PgPool) -> anyhow::Result<()> {
    super::live_tests::seed_protocol_rows(pool).await?;
    seed_catalog_endpoints_and_grants(pool).await
}

async fn seed_catalog_endpoints_and_grants(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(
        r"
        INSERT INTO iam.application_obo_endpoints (
            organization_id, application_id, endpoint_id, path, critical, status, retired_at
        ) VALUES
          ('00000000-0000-0000-0000-000000000021',
           '00000000-0000-0000-0000-000000000012', 'files.delete', '/files/delete', true, 'active', NULL),
          ('00000000-0000-0000-0000-000000000021',
           '00000000-0000-0000-0000-000000000012', 'files.legacy', '/files/legacy', false, 'retired', transaction_timestamp());
        ",
    )
    .execute(pool)
    .await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(pool)
        .await
        .context("scope catalog restricted runtime grants")?;
    Ok(())
}

async fn assert_catalog_choices(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    select_runtime_actor(&mut tx).await?;
    let table_visible = sqlx::query_scalar::<_, bool>(
        "SELECT has_table_privilege(current_user,'iam.oauth_scope_catalog','SELECT')",
    )
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        !table_visible,
        "shared external scope history must remain private"
    );
    let iam = catalog_items(&mut tx, None).await.map_err(catalog_error)?;
    ensure!(
        iam.len() == super::scopes::IAM_SCOPES.len()
            && iam.iter().all(|scope| scope.app_id.is_none())
    );
    let empty = catalog_items(&mut tx, Some("test_org>app-alpha"))
        .await
        .map_err(catalog_error)?;
    ensure!(
        empty.is_empty(),
        "valid empty catalog must remain a success"
    );
    assert_not_found(&mut tx, "test_org>missing-app").await?;
    let external = catalog_items(&mut tx, Some("test_org>app-beta"))
        .await
        .map_err(catalog_error)?;
    ensure!(
        external.len() == 2,
        "retired scopes must not be discoverable"
    );
    ensure!(
        external
            .iter()
            .all(|scope| scope.app_id.as_deref() == Some("test_org>app-beta"))
    );
    ensure!(external[0].scope == "obo:test_org>app-beta:files.delete" && external[0].critical);
    ensure!(external[1].scope == "obo:test_org>app-beta:trust.manage" && !external[1].critical);
    tx.rollback().await?;

    for state in ["under_review", "suspended", "deleted"] {
        let mut tx = pool.begin().await?;
        sqlx::query("UPDATE iam.applications SET review_status=$1, deleted_at=CASE WHEN $1='deleted' THEN transaction_timestamp() END WHERE app_id='test_org>app-beta'")
            .bind(state).execute(&mut *tx).await?;
        select_runtime_actor(&mut tx).await?;
        assert_not_found(&mut tx, "test_org>app-beta").await?;
        tx.rollback().await?;
    }
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE iam.principals SET status='suspended', suspended_at=transaction_timestamp() WHERE id='00000000-0000-0000-0000-000000000012'")
        .execute(&mut *tx).await?;
    select_runtime_actor(&mut tx).await?;
    assert_not_found(&mut tx, "test_org>app-beta").await?;
    tx.rollback().await?;
    Ok(())
}

async fn select_runtime_actor(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<()> {
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT set_config('iam.principal_id','00000000-0000-0000-0000-000000000001',true),set_config('iam.organization_id','',true)")
        .execute(&mut **tx).await?;
    Ok(())
}

async fn assert_not_found(tx: &mut Transaction<'_, Postgres>, app_id: &str) -> anyhow::Result<()> {
    let Err(error) = catalog_items(tx, Some(app_id)).await else {
        anyhow::bail!("unavailable application must not return a successful empty catalog");
    };
    ensure!(error.into_response().status() == StatusCode::NOT_FOUND);
    Ok(())
}

fn catalog_error(error: super::error::ApiError) -> anyhow::Error {
    anyhow::anyhow!("scope catalog failed: {}", error.into_response().status())
}

const POLICY_ORG: Uuid = Uuid::from_u128(0x21);
const POLICY_APP: Uuid = Uuid::from_u128(0x11);
const POLICY_ACTOR: Uuid = Uuid::from_u128(1);
const RESTRICTED_SCOPE: &str = "organization.invitations.create";

async fn assert_policy_concurrency(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO iam.platform_role_grants(id,carbon_id,role,grant_source) VALUES($1,$2,'application_reviewer','bootstrap')")
        .bind(Uuid::from_u128(0x171)).bind(POLICY_ACTOR).execute(pool).await?;
    existing_review_cannot_commit_past_policy_revocation(pool).await?;
    uncommitted_application_grant_holds_organization_policy(pool).await?;
    new_application_grant_rechecks_policy_after_wait(pool).await?;
    Ok(())
}

async fn begin_policy_transaction(
    pool: &PgPool,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout = '10s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL deadlock_timeout = '100ms'")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn configure_restricted_scope(
    tx: &mut Transaction<'_, Postgres>,
    application: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT iam_private.configure_application_scopes($1,$2,$3)")
        .bind(application)
        .bind(json!({"iam":["self.organizations.read", RESTRICTED_SCOPE],"external":[]}))
        .bind(POLICY_ACTOR)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn restore_policy(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("UPDATE iam.organizations SET trusted_org=true WHERE id=$1")
        .bind(POLICY_ORG)
        .execute(pool)
        .await?;
    Ok(())
}

async fn deny_policy(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE iam.organizations SET trusted_org=false WHERE id=$1")
        .bind(POLICY_ORG)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn backend_pid(tx: &mut Transaction<'_, Postgres>) -> Result<i32, sqlx::Error> {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await
}

async fn wait_for_blocker(pool: &PgPool, waiting: i32, blocker: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if sqlx::query_scalar::<_, bool>("SELECT $1 = ANY(pg_blocking_pids($2))")
                .bind(blocker)
                .bind(waiting)
                .fetch_one(pool)
                .await?
            {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("transaction did not wait for its required policy/app lock")??;
    Ok(())
}

async fn finish_transaction(
    tx: Transaction<'_, Postgres>,
    result: Result<(), sqlx::Error>,
) -> Result<(), sqlx::Error> {
    match result {
        Ok(()) => tx.commit().await,
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

fn is_deadlock(result: &Result<(), sqlx::Error>) -> bool {
    matches!(result, Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("40P01"))
}

async fn assert_no_policy_authority(pool: &PgPool, application: Uuid) -> anyhow::Result<()> {
    let active = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM iam.application_approved_scopes WHERE application_id=$1 AND scope=$2 AND revoked_at IS NULL)")
        .bind(application).bind(RESTRICTED_SCOPE).fetch_one(pool).await?;
    ensure!(
        !active,
        "concurrent approval survived organization policy revocation"
    );
    let token = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM iam.access_tokens token JOIN iam.access_token_scopes scope ON scope.access_token_id=token.id WHERE token.client_application_id=$1 AND scope.scope=$2 AND token.revoked_at IS NULL)")
        .bind(application).bind(RESTRICTED_SCOPE).fetch_one(pool).await?;
    ensure!(
        !token,
        "concurrent restricted token survived organization policy revocation"
    );
    Ok(())
}

async fn existing_review_cannot_commit_past_policy_revocation(pool: &PgPool) -> anyhow::Result<()> {
    restore_policy(pool).await?;
    let mut setup = begin_policy_transaction(pool).await?;
    select_runtime_actor(&mut setup).await?;
    configure_restricted_scope(&mut setup, POLICY_APP).await?;
    let requests = sqlx::query_scalar::<_, Vec<Uuid>>(
        "SELECT iam_private.submit_application_scope_requests($1,$2,'Concurrency regression')",
    )
    .bind(POLICY_APP)
    .bind(POLICY_ACTOR)
    .fetch_one(&mut *setup)
    .await?;
    ensure!(
        requests.len() == 1,
        "fixture requires exactly one restricted scope request"
    );
    setup.commit().await?;
    sqlx::query("INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES($1,$2)")
        .bind(Uuid::from_u128(0x101))
        .bind(RESTRICTED_SCOPE)
        .execute(pool)
        .await?;

    let mut grant = begin_policy_transaction(pool).await?;
    let grant_pid = backend_pid(&mut grant).await?;
    select_runtime_actor(&mut grant).await?;
    sqlx::query("SELECT id FROM iam.applications WHERE id=$1 FOR UPDATE")
        .bind(POLICY_APP)
        .execute(&mut *grant)
        .await?;
    let mut revocation = begin_policy_transaction(pool).await?;
    let revocation_pid = backend_pid(&mut revocation).await?;
    let revocation = tokio::spawn(async move {
        let result = deny_policy(&mut revocation).await;
        finish_transaction(revocation, result).await
    });
    wait_for_blocker(pool, revocation_pid, grant_pid).await?;

    // Without the application-before-grants scan, revocation has already
    // missed this uncommitted approval by the time it waits for the app lock.
    let approval = sqlx::query_scalar::<_, Value>("SELECT iam_private.mutate_application_scope_request($1,$2,1,'approve','Concurrency regression')")
        .bind(requests[0]).bind(POLICY_ACTOR).fetch_one(&mut *grant).await.map(|_| ());
    let approval = finish_transaction(grant, approval).await;
    let revocation = tokio::time::timeout(Duration::from_secs(10), revocation).await??;
    ensure!(
        approval.is_ok() || is_deadlock(&approval),
        "unexpected approval result: {approval:?}"
    );
    ensure!(
        revocation.is_ok() || is_deadlock(&revocation),
        "unexpected policy result: {revocation:?}"
    );
    ensure!(
        approval.is_ok() || revocation.is_ok(),
        "one conflicting transaction must complete"
    );
    if revocation.is_err() {
        let mut retry = begin_policy_transaction(pool).await?;
        deny_policy(&mut retry).await?;
        retry.commit().await?;
    }
    assert_no_policy_authority(pool, POLICY_APP).await?;
    restore_policy(pool).await?;
    assert_no_policy_authority(pool, POLICY_APP).await?;
    Ok(())
}

async fn insert_uncommitted_application(
    tx: &mut Transaction<'_, Postgres>,
    application: Uuid,
    name: &str,
) -> Result<(), sqlx::Error> {
    // Exercise the DB guard even for imports/privileged writers that have not
    // used the normal creation helper's existing organization SHARE lock.
    sqlx::query("INSERT INTO iam.principals(id,kind,status,activated_at) VALUES($1,'application','active',transaction_timestamp())")
        .bind(application).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,review_status,base_url) VALUES($1,$2,$3,$4,'verified','https://concurrent.example.test/api')")
        .bind(application).bind(name).bind(POLICY_ORG).bind(POLICY_ACTOR).execute(&mut **tx).await?;
    Ok(())
}

async fn uncommitted_application_grant_holds_organization_policy(
    pool: &PgPool,
) -> anyhow::Result<()> {
    restore_policy(pool).await?;
    let application = Uuid::from_u128(0x172);
    let mut creation = begin_policy_transaction(pool).await?;
    let creation_pid = backend_pid(&mut creation).await?;
    insert_uncommitted_application(&mut creation, application, "test_org>policy-race-new").await?;
    select_runtime_actor(&mut creation).await?;
    configure_restricted_scope(&mut creation, application).await?;
    sqlx::query("INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES($1,$2,$3)")
        .bind(application).bind(RESTRICTED_SCOPE).bind(POLICY_ACTOR).execute(&mut *creation).await?;
    let mut revocation = begin_policy_transaction(pool).await?;
    let revocation_pid = backend_pid(&mut revocation).await?;
    let revocation = tokio::spawn(async move {
        let result = deny_policy(&mut revocation).await;
        finish_transaction(revocation, result).await
    });
    wait_for_blocker(pool, revocation_pid, creation_pid).await?;
    creation.commit().await?;
    tokio::time::timeout(Duration::from_secs(10), revocation).await???;
    assert_no_policy_authority(pool, application).await?;
    restore_policy(pool).await?;
    assert_no_policy_authority(pool, application).await?;
    Ok(())
}

async fn new_application_grant_rechecks_policy_after_wait(pool: &PgPool) -> anyhow::Result<()> {
    restore_policy(pool).await?;
    let mut revocation = begin_policy_transaction(pool).await?;
    let revocation_pid = backend_pid(&mut revocation).await?;
    deny_policy(&mut revocation).await?;
    let mut creation = begin_policy_transaction(pool).await?;
    let creation_pid = backend_pid(&mut creation).await?;
    insert_uncommitted_application(
        &mut creation,
        Uuid::from_u128(0x173),
        "test_org>policy-race-blocked",
    )
    .await?;
    select_runtime_actor(&mut creation).await?;
    let creation = tokio::spawn(async move {
        let result = configure_restricted_scope(&mut creation, Uuid::from_u128(0x173)).await;
        finish_transaction(creation, result).await
    });
    wait_for_blocker(pool, creation_pid, revocation_pid).await?;
    revocation.commit().await?;
    let result = tokio::time::timeout(Duration::from_secs(10), creation).await??;
    ensure!(
        matches!(result, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
        "a grant waiting on policy revocation must recheck the committed policy: {result:?}"
    );
    assert_no_policy_authority(pool, Uuid::from_u128(0x173)).await?;
    Ok(())
}
