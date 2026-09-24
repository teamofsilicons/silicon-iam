//! Restricted-role authorization and bounded concurrency for the scoped hot path.
#![allow(clippy::too_many_lines)]

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::domain::id::Id;
use anyhow::{Context as _, ensure};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use tokio::{sync::Barrier, task::JoinSet};

const SUBJECT: Id = Id::fixture("c:test_carbon");
const APPLICATION: Id = Id::fixture("app-alpha");
const MEMBER: Id = Id::from_u128(0x31);
const WORLD: Id = Id::from_u128(0xa001);
const MIGRATION: &str =
    include_str!("../../../migrations/0094_membership_authorization_join_planning.sql");

#[derive(Clone, Copy)]
struct Check {
    principal: Id,
    application: Option<Id>,
    token: Id,
    membership: Id,
}

const CARBON: Check = Check {
    principal: SUBJECT,
    application: None,
    token: Id::from_u128(0x101),
    membership: MEMBER,
};
const CARBON_BOUND: Check = Check {
    token: Id::from_u128(0x102),
    ..CARBON
};
const SILICON: Check = Check {
    principal: Id::fixture("si:planner_silicon"),
    application: None,
    token: Id::from_u128(0x551),
    membership: Id::from_u128(0x531),
};
const SILICON_BOUND: Check = Check {
    token: Id::from_u128(0x552),
    ..SILICON
};
const POSITIVE: [Check; 4] = [CARBON, CARBON_BOUND, SILICON, SILICON_BOUND];

#[allow(
    clippy::large_types_passed_by_value,
    reason = "test fixtures intentionally copy bounded canonical authority snapshots"
)]
async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    world: Option<Id>,
    input: Check,
) -> anyhow::Result<bool> {
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT set_config('iam.principal_id',$1,true),set_config('iam.application_id',$2,true),set_config('iam.testing_environment_id',$3,true)")
        .bind(input.principal.to_string())
        .bind(input.application.map(|id| id.to_string()).unwrap_or_default())
        .bind(world.map(|id| id.to_string()).unwrap_or_default())
        .execute(&mut **tx).await?;
    let allowed =
        sqlx::query_scalar("SELECT iam_private.application_token_allows_membership($1,$2)")
            .bind(input.token)
            .bind(input.membership)
            .fetch_one(&mut **tx)
            .await?;
    let planner: String = sqlx::query_scalar("SHOW join_collapse_limit")
        .fetch_one(&mut **tx)
        .await?;
    ensure!(
        planner == "8",
        "function-local planner setting leaked into its caller"
    );
    Ok(allowed)
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "test fixtures intentionally copy bounded canonical authority snapshots"
)]
async fn read(pool: &PgPool, world: Option<Id>, input: Check) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    let value = authorize(&mut tx, world, input).await?;
    tx.rollback().await?;
    Ok(value)
}

#[tokio::test]
#[ignore = "requires Docker or local PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL"]
async fn membership_join_planning_preserves_authority_and_bounds_concurrent_work()
-> anyhow::Result<()> {
    let production_database = crate::test_database::TestDatabase::start().await?;
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let production = admin_pool(&production_database.url, None).await?;
    let testing = admin_pool(&testing_database.url, Some(WORLD)).await?;
    let runtime_role = format!("iam_planner_{}", uuid::Uuid::now_v7().simple());
    for pool in [&production, &testing] {
        sqlx::raw_sql("DO $$ DECLARE name text; BEGIN FOREACH name IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator'] LOOP IF to_regrole(name) IS NULL THEN EXECUTE format('CREATE ROLE %I NOLOGIN',name); END IF; END LOOP; END $$;").execute(pool).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DO $$ BEGIN IF to_regrole('{runtime_role}') IS NULL THEN CREATE ROLE {runtime_role} LOGIN PASSWORD 'disposable-planner-test' IN ROLE silicon_iam_api; END IF; END $$;"))).execute(pool).await?;
    }
    super::migrate(&production).await?;
    super::migrate_testing(&testing).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    for (label, admin, world, database_url) in [
        ("production", &production, None, &production_database.url),
        ("testing", &testing, Some(WORLD), &testing_database.url),
    ] {
        crate::features::applications::live_tests::seed_protocol_rows(admin).await?;
        sqlx::raw_sql(include_str!("membership_planning_seed.sql"))
            .execute(admin)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
            .execute(admin)
            .await?;
        let mut runtime_url = url::Url::parse(database_url)?;
        runtime_url
            .set_username(&runtime_role)
            .map_err(|()| anyhow::anyhow!("runtime username"))?;
        runtime_url
            .set_password(Some("disposable-planner-test"))
            .map_err(|()| anyhow::anyhow!("runtime password"))?;
        let runtime = PgPoolOptions::new()
            .max_connections(2)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(3))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET statement_timeout='10s'")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(runtime_url.as_str())
            .await?;
        let (superuser, bypass): (bool, bool) =
            sqlx::query_as("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")
                .fetch_one(&runtime)
                .await?;
        ensure!(
            !superuser && !bypass,
            "requests require a restricted runtime login"
        );
        check_metadata(admin).await?;
        Box::pin(authority_matrix(admin, &runtime, world))
            .await
            .with_context(|| label.to_owned())?;
        // 0094 only changes a planner setting; both arguments are resource
        // UUIDs (token and membership), so its signature survives 0111 intact.
        // The current canonical body, owner, security mode and ACL must remain
        // unchanged when this historical setting-only migration is reapplied.
        let identity = function_identity(admin).await?;
        sqlx::query("ALTER FUNCTION iam_private.application_token_allows_membership(uuid,uuid) RESET join_collapse_limit")
            .execute(admin).await?;
        let baseline = concurrent(&runtime, world, true).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(MIGRATION))
            .execute(admin)
            .await?;
        ensure!(
            function_identity(admin).await? == identity,
            "0094 changed authorization semantics or privileges"
        );
        check_metadata(admin).await?;
        let optimized = concurrent(&runtime, world, false).await?;
        // Report timing rather than imposing a machine-dependent speed ratio.
        // Old-code checkout timeouts are diagnostic, not failures of the fix.
        // Every admitted baseline check and all 12 optimized checks must pass.
        eprintln!(
            "membership planning {label}: 12 requests/pool2; baseline total={:.1}ms max={:.1}ms checkout_timeouts={}; function-local total={:.1}ms max={:.1}ms checkout_timeouts={}",
            baseline.0, baseline.1, baseline.2, optimized.0, optimized.1, optimized.2
        );
        runtime.close().await;
    }
    for pool in [&production, &testing] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP ROLE IF EXISTS {runtime_role}"
        )))
        .execute(pool)
        .await?;
    }
    testing.close().await;
    production.close().await;
    Ok(())
}

async fn admin_pool(database_url: &str, world: Option<Id>) -> anyhow::Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(3)
        .after_connect(move |connection, _| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                    .bind(world.map(|id| id.to_string()).unwrap_or_default())
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await?)
}

async fn function_identity(pool: &PgPool) -> anyhow::Result<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('body',prosrc,'owner',proowner,'definer',prosecdef,'volatility',provolatile,'acl',proacl::text,'search_path',(SELECT setting FROM unnest(proconfig) setting WHERE setting LIKE 'search_path=%')) FROM pg_proc WHERE oid='iam_private.application_token_allows_membership(uuid,uuid)'::regprocedure")
        .fetch_one(pool).await?)
}

async fn check_metadata(pool: &PgPool) -> anyhow::Result<()> {
    let (configured,public_execute): (bool,bool) = sqlx::query_as("SELECT 'join_collapse_limit=1'=ANY(proconfig),EXISTS(SELECT 1 FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') FROM pg_proc WHERE oid='iam_private.application_token_allows_membership(uuid,uuid)'::regprocedure")
        .fetch_one(pool).await?;
    let identity = function_identity(pool).await?;
    ensure!(
        configured && !public_execute,
        "planner setting or EXECUTE boundary changed"
    );
    ensure!(identity["definer"] == true && identity["volatility"] == "s");
    ensure!(identity["search_path"] == "search_path=pg_catalog, iam, iam_private");
    Ok(())
}

async fn authority_matrix(
    admin: &PgPool,
    runtime: &PgPool,
    world: Option<Id>,
) -> anyhow::Result<()> {
    for input in POSITIVE {
        ensure!(
            read(runtime, world, input).await?,
            "valid Carbon/Silicon chain denied"
        );
        ensure!(
            read(
                runtime,
                world,
                Check {
                    principal: APPLICATION,
                    application: Some(APPLICATION),
                    ..input
                }
            )
            .await?,
            "exact client context denied"
        );
    }
    for input in [
        Check {
            principal: Id::fixture("c:test_admin"),
            ..CARBON
        },
        Check {
            principal: APPLICATION,
            ..CARBON
        },
        Check {
            principal: APPLICATION,
            application: Some(Id::fixture("app-beta")),
            ..CARBON
        },
        Check {
            token: Id::from_u128(0x103),
            ..CARBON
        },
        Check {
            membership: Id::from_u128(0x32),
            ..CARBON
        },
        Check {
            membership: SILICON.membership,
            ..CARBON_BOUND
        },
        Check {
            membership: MEMBER,
            ..SILICON_BOUND
        },
        Check {
            token: Id::nil(),
            ..CARBON
        },
    ] {
        ensure!(
            !read(runtime, world, input).await?,
            "mismatched token, actor, application or membership admitted"
        );
    }
    if world.is_some() {
        for input in POSITIVE {
            ensure!(
                !read(runtime, Some(Id::from_u128(0xa002)), input).await?,
                "authorization crossed testing worlds"
            );
        }
    }
    for (label, statement, input) in [
        (
            "revoked token",
            "UPDATE iam.access_tokens SET revoked_at=now(),revocation_reason='test' WHERE id='00000000-0000-0000-0000-000000000101'",
            CARBON,
        ),
        (
            "stale subject epoch",
            "UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='c:test_carbon'",
            CARBON,
        ),
        (
            "stale client epoch",
            "UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='app-alpha'",
            CARBON,
        ),
        (
            "stale membership epoch",
            "UPDATE iam.organization_memberships SET authz_epoch=authz_epoch+1 WHERE id='00000000-0000-0000-0000-000000000031'",
            CARBON_BOUND,
        ),
        (
            "stale Silicon membership epoch",
            "UPDATE iam.organization_memberships SET authz_epoch=authz_epoch+1 WHERE id='00000000-0000-0000-0000-000000000531'",
            SILICON_BOUND,
        ),
        (
            "revoked consent",
            "UPDATE iam.oauth_consent_grants SET status='revoked',revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000071'",
            CARBON,
        ),
        (
            "revoked Silicon consent",
            "UPDATE iam.oauth_consent_grants SET status='revoked',revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000571'",
            SILICON,
        ),
        (
            "unselected membership",
            "UPDATE iam.oauth_consent_grants SET selected_membership_ids='{}' WHERE id='00000000-0000-0000-0000-000000000071'",
            CARBON,
        ),
        (
            "unselected Silicon membership",
            "UPDATE iam.oauth_consent_grants SET selected_membership_ids='{}' WHERE id='00000000-0000-0000-0000-000000000571'",
            SILICON,
        ),
        (
            "expired session",
            "UPDATE iam.authentication_sessions SET created_at=now()-interval '2 days',idle_expires_at=now()-interval '1 day' WHERE id='00000000-0000-0000-0000-000000000041'",
            CARBON,
        ),
        (
            "revoked session",
            "UPDATE iam.authentication_sessions SET status='revoked',revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000041'",
            CARBON,
        ),
        (
            "removed Silicon",
            "UPDATE iam.organization_memberships SET status='removed',removed_at=now() WHERE id='00000000-0000-0000-0000-000000000531'",
            SILICON,
        ),
    ] {
        let mut tx = admin.begin().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
            .execute(&mut *tx)
            .await
            .with_context(|| label.to_owned())?;
        ensure!(
            !authorize(&mut tx, world, input).await?,
            "{label} remained authorized"
        );
        tx.rollback().await?;
    }
    // The active bound consent cannot fill a missing selected membership on
    // the unbound consent, and changing one grant does not revoke the other.
    let mut tx = admin.begin().await?;
    sqlx::query("UPDATE iam.oauth_consent_grants SET selected_membership_ids='{}' WHERE id='00000000-0000-0000-0000-000000000071'").execute(&mut *tx).await?;
    ensure!(!authorize(&mut tx, world, CARBON).await?);
    ensure!(authorize(&mut tx, world, CARBON_BOUND).await?);
    tx.rollback().await?;
    Ok(())
}

async fn concurrent(
    pool: &PgPool,
    world: Option<Id>,
    baseline: bool,
) -> anyhow::Result<(f64, f64, u32)> {
    let barrier = Arc::new(Barrier::new(12));
    let mut tasks = JoinSet::new();
    let start = Instant::now();
    for index in 0..12 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            let request_start = Instant::now();
            ensure!(
                read(&pool, world, POSITIVE[index % POSITIVE.len()]).await?,
                "concurrent valid chain denied"
            );
            anyhow::Ok(request_start.elapsed().as_secs_f64() * 1000.0)
        });
    }
    let mut maximum = 0.0_f64;
    let mut queue_timeouts = 0;
    while let Some(result) = tasks.join_next().await {
        match result? {
            Ok(elapsed) => maximum = maximum.max(elapsed),
            Err(error)
                if baseline
                    && matches!(
                        error.downcast_ref::<sqlx::Error>(),
                        Some(sqlx::Error::PoolTimedOut)
                    ) =>
            {
                queue_timeouts += 1;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((
        start.elapsed().as_secs_f64() * 1000.0,
        maximum,
        queue_timeouts,
    ))
}
