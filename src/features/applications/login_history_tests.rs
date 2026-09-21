//! A hidden directory handle must not make authorized application history fail.

use crate::domain::id::Id;
use anyhow::ensure;
use axum::{http::StatusCode, response::IntoResponse as _};
use sqlx::{PgPool, postgres::PgPoolOptions};

use super::{applications::resolve_readable_app, cursor::Cursor, webhooks::login_history_items};

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; checks login history against restricted production and testing roles"]
async fn login_history_preserves_events_for_inaccessible_silicon_actors() -> anyhow::Result<()> {
    let production_database = crate::test_database::TestDatabase::start().await?;
    let production = production_database.pool.clone();
    sqlx::raw_sql("DO $$ BEGIN CREATE ROLE silicon_iam_api NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$; DO $$ BEGIN CREATE ROLE silicon_iam_worker NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$; DO $$ BEGIN CREATE ROLE silicon_iam_key_operator NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;")
        .execute(&production).await?;
    crate::infrastructure::postgres::migrate(&production).await?;
    seed_history(&production).await?;
    assert_history(&production, false).await?;
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let testing = PgPoolOptions::new().max_connections(3)
        .after_connect(|connection, _| Box::pin(async move {
            sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-000000000801',false)")
                .execute(connection).await?;
            Ok(())
        }))
        .connect(&testing_database.url).await?;
    crate::infrastructure::postgres::migrate_testing(&testing).await?;
    seed_history(&testing).await?;
    assert_history(&testing, true).await?;
    testing.close().await;
    production.close().await;
    Ok(())
}

async fn seed_history(pool: &PgPool) -> anyhow::Result<()> {
    super::live_tests::seed_protocol_rows(pool).await?;
    sqlx::raw_sql(r"
        BEGIN;
        INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
        VALUES ('00000000-0000-0000-0000-000000000022', 'other_org',
                'test_admin', 'Other Organization');
        INSERT INTO iam.organization_memberships
            (id, organization_id, principal_id, principal_kind, org_role)
        VALUES ('00000000-0000-0000-0000-000000000033',
                '00000000-0000-0000-0000-000000000022',
                'test_admin', 'carbon', 'owner');
        INSERT INTO iam.principals (id, kind, status, activated_at)
        VALUES ('test_silicon:other_org', 'silicon', 'active', transaction_timestamp());
        INSERT INTO iam.organization_memberships
            (id, organization_id, principal_id, principal_kind, org_role)
        VALUES ('00000000-0000-0000-0000-000000000531',
                '00000000-0000-0000-0000-000000000022',
                'test_silicon:other_org', 'silicon', 'member');
        INSERT INTO iam.silicons
            (id, organization_id, membership_id, organization_handle, silicon_handle, display_name, provisioning_status)
        VALUES ('test_silicon:other_org',
                '00000000-0000-0000-0000-000000000022',
                '00000000-0000-0000-0000-000000000531', 'other_org', 'test_silicon', 'Test Silicon', 'active');
        INSERT INTO iam.authentication_events
            (id, event_type, outcome, subject_principal_id, subject_kind, application_id, organization_id, request_id)
        VALUES
          ('00000000-0000-0000-0000-000000000601', 'oauth.authorization', 'success',
           'test_carbon', 'carbon',
           'test_org>app-alpha', '00000000-0000-0000-0000-000000000021',
           '00000000-0000-0000-0000-000000000611'),
          ('00000000-0000-0000-0000-000000000602', 'oauth.token_exchange', 'failure',
           'test_silicon:other_org', 'silicon',
           'test_org>app-alpha', '00000000-0000-0000-0000-000000000022',
           '00000000-0000-0000-0000-000000000612'),
          ('00000000-0000-0000-0000-000000000603', 'oauth.token_exchange', 'success',
           'test_silicon:other_org', 'silicon',
           'test_org>app-beta', '00000000-0000-0000-0000-000000000022',
           '00000000-0000-0000-0000-000000000613');
        COMMIT;
    ").execute(pool).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(pool)
        .await?;
    Ok(())
}

async fn assert_history(pool: &PgPool, testing: bool) -> anyhow::Result<()> {
    let actor_id = Id::fixture("test_carbon");
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('iam.principal_id',$1,true)")
        .bind(actor_id.to_string())
        .execute(&mut *tx)
        .await?;
    let app = resolve_readable_app(&mut tx, actor_id, "test_org>app-alpha", false)
        .await
        .map_err(history_error)?;
    let hidden: i64 =
        sqlx::query_scalar("SELECT count(*) FROM iam.silicons WHERE id='test_silicon:other_org'")
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        hidden == 0,
        "the unrelated Silicon's directory row must stay private"
    );
    let events = login_history_items(&mut tx, app.id, None, 1)
        .await
        .map_err(history_error)?;
    ensure!(
        events.len() == 2,
        "the first page includes one lookahead, but not another app's event"
    );
    let hidden_event = &events[0];
    ensure!(hidden_event.actor.actor_type == "silicon" && hidden_event.actor.public_id.is_none());
    ensure!(hidden_event.actor.principal_id == Id::fixture("test_silicon:other_org"));
    ensure!(hidden_event.org_id.is_none() && !hidden_event.success);
    ensure!(hidden_event.event_type == "oauth_token_exchange");
    ensure!(hidden_event.request_id == Id::from_u128(0x612).to_string());
    let value = serde_json::to_value(hidden_event)?;
    ensure!(value["actor"]["public_id"].is_null());
    let next = login_history_items(
        &mut tx,
        app.id,
        Some(Cursor {
            at: hidden_event.occurred_at,
            id: hidden_event.id,
        }),
        1,
    )
    .await
    .map_err(history_error)?;
    ensure!(next.len() == 1 && next[0].actor.public_id.as_deref() == Some("test_carbon"));
    ensure!(next[0].success && next[0].id != hidden_event.id);
    if testing {
        sqlx::query("SELECT set_config('iam.testing_environment_id','00000000-0000-0000-0000-000000000802',true)")
            .execute(&mut *tx).await?;
    } else {
        sqlx::query("SELECT set_config('iam.principal_id','',true)")
            .execute(&mut *tx)
            .await?;
    }
    let Err(error) = resolve_readable_app(&mut tx, actor_id, "test_org>app-alpha", false).await
    else {
        anyhow::bail!("an unavailable application must not authorize history access");
    };
    ensure!(error.into_response().status() == StatusCode::NOT_FOUND);
    tx.rollback().await?;
    Ok(())
}

fn history_error(error: super::error::ApiError) -> anyhow::Error {
    anyhow::anyhow!("login history failed: {}", error.into_response().status())
}
