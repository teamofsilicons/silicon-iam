//! Independent app logins share parent IAM authority, but never revocation.
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use anyhow::{Context as _, ensure};
use sqlx::{PgPool, postgres::PgPoolOptions};

use super::*;
use crate::{
    config::Settings,
    infrastructure::{
        crypto::CryptoService,
        providers::NotificationProviders,
        testing_plane::{self, SelectedEnvironment},
    },
};

const APP: Id = Id::fixture("test_org>app-alpha");
const SESSION: Id = Id::from_u128(0x41);
const ENVIRONMENT: Id = Id::from_u128(0x801);

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL plus synthetic IAM settings"]
async fn oauth_family_logout_and_reuse_preserve_sibling_logins() -> anyhow::Result<()> {
    for testing in [false, true] {
        let database = crate::test_database::TestDatabase::start().await?;
        let pool = PgPoolOptions::new()
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    if testing {
                        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                            .bind(ENVIRONMENT.to_string())
                            .execute(connection)
                            .await?;
                    }
                    Ok(())
                })
            })
            .connect(&database.url)
            .await?;
        if testing {
            crate::infrastructure::postgres::migrate_testing(&pool).await?;
        } else {
            crate::infrastructure::postgres::migrate(&pool).await?;
        }
        super::super::live_tests::seed_protocol_rows(&pool).await?;
        let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
            .execute(&pool)
            .await?;
        let settings = Settings::from_env()?;
        let state = ApiState {
            pool: PgPoolOptions::new()
                .after_connect(|connection, _| {
                    Box::pin(async move {
                        sqlx::query("SET ROLE silicon_iam_api")
                            .execute(connection)
                            .await?;
                        Ok(())
                    })
                })
                .connect(&database.url)
                .await?,
            testing: None,
            crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
            notifications: NotificationProviders::from_settings(&settings.providers)?,
            workos: None,
            settings: Arc::new(settings),
        };
        let checks = Box::pin(async {
            for reuse in [false, true] {
                assert_family_boundary(&state, &pool, reuse).await?;
            }
            anyhow::Ok(())
        });
        if testing {
            testing_plane::scope(
                SelectedEnvironment {
                    id: ENVIRONMENT,
                    organization_id: Id::from_u128(0x21),
                },
                checks,
            )
            .await?;
        } else {
            checks.await?;
        }
        state.pool.close().await;
        pool.close().await;
    }
    Ok(())
}

async fn assert_family_boundary(
    state: &ApiState,
    pool: &PgPool,
    reuse: bool,
) -> anyhow::Result<()> {
    let client = ApplicationIdentity {
        application_id: APP,
        app_id: APP.to_string(),
        organization_id: Id::from_u128(0x21),
        auth_epoch: 1,
    };
    let mut tx = context::begin(&state.pool, DatabaseContext::application(APP, APP)).await?;
    let first = issue(&mut tx, state, &client, None).await?;
    let first_ids = refresh_ids(&mut tx, state, &first.refresh_token).await?;
    let rotated = issue(&mut tx, state, &client, Some(&first_ids)).await?;
    let sibling = issue(&mut tx, state, &client, None).await?;
    let sibling_ids = refresh_ids(&mut tx, state, &sibling.refresh_token).await?;
    ensure!(
        first_ids.0 != sibling_ids.0,
        "new logins must have distinct families"
    );
    tx.commit().await?;
    for token in [
        &first.access_token,
        &rotated.access_token,
        &sibling.access_token,
    ] {
        ensure!(
            access_is_active(state, token).await?,
            "issued access must authenticate"
        );
    }
    let mut tx = context::begin(&state.pool, DatabaseContext::application(APP, APP)).await?;
    if reuse {
        ensure!(
            compromise_refresh_family(&mut tx, first_ids.0, SESSION, APP)
                .await
                .map_err(|e| anyhow::anyhow!("{e:?}"))?
        );
    } else {
        ensure!(
            revoke_refresh_family(
                &mut tx,
                state,
                &client,
                &SecretString::from(rotated.refresh_token)
            )
            .await
            .map_err(|e| anyhow::anyhow!("{e:?}"))?
                == Some(first_ids.0)
        );
    }
    tx.commit().await?;
    ensure!(!access_is_active(state, &first.access_token).await?);
    ensure!(!access_is_active(state, &rotated.access_token).await?);
    ensure!(
        access_is_active(state, &sibling.access_token).await?,
        "sibling access was revoked"
    );
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT status='active' FROM iam.authentication_sessions WHERE id=$1"
        )
        .bind(SESSION)
        .fetch_one(pool)
        .await?,
        "parent IAM session must survive"
    );
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam.refresh_tokens WHERE family_id=$1 AND revoked_at IS NULL"
        )
        .bind(first_ids.0)
        .fetch_one(pool)
        .await?
            == 0,
        "all target refresh tokens must be revoked"
    );
    // Rotate the surviving sibling through the real issuer and verify its new
    // access survives too. Its parent ID and family link must remain intact.
    let mut tx = context::begin(&state.pool, DatabaseContext::application(APP, APP)).await?;
    ensure!(sqlx::query_scalar::<_, bool>(
        "SELECT family.status='active' AND token.revoked_at IS NULL AND token.consumed_at IS NULL FROM iam.refresh_tokens token JOIN iam.refresh_token_families family ON family.id=token.family_id WHERE token.id=$1"
    ).bind(sibling_ids.1).fetch_one(&mut *tx).await?);
    let sibling_rotated = issue(&mut tx, state, &client, Some(&sibling_ids)).await?;
    tx.commit().await?;
    ensure!(access_is_active(state, &sibling_rotated.access_token).await?);
    Ok(())
}

async fn issue(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationIdentity,
    parent: Option<&(Id, Id)>,
) -> anyhow::Result<TokenResponse> {
    issue_tokens(
        tx,
        state,
        client,
        TokenSubject {
            session_id: SESSION,
            principal_id: Id::fixture("test_carbon"),
            subject_kind: "carbon".to_owned(),
            subject_auth_epoch: 1,
            organization_id: None,
            membership_id: None,
            membership_authz_epoch: None,
            consent_grant_id: Id::from_u128(0x71),
            org_id: None,
            subject_public_id: "test_carbon".to_owned(),
        },
        &["self.organizations.read".to_owned()],
        parent.map(|p| p.0),
        parent.map(|p| p.1),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e:?}"))
}

async fn refresh_ids(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    raw: &str,
) -> anyhow::Result<(Id, Id)> {
    let digest = state.crypto.digest_secret(
        DigestPurpose::OAuthRefreshToken,
        &SecretString::from(raw.to_owned()),
    )?;
    Ok(sqlx::query_as("SELECT family_id,id FROM iam.refresh_tokens WHERE token_digest=$1 AND digest_key_version=$2")
        .bind(digest.as_bytes().as_slice()).bind(digest.key_version()).fetch_one(&mut **tx).await?)
}

async fn access_is_active(state: &ApiState, raw: &str) -> anyhow::Result<bool> {
    Ok(tokens::authenticate(
        &state.pool,
        &state.crypto,
        &SecretString::from(raw.to_owned()),
    )
    .await?
    .is_some())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL"]
async fn oauth_family_migration_backfills_only_unambiguous_live_issuance() -> anyhow::Result<()> {
    let database = crate::test_database::TestDatabase::start().await?;
    let pool = &database.pool;
    let migrations = sqlx::migrate!("./migrations");
    let old = sqlx::migrate::Migrator::with_migrations(
        migrations
            .iter()
            .filter(|m| m.version < 116)
            .cloned()
            .collect(),
    );
    old.run(pool).await?;
    super::super::live_tests::seed_protocol_rows(pool).await?;
    // Manufacture two matching historical families in one transaction. Never
    // silently select one of those ambiguous matches.
    sqlx::query("UPDATE iam.refresh_tokens SET created_at=created_at+interval '1 microsecond' WHERE id='00000000-0000-0000-0000-000000000095'")
        .execute(pool).await?;
    let mut tx = pool.begin().await?;
    let error = sqlx::raw_sql(include_str!(
        "../../../migrations/0116_oauth_access_refresh_family.sql"
    ))
    .execute(&mut *tx)
    .await
    .err()
    .context("ambiguous live access must stop migration")?;
    ensure!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
            == Some("23514")
    );
    tx.rollback().await?;
    // Give the second issuance its own transaction timestamp, as real login
    // requests do; an unrelated expired token needs no invented family link.
    sqlx::raw_sql("UPDATE iam.refresh_tokens SET created_at=created_at+interval '1 microsecond' WHERE family_id='00000000-0000-0000-0000-000000000093'; UPDATE iam.access_tokens SET created_at=created_at+interval '1 microsecond' WHERE id='00000000-0000-0000-0000-000000000102'; UPDATE iam.access_tokens SET created_at=created_at-interval '1 hour',expires_at=expires_at-interval '1 hour' WHERE id='00000000-0000-0000-0000-000000000103';")
        .execute(pool).await?;
    migrations.run(pool).await?;
    let rows: Vec<(Id, Option<Id>)> =
        sqlx::query_as("SELECT id,oauth_refresh_family_id FROM iam.access_tokens ORDER BY id")
            .fetch_all(pool)
            .await?;
    ensure!(
        rows == vec![
            (Id::from_u128(0x101), Some(Id::from_u128(0x91))),
            (Id::from_u128(0x102), Some(Id::from_u128(0x93))),
            (Id::from_u128(0x103), None)
        ]
    );
    // A family cannot be attached to a different app, even if the caller has
    // administrator access to the database.
    let error = sqlx::query("UPDATE iam.access_tokens SET oauth_refresh_family_id=$1 WHERE id=$2")
        .bind(Id::from_u128(0x91))
        .bind(Id::from_u128(0x103))
        .execute(pool)
        .await
        .err()
        .context("cross-client family must fail")?;
    ensure!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
            == Some("23503")
    );
    // Retention may delete a terminal family before an old access row; only
    // the optional association is cleared, never the token's parent identity.
    sqlx::raw_sql("UPDATE iam.refresh_token_families SET status='revoked',revoked_at=transaction_timestamp()-interval '2 days' WHERE id='00000000-0000-0000-0000-000000000091'; UPDATE iam.access_tokens SET revoked_at=transaction_timestamp()-interval '2 days' WHERE oauth_refresh_family_id='00000000-0000-0000-0000-000000000091'; SELECT * FROM iam_private.run_worker_retention_maintenance('refresh_token_families',1,1,1,1,1,1,100);")
        .execute(pool).await?;
    ensure!(sqlx::query_scalar::<_, bool>("SELECT oauth_refresh_family_id IS NULL AND authentication_session_id=$1 FROM iam.access_tokens WHERE id=$2")
        .bind(SESSION).bind(Id::from_u128(0x101)).fetch_one(pool).await?);
    Ok(())
}
