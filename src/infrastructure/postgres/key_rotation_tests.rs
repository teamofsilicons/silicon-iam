//! Live PostgreSQL coverage for the runtime-key rotation state machine.
//!
//! This test is ignored by default because it requires a local Docker daemon.

use anyhow::ensure;
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;

use super::{RuntimeKeyPurpose, activate_runtime_key_version, migrate};

#[tokio::test]
#[ignore = "requires a local Docker daemon"]
#[allow(
    clippy::too_many_lines,
    reason = "one live test deliberately exercises the complete monotonic rotation state machine"
)]
async fn activation_is_preloaded_monotonic_and_stale_startup_safe() -> anyhow::Result<()> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(5432).await?;
    let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await?;
    sqlx::raw_sql(
        "CREATE ROLE silicon_iam_key_operator NOLOGIN; \
         CREATE ROLE silicon_iam_worker NOLOGIN; \
         CREATE ROLE key_rotation_test_operator LOGIN PASSWORD 'operator-test-password' \
           NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS \
           IN ROLE silicon_iam_key_operator; \
         CREATE ROLE worker_keyring_test LOGIN PASSWORD 'worker-test-password' \
           NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS \
           IN ROLE silicon_iam_worker;",
    )
    .execute(&pool)
    .await?;
    migrate(&pool).await?;
    sqlx::raw_sql(
        "GRANT USAGE ON SCHEMA iam_private TO silicon_iam_key_operator, silicon_iam_worker; \
         GRANT EXECUTE ON FUNCTION iam_private.activate_runtime_key_version( \
           text, smallint, smallint \
         ) TO silicon_iam_key_operator; \
         GRANT EXECUTE ON FUNCTION iam_private.reconcile_worker_contact_aead_keyring( \
           smallint, smallint[] \
         ) TO silicon_iam_worker;",
    )
    .execute(&pool)
    .await?;
    let operator_database_url = format!(
        "postgres://key_rotation_test_operator:operator-test-password@{host}:{port}/postgres"
    );
    let operator_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&operator_database_url)
        .await?;
    let worker_database_url =
        format!("postgres://worker_keyring_test:worker-test-password@{host}:{port}/postgres");
    let worker_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&worker_database_url)
        .await?;

    ensure!(
        reconcile_worker_contact_aead(&pool, 1, &[1]).await.is_err(),
        "database owner unexpectedly passed worker-role attestation"
    );
    reconcile_worker_contact_aead(&worker_pool, 1, &[1]).await?;
    ensure!(
        sqlx::query("SELECT iam_private.reconcile_runtime_keyring($1, $2, $3)")
            .bind("token_hmac")
            .bind(1_i16)
            .bind(vec![1_i16])
            .execute(&worker_pool)
            .await
            .is_err(),
        "worker unexpectedly retained generic key-purpose reconciliation authority"
    );

    reconcile(&pool, 1, &[1, 2]).await?;
    assert_statuses(&pool, &[(1, "active"), (2, "decrypt_only")]).await?;

    ensure!(
        activate_runtime_key_version(&pool, RuntimeKeyPurpose::TokenHmac, 1, 2)
            .await
            .is_err(),
        "database owner unexpectedly passed operator-role attestation"
    );
    let first =
        activate_runtime_key_version(&operator_pool, RuntimeKeyPurpose::TokenHmac, 1, 2).await?;
    ensure!(
        first.previous_version == 1 && first.active_version == 2,
        "operator activation returned an unexpected transition"
    );
    assert_statuses(&pool, &[(1, "decrypt_only"), (2, "active")]).await?;

    ensure!(
        reconcile(&pool, 1, &[1, 2]).await.is_err(),
        "a stale startup accepted a database-active version mismatch"
    );
    assert_statuses(&pool, &[(1, "decrypt_only"), (2, "active")]).await?;

    ensure!(
        reconcile(&pool, 2, &[2]).await.is_err(),
        "startup accepted a missing decrypt-only local version"
    );
    ensure!(
        activate_runtime_key_version(&operator_pool, RuntimeKeyPurpose::TokenHmac, 2, 1)
            .await
            .is_err(),
        "operator activation accepted a downgrade"
    );
    ensure!(
        activate_runtime_key_version(&operator_pool, RuntimeKeyPurpose::TokenHmac, 2, 2)
            .await
            .is_err(),
        "operator activation accepted the current version"
    );

    reconcile(&pool, 2, &[1, 2, 3]).await?;
    let second =
        activate_runtime_key_version(&operator_pool, RuntimeKeyPurpose::TokenHmac, 2, 3).await?;
    ensure!(
        second.previous_version == 2 && second.active_version == 3,
        "second operator activation returned an unexpected transition"
    );
    assert_statuses(
        &pool,
        &[(1, "decrypt_only"), (2, "decrypt_only"), (3, "active")],
    )
    .await?;

    let history_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.runtime_key_activations WHERE purpose = 'token_hmac'",
    )
    .fetch_one(&pool)
    .await?;
    ensure!(history_count == 2, "activation history was not append-only");

    let duplicate_active = sqlx::query(
        "INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status) \
         VALUES ('token_hmac', 4, 'active')",
    )
    .execute(&pool)
    .await;
    ensure!(
        duplicate_active.is_err(),
        "database accepted two active versions for one purpose"
    );

    worker_pool.close().await;
    operator_pool.close().await;
    pool.close().await;
    Ok(())
}

async fn reconcile_worker_contact_aead(
    pool: &PgPool,
    current: i16,
    local: &[i16],
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT iam_private.reconcile_worker_contact_aead_keyring($1, $2)")
        .bind(current)
        .bind(local.to_vec())
        .execute(pool)
        .await?;
    Ok(())
}

async fn reconcile(pool: &PgPool, current: i16, local: &[i16]) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT iam_private.reconcile_runtime_keyring($1, $2, $3)")
        .bind("token_hmac")
        .bind(current)
        .bind(local.to_vec())
        .execute(pool)
        .await?;
    Ok(())
}

async fn assert_statuses(pool: &PgPool, expected: &[(i16, &str)]) -> anyhow::Result<()> {
    let actual = sqlx::query_as::<_, (i16, String)>(
        "SELECT key_version, status FROM iam.cryptographic_key_versions \
         WHERE purpose = 'token_hmac' ORDER BY key_version",
    )
    .fetch_all(pool)
    .await?;
    let expected = expected
        .iter()
        .map(|(version, status)| (*version, (*status).to_owned()))
        .collect::<Vec<_>>();
    ensure!(actual == expected, "unexpected runtime-key metadata state");
    Ok(())
}
