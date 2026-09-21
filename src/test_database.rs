//! Disposable integration databases on a local PostgreSQL server or Docker.

use anyhow::{Context as _, ensure};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;

pub(crate) struct TestDatabase {
    pub(crate) pool: PgPool,
    pub(crate) url: String,
    _container: Option<ContainerAsync<Postgres>>,
    cleanup: Option<(String, String)>,
}

impl TestDatabase {
    pub(crate) async fn start() -> anyhow::Result<Self> {
        let (url, container, cleanup) = match std::env::var("IAM_TEST_DATABASE_ADMIN_URL") {
            Ok(value) => {
                let mut url = url::Url::parse(&value)?;
                ensure!(
                    matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
                    "integration database administrator must be on loopback"
                );
                let admin = PgPool::connect(&value).await?;
                let database = format!("iam_fixture_{}", uuid::Uuid::now_v7().simple());
                sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
                    .execute(&admin)
                    .await
                    .context("create isolated integration database")?;
                admin.close().await;
                url.set_path(&database);
                (url.to_string(), None, Some((value, database)))
            }
            Err(std::env::VarError::NotPresent) => {
                let container = Postgres::default().with_tag("16-alpine").start().await?;
                let host = container.get_host().await?;
                let port = container.get_host_port_ipv4(5432).await?;
                (
                    format!("postgres://postgres:postgres@{host}:{port}/postgres"),
                    Some(container),
                    None,
                )
            }
            Err(error) => return Err(error.into()),
        };
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await?;
        // Docker gives each plane its own cluster. Native fixtures may share
        // cluster roles, so initialize every plane explicitly and idempotently.
        sqlx::raw_sql(
            "DO $$ DECLARE role_name text; BEGIN \
             FOREACH role_name IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator'] LOOP \
             BEGIN EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', role_name); \
             EXCEPTION WHEN duplicate_object THEN NULL; END; END LOOP; END $$;",
        )
        .execute(&pool)
        .await?;
        Ok(Self {
            pool,
            url,
            _container: container,
            cleanup,
        })
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let Some((admin_url, database)) = self.cleanup.take() else {
            return;
        };
        // Only the exact database this instance created is eligible for cleanup.
        // A separate runtime prevents nested-runtime blocking in async tests.
        let cleanup = std::thread::spawn(move || -> anyhow::Result<()> {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let admin = PgPoolOptions::new()
                        .max_connections(1)
                        .connect(&admin_url)
                        .await?;
                    sqlx::query(sqlx::AssertSqlSafe(format!(
                        "DROP DATABASE {database} WITH (FORCE)"
                    )))
                    .execute(&admin)
                    .await?;
                    admin.close().await;
                    Ok(())
                })
        })
        .join();
        match cleanup {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "isolated integration database cleanup failed");
            }
            Err(_) => tracing::warn!("isolated integration database cleanup thread failed"),
        }
    }
}
