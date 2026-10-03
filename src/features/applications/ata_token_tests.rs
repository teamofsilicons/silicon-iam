//! ATA isolation, receiver authority, expiry, dependency and rotation coverage.
#![allow(clippy::too_many_lines)]
use anyhow::{Context as _, ensure};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions, types::Json};
use uuid::Uuid;
const WORLD: &str = "00000000-0000-0000-0000-000000000801";
const OTHER_WORLD: &str = "00000000-0000-0000-0000-000000000802";
struct Fixture {
    _database: crate::test_database::TestDatabase,
    pool: PgPool,
    testing: bool,
}
impl Fixture {
    async fn new(testing: bool) -> anyhow::Result<Self> {
        let database = crate::test_database::TestDatabase::start().await?;
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .after_connect(move |c, _| {
                Box::pin(async move {
                    if testing {
                        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                            .bind(WORLD)
                            .execute(c)
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
        sqlx::raw_sql(include_str!("obo_disclosure_seed.sql"))
            .execute(&pool)
            .await?;
        sqlx::raw_sql("INSERT INTO iam.principals(id,kind,status,activated_at) VALUES('store','application','active',now()); INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,app_name,base_url,review_status) VALUES('store','store','00000000-0000-0000-0000-000000000023','c:test_admin','Store','https://store.example.test','verified');").execute(&pool).await?;
        let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|l| !l.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
            .execute(&pool)
            .await?;
        let fixture = Self {
            _database: database,
            pool,
            testing,
        };
        for (app, path, downstream) in [
            ("store", "/ata/write", json!([])),
            (
                "target",
                "/ata/read",
                json!([{"audience":"store","endpoint_id":"write"}]),
            ),
        ] {
            let mut tx = fixture.context("c:test_admin", "", None).await?;
            sqlx::query("SELECT iam_private.configure_application_ata_endpoints($1,$2)")
    .bind(app).bind(Json(json!([{"endpoint_id":if app=="store"{"write"}else{"read"},"name":"Work","description":"Application storage action","path":path,"critical":false,"metadata":{},"note_to_user":null,"additional_warnings":[],"enabled":true,"downstream":downstream}])))
    .execute(&mut *tx).await?;
            tx.commit().await?;
        }
        Ok(fixture)
    }
    async fn context(
        &self,
        principal: &str,
        app: &str,
        world: Option<&str>,
    ) -> anyhow::Result<Transaction<'_, Postgres>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE silicon_iam_api")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('iam.principal_id',$1,true),set_config('iam.application_id',$2,true),set_config('iam.testing_environment_id',$3,true)")
   .bind(principal).bind(app).bind(world.unwrap_or(if self.testing{WORLD}else{""})).execute(&mut *tx).await?;
        Ok(tx)
    }
    async fn create(&self, seed: u8, ttl: i32, expires: Option<i64>) -> anyhow::Result<Uuid> {
        let mut tx = self.context("c:test_admin", "", None).await?;
        let roots = json!([{"audience":"target","endpoint_id":"read"}]);
        let Json(graph): Json<Value> =
            sqlx::query_scalar("SELECT iam_private.application_ata_graph('app-alpha',$1)")
                .bind(Json(&roots))
                .fetch_one(&mut *tx)
                .await?;
        ensure!(graph.as_array().is_some_and(|v| v.len() == 2));
        let id = Uuid::now_v7();
        let Json(created): Json<Value> = sqlx::query_scalar(
            "SELECT iam_private.ata_verification_create('app-alpha',$1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(id)
        .bind(Json(roots))
        .bind(Json(graph))
        .bind(vec!["target", "store"])
        .bind(expires)
        .bind(ttl)
        .bind(Json(credential(seed)))
        .fetch_one(&mut *tx)
        .await?;
        ensure!(created["signing_principal"]["id"] == "c:test_admin");
        ensure!(created["expires_at"].is_null() == expires.is_none());
        ensure!(created.get("refresh_token").is_none());
        tx.commit().await?;
        Ok(id)
    }
    async fn refresh(&self, seed: u8, next: u8, app: &str) -> anyhow::Result<Value> {
        let mut tx = self.context(app, app, None).await?;
        let Json(result): Json<Value> =
            sqlx::query_scalar("SELECT iam_private.ata_token_refresh($1,$2)")
                .bind(Json(candidates(seed)))
                .bind(Json(pair(next)))
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(result)
    }
    async fn verify(
        &self,
        seed: u8,
        app: &str,
        origin: &str,
        path: &str,
        world: Option<&str>,
    ) -> anyhow::Result<Value> {
        let mut tx = self.context(app, app, world).await?;
        let Json(result): Json<Value> =
            sqlx::query_scalar("SELECT iam_private.ata_token_verify($1,$2,$3)")
                .bind(origin)
                .bind(Json(candidates(seed)))
                .bind(path)
                .fetch_one(&mut *tx)
                .await?;
        tx.rollback().await?;
        Ok(result)
    }
}
fn credential(seed: u8) -> Value {
    json!({"id":Uuid::now_v7(),"digest":format!("{seed:02x}").repeat(32),"key_version":1})
}
fn candidates(seed: u8) -> Value {
    json!([{"digest":format!("{seed:02x}").repeat(32),"key_version":1}])
}
fn pair(seed: u8) -> Value {
    json!({"access":credential(seed),"refresh":credential(seed+1)})
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn ata_shared_token_recipient_endpoint_expiry_rotation_and_testing_boundaries()
-> anyhow::Result<()> {
    for testing in [false, true] {
        let f = Fixture::new(testing).await?;
        let verification = f.create(10, 1800, None).await?;
        ensure!(
            f.refresh(10, 20, "store").await.is_err(),
            "recipient obtained root refresh authority"
        );
        let issued = f.refresh(10, 20, "app-alpha").await?;
        ensure!(
            issued["expires_in"]
                .as_i64()
                .is_some_and(|seconds| (1790..=1800).contains(&seconds))
        );
        for (receiver, path) in [("target", "/ata/read"), ("store", "/ata/write")] {
            let proof = f.verify(20, receiver, "app-alpha", path, None).await?;
            ensure!(
                proof["verified"] == true
                    && proof["valid_till"]
                        .as_i64()
                        .is_some_and(|n| n > 20_260_000_000_000)
            );
        }
        for proof in [
            f.verify(20, "target", "app-beta", "/ata/read", None)
                .await?,
            f.verify(20, "target", "app-alpha", "/ata/write", None)
                .await?,
            f.verify(20, "app-beta", "app-alpha", "/ata/read", None)
                .await?,
            f.verify(99, "target", "app-alpha", "/ata/read", None)
                .await?,
        ] {
            ensure!(
                proof == json!({"verified":false}),
                "invalid proof disclosed differing details: {proof}"
            );
        }
        if testing {
            ensure!(
                f.verify(20, "target", "app-alpha", "/ata/read", Some(OTHER_WORLD))
                    .await?
                    == json!({"verified":false})
            );
        }
        // The immutable signer is an audit record; leaving the owner organization does not stop app authority.
        sqlx::query("UPDATE iam.organization_memberships SET status='removed',removed_at=now() WHERE id='00000000-0000-0000-0000-000000000032'").execute(&f.pool).await?;
        ensure!(
            f.verify(20, "target", "app-alpha", "/ata/read", None)
                .await?["verified"]
                == true
        );
        let rotated = f.refresh(21, 30, "app-alpha").await?;
        ensure!(rotated["verification_id"] == verification.to_string());
        ensure!(f.refresh(10, 40, "app-alpha").await?["error"] == "ata_refresh_reused");
        ensure!(
            f.verify(20, "store", "app-alpha", "/ata/write", None)
                .await?
                == json!({"verified":false})
        );
        ensure!(
            f.verify(30, "target", "app-alpha", "/ata/read", None)
                .await?
                == json!({"verified":false})
        );
        f.pool.close().await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn ata_graph_changes_expiry_and_explicit_revocation_fail_closed() -> anyhow::Result<()> {
    let f = Fixture::new(false).await?;
    ensure!(f.create(45, 59, None).await.is_err());
    ensure!(f.create(46, 86401, None).await.is_err());
    ensure!(f.create(47, 60, Some(3599)).await.is_err());
    let verification = f.create(50, 60, Some(3600)).await?;
    f.refresh(50, 60, "app-alpha").await?;
    sqlx::query("UPDATE iam.ata_access_tokens SET expires_at=now()-interval '1 second' WHERE verification_id=$1").bind(verification).execute(&f.pool).await?;
    ensure!(
        f.verify(60, "target", "app-alpha", "/ata/read", None)
            .await?
            == json!({"verified":false})
    );
    f.refresh(61, 70, "app-alpha").await?;
    let mut tx = f.context("c:test_admin", "", None).await?;
    sqlx::query_scalar::<_, Json<Value>>(
        "SELECT iam_private.ata_verification_revoke('app-alpha',$1)",
    )
    .bind(verification)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    ensure!(
        f.verify(70, "target", "app-alpha", "/ata/read", None)
            .await?
            == json!({"verified":false})
    );
    let _ = f.create(80, 60, None).await?;
    f.refresh(80, 90, "app-alpha").await?;
    sqlx::query(
        "UPDATE iam.application_ata_endpoints SET version=version+1 WHERE application_id='store'",
    )
    .execute(&f.pool)
    .await?;
    ensure!(
        f.verify(90, "target", "app-alpha", "/ata/read", None)
            .await?
            == json!({"verified":false}),
        "changed downstream definition retained old authority"
    );
    ensure!(f.refresh(91, 100, "app-alpha").await.is_err());
    f.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn ata_concurrent_refresh_detects_reuse_without_deadlock() -> anyhow::Result<()> {
    let f = Fixture::new(false).await?;
    f.create(110, 1800, None).await?;
    let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            f.refresh(110, 120, "app-alpha"),
            f.refresh(110, 130, "app-alpha")
        )
    })
    .await
    .context("concurrent ATA refresh deadlocked")?;
    let a = a?;
    let b = b?;
    ensure!((a.get("error").is_some()) != (b.get("error").is_some()));
    ensure!(
        f.verify(120, "target", "app-alpha", "/ata/read", None)
            .await?
            == json!({"verified":false})
    );
    ensure!(
        f.verify(130, "target", "app-alpha", "/ata/read", None)
            .await?
            == json!({"verified":false})
    );
    f.pool.close().await;
    Ok(())
}
