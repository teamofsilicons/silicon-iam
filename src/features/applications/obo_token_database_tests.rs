//! Restricted-role SQL coverage for graph changes, rotating credentials and testing isolation.
#![allow(clippy::too_many_lines)]

use anyhow::{Context as _, ensure};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions, types::Json};
use uuid::Uuid;

const WORLD: &str = "00000000-0000-0000-0000-000000000801";
const OTHER_WORLD: &str = "00000000-0000-0000-0000-000000000802";
const APP_TOKEN: &str = "00000000-0000-0000-0000-000000000101";
const USER_TOKEN: &str = "00000000-0000-0000-0000-000000000201";

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
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    if testing {
                        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                            .bind(WORLD)
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
        sqlx::raw_sql(include_str!("obo_disclosure_seed.sql"))
            .execute(&pool)
            .await?;
        super::protocol_tests::seed_chain(&pool).await?;
        sqlx::query("UPDATE iam.access_tokens SET oauth_refresh_family_id='00000000-0000-0000-0000-000000000091' WHERE id=$1::text::uuid")
            .bind(APP_TOKEN).execute(&pool).await?;
        let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
            .execute(&pool)
            .await?;
        Ok(Self {
            _database: database,
            pool,
            testing,
        })
    }

    async fn context(
        &self,
        principal: &str,
        application: &str,
        world: Option<&str>,
    ) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE silicon_iam_api")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('iam.principal_id',$1,true),set_config('iam.application_id',$2,true),set_config('iam.testing_environment_id',$3,true)")
            .bind(principal).bind(application).bind(world.unwrap_or(if self.testing {WORLD} else {""})).execute(&mut *tx).await?;
        Ok(tx)
    }

    async fn request(&self) -> anyhow::Result<Uuid> {
        let id = Uuid::now_v7();
        let mut tx = self.context("app-alpha", "app-alpha", None).await?;
        sqlx::query_scalar::<_, Json<Value>>(
            "SELECT iam_private.obo_authorization_create($1::text::uuid,'test_org',$2,$3)",
        )
        .bind(APP_TOKEN)
        .bind(Json(
            json!([{"audience":"target","endpoint_id":"files.read"}]),
        ))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    async fn read(&self, request: Uuid) -> anyhow::Result<Value> {
        let mut tx = self.context("c:test_carbon", "", None).await?;
        let result =
            sqlx::query_scalar::<_, Json<Value>>("SELECT iam_private.obo_authorization_read($1)")
                .bind(request)
                .fetch_one(&mut *tx)
                .await?
                .0;
        tx.commit().await?;
        Ok(result)
    }

    async fn approve(&self, request: Uuid, version: i64, seed: u8) -> Result<Value, sqlx::Error> {
        let mut tx = self.context("c:test_carbon", "", None).await?;
        let result = sqlx::query_scalar::<_, Json<Value>>(
            "SELECT iam_private.obo_authorization_decide($1,$2::text::uuid,$3,true,$4)",
        )
        .bind(request)
        .bind(USER_TOKEN)
        .bind(version)
        .bind(Json(credential(seed)))
        .fetch_one(&mut *tx)
        .await;
        match result {
            Ok(Json(value)) => {
                tx.commit().await?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }

    async fn issue(&self, seed: u8) -> anyhow::Result<Issued> {
        let request = self.request().await?;
        self.approve(request, 1, seed).await?;
        let pair = pair(seed + 1);
        let mut tx = self.context("app-alpha", "app-alpha", None).await?;
        let result = sqlx::query_scalar::<_, Json<Value>>(
            "SELECT iam_private.obo_authorization_redeem($1,$2,$3)",
        )
        .bind(request)
        .bind(Json(candidates(seed)))
        .bind(Json(json!([pair])))
        .fetch_one(&mut *tx)
        .await?
        .0;
        tx.commit().await?;
        let row = &result["items"][0];
        Ok(Issued {
            request,
            grant: Uuid::parse_str(row["grant_id"].as_str().context("grant id")?)?,
            access: Uuid::parse_str(row["token_id"].as_str().context("access id")?)?,
            access_seed: seed + 1,
            refresh_seed: seed + 2,
        })
    }

    async fn verify(&self, issued: &Issued, world: Option<&str>) -> Result<Value, sqlx::Error> {
        let mut tx = self.context("target", "target", world).await?;
        let result = sqlx::query_scalar::<_, Json<Value>>(
            "SELECT iam_private.obo_token_verify($1,'files.read','POST','/files')",
        )
        .bind(Json(candidates(issued.access_seed)))
        .fetch_one(&mut *tx)
        .await;
        tx.rollback().await?;
        result.map(|Json(value)| value)
    }
}
struct Issued {
    request: Uuid,
    grant: Uuid,
    access: Uuid,
    access_seed: u8,
    refresh_seed: u8,
}
fn credential(seed: u8) -> Value {
    json!({"id":Uuid::now_v7(),"key_version":1,"digest":format!("{seed:02x}").repeat(32),"iam_disclosures_reviewed":true})
}
fn candidates(seed: u8) -> Value {
    json!([{"key_version":1,"digest":format!("{seed:02x}").repeat(32)}])
}
fn pair(seed: u8) -> Value {
    json!({"family_id":Uuid::now_v7(),"access":credential(seed),"refresh":credential(seed+1)})
}
fn is_error(error: &sqlx::Error, message: &str) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.message() == message)
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn obo_database_graph_versions_and_irreversible_removal() -> anyhow::Result<()> {
    let fixture = Fixture::new(false).await?;
    let root = fixture.issue(151).await?;
    // Administrative endpoint updates lock the endpoint before revoking its
    // grants. Verification must wait without holding the grant in reverse order.
    let mut administration = fixture.pool.begin().await?;
    sqlx::query("SELECT endpoint_id FROM iam.application_obo_endpoints WHERE application_id='target' FOR UPDATE")
        .execute(&mut *administration).await?;
    let mut verification = Box::pin(fixture.verify(&root, None));
    ensure!(
        tokio::time::timeout(std::time::Duration::from_millis(150), &mut verification)
            .await
            .is_err(),
        "verification did not wait on the endpoint lock"
    );
    tokio::time::timeout(std::time::Duration::from_secs(3),
        sqlx::query("UPDATE iam.application_obo_endpoints SET downstream='[]' WHERE application_id='target'").execute(&mut *administration)
    ).await.context("endpoint/grant lock order deadlocked")??;
    administration.rollback().await?;
    ensure!(
        tokio::time::timeout(std::time::Duration::from_secs(3), verification).await??["active"]
            == true
    );
    let pending = fixture.request().await?;
    let before = fixture.read(pending).await?;
    sqlx::raw_sql(r#"
      INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical)
      VALUES('00000000-0000-0000-0000-000000000023','store','blobs.extra','/extra','{}',false);
      UPDATE iam.applications SET app_scope=jsonb_set(app_scope,'{external}',app_scope->'external'||'[{"app_id":"store","endpoint_id":"blobs.extra"}]') WHERE id='target';
      INSERT INTO iam.oauth_scope_catalog(scope,description) VALUES('obo:store:blobs.extra','Extra');
      INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES('target','obo:store:blobs.extra');
      INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES('target','obo:store:blobs.extra','c:test_carbon');
      UPDATE iam.application_obo_endpoints SET downstream=downstream||'[{"audience":"store","endpoint_id":"blobs.extra"}]'::jsonb WHERE application_id='target';
    "#).execute(&fixture.pool).await?;
    ensure!(
        fixture.verify(&root, None).await?["active"] == true,
        "addition revoked old subset"
    );
    let mut tx = fixture.context("target", "target", None).await?;
    let error = sqlx::query_scalar::<_, Json<Value>>(
        "SELECT iam_private.obo_token_delegate($1,'store','blobs.extra',$2)",
    )
    .bind(Json(candidates(root.access_seed)))
    .bind(Json(credential(161)))
    .fetch_one(&mut *tx)
    .await
    .err()
    .context("new edge must need consent")?;
    ensure!(is_error(&error, "obo_dependency_not_approved"));
    tx.rollback().await?;
    let after = fixture.read(pending).await?;
    ensure!(after["version"] == 2 && after["expires_at"] == before["expires_at"]);
    ensure!(
        after["endpoints"][0]["downstream"]
            .as_array()
            .is_some_and(|items| items.len() == 2)
    );
    let stale = fixture
        .approve(pending, 1, 162)
        .await
        .err()
        .context("old screen must fail")?;
    ensure!(is_error(&stale, "obo_consent_changed"));
    fixture.approve(pending, 2, 162).await?;
    sqlx::query(
        "UPDATE iam.application_obo_endpoints SET downstream='[]' WHERE application_id='target'",
    )
    .execute(&fixture.pool)
    .await?;
    sqlx::query("UPDATE iam.application_obo_endpoints SET downstream='[{\"audience\":\"store\",\"endpoint_id\":\"blobs.write\"}]' WHERE application_id='target'").execute(&fixture.pool).await?;
    ensure!(is_error(
        &fixture
            .verify(&root, None)
            .await
            .err()
            .context("removed authority must stay revoked")?,
        "obo_access_token_invalid"
    ));
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM iam.obo_grants WHERE id=$1")
            .bind(root.grant)
            .fetch_one(&fixture.pool)
            .await?;
    ensure!(revoked);
    fixture.pool.close().await;
    Ok(())
}

async fn refresh_once(fixture: &Fixture, refresh_seed: u8, seed: u8) -> anyhow::Result<Value> {
    let mut tx = fixture.context("app-alpha", "app-alpha", None).await?;
    let result =
        sqlx::query_scalar::<_, Json<Value>>("SELECT iam_private.obo_token_refresh($1,$2)")
            .bind(Json(candidates(refresh_seed)))
            .bind(Json(pair(seed)))
            .fetch_one(&mut *tx)
            .await?
            .0;
    tx.commit().await?;
    Ok(result)
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn obo_database_concurrent_refresh_revokes_reused_family() -> anyhow::Result<()> {
    let fixture = Fixture::new(false).await?;
    let root = fixture.issue(171).await?;
    let (first, second) = tokio::join!(
        refresh_once(&fixture, root.refresh_seed, 181),
        refresh_once(&fixture, root.refresh_seed, 191)
    );
    let results = [first?, second?];
    ensure!(
        results
            .iter()
            .filter(|value| value["error"] == "obo_refresh_token_reused")
            .count()
            == 1
    );
    ensure!(
        results
            .iter()
            .filter(|value| value["items"].is_array())
            .count()
            == 1
    );
    let compromised: bool = sqlx::query_scalar("SELECT family.revoked_at IS NOT NULL AND family.revocation_reason='refresh_reuse' FROM iam.obo_token_families family JOIN iam.obo_access_tokens token ON token.family_id=family.id WHERE token.id=$1")
        .bind(root.access).fetch_one(&fixture.pool).await?;
    ensure!(compromised);
    ensure!(is_error(
        &fixture
            .verify(&root, None)
            .await
            .err()
            .context("compromised family must reject old token")?,
        "obo_access_token_invalid"
    ));
    let mut tx = fixture.context("app-alpha", "app-alpha", None).await?;
    let replay: Json<Value> = sqlx::query_scalar("SELECT iam_private.obo_token_result_is_live($1)")
        .bind(vec![root.access])
        .fetch_one(&mut *tx)
        .await?;
    ensure!(replay.0["active"] == false);
    tx.rollback().await?;
    fixture.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL testing plane"]
async fn obo_database_testing_generation_isolation_and_erasure() -> anyhow::Result<()> {
    let fixture = Fixture::new(true).await?;
    let root = fixture.issue(201).await?;
    ensure!(fixture.verify(&root, None).await?["active"] == true);
    ensure!(is_error(
        &fixture
            .verify(&root, Some(OTHER_WORLD))
            .await
            .err()
            .context("foreign testing token must fail")?,
        "obo_access_token_invalid"
    ));
    let mut tx = fixture
        .context("app-alpha", "app-alpha", Some(OTHER_WORLD))
        .await?;
    let error =
        sqlx::query_scalar::<_, Json<Value>>("SELECT iam_private.obo_authorization_read($1)")
            .bind(root.request)
            .fetch_one(&mut *tx)
            .await
            .err()
            .context("foreign request must fail")?;
    ensure!(is_error(&error, "obo_authorization_not_found"));
    tx.rollback().await?;
    sqlx::query("SELECT iam_private.set_testing_runtime_state($1::text::uuid,2,1,true)")
        .bind(WORLD)
        .execute(&fixture.pool)
        .await?;
    ensure!(is_error(
        &fixture
            .verify(&root, None)
            .await
            .err()
            .context("old generation must fail")?,
        "obo_access_token_invalid"
    ));
    sqlx::query("SELECT iam_private.erase_testing_environment($1::text::uuid)")
        .bind(WORLD)
        .execute(&fixture.pool)
        .await?;
    for table in [
        "obo_authorization_requests",
        "obo_authorization_codes",
        "obo_grants",
        "obo_token_families",
        "obo_access_tokens",
        "obo_refresh_tokens",
    ] {
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM iam.{table}"
        )))
        .fetch_one(&fixture.pool)
        .await?;
        ensure!(count == 0, "testing cleanup retained {table}");
    }
    fixture.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn obo_durable_shared_graph_token_survives_logout_and_checks_recipient() -> anyhow::Result<()>
{
    let fixture = Fixture::new(false).await?;
    let issued = fixture.issue(31).await?;
    let mut receiver = fixture.context("store", "store", None).await?;
    let Json(verified): Json<Value> =
        sqlx::query_scalar("SELECT iam_private.obo_token_verify($1,'blobs.write','POST','/blobs')")
            .bind(Json(candidates(issued.access_seed)))
            .fetch_one(&mut *receiver)
            .await?;
    ensure!(verified["active"] == true && verified["issuer_app_id"] == "target");
    ensure!(verified["endpoint"]["obo_id"] == "[store:obo:blobs.write]");
    receiver.rollback().await?;
    let mut wrong_receiver = fixture.context("app-alpha", "app-alpha", None).await?;
    ensure!(
        sqlx::query_scalar::<_, Json<Value>>(
            "SELECT iam_private.obo_token_verify($1,'blobs.write','POST','/blobs')",
        )
        .bind(Json(candidates(issued.access_seed)))
        .fetch_one(&mut *wrong_receiver)
        .await
        .is_err()
    );
    wrong_receiver.rollback().await?;
    sqlx::raw_sql("UPDATE iam.authentication_sessions SET status='revoked',revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000041'; UPDATE iam.refresh_token_families SET status='revoked',revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000091'; UPDATE iam.oauth_consent_grants SET status='revoked',revoked_at=now() WHERE application_id='app-alpha';")
        .execute(&fixture.pool).await?;
    ensure!(
        fixture.verify(&issued, None).await?["active"] == true,
        "ordinary logout revoked separate OBO permission"
    );
    ensure!(
        refresh_once(&fixture, issued.refresh_seed, 41).await?["items"][0]["token_id"].is_string()
    );
    // Removing the chosen membership is still immediate, irreversible revocation.
    sqlx::raw_sql("BEGIN; UPDATE iam.organization_memberships SET status='suspended',suspended_at=now(),org_role='member' WHERE id='00000000-0000-0000-0000-000000000031'; UPDATE iam.organization_memberships SET org_role='owner' WHERE id='00000000-0000-0000-0000-000000000032'; COMMIT;")
        .execute(&fixture.pool).await?;
    ensure!(fixture.verify(&issued, None).await.is_err());
    fixture.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn obo_provider_context_requires_token_proof_and_uses_selected_account_org()
-> anyhow::Result<()> {
    for testing in [false, true] {
        provider_context_disclosure_case(testing).await?;
    }
    Ok(())
}

async fn provider_context_disclosure_case(testing: bool) -> anyhow::Result<()> {
    const ADMIN_TOKEN: &str = "00000000-0000-0000-0000-000000000211";
    let fixture = Fixture::new(testing).await?;
    sqlx::raw_sql("INSERT INTO iam.authentication_sessions(id,subject_principal_id,subject_kind,authentication_method,assurance_level,subject_auth_epoch,idle_expires_at,absolute_expires_at) VALUES('00000000-0000-0000-0000-000000000042','c:test_admin','carbon','email_otp',1,1,now()+interval '1 day',now()+interval '2 days'); INSERT INTO iam.access_tokens(id,token_class,token_digest,digest_key_version,token_prefix,authentication_session_id,subject_principal_id,subject_kind,audience,subject_auth_epoch,expires_at) VALUES('00000000-0000-0000-0000-000000000211','carbon_access',decode(repeat('aa',32),'hex'),1,'cat_context1','00000000-0000-0000-0000-000000000042','c:test_admin','carbon','silicon-iam',1,now()+interval '1 hour'); INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000211','iam.self');")
        .execute(&fixture.pool).await?;
    let request = fixture.request().await?;
    let displayed = fixture.read(request).await?;
    let expected_disclosures = json!([
        "self.identity.read",
        "self.membership.read",
        "self.tags.read"
    ]);
    ensure!(displayed["endpoints"][0]["iam_disclosures"] == expected_disclosures);
    ensure!(displayed["endpoints"][0]["downstream"][0]["iam_disclosures"] == expected_disclosures);
    let mut old_client_code = credential(51);
    old_client_code
        .as_object_mut()
        .context("code object")?
        .remove("iam_disclosures_reviewed");
    let mut tx = fixture.context("c:test_carbon", "", None).await?;
    let missing_review = sqlx::query_scalar::<_, Json<Value>>(
        "SELECT iam_private.obo_authorization_decide($1,$2::text::uuid,1,true,$3)",
    )
    .bind(request)
    .bind(USER_TOKEN)
    .bind(Json(old_client_code))
    .fetch_one(&mut *tx)
    .await;
    ensure!(is_error(
        &missing_review
            .err()
            .context("old client must not approve unseen disclosures")?,
        "obo_disclosure_review_required"
    ));
    tx.rollback().await?;
    let contexts = json!([{"app_id":"store","org_id":"other_org","token_id":ADMIN_TOKEN,"digests":candidates(0xaa)}]);
    let mut forged = contexts.clone();
    forged[0]["digests"] = candidates(0xbb);
    for selections in [
        forged,
        json!([{"app_id":"store","org_id":"not_a_member","token_id":ADMIN_TOKEN,"digests":candidates(0xaa)}]),
    ] {
        let mut tx = fixture.context("c:test_carbon", "", None).await?;
        ensure!(
            sqlx::query_scalar::<_, Json<Value>>(
                "SELECT iam_private.obo_authorization_decide($1,$2::text::uuid,1,true,$3,$4)",
            )
            .bind(request)
            .bind(USER_TOKEN)
            .bind(Json(credential(51)))
            .bind(Json(selections))
            .fetch_one(&mut *tx)
            .await
            .is_err(),
            "forged account token or membership accepted"
        );
        tx.rollback().await?;
    }
    let mut tx = fixture.context("c:test_carbon", "", None).await?;
    sqlx::query_scalar::<_, Json<Value>>(
        "SELECT iam_private.obo_authorization_decide($1,$2::text::uuid,1,true,$3,$4)",
    )
    .bind(request)
    .bind(USER_TOKEN)
    .bind(Json(credential(51)))
    .bind(Json(contexts))
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut tx = fixture.context("app-alpha", "app-alpha", None).await?;
    let Json(pair): Json<Value> =
        sqlx::query_scalar("SELECT iam_private.obo_authorization_redeem($1,$2,$3)")
            .bind(request)
            .bind(Json(candidates(51)))
            .bind(Json(json!([pair(52)])))
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    ensure!(pair["items"][0]["actor"]["public_id"] == "c:test_carbon");
    let mut tx = fixture.context("target", "target", None).await?;
    let Json(delegated): Json<Value> =
        sqlx::query_scalar("SELECT iam_private.obo_token_delegate($1,'store','blobs.write',$2)")
            .bind(Json(candidates(52)))
            .bind(Json(credential(99)))
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        delegated["token_id"] == pair["items"][0]["token_id"],
        "delegation changed the shared token"
    );
    ensure!(
        delegated["actor"]["public_id"] == "c:test_admin" && delegated["org_id"] == "other_org",
        "delegation returned the root context"
    );
    ensure!(delegated["audience"] == "store" && delegated["endpoint_id"] == "blobs.write");
    tx.rollback().await?;
    let mut tx = fixture.context("store", "store", None).await?;
    let Json(verified): Json<Value> =
        sqlx::query_scalar("SELECT iam_private.obo_token_verify($1,'blobs.write','POST','/blobs')")
            .bind(Json(candidates(52)))
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        verified["actor"]["public_id"] == "c:test_admin" && verified["org_id"] == "other_org",
        "wrong selected provider authority: {verified}"
    );
    ensure!(
        verified["authorization"]["org_role"] == "owner"
            && verified["authorization"]["actor_type"] == "carbon"
            && verified["authorization"]["public_id"] == "c:test_admin"
            && verified["authorization"]["membership_id"] == "00000000-0000-0000-0000-000000000033",
        "selected account did not receive its explicitly approved disclosure snapshot: {verified}"
    );
    tx.rollback().await?;
    let mut tx = fixture.context("target", "target", None).await?;
    let Json(verified): Json<Value> =
        sqlx::query_scalar("SELECT iam_private.obo_token_verify($1,'files.read','POST','/files')")
            .bind(Json(candidates(52)))
            .fetch_one(&mut *tx)
            .await?;
    ensure!(verified["actor"]["public_id"] == "c:test_carbon" && verified["org_id"] == "test_org");
    tx.rollback().await?;
    let mut tx = fixture.context("c:test_admin", "", None).await?;
    sqlx::query_scalar::<_, Json<Value>>("SELECT iam_private.obo_grant_revoke($1,$2::text::uuid)")
        .bind(Uuid::parse_str(
            pair["items"][0]["grant_id"].as_str().context("grant")?,
        )?)
        .bind(ADMIN_TOKEN)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut tx = fixture.context("target", "target", None).await?;
    ensure!(
        sqlx::query_scalar::<_, Json<Value>>(
            "SELECT iam_private.obo_token_verify($1,'files.read','POST','/files')"
        )
        .bind(Json(candidates(52)))
        .fetch_one(&mut *tx)
        .await
        .is_err(),
        "selected downstream account could not revoke the grant"
    );
    tx.rollback().await?;
    fixture.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn obo_security_epoch_invalidates_credentials_without_erasing_consent() -> anyhow::Result<()>
{
    let fixture = Fixture::new(false).await?;
    let issued = fixture.issue(61).await?;
    sqlx::query("UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='target'")
        .execute(&fixture.pool)
        .await?;
    ensure!(
        fixture.verify(&issued, None).await.is_err(),
        "old credential survived recipient security reset"
    );
    ensure!(
        refresh_once(&fixture, issued.refresh_seed, 71)
            .await
            .is_err(),
        "old refresh credential survived reset"
    );
    let active: bool = sqlx::query_scalar("SELECT iam_private.obo_grant_is_live($1)")
        .bind(issued.grant)
        .fetch_one(&fixture.pool)
        .await?;
    ensure!(active, "credential reset erased durable permission");
    let mut tx = fixture.context("app-alpha", "app-alpha", None).await?;
    let Json(recovered): Json<Value> =
        sqlx::query_scalar("SELECT iam_private.obo_grant_recover($1,$2::text::uuid,$3)")
            .bind(issued.grant)
            .bind(APP_TOKEN)
            .bind(Json(pair(72)))
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    ensure!(recovered["items"][0]["grant_id"] == issued.grant.to_string());
    let mut tx = fixture.context("target", "target", None).await?;
    ensure!(
        sqlx::query_scalar::<_, Json<Value>>(
            "SELECT iam_private.obo_token_verify($1,'files.read','POST','/files')"
        )
        .bind(Json(candidates(72)))
        .fetch_one(&mut *tx)
        .await?
        .0["active"]
            == true
    );
    tx.rollback().await?;
    sqlx::query("UPDATE iam.obo_token_families SET revoked_at=now(),revocation_reason='security_reset' WHERE grant_id=$1")
        .bind(issued.grant).execute(&fixture.pool).await?;
    ensure!(
        refresh_once(&fixture, 73, 75).await.is_err(),
        "explicit family revocation was ignored"
    );
    fixture.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn application_login_requires_one_org_and_only_critical_iam_consent() -> anyhow::Result<()> {
    for testing in [false, true] {
        let f = Fixture::new(testing).await?;
        for ids in [
            Vec::<String>::new(),
            vec!["test_org".into(), "other_org".into()],
        ] {
            let mut tx = f.context("c:test_carbon", "", None).await?;
            let result = sqlx::query_scalar::<_, Vec<Uuid>>("SELECT iam_private.lock_account_login_organization_selection('c:test_carbon','00000000-0000-0000-0000-000000000041',$1,'app-alpha')")
                .bind(ids).fetch_one(&mut *tx).await;
            ensure!(
                result.is_err(),
                "application login accepted zero or multiple organizations"
            );
            tx.rollback().await?;
        }
        let mut tx = f.context("c:test_carbon", "", None).await?;
        let selected = sqlx::query_scalar::<_, Vec<Uuid>>("SELECT iam_private.lock_account_login_organization_selection('c:test_carbon','00000000-0000-0000-0000-000000000041',ARRAY['test_org'],'app-alpha')")
            .fetch_one(&mut *tx).await?;
        ensure!(selected == vec![Uuid::from_u128(0x31)]);
        tx.rollback().await?;
        sqlx::query("UPDATE iam.application_approved_scopes SET revoked_at=clock_timestamp(),revoked_by_policy=true WHERE application_id='app-alpha' AND scope NOT LIKE 'obo:%'").execute(&f.pool).await?;
        sqlx::query("INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES('app-alpha','self.identity.read','c:test_admin')").execute(&f.pool).await?;
        let mut tx = f.context("c:test_carbon", "", None).await?;
        let Json(policy): Json<Value> =
            sqlx::query_scalar("SELECT iam_private.application_login_scope_policy('app-alpha')")
                .fetch_one(&mut *tx)
                .await?;
        ensure!(policy["consent_required"] == false);
        ensure!(
            policy["scopes"]
                .as_array()
                .is_some_and(|s| s.len() == 1 && s[0]["scope"] == "self.identity.read")
        );
        tx.rollback().await?;
        let critical: String = sqlx::query_scalar("SELECT scope FROM iam_private.iam_scope_catalog() WHERE critical ORDER BY scope LIMIT 1").fetch_one(&f.pool).await?;
        sqlx::query("INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES('app-alpha',$1) ON CONFLICT DO NOTHING").bind(&critical).execute(&f.pool).await?;
        sqlx::query("INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES('app-alpha',$1,'c:test_admin')").bind(&critical).execute(&f.pool).await?;
        sqlx::query("UPDATE iam.organizations SET trusted_org=true,skip_application_consent=true WHERE id='00000000-0000-0000-0000-000000000021'").execute(&f.pool).await?;
        let mut tx = f.context("c:test_carbon", "", None).await?;
        let Json(policy): Json<Value> =
            sqlx::query_scalar("SELECT iam_private.application_login_scope_policy('app-alpha')")
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            policy["consent_required"] == true,
            "critical IAM consent bypassed by trusted organization"
        );
        ensure!(
            policy["scopes"]
                .as_array()
                .context("scope array")?
                .iter()
                .all(|s| s["scope"]
                    .as_str()
                    .is_some_and(|scope| !scope.starts_with("obo:")))
        );
        tx.rollback().await?;
        if testing {
            let mut tx = f.context("app-alpha", "app-alpha", None).await?;
            let binding: (Uuid,Uuid,String)=sqlx::query_as("SELECT organization_id,membership_id,org_id FROM iam_private.create_testing_actor_organization_login('app-alpha',1,'c:test_carbon',$1,$2,1800,'test_org')")
                .bind(Uuid::now_v7()).bind(Uuid::now_v7()).fetch_one(&mut *tx).await?;
            ensure!(
                binding
                    == (
                        Uuid::from_u128(0x21),
                        Uuid::from_u128(0x31),
                        "test_org".into()
                    )
            );
            tx.rollback().await?;
            let mut tx = f.context("app-alpha", "app-alpha", None).await?;
            let invalid=sqlx::query("SELECT * FROM iam_private.create_testing_actor_organization_login('app-alpha',1,'c:test_carbon',$1,$2,1800,'other_org')")
                .bind(Uuid::now_v7()).bind(Uuid::now_v7()).fetch_all(&mut *tx).await;
            ensure!(invalid.is_err());
            tx.rollback().await?;
        }
        f.pool.close().await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn directory_visibility_is_directional_filters_rls_and_preserves_self() -> anyhow::Result<()>
{
    for testing in [false, true] {
        let f = Fixture::new(testing).await?;
        let org = Uuid::from_u128(0x21);
        let owner = Uuid::from_u128(0x31);
        let admin = Uuid::from_u128(0x32);
        let mut tx = f.context("c:test_carbon", "", None).await?;
        let Json(policy): Json<Value> = sqlx::query_scalar(
            "SELECT iam_private.directory_visibility_replace($1,NULL,'self',ARRAY[]::text[],1)",
        )
        .bind(org)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(policy["version"] == 2 && policy["effective_mode"] == "self");
        tx.commit().await?;
        for (actor, expected) in [("c:test_carbon", owner), ("c:test_admin", admin)] {
            let mut tx = f.context(actor, "", None).await?;
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM iam.organization_memberships WHERE organization_id=$1 ORDER BY id",
            )
            .bind(org)
            .fetch_all(&mut *tx)
            .await?;
            ensure!(
                ids == vec![expected],
                "RLS list leaked hidden member for {actor}: {ids:?}"
            );
            let reference: Uuid =
                sqlx::query_scalar("SELECT iam_private.organization_owner_reference($1)")
                    .bind(org)
                    .fetch_one(&mut *tx)
                    .await?;
            ensure!(
                reference == owner,
                "hidden owner removed organization metadata"
            );
            tx.rollback().await?;
        }
        let mut tx = f.context("c:test_carbon", "", None).await?;
        let Json(policy):Json<Value>=sqlx::query_scalar("SELECT iam_private.directory_visibility_replace($1,$2,'selected',ARRAY['c:test_admin[test_org]'],1)").bind(org).bind(owner).fetch_one(&mut *tx).await?;
        ensure!(policy["effective_visible_membership_ids"] == json!(["c:test_admin[test_org]"]));
        tx.commit().await?;
        let mut tx = f.context("c:test_carbon", "", None).await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM iam.organization_memberships WHERE organization_id=$1 ORDER BY id",
        )
        .bind(org)
        .fetch_all(&mut *tx)
        .await?;
        ensure!(ids == vec![owner, admin]);
        tx.rollback().await?;
        let mut tx = f.context("c:test_admin", "app-alpha", None).await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM iam.organization_memberships WHERE organization_id=$1 ORDER BY id",
        )
        .bind(org)
        .fetch_all(&mut *tx)
        .await?;
        ensure!(
            ids == vec![admin],
            "visibility accidentally became reciprocal or application bearer bypassed it"
        );
        let tags: i64 =
            sqlx::query_scalar("SELECT count(*) FROM iam.membership_tags WHERE organization_id=$1")
                .bind(org)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(tags == 0, "hidden member's tags leaked");
        tx.rollback().await?;
        for (targets, version) in [
            (vec!["c:test_admin[other_org]"], 2),
            (vec!["c:test_admin[test_org]"], 1),
        ] {
            let mut tx = f.context("c:test_carbon", "", None).await?;
            ensure!(
                sqlx::query(
                    "SELECT iam_private.directory_visibility_replace($1,$2,'selected',$3,$4)"
                )
                .bind(org)
                .bind(owner)
                .bind(targets)
                .bind(i64::from(version))
                .execute(&mut *tx)
                .await
                .is_err()
            );
            tx.rollback().await?;
        }
        let mut tx = f.context("c:test_carbon", "", None).await?;
        sqlx::query(
            "SELECT iam_private.directory_visibility_replace($1,$2,'inherit',ARRAY[]::text[],2)",
        )
        .bind(org)
        .bind(owner)
        .execute(&mut *tx)
        .await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM iam.organization_memberships WHERE organization_id=$1 ORDER BY id",
        )
        .bind(org)
        .fetch_all(&mut *tx)
        .await?;
        ensure!(ids == vec![owner]);
        tx.rollback().await?;
        f.pool.close().await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn silicon_invitation_requires_shared_org_and_target_account_acceptance() -> anyhow::Result<()>
{
    for testing in [false, true] {
        let f = Fixture::new(testing).await?;
        sqlx::raw_sql("BEGIN; INSERT INTO iam.principals(id,kind,status,activated_at) VALUES('si:invited','silicon','active',now()),('si:waiting','silicon','active',now()); INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES('00000000-0000-0000-0000-000000000535','00000000-0000-0000-0000-000000000023','si:invited','silicon','member'),('00000000-0000-0000-0000-000000000536','00000000-0000-0000-0000-000000000023','si:waiting','silicon','member'); INSERT INTO iam.silicons(id,organization_id,membership_id,organization_handle,silicon_handle,display_name,provisioning_status) VALUES('si:invited','00000000-0000-0000-0000-000000000023','00000000-0000-0000-0000-000000000535','other_org','invited','Invited','active'),('si:waiting','00000000-0000-0000-0000-000000000023','00000000-0000-0000-0000-000000000536','other_org','waiting','Waiting','active'); COMMIT;").execute(&f.pool).await?;
        let invite = Uuid::now_v7();
        let org = Uuid::from_u128(0x21);
        let mut tx = f.context("c:test_carbon", "", None).await?;
        ensure!(
            sqlx::query("SELECT iam_private.silicon_invitation_create($1,'si:invited',$2)")
                .bind(org)
                .bind(invite)
                .execute(&mut *tx)
                .await
                .is_err(),
            "invited silicon from organization actor does not belong to"
        );
        tx.rollback().await?;
        sqlx::query("INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES('00000000-0000-0000-0000-000000000534','00000000-0000-0000-0000-000000000023','c:test_carbon','carbon','member')").execute(&f.pool).await?;
        let Json(custody): Json<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM iam.silicon_custodians c WHERE silicon_id='si:invited'",
        )
        .fetch_one(&f.pool)
        .await?;
        let mut tx = f.context("c:test_carbon", "", None).await?;
        sqlx::query("SELECT iam_private.silicon_invitation_create($1,'si:invited',$2)")
            .bind(org)
            .bind(invite)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let mut tx = f.context("c:test_admin", "", None).await?;
        ensure!(
            sqlx::query("SELECT iam_private.silicon_invitation_decide($1,'accept')")
                .bind(invite)
                .execute(&mut *tx)
                .await
                .is_err(),
            "custodian/other Carbon accepted invitation as Silicon"
        );
        tx.rollback().await?;
        let mut tx = f.context("si:invited", "", None).await?;
        let Json(accepted): Json<Value> =
            sqlx::query_scalar("SELECT iam_private.silicon_invitation_decide($1,'accept')")
                .bind(invite)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(accepted["membership_id"] == "si:invited[test_org]");
        tx.commit().await?;
        let Json(after): Json<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM iam.silicon_custodians c WHERE silicon_id='si:invited'",
        )
        .fetch_one(&f.pool)
        .await?;
        ensure!(custody == after, "joining changed Silicon custody");
        let session = Uuid::now_v7();
        sqlx::query("INSERT INTO iam.authentication_sessions(id,subject_principal_id,subject_kind,authentication_method,assurance_level,subject_auth_epoch,idle_expires_at,absolute_expires_at,identity_only) VALUES($1,'si:invited','silicon','silicon_credential',1,1,now()+interval '1 day',now()+interval '1 day',true)").bind(session).execute(&f.pool).await?;
        let mut tx = f.context("si:invited", "", None).await?;
        let chosen:Vec<Uuid>=sqlx::query_scalar("SELECT iam_private.lock_account_login_organization_selection('si:invited',$1,ARRAY['test_org'],'app-alpha')").bind(session).fetch_one(&mut *tx).await?;
        ensure!(chosen.len() == 1);
        tx.rollback().await?;
        let consent = Uuid::now_v7();
        sqlx::query("INSERT INTO iam.oauth_consent_grants(id,application_id,subject_principal_id,subject_kind,organization_id,membership_id,parent_authentication_session_id,selected_membership_ids) VALUES($1,'app-alpha','si:invited','silicon',$2,$3,$4,ARRAY[$3])").bind(consent).bind(org).bind(chosen[0]).bind(session).execute(&f.pool).await?;
        let mut tx = f.context("app-alpha", "app-alpha", None).await?;
        let binding:String=sqlx::query_scalar("SELECT org_id FROM iam_private.lock_current_application_oauth_subject_authority('app-alpha',$1,$2,'si:invited','silicon',$3,$4)").bind(consent).bind(session).bind(org).bind(chosen[0]).fetch_one(&mut *tx).await?;
        ensure!(binding == "test_org");
        tx.rollback().await?;
        let pending = Uuid::now_v7();
        let mut tx = f.context("c:test_carbon", "", None).await?;
        sqlx::query("SELECT iam_private.silicon_invitation_create($1,'si:waiting',$2)")
            .bind(org)
            .bind(pending)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        sqlx::query("UPDATE iam.organization_memberships SET status='removed',removed_at=now() WHERE id='00000000-0000-0000-0000-000000000534'").execute(&f.pool).await?;
        let mut tx = f.context("si:waiting", "", None).await?;
        ensure!(
            sqlx::query("SELECT iam_private.silicon_invitation_decide($1,'accept')")
                .bind(pending)
                .execute(&mut *tx)
                .await
                .is_err(),
            "acceptance ignored inviter losing shared source organization"
        );
        tx.rollback().await?;
        f.pool.close().await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; isolated PostgreSQL"]
async fn obo_disclosure_review_tracks_declared_approvals_without_login_inheritance()
-> anyhow::Result<()> {
    for testing in [false, true] {
        let f = Fixture::new(testing).await?;
        // An origin login cannot approve another account's disclosures. The new
        // OBO screen makes its own explicit, bounded disclosure decision.
        sqlx::query("DELETE FROM iam.oauth_consent_grant_scopes WHERE scope IN ('self.identity.read','self.membership.read','self.tags.read')")
            .execute(&f.pool).await?;
        let request = f.request().await?;
        let shown = f.read(request).await?;
        ensure!(
            shown["endpoints"][0]["iam_disclosures"]
                == json!([
                    "self.identity.read",
                    "self.membership.read",
                    "self.tags.read"
                ])
        );
        // A provider's declaration narrows every descendant path, even if the
        // administrator's older approval row is still active.
        sqlx::query("UPDATE iam.applications SET app_scope=jsonb_set(app_scope,'{iam}',(app_scope->'iam')-'self.membership.read') WHERE id='target'")
            .execute(&f.pool).await?;
        let error = f
            .approve(request, 1, 201)
            .await
            .err()
            .context("old review must fail")?;
        ensure!(is_error(&error, "obo_consent_changed"));
        let refreshed = f.read(request).await?;
        ensure!(refreshed["version"] == 2);
        let bounded = json!(["self.identity.read", "self.tags.read"]);
        ensure!(refreshed["endpoints"][0]["iam_disclosures"] == bounded);
        ensure!(refreshed["endpoints"][0]["downstream"][0]["iam_disclosures"] == bounded);
        f.approve(request, 2, 202).await?;
        let issued = f.issue(204).await?;
        let verified = f.verify(&issued, None).await?;
        ensure!(verified["authorization"]["org_role"].is_null());
        ensure!(verified["authorization"]["public_id"] == "c:test_carbon");
        ensure!(
            verified["authorization"]["scopes"]
                == json!([
                    "obo:target:files.read",
                    "self.identity.read",
                    "self.tags.read"
                ])
        );
        // Approved-scope identity matters as well as its spelling. Replacing an
        // approval cannot silently reactivate a previously approved snapshot.
        sqlx::query("UPDATE iam.application_approved_scopes SET approved_at=approved_at+interval '1 second' WHERE application_id='target' AND scope='self.identity.read' AND revoked_at IS NULL")
            .execute(&f.pool).await?;
        ensure!(
            f.verify(&issued, None).await.is_err(),
            "approval replacement kept old disclosure authority"
        );
        let renewed = f.issue(211).await?;
        ensure!(f.verify(&renewed, None).await.is_ok());
        // Pre-upgrade grants have no per-context disclosure decision and must
        // be reapproved; their root login scope snapshot is not upgraded.
        sqlx::query("UPDATE iam.obo_grants SET graph=graph-'_disclosure_consent' WHERE id=$1")
            .bind(renewed.grant)
            .execute(&f.pool)
            .await?;
        ensure!(
            f.verify(&renewed, None).await.is_err(),
            "legacy graph acquired implicit disclosures"
        );
        f.pool.close().await;
    }
    Ok(())
}
