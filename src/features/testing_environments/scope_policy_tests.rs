//! Production-to-testing IAM policy synchronization under runtime database roles.
#![allow(clippy::too_many_lines)]

use crate::domain::id::Id;
use anyhow::{Context as _, ensure};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::infrastructure::{
    postgres::{
        self,
        context::{self, DatabaseContext},
    },
    testing_plane::{self, SelectedEnvironment},
};

const SOURCE: Id = Id::fixture("test_org>app-alpha");
const OWNER_ORG: Id = Id::from_u128(0x21);
const APP: Id = Id::fixture("test_org>app-alpha");
const ENVIRONMENT: Id = Id::from_u128(0xa001);

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; uses isolated PostgreSQL planes"]
async fn imported_iam_scope_policy_tracks_source_without_restoring_revoked_grants()
-> anyhow::Result<()> {
    let production_database = crate::test_database::TestDatabase::start().await?;
    let production = production_database.pool.clone();
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NULL THEN CREATE ROLE silicon_iam_api NOLOGIN; END IF; IF to_regrole('silicon_iam_worker') IS NULL THEN CREATE ROLE silicon_iam_worker NOLOGIN; END IF; IF to_regrole('silicon_iam_key_operator') IS NULL THEN CREATE ROLE silicon_iam_key_operator NOLOGIN; END IF; END $$; DO $$ BEGIN IF to_regrole('policy_runtime') IS NULL THEN CREATE ROLE policy_runtime LOGIN PASSWORD 'policy-test' IN ROLE silicon_iam_api; END IF; END $$;")
        .execute(&production).await?;
    postgres::migrate(&production).await?;
    crate::features::applications::live_tests::seed_protocol_rows(&production).await?;
    sqlx::query("UPDATE iam.organizations SET trusted_org=true,allowed_restricted_iam_scopes=ARRAY['organizations.join'] WHERE id=$1")
        .bind(OWNER_ORG).execute(&production).await?;
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let testing = testing_database.pool.clone();
    postgres::migrate_testing(&testing).await?;
    sqlx::query("INSERT INTO iam.cryptographic_key_versions(purpose,key_version,status) VALUES('contact_aead',1,'active'),('token_hmac',1,'active') ON CONFLICT DO NOTHING")
        .execute(&testing).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    for pool in [&production, &testing] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
            .execute(pool)
            .await?;
    }
    let runtime_url = |value: &str| -> anyhow::Result<String> {
        let mut url = url::Url::parse(value)?;
        url.set_username("policy_runtime")
            .map_err(|()| anyhow::anyhow!("runtime username"))?;
        url.set_password(Some("policy-test"))
            .map_err(|()| anyhow::anyhow!("runtime password"))?;
        Ok(url.to_string())
    };
    let runtime_production = PgPoolOptions::new()
        .max_connections(3)
        .connect(&runtime_url(&production_database.url)?)
        .await?;
    let runtime_testing = PgPoolOptions::new()
        .max_connections(3)
        .connect(&runtime_url(&testing_database.url)?)
        .await?;

    // Production has an inert boundary even if a runtime client forges the
    // testing setting. No local organization can be elevated by that helper.
    let mut transaction = runtime_production.begin().await?;
    sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
        .bind(ENVIRONMENT.to_string())
        .execute(&mut *transaction)
        .await?;
    let attempted = sqlx::query("SELECT iam_private.apply_testing_import_iam_scope_policies('[]')")
        .execute(&mut *transaction)
        .await;
    ensure!(
        matches!(attempted, Err(sqlx::Error::Database(ref error)) if error.code().as_deref()==Some("42501"))
    );
    transaction.rollback().await?;

    let selected = SelectedEnvironment {
        id: ENVIRONMENT,
        organization_id: OWNER_ORG,
    };
    testing_plane::scope(selected, async {
        let mut transaction =
            context::begin(&runtime_testing, DatabaseContext::anonymous()).await?;
        sqlx::query("SELECT iam_private.import_testing_application_configuration($1)")
            .bind(sqlx::types::Json(config(APP)))
            .execute(&mut *transaction)
            .await?;
        super::scope_policy::synchronize(&mut transaction, &runtime_production).await?;
        sqlx::query("SELECT iam_private.activate_testing_application_scopes($1)")
            .bind(vec![APP.to_string()])
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        anyhow::Ok(())
    })
    .await
    .context("import a trusted source with restricted permissions")?;
    ensure!(
        active_scopes(&testing).await?
            == vec![
                "organizations.create",
                "organizations.join",
                "self.identity.read"
            ]
    );
    let version = org_version(&testing).await?;
    synchronize(&runtime_testing, &runtime_production).await?;
    ensure!(
        org_version(&testing).await? == version,
        "unchanged policy rewrote the organization"
    );

    // A different selected environment cannot target an imported row by UUID.
    testing_plane::scope(SelectedEnvironment { id: Id::from_u128(0xa002), ..selected }, async {
        let mut transaction = context::begin(&runtime_testing, DatabaseContext::anonymous()).await?;
        let payload = json!([{"application_id":APP,"source_application_id":SOURCE,"org_id":"test_org","trusted_org":true,"allowed_scopes":["organizations.join"]}]);
        let attempted = sqlx::query("SELECT iam_private.apply_testing_import_iam_scope_policies($1)")
            .bind(sqlx::types::Json(payload)).execute(&mut *transaction).await;
        ensure!(matches!(attempted, Err(sqlx::Error::Database(ref error)) if error.code().as_deref()==Some("42501")), "policy crossed test environments");
        transaction.rollback().await?;
        anyhow::Ok(())
    }).await?;

    sqlx::query("UPDATE iam.organizations SET allowed_restricted_iam_scopes='{}' WHERE id=$1")
        .bind(OWNER_ORG)
        .execute(&production)
        .await?;
    synchronize(&runtime_testing, &runtime_production).await?;
    ensure!(active_scopes(&testing).await? == vec!["organizations.create", "self.identity.read"]);
    ensure!(sqlx::query_scalar::<_, bool>("SELECT revoked_by_policy FROM iam.application_approved_scopes WHERE application_id=$1 AND scope='organizations.join'")
        .bind(APP).fetch_one(&testing).await?);

    sqlx::query("UPDATE iam.organizations SET allowed_restricted_iam_scopes=ARRAY['organizations.join'] WHERE id=$1")
        .bind(OWNER_ORG).execute(&production).await?;
    synchronize(&runtime_testing, &runtime_production).await?;
    ensure!(
        !active_scopes(&testing)
            .await?
            .contains(&"organizations.join".to_owned()),
        "policy restoration reactivated an old approval"
    );
    testing_plane::scope(selected, async {
        let mut transaction =
            context::begin(&runtime_testing, DatabaseContext::anonymous()).await?;
        super::scope_policy::synchronize(&mut transaction, &runtime_production).await?;
        sqlx::query("SELECT iam_private.activate_testing_application_scopes($1)")
            .bind(vec![APP.to_string()])
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        anyhow::Ok(())
    })
    .await
    .context("explicit import reuse may approve currently available test scopes")?;
    ensure!(
        active_scopes(&testing)
            .await?
            .contains(&"organizations.join".to_owned())
    );
    sqlx::query("UPDATE iam.organizations SET trusted_org=false WHERE id=$1")
        .bind(OWNER_ORG)
        .execute(&production)
        .await?;
    synchronize(&runtime_testing, &runtime_production).await?;
    ensure!(
        !active_scopes(&testing)
            .await?
            .contains(&"organizations.join".to_owned())
    );
    // A missing control-plane connection aborts before authorization; stale
    // local snapshots never become a fallback while production is unavailable.
    runtime_production.close().await;
    ensure!(
        synchronize(&runtime_testing, &runtime_production)
            .await
            .is_err()
    );
    Ok(())
}

async fn synchronize(testing: &PgPool, production: &PgPool) -> anyhow::Result<()> {
    testing_plane::scope(
        SelectedEnvironment {
            id: ENVIRONMENT,
            organization_id: OWNER_ORG,
        },
        async {
            let mut transaction = context::begin(testing, DatabaseContext::anonymous()).await?;
            super::scope_policy::synchronize(&mut transaction, production).await?;
            transaction.commit().await?;
            anyhow::Ok(())
        },
    )
    .await
}

async fn active_scopes(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT scope FROM iam.application_approved_scopes WHERE application_id=$1 AND revoked_at IS NULL ORDER BY scope")
        .bind(APP).fetch_all(pool).await?)
}

async fn org_version(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT org.version FROM iam.organizations org JOIN iam.applications app ON app.organization_id=org.id WHERE app.id=$1")
        .bind(APP).fetch_one(pool).await?)
}

fn config(application_id: Id) -> Value {
    json!({
        "application_id":application_id,"source_application_id":SOURCE,
        "app_id":"test_org>app-alpha","org_id":"test_org","organization_name":"Imported organization",
        "app_name":"Imported Interface","base_url":"https://example.test",
        "app_scope":{"iam":["self.identity.read","organizations.create","organizations.join","organization.sso.manage"],"external":[]},
        "webhook_scope":["full"],"testing_idle_days":30,"obo_endpoints":[],
        "endpoint_id":Id::now_v7(),"signing_key_id":Id::now_v7(),"webhook_secret_version":1,"webhook_fingerprint":"whs_abcdefgh",
        "url_ciphertext":"11".repeat(17),"url_nonce":"12".repeat(12),"url_key_version":1,"url_digest":"13".repeat(32),
        "signing_ciphertext":"14".repeat(17),"signing_nonce":"15".repeat(12),"signing_key_version":1,
        "secret_id":Id::now_v7(),"secret_digest":"16".repeat(32),"secret_digest_version":1,"secret_prefix":"ask_abcdefgh",
        "secret_ciphertext":"17".repeat(17),"secret_nonce":"18".repeat(12),"secret_key_version":1
    })
}
