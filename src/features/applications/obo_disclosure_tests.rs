//! Real restricted-role disclosure and consent-lock regression coverage.
use std::time::Duration;

use crate::domain::id::Id;
use anyhow::{Context as _, ensure};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};

const SUBJECT: Id = Id::fixture("c:test_carbon");
const ISSUER: Id = Id::fixture("app-alpha");
const RECIPIENT: Id = Id::fixture("target");
const ORG: Id = Id::from_u128(0x21);
const MEMBER: Id = Id::from_u128(0x31);
const TOKEN: Id = Id::from_u128(0x101);
const PROOF: Id = Id::from_u128(0x123);
const WORLD: Id = Id::from_u128(0x801);
const DISCLOSURES: [&str; 3] = [
    "self.identity.read",
    "self.membership.read",
    "self.tags.read",
];
const ENDPOINT: &str = "obo:target:files.read";

#[derive(Clone, Copy)]
struct Snapshot {
    token: Id,
    org: Id,
    member: Id,
    recipient: Id,
    proof: Option<Id>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            token: TOKEN,
            org: ORG,
            member: MEMBER,
            recipient: RECIPIENT,
            proof: Some(PROOF),
        }
    }
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "test fixtures intentionally copy bounded canonical authority snapshots"
)]
async fn snapshot(
    tx: &mut Transaction<'_, Postgres>,
    world: Option<Id>,
    input: Snapshot,
) -> anyhow::Result<Option<Value>> {
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT set_config('iam.principal_id',$1,true), set_config('iam.application_id',$2,true), set_config('iam.organization_id',$3,true), set_config('iam.testing_environment_id',$4,true)")
        .bind(SUBJECT.to_string()).bind(input.recipient.to_string()).bind(input.org.to_string())
        .bind(world.map(|id| id.to_string()).unwrap_or_default()).execute(&mut **tx).await?;
    Ok(sqlx::query_scalar(
        "SELECT iam_private.get_current_application_authorization($1,$2,$3,$4,$5,1,$6)",
    )
    .bind(input.token)
    .bind(SUBJECT)
    .bind(input.org)
    .bind(input.member)
    .bind(input.recipient)
    .bind(input.proof)
    .fetch_one(&mut **tx)
    .await?)
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "test fixtures intentionally copy bounded canonical authority snapshots"
)]
async fn read(pool: &PgPool, world: Option<Id>, input: Snapshot) -> anyhow::Result<Option<Value>> {
    let mut tx = pool.begin().await?;
    let result = snapshot(&mut tx, world, input).await;
    tx.rollback().await?;
    result
}

fn assert_disclosures(value: &Value, omitted: Option<&str>) -> anyhow::Result<()> {
    let expected: Vec<_> = std::iter::once(ENDPOINT)
        .chain(
            DISCLOSURES
                .into_iter()
                .filter(|scope| Some(*scope) != omitted),
        )
        .collect();
    ensure!(
        value["scopes"] == json!(expected),
        "unexpected delegated scopes: {}",
        value["scopes"]
    );
    if omitted == Some("self.identity.read") {
        ensure!(value.get("actor_type").is_none() && value.get("public_id").is_none());
    } else {
        ensure!(value["actor_type"] == "carbon" && value["public_id"] == "c:test_carbon");
    }
    if omitted == Some("self.membership.read") {
        ensure!(value["org_role"].is_null());
    } else {
        ensure!(value["org_role"] == "owner");
    }
    if omitted == Some("self.tags.read") {
        ensure!(value["tags"].is_null());
    } else {
        ensure!(value["tags"] == json!([{"id":Id::from_u128(0x151),"name":"Design"}]));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; uses isolated PostgreSQL planes"]
async fn obo_disclosures_require_exact_current_consent_and_both_application_ceilings()
-> anyhow::Result<()> {
    let production_database = crate::test_database::TestDatabase::start().await?;
    let production = production_database.pool.clone();
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NULL THEN CREATE ROLE silicon_iam_api NOLOGIN; END IF; IF to_regrole('silicon_iam_worker') IS NULL THEN CREATE ROLE silicon_iam_worker NOLOGIN; END IF; IF to_regrole('silicon_iam_key_operator') IS NULL THEN CREATE ROLE silicon_iam_key_operator NOLOGIN; END IF; END $$;").execute(&production).await?;
    crate::infrastructure::postgres::migrate(&production).await?;
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let testing = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                    .bind(WORLD.to_string())
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&testing_database.url)
        .await?;
    crate::infrastructure::postgres::migrate_testing(&testing).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    for (pool, world) in [(&production, None), (&testing, Some(WORLD))] {
        super::live_tests::seed_protocol_rows(pool).await?;
        sqlx::raw_sql(include_str!("obo_disclosure_seed.sql"))
            .execute(pool)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
            .execute(pool)
            .await?;
        disclosure_matrix(pool, world).await?;
        retained_boundaries(pool, world).await?;
    }
    ensure!(
        read(&testing, Some(Id::from_u128(0x802)), Snapshot::default())
            .await?
            .is_none(),
        "proof crossed worlds"
    );
    consent_serialization(&production).await?;
    Ok(())
}

async fn disclosure_matrix(pool: &PgPool, world: Option<Id>) -> anyhow::Result<()> {
    let value = read(pool, world, Snapshot::default())
        .await?
        .context("positive proof missing")?;
    assert_disclosures(&value, None)?;
    ensure!(value["testing_environment_id"] == json!(world));
    let ordinary = read(
        pool,
        world,
        Snapshot {
            recipient: ISSUER,
            proof: None,
            ..Snapshot::default()
        },
    )
    .await?
    .context("ordinary bearer missing")?;
    ensure!(
        ordinary["scopes"]
            .as_array()
            .is_some_and(|scopes| scopes.contains(&json!("directory.tags.read"))),
        "ordinary bearer was narrowed"
    );
    // Rollback each independently missing ceiling. The other bound grant also
    // contains these scopes and must never fill the exact unscoped grant's gap.
    for missing in DISCLOSURES {
        for (name, query, id) in [
            (
                "parent token",
                "DELETE FROM iam.access_token_scopes WHERE access_token_id=$1 AND scope=$2",
                TOKEN,
            ),
            (
                "exact consent",
                "DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id=$1 AND scope=$2",
                Id::from_u128(0x71),
            ),
            (
                "issuer approval",
                "UPDATE iam.application_approved_scopes SET revoked_at=now(),revoked_by_carbon_id='c:test_carbon' WHERE application_id=$1 AND scope=$2",
                ISSUER,
            ),
            (
                "recipient approval",
                "UPDATE iam.application_approved_scopes SET revoked_at=now(),revoked_by_carbon_id='c:test_carbon' WHERE application_id=$1 AND scope=$2",
                RECIPIENT,
            ),
        ] {
            let mut tx = pool.begin().await?;
            sqlx::query(sqlx::AssertSqlSafe(query))
                .bind(id)
                .bind(missing)
                .execute(&mut *tx)
                .await?;
            let value = snapshot(&mut tx, world, Snapshot::default())
                .await?
                .context("proof missing after disclosure removal")?;
            assert_disclosures(&value, Some(missing))
                .with_context(|| format!("{name}: {missing}"))?;
            tx.rollback().await?;
        }
    }
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM iam.membership_tags WHERE membership_id=$1")
        .bind(MEMBER)
        .execute(&mut *tx)
        .await?;
    let value = snapshot(&mut tx, world, Snapshot::default())
        .await?
        .context("empty-tag proof missing")?;
    ensure!(
        value["tags"] == json!([]),
        "disclosed empty tags must differ from null"
    );
    tx.rollback().await?;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id=$1 AND scope = ANY($2)",
    )
    .bind(Id::from_u128(0x71))
    .bind(DISCLOSURES.as_slice())
    .execute(&mut *tx)
    .await?;
    let value = snapshot(&mut tx, world, Snapshot::default())
        .await?
        .context("endpoint-only proof missing")?;
    ensure!(
        value["scopes"] == json!([ENDPOINT])
            && value["org_role"].is_null()
            && value["tags"].is_null()
            && value.get("public_id").is_none()
    );
    tx.rollback().await?;
    Ok(())
}

async fn retained_boundaries(pool: &PgPool, world: Option<Id>) -> anyhow::Result<()> {
    for input in [
        Snapshot {
            recipient: Id::fixture("app-beta"),
            ..Snapshot::default()
        },
        Snapshot {
            org: Id::from_u128(0x23),
            member: Id::from_u128(0x33),
            ..Snapshot::default()
        },
        Snapshot {
            token: Id::from_u128(0x103),
            ..Snapshot::default()
        },
        Snapshot {
            proof: None,
            ..Snapshot::default()
        },
    ] {
        ensure!(
            read(pool, world, input).await?.is_none(),
            "unbound proof authority accepted"
        );
    }
    for query in [
        "UPDATE iam.access_tokens SET revoked_at=now(),revocation_reason='test' WHERE id='00000000-0000-0000-0000-000000000101'",
        "UPDATE iam.obo_proofs SET revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000123'",
        "UPDATE iam.oauth_consent_grants SET status='revoked',revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000071'",
        "DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id='00000000-0000-0000-0000-000000000071' AND scope='obo:target:files.read'",
        "UPDATE iam.organization_memberships SET authz_epoch=authz_epoch+1 WHERE id='00000000-0000-0000-0000-000000000031'",
        "UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='c:test_carbon'",
        "UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='app-alpha'",
        "UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='target'",
        "UPDATE iam.application_obo_endpoints SET version=version+1 WHERE application_id='target'",
    ] {
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(query))
            .execute(&mut *tx)
            .await?;
        ensure!(
            snapshot(&mut tx, world, Snapshot::default())
                .await?
                .is_none(),
            "revoked proof accepted: {query}"
        );
        tx.rollback().await?;
    }
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE iam.obo_proofs SET consumed_at=now(),consumed_by_application_id=$1 WHERE id=$2",
    )
    .bind(RECIPIENT)
    .bind(PROOF)
    .execute(&mut *tx)
    .await?;
    let failure = snapshot(&mut tx, world, Snapshot::default())
        .await
        .err()
        .context("consumed proof must fail")?;
    ensure!(failure.to_string().contains("obo_proof_consumed"));
    tx.rollback().await?;
    Ok(())
}

async fn consent_serialization(pool: &PgPool) -> anyhow::Result<()> {
    let mut proof = pool.begin().await?;
    ensure!(
        snapshot(&mut proof, None, Snapshot::default())
            .await?
            .is_some()
    );
    let writer_pool = pool.clone();
    let mut writer = tokio::spawn(async move {
        sqlx::query("UPDATE iam.oauth_consent_grants SET version=version+1 WHERE id=$1")
            .bind(Id::from_u128(0x71))
            .execute(&writer_pool)
            .await
    });
    ensure!(
        tokio::time::timeout(Duration::from_millis(150), &mut writer)
            .await
            .is_err(),
        "consent changed while proof held disclosure"
    );
    proof.rollback().await?;
    tokio::time::timeout(Duration::from_secs(3), writer).await???;
    // If re-consent owns the row first, proof disclosure waits and then reads
    // the committed reduced scope set rather than its older statement snapshot.
    let mut writer = pool.begin().await?;
    sqlx::query("UPDATE iam.oauth_consent_grants SET version=version+1 WHERE id=$1")
        .bind(Id::from_u128(0x71))
        .execute(&mut *writer)
        .await?;
    sqlx::query("DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id=$1 AND scope='self.tags.read'").bind(Id::from_u128(0x71)).execute(&mut *writer).await?;
    let reader_pool = pool.clone();
    let mut reader =
        tokio::spawn(async move { read(&reader_pool, None, Snapshot::default()).await });
    ensure!(
        tokio::time::timeout(Duration::from_millis(150), &mut reader)
            .await
            .is_err(),
        "disclosure bypassed concurrent re-consent"
    );
    writer.commit().await?;
    let value = tokio::time::timeout(Duration::from_secs(3), reader)
        .await???
        .context("proof missing after re-consent")?;
    assert_disclosures(&value, Some("self.tags.read"))?;
    Ok(())
}
