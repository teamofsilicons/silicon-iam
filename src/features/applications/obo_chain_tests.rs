//! Chained OBO delegation through the real restricted-role SQL surface.
use crate::domain::id::Id;
use anyhow::{Context as _, ensure};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};

const SUBJECT: &str = "c:test_carbon";
const ORG: Id = Id::from_u128(0x21);
const MEMBER: Id = Id::from_u128(0x31);
const TOKEN: Id = Id::from_u128(0x101);
const ROOT: Id = Id::from_u128(0x124);
const WORLD: Id = Id::from_u128(0x801);
const CHAINED_SCOPES: [&str; 4] = [
    "obo:store:blobs.write",
    "self.identity.read",
    "self.membership.read",
    "self.tags.read",
];

/// Mirrors the handler: application context to find the consumed parent,
/// then the parent's subject context for every authority decision.
async fn context(
    tx: &mut Transaction<'_, Postgres>,
    world: Option<Id>,
    principal: &str,
    application: &str,
    organization: Option<Id>,
) -> anyhow::Result<()> {
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut **tx)
        .await?;
    sqlx::query("SELECT set_config('iam.principal_id',$1,true), set_config('iam.application_id',$2,true), set_config('iam.organization_id',$3,true), set_config('iam.testing_environment_id',$4,true)")
        .bind(principal)
        .bind(application)
        .bind(organization.map(|id| id.to_string()).unwrap_or_default())
        .bind(world.map(|id| id.to_string()).unwrap_or_default())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn as_subject(
    tx: &mut Transaction<'_, Postgres>,
    world: Option<Id>,
    application: &str,
) -> anyhow::Result<()> {
    context(tx, world, SUBJECT, application, Some(ORG)).await
}

async fn resolve(
    tx: &mut Transaction<'_, Postgres>,
    world: Option<Id>,
    caller: &str,
    parent: Id,
) -> anyhow::Result<Option<Value>> {
    context(tx, world, caller, caller, None).await?;
    Ok(sqlx::query_scalar(
        "SELECT to_jsonb(parent) FROM iam_private.resolve_application_obo_chain_parent($1) AS parent",
    )
    .bind(parent)
    .fetch_optional(&mut **tx)
    .await?)
}

async fn authority(
    tx: &mut Transaction<'_, Postgres>,
    world: Option<Id>,
    caller: &str,
    parent: Id,
    audience: &str,
    endpoint: &str,
) -> anyhow::Result<Option<Value>> {
    as_subject(tx, world, caller).await?;
    Ok(sqlx::query_scalar(
        "SELECT to_jsonb(authority) FROM iam_private.lock_application_obo_chained_exchange_authority($1, 1, $2, $3, $4) AS authority",
    )
    .bind(caller)
    .bind(parent)
    .bind(audience)
    .bind(endpoint)
    .fetch_optional(&mut **tx)
    .await?)
}

/// Issues one hop exactly as the handler persists it.
async fn issue(
    tx: &mut Transaction<'_, Postgres>,
    world: Option<Id>,
    caller: &str,
    parent: Id,
    audience: &str,
    endpoint: &str,
) -> anyhow::Result<Id> {
    as_subject(tx, world, caller).await?;
    let id = Id::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.obo_proofs (
            id, proof_digest, digest_key_version, proof_prefix,
            issuer_application_id, audience_application_id,
            subject_principal_id, subject_kind, organization_id, membership_id,
            parent_access_token_id, endpoint_id, request_metadata, endpoint_version,
            request_method, request_path, request_body_sha256, request_signed_at,
            subject_auth_epoch, membership_authz_epoch, issuer_auth_epoch, audience_auth_epoch,
            created_at, expires_at,
            root_issuer_application_id, chain_depth, parent_proof_id, root_proof_id,
            chain, chain_not_after
        )
        SELECT $1, decode(md5($1::text) || md5($1::text || 'digest'), 'hex'), 1,
               'obo_' || left(md5($1::text), 8),
               $2, authority.audience_application_id,
               $5, 'carbon', $6, $7,
               authority.parent_access_token_id, $4, '{}', authority.endpoint_version,
               'POST', authority.endpoint_path, decode(repeat('00', 32), 'hex'), clock_timestamp(),
               authority.subject_auth_epoch, authority.membership_authz_epoch, 1, authority.audience_auth_epoch,
               clock_timestamp(),
               LEAST(clock_timestamp() + authority.ttl_seconds * interval '1 second', authority.window_ends_at),
               authority.root_issuer_application_id, authority.chain_depth, $8, authority.root_proof_id,
               authority.chain, authority.window_ends_at
        FROM iam_private.lock_application_obo_chained_exchange_authority($2, 1, $8, $3, $4) AS authority
        ",
    )
    .bind(id)
    .bind(caller)
    .bind(audience)
    .bind(endpoint)
    .bind(SUBJECT)
    .bind(ORG)
    .bind(MEMBER)
    .bind(parent)
    .execute(&mut **tx)
    .await?;
    Ok(id)
}

async fn verify(
    tx: &mut Transaction<'_, Postgres>,
    world: Option<Id>,
    audience: &str,
    proof: Id,
) -> anyhow::Result<(Option<Value>, Option<Value>)> {
    as_subject(tx, world, audience).await?;
    let current: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(current) FROM iam_private.application_obo_load_chained_context($1) AS current",
    )
    .bind(proof)
    .fetch_optional(&mut **tx)
    .await?;
    let authorization: Option<Value> = sqlx::query_scalar(
        "SELECT iam_private.get_current_application_authorization($1,$2,$3,$4,$5,1,$6)",
    )
    .bind(TOKEN)
    .bind(SUBJECT)
    .bind(ORG)
    .bind(MEMBER)
    .bind(audience)
    .bind(proof)
    .fetch_one(&mut **tx)
    .await?;
    Ok((current, authorization))
}

async fn consume(
    tx: &mut Transaction<'_, Postgres>,
    audience: &str,
    proof: Id,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE iam.obo_proofs SET consumed_at=clock_timestamp(), consumed_by_application_id=$1 WHERE id=$2 AND consumed_at IS NULL",
    )
    .bind(audience)
    .bind(proof)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn replay_path(
    tx: &mut Transaction<'_, Postgres>,
    world: Option<Id>,
    issuer: &str,
    proof: Id,
) -> anyhow::Result<Option<String>> {
    as_subject(tx, world, issuer).await?;
    Ok(
        sqlx::query_scalar("SELECT iam_private.application_obo_chained_replay_path($1, $2, $3)")
            .bind(proof)
            .bind(issuer)
            .bind(ORG)
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// One requested hop: caller, consumed parent, downstream audience, endpoint.
type Hop<'a> = (&'a str, Id, &'a str, &'a str);

async fn expect_refusal(
    pool: &PgPool,
    world: Option<Id>,
    setup: &str,
    (caller, parent, audience, endpoint): Hop<'_>,
    code: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    if !setup.is_empty() {
        sqlx::raw_sql(sqlx::AssertSqlSafe(setup))
            .execute(&mut *tx)
            .await?;
    }
    let result = authority(&mut tx, world, caller, parent, audience, endpoint).await;
    tx.rollback().await?;
    let failure = result
        .err()
        .with_context(|| format!("expected {code} after: {setup}"))?;
    ensure!(
        failure.to_string().contains(code),
        "expected {code}, got {failure} after: {setup}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL; uses isolated PostgreSQL planes"]
async fn chained_obo_is_declared_bounded_and_dies_with_its_root() -> anyhow::Result<()> {
    let production_database = crate::test_database::TestDatabase::start().await?;
    let production = production_database.pool.clone();
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
        sqlx::raw_sql(include_str!("obo_chain_seed.sql"))
            .execute(pool)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
            .execute(pool)
            .await?;
        declared_closure(pool).await?;
        chain_lifecycle(pool, world).await?;
        chain_refusals(pool, world).await?;
        chain_budgets(pool, world).await?;
        chain_revocation(pool, world).await?;
    }
    let mut tx = testing.begin().await?;
    ensure!(
        resolve(&mut tx, Some(Id::from_u128(0x802)), "target", ROOT)
            .await?
            .is_none(),
        "chain parent crossed worlds"
    );
    tx.rollback().await?;
    Ok(())
}

async fn declared_closure(pool: &PgPool) -> anyhow::Result<()> {
    let grant: Option<Value> =
        sqlx::query_scalar("SELECT downstream_grant FROM iam.obo_proofs WHERE id=$1")
            .bind(ROOT)
            .fetch_one(pool)
            .await?;
    // store.blobs.write -> target.files.read returns to the root audience, so
    // it is not part of the root's closure.
    ensure!(
        grant
            == Some(json!([{
                "from_app": "target", "from_endpoint": "files.read",
                "app": "store", "endpoint": "blobs.write",
            }])),
        "unexpected captured closure: {grant:?}"
    );
    let direct: Option<Value> =
        sqlx::query_scalar("SELECT downstream_grant FROM iam.obo_proofs WHERE id=$1")
            .bind(Id::from_u128(0x123))
            .fetch_one(pool)
            .await?;
    ensure!(
        direct.is_none(),
        "a root issued before the declaration must not gain one"
    );
    let policy: Value =
        sqlx::query_scalar("SELECT iam_private.application_login_scope_policy('app-alpha')")
            .fetch_one(pool)
            .await?;
    // Legacy proof storage still needs migration coverage, but the current
    // login policy must never expose its former bundled OBO consent.
    ensure!(
        policy["scopes"]
            .as_array()
            .context("login scopes")?
            .iter()
            .all(|scope| {
                !scope["scope"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("obo:")
            }),
        "ordinary login exposed OBO authority: {policy}"
    );
    Ok(())
}

async fn chain_lifecycle(pool: &PgPool, world: Option<Id>) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let parent = resolve(&mut tx, world, "target", ROOT)
        .await?
        .context("the consumer must resolve its parent")?;
    ensure!(parent["subject_principal_id"] == SUBJECT && parent["organization_id"] == json!(ORG));
    for stranger in ["app-alpha", "store"] {
        ensure!(
            resolve(&mut tx, world, stranger, ROOT).await?.is_none(),
            "{stranger} resolved a proof it did not consume"
        );
    }
    let decided = authority(&mut tx, world, "target", ROOT, "store", "blobs.write")
        .await?
        .context("declared hop refused")?;
    ensure!(decided["chain_depth"] == 1 && decided["root_proof_id"] == json!(ROOT));
    ensure!(
        decided["chain"]
            .as_array()
            .is_some_and(|chain| chain.len() == 1
                && chain[0]["proof_id"] == json!(ROOT)
                && chain[0]["issuer_application_id"] == "app-alpha"),
        "unexpected chain: {}",
        decided["chain"]
    );
    tx.rollback().await?;

    let mut tx = pool.begin().await?;
    let proof = issue(&mut tx, world, "target", ROOT, "store", "blobs.write").await?;
    let window: bool = sqlx::query_scalar(
        "SELECT chain_not_after > clock_timestamp() + interval '590 seconds' AND chain_not_after <= clock_timestamp() + interval '601 seconds' AND expires_at <= chain_not_after FROM iam.obo_proofs WHERE id=$1",
    )
    .bind(proof)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(window, "window is not consumed_at + downstream_ttl_seconds");
    ensure!(
        replay_path(&mut tx, world, "target", proof)
            .await?
            .as_deref()
            == Some("/blobs"),
        "live chained replay lost its bound path"
    );

    let (current, authorization) = verify(&mut tx, world, "store", proof).await?;
    let current = current.context("chained context missing")?;
    ensure!(
        current["parent_active"] == true && current["endpoint_active"] == true,
        "chained context inactive: {current}"
    );
    let authorization = authorization.context("chained authorization missing")?;
    ensure!(
        authorization["scopes"] == json!(CHAINED_SCOPES),
        "unexpected chained scopes: {}",
        authorization["scopes"]
    );
    consume(&mut tx, "store", proof).await?;
    ensure!(
        replay_path(&mut tx, world, "target", proof)
            .await?
            .is_none(),
        "consumed chained proof still replays"
    );
    // store.blobs.write declares target.files.read, but target is already in
    // the chain.
    let cycle = authority(&mut tx, world, "store", proof, "target", "files.read").await;
    ensure!(
        cycle
            .err()
            .is_some_and(|error| error.to_string().contains("obo_chain_cycle")),
        "a hop back into the chain was accepted"
    );
    tx.rollback().await?;

    // A self disclosure survives only when every chained issuer holds it.
    let mut tx = pool.begin().await?;
    let proof = issue(&mut tx, world, "target", ROOT, "store", "blobs.write").await?;
    sqlx::query("RESET ROLE").execute(&mut *tx).await?;
    sqlx::query("UPDATE iam.application_approved_scopes SET revoked_at=now(),revoked_by_carbon_id='c:test_carbon' WHERE application_id='target' AND scope='self.tags.read'")
        .execute(&mut *tx)
        .await?;
    let (_, authorization) = verify(&mut tx, world, "store", proof).await?;
    let authorization = authorization.context("narrowed chained authorization missing")?;
    ensure!(
        authorization["scopes"] == json!(&CHAINED_SCOPES[..3]) && authorization["tags"].is_null(),
        "chained issuer disclosure ceiling ignored: {authorization}"
    );
    tx.rollback().await?;
    Ok(())
}

async fn chain_refusals(pool: &PgPool, world: Option<Id>) -> anyhow::Result<()> {
    for (setup, audience, endpoint, code) in [
        ("", "store", "blobs.read", "obo_chain_endpoint_not_declared"),
        (
            "",
            "app-beta",
            "trust.manage",
            "obo_chain_endpoint_not_declared",
        ),
        (
            "UPDATE iam.application_approved_scopes SET revoked_at=now(),revoked_by_carbon_id='c:test_carbon' WHERE application_id='target' AND scope='obo:store:blobs.write'",
            "store",
            "blobs.write",
            "obo_chain_scope_not_approved",
        ),
        (
            "UPDATE iam.obo_proofs SET consumed_at=clock_timestamp() - interval '601 seconds' WHERE id='00000000-0000-0000-0000-000000000124'",
            "store",
            "blobs.write",
            "obo_chain_window_closed",
        ),
        (
            "UPDATE iam.access_tokens SET expires_at=clock_timestamp() + interval '200 milliseconds' WHERE id='00000000-0000-0000-0000-000000000101'; SELECT pg_sleep(0.3)",
            "store",
            "blobs.write",
            "obo_chain_window_closed",
        ),
        // A catalog change pins nothing new: the parent's endpoint version
        // no longer matches, so the running chain stops.
        (
            "UPDATE iam.application_obo_endpoints SET downstream='[{\"audience\":\"store\",\"endpoint_id\":\"blobs.write\"},{\"audience\":\"app-beta\",\"endpoint_id\":\"trust.manage\"}]' WHERE application_id='target' AND endpoint_id='files.read'",
            "store",
            "blobs.write",
            "obo_proof_revoked",
        ),
        (
            "UPDATE iam.obo_proofs SET revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000124'",
            "store",
            "blobs.write",
            "obo_proof_revoked",
        ),
        (
            "DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id='00000000-0000-0000-0000-000000000071' AND scope='obo:target:files.read'",
            "store",
            "blobs.write",
            "obo_proof_revoked",
        ),
    ] {
        expect_refusal(
            pool,
            world,
            setup,
            ("target", ROOT, audience, endpoint),
            code,
        )
        .await?;
    }
    // Only the consumer can chain from a proof.
    expect_refusal(
        pool,
        world,
        "",
        ("store", ROOT, "store", "blobs.write"),
        "obo_subject_proof_not_found",
    )
    .await?;
    // Depth is bounded no matter what the catalog declares.
    let deep = Id::from_u128(0x125);
    let synthetic = format!(
        "SELECT set_config('iam.principal_id','{SUBJECT}',true), set_config('iam.organization_id','{ORG}',true), set_config('iam.application_id','target',true);
         INSERT INTO iam.obo_proofs(id,proof_digest,digest_key_version,proof_prefix,issuer_application_id,audience_application_id,subject_principal_id,subject_kind,organization_id,membership_id,parent_access_token_id,endpoint_id,request_metadata,endpoint_version,request_method,request_path,request_body_sha256,request_signed_at,subject_auth_epoch,membership_authz_epoch,issuer_auth_epoch,audience_auth_epoch,expires_at,root_issuer_application_id,chain_depth,root_proof_id,chain,chain_not_after,consumed_at,consumed_by_application_id)
         SELECT '{deep}',decode(repeat('3b',32),'hex'),1,'obo_deepdeep','store','target','{SUBJECT}','carbon','{ORG}','{MEMBER}','{TOKEN}','files.read','{{}}',endpoint.version,'POST','/files',decode(repeat('00',32),'hex'),now(),1,1,1,1,now()+interval '60 seconds','app-alpha',10,'{ROOT}',
                (SELECT jsonb_agg(jsonb_build_object('proof_id','{ROOT}')) FROM generate_series(1,10)),now()+interval '600 seconds',now(),'target'
         FROM iam.application_obo_endpoints endpoint WHERE endpoint.application_id='target' AND endpoint.endpoint_id='files.read';"
    );
    expect_refusal(
        pool,
        world,
        &synthetic,
        ("target", deep, "store", "blobs.write"),
        "obo_chain_depth_exceeded",
    )
    .await?;
    Ok(())
}

async fn chain_budgets(pool: &PgPool, world: Option<Id>) -> anyhow::Result<()> {
    // Eight hops from one parent, then the ninth is refused.
    let mut tx = pool.begin().await?;
    for _ in 0..8 {
        issue(&mut tx, world, "target", ROOT, "store", "blobs.write").await?;
    }
    let ninth = authority(&mut tx, world, "target", ROOT, "store", "blobs.write").await;
    ensure!(
        ninth
            .err()
            .is_some_and(|error| error.to_string().contains("obo_chain_use_limit")),
        "the per-parent budget was not enforced"
    );
    tx.rollback().await?;

    // Thirty-two descendants anywhere in the tree exhaust the root.
    let mut tx = pool.begin().await?;
    let template = issue(&mut tx, world, "target", ROOT, "store", "blobs.write").await?;
    sqlx::query(
        r"
        INSERT INTO iam.obo_proofs (
            id, proof_digest, digest_key_version, proof_prefix, issuer_application_id,
            audience_application_id, subject_principal_id, subject_kind, organization_id,
            membership_id, parent_access_token_id, endpoint_id, request_metadata, endpoint_version,
            request_method, request_path, request_body_sha256, request_signed_at, subject_auth_epoch,
            membership_authz_epoch, issuer_auth_epoch, audience_auth_epoch, created_at, expires_at,
            root_issuer_application_id, chain_depth, parent_proof_id, root_proof_id, chain, chain_not_after
        )
        SELECT sibling.id, decode(md5(sibling.id::text) || md5(sibling.id::text || 'digest'), 'hex'), 1,
               'obo_' || left(md5(sibling.id::text), 8), proof.issuer_application_id,
               proof.audience_application_id, proof.subject_principal_id, proof.subject_kind,
               proof.organization_id, proof.membership_id, proof.parent_access_token_id,
               proof.endpoint_id, proof.request_metadata, proof.endpoint_version, proof.request_method,
               proof.request_path, proof.request_body_sha256, proof.request_signed_at,
               proof.subject_auth_epoch, proof.membership_authz_epoch, proof.issuer_auth_epoch,
               proof.audience_auth_epoch, proof.created_at, proof.expires_at,
               proof.root_issuer_application_id, proof.chain_depth, gen_random_uuid(),
               proof.root_proof_id, proof.chain, proof.chain_not_after
        FROM iam.obo_proofs AS proof
        CROSS JOIN LATERAL (SELECT gen_random_uuid() AS id FROM generate_series(1, 31)) AS sibling
        WHERE proof.id = $1
        ",
    )
    .bind(template)
    .execute(&mut *tx)
    .await?;
    let exhausted = authority(&mut tx, world, "target", ROOT, "store", "blobs.write").await;
    ensure!(
        exhausted
            .err()
            .is_some_and(|error| error.to_string().contains("obo_chain_budget_exhausted")),
        "the per-root budget was not enforced"
    );
    tx.rollback().await?;
    Ok(())
}

async fn chain_revocation(pool: &PgPool, world: Option<Id>) -> anyhow::Result<()> {
    for query in [
        // Logout ends the subject token every hop inherits.
        "UPDATE iam.access_tokens SET revoked_at=now(),revocation_reason='test' WHERE id='00000000-0000-0000-0000-000000000101'",
        // Consent to the root delegation is withdrawn.
        "UPDATE iam.oauth_consent_grants SET status='revoked',revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000071'",
        "DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id='00000000-0000-0000-0000-000000000071' AND scope='obo:target:files.read'",
        "UPDATE iam.obo_proofs SET revoked_at=now() WHERE id='00000000-0000-0000-0000-000000000124'",
        "UPDATE iam.organization_memberships SET authz_epoch=authz_epoch+1 WHERE id='00000000-0000-0000-0000-000000000031'",
        "UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='c:test_carbon'",
        // Any application in the chain changing its credentials.
        "UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='app-alpha'",
        "UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='target'",
        "UPDATE iam.principals SET auth_epoch=auth_epoch+1 WHERE id='store'",
        // The ancestor endpoint changing, or the chained issuer losing its hop.
        "UPDATE iam.application_obo_endpoints SET version=version+1 WHERE application_id='target'",
        "UPDATE iam.application_approved_scopes SET revoked_at=now(),revoked_by_carbon_id='c:test_carbon' WHERE application_id='target' AND scope='obo:store:blobs.write'",
    ] {
        let mut tx = pool.begin().await?;
        let proof = issue(&mut tx, world, "target", ROOT, "store", "blobs.write").await?;
        sqlx::query("RESET ROLE").execute(&mut *tx).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(query))
            .execute(&mut *tx)
            .await?;
        let (current, authorization) = verify(&mut tx, world, "store", proof).await?;
        ensure!(authorization.is_none(), "chained proof survived: {query}");
        ensure!(
            current.is_none_or(|current| current["parent_active"] != true
                || current["issuer_auth_epoch"] != 1
                || current["audience_auth_epoch"] != 1
                || current["subject_auth_epoch"] != 1
                || current["membership_authz_epoch"] != 1
                || current["endpoint_active"] != true),
            "chained context survived: {query}"
        );
        tx.rollback().await?;
    }
    Ok(())
}
