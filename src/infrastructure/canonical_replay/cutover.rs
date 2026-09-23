//! Offline operator authority for the canonical identity cutover.
use crate::{
    domain::id::Id,
    infrastructure::{
        canonical_replay::{Entry, canonical_payload},
        crypto::{EncryptedValue, EncryptionContext, EncryptionService, ProtectedField},
        testing_plane::{self, SelectedEnvironment},
    },
};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::BTreeMap;
type Memberships = BTreeMap<(Option<uuid::Uuid>, uuid::Uuid), String>;
const PREPARE_TABLES: &str = r"
CREATE TABLE IF NOT EXISTS iam_private.canonical_replay_cutover (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),prepared_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,converted_at timestamptz);
CREATE TABLE IF NOT EXISTS iam_private.canonical_replay_metadata (
 legacy_id uuid PRIMARY KEY,public_id text NOT NULL,testing_environment_id uuid,
 actor_type text NOT NULL CHECK(actor_type IN('carbon','silicon','application','service')));
REVOKE ALL ON iam_private.canonical_replay_cutover,iam_private.canonical_replay_metadata FROM PUBLIC;
";

/// Captures finite private replay metadata before applying migration 0111.
///
/// # Errors
/// Rejects an unprepared already-migrated schema or unavailable operator authority.
pub async fn prepare(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('iam:canonical-cutover',0))")
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(PREPARE_TABLES).execute(&mut *tx).await?;
    let existing: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM iam_private.canonical_replay_cutover)")
            .fetch_one(&mut *tx)
            .await?;
    if existing {
        tx.commit().await?;
        println!("Cutover already prepared; original metadata and deadline retained.");
        return Ok(());
    }
    let legacy:bool=sqlx::query_scalar("SELECT atttypid='uuid'::regtype FROM pg_attribute WHERE attrelid='iam.principals'::regclass AND attname='id'").fetch_one(&mut *tx).await?;
    anyhow::ensure!(
        legacy,
        "prepare must run before migration 0111; recover original metadata from the verified backup"
    );
    sqlx::raw_sql("LOCK TABLE iam.principals,iam.idempotency_records IN ACCESS EXCLUSIVE MODE;
        INSERT INTO iam_private.canonical_replay_cutover(singleton,prepared_at,expires_at) SELECT true,clock_timestamp(),GREATEST(clock_timestamp(),COALESCE(max(expires_at),clock_timestamp())) FROM iam.idempotency_records;
        INSERT INTO iam_private.canonical_replay_metadata
        SELECT p.id,CASE p.kind WHEN 'carbon' THEN c.carbon_id WHEN 'silicon' THEN s.global_silicon_id WHEN 'application' THEN a.app_id WHEN 'service' THEN 'service/'||v.service_id END,
        (to_jsonb(p)->>'testing_environment_id')::uuid,p.kind
        FROM iam.principals p LEFT JOIN iam.carbons c ON c.id=p.id LEFT JOIN iam.silicons s ON s.id=p.id LEFT JOIN iam.applications a ON a.id=p.id LEFT JOIN iam.service_principals v ON v.id=p.id;").execute(&mut *tx).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM iam_private.canonical_replay_metadata")
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    println!(
        "Prepared private replay metadata for {count} identities. Keep APIs and workers stopped until convert succeeds."
    );
    Ok(())
}

#[derive(sqlx::FromRow)]
struct Payload {
    id: uuid::Uuid,
    environment: Option<uuid::Uuid>,
    application: Option<String>,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    key_version: i16,
}

/// Re-encrypts historical responses and projections in one atomic transaction.
///
/// # Errors
/// Any missing metadata, unavailable key, authentication or JSON failure aborts
/// the entire conversion and leaves API/worker startup blocked.
pub async fn convert(pool: &PgPool, keys: &crate::config::KeyringSettings) -> anyhow::Result<()> {
    let mut encryption = EncryptionService::from_settings(keys)?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('iam:canonical-cutover',0))")
        .execute(&mut *tx)
        .await?;
    let prepared: Option<bool> = sqlx::query_scalar(
        "SELECT converted_at IS NOT NULL FROM iam_private.canonical_replay_cutover FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?;
    anyhow::ensure!(
        prepared.is_some(),
        "prepare metadata missing; do not resume traffic after an unprepared upgrade"
    );
    if prepared == Some(true) {
        tx.commit().await?;
        println!("Cutover already converted; no payloads changed.");
        return Ok(());
    }
    encryption.load_canonical_cutover_contexts(pool).await?;
    let entries:Vec<Entry>=sqlx::query_as("SELECT legacy_id,public_id,testing_environment_id,actor_type FROM iam_private.canonical_replay_metadata").fetch_all(&mut *tx).await?;
    let membership_rows: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
        "SELECT membership_key,scope_key,membership_id FROM iam_private.membership_identifiers",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut memberships = Memberships::new();
    for (key, scope, public) in membership_rows {
        memberships.insert(
            (
                if scope.is_empty() {
                    None
                } else {
                    Some(uuid::Uuid::parse_str(&scope)?)
                },
                key,
            ),
            public,
        );
    }
    let mut counts = Vec::new();
    for kind in [
        PayloadKind::Idempotency,
        PayloadKind::Honeycomb,
        PayloadKind::Projection,
    ] {
        counts.push(convert_table(&mut tx, &encryption, &entries, &memberships, kind).await?);
    }
    sqlx::query("UPDATE iam_private.canonical_replay_cutover SET converted_at=clock_timestamp()")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    println!(
        "Converted replay={}, Honeycomb={}, webhook={} encrypted payloads atomically. Existing digests, deadlines, delivery records and credentials retained.",
        counts[0], counts[1], counts[2]
    );
    Ok(())
}
#[derive(Clone, Copy)]
enum PayloadKind {
    Idempotency,
    Honeycomb,
    Projection,
}
async fn convert_table(
    tx: &mut Transaction<'_, Postgres>,
    encryption: &EncryptionService,
    entries: &[Entry],
    memberships: &Memberships,
    kind: PayloadKind,
) -> anyhow::Result<usize> {
    let (table, id, cipher, nonce, key, application) = match kind {
        PayloadKind::Idempotency => (
            "iam.idempotency_records",
            "id",
            "response_ciphertext",
            "response_nonce",
            "encryption_key_version",
            "NULL::text",
        ),
        PayloadKind::Honeycomb => (
            "iam.honeycomb_operations",
            "operation_id",
            "response_ciphertext",
            "response_nonce",
            "response_key_version",
            "NULL::text",
        ),
        PayloadKind::Projection => (
            "iam.application_webhook_event_projections",
            "id",
            "payload_ciphertext",
            "payload_nonce",
            "encryption_key_version",
            "application_id",
        ),
    };
    let mut after = uuid::Uuid::nil();
    let mut count = 0;
    loop {
        let query = format!(
            "SELECT {id} AS id,(to_jsonb(row)->>'testing_environment_id')::uuid AS environment,{application} AS application,{cipher} AS ciphertext,{nonce} AS nonce,{key} AS key_version FROM {table} row WHERE {cipher} IS NOT NULL AND {id}>$1 ORDER BY {id} LIMIT 100 FOR UPDATE"
        );
        let rows: Vec<Payload> = sqlx::query_as(sqlx::AssertSqlSafe(query))
            .bind(after)
            .fetch_all(&mut **tx)
            .await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            after = row.id;
            let action = async {
                let context = if let Some(app) = &row.application {
                    EncryptionContext::tenant(
                        ProtectedField::ApplicationWebhookEventPayload,
                        Id::legacy_application_encryption_id(app)?,
                        Id::from(row.id),
                    )
                } else {
                    EncryptionContext::global(
                        ProtectedField::IdempotencySecretResponse,
                        Id::from(row.id),
                    )
                };
                let encrypted = EncryptedValue {
                    key_version: row.key_version,
                    nonce: row.nonce.as_slice().try_into()?,
                    ciphertext: row.ciphertext.clone(),
                };
                let plaintext = encryption.decrypt(context, &encrypted)?;
                // A 204 response has no JSON body. Preserve it verbatim.
                if plaintext.is_empty() {
                    return Ok::<_, anyhow::Error>(());
                }
                let mut value: serde_json::Value = serde_json::from_slice(&plaintext)?;
                canonical_payload(&mut value, entries, row.environment);
                if matches!(kind, PayloadKind::Projection) {
                    backfill_membership_handles(&mut value, memberships, row.environment)?;
                }
                let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&value)?);
                let updated = encryption.encrypt(context, &encoded)?;
                let update =
                    format!("UPDATE {table} SET {cipher}=$2,{nonce}=$3,{key}=$4 WHERE {id}=$1");
                sqlx::query(sqlx::AssertSqlSafe(update))
                    .bind(row.id)
                    .bind(updated.ciphertext)
                    .bind(updated.nonce.as_slice())
                    .bind(updated.key_version)
                    .execute(&mut **tx)
                    .await?;
                Ok(())
            };
            if let Some(env) = row.environment {
                testing_plane::scope(
                    SelectedEnvironment {
                        id: Id::from(env),
                        organization_id: Id::nil(),
                    },
                    action,
                )
                .await?;
            } else {
                action.await?;
            }
            count += 1;
        }
    }
    Ok(count)
}

fn backfill_membership_handles(
    value: &mut serde_json::Value,
    memberships: &Memberships,
    environment: Option<uuid::Uuid>,
) -> anyhow::Result<()> {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                backfill_membership_handles(item, memberships, environment)?;
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(resource) = object
                .get_mut("resource")
                .and_then(serde_json::Value::as_object_mut)
                && resource.get("type").and_then(serde_json::Value::as_str)
                    == Some("organization_membership")
            {
                let key = resource
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("captured membership resource key missing"))?;
                let key = uuid::Uuid::parse_str(key)?;
                let public = memberships.get(&(environment, key)).ok_or_else(|| {
                    anyhow::anyhow!(
                        "captured membership resource has no same-environment canonical mapping"
                    )
                })?;
                resource.insert(
                    "membership_id".into(),
                    serde_json::Value::String(public.clone()),
                );
            }
            for child in object.values_mut() {
                backfill_membership_handles(child, memberships, environment)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{KeyringSettings, SecuritySettings},
        infrastructure::{
            crypto::CryptoService,
            postgres::idempotency::{self, IdempotencyClaim, IdempotencyKey, IdempotencyRequest},
        },
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use secrecy::SecretString;
    use std::{collections::BTreeMap, fmt::Write as _, time::Duration};
    fn settings() -> SecuritySettings {
        let ring = |byte| KeyringSettings {
            current_version: 1,
            keys: BTreeMap::from([(1, SecretString::from(URL_SAFE_NO_PAD.encode([byte; 32])))]),
        };
        SecuritySettings {
            token_peppers: ring(11),
            blind_index_keys: ring(31),
            encryption_keys: ring(41),
            cookie_key: SecretString::from(URL_SAFE_NO_PAD.encode([51; 32])),
            access_token_ttl: Duration::from_mins(30),
            refresh_family_ttl: Duration::from_hours(24),
            authorization_code_ttl: Duration::from_mins(2),
            otp_ttl: Duration::from_mins(10),
            otp_max_attempts: 10,
        }
    }
    async fn phase(pool: &PgPool, testing: bool, before: bool) -> anyhow::Result<()> {
        let base = sqlx::migrate!("./migrations");
        let overlays = sqlx::migrate!("./migrations/testing");
        for (source, boundary) in [(&base, 111), (&overlays, 9014)] {
            if boundary == 9014 && !testing {
                continue;
            }
            let mut migrator = sqlx::migrate::Migrator::with_migrations(
                source
                    .iter()
                    // This rehearsal is specifically the 0111 canonical-key cutover.
                    // 0118 is a separate maintenance cutover that requires these
                    // deliberately live replay receipts to expire first.
                    .filter(|migration| migration.version != 118 && (migration.version < boundary) == before)
                    .cloned()
                    .collect(),
            );
            migrator.set_ignore_missing(true);
            migrator.run(pool).await?;
        }
        if testing && !before {
            sqlx::query("SELECT iam_private.reconcile_testing_environment_security()")
                .execute(pool)
                .await?;
        }
        Ok(())
    }
    async fn scope<T>(env: Option<uuid::Uuid>, future: impl std::future::Future<Output = T>) -> T {
        if let Some(id) = env {
            testing_plane::scope(
                SelectedEnvironment {
                    id: Id::from(id),
                    organization_id: Id::nil(),
                },
                future,
            )
            .await
        } else {
            future.await
        }
    }
    async fn begin(
        pool: &PgPool,
        env: Option<uuid::Uuid>,
    ) -> anyhow::Result<Transaction<'_, Postgres>> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,true)")
            .bind(env.map_or_else(String::new, |id| id.to_string()))
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL or Docker"]
    async fn canonical_cutover_preserves_replay_ciphertext_and_isolation() -> anyhow::Result<()> {
        for testing in [false, true] {
            let database = crate::test_database::TestDatabase::start().await?;
            let pool = &database.pool;
            sqlx::raw_sql("DO $$ DECLARE role_name text; BEGIN FOREACH role_name IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator'] LOOP IF to_regrole(role_name) IS NULL THEN EXECUTE format('CREATE ROLE %I NOLOGIN',role_name); END IF; END LOOP; END $$").execute(pool).await?;
            phase(pool, testing, true).await?;
            let mut seed =
                include_str!("../../../tests/sql/canonical_identity_upgrade_seed.sql").to_owned();
            let planes = if testing { vec![2, 3] } else { vec![1] };
            for plane in &planes {
                write!(
                    seed,
                    "BEGIN; SELECT pg_temp.seed_identity_upgrade({plane},{testing}); COMMIT;"
                )?;
            }
            sqlx::raw_sql(sqlx::AssertSqlSafe(seed))
                .execute(pool)
                .await?;
            let security = settings();
            let old = CryptoService::from_settings(&security)?;
            let mut rows = Vec::new();
            for plane in planes {
                let ids:(uuid::Uuid,uuid::Uuid,uuid::Uuid,uuid::Uuid,uuid::Uuid)=sqlx::query_as("SELECT md5('canonical-migration/'||$1||'/carbon')::uuid,md5('canonical-migration/'||$1||'/app')::uuid,md5('canonical-migration/'||$1||'/event')::uuid,md5('canonical-migration/'||$1||'/environment')::uuid,md5('canonical-migration/'||$1||'/member')::uuid").bind(plane.to_string()).fetch_one(pool).await?;
                let env = testing.then_some(ids.3);
                let record = uuid::Uuid::now_v7();
                let projection = uuid::Uuid::now_v7();
                scope(env,async {
                    let mut tx=begin(pool,env).await?;
                    let caller=SecretString::from(format!("carbon:{}",ids.0));let payload=SecretString::from(r#"{"job_role":"Chef"}"#);let key=IdempotencyKey::parse("canonical-cutover-replay")?;
                    let claim=idempotency::claim(&mut tx,&old,IdempotencyRequest{route:"PATCH /api/v1/me",caller_scope:&caller,key:&key,request_payload:&payload,contains_one_time_secret:false}).await?;
                    let IdempotencyClaim::Acquired(lease)=claim else {anyhow::bail!("fresh fixture unexpectedly replayed")};
                    let response=serde_json::json!({"current":{"members":[{"resource":{"type":"organization_membership","id":ids.4,"principal_id":ids.0},"authorization":"removed"}]},"actor":{"id":ids.0,"actor_type":"carbon"},"contact":{"id":ids.0},"job_role":"Chef","application_id":ids.1,"description":"unrelated resource text"});
                    idempotency::complete(&mut tx,&old,lease,200,&serde_json::to_vec(&response)?).await?;
                    let pending_key=IdempotencyKey::parse("canonical-cutover-pending")?;
                    assert!(matches!(idempotency::claim(&mut tx,&old,IdempotencyRequest{route:"PATCH /api/v1/me",caller_scope:&caller,key:&pending_key,request_payload:&payload,contains_one_time_secret:false}).await?,IdempotencyClaim::Acquired(_)));
                    let encrypted=old.encrypt(EncryptionContext::tenant(ProtectedField::ApplicationWebhookEventPayload,Id::from(ids.1),Id::from(projection)),&serde_json::to_vec(&response)?)?;
                    sqlx::query("INSERT INTO iam.application_webhook_event_projections(id,outbox_event_id,application_id,payload_ciphertext,payload_nonce,encryption_key_version) VALUES($1,$2,$3,$4,$5,$6)").bind(projection).bind(ids.2).bind(ids.1).bind(encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).execute(&mut *tx).await?;
                    let encrypted=old.encrypt(EncryptionContext::global(ProtectedField::IdempotencySecretResponse,Id::from(record)),&serde_json::to_vec(&response)?)?;
                    sqlx::query("INSERT INTO iam.honeycomb_operations(operation_id,service_application_id,actor_principal_id,operation_kind,resource_id,idempotency_digest,request_digest,state,response_ciphertext,response_nonce,response_key_version) VALUES($1,$2,$3,'test','resource',decode(repeat('44',32),'hex'),decode(repeat('45',32),'hex'),'pending',$4,$5,$6)").bind(record).bind(ids.1).bind(ids.0).bind(encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).execute(&mut *tx).await?;
                    tx.commit().await?;Ok::<_,anyhow::Error>(())
                }).await?;
                rows.push((env, ids, record, projection));
            }
            prepare(pool).await?;
            prepare(pool).await?;
            phase(pool, testing, false).await?;
            // This offline converter runs as the schema owner. Current runtime
            // grants belong to 0118 and are checked in its own upgrade tests.
            let mut current = CryptoService::from_settings(&security)?;
            assert!(
                current
                    .replay
                    .load_legacy_cutover_fixture(pool)
                    .await
                    .is_err(),
                "unconverted startup must fail closed"
            );
            convert(pool, &security.encryption_keys).await?;
            convert(pool, &security.encryption_keys).await?;
            current.replay.load_legacy_cutover_fixture(pool).await?;
            for (env, ids, record, projection) in rows {
                scope(env,async {
                    let mut tx=begin(pool,env).await?;
                    let caller=SecretString::from("carbon:migration-owner");let payload=SecretString::from(r#"{"job_description":"Chef"}"#);let key=IdempotencyKey::parse("canonical-cutover-replay")?;
                    let claim=idempotency::claim(&mut tx,&current,IdempotencyRequest{route:"PATCH /api/v1/me",caller_scope:&caller,key:&key,request_payload:&payload,contains_one_time_secret:false}).await?;
                    let IdempotencyClaim::Replay(replay)=claim else {anyhow::bail!("cutover executed a duplicate mutation")};
                    let result:serde_json::Value=serde_json::from_slice(&replay.body)?;
                    assert_eq!(result["actor"]["id"],"migration-owner");assert_eq!(result["contact"]["id"],ids.0.to_string());assert_eq!(result["application_id"],"identity-test>app");assert_eq!(result["job_description"],"Chef");assert!(result.get("job_role").is_none());
                    let changed=SecretString::from(r#"{"job_description":"Different"}"#);
                    assert!(idempotency::claim(&mut tx,&current,IdempotencyRequest{route:"PATCH /api/v1/me",caller_scope:&caller,key:&key,request_payload:&changed,contains_one_time_secret:false}).await.is_err());
                    let key=IdempotencyKey::parse("canonical-cutover-pending")?;
                    assert!(idempotency::claim(&mut tx,&current,IdempotencyRequest{route:"PATCH /api/v1/me",caller_scope:&caller,key:&key,request_payload:&payload,contains_one_time_secret:false}).await.is_err(),"unknown pre-cutover outcome must not execute twice");
                    let ciphertext:(Vec<u8>,Vec<u8>,i16)=sqlx::query_as("SELECT payload_ciphertext,payload_nonce,encryption_key_version FROM iam.application_webhook_event_projections WHERE id=$1").bind(projection).fetch_one(&mut *tx).await?;
                    let encrypted=EncryptedValue{ciphertext:ciphertext.0,nonce:ciphertext.1.try_into().map_err(|_|anyhow::anyhow!("nonce"))?,key_version:ciphertext.2};
                    // A pristine service without any legacy-AAD map decrypts the
                    // rewritten projection: conversion actually re-encrypted it.
                    let plain=old.decrypt(EncryptionContext::tenant(ProtectedField::ApplicationWebhookEventPayload,Id::legacy_application_encryption_id("identity-test>app")?,Id::from(projection)),&encrypted)?;
                    let value:serde_json::Value=serde_json::from_slice(&plain)?;assert_eq!(value["actor"]["id"],"migration-owner");assert_eq!(value["current"]["members"][0]["resource"]["membership_id"],"migration:identity-test[identity-test]");assert_eq!(value["current"]["members"][0]["resource"]["id"],ids.4.to_string());
                    let stored:(Vec<u8>,Vec<u8>,i16)=sqlx::query_as("SELECT response_ciphertext,response_nonce,response_key_version FROM iam.honeycomb_operations WHERE operation_id=$1").bind(record).fetch_one(&mut *tx).await?;
                    let plain=old.decrypt(EncryptionContext::global(ProtectedField::IdempotencySecretResponse,Id::from(record)),&EncryptedValue{ciphertext:stored.0,nonce:stored.1.try_into().map_err(|_|anyhow::anyhow!("nonce"))?,key_version:stored.2})?;
                    let value:serde_json::Value=serde_json::from_slice(&plain)?;assert_eq!(value["application_id"],"identity-test>app");
                    tx.rollback().await?;Ok::<_,anyhow::Error>(())
                }).await?;
            }
            sqlx::query("UPDATE iam_private.canonical_replay_cutover SET expires_at=clock_timestamp()-interval '1 second'").execute(pool).await?;
            sqlx::query("SELECT * FROM iam_private.run_worker_ephemeral_maintenance(100)")
                .execute(pool)
                .await?;
            let remaining: i64 =
                sqlx::query_scalar("SELECT count(*) FROM iam_private.canonical_replay_metadata")
                    .fetch_one(pool)
                    .await?;
            assert_eq!(remaining, 0);
        }
        Ok(())
    }
}
