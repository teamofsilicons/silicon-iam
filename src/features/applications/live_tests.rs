//! Live PostgreSQL protocol-invariant coverage.
//!
//! The test is ignored in the default suite because it needs a local Docker
//! daemon. It migrates PostgreSQL 16 and exercises the same conditional updates
//! used by the HTTP handlers.
#![allow(clippy::too_many_lines)]

use anyhow::{Context as _, ensure};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use uuid::Uuid;

const CARBON_ID: Uuid = Uuid::from_u128(1);
const APP_A_ID: Uuid = Uuid::from_u128(0x11);
const APP_B_ID: Uuid = Uuid::from_u128(0x12);
const CONSENT_ID: Uuid = Uuid::from_u128(0x71);
const FAMILY_ID: Uuid = Uuid::from_u128(0x91);
const SECOND_FAMILY_ID: Uuid = Uuid::from_u128(0x93);
const PARENT_REFRESH_ID: Uuid = Uuid::from_u128(0x92);
const PROOF_ID: Uuid = Uuid::from_u128(0x121);
const APP_SECRET_ID: Uuid = Uuid::from_u128(0x131);

#[tokio::test]
#[ignore = "requires a local Docker daemon"]
async fn protocol_credentials_are_single_use_and_revocation_is_atomic() -> anyhow::Result<()> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(5432).await?;
    let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await?;
    crate::infrastructure::postgres::migrate(&pool).await?;
    seed_protocol_rows(&pool).await?;

    application_lifecycle_and_manual_replay_are_atomic(&pool).await?;
    application_deletion_revokes_all_client_authority(&pool).await?;
    authorization_code_scope_revocation_fails_closed(&pool).await?;
    application_scope_revocation_contains_existing_access(&pool).await?;
    authorization_code_is_single_use(&pool).await?;
    refresh_reuse_compromises_the_complete_family(&pool).await?;
    consent_revocation_cascades_to_tokens(&pool).await?;
    obo_proof_is_single_use(&pool).await?;
    committed_application_secret_revocation_wins_authentication(&pool).await?;
    Ok(())
}

async fn application_lifecycle_and_manual_replay_are_atomic(pool: &PgPool) -> anyhow::Result<()> {
    let replacement_secret_id = Uuid::from_u128(0x132);
    let replacement_redirect_id = Uuid::from_u128(0x52);
    let event_id = Uuid::from_u128(0x151);
    let recipient_id = Uuid::from_u128(0x152);
    let delivery_id = Uuid::from_u128(0x153);
    let second_event_id = Uuid::from_u128(0x157);
    let second_recipient_id = Uuid::from_u128(0x158);
    let second_delivery_id = Uuid::from_u128(0x159);
    let replay_batch_id = Uuid::from_u128(0x156);
    let mut transaction = pool.begin().await?;

    sqlx::query(
        r"
        UPDATE iam.application_secrets
        SET status = 'retired', retired_at = transaction_timestamp(), retires_at = NULL
        WHERE application_id = $1 AND status IN ('active', 'retiring')
        ",
    )
    .bind(APP_A_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.application_secrets (
            id, application_id, secret_version, secret_prefix, secret_digest,
            pepper_key_version, created_by_carbon_id
        ) VALUES ($1, $2, 2, 'ask_ijklmnop', decode(repeat('23', 32), 'hex'), 1, $3)
        ",
    )
    .bind(replacement_secret_id)
    .bind(APP_A_ID)
    .bind(CARBON_ID)
    .execute(&mut *transaction)
    .await?;
    let secret_states = sqlx::query_as::<_, (i64, String)>(
        r"
        SELECT secret_version, status
        FROM iam.application_secrets
        WHERE application_id = $1
        ORDER BY secret_version
        ",
    )
    .bind(APP_A_ID)
    .fetch_all(&mut *transaction)
    .await?;
    ensure!(
        secret_states == [(1, "retired".to_owned()), (2, "active".to_owned())],
        "client-secret rotation did not atomically retire the previous secret"
    );

    sqlx::query(
        r"
        UPDATE iam.application_redirect_uris
        SET status = 'retired', retired_at = transaction_timestamp()
        WHERE application_id = $1 AND status IN ('active', 'pending_review')
        ",
    )
    .bind(APP_A_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.application_redirect_uris (
            id, application_id, redirect_uri, uri_digest
        ) VALUES ($1, $2, 'https://client.test/new-callback', decode(repeat('52', 32), 'hex'))
        ",
    )
    .bind(replacement_redirect_id)
    .bind(APP_A_ID)
    .execute(&mut *transaction)
    .await?;
    let redirect_states = sqlx::query_as::<_, (Uuid, String, i64)>(
        r"
        SELECT id, status, version
        FROM iam.application_redirect_uris
        WHERE application_id = $1
        ORDER BY created_at, id
        ",
    )
    .bind(APP_A_ID)
    .fetch_all(&mut *transaction)
    .await?;
    ensure!(
        redirect_states
            == [
                (Uuid::from_u128(0x51), "retired".to_owned(), 2),
                (replacement_redirect_id, "pending_review".to_owned(), 1),
            ],
        "redirect replacement did not retain versioned retired history"
    );

    sqlx::query(
        r"
        INSERT INTO iam.outbox_events (
            id, aggregate_type, aggregate_id, aggregate_version,
            event_ordinal, event_type, schema_version, payload, status, completed_at
        ) VALUES ($1, 'application', $2, 3, 1,
                  'application.updated', 1, jsonb_build_object('application_id', $2),
                  'completed', transaction_timestamp())
        ",
    )
    .bind(event_id)
    .bind(APP_A_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.outbox_events (
            id, aggregate_type, aggregate_id, aggregate_version,
            event_ordinal, event_type, schema_version, payload, status, completed_at
        ) VALUES ($1, 'carbon', $2, 7, 1,
                  'carbon.updated.v1', 1, jsonb_build_object('carbon_id', $2),
                  'completed', transaction_timestamp())
        ",
    )
    .bind(second_event_id)
    .bind(CARBON_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.outbox_event_recipients (
            id, outbox_event_id, recipient_kind,
            application_webhook_endpoint_id, ordering_key
        ) VALUES ($1, $2, 'application',
                  '00000000-0000-0000-0000-000000000141',
                  'application:test:application:test')
        ",
    )
    .bind(recipient_id)
    .bind(event_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.outbox_event_recipients (
            id, outbox_event_id, recipient_kind,
            application_webhook_endpoint_id, ordering_key
        ) VALUES ($1, $2, 'application',
                  '00000000-0000-0000-0000-000000000141',
                  'application:test:carbon:test')
        ",
    )
    .bind(second_recipient_id)
    .bind(second_event_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.webhook_deliveries (
            id, outbox_event_id, recipient_id, signing_key_id, status,
            attempt_count, cycle_attempt_count, dead_lettered_at, last_error_code
        ) VALUES ($1, $2, $3,
                  '00000000-0000-0000-0000-000000000142', 'dead_letter',
                  2, 2, transaction_timestamp(), 'remote_server_error')
        ",
    )
    .bind(delivery_id)
    .bind(event_id)
    .bind(recipient_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.webhook_deliveries (
            id, outbox_event_id, recipient_id, signing_key_id, status,
            attempt_count, cycle_attempt_count, dead_lettered_at, last_error_code
        ) VALUES ($1, $2, $3,
                  '00000000-0000-0000-0000-000000000142', 'dead_letter',
                  1, 1, transaction_timestamp(), 'timeout')
        ",
    )
    .bind(second_delivery_id)
    .bind(second_event_id)
    .bind(second_recipient_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.webhook_delivery_attempts (
            id, delivery_id, attempt_number, started_at, finished_at, error_code
        ) VALUES
          ('00000000-0000-0000-0000-000000000154', $1, 1,
           transaction_timestamp(), transaction_timestamp(), 'timeout'),
          ('00000000-0000-0000-0000-000000000155', $1, 2,
           transaction_timestamp(), transaction_timestamp(), 'remote_server_error')
        ",
    )
    .bind(delivery_id)
    .execute(&mut *transaction)
    .await?;
    let locked = crate::features::webhook_replay::lock_application_dead_letters(
        &mut transaction,
        APP_A_ID,
        &[second_delivery_id, delivery_id],
    )
    .await?;
    ensure!(
        locked.iter().map(|row| row.delivery_id).collect::<Vec<_>>()
            == [delivery_id, second_delivery_id],
        "dead letters were not locked in original event order"
    );
    let mut replayed = Vec::with_capacity(locked.len());
    for delivery in &locked {
        replayed.push(
            crate::features::webhook_replay::replay_application_delivery(
                &mut transaction,
                delivery,
                Uuid::from_u128(0x141),
                Uuid::from_u128(0x142),
                replay_batch_id,
            )
            .await?,
        );
    }
    let retained_attempts = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.webhook_delivery_attempts WHERE delivery_id = $1",
    )
    .bind(delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    ensure!(
        replayed[0].status == "pending"
            && replayed[0].attempt_count == 2
            && replayed[0].cycle_attempt_count == 0
            && replayed[0].manual_replay_count == 1
            && replayed[0].dead_lettered_at.is_none()
            && replayed[0].version == 2
            && retained_attempts == 2,
        "manual replay did not preserve lifetime attempts and reset only the delivery cycle"
    );
    let ordering_keys = sqlx::query_scalar::<_, String>(
        r"
        SELECT ordering_key
        FROM iam.outbox_event_recipients
        WHERE id = ANY($1::uuid[])
        ORDER BY outbox_event_id
        ",
    )
    .bind([recipient_id, second_recipient_id].as_slice())
    .fetch_all(&mut *transaction)
    .await?;
    ensure!(
        ordering_keys.len() == 2 && ordering_keys[0] == ordering_keys[1],
        "a replay batch did not share one destination-bound worker ordering lane"
    );
    let delivery_ids = [delivery_id, second_delivery_id];
    let first_claimable = claimable_replay_deliveries(&mut transaction, &delivery_ids).await?;
    ensure!(
        first_claimable == [delivery_id],
        "the worker could claim more than the earliest replay-batch delivery"
    );
    sqlx::query(
        r"
        UPDATE iam.webhook_deliveries
        SET status = 'delivered', delivered_at = transaction_timestamp()
        WHERE id = $1
        ",
    )
    .bind(delivery_id)
    .execute(&mut *transaction)
    .await?;
    let second_claimable = claimable_replay_deliveries(&mut transaction, &delivery_ids).await?;
    ensure!(
        second_claimable == [second_delivery_id],
        "the next replay-batch delivery did not become eligible after its predecessor finished"
    );
    let preserved_event = sqlx::query_as::<_, (Uuid, i64, String, serde_json::Value)>(
        r"
        SELECT id, aggregate_version, event_type, payload
        FROM iam.outbox_events WHERE id = $1
        ",
    )
    .bind(event_id)
    .fetch_one(&mut *transaction)
    .await?;
    ensure!(
        preserved_event
            == (
                event_id,
                3,
                "application.updated".to_owned(),
                serde_json::json!({ "application_id": APP_A_ID }),
            ),
        "manual replay mutated the original event identity, version, type, or payload"
    );
    transaction.rollback().await?;
    Ok(())
}

async fn claimable_replay_deliveries(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery_ids: &[Uuid],
) -> anyhow::Result<Vec<Uuid>> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT delivery.id
        FROM iam.webhook_deliveries AS delivery
        JOIN iam.outbox_event_recipients AS recipient
          ON recipient.id = delivery.recipient_id
         AND recipient.outbox_event_id = delivery.outbox_event_id
        JOIN iam.outbox_events AS event ON event.id = delivery.outbox_event_id
        WHERE delivery.id = ANY($1::uuid[])
          AND delivery.status = 'pending'
          AND NOT EXISTS (
              SELECT 1
              FROM iam.webhook_deliveries AS prior_delivery
              JOIN iam.outbox_event_recipients AS prior_recipient
                ON prior_recipient.id = prior_delivery.recipient_id
               AND prior_recipient.outbox_event_id = prior_delivery.outbox_event_id
              JOIN iam.outbox_events AS prior_event
                ON prior_event.id = prior_delivery.outbox_event_id
              WHERE prior_recipient.ordering_key = recipient.ordering_key
                AND prior_event.global_sequence < event.global_sequence
                AND prior_delivery.status IN ('pending', 'processing')
          )
        ORDER BY event.global_sequence, delivery.id
        ",
    )
    .bind(delivery_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn application_deletion_revokes_all_client_authority(pool: &PgPool) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    let version = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE iam.applications
        SET review_status = 'deleted', deleted_at = transaction_timestamp()
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING version
        ",
    )
    .bind(APP_A_ID)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE iam.principals
        SET status = 'deleted', deleted_at = transaction_timestamp(),
            auth_epoch = auth_epoch + 1
        WHERE id = $1 AND kind = 'application'
        ",
    )
    .bind(APP_A_ID)
    .execute(&mut *transaction)
    .await?;
    super::applications::retire_application_credentials(&mut transaction, CARBON_ID, APP_A_ID)
        .await
        .map_err(|error| anyhow::anyhow!("credential retirement failed: {error:?}"))?;
    super::applications::revoke_application_authority(
        &mut transaction,
        APP_A_ID,
        "application_deleted",
    )
    .await
    .map_err(|error| anyhow::anyhow!("authority revocation failed: {error:?}"))?;
    sqlx::query(
        r"
        INSERT INTO iam.application_reviews (
            id, application_id, reviewer_carbon_id, decision, reason, application_version
        ) VALUES ($1, $2, $3, 'delete', 'operator request', $4)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(APP_A_ID)
    .bind(CARBON_ID)
    .bind(version)
    .execute(&mut *transaction)
    .await?;

    let revoked = sqlx::query_scalar::<_, bool>(
        r"
        SELECT
            (SELECT review_status = 'deleted' AND deleted_at IS NOT NULL
             FROM iam.applications WHERE id = $1)
            AND (SELECT status = 'deleted' AND deleted_at IS NOT NULL AND auth_epoch = 2
                 FROM iam.principals WHERE id = $1)
            AND (SELECT status = 'compromised' AND retired_at IS NOT NULL
                 FROM iam.application_secrets WHERE id = $2)
            AND (SELECT status = 'retired'
                 FROM iam.application_redirect_uris WHERE application_id = $1)
            AND (SELECT revoked_at IS NOT NULL
                 FROM iam.application_approved_scopes
                 WHERE application_id = $1 AND scope = 'organizations.read')
            AND (SELECT consumed_at IS NOT NULL
                 FROM iam.oauth_authorization_codes WHERE application_id = $1)
            AND (SELECT status = 'denied'
                 FROM iam.oauth_authorization_requests WHERE application_id = $1)
            AND NOT EXISTS (
                SELECT 1 FROM iam.refresh_token_families
                WHERE client_application_id = $1 AND status = 'active'
            )
            AND NOT EXISTS (
                SELECT 1
                FROM iam.refresh_tokens AS token
                JOIN iam.refresh_token_families AS family ON family.id = token.family_id
                WHERE family.client_application_id = $1 AND token.revoked_at IS NULL
            )
            AND NOT EXISTS (
                SELECT 1 FROM iam.access_tokens
                WHERE (client_application_id = $1 OR audience_application_id = $1)
                  AND revoked_at IS NULL
            )
            AND (SELECT revoked_at IS NOT NULL FROM iam.obo_proofs WHERE id = $3)
            AND (SELECT status = 'disabled'
                 FROM iam.application_webhook_endpoints WHERE application_id = $1)
            AND (SELECT status = 'compromised' AND retired_at IS NOT NULL
                 FROM iam.application_webhook_signing_keys WHERE application_id = $1)
        ",
    )
    .bind(APP_A_ID)
    .bind(APP_SECRET_ID)
    .bind(PROOF_ID)
    .fetch_one(&mut *transaction)
    .await?;
    let unrelated_authority_survived = sqlx::query_scalar::<_, bool>(
        r"
        SELECT
            (SELECT revoked_at IS NULL FROM iam.access_tokens
             WHERE id = '00000000-0000-0000-0000-000000000103')
            AND (SELECT status = 'active' FROM iam.application_obo_endpoints
                 WHERE application_id = $1 AND endpoint_id = 'trust.manage')
        ",
    )
    .bind(APP_B_ID)
    .fetch_one(&mut *transaction)
    .await?;
    ensure!(
        revoked && unrelated_authority_survived,
        "application deletion missed authority or crossed the client boundary"
    );
    transaction.rollback().await?;
    Ok(())
}

async fn application_scope_revocation_contains_existing_access(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    let removed_scopes = sqlx::query_scalar::<_, String>(
        r"
        UPDATE iam.application_approved_scopes
        SET revoked_by_carbon_id = $2, revoked_at = transaction_timestamp()
        WHERE application_id = $1 AND revoked_at IS NULL
          AND NOT (scope = ANY($3::text[]))
        RETURNING scope
        ",
    )
    .bind(APP_A_ID)
    .bind(CARBON_ID)
    .bind(Vec::<String>::new())
    .fetch_all(&mut *transaction)
    .await?;
    ensure!(
        removed_scopes == ["organizations.read"],
        "review did not identify the newly removed scope"
    );
    sqlx::query(super::applications::REVOKE_ACCESS_TOKENS_FOR_REMOVED_SCOPES_QUERY)
        .bind(APP_A_ID)
        .bind(&removed_scopes)
        .execute(&mut *transaction)
        .await?;

    let matching_token_contained = sqlx::query_scalar::<_, bool>(
        r"
        SELECT revoked_at IS NOT NULL
           AND revocation_reason = 'application_scope_revoked'
        FROM iam.access_tokens
        WHERE id = '00000000-0000-0000-0000-000000000101'
        ",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let nonmatching_scope_survived = sqlx::query_scalar::<_, bool>(
        r"
        SELECT revoked_at IS NULL
        FROM iam.access_tokens
        WHERE id = '00000000-0000-0000-0000-000000000102'
        ",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let other_client_survived = sqlx::query_scalar::<_, bool>(
        r"
        SELECT revoked_at IS NULL
        FROM iam.access_tokens
        WHERE id = '00000000-0000-0000-0000-000000000103'
        ",
    )
    .fetch_one(&mut *transaction)
    .await?;
    ensure!(
        matching_token_contained && nonmatching_scope_survived && other_client_survived,
        "scope-removal containment crossed or missed its token boundary"
    );
    transaction.rollback().await?;
    Ok(())
}

async fn authorization_code_scope_revocation_fails_closed(pool: &PgPool) -> anyhow::Result<()> {
    let request_id = Uuid::from_u128(0x61);
    let mut transaction = pool.begin().await?;
    let scopes = super::oauth::authorized_code_exchange_scopes(
        &mut transaction,
        request_id,
        CONSENT_ID,
        APP_A_ID,
    )
    .await
    .map_err(|error| anyhow::anyhow!("initial code scope authority failed: {error:?}"))?;
    ensure!(
        scopes == ["organizations.read"],
        "initial code scope authority was incomplete"
    );
    sqlx::query(
        r"
        UPDATE iam.application_approved_scopes
        SET revoked_by_carbon_id = $2, revoked_at = transaction_timestamp()
        WHERE application_id = $1 AND scope = 'organizations.read' AND revoked_at IS NULL
        ",
    )
    .bind(APP_A_ID)
    .bind(CARBON_ID)
    .execute(&mut *transaction)
    .await?;
    let revoked_approval = super::oauth::authorized_code_exchange_scopes(
        &mut transaction,
        request_id,
        CONSENT_ID,
        APP_A_ID,
    )
    .await;
    ensure!(
        revoked_approval.is_err(),
        "code exchange retained an application-revoked scope"
    );
    transaction.rollback().await?;

    let mut transaction = pool.begin().await?;
    sqlx::query(
        "DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id = $1 AND scope = 'organizations.read'",
    )
    .bind(CONSENT_ID)
    .execute(&mut *transaction)
    .await?;
    let revoked_consent = super::oauth::authorized_code_exchange_scopes(
        &mut transaction,
        request_id,
        CONSENT_ID,
        APP_A_ID,
    )
    .await;
    ensure!(
        revoked_consent.is_err(),
        "code exchange retained a consent-revoked scope"
    );
    transaction.rollback().await?;
    Ok(())
}

async fn authorization_code_is_single_use(pool: &PgPool) -> anyhow::Result<()> {
    let first = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE iam.oauth_authorization_codes
        SET consumed_at = transaction_timestamp()
        WHERE id = '00000000-0000-0000-0000-000000000081'
          AND consumed_at IS NULL
        RETURNING id
        ",
    )
    .fetch_optional(pool)
    .await?;
    let replay = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE iam.oauth_authorization_codes
        SET consumed_at = transaction_timestamp()
        WHERE id = '00000000-0000-0000-0000-000000000081'
          AND consumed_at IS NULL
        RETURNING id
        ",
    )
    .fetch_optional(pool)
    .await?;
    ensure!(
        first.is_some() && replay.is_none(),
        "authorization code was reusable"
    );
    Ok(())
}

async fn refresh_reuse_compromises_the_complete_family(pool: &PgPool) -> anyhow::Result<()> {
    let replacement_id = Uuid::from_u128(0x94);
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO iam.refresh_tokens (
            id, family_id, parent_token_id, token_digest,
            digest_key_version, token_prefix, expires_at
        ) VALUES ($1, $2, $3, decode(repeat('33', 32), 'hex'), 1,
                  'ort_ijklmnop', transaction_timestamp() + interval '1 day')
        ",
    )
    .bind(replacement_id)
    .bind(FAMILY_ID)
    .bind(PARENT_REFRESH_ID)
    .execute(&mut *transaction)
    .await?;
    let rotated = sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE iam.refresh_tokens
        SET consumed_at = transaction_timestamp(), replacement_token_id = $2
        WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
        RETURNING id
        ",
    )
    .bind(PARENT_REFRESH_ID)
    .bind(replacement_id)
    .fetch_optional(&mut *transaction)
    .await?;
    transaction.commit().await?;
    ensure!(
        rotated == Some(PARENT_REFRESH_ID),
        "first refresh did not rotate"
    );

    let consumed = sqlx::query_scalar::<_, bool>(
        "SELECT consumed_at IS NOT NULL FROM iam.refresh_tokens WHERE id = $1",
    )
    .bind(PARENT_REFRESH_ID)
    .fetch_one(pool)
    .await?;
    ensure!(consumed, "refresh replay was not detectable");
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'compromised', compromised_at = transaction_timestamp(),
            revocation_reason = 'refresh_token_reuse'
        WHERE id = $1 AND status = 'active'
        ",
    )
    .bind(FAMILY_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE iam.refresh_tokens
        SET revoked_at = COALESCE(revoked_at, transaction_timestamp())
        WHERE family_id = $1
        ",
    )
    .bind(FAMILY_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE iam.access_tokens
        SET revoked_at = COALESCE(revoked_at, transaction_timestamp()),
            revocation_reason = COALESCE(revocation_reason, 'refresh_token_reuse')
        WHERE authentication_session_id = '00000000-0000-0000-0000-000000000041'
          AND client_application_id = $1
        ",
    )
    .bind(APP_A_ID)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM iam.refresh_token_families WHERE id = $1",
    )
    .bind(FAMILY_ID)
    .fetch_one(pool)
    .await?;
    let unrevoked = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.refresh_tokens WHERE family_id = $1 AND revoked_at IS NULL",
    )
    .bind(FAMILY_ID)
    .fetch_one(pool)
    .await?;
    let unrevoked_client_access = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*) FROM iam.access_tokens
        WHERE authentication_session_id = '00000000-0000-0000-0000-000000000041'
          AND client_application_id = $1 AND revoked_at IS NULL
        ",
    )
    .bind(APP_A_ID)
    .fetch_one(pool)
    .await?;
    let unrelated_client_access_active = sqlx::query_scalar::<_, bool>(
        r"
        SELECT revoked_at IS NULL FROM iam.access_tokens
        WHERE id = '00000000-0000-0000-0000-000000000103'
        ",
    )
    .fetch_one(pool)
    .await?;
    let parent_session_active = sqlx::query_scalar::<_, bool>(
        r"
        SELECT status = 'active' FROM iam.authentication_sessions
        WHERE id = '00000000-0000-0000-0000-000000000041'
        ",
    )
    .fetch_one(pool)
    .await?;
    ensure!(
        status == "compromised"
            && unrevoked == 0
            && unrevoked_client_access == 0
            && unrelated_client_access_active
            && parent_session_active,
        "refresh reuse containment crossed or missed its client boundary"
    );
    Ok(())
}

async fn consent_revocation_cascades_to_tokens(pool: &PgPool) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        UPDATE iam.oauth_consent_grants
        SET status = 'revoked', revoked_at = transaction_timestamp()
        WHERE id = $1 AND status = 'active'
        ",
    )
    .bind(CONSENT_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE iam.refresh_token_families
        SET status = 'revoked', revoked_at = transaction_timestamp(),
            revocation_reason = 'consent_revoked'
        WHERE oauth_consent_grant_id = $1 AND status = 'active'
        ",
    )
    .bind(CONSENT_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE iam.access_tokens
        SET revoked_at = transaction_timestamp(), revocation_reason = 'consent_revoked'
        WHERE client_application_id = $1 AND subject_principal_id = $2
          AND organization_id IS NULL AND revoked_at IS NULL
        ",
    )
    .bind(APP_A_ID)
    .bind(CARBON_ID)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let family_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM iam.refresh_token_families WHERE id = $1",
    )
    .bind(SECOND_FAMILY_ID)
    .fetch_one(pool)
    .await?;
    let access_revoked = sqlx::query_scalar::<_, bool>(
        r"
        SELECT revoked_at IS NOT NULL
        FROM iam.access_tokens
        WHERE id = '00000000-0000-0000-0000-000000000101'
        ",
    )
    .fetch_one(pool)
    .await?;
    ensure!(
        family_status == "revoked" && access_revoked,
        "consent authority survived revocation"
    );
    Ok(())
}

async fn obo_proof_is_single_use(pool: &PgPool) -> anyhow::Result<()> {
    let first = consume_obo_proof(pool).await?;
    let replay = consume_obo_proof(pool).await?;
    ensure!(
        first == Some(PROOF_ID) && replay.is_none(),
        "OBO proof was reusable"
    );
    Ok(())
}

async fn consume_obo_proof(pool: &PgPool) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r"
        UPDATE iam.obo_proofs
        SET consumed_at = transaction_timestamp(), consumed_by_application_id = $2
        WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
          AND expires_at > transaction_timestamp()
        RETURNING id
        ",
    )
    .bind(PROOF_ID)
    .bind(APP_B_ID)
    .fetch_optional(pool)
    .await
}

async fn committed_application_secret_revocation_wins_authentication(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let mut revocation = pool.begin().await?;
    sqlx::query(
        r"
        UPDATE iam.application_secrets
        SET status = 'retired', retired_at = transaction_timestamp()
        WHERE id = $1
        ",
    )
    .bind(APP_SECRET_ID)
    .execute(&mut *revocation)
    .await?;

    let authentication_pool = pool.clone();
    let authentication = tokio::spawn(async move {
        let mut transaction = authentication_pool.begin().await?;
        let resolved = sqlx::query_scalar::<_, Uuid>(
            r"
            SELECT id FROM iam.application_secrets
            WHERE id = $1
              AND (status = 'active' OR (status = 'retiring' AND retires_at > transaction_timestamp()))
            FOR UPDATE
            ",
        )
        .bind(APP_SECRET_ID)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok::<Option<Uuid>, sqlx::Error>(resolved)
    });
    tokio::task::yield_now().await;
    revocation.commit().await?;
    let resolved = authentication
        .await
        .context("application-secret authentication task panicked")??;
    ensure!(
        resolved.is_none(),
        "a committed secret revocation authenticated"
    );
    Ok(())
}

async fn seed_protocol_rows(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(
        r#"
        BEGIN;
        INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status)
        VALUES ('token_hmac', 1, 'active'), ('contact_aead', 1, 'active');

        INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
          ('00000000-0000-0000-0000-000000000001', 'carbon', 'active', transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000011', 'application', 'active', transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000012', 'application', 'active', transaction_timestamp());
        INSERT INTO iam.carbons (id, carbon_id, display_name)
        VALUES ('00000000-0000-0000-0000-000000000001', 'test_carbon', 'Test Carbon');
        INSERT INTO iam.carbon_contacts (
            id, carbon_id, kind, ciphertext, nonce, encryption_key_version, verified_at
        ) VALUES
          ('00000000-0000-0000-0000-000000000002',
           '00000000-0000-0000-0000-000000000001', 'email',
           decode(repeat('02', 17), 'hex'), decode(repeat('12', 12), 'hex'), 1,
           transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000003',
           '00000000-0000-0000-0000-000000000001', 'phone',
           decode(repeat('03', 17), 'hex'), decode(repeat('13', 12), 'hex'), 1,
           transaction_timestamp());
        INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
        VALUES ('00000000-0000-0000-0000-000000000021', 'test_org',
                '00000000-0000-0000-0000-000000000001', 'Test Organization');
        INSERT INTO iam.organization_memberships (
            id, organization_id, principal_id, principal_kind, org_role
        ) VALUES (
            '00000000-0000-0000-0000-000000000031',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000001', 'carbon', 'owner'
        );
        INSERT INTO iam.applications (id, app_id, owner_carbon_id, review_status) VALUES
          ('00000000-0000-0000-0000-000000000011', 'app-alpha',
           '00000000-0000-0000-0000-000000000001', 'verified'),
          ('00000000-0000-0000-0000-000000000012', 'app-beta',
           '00000000-0000-0000-0000-000000000001', 'verified');
        INSERT INTO iam.application_secrets (
            id, application_id, secret_version, secret_prefix, secret_digest,
            pepper_key_version, created_by_carbon_id
        ) VALUES (
            '00000000-0000-0000-0000-000000000131',
            '00000000-0000-0000-0000-000000000011', 1, 'ask_abcdefgh',
            decode(repeat('13', 32), 'hex'), 1,
            '00000000-0000-0000-0000-000000000001'
        );
        INSERT INTO iam.application_webhook_endpoints (
            id, application_id, url_ciphertext, url_nonce, encryption_key_version,
            url_digest, status, activated_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000141',
            '00000000-0000-0000-0000-000000000011',
            decode(repeat('41', 17), 'hex'), decode(repeat('42', 12), 'hex'), 1,
            decode(repeat('43', 32), 'hex'), 'active', transaction_timestamp()
        );
        INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES (
            '00000000-0000-0000-0000-000000000142',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000141', 1, 'whs_abcdefgh',
            decode(repeat('44', 17), 'hex'), decode(repeat('45', 12), 'hex'), 1
        );
        INSERT INTO iam.authentication_sessions (
            id, subject_principal_id, subject_kind, authentication_method,
            assurance_level, subject_auth_epoch, idle_expires_at, absolute_expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000041',
            '00000000-0000-0000-0000-000000000001', 'carbon', 'email_otp', 1, 1,
            transaction_timestamp() + interval '1 day',
            transaction_timestamp() + interval '2 days'
        );
        INSERT INTO iam.application_redirect_uris (
            id, application_id, redirect_uri, uri_digest, status, approved_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000051',
            '00000000-0000-0000-0000-000000000011', 'https://client.test/callback',
            decode(repeat('51', 32), 'hex'), 'active', transaction_timestamp()
        );
        INSERT INTO iam.application_requested_scopes (application_id, scope)
        VALUES ('00000000-0000-0000-0000-000000000011', 'organizations.read');
        INSERT INTO iam.application_approved_scopes (application_id, scope, approved_by_carbon_id)
        VALUES ('00000000-0000-0000-0000-000000000011', 'organizations.read',
                '00000000-0000-0000-0000-000000000001');
        INSERT INTO iam.oauth_authorization_requests (
            id, application_id, redirect_uri_id, authentication_session_id,
            subject_principal_id, subject_kind, state_digest, state_ciphertext,
            state_encryption_nonce, encryption_key_version, pkce_code_challenge,
            status, expires_at, decided_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000061',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000051',
            '00000000-0000-0000-0000-000000000041',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            decode(repeat('61', 32), 'hex'), decode(repeat('62', 17), 'hex'),
            decode(repeat('63', 12), 'hex'), 1, repeat('A', 43), 'approved',
            transaction_timestamp() + interval '2 minutes', transaction_timestamp()
        );
        INSERT INTO iam.oauth_authorization_request_scopes (
            authorization_request_id, application_id, scope, approved_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000061',
            '00000000-0000-0000-0000-000000000011', 'organizations.read', transaction_timestamp()
        );
        INSERT INTO iam.oauth_consent_grants (
            id, application_id, subject_principal_id, subject_kind,
            parent_authentication_session_id
        ) VALUES (
            '00000000-0000-0000-0000-000000000071',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            '00000000-0000-0000-0000-000000000041'
        );
        INSERT INTO iam.oauth_consent_grant_scopes (consent_grant_id, scope)
        VALUES ('00000000-0000-0000-0000-000000000071', 'organizations.read');
        INSERT INTO iam.oauth_authorization_codes (
            id, authorization_request_id, application_id, code_digest,
            digest_key_version, code_prefix, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000081',
            '00000000-0000-0000-0000-000000000061',
            '00000000-0000-0000-0000-000000000011',
            decode(repeat('81', 32), 'hex'), 1, 'oac_abcdefgh',
            transaction_timestamp() + interval '2 minutes'
        );
        INSERT INTO iam.refresh_token_families (
            id, authentication_session_id, subject_principal_id,
            client_application_id, oauth_consent_grant_id, absolute_expires_at
        ) VALUES
          ('00000000-0000-0000-0000-000000000091',
           '00000000-0000-0000-0000-000000000041',
           '00000000-0000-0000-0000-000000000001',
           '00000000-0000-0000-0000-000000000011',
           '00000000-0000-0000-0000-000000000071', transaction_timestamp() + interval '30 days'),
          ('00000000-0000-0000-0000-000000000093',
           '00000000-0000-0000-0000-000000000041',
           '00000000-0000-0000-0000-000000000001',
           '00000000-0000-0000-0000-000000000011',
           '00000000-0000-0000-0000-000000000071', transaction_timestamp() + interval '30 days');
        INSERT INTO iam.oauth_refresh_family_scopes (family_id, consent_grant_id, scope) VALUES
          ('00000000-0000-0000-0000-000000000091',
           '00000000-0000-0000-0000-000000000071', 'organizations.read'),
          ('00000000-0000-0000-0000-000000000093',
           '00000000-0000-0000-0000-000000000071', 'organizations.read');
        INSERT INTO iam.refresh_tokens (
            id, family_id, token_digest, digest_key_version, token_prefix, expires_at
        ) VALUES
          ('00000000-0000-0000-0000-000000000092',
           '00000000-0000-0000-0000-000000000091', decode(repeat('92', 32), 'hex'), 1,
           'ort_abcdefgh', transaction_timestamp() + interval '1 day'),
          ('00000000-0000-0000-0000-000000000095',
           '00000000-0000-0000-0000-000000000093', decode(repeat('95', 32), 'hex'), 1,
           'ort_qrstuvwx', transaction_timestamp() + interval '1 day');
        INSERT INTO iam.access_tokens (
            id, token_class, token_digest, digest_key_version, token_prefix,
            authentication_session_id, subject_principal_id, subject_kind,
            client_application_id, audience, audience_application_id,
            subject_auth_epoch, client_auth_epoch, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000101', 'application_access',
            decode(repeat('10', 32), 'hex'), 1, 'oat_abcdefgh',
            '00000000-0000-0000-0000-000000000041',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            '00000000-0000-0000-0000-000000000011', 'app-alpha',
            '00000000-0000-0000-0000-000000000011', 1, 1,
            transaction_timestamp() + interval '15 minutes'
        );
        INSERT INTO iam.access_tokens (
            id, token_class, token_digest, digest_key_version, token_prefix,
            authentication_session_id, subject_principal_id, subject_kind,
            client_application_id, audience, audience_application_id,
            organization_id, membership_id, subject_auth_epoch,
            membership_authz_epoch, client_auth_epoch, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000102', 'application_access',
            decode(repeat('12', 32), 'hex'), 1, 'oat_ijklmnop',
            '00000000-0000-0000-0000-000000000041',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            '00000000-0000-0000-0000-000000000011', 'app-alpha',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000031', 1, 1, 1,
            transaction_timestamp() + interval '15 minutes'
        );
        INSERT INTO iam.access_tokens (
            id, token_class, token_digest, digest_key_version, token_prefix,
            authentication_session_id, subject_principal_id, subject_kind,
            client_application_id, audience, audience_application_id,
            subject_auth_epoch, client_auth_epoch, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000103', 'application_access',
            decode(repeat('14', 32), 'hex'), 1, 'oat_qrstuvwx',
            '00000000-0000-0000-0000-000000000041',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            '00000000-0000-0000-0000-000000000012', 'app-beta',
            '00000000-0000-0000-0000-000000000012', 1, 1,
            transaction_timestamp() + interval '15 minutes'
        );
        INSERT INTO iam.access_token_scopes (access_token_id, scope) VALUES
          ('00000000-0000-0000-0000-000000000101', 'organizations.read'),
          ('00000000-0000-0000-0000-000000000102', 'memberships.read'),
          ('00000000-0000-0000-0000-000000000103', 'organizations.read');
        INSERT INTO iam.application_obo_endpoints (
            application_id, endpoint_id, path, metadata_definition
        ) VALUES (
            '00000000-0000-0000-0000-000000000012',
            'trust.manage', '/v1/trust', '{"reason":{"type":"string"}}'
        );
        INSERT INTO iam.obo_proofs (
            id, proof_digest, digest_key_version, proof_prefix,
            issuer_application_id, audience_application_id,
            subject_principal_id, subject_kind, organization_id, membership_id,
            parent_access_token_id, endpoint_id, request_metadata, endpoint_version,
            subject_auth_epoch,
            membership_authz_epoch, issuer_auth_epoch, audience_auth_epoch, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000121',
            decode(repeat('21', 32), 'hex'), 1, 'obo_abcdefgh',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000012',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000031',
            '00000000-0000-0000-0000-000000000102', 'trust.manage',
            '{"reason":"review"}', 1, 1, 1, 1, 1,
            transaction_timestamp() + interval '60 seconds'
        );
        COMMIT;
        "#,
    )
    .execute(pool)
    .await
    .context("seed application protocol invariant test")?;
    Ok(())
}
