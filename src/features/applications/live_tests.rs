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
const ADMIN_CARBON_ID: Uuid = Uuid::from_u128(2);
const ORGANIZATION_ID: Uuid = Uuid::from_u128(0x21);
const OWNER_MEMBERSHIP_ID: Uuid = Uuid::from_u128(0x31);
const ADMIN_MEMBERSHIP_ID: Uuid = Uuid::from_u128(0x32);
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

    authorized_application_organization_projection_is_exact(&pool).await?;
    application_lifecycle_and_manual_replay_are_atomic(&pool).await?;
    application_deletion_revokes_all_client_authority(&pool).await?;
    authorization_code_scope_revocation_fails_closed(&pool).await?;
    application_scope_revocation_contains_existing_access(&pool).await?;
    authorization_code_is_single_use(&pool).await?;
    refresh_reuse_compromises_the_complete_family(&pool).await?;
    consent_revocation_cascades_to_tokens(&pool).await?;
    obo_proof_is_single_use(&pool).await?;
    expired_obo_proof_cannot_be_consumed_after_transaction_wait(&pool).await?;
    stale_obo_parent_authority_is_rejected(&pool).await?;
    committed_application_secret_revocation_wins_authentication(&pool).await?;
    organization_management_authority_tracks_current_roles(&pool).await?;
    application_list_authority_lock_blocks_concurrent_demotion(&pool).await?;
    application_tenancy_and_creator_are_immutable(&pool).await?;
    Ok(())
}

async fn authorized_application_organization_projection_is_exact(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let reviewer_id = Uuid::from_u128(3);
    let other_organization_id = Uuid::from_u128(0x22);
    let other_application_id = Uuid::from_u128(0x13);
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
          ($1, 'carbon', 'active', transaction_timestamp()),
          ($2, 'application', 'active', transaction_timestamp())
        ",
    )
    .bind(reviewer_id)
    .bind(other_application_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO iam.carbons (id, carbon_id, display_name) VALUES ($1, 'test_reviewer', 'Test Reviewer')",
    )
    .bind(reviewer_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.platform_role_grants (id, carbon_id, role, grant_source)
        VALUES ('00000000-0000-0000-0000-000000000181', $1,
                'application_reviewer', 'bootstrap')
        ",
    )
    .bind(reviewer_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
        VALUES ($1, 'other_org', $2, 'Other Organization')
        ",
    )
    .bind(other_organization_id)
    .bind(reviewer_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.applications (
            id, app_id, organization_id, created_by_carbon_id, review_status
        ) VALUES ($1, 'app-gamma', $2, $3, 'verified')
        ",
    )
    .bind(other_application_id)
    .bind(other_organization_id)
    .bind(reviewer_id)
    .execute(&mut *transaction)
    .await?;

    set_application_projection_context(&mut transaction, CARBON_ID, None).await?;
    let owner_org = projected_organization(&mut transaction, APP_A_ID).await?;
    ensure!(
        owner_org.as_deref() == Some("test_org"),
        "current organization owner could not project an Application tenant"
    );

    set_application_projection_context(&mut transaction, reviewer_id, None).await?;
    let reviewer_org = projected_organization(&mut transaction, APP_A_ID).await?;
    ensure!(
        reviewer_org.as_deref() == Some("test_org"),
        "Application reviewer could not project an Application tenant"
    );

    set_application_projection_context(&mut transaction, APP_A_ID, Some(APP_A_ID)).await?;
    let same_org = projected_organization(&mut transaction, APP_B_ID).await?;
    let cross_org = projected_organization(&mut transaction, other_application_id).await?;
    ensure!(
        same_org.as_deref() == Some("test_org") && cross_org.is_none(),
        "Application projection did not enforce the exact same-organization boundary"
    );

    sqlx::query(
        r"
        UPDATE iam.principals
        SET status = 'suspended', suspended_at = transaction_timestamp()
        WHERE id = $1
        ",
    )
    .bind(APP_A_ID)
    .execute(&mut *transaction)
    .await?;
    let suspended_caller = projected_organization(&mut transaction, APP_B_ID).await?;
    ensure!(
        suspended_caller.is_none(),
        "suspended Application caller retained organization discovery authority"
    );
    transaction.rollback().await?;
    Ok(())
}

async fn set_application_projection_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal_id: Uuid,
    application_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
        SELECT set_config('iam.principal_id', $1, true),
               set_config('iam.application_id', $2, true)
        ",
    )
    .bind(principal_id.to_string())
    .bind(application_id.map_or_else(String::new, |id| id.to_string()))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn projected_organization(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    application_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        r"
        SELECT org_id
        FROM iam_private.resolve_authorized_application_organization($1)
        ",
    )
    .bind(application_id)
    .fetch_optional(&mut **transaction)
    .await
}

async fn application_list_authority_lock_blocks_concurrent_demotion(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let mut list_transaction = pool.begin().await?;
    super::applications::lock_current_application_manager(
        &mut list_transaction,
        ORGANIZATION_ID,
        ADMIN_CARBON_ID,
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!("failed to lock the current Application manager for list consistency")
    })?;

    let mut demotion_transaction = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout = '250ms'")
        .execute(&mut *demotion_transaction)
        .await?;
    let Err(demotion_error) = sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET org_role = 'member', role_granted_by_membership_id = NULL
        WHERE id = $1
        ",
    )
    .bind(ADMIN_MEMBERSHIP_ID)
    .execute(&mut *demotion_transaction)
    .await
    else {
        anyhow::bail!("concurrent demotion bypassed the Application list authority lock");
    };
    ensure!(
        demotion_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
            == Some("55P03"),
        "concurrent demotion failed for an unexpected reason: {demotion_error}"
    );
    demotion_transaction.rollback().await?;
    list_transaction.commit().await?;
    Ok(())
}

async fn organization_management_authority_tracks_current_roles(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let initially_authorized = sqlx::query_scalar::<_, bool>(
        "SELECT iam_private.is_active_organization_owner_or_admin($1, $2)",
    )
    .bind(ORGANIZATION_ID)
    .bind(ADMIN_CARBON_ID)
    .fetch_one(pool)
    .await?;
    ensure!(
        initially_authorized,
        "an active organization admin could not manage its applications"
    );

    sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET org_role = 'member', role_granted_by_membership_id = NULL
        WHERE id = $1
        ",
    )
    .bind(ADMIN_MEMBERSHIP_ID)
    .execute(pool)
    .await?;
    let authorized_after_demotion = sqlx::query_scalar::<_, bool>(
        "SELECT iam_private.is_active_organization_owner_or_admin($1, $2)",
    )
    .bind(ORGANIZATION_ID)
    .bind(ADMIN_CARBON_ID)
    .fetch_one(pool)
    .await?;
    ensure!(
        !authorized_after_demotion,
        "a demoted organization admin retained Application management authority"
    );

    sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET org_role = 'admin', role_granted_by_membership_id = $2
        WHERE id = $1
        ",
    )
    .bind(ADMIN_MEMBERSHIP_ID)
    .bind(OWNER_MEMBERSHIP_ID)
    .execute(pool)
    .await?;
    let authorized_after_repromotion = sqlx::query_scalar::<_, bool>(
        "SELECT iam_private.is_active_organization_owner_or_admin($1, $2)",
    )
    .bind(ORGANIZATION_ID)
    .bind(ADMIN_CARBON_ID)
    .fetch_one(pool)
    .await?;
    ensure!(
        authorized_after_repromotion,
        "a re-promoted organization admin did not regain Application management authority"
    );
    Ok(())
}

async fn application_tenancy_and_creator_are_immutable(pool: &PgPool) -> anyhow::Result<()> {
    let Err(organization_change) =
        sqlx::query("UPDATE iam.applications SET organization_id = $2 WHERE id = $1")
            .bind(APP_B_ID)
            .bind(Uuid::from_u128(0x22))
            .execute(pool)
            .await
    else {
        anyhow::bail!("Application organization mutation unexpectedly succeeded");
    };
    ensure!(
        organization_change
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
            == Some("23514"),
        "Application organization mutation did not fail through the immutable identity guard"
    );

    let Err(creator_change) =
        sqlx::query("UPDATE iam.applications SET created_by_carbon_id = $2 WHERE id = $1")
            .bind(APP_B_ID)
            .bind(ADMIN_CARBON_ID)
            .execute(pool)
            .await
    else {
        anyhow::bail!("Application creator mutation unexpectedly succeeded");
    };
    ensure!(
        creator_change
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
            == Some("23514"),
        "Application creator mutation did not fail through the immutable identity guard"
    );
    Ok(())
}

async fn application_lifecycle_and_manual_replay_are_atomic(pool: &PgPool) -> anyhow::Result<()> {
    let replacement_secret_id = Uuid::from_u128(0x132);
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
    // The ceiling is read through an owner-rights function that answers only
    // for the application the caller is authenticated as, exactly as the real
    // exchange runs it.
    set_application_projection_context(&mut transaction, APP_A_ID, Some(APP_A_ID)).await?;
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
    // The ceiling is read through an owner-rights function that answers only
    // for the application the caller is authenticated as, exactly as the real
    // exchange runs it.
    set_application_projection_context(&mut transaction, APP_A_ID, Some(APP_A_ID)).await?;
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

async fn stale_obo_parent_authority_is_rejected(pool: &PgPool) -> anyhow::Result<()> {
    let parent_id = Uuid::from_u128(0x102);
    let parent_is_current = sqlx::query_scalar::<_, bool>(
        r"
        SELECT parent.membership_authz_epoch = membership.authz_epoch
        FROM iam.access_tokens AS parent
        JOIN iam.organization_memberships AS membership
          ON membership.organization_id = parent.organization_id
         AND membership.id = parent.membership_id
         AND membership.principal_id = parent.subject_principal_id
         AND membership.principal_kind = parent.subject_kind
        JOIN iam.access_token_scopes AS token_scope
          ON token_scope.access_token_id = parent.id
         AND token_scope.scope = 'obo.issue'
        WHERE parent.id = $1
        ",
    )
    .bind(parent_id)
    .fetch_one(pool)
    .await?;
    ensure!(parent_is_current, "seeded OBO parent token was not current");

    sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET authz_epoch = authz_epoch + 1
        WHERE id = $1
        ",
    )
    .bind(OWNER_MEMBERSHIP_ID)
    .execute(pool)
    .await?;
    let stale_parent_is_accepted = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM iam.access_tokens AS parent
            JOIN iam.organization_memberships AS membership
              ON membership.organization_id = parent.organization_id
             AND membership.id = parent.membership_id
             AND membership.principal_id = parent.subject_principal_id
             AND membership.principal_kind = parent.subject_kind
             AND parent.membership_authz_epoch = membership.authz_epoch
            JOIN iam.access_token_scopes AS token_scope
              ON token_scope.access_token_id = parent.id
             AND token_scope.scope = 'obo.issue'
            WHERE parent.id = $1
        )
        ",
    )
    .bind(parent_id)
    .fetch_one(pool)
    .await?;
    ensure!(
        !stale_parent_is_accepted,
        "an OBO parent token survived a membership authorization epoch change"
    );
    Ok(())
}

async fn expired_obo_proof_cannot_be_consumed_after_transaction_wait(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let expiring_proof_id = Uuid::from_u128(0x122);
    sqlx::query(
        r"
        WITH wall_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS value
        )
        INSERT INTO iam.obo_proofs (
            id, proof_digest, digest_key_version, proof_prefix,
            issuer_application_id, audience_application_id,
            subject_principal_id, subject_kind, organization_id, membership_id,
            parent_access_token_id, endpoint_id, request_metadata, endpoint_version,
            request_method, request_path, request_body_sha256, request_signed_at,
            subject_auth_epoch, membership_authz_epoch,
            issuer_auth_epoch, audience_auth_epoch, created_at, expires_at
        )
        SELECT $1, decode(repeat('22', 32), 'hex'), digest_key_version, 'obo_expiring',
               issuer_application_id, audience_application_id,
               subject_principal_id, subject_kind, organization_id, membership_id,
               parent_access_token_id, endpoint_id, request_metadata, endpoint_version,
               request_method, request_path, request_body_sha256, wall_clock.value,
               subject_auth_epoch, membership_authz_epoch,
               issuer_auth_epoch, audience_auth_epoch, wall_clock.value,
               wall_clock.value + interval '100 milliseconds'
        FROM iam.obo_proofs AS template
        CROSS JOIN wall_clock
        WHERE template.id = $2
        ",
    )
    .bind(expiring_proof_id)
    .bind(PROOF_ID)
    .execute(pool)
    .await?;

    let mut verification = pool.begin().await?;
    sqlx::query("SELECT transaction_timestamp()")
        .execute(&mut *verification)
        .await?;
    sqlx::query("SELECT pg_sleep(0.2)")
        .execute(&mut *verification)
        .await?;
    let consumed = sqlx::query_scalar::<_, Uuid>(
        r"
        WITH wall_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS value
        )
        UPDATE iam.obo_proofs
        SET consumed_at = wall_clock.value, consumed_by_application_id = $2
        FROM wall_clock
        WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL
          AND expires_at > wall_clock.value
        RETURNING id
        ",
    )
    .bind(expiring_proof_id)
    .bind(APP_B_ID)
    .fetch_optional(&mut *verification)
    .await?;
    ensure!(
        consumed.is_none(),
        "an OBO proof was consumed after wall-clock expiry"
    );
    verification.rollback().await?;
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
          ('00000000-0000-0000-0000-000000000002', 'carbon', 'active', transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000011', 'application', 'active', transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000012', 'application', 'active', transaction_timestamp());
        INSERT INTO iam.carbons (id, carbon_id, display_name) VALUES
          ('00000000-0000-0000-0000-000000000001', 'test_carbon', 'Test Carbon'),
          ('00000000-0000-0000-0000-000000000002', 'test_admin', 'Test Admin');
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
           transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000004',
           '00000000-0000-0000-0000-000000000002', 'email',
           decode(repeat('04', 17), 'hex'), decode(repeat('14', 12), 'hex'), 1,
           transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000005',
           '00000000-0000-0000-0000-000000000002', 'phone',
           decode(repeat('05', 17), 'hex'), decode(repeat('15', 12), 'hex'), 1,
           transaction_timestamp());
        INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
        VALUES ('00000000-0000-0000-0000-000000000021', 'test_org',
                '00000000-0000-0000-0000-000000000001', 'Test Organization');
        INSERT INTO iam.organization_memberships (
            id, organization_id, principal_id, principal_kind, org_role,
            job_role, role_granted_by_membership_id
        ) VALUES (
            '00000000-0000-0000-0000-000000000031',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000001', 'carbon', 'owner', '', NULL
        ), (
            '00000000-0000-0000-0000-000000000032',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000002', 'carbon', 'admin', '',
            '00000000-0000-0000-0000-000000000031'
        );
        INSERT INTO iam.applications (
            id, app_id, organization_id, created_by_carbon_id, review_status
        ) VALUES
          ('00000000-0000-0000-0000-000000000011', 'app-alpha',
           '00000000-0000-0000-0000-000000000021',
           '00000000-0000-0000-0000-000000000001', 'verified'),
          ('00000000-0000-0000-0000-000000000012', 'app-beta',
           '00000000-0000-0000-0000-000000000021',
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
        INSERT INTO iam.application_requested_scopes (application_id, scope)
        VALUES ('00000000-0000-0000-0000-000000000011', 'organizations.read');
        INSERT INTO iam.application_approved_scopes (application_id, scope, approved_by_carbon_id)
        VALUES ('00000000-0000-0000-0000-000000000011', 'organizations.read',
                '00000000-0000-0000-0000-000000000001');
        INSERT INTO iam.oauth_authorization_requests (
            id, application_id, redirect_uri, authentication_session_id,
            subject_principal_id, subject_kind,
            status, expires_at, decided_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000061',
            '00000000-0000-0000-0000-000000000011',
            'https://client.test/callback',
            '00000000-0000-0000-0000-000000000041',
            '00000000-0000-0000-0000-000000000001', 'carbon', 'approved',
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
          ('00000000-0000-0000-0000-000000000102', 'obo.issue'),
          ('00000000-0000-0000-0000-000000000103', 'organizations.read');
        INSERT INTO iam.application_obo_endpoints (
            organization_id, application_id, endpoint_id, path, metadata_definition
        ) VALUES (
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000012',
            'trust.manage', '/v1/trust', '{"reason":{"type":"string"}}'
        );
        INSERT INTO iam.obo_proofs (
            id, proof_digest, digest_key_version, proof_prefix,
            issuer_application_id, audience_application_id,
            subject_principal_id, subject_kind, organization_id, membership_id,
            parent_access_token_id, endpoint_id, request_metadata, endpoint_version,
            request_method, request_path, request_body_sha256, request_signed_at,
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
            '{"reason":"review"}', 1, 'POST', '/v1/trust',
            decode(repeat('00', 32), 'hex'), transaction_timestamp(),
            1, 1, 1, 1,
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
