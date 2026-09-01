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

    authorization_code_scope_revocation_fails_closed(&pool).await?;
    application_scope_revocation_contains_existing_access(&pool).await?;
    authorization_code_is_single_use(&pool).await?;
    refresh_reuse_compromises_the_complete_family(&pool).await?;
    consent_revocation_cascades_to_tokens(&pool).await?;
    obo_proof_is_single_use(&pool).await?;
    committed_application_secret_revocation_wins_authentication(&pool).await?;
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
        removed_scopes == ["openid"],
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
        scopes == ["openid"],
        "initial code scope authority was incomplete"
    );
    sqlx::query(
        r"
        UPDATE iam.application_approved_scopes
        SET revoked_by_carbon_id = $2, revoked_at = transaction_timestamp()
        WHERE application_id = $1 AND scope = 'openid' AND revoked_at IS NULL
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
        "DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id = $1 AND scope = 'openid'",
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
        r"
        BEGIN;
        INSERT INTO iam.cryptographic_key_versions (purpose, key_version, status)
        VALUES ('token_hmac', 1, 'active'), ('contact_aead', 1, 'active');

        INSERT INTO iam.principals (id, kind, status, activated_at) VALUES
          ('00000000-0000-0000-0000-000000000001', 'carbon', 'active', transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000011', 'application', 'active', transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000012', 'application', 'active', transaction_timestamp());
        INSERT INTO iam.carbons (id, carbon_id, display_name)
        VALUES ('00000000-0000-0000-0000-000000000001', 'test_carbon', 'Test Carbon');
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
        VALUES ('00000000-0000-0000-0000-000000000011', 'openid');
        INSERT INTO iam.application_approved_scopes (application_id, scope, approved_by_carbon_id)
        VALUES ('00000000-0000-0000-0000-000000000011', 'openid',
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
        VALUES ('00000000-0000-0000-0000-000000000071', 'openid');
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
           '00000000-0000-0000-0000-000000000071', 'openid'),
          ('00000000-0000-0000-0000-000000000093',
           '00000000-0000-0000-0000-000000000071', 'openid');
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
          ('00000000-0000-0000-0000-000000000101', 'openid'),
          ('00000000-0000-0000-0000-000000000102', 'profile'),
          ('00000000-0000-0000-0000-000000000103', 'openid');
        INSERT INTO iam.obo_action_catalog (audience_application_id, action, description)
        VALUES ('00000000-0000-0000-0000-000000000012', 'trust.manage', 'Manage trust');
        INSERT INTO iam.obo_application_grants (
            id, issuer_application_id, audience_application_id, action, approved_by_carbon_id
        ) VALUES (
            '00000000-0000-0000-0000-000000000111',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000012', 'trust.manage',
            '00000000-0000-0000-0000-000000000001'
        );
        INSERT INTO iam.obo_proofs (
            id, proof_digest, digest_key_version, proof_prefix,
            issuer_application_id, audience_application_id,
            subject_principal_id, subject_kind, organization_id, membership_id,
            parent_access_token_id, action, subject_auth_epoch,
            membership_authz_epoch, issuer_auth_epoch, audience_auth_epoch, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000121',
            decode(repeat('21', 32), 'hex'), 1, 'obo_abcdefgh',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000012',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000031',
            '00000000-0000-0000-0000-000000000102', 'trust.manage', 1, 1, 1, 1,
            transaction_timestamp() + interval '60 seconds'
        );
        COMMIT;
        ",
    )
    .execute(pool)
    .await
    .context("seed application protocol invariant test")?;
    Ok(())
}
