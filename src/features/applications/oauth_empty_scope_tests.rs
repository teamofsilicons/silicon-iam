//! Empty ordinary login authority remains separate from endpoint OBO consent.
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use anyhow::{Context as _, ensure};

use super::*;
use crate::{
    config::Settings,
    infrastructure::{crypto::CryptoService, providers::NotificationProviders},
};

const APP: Id = Id::fixture("app-alpha");
const CONSENT: Id = Id::from_u128(0x71);
const REQUEST: Id = Id::from_u128(0x62);

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL plus synthetic IAM settings"]
async fn oauth_obo_only_login_refreshes_without_restoring_revoked_iam_authority()
-> anyhow::Result<()> {
    let database = crate::test_database::TestDatabase::start().await?;
    let pool = database.pool.clone();
    crate::infrastructure::postgres::migrate(&pool).await?;
    super::super::live_tests::seed_protocol_rows(&pool).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(&pool)
        .await?;
    sqlx::raw_sql(
        r#"
        UPDATE iam.applications SET app_scope =
          '{"iam":[],"external":[{"app_id":"app-beta","endpoint_id":"trust.manage"}]}'
        WHERE id = 'app-alpha';
        UPDATE iam.application_approved_scopes SET revoked_at = transaction_timestamp(), revoked_by_policy = true
        WHERE application_id = 'app-alpha' AND scope NOT LIKE 'obo:%';
        INSERT INTO iam.oauth_authorization_requests (
            id, application_id, redirect_uri, authentication_session_id,
            subject_principal_id, subject_kind, status, expires_at, decided_at
        ) SELECT '00000000-0000-0000-0000-000000000062', application_id, redirect_uri,
            authentication_session_id, subject_principal_id, subject_kind,
            status, expires_at, decided_at
        FROM iam.oauth_authorization_requests
        WHERE id = '00000000-0000-0000-0000-000000000061';
        INSERT INTO iam.oauth_authorization_request_scopes (
            authorization_request_id, application_id, scope, approved_at
        ) SELECT '00000000-0000-0000-0000-000000000062', application_id, scope, approved_at
        FROM iam.application_approved_scopes
        WHERE application_id = 'app-alpha' AND scope = 'obo:app-beta:trust.manage';
        "#,
    )
    .execute(&pool)
    .await?;
    let settings = Settings::from_env()?;
    let state = ApiState {
        pool: pool.clone(),
        testing: None,
        crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
        notifications: NotificationProviders::from_settings(&settings.providers)?,
        workos: None,
        settings: Arc::new(settings),
    };
    let client = ApplicationIdentity {
        application_id: APP,
        app_id: "app-alpha".to_owned(),
        organization_id: Id::from_u128(0x21),
        auth_epoch: 1,
    };
    let mut tx = runtime(&pool).await?;
    ensure!(
        authorized_code_exchange_scopes(&mut tx, REQUEST, CONSENT, APP)
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?
            .is_empty(),
        "legacy external scope rows must not become ordinary login authority"
    );
    ensure!(
        authorized_code_exchange_scopes(&mut tx, Id::from_u128(0x61), CONSENT, APP)
            .await
            .is_err(),
        "revoked nonempty authorization-code authority must remain invalid"
    );
    ensure!(
        locked_refresh_issuance_scopes(&mut tx, Id::from_u128(0x91), CONSENT, APP)
            .await
            .is_err(),
        "revoked nonempty refresh authority must not become an empty login"
    );
    let first = issue(&mut tx, &state, &client, None).await?;
    ensure!(first.scope.is_empty() && first.actor.is_none());
    let digest = state.crypto.digest_secret(
        DigestPurpose::OAuthRefreshToken,
        &SecretString::from(first.refresh_token.clone()),
    )?;
    let ids: (Id, Id) = sqlx::query_as(
        "SELECT family_id,id FROM iam.refresh_tokens WHERE token_digest=$1 AND digest_key_version=$2",
    )
    .bind(digest.as_bytes().as_slice())
    .bind(digest.key_version())
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        locked_refresh_issuance_scopes(&mut tx, ids.0, CONSENT, APP)
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?
            .is_empty()
    );
    ensure!(
        refresh_family_scopes(&mut tx, ids.0, CONSENT)
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?
            .is_empty()
    );
    let rotated = issue(&mut tx, &state, &client, Some(&ids)).await?;
    ensure!(rotated.scope.is_empty() && rotated.refresh_token != first.refresh_token);
    let authority: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam.access_token_scopes scope \
         JOIN iam.access_tokens token ON token.id=scope.access_token_id \
         WHERE token.oauth_refresh_family_id=$1",
    )
    .bind(ids.0)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(authority == 0, "empty login issued access-token authority");
    tx.commit().await?;
    let obo_grants: i64 = sqlx::query_scalar("SELECT count(*) FROM iam.obo_grants")
        .fetch_one(&pool)
        .await?;
    ensure!(
        obo_grants == 0,
        "ordinary login must not approve OBO grants"
    );

    sqlx::query("UPDATE iam.applications SET app_scope=jsonb_set(app_scope,'{iam}','[\"self.identity.read\"]') WHERE id=$1")
        .bind(APP).execute(&pool).await?;
    let mut tx = runtime(&pool).await?;
    ensure!(
        locked_refresh_issuance_scopes(&mut tx, ids.0, CONSENT, APP)
            .await
            .is_err(),
        "empty refresh requires an explicit current empty IAM declaration"
    );
    ensure!(
        authorized_code_exchange_scopes(&mut tx, REQUEST, CONSENT, APP)
            .await
            .is_err(),
        "empty authorization-code exchange requires the same explicit declaration"
    );
    tx.rollback().await?;
    pool.close().await;
    Ok(())
}

async fn runtime(pool: &sqlx::PgPool) -> anyhow::Result<Transaction<'_, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('iam.principal_id','app-alpha',true),set_config('iam.application_id','app-alpha',true)")
        .execute(&mut *tx).await?;
    Ok(tx)
}

async fn issue(
    tx: &mut Transaction<'_, Postgres>,
    state: &ApiState,
    client: &ApplicationIdentity,
    parent: Option<&(Id, Id)>,
) -> anyhow::Result<TokenResponse> {
    issue_tokens(
        tx,
        state,
        client,
        TokenSubject {
            session_id: Id::from_u128(0x41),
            principal_id: Id::fixture("c:test_carbon"),
            subject_kind: "carbon".to_owned(),
            subject_auth_epoch: 1,
            organization_id: None,
            membership_id: None,
            membership_authz_epoch: None,
            consent_grant_id: CONSENT,
            org_id: None,
            subject_public_id: "c:test_carbon".to_owned(),
        },
        &["obo:app-beta:trust.manage".to_owned()],
        parent.map(|ids| ids.0),
        parent.map(|ids| ids.1),
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error:?}"))
    .context("ordinary empty-authority login issuance")
}
