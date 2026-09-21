//! Live PostgreSQL protocol-invariant coverage.
//!
//! The test is ignored in the default suite because it needs a disposable
//! PostgreSQL database. Docker is the default; `IAM_TEST_DATABASE_ADMIN_URL`
//! can select a local server for a fresh isolated database. Production credentials
//! must never be supplied. It exercises the same queries used by HTTP handlers.
#![allow(clippy::too_many_lines)]

use crate::domain::id::Id;
use anyhow::{Context as _, ensure};
use axum::{body::to_bytes, http::StatusCode, response::IntoResponse as _};
use serde_json::Value;
use sqlx::{Acquire as _, PgPool};

use crate::infrastructure::testing_plane::{self, SelectedEnvironment};

use super::applications::ensure_application_id_available_for_testing;

const CARBON_ID: Id = Id::fixture("test_carbon");
const ADMIN_CARBON_ID: Id = Id::fixture("test_admin");
const ORGANIZATION_ID: Id = Id::from_u128(0x21);
const OWNER_MEMBERSHIP_ID: Id = Id::from_u128(0x31);
const ADMIN_MEMBERSHIP_ID: Id = Id::from_u128(0x32);
const APP_A_ID: Id = Id::fixture("test_org>app-alpha");
const APP_B_ID: Id = Id::fixture("test_org>app-beta");
const CONSENT_ID: Id = Id::from_u128(0x71);
const FAMILY_ID: Id = Id::from_u128(0x91);
const SECOND_FAMILY_ID: Id = Id::from_u128(0x93);
const PARENT_REFRESH_ID: Id = Id::from_u128(0x92);
const PROOF_ID: Id = Id::from_u128(0x121);
const APP_SECRET_ID: Id = Id::from_u128(0x131);

#[tokio::test]
#[ignore = "requires Docker or local PostgreSQL via IAM_TEST_DATABASE_ADMIN_URL"]
async fn protocol_credentials_are_single_use_and_revocation_is_atomic() -> anyhow::Result<()> {
    let database = crate::test_database::TestDatabase::start().await?;
    let pool = database.pool.clone();
    crate::infrastructure::postgres::migrate(&pool).await?;
    seed_protocol_rows(&pool).await?;
    private_application_authority_and_endpoint_lifetime(&pool).await?;
    cross_organization_login_selection_reports_private_restriction(&pool).await?;

    unscoped_silicon_oauth_authority_preserves_its_exact_live_chain(&pool).await?;
    selected_login_additions_preserve_existing_organizations(&pool).await?;
    expired_obo_proof_cannot_be_consumed_after_transaction_wait(&pool).await?;
    consent_preserves_each_parent_session(&pool).await?;
    direct_test_creation_rejects_a_production_application_id(&pool).await?;
    qualified_application_directory_and_webhook_rotation_are_consistent(&pool).await?;
    pending_webhook_application_is_importable(&pool).await?;
    authorized_application_organization_projection_is_exact(&pool).await?;
    application_lifecycle_and_manual_replay_are_atomic(&pool).await?;
    application_deletion_revokes_all_client_authority(&pool).await?;
    authorization_code_scope_revocation_fails_closed(&pool).await?;
    application_scope_revocation_contains_existing_access(&pool).await?;
    authorization_code_is_single_use(&pool).await?;
    refresh_reuse_compromises_the_complete_family(&pool).await?;
    consent_revocation_cascades_to_tokens(&pool).await?;
    obo_proof_is_single_use(&pool).await?;
    stale_obo_parent_authority_is_rejected(&pool).await?;
    committed_application_secret_revocation_wins_authentication(&pool).await?;
    organization_management_authority_tracks_current_roles(&pool).await?;
    application_list_authority_lock_blocks_concurrent_demotion(&pool).await?;
    application_tenancy_and_creator_are_immutable(&pool).await?;
    Ok(())
}

/// Private authority is checked live, including existing grants and app callers.
async fn private_application_authority_and_endpoint_lifetime(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "SELECT set_config('iam.principal_id','',true),set_config('iam.application_id','',true)",
    )
    .execute(&mut *tx)
    .await?;
    let public = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam_private.discover_application_origin('test_org>app-alpha',NULL)",
    )
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        public == 1,
        "public origins must be anonymously discoverable"
    );
    sqlx::query("UPDATE iam.applications SET visibility='private' WHERE id=$1")
        .bind(APP_A_ID)
        .execute(&mut *tx)
        .await?;
    let hidden = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam_private.discover_application_origin('test_org>app-alpha',NULL)",
    )
    .fetch_one(&mut *tx)
    .await?;
    ensure!(hidden == 0, "private origins must not leak anonymously");
    sqlx::query("SELECT set_config('iam.principal_id',$1,true)")
        .bind(CARBON_ID.to_string())
        .execute(&mut *tx)
        .await?;
    ensure!(
        sqlx::query_scalar::<_, bool>("SELECT iam_private.application_is_discoverable($1,NULL)")
            .bind(APP_A_ID)
            .fetch_one(&mut *tx)
            .await?,
        "owner can discover private application"
    );
    sqlx::query(
        "SELECT set_config('iam.principal_id',$1,true),set_config('iam.application_id',$1,true)",
    )
    .bind(APP_B_ID.to_string())
    .execute(&mut *tx)
    .await?;
    ensure!(
        !sqlx::query_scalar::<_, bool>("SELECT iam_private.application_is_discoverable($1,NULL)")
            .bind(APP_A_ID)
            .fetch_one(&mut *tx)
            .await?,
        "an arbitrary app secret is not private discovery authority"
    );
    sqlx::query(
        "SELECT set_config('iam.principal_id',$1,true),set_config('iam.application_id',$1,true)",
    )
    .bind(APP_A_ID.to_string())
    .execute(&mut *tx)
    .await?;
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT iam_private.application_private_token_is_current($1)"
        )
        .bind(Id::from_u128(0x101))
        .fetch_one(&mut *tx)
        .await?,
        "owning membership authorizes existing private token"
    );
    ensure!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM iam_private.lock_current_application_oauth_subject_authority($1,$2,$3,$4,'carbon',NULL,NULL)").bind(APP_A_ID).bind(CONSENT_ID).bind(Id::from_u128(0x41)).bind(CARBON_ID).fetch_one(&mut *tx).await? == 1, "private refresh/introspection chain is live");
    // Suspend within a rollback-only transaction; no production data is involved.
    sqlx::query("UPDATE iam.organization_memberships SET status='suspended',suspended_at=transaction_timestamp() WHERE id=$1").bind(OWNER_MEMBERSHIP_ID).execute(&mut *tx).await?;
    ensure!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT iam_private.application_private_token_is_current($1)"
        )
        .bind(Id::from_u128(0x101))
        .fetch_one(&mut *tx)
        .await?,
        "membership removal invalidates private bearer authority"
    );
    ensure!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM iam_private.lock_current_application_oauth_subject_authority($1,$2,$3,$4,'carbon',NULL,NULL)").bind(APP_A_ID).bind(CONSENT_ID).bind(Id::from_u128(0x41)).bind(CARBON_ID).fetch_one(&mut *tx).await? == 0, "membership loss invalidates refresh and introspection");
    tx.rollback().await?;

    let mut tx = pool.begin().await?;
    let before = sqlx::query_as::<_, (i32,i64)>("SELECT ttl_seconds,version FROM iam.application_obo_endpoints WHERE application_id=$1 AND endpoint_id='trust.manage'").bind(APP_B_ID).fetch_one(&mut *tx).await?;
    ensure!(
        before.0 == 300,
        "existing endpoints migrate to five minutes"
    );
    let expiry = sqlx::query_scalar::<_, time::OffsetDateTime>(
        "SELECT expires_at FROM iam.obo_proofs WHERE id=$1",
    )
    .bind(PROOF_ID)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE iam.application_obo_endpoints SET ttl_seconds=900 WHERE application_id=$1 AND endpoint_id='trust.manage'").bind(APP_B_ID).execute(&mut *tx).await?;
    let after = sqlx::query_as::<_, (i32,i64)>("SELECT ttl_seconds,version FROM iam.application_obo_endpoints WHERE application_id=$1 AND endpoint_id='trust.manage'").bind(APP_B_ID).fetch_one(&mut *tx).await?;
    ensure!(
        after == (900, before.1),
        "TTL changes do not revoke earlier proofs by changing endpoint authority version"
    );
    ensure!(
        sqlx::query_scalar::<_, time::OffsetDateTime>(
            "SELECT expires_at FROM iam.obo_proofs WHERE id=$1"
        )
        .bind(PROOF_ID)
        .fetch_one(&mut *tx)
        .await?
            == expiry,
        "existing proof expiry is unchanged"
    );
    tx.rollback().await?;
    Ok(())
}

/// SLT exchange, refresh, and introspection share this authority projection.
/// Selected-organization Silicon logins must keep their unscoped token shape
/// while still depending on the Silicon's own live organization and membership.
async fn unscoped_silicon_oauth_authority_preserves_its_exact_live_chain(
    pool: &PgPool,
) -> anyhow::Result<()> {
    const AUTHORITY_QUERY: &str = r"
        SELECT to_jsonb(authority)
        FROM iam_private.lock_current_application_oauth_subject_authority(
            $1, $2, $3, $4, 'silicon', $5, $6
        ) AS authority
    ";
    let silicon_id = Id::fixture("test_silicon:test_org");
    let membership_id = Id::from_u128(0x531);
    let parent_id = Id::from_u128(0x541);
    let second_parent_id = Id::from_u128(0x542);
    let unscoped_consent = Id::from_u128(0x571);
    let scoped_consent = Id::from_u128(0x572);
    let mut transaction = pool.begin().await?;
    sqlx::raw_sql(
        r"
        INSERT INTO iam.principals (id, kind, status, activated_at)
        VALUES ('test_silicon:test_org', 'silicon', 'active',
                transaction_timestamp());
        INSERT INTO iam.organization_memberships (
            id, organization_id, principal_id, principal_kind, org_role
        ) VALUES ('00000000-0000-0000-0000-000000000531',
                  '00000000-0000-0000-0000-000000000021',
                  'test_silicon:test_org', 'silicon', 'member');
        INSERT INTO iam.silicons (
            id, organization_id, membership_id, organization_handle, silicon_handle,
            display_name, provisioning_status
        ) VALUES ('test_silicon:test_org',
                  '00000000-0000-0000-0000-000000000021',
                  '00000000-0000-0000-0000-000000000531', 'test_org', 'test_silicon',
                  'Test Silicon', 'active');
        INSERT INTO iam.authentication_sessions (
            id, subject_principal_id, subject_kind, authentication_method,
            assurance_level, subject_auth_epoch, idle_expires_at, absolute_expires_at
        ) SELECT id, 'test_silicon:test_org', 'silicon',
                 'silicon_credential', 1, 1,
                 transaction_timestamp() + interval '1 day',
                 transaction_timestamp() + interval '2 days'
          FROM unnest(ARRAY['00000000-0000-0000-0000-000000000541'::uuid,
                            '00000000-0000-0000-0000-000000000542'::uuid]) AS id;
        INSERT INTO iam.oauth_consent_grants (
            id, application_id, subject_principal_id, subject_kind,
            organization_id, membership_id, parent_authentication_session_id,
            selected_membership_ids
        ) VALUES (
            '00000000-0000-0000-0000-000000000571',
            'test_org>app-alpha',
            'test_silicon:test_org', 'silicon', NULL, NULL,
            '00000000-0000-0000-0000-000000000541',
            ARRAY['00000000-0000-0000-0000-000000000531'::uuid]
        ), (
            '00000000-0000-0000-0000-000000000572',
            'test_org>app-alpha',
            'test_silicon:test_org', 'silicon',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000531',
            '00000000-0000-0000-0000-000000000541',
            ARRAY['00000000-0000-0000-0000-000000000531'::uuid]
        );
        ",
    )
    .execute(&mut *transaction)
    .await?;
    set_context(&mut transaction, APP_A_ID, None, APP_A_ID).await?;

    for (consent, organization, membership) in [
        (unscoped_consent, None, None),
        (scoped_consent, Some(ORGANIZATION_ID), Some(membership_id)),
    ] {
        let authority = sqlx::query_scalar::<_, Value>(AUTHORITY_QUERY)
            .bind(APP_A_ID)
            .bind(consent)
            .bind(parent_id)
            .bind(silicon_id)
            .bind(organization)
            .bind(membership)
            .fetch_optional(&mut *transaction)
            .await?
            .context("a live Silicon login lost its OAuth subject authority")?;
        ensure!(authority["subject_public_id"] == "test_silicon:test_org");
        ensure!(authority["subject_auth_epoch"] == 1);
        ensure!(
            authority["org_id"] == serde_json::json!(organization.map(|_| "test_org"))
                && authority["membership_authz_epoch"] == serde_json::json!(membership.map(|_| 1)),
            "the Silicon login's organization binding changed: {authority}"
        );
        ensure!(authority["session_idle_expires_at"].is_string());
        ensure!(authority["session_absolute_expires_at"].is_string());
    }

    // Every identifier must belong to this exact grant, subject and session.
    for (label, application, consent, parent, subject, organization, membership) in [
        (
            "other Application",
            APP_B_ID,
            unscoped_consent,
            parent_id,
            silicon_id,
            None,
            None,
        ),
        (
            "other consent",
            APP_A_ID,
            CONSENT_ID,
            parent_id,
            silicon_id,
            None,
            None,
        ),
        (
            "other live parent",
            APP_A_ID,
            unscoped_consent,
            second_parent_id,
            silicon_id,
            None,
            None,
        ),
        (
            "other subject",
            APP_A_ID,
            unscoped_consent,
            parent_id,
            CARBON_ID,
            None,
            None,
        ),
        (
            "added organization binding",
            APP_A_ID,
            unscoped_consent,
            parent_id,
            silicon_id,
            Some(ORGANIZATION_ID),
            Some(membership_id),
        ),
        (
            "removed organization binding",
            APP_A_ID,
            scoped_consent,
            parent_id,
            silicon_id,
            None,
            None,
        ),
        (
            "other membership",
            APP_A_ID,
            scoped_consent,
            parent_id,
            silicon_id,
            Some(ORGANIZATION_ID),
            Some(OWNER_MEMBERSHIP_ID),
        ),
        (
            "partial organization binding",
            APP_A_ID,
            unscoped_consent,
            parent_id,
            silicon_id,
            Some(ORGANIZATION_ID),
            None,
        ),
    ] {
        set_context(&mut transaction, application, None, application).await?;
        let authority = sqlx::query_scalar::<_, Value>(AUTHORITY_QUERY)
            .bind(application)
            .bind(consent)
            .bind(parent)
            .bind(subject)
            .bind(organization)
            .bind(membership)
            .fetch_optional(&mut *transaction)
            .await?;
        ensure!(
            authority.is_none(),
            "Silicon authority accepted {label}: {authority:?}"
        );
    }
    set_context(&mut transaction, APP_A_ID, None, APP_A_ID).await?;

    // Each revocation is independent and rolled back before the next case.
    for (label, mutation) in [
        (
            "principal epoch change",
            "UPDATE iam.principals SET auth_epoch = auth_epoch + 1 WHERE id = 'test_silicon:test_org'",
        ),
        (
            "suspended principal",
            "UPDATE iam.principals SET status = 'suspended', suspended_at = transaction_timestamp() WHERE id = 'test_silicon:test_org'",
        ),
        (
            "inactive Silicon",
            "UPDATE iam.silicons SET provisioning_status = 'hook_error' WHERE id = 'test_silicon:test_org'",
        ),
        (
            "suspended organization",
            "UPDATE iam.organizations SET status = 'suspended' WHERE id = '00000000-0000-0000-0000-000000000021'",
        ),
        (
            "removed membership",
            "UPDATE iam.organization_memberships SET status = 'removed', removed_at = transaction_timestamp() WHERE id = '00000000-0000-0000-0000-000000000531'",
        ),
        (
            "revoked parent",
            "UPDATE iam.authentication_sessions SET status = 'revoked', revoked_at = transaction_timestamp() WHERE id = '00000000-0000-0000-0000-000000000541'",
        ),
        (
            "expired parent",
            "UPDATE iam.authentication_sessions SET created_at = transaction_timestamp() - interval '2 days', idle_expires_at = transaction_timestamp() - interval '1 day' WHERE id = '00000000-0000-0000-0000-000000000541'",
        ),
        (
            "revoked consent",
            "UPDATE iam.oauth_consent_grants SET status = 'revoked', revoked_at = transaction_timestamp() WHERE id = '00000000-0000-0000-0000-000000000571'",
        ),
    ] {
        let mut savepoint = transaction.begin().await?;
        sqlx::query(mutation).execute(&mut *savepoint).await?;
        let authority = sqlx::query_scalar::<_, Value>(AUTHORITY_QUERY)
            .bind(APP_A_ID)
            .bind(unscoped_consent)
            .bind(parent_id)
            .bind(silicon_id)
            .bind(None::<Id>)
            .bind(None::<Id>)
            .fetch_optional(&mut *savepoint)
            .await?;
        ensure!(
            authority.is_none(),
            "Silicon authority survived {label}: {authority:?}"
        );
        savepoint.rollback().await?;
    }

    // An Application cannot borrow the projection through another principal's
    // context, even when every supplied subject-chain identifier is valid.
    let mut savepoint = transaction.begin().await?;
    set_context(&mut savepoint, silicon_id, None, APP_A_ID).await?;
    let error = sqlx::query_scalar::<_, Value>(AUTHORITY_QUERY)
        .bind(APP_A_ID)
        .bind(unscoped_consent)
        .bind(parent_id)
        .bind(silicon_id)
        .bind(None::<Id>)
        .bind(None::<Id>)
        .fetch_optional(&mut *savepoint)
        .await
        .err()
        .context("a non-Application principal borrowed OAuth subject authority")?;
    ensure!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
            == Some("42501")
    );
    savepoint.rollback().await?;
    transaction.rollback().await?;
    Ok(())
}

/// Application authority follows explicit selected active memberships; additions
/// preserve previous grants. A legacy bound token still cannot leave its org.
///
/// The whole case runs in one transaction that is never committed, so it can be
/// ordered anywhere in the suite without leaving an extra organization behind.
async fn selected_login_additions_preserve_existing_organizations(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    let unscoped_token = Id::from_u128(0x101);
    let bound_token = Id::from_u128(0x102);
    let second_organization = Id::from_u128(0x22);
    let second_membership = Id::from_u128(0x33);

    set_context(&mut transaction, CARBON_ID, None, APP_A_ID).await?;
    let reachable = reachable_organizations(&mut transaction, unscoped_token).await?;
    ensure!(
        reachable.as_deref() == Some(["test_org".to_owned()].as_slice()),
        "an unscoped login did not reach its subject's only organization: {reachable:?}"
    );

    sqlx::query(
        r"
        INSERT INTO iam.organizations (id, org_id, created_by_carbon_id, name)
        VALUES ($1, 'zz_second_org', $2, 'Second Organization')
        ",
    )
    .bind(second_organization)
    .bind(CARBON_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.organization_memberships (
            id, organization_id, principal_id, principal_kind, org_role,
            job_role, role_granted_by_membership_id
        ) VALUES ($1, $2, $3, 'carbon', 'owner', '', NULL)
        ",
    )
    .bind(second_membership)
    .bind(second_organization)
    .bind(CARBON_ID)
    .execute(&mut *transaction)
    .await?;

    // Joining alone does not disclose the new organization.
    let reachable = reachable_organizations(&mut transaction, unscoped_token).await?;
    ensure!(reachable.as_deref() == Some(["test_org".to_owned()].as_slice()));
    // Explicit additive consent extends the existing token without replacing it.
    sqlx::query(
        "UPDATE iam.oauth_consent_grants SET selected_membership_ids = array_append(selected_membership_ids, $1) WHERE id = $2",
    )
    .bind(second_membership)
    .bind(CONSENT_ID)
    .execute(&mut *transaction)
    .await?;
    let reachable = reachable_organizations(&mut transaction, unscoped_token).await?;
    ensure!(
        reachable.as_deref()
            == Some(["test_org".to_owned(), "zz_second_org".to_owned()].as_slice()),
        "explicit additive consent did not preserve and extend the token: {reachable:?}"
    );

    // Reaching every organization still means answering for exactly one.
    set_context(
        &mut transaction,
        CARBON_ID,
        Some(second_organization),
        APP_A_ID,
    )
    .await?;
    let selected = selected_organization(
        &mut transaction,
        unscoped_token,
        second_organization,
        second_membership,
    )
    .await?;
    ensure!(
        selected.as_deref() == Some("zz_second_org"),
        "an unscoped login could not be answered for one of the organizations it reaches: {selected:?}"
    );
    let roaming_bound_token = selected_organization(
        &mut transaction,
        bound_token,
        second_organization,
        second_membership,
    )
    .await?;
    ensure!(
        roaming_bound_token.is_none(),
        "an organization-bound token answered for an organization it was never bound to"
    );
    set_context(&mut transaction, CARBON_ID, Some(ORGANIZATION_ID), APP_A_ID).await?;
    let bound_home = selected_organization(
        &mut transaction,
        bound_token,
        ORGANIZATION_ID,
        OWNER_MEMBERSHIP_ID,
    )
    .await?;
    ensure!(
        bound_home.as_deref() == Some("test_org"),
        "an organization-bound token stopped answering for its own organization: {bound_home:?}"
    );

    // Losing the membership withdraws the organization on the next request.
    sqlx::query(
        r"
        UPDATE iam.organization_memberships
        SET status = 'removed', removed_at = transaction_timestamp()
        WHERE id = $1
        ",
    )
    .bind(second_membership)
    .execute(&mut *transaction)
    .await?;
    set_context(
        &mut transaction,
        CARBON_ID,
        Some(second_organization),
        APP_A_ID,
    )
    .await?;
    let selected = selected_organization(
        &mut transaction,
        unscoped_token,
        second_organization,
        second_membership,
    )
    .await?;
    ensure!(
        selected.is_none(),
        "a removed membership still answered for its organization: {selected:?}"
    );
    set_context(&mut transaction, CARBON_ID, None, APP_A_ID).await?;
    let reachable = reachable_organizations(&mut transaction, unscoped_token).await?;
    ensure!(
        reachable.as_deref() == Some(["test_org".to_owned()].as_slice()),
        "a removed membership was still listed as reachable: {reachable:?}"
    );

    // OBO resolves the calling Application's own organization for an unscoped
    // parent, and refuses a subject who is not an active member of it.
    sqlx::query(
        "INSERT INTO iam.access_token_scopes (access_token_id, scope) VALUES ($1, 'obo:test_org>app-beta:trust.manage')",
    )
    .bind(unscoped_token)
    .execute(&mut *transaction)
    .await?;
    set_context(&mut transaction, APP_A_ID, Some(ORGANIZATION_ID), APP_A_ID).await?;
    let authority = obo_exchange_authority(
        &mut transaction,
        unscoped_token,
        ORGANIZATION_ID,
        OWNER_MEMBERSHIP_ID,
    )
    .await?;
    ensure!(
        authority == Some(1),
        "an unscoped subject token could not issue an OBO proof in its Application's organization"
    );
    let foreign_membership = obo_exchange_authority(
        &mut transaction,
        unscoped_token,
        ORGANIZATION_ID,
        second_membership,
    )
    .await?;
    ensure!(
        foreign_membership.is_none(),
        "an OBO exchange accepted a membership from outside the Application's organization"
    );
    Ok(())
}

async fn set_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal_id: Id,
    organization_id: Option<Id>,
    application_id: Id,
) -> anyhow::Result<()> {
    sqlx::query(
        r"
        SELECT set_config('iam.principal_id', $1, true),
               set_config('iam.organization_id', COALESCE($2, ''), true),
               set_config('iam.application_id', $3, true)
        ",
    )
    .bind(principal_id.to_string())
    .bind(organization_id.map(|id| id.to_string()))
    .bind(application_id.to_string())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn reachable_organizations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token_id: Id,
) -> anyhow::Result<Option<Vec<String>>> {
    let listed = sqlx::query_scalar::<_, Option<Value>>(
        "SELECT iam_private.list_current_application_authorizations($1, $2, $3, 1)",
    )
    .bind(token_id)
    .bind(CARBON_ID)
    .bind(APP_A_ID)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(listed.map(|value| {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| Some(entry.get("org_id")?.as_str()?.to_owned()))
            .collect()
    }))
}

async fn selected_organization(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token_id: Id,
    organization_id: Id,
    membership_id: Id,
) -> anyhow::Result<Option<String>> {
    let snapshot = sqlx::query_scalar::<_, Option<Value>>(
        "SELECT iam_private.get_current_application_authorization($1, $2, $3, $4, $5, 1, NULL)",
    )
    .bind(token_id)
    .bind(CARBON_ID)
    .bind(organization_id)
    .bind(membership_id)
    .bind(APP_A_ID)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(snapshot.and_then(|value| Some(value.get("org_id")?.as_str()?.to_owned())))
}

async fn obo_exchange_authority(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    parent_token_id: Id,
    organization_id: Id,
    membership_id: Id,
) -> anyhow::Result<Option<i64>> {
    sqlx::query_scalar::<_, i64>(
        r"
        SELECT endpoint_version
        FROM iam_private.lock_current_application_obo_exchange_authority(
            $1, 1, $2, $3, 'carbon'::iam.principal_kind, $4, $5,
            'test_org>app-beta', 'trust.manage'
        )
        ",
    )
    .bind(APP_A_ID)
    .bind(parent_token_id)
    .bind(CARBON_ID)
    .bind(organization_id)
    .bind(membership_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn consent_preserves_each_parent_session(pool: &PgPool) -> anyhow::Result<()> {
    let mut transaction = pool.begin().await?;
    let first_parent = Id::from_u128(0x41);
    let second_parent = Id::from_u128(0x42);
    sqlx::query(
        r"
        INSERT INTO iam.authentication_sessions (
            id, subject_principal_id, subject_kind, authentication_method,
            assurance_level, subject_auth_epoch, idle_expires_at, absolute_expires_at
        ) VALUES ($1, $2, 'carbon', 'email_otp', 1, 1,
                  transaction_timestamp() + interval '1 day',
                  transaction_timestamp() + interval '2 days')
        ",
    )
    .bind(second_parent)
    .bind(CARBON_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("SELECT set_config('iam.principal_id', $1, true), set_config('iam.application_id', $1, true)")
        .bind(APP_A_ID.to_string()).execute(&mut *transaction).await?;

    // Nullable organization scope and organization-bound grants both need
    // session isolation. Repeated authorization in one parent remains stable.
    for organization in [None, Some(ORGANIZATION_ID)] {
        let membership = organization.map(|_| OWNER_MEMBERSHIP_ID);
        let mut grants = Vec::new();
        for parent in [first_parent, second_parent, first_parent] {
            let (grant, _) =
                sqlx::query_as::<_, (Id, i64)>(super::oauth::OAUTH_CONSENT_UPSERT_QUERY)
                    .bind(Id::now_v7())
                    .bind(APP_A_ID)
                    .bind(CARBON_ID)
                    .bind("carbon")
                    .bind(organization)
                    .bind(membership)
                    .bind(parent)
                    .fetch_one(&mut *transaction)
                    .await?;
            grants.push(grant);
        }
        ensure!(
            grants[0] != grants[1],
            "another login replaced the original consent"
        );
        ensure!(
            grants[0] == grants[2],
            "same-parent authorization duplicated consent"
        );
        if organization.is_none() {
            ensure!(
                grants[0] == CONSENT_ID,
                "the migration replaced an existing consent id"
            );
        }

        for (grant, parent) in [(grants[0], first_parent), (grants[1], second_parent)] {
            let active = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM iam_private.lock_current_application_oauth_subject_authority($1,$2,$3,$4,'carbon',$5,$6)",
            ).bind(APP_A_ID).bind(grant).bind(parent).bind(CARBON_ID)
                .bind(organization).bind(membership).fetch_one(&mut *transaction).await?;
            ensure!(active == 1, "an independent parent lost refresh authority");
        }
        let mismatched = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam_private.lock_current_application_oauth_subject_authority($1,$2,$3,$4,'carbon',$5,$6)",
        ).bind(APP_A_ID).bind(grants[0]).bind(second_parent).bind(CARBON_ID)
            .bind(organization).bind(membership).fetch_one(&mut *transaction).await?;
        ensure!(mismatched == 0, "consent accepted the wrong parent login");

        sqlx::query("UPDATE iam.oauth_consent_grants SET status='revoked', revoked_at=transaction_timestamp() WHERE id=$1")
            .bind(grants[1]).execute(&mut *transaction).await?;
        let first_active = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM iam_private.lock_current_application_oauth_subject_authority($1,$2,$3,$4,'carbon',$5,$6)",
        ).bind(APP_A_ID).bind(grants[0]).bind(first_parent).bind(CARBON_ID)
            .bind(organization).bind(membership).fetch_one(&mut *transaction).await?;
        ensure!(
            first_active == 1,
            "revoking another parent revoked the original grant"
        );

        sqlx::query("SAVEPOINT parent_change")
            .execute(&mut *transaction)
            .await?;
        let change = sqlx::query(
            "UPDATE iam.oauth_consent_grants SET parent_authentication_session_id=$1 WHERE id=$2",
        )
        .bind(second_parent)
        .bind(grants[0])
        .execute(&mut *transaction)
        .await;
        ensure!(
            matches!(&change, Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("23514")),
            "an existing consent parent was not rejected by the immutability guard"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT parent_change")
            .execute(&mut *transaction)
            .await?;
    }
    transaction.rollback().await?;
    Ok(())
}

async fn direct_test_creation_rejects_a_production_application_id(
    production_pool: &PgPool,
) -> anyhow::Result<()> {
    ensure!(
        ensure_application_id_available_for_testing(production_pool, "test_org>app-alpha")
            .await
            .is_ok(),
        "the production create path must not reject its own identifiers"
    );

    let Err(rejection) = testing_plane::scope(
        SelectedEnvironment {
            id: Id::from_u128(0x501),
            organization_id: ORGANIZATION_ID,
        },
        ensure_application_id_available_for_testing(production_pool, "test_org>app-alpha"),
    )
    .await
    else {
        anyhow::bail!("a direct test create must not shadow a production Application id");
    };
    let rejection = rejection.into_response();
    ensure!(
        rejection.status() == StatusCode::CONFLICT,
        "a reserved production Application id must return HTTP 409"
    );
    let body = to_bytes(rejection.into_body(), 16_384).await?;
    let body = serde_json::from_slice::<Value>(&body)?;
    ensure!(
        body.pointer("/error/code").and_then(Value::as_str)
            == Some("application_id_reserved_in_production"),
        "the production reservation rejection must have a stable error code"
    );
    Ok(())
}

async fn qualified_application_directory_and_webhook_rotation_are_consistent(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let (app_id, base_url) = sqlx::query_as::<_, (String, String)>(
        "SELECT app_id, base_url FROM iam.applications WHERE id = $1",
    )
    .bind(APP_A_ID)
    .fetch_one(pool)
    .await?;
    ensure!(
        app_id == "test_org>app-alpha" && base_url == "https://alpha.example.test/api",
        "Application directory fields were not stored in their canonical form"
    );

    let pending_endpoint_id = Id::from_u128(0x143);
    let pending_key_id = Id::from_u128(0x144);
    let active_successor_key_id = Id::from_u128(0x145);
    let pending_successor_key_id = Id::from_u128(0x146);
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_endpoints (
            id, application_id, url_ciphertext, url_nonce,
            encryption_key_version, url_digest
        ) VALUES ($1, $2, decode(repeat('51', 17), 'hex'),
                  decode(repeat('52', 12), 'hex'), 1,
                  decode(repeat('53', 32), 'hex'))
        ",
    )
    .bind(pending_endpoint_id)
    .bind(APP_A_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES ($1, $2, $3, 2, 'whs_pending1',
                  decode(repeat('54', 17), 'hex'),
                  decode(repeat('55', 12), 'hex'), 1)
        ",
    )
    .bind(pending_key_id)
    .bind(APP_A_ID)
    .bind(pending_endpoint_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        UPDATE iam.application_webhook_signing_keys
        SET status = 'retiring', retires_at = transaction_timestamp() + interval '10 minutes'
        WHERE id IN ('00000000-0000-0000-0000-000000000142', $1)
        ",
    )
    .bind(pending_key_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES
        (
            $1, $3, '00000000-0000-0000-0000-000000000141', 3,
            'whs_successr', decode(repeat('46', 17), 'hex'),
            decode(repeat('47', 12), 'hex'), 1
        ),
        (
            $2, $3, $4, 3,
            'whs_successr', decode(repeat('48', 17), 'hex'),
            decode(repeat('49', 12), 'hex'), 1
        )
        ",
    )
    .bind(active_successor_key_id)
    .bind(pending_successor_key_id)
    .bind(APP_A_ID)
    .bind(pending_endpoint_id)
    .execute(&mut *transaction)
    .await?;
    let version_three_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM iam.application_webhook_signing_keys WHERE application_id = $1 AND secret_version = 3",
    )
    .bind(APP_A_ID)
    .fetch_one(&mut *transaction)
    .await?;
    ensure!(
        version_three_count == 2,
        "one logical rotation version was not shared by active and pending endpoints"
    );
    let recipients = sqlx::query_as::<_, (Id, Id)>(
        r"
        SELECT endpoint_id, signing_key_id
        FROM iam_private.list_worker_application_webhook_recipients(
            NULL, NULL, $1, transaction_timestamp()
        )
        ",
    )
    .bind(APP_A_ID)
    .fetch_all(&mut *transaction)
    .await?;
    ensure!(
        recipients.len() == 1 && recipients[0].1 == active_successor_key_id,
        "a rotation did not route new webhook events only to the active successor key"
    );
    let legacy_recipient_count = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM iam_private.list_worker_application_webhook_recipients_legacy(
            NULL, NULL, $1, transaction_timestamp()
        )
        ",
    )
    .bind(APP_A_ID)
    .fetch_one(&mut *transaction)
    .await?;
    ensure!(
        legacy_recipient_count == 2,
        "the retiring key was not preserved for already-bound deliveries"
    );
    transaction.rollback().await?;
    Ok(())
}

async fn pending_webhook_application_is_importable(pool: &PgPool) -> anyhow::Result<()> {
    let endpoint_id = Id::from_u128(0x151);
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_endpoints (
            id, application_id, url_ciphertext, url_nonce,
            encryption_key_version, url_digest
        ) VALUES ($1, $2, decode(repeat('61', 17), 'hex'),
                  decode(repeat('62', 12), 'hex'), 1,
                  decode(repeat('63', 32), 'hex'))
        ",
    )
    .bind(endpoint_id)
    .bind(APP_B_ID)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
        INSERT INTO iam.application_webhook_signing_keys (
            id, application_id, endpoint_id, secret_version, key_prefix,
            secret_ciphertext, secret_nonce, encryption_key_version
        ) VALUES ($1, $2, $3, 1, 'whs_pending2',
                  decode(repeat('64', 17), 'hex'),
                  decode(repeat('65', 12), 'hex'), 1)
        ",
    )
    .bind(Id::from_u128(0x152))
    .bind(APP_B_ID)
    .bind(endpoint_id)
    .execute(&mut *transaction)
    .await?;
    let imported_endpoint = sqlx::query_scalar::<_, Id>(
        "SELECT source_webhook_endpoint_id FROM iam_private.get_testing_application_import($1)",
    )
    .bind("test_org>app-beta")
    .fetch_optional(&mut *transaction)
    .await?;
    ensure!(
        imported_endpoint == Some(endpoint_id),
        "a verified production Application with only its initial pending webhook was not importable"
    );
    transaction.rollback().await?;
    Ok(())
}

async fn authorized_application_organization_projection_is_exact(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let reviewer_id = Id::fixture("test_reviewer");
    let other_organization_id = Id::from_u128(0x22);
    let other_application_id = Id::fixture("other_org>app-gamma");
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
            id, app_id, organization_id, created_by_carbon_id, review_status, base_url
        ) VALUES ($1, 'other_org>app-gamma', $2, $3, 'verified',
                  'https://gamma.example.test/api')
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
    principal_id: Id,
    application_id: Option<Id>,
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
    application_id: Id,
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
            .bind(Id::from_u128(0x22))
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
    let replacement_secret_id = Id::from_u128(0x132);
    let event_id = Id::from_u128(0x151);
    let recipient_id = Id::from_u128(0x152);
    let delivery_id = Id::from_u128(0x153);
    let second_event_id = Id::from_u128(0x157);
    let second_recipient_id = Id::from_u128(0x158);
    let second_delivery_id = Id::from_u128(0x159);
    let replay_batch_id = Id::from_u128(0x156);
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
                Id::from_u128(0x141),
                Id::from_u128(0x142),
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
    let preserved_event = sqlx::query_as::<_, (Id, i64, String, serde_json::Value)>(
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
    delivery_ids: &[Id],
) -> anyhow::Result<Vec<Id>> {
    sqlx::query_scalar::<_, Id>(
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
    .bind(Id::now_v7())
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
                 WHERE application_id = $1 AND scope = 'self.organizations.read')
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
    .bind(vec!["obo:test_org>app-beta:trust.manage".to_owned()])
    .fetch_all(&mut *transaction)
    .await?;
    ensure!(
        removed_scopes == ["self.organizations.read"],
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
    let request_id = Id::from_u128(0x61);
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
        scopes == ["self.organizations.read"],
        "initial code scope authority was incomplete"
    );
    sqlx::query(
        r"
        UPDATE iam.application_approved_scopes
        SET revoked_by_carbon_id = $2, revoked_at = transaction_timestamp()
        WHERE application_id = $1 AND scope = 'self.organizations.read' AND revoked_at IS NULL
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
        "DELETE FROM iam.oauth_consent_grant_scopes WHERE consent_grant_id = $1 AND scope = 'self.organizations.read'",
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
    let first = sqlx::query_scalar::<_, Id>(
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
    let replay = sqlx::query_scalar::<_, Id>(
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
    let replacement_id = Id::from_u128(0x94);
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
    let rotated = sqlx::query_scalar::<_, Id>(
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
    sqlx::query("UPDATE iam.access_tokens SET oauth_refresh_family_id=$1 WHERE id IN ('00000000-0000-0000-0000-000000000101','00000000-0000-0000-0000-000000000102')")
        .bind(FAMILY_ID).execute(&mut *transaction).await?;
    ensure!(
        super::oauth::compromise_refresh_family(
            &mut transaction,
            FAMILY_ID,
            Id::from_u128(0x41),
            APP_A_ID,
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?
    );
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
    let parent_id = Id::from_u128(0x102);
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
         AND token_scope.scope = 'obo:test_org>app-beta:trust.manage'
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
             AND token_scope.scope = 'obo:test_org>app-beta:trust.manage'
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
    let expiring_proof_id = Id::from_u128(0x122);
    let mut issuance = pool.begin().await?;
    set_context(&mut issuance, CARBON_ID, Some(ORGANIZATION_ID), APP_A_ID).await?;
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
    .execute(&mut *issuance)
    .await?;
    issuance.commit().await?;

    let mut verification = pool.begin().await?;
    sqlx::query("SELECT transaction_timestamp()")
        .execute(&mut *verification)
        .await?;
    sqlx::query("SELECT pg_sleep(0.2)")
        .execute(&mut *verification)
        .await?;
    let consumed = sqlx::query_scalar::<_, Id>(
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

async fn consume_obo_proof(pool: &PgPool) -> Result<Option<Id>, sqlx::Error> {
    sqlx::query_scalar::<_, Id>(
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
        let resolved = sqlx::query_scalar::<_, Id>(
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
        Ok::<Option<Id>, sqlx::Error>(resolved)
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

pub(crate) async fn seed_protocol_rows(pool: &PgPool) -> anyhow::Result<()> {
    let canonical = sqlx::query_scalar::<_, bool>(
        "SELECT atttypid='text'::regtype FROM pg_attribute WHERE attrelid='iam.principals'::regclass AND attname='id'",
    ).fetch_one(pool).await?;
    let mut fixture = r#"
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
            id, app_id, organization_id, created_by_carbon_id, review_status, base_url
        ) VALUES
          ('00000000-0000-0000-0000-000000000011', 'test_org>app-alpha',
           '00000000-0000-0000-0000-000000000021',
           '00000000-0000-0000-0000-000000000001', 'verified',
           'https://alpha.example.test/api'),
          ('00000000-0000-0000-0000-000000000012', 'test_org>app-beta',
           '00000000-0000-0000-0000-000000000021',
           '00000000-0000-0000-0000-000000000001', 'verified',
           'https://beta.example.test/api');
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
        VALUES ('00000000-0000-0000-0000-000000000011', 'self.organizations.read');
        INSERT INTO iam.application_approved_scopes (application_id, scope, approved_by_carbon_id)
        VALUES ('00000000-0000-0000-0000-000000000011', 'self.organizations.read',
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
            '00000000-0000-0000-0000-000000000011', 'self.organizations.read', transaction_timestamp()
        );
        INSERT INTO iam.oauth_consent_grants (
            id, application_id, subject_principal_id, subject_kind,
            parent_authentication_session_id, selected_membership_ids
        ) VALUES (
            '00000000-0000-0000-0000-000000000071',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            '00000000-0000-0000-0000-000000000041',
            ARRAY['00000000-0000-0000-0000-000000000031'::uuid]
        );
        INSERT INTO iam.oauth_consent_grants (
            id, application_id, subject_principal_id, subject_kind,
            organization_id, membership_id, parent_authentication_session_id,
            selected_membership_ids
        ) VALUES (
            '00000000-0000-0000-0000-000000000072',
            '00000000-0000-0000-0000-000000000011',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000031',
            '00000000-0000-0000-0000-000000000041',
            ARRAY['00000000-0000-0000-0000-000000000031'::uuid]
        );
        INSERT INTO iam.oauth_consent_grant_scopes (consent_grant_id, scope)
        VALUES ('00000000-0000-0000-0000-000000000071', 'self.organizations.read');
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
           '00000000-0000-0000-0000-000000000071', 'self.organizations.read'),
          ('00000000-0000-0000-0000-000000000093',
           '00000000-0000-0000-0000-000000000071', 'self.organizations.read');
        INSERT INTO iam.refresh_tokens (
            id, family_id, token_digest, digest_key_version, token_prefix, expires_at
        ) VALUES
          ('00000000-0000-0000-0000-000000000092',
           '00000000-0000-0000-0000-000000000091', decode(repeat('92', 32), 'hex'), 1,
           'ort_abcdefgh', transaction_timestamp() + interval '1 day'),
          ('00000000-0000-0000-0000-000000000095',
           '00000000-0000-0000-0000-000000000093', decode(repeat('95', 32), 'hex'), 1,
           'ort_qrstuvwx', transaction_timestamp() + interval '1 day');
        -- Historical token pairs carry one issuance timestamp per family.
        UPDATE iam.refresh_tokens SET created_at=created_at-interval '1 microsecond'
        WHERE id='00000000-0000-0000-0000-000000000095';
        INSERT INTO iam.oauth_consent_grants (
            id, application_id, subject_principal_id, subject_kind,
            parent_authentication_session_id, selected_membership_ids
        ) VALUES (
            '00000000-0000-0000-0000-000000000073',
            '00000000-0000-0000-0000-000000000012',
            '00000000-0000-0000-0000-000000000001', 'carbon',
            '00000000-0000-0000-0000-000000000041', ARRAY[]::uuid[]
        );
        INSERT INTO iam.refresh_token_families (
            id, authentication_session_id, subject_principal_id,
            client_application_id, oauth_consent_grant_id, absolute_expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000096',
            '00000000-0000-0000-0000-000000000041',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000012',
            '00000000-0000-0000-0000-000000000073', transaction_timestamp()+interval '30 days'
        );
        INSERT INTO iam.refresh_tokens (
            id, family_id, token_digest, digest_key_version, token_prefix, expires_at
        ) VALUES (
            '00000000-0000-0000-0000-000000000097',
            '00000000-0000-0000-0000-000000000096', decode(repeat('97',32),'hex'), 1,
            'ort_otherapp', transaction_timestamp()+interval '1 day'
        );
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
            '00000000-0000-0000-0000-000000000011', 'test_org>app-alpha',
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
            '00000000-0000-0000-0000-000000000011', 'test_org>app-alpha',
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
            '00000000-0000-0000-0000-000000000012', 'test_org>app-beta',
            '00000000-0000-0000-0000-000000000012', 1, 1,
            transaction_timestamp() + interval '15 minutes'
        );
        INSERT INTO iam.access_token_scopes (access_token_id, scope) VALUES
          ('00000000-0000-0000-0000-000000000101', 'self.organizations.read'),
          ('00000000-0000-0000-0000-000000000102', 'obo:test_org>app-beta:trust.manage'),
          ('00000000-0000-0000-0000-000000000103', 'self.organizations.read');
        INSERT INTO iam.application_obo_endpoints (
            organization_id, application_id, endpoint_id, path, metadata_definition
        ) VALUES (
            '00000000-0000-0000-0000-000000000021',
            '00000000-0000-0000-0000-000000000012',
            'trust.manage', '/v1/trust', '{"reason":{"type":"string"}}'
        );
        INSERT INTO iam.oauth_scope_catalog(scope,description,sensitive) VALUES ('obo:test_org>app-beta:trust.manage','Manage trust',false);
        INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES('00000000-0000-0000-0000-000000000011','obo:test_org>app-beta:trust.manage');
        INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES('00000000-0000-0000-0000-000000000011','obo:test_org>app-beta:trust.manage','00000000-0000-0000-0000-000000000001');
        INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) VALUES('00000000-0000-0000-0000-000000000071','obo:test_org>app-beta:trust.manage');
        SELECT set_config('iam.principal_id', '00000000-0000-0000-0000-000000000001', true),
               set_config('iam.application_id', '00000000-0000-0000-0000-000000000011', true);
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
        "#.to_owned();
    if canonical {
        // This contact resource deliberately shares its old UUID with the
        // administrator identity; only the identity reference is converted.
        fixture = fixture.replace(
            "('00000000-0000-0000-0000-000000000002',\n           '00000000-0000-0000-0000-000000000001', 'email'",
            "('__owner_email_contact__',\n           '00000000-0000-0000-0000-000000000001', 'email'",
        );
        for (old, current) in [
            ("00000000-0000-0000-0000-000000000001", "test_carbon"),
            ("00000000-0000-0000-0000-000000000002", "test_admin"),
            ("00000000-0000-0000-0000-000000000011", "test_org>app-alpha"),
            ("00000000-0000-0000-0000-000000000012", "test_org>app-beta"),
        ] {
            fixture = fixture.replace(old, current);
        }
        fixture = fixture.replace(
            "__owner_email_contact__",
            "00000000-0000-0000-0000-000000000002",
        );
    }
    sqlx::raw_sql(sqlx::AssertSqlSafe(fixture))
        .execute(pool)
        .await
        .context("seed application protocol invariant test")?;
    Ok(())
}

/// Real PostgreSQL exceptions must be authorization errors, never a 500 or a grant.
async fn cross_organization_login_selection_reports_private_restriction(
    pool: &PgPool,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::raw_sql("INSERT INTO iam.organizations(id,org_id,name,created_by_carbon_id) VALUES ('00000000-0000-0000-0000-000000000621','second_org','Second','test_carbon'); INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES ('00000000-0000-0000-0000-000000000631','00000000-0000-0000-0000-000000000621','test_carbon','carbon','owner');").execute(&mut *tx).await?;
    sqlx::query(
        "SELECT set_config('iam.principal_id',$1,true),set_config('iam.application_id','',true)",
    )
    .bind(CARBON_ID.to_string())
    .execute(&mut *tx)
    .await?;
    let query = "SELECT iam_private.lock_account_login_organization_selection($1,$2,$3,$4)";
    // Public apps allow an explicitly selected second organization.
    let selected: Vec<Id> = sqlx::query_scalar(query)
        .bind(CARBON_ID)
        .bind(Id::from_u128(0x41))
        .bind(vec!["second_org"])
        .bind(APP_A_ID)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(selected == vec![Id::from_u128(0x631)]);
    sqlx::query("UPDATE iam.applications SET visibility='private' WHERE id=$1")
        .bind(APP_A_ID)
        .execute(&mut *tx)
        .await?;
    let same: Vec<Id> = sqlx::query_scalar(query)
        .bind(CARBON_ID)
        .bind(Id::from_u128(0x41))
        .bind(vec!["test_org"])
        .bind(APP_A_ID)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(same == vec![OWNER_MEMBERSHIP_ID]);
    let mut attempt = tx.begin().await?;
    let error = sqlx::query_scalar::<_, Vec<Id>>(query)
        .bind(CARBON_ID)
        .bind(Id::from_u128(0x41))
        .bind(vec!["second_org"])
        .bind(APP_A_ID)
        .fetch_one(&mut *attempt)
        .await
        .err()
        .context("private cross-organization grants must be refused")?;
    let response = super::oauth::login_selection_error(&error).into_response();
    ensure!(response.status() == StatusCode::FORBIDDEN);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    ensure!(body["error"]["code"] == "private_application_organization_required");
    ensure!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("owning organization"))
    );
    attempt.rollback().await?;
    tx.rollback().await?;
    // Unexpected database failures must stay internal.
    ensure!(
        super::oauth::login_selection_error(&sqlx::Error::RowNotFound)
            .into_response()
            .status()
            == StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}
