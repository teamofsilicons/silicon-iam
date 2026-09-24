//! Scoped organization mutations exercised through real bearer authentication
//! and the production runtime database grants in an isolated PostgreSQL.
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use crate::domain::id::Id;
use anyhow::{Context as _, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt as _;

use crate::{
    api::{ApiState, authentication::Authenticated},
    config::{RuntimeEnvironment, Settings},
    domain::actor::{ActorRef, ActorType},
    infrastructure::{
        crypto::{CryptoService, DigestPurpose, SecretKind},
        postgres::{self, tokens::AccessContext},
        providers::NotificationProviders,
    },
};

const OWNER: Id = Id::fixture("c:test_carbon");
const MEMBER: Id = Id::fixture("c:plain_member");
const APP: Id = Id::fixture("app-alpha");
const ORG: Id = Id::from_u128(0x21);
const OWNER_MEMBERSHIP: Id = Id::from_u128(0x31);
const MEMBER_MEMBERSHIP: Id = Id::from_u128(0x33);
const TAG: Id = Id::from_u128(0x51);
const WRITE_SCOPES: &[&str] = &[
    "self.organizations.read",
    "organization.profile.update",
    "organization.tags.update",
    "organization.admins.demote",
    "organizations.create",
    "organizations.join",
];

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and the CI IAM test settings"]
async fn scoped_mutations_enforce_scope_membership_capability_and_step_up() -> anyhow::Result<()> {
    let mut settings = Settings::from_env().context("load the CI IAM test settings")?;
    ensure!(
        settings.environment == RuntimeEnvironment::Test,
        "requires IAM_ENVIRONMENT=test"
    );
    let database = crate::test_database::TestDatabase::start().await?;
    let admin = database.pool.clone();
    postgres::migrate(&admin).await?;
    crate::features::applications::live_tests::seed_protocol_rows(&admin).await?;
    sqlx::raw_sql("DO $$ DECLARE role_name text; BEGIN
      FOREACH role_name IN ARRAY ARRAY['silicon_iam_api','silicon_iam_worker','silicon_iam_key_operator'] LOOP
        IF to_regrole(role_name) IS NULL THEN EXECUTE format('CREATE ROLE %I NOLOGIN',role_name); END IF;
      END LOOP;
      IF to_regrole('scoped_runtime') IS NULL THEN CREATE ROLE scoped_runtime LOGIN PASSWORD 'scoped-test-only' IN ROLE silicon_iam_api; END IF;
    END $$;")
        .execute(&admin).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(&admin)
        .await?;
    for fixture in [
        include_str!("../../../tests/sql/iam_mutation_scope_policy.sql"),
        include_str!("../../../tests/sql/unscoped_membership_disclosure.sql"),
        include_str!("../../../tests/sql/account_onboarding_login.sql"),
        include_str!("../../../tests/sql/application_webhook_scopes.sql"),
    ] {
        sqlx::raw_sql(fixture).execute(&admin).await?;
    }
    seed_directory(&admin).await?;
    grant_scopes(&admin).await?;
    let mut runtime_url = url::Url::parse(&database.url)?;
    runtime_url
        .set_username("scoped_runtime")
        .map_err(|()| anyhow::anyhow!("invalid test database URL"))?;
    runtime_url
        .set_password(Some("scoped-test-only"))
        .map_err(|()| anyhow::anyhow!("invalid test database URL"))?;
    let runtime_url = runtime_url.to_string();
    let runtime = PgPoolOptions::new()
        .max_connections(4)
        .connect(&runtime_url)
        .await?;
    let (superuser, bypass_rls) = sqlx::query_as::<_, (bool, bool)>(
        "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&runtime)
    .await?;
    ensure!(
        !superuser && !bypass_rls,
        "HTTP requests must use real restricted runtime authority"
    );
    settings.database.url = SecretString::from(runtime_url);
    let state = ApiState {
        pool: runtime.clone(),
        crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
        notifications: NotificationProviders::from_settings(&settings.providers)?,
        workos: None,
        testing: None,
        settings: Arc::new(settings),
    };
    let app = super::scoped_router().with_state(state.clone());
    let owner = seed_bearer(&admin, &state.crypto, OWNER, OWNER_MEMBERSHIP, WRITE_SCOPES).await?;
    let reader = seed_bearer(
        &admin,
        &state.crypto,
        OWNER,
        OWNER_MEMBERSHIP,
        &["self.organizations.read"],
    )
    .await?;
    let member = seed_bearer(
        &admin,
        &state.crypto,
        MEMBER,
        MEMBER_MEMBERSHIP,
        WRITE_SCOPES,
    )
    .await?;
    let writer = seed_bearer(
        &admin,
        &state.crypto,
        OWNER,
        OWNER_MEMBERSHIP,
        &["organization.profile.update"],
    )
    .await?;

    let initial_version = version(&admin, ORG).await?;
    let profile_path = "/api/v1/organizations/test_org";
    for (label, token, path, expected) in [
        (
            "missing write scope",
            &reader,
            profile_path,
            StatusCode::FORBIDDEN,
        ),
        (
            "scope without user capability",
            &member,
            profile_path,
            StatusCode::FORBIDDEN,
        ),
        (
            "unselected membership",
            &owner,
            "/api/v1/organizations/other_org",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, body) = request(
            &app,
            token,
            "PATCH",
            path,
            Some(initial_version),
            json!({"name":"Forbidden change"}),
        )
        .await?;
        ensure!(
            status == expected,
            "{label}: expected {expected}, got {status}: {body}"
        );
    }
    ensure!(
        version(&admin, ORG).await? == initial_version,
        "denied writes must not mutate version"
    );

    let (status, body) = request(
        &app,
        &owner,
        "PATCH",
        profile_path,
        Some(initial_version),
        json!({"name":"Scoped profile"}),
    )
    .await?;
    ensure!(
        status == StatusCode::OK && body["name"] == "Scoped profile",
        "authorized profile: {status} {body}"
    );
    ensure!(
        sqlx::query_scalar::<_, String>("SELECT name FROM iam.organizations WHERE id=$1")
            .bind(ORG)
            .fetch_one(&admin)
            .await?
            == "Scoped profile"
    );
    let current_version = version(&admin, ORG).await?;
    let (status, body) = request(
        &app,
        &writer,
        "PATCH",
        profile_path,
        Some(current_version),
        json!({"description":"Write-only update"}),
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "write-only profile: {status} {body}"
    );
    ensure!(
        body.get("name").is_none() && body.get("description").is_none(),
        "a write scope must not imply profile read access: {body}"
    );
    ensure!(
        body.get("id").is_some() && body.get("version").is_some(),
        "write receipt must identify its aggregate"
    );

    let tag_path = format!("/api/v1/organizations/test_org/tags/{TAG}");
    let (status, body) = request(
        &app,
        &owner,
        "PATCH",
        &tag_path,
        Some(1),
        json!({"name":"Scoped tag"}),
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "authorized tag update: {status} {body}"
    );
    ensure!(
        body.get("name").is_none()
            && body.get("created_at").is_none()
            && body.get("id").is_some()
            && body.get("version").is_some(),
        "tag write-only receipt exposed existing tag data: {body}"
    );
    ensure!(
        sqlx::query_scalar::<_, String>("SELECT name FROM iam.organization_tags WHERE id=$1")
            .bind(TAG)
            .fetch_one(&admin)
            .await?
            == "Scoped tag"
    );
    let audited = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM iam.audit_events WHERE application_id=$1 AND actor_principal_id=$2 AND action IN ('organization.updated','tag.updated')")
        .bind(APP).bind(OWNER).fetch_one(&admin).await?;
    ensure!(
        audited == 3,
        "each allowed mutation must carry its application and actor audit attribution"
    );

    let admin_membership = Id::from_u128(0x32);
    let admin_path =
        "/api/v1/organizations/test_org/members/c:test_admin%5Btest_org%5D/admin-demotions"
            .to_owned();
    let target_version = sqlx::query_scalar::<_, i64>(
        "SELECT version FROM iam.organization_memberships WHERE id=$1",
    )
    .bind(admin_membership)
    .fetch_one(&admin)
    .await?;
    let (status, body) = request(
        &app,
        &owner,
        "POST",
        &admin_path,
        Some(target_version),
        Value::Null,
    )
    .await?;
    ensure!(
        status == StatusCode::PRECONDITION_REQUIRED && body["error"]["code"] == "step_up_required",
        "scoped admin action must still require step-up: {status} {body}"
    );
    ensure!(
        sqlx::query_scalar::<_, String>(
            "SELECT org_role::text FROM iam.organization_memberships WHERE id=$1"
        )
        .bind(admin_membership)
        .fetch_one(&admin)
        .await?
            == "admin"
    );

    let wrong_session = seed_step_up(&admin, &state.crypto, &reader, admin_membership).await?;
    let (status, body) = request_with_step_up(
        &app,
        &owner,
        "POST",
        &admin_path,
        Some(target_version),
        Value::Null,
        Some(&wrong_session),
    )
    .await?;
    ensure!(
        status == StatusCode::PRECONDITION_FAILED && body["error"]["code"] == "step_up_invalid",
        "a different login session must not authorize a privileged mutation: {status} {body}"
    );
    let matching_session = seed_step_up(&admin, &state.crypto, &owner, admin_membership).await?;
    let (status, body) = request_with_step_up(
        &app,
        &owner,
        "POST",
        &admin_path,
        Some(target_version),
        Value::Null,
        Some(&matching_session),
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "an existing same-session step-up must authorize the scoped action: {status} {body}"
    );
    ensure!(
        sqlx::query_scalar::<_, String>(
            "SELECT org_role::text FROM iam.organization_memberships WHERE id=$1"
        )
        .bind(admin_membership)
        .fetch_one(&admin)
        .await?
            == "member"
    );
    let used = state
        .crypto
        .digest_secret(DigestPurpose::StepUpAssertion, &matching_session)?;
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT consumed_at IS NOT NULL FROM iam.step_up_assertions WHERE token_digest=$1"
        )
        .bind(used.as_bytes().as_slice())
        .fetch_one(&admin)
        .await?,
        "successful mutation must consume its one-time assertion"
    );

    let (status, body) = request(
        &app,
        &owner,
        "POST",
        "/api/v1/organizations",
        None,
        json!({"org_id":"scoped_created", "name":"Scoped created"}),
    )
    .await?;
    ensure!(
        status == StatusCode::CREATED,
        "Carbon organization creation: {status} {body}"
    );
    ensure!(sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM iam.organization_memberships m JOIN iam.organizations o ON o.id=m.organization_id WHERE o.org_id='scoped_created' AND m.principal_id=$1 AND m.org_role='owner')").bind(OWNER).fetch_one(&admin).await?);

    runtime.close().await;
    admin.close().await;
    Ok(())
}

async fn seed_directory(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(r"
        BEGIN;
        UPDATE iam.organizations SET trusted_org=true WHERE id='00000000-0000-0000-0000-000000000021';
        INSERT INTO iam.principals(id,kind,status,activated_at) VALUES('c:plain_member','carbon','active',transaction_timestamp());
        INSERT INTO iam.carbons(id,carbon_id,display_name) VALUES('c:plain_member','c:plain_member','Plain member');
        INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at) VALUES
          ('00000000-0000-0000-0000-000000000301','c:plain_member','email',decode(repeat('31',17),'hex'),decode(repeat('32',12),'hex'),1,transaction_timestamp()),
          ('00000000-0000-0000-0000-000000000302','c:plain_member','phone',decode(repeat('33',17),'hex'),decode(repeat('34',12),'hex'),1,transaction_timestamp());
        INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES('00000000-0000-0000-0000-000000000033','00000000-0000-0000-0000-000000000021','c:plain_member','carbon','member');
        INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES('00000000-0000-0000-0000-000000000022','other_org','c:test_carbon','Not selected');
        INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES('00000000-0000-0000-0000-000000000034','00000000-0000-0000-0000-000000000022','c:test_carbon','carbon','owner');
        INSERT INTO iam.organization_tags(id,organization_id,name,normalized_name,created_by_membership_id) VALUES('00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000021','Initial tag','initial_tag','00000000-0000-0000-0000-000000000031');
        COMMIT;
    ").execute(pool).await?;
    Ok(())
}

async fn grant_scopes(pool: &PgPool) -> anyhow::Result<()> {
    for scope in WRITE_SCOPES {
        sqlx::query("INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(APP).bind(scope).execute(pool).await?;
        sqlx::query("INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(APP).bind(scope).bind(OWNER).execute(pool).await?;
    }
    Ok(())
}

async fn seed_bearer(
    pool: &PgPool,
    crypto: &CryptoService,
    subject: Id,
    membership: Id,
    scopes: &[&str],
) -> anyhow::Result<SecretString> {
    let token = crypto.generate_secret(SecretKind::ApplicationAccessToken)?;
    let digest = crypto.digest_secret(DigestPurpose::ApplicationAccessToken, &token)?;
    let session_id = Id::now_v7();
    let consent_id = Id::now_v7();
    let token_id = Id::now_v7();
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO iam.authentication_sessions(id,subject_principal_id,subject_kind,authentication_method,assurance_level,subject_auth_epoch,idle_expires_at,absolute_expires_at) VALUES($1,$2,'carbon','email_otp',1,1,transaction_timestamp()+interval '1 day',transaction_timestamp()+interval '2 days')")
        .bind(session_id).bind(subject).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO iam.oauth_consent_grants(id,application_id,subject_principal_id,subject_kind,parent_authentication_session_id,selected_membership_ids) VALUES($1,$2,$3,'carbon',$4,ARRAY[$5]::uuid[])")
        .bind(consent_id).bind(APP).bind(subject).bind(session_id).bind(membership).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO iam.access_tokens(id,token_class,token_digest,digest_key_version,token_prefix,authentication_session_id,subject_principal_id,subject_kind,client_application_id,audience,audience_application_id,subject_auth_epoch,client_auth_epoch,expires_at) VALUES($1,'application_access',$2,1,$3,$4,$5,'carbon',$6,'app-alpha',$6,1,1,transaction_timestamp()+interval '15 minutes')")
        .bind(token_id).bind(digest.as_bytes().as_slice()).bind(&token.expose_secret()[..12]).bind(session_id).bind(subject).bind(APP).execute(&mut *tx).await?;
    for scope in scopes {
        sqlx::query(
            "INSERT INTO iam.oauth_consent_grant_scopes(consent_grant_id,scope) VALUES($1,$2)",
        )
        .bind(consent_id)
        .bind(scope)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES($1,$2)")
            .bind(token_id)
            .bind(scope)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(token)
}

async fn seed_step_up(
    pool: &PgPool,
    crypto: &CryptoService,
    bearer: &SecretString,
    resource: Id,
) -> anyhow::Result<SecretString> {
    let bearer_digest = crypto.digest_secret(DigestPurpose::ApplicationAccessToken, bearer)?;
    let session = sqlx::query_scalar::<_, Id>(
        "SELECT authentication_session_id FROM iam.access_tokens WHERE token_digest=$1",
    )
    .bind(bearer_digest.as_bytes().as_slice())
    .fetch_one(pool)
    .await?;
    let token = crypto.generate_secret(SecretKind::StepUpAssertion)?;
    let digest = crypto.digest_secret(DigestPurpose::StepUpAssertion, &token)?;
    let challenge = Id::now_v7();
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO iam.step_up_challenges(id,authentication_session_id,carbon_id,purpose,resource_id,channel,challenge_digest,digest_key_version,status,expires_at,consumed_at) VALUES($1,$2,$3,'organization.authorization_change',$4,'email',$5,1,'completed',transaction_timestamp()+interval '5 minutes',transaction_timestamp())")
        .bind(challenge).bind(session).bind(OWNER).bind(resource).bind(digest.as_bytes().as_slice()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO iam.step_up_assertions(id,step_up_challenge_id,authentication_session_id,carbon_id,purpose,token_prefix,token_digest,digest_key_version,assurance_level,expires_at) VALUES($1,$2,$3,$4,'organization.authorization_change',$5,$6,1,2,transaction_timestamp()+interval '5 minutes')")
        .bind(Id::now_v7()).bind(challenge).bind(session).bind(OWNER).bind(&token.expose_secret()[..12]).bind(digest.as_bytes().as_slice()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(token)
}

async fn version(pool: &PgPool, organization: Id) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT version FROM iam.organizations WHERE id=$1")
            .bind(organization)
            .fetch_one(pool)
            .await?,
    )
}

async fn request(
    app: &Router,
    token: &SecretString,
    method: &str,
    path: &str,
    version: Option<i64>,
    value: Value,
) -> anyhow::Result<(StatusCode, Value)> {
    request_with_step_up(app, token, method, path, version, value, None).await
}

async fn request_with_step_up(
    app: &Router,
    token: &SecretString,
    method: &str,
    path: &str,
    version: Option<i64>,
    value: Value,
    step_up: Option<&SecretString>,
) -> anyhow::Result<(StatusCode, Value)> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .header("content-type", "application/json")
        .header("idempotency-key", Id::now_v7().to_string());
    if let Some(version) = version {
        builder = builder.header("if-match", format!("\"{version}\""));
    }
    if let Some(step_up) = step_up {
        builder = builder.header("x-step-up-token", step_up.expose_secret());
    }
    let body = if value.is_null() {
        Body::empty()
    } else {
        Body::from(serde_json::to_vec(&value)?)
    };
    let response = app.clone().oneshot(builder.body(body)?).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 128 * 1024).await?;
    let json = serde_json::from_slice(&bytes).context("response must be JSON")?;
    Ok((status, json))
}

#[test]
fn scope_gates_reject_external_obo_and_preserve_carbon_only_onboarding() {
    let mut actor = Authenticated(AccessContext {
        token_id: Id::now_v7(),
        authentication_session_id: Id::now_v7(),
        subject: ActorRef {
            actor_type: ActorType::Carbon,
            id: OWNER,
        },
        client_application_id: Some(APP),
        audience_application_id: Some(APP),
        audience: "app-alpha".to_owned(),
        organization_id: None,
        membership_id: None,
        scopes: vec![
            "organization.profile.update".into(),
            "organizations.create".into(),
            "organizations.join".into(),
        ],
        assurance_level: 1,
    });
    assert!(
        super::support::require_application_scope(&actor, "organization.profile.update").is_ok()
    );
    for onboarding in ["organizations.create", "organizations.join"] {
        assert!(super::support::require_scoped_carbon(&actor, onboarding).is_ok());
        actor.0.subject.actor_type = ActorType::Silicon;
        assert!(super::support::require_scoped_carbon(&actor, onboarding).is_err());
        actor.0.subject.actor_type = ActorType::Carbon;
    }
    actor.0.audience_application_id = Some(Id::fixture("app-beta"));
    assert!(
        super::support::require_application_scope(&actor, "organization.profile.update").is_err()
    );
    actor.0.audience_application_id = Some(APP);
    actor.0.audience = "silicon-iam".into();
    actor.0.scopes = vec!["iam.self".into(), "organization.profile.update".into()];
    assert!(
        super::support::require_application_scope(&actor, "organization.profile.update").is_err()
    );
}

fn projection_actor(scopes: &[&str]) -> Authenticated {
    Authenticated(AccessContext {
        token_id: Id::from_u128(0x901),
        authentication_session_id: Id::from_u128(0x902),
        subject: ActorRef {
            actor_type: ActorType::Carbon,
            id: OWNER,
        },
        client_application_id: Some(APP),
        audience_application_id: Some(APP),
        audience: "app-alpha".into(),
        organization_id: None,
        membership_id: None,
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        assurance_level: 1,
    })
}

#[test]
fn mutation_member_projection_requires_the_correct_target_actor_read_scope() {
    use super::support::{MutationView, mutation_projection};
    let mut member = json!({
        "id": "membership", "org_id": "test_org", "version": 3, "status": "active",
        "principal": {"type": "carbon", "public_id": "private_carbon"},
        "job_description": "private role", "org_role": "admin", "tags": [{"id":"tag", "name":"private tag"}]
    });
    let receipt = json!({"id":"membership", "org_id":"test_org", "version":3, "status":"active"});
    for scopes in [
        vec!["organization.job_roles.update"],
        vec![
            "organization.job_roles.update",
            "directory.silicons.read",
            "directory.job_roles.read",
        ],
    ] {
        assert_eq!(
            mutation_projection(
                &projection_actor(&scopes),
                MutationView::Member,
                member.clone()
            ),
            receipt
        );
    }
    let permitted = mutation_projection(
        &projection_actor(&["directory.carbons.read", "directory.job_roles.read"]),
        MutationView::Member,
        member.clone(),
    );
    assert_eq!(permitted["principal"], member["principal"]);
    assert_eq!(permitted["job_description"], "private role");
    assert!(permitted.get("tags").is_none());
    assert!(permitted.get("org_role").is_none());
    member["principal"]["type"] = json!("silicon");
    assert_eq!(
        mutation_projection(
            &projection_actor(&["directory.carbons.read", "directory.job_roles.read"]),
            MutationView::Member,
            member,
        ),
        receipt
    );
}

#[test]
fn mutation_self_projection_and_authorization_use_self_field_permissions() {
    use super::support::{MutationView, mutation_projection};
    let member = json!({
        "id":"membership", "version":3,
        "principal":{"type":"carbon", "public_id":"c:test_carbon"},
        "job_description":"private role", "org_role":"admin", "capabilities":["members.invite"]
    });
    let actor = projection_actor(&[
        "self.identity.read",
        "self.job_role.read",
        "directory.memberships.read",
    ]);
    let projected = mutation_projection(&actor, MutationView::Member, member);
    assert!(projected.get("principal").is_some());
    assert_eq!(projected["job_description"], "private role");
    assert!(projected.get("org_role").is_none());
    assert!(projected.get("capabilities").is_none());

    let authorization = json!({"membership_id":"member", "version":3, "org_role":"admin", "capabilities":["members.invite"], "authorization_epoch":4});
    let actor = projection_actor(&["self.membership.read", "self.capabilities.read"]);
    assert_eq!(
        mutation_projection(
            &actor,
            MutationView::Authorization(true),
            authorization.clone()
        ),
        authorization
    );
    assert_eq!(
        mutation_projection(&actor, MutationView::Authorization(false), authorization),
        json!({"membership_id":"member", "version":3})
    );
}

#[test]
fn mutation_silicon_creation_returns_generated_ids_and_secret_without_directory_data() {
    use super::support::{MutationView, mutation_projection};
    let silicon = json!({
        "membership_id":"member", "silicon_id":"helper:test_org", "org_id":"test_org", "version":1,
        "display_name":"private", "job_description":"private role", "reports_to_membership_id":"private parent", "tags":[{"id":"tag", "name":"private tag"}]
    });
    let actor = projection_actor(&[
        "organization.silicons.update",
        "directory.carbons.read",
        "directory.profiles.read",
    ]);
    assert_eq!(
        mutation_projection(&actor, MutationView::Silicon, silicon.clone()),
        json!({"membership_id":"member", "org_id":"test_org", "version":1})
    );
    let created = json!({"silicon":silicon, "silicon_token":"one-time-secret", "secret_replay_expires_at":"expires"});
    assert_eq!(
        mutation_projection(&actor, MutationView::SiliconCreated, created),
        json!({
            "silicon":{"membership_id":"member", "silicon_id":"helper:test_org", "org_id":"test_org", "version":1},
            "silicon_token":"one-time-secret", "secret_replay_expires_at":"expires"
        })
    );
    let mut direct = actor;
    direct.0.client_application_id = None;
    assert_eq!(
        mutation_projection(&direct, MutationView::Silicon, silicon.clone()),
        silicon
    );
}

#[test]
fn mutation_tag_projection_does_not_disclose_existing_metadata_without_read_scope() {
    use super::support::{MutationView, mutation_projection};
    let tag = json!({"id":"tag", "org_id":"test_org", "name":"name", "version":3, "created_at":"earlier", "updated_at":"now"});
    assert_eq!(
        mutation_projection(
            &projection_actor(&["organization.tags.update"]),
            MutationView::Tag,
            tag.clone()
        ),
        json!({"id":"tag", "org_id":"test_org", "version":3})
    );
    assert_eq!(
        mutation_projection(
            &projection_actor(&["organization.tags.update", "organization.tags.read"]),
            MutationView::Tag,
            tag.clone()
        ),
        tag
    );
}
