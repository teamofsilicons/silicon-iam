//! Real runtime-role coverage of explicit delegated world creation.
#![allow(clippy::too_many_lines)]
use super::scoped::{CREATE_SCOPE, validate_boundary};
use crate::domain::id::Id;
use crate::{
    api::{ApiState, TestingPlane, authentication::Authenticated},
    config::{Settings, TestingSettings},
    domain::actor::{ActorRef, ActorType},
    infrastructure::{
        crypto::{CryptoService, DigestPurpose, SecretKind},
        postgres::{self, tokens::AccessContext},
        providers::NotificationProviders,
    },
};
use anyhow::{Context as _, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt as _;
const APP: Id = Id::fixture("app-alpha");
const OWNER: Id = Id::fixture("c:test_carbon");
const MEMBER: Id = Id::fixture("c:test_admin");
const MEMBER_MEMBERSHIP: Id = Id::from_u128(0x32);

#[test]
fn delegated_creation_requires_exact_carbon_application_and_selected_org() {
    let mut actor = Authenticated(AccessContext {
        token_id: Id::now_v7(),
        authentication_session_id: Id::now_v7(),
        subject: ActorRef {
            actor_type: ActorType::Carbon,
            id: OWNER,
        },
        client_application_id: Some(APP),
        audience_application_id: Some(APP),
        audience: "app-alpha".into(),
        organization_id: None,
        membership_id: None,
        scopes: vec![CREATE_SCOPE.into()],
        assurance_level: 1,
    });
    let mut headers = HeaderMap::new();
    assert!(validate_boundary(&actor, "test_org", &headers).is_ok());
    for header in [super::ENVIRONMENT_KEY_HEADER, super::APPLICATION_HEADER] {
        headers.insert(header, axum::http::HeaderValue::from_static("selector"));
        assert!(validate_boundary(&actor, "test_org", &headers).is_err());
        headers.remove(header);
    }
    headers.insert(
        "x-org-id",
        axum::http::HeaderValue::from_static("other_org"),
    );
    assert!(validate_boundary(&actor, "test_org", &headers).is_err());
    headers.remove("x-org-id");
    actor.0.subject.actor_type = ActorType::Silicon;
    assert!(validate_boundary(&actor, "test_org", &headers).is_err());
    actor.0.subject.actor_type = ActorType::Carbon;
    actor.0.scopes = vec!["organization.silicons.create".into()];
    assert!(validate_boundary(&actor, "test_org", &headers).is_err());
    actor.0.scopes = vec![CREATE_SCOPE.into()];
    actor.0.client_application_id = None;
    assert!(validate_boundary(&actor, "test_org", &headers).is_err());
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL plus synthetic IAM settings"]
async fn scoped_test_creation_preserves_actor_current_authority_and_root_receipt()
-> anyhow::Result<()> {
    let production_database = crate::test_database::TestDatabase::start().await?;
    let admin = production_database.pool.clone();
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('silicon_iam_api') IS NULL THEN CREATE ROLE silicon_iam_api NOLOGIN; END IF; IF to_regrole('silicon_iam_worker') IS NULL THEN CREATE ROLE silicon_iam_worker NOLOGIN; END IF; IF to_regrole('silicon_iam_key_operator') IS NULL THEN CREATE ROLE silicon_iam_key_operator NOLOGIN; END IF; END $$; DO $$ BEGIN IF to_regrole('scoped_untrusted') IS NULL THEN CREATE ROLE scoped_untrusted NOLOGIN; END IF; END $$;").execute(&admin).await?;
    postgres::migrate(&admin).await?;
    crate::features::applications::live_tests::seed_protocol_rows(&admin).await?;
    sqlx::raw_sql("UPDATE iam.organization_memberships SET org_role='member' WHERE id='00000000-0000-0000-0000-000000000032';").execute(&admin).await?;
    for scope in [CREATE_SCOPE, "self.organizations.read"] {
        sqlx::query("INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(APP).bind(scope).execute(&admin).await?;
        sqlx::query("INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(APP).bind(scope).bind(OWNER).execute(&admin).await?;
    }
    ensure!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT sensitive FROM iam.oauth_scope_catalog WHERE scope=$1"
        )
        .bind(CREATE_SCOPE)
        .fetch_one(&admin)
        .await?
    );
    ensure!(!sqlx::query_scalar::<_,bool>("SELECT has_function_privilege('scoped_untrusted','iam_private.authorize_scoped_testing_environment_creation(uuid,uuid)','EXECUTE')").fetch_one(&admin).await?);
    let testing_database = crate::test_database::TestDatabase::start().await?;
    let testing = testing_database.pool.clone();
    postgres::migrate_testing(&testing).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|l| !l.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    for pool in [&admin, &testing] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants.clone()))
            .execute(pool)
            .await?;
    }
    let restricted = |database: String| async move {
        PgPoolOptions::new()
            .max_connections(5)
            .after_connect(|c, _| {
                Box::pin(async move {
                    sqlx::query("SET ROLE silicon_iam_api").execute(c).await?;
                    Ok(())
                })
            })
            .connect(&database)
            .await
    };
    let settings = Settings::from_env()?;
    let state = ApiState {
        pool: restricted(production_database.url.clone()).await?,
        crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
        notifications: NotificationProviders::from_settings(&settings.providers)?,
        workos: None,
        testing: Some(TestingPlane {
            pool: restricted(testing_database.url.clone()).await?,
            settings: Arc::new(TestingSettings {
                database: settings.database.clone(),
                idle_days: 30,
                recovery_days: 30,
                max_per_organization: 3,
            }),
        }),
        settings: Arc::new(settings),
    };
    let app = super::scoped_router().with_state(state.clone());
    let member = seed_bearer(
        &admin,
        &state.crypto,
        MEMBER,
        MEMBER_MEMBERSHIP,
        &[CREATE_SCOPE],
    )
    .await?;
    let reader = seed_bearer(
        &admin,
        &state.crypto,
        MEMBER,
        MEMBER_MEMBERSHIP,
        &["self.organizations.read"],
    )
    .await?;
    let body = json!({"name":"Interface test","description":"Isolated world"});
    let (status, created) = request(
        &app,
        &member,
        "test_org",
        "create-test-world-0001",
        &body,
        None,
    )
    .await?;
    ensure!(
        status == StatusCode::CREATED,
        "create failed {status} {created}"
    );
    ensure!(created["created_by_membership_id"] == MEMBER_MEMBERSHIP.to_string());
    ensure!(created["key"].as_str().is_some_and(|v| v.len() == 32));
    let replay = request(
        &app,
        &member,
        "test_org",
        "create-test-world-0001",
        &body,
        None,
    )
    .await?;
    ensure!(
        replay.0 == StatusCode::CREATED && replay.1 == created,
        "receipt must preserve actual key"
    );
    ensure!(
        request(
            &app,
            &member,
            "test_org",
            "create-test-world-0001",
            &json!({"name":"changed"}),
            None
        )
        .await?
        .0 == StatusCode::CONFLICT
    );
    ensure!(
        request(
            &app,
            &reader,
            "test_org",
            "create-test-world-0001",
            &body,
            None
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    ensure!(
        request(
            &app,
            &member,
            "other_org",
            "create-test-world-0001",
            &body,
            None
        )
        .await?
        .0
        .is_client_error()
    );
    ensure!(
        request(
            &app,
            &member,
            "test_org",
            "selector-test-world-0001",
            &body,
            Some(created["key"].as_str().context("created root")?)
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    let renewed = seed_bearer(
        &admin,
        &state.crypto,
        MEMBER,
        MEMBER_MEMBERSHIP,
        &[CREATE_SCOPE],
    )
    .await?;
    let different = request(
        &app,
        &renewed,
        "test_org",
        "create-test-world-0001",
        &body,
        None,
    )
    .await?;
    ensure!(
        different.0 == StatusCode::CONFLICT && different.1.get("key").is_none(),
        "another session must not recover root"
    );
    sqlx::query("DELETE FROM iam.application_approved_scopes WHERE application_id=$1 AND scope=$2")
        .bind(APP)
        .bind(CREATE_SCOPE)
        .execute(&admin)
        .await?;
    let revoked = request(
        &app,
        &member,
        "test_org",
        "create-test-world-0001",
        &body,
        None,
    )
    .await?;
    ensure!(
        revoked.0.is_client_error() && revoked.1.get("key").is_none(),
        "revoked grant must block root replay"
    );
    sqlx::query("INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES($1,$2,$3)").bind(APP).bind(CREATE_SCOPE).bind(OWNER).execute(&admin).await?;
    sqlx::query("UPDATE iam.organization_memberships SET status='suspended',suspended_at=transaction_timestamp() WHERE id=$1")
        .bind(MEMBER_MEMBERSHIP)
        .execute(&admin)
        .await?;
    ensure!(
        request(
            &app,
            &member,
            "test_org",
            "create-test-world-0001",
            &body,
            None
        )
        .await?
        .0
        .is_client_error()
    );
    sqlx::query(
        "UPDATE iam.organization_memberships SET status='active',suspended_at=NULL WHERE id=$1",
    )
    .bind(MEMBER_MEMBERSHIP)
    .execute(&admin)
    .await?;
    let inputs = [
        json!({"name":"Concurrent A"}),
        json!({"name":"Concurrent B"}),
        json!({"name":"Concurrent C"}),
    ];
    let (a, b, c) = tokio::join!(
        request(
            &app,
            &member,
            "test_org",
            "quota-test-world-0001",
            &inputs[0],
            None
        ),
        request(
            &app,
            &member,
            "test_org",
            "quota-test-world-0002",
            &inputs[1],
            None
        ),
        request(
            &app,
            &member,
            "test_org",
            "quota-test-world-0003",
            &inputs[2],
            None
        )
    );
    let outcomes = [a?, b?, c?];
    let statuses = outcomes.each_ref().map(|value| value.0);
    ensure!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::CREATED)
            .count()
            == 2
            && statuses
                .iter()
                .filter(|s| **s == StatusCode::CONFLICT)
                .count()
                == 1,
        "quota must serialize concurrent requests: {statuses:?}"
    );
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM iam.testing_environments")
            .fetch_one(&admin)
            .await?
            == 3
    );
    let other = outcomes
        .iter()
        .find(|value| value.0 == StatusCode::CREATED)
        .context("concurrent environment")?;
    exercise_test_login(&state, &admin, &testing_database.url, &created, &other.1).await?;
    state.pool.close().await;
    state
        .testing
        .as_ref()
        .context("testing plane")?
        .pool
        .close()
        .await;
    testing.close().await;
    admin.close().await;
    Ok(())
}

async fn request(
    app: &Router,
    token: &SecretString,
    org: &str,
    key: &str,
    input: &Value,
    root: Option<&str>,
) -> anyhow::Result<(StatusCode, Value)> {
    let mut req = Request::post(format!("/api/v1/organizations/{org}/testing-environments"))
        .header("authorization", format!("Bearer {}", token.expose_secret()))
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .header("x-org-id", org);
    if let Some(root) = root {
        req = req.header(super::ENVIRONMENT_KEY_HEADER, root);
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(serde_json::to_vec(input)?))?)
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
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

// The root minted through the real scoped mutation selects an isolated DB;
// only the imported fixed service identity can activate its actor-ID shortcut.
async fn exercise_test_login(
    state: &ApiState,
    production: &PgPool,
    testing_url: &str,
    created: &Value,
    other: &Value,
) -> anyhow::Result<()> {
    let environment = Id::parse_str(created["id"].as_str().context("created environment ID")?)?;
    let testing = PgPoolOptions::new()
        .max_connections(3)
        .after_connect(move |connection, _| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                    .bind(environment.to_string())
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(testing_url)
        .await?;
    crate::features::applications::live_tests::seed_protocol_rows(&testing).await?;
    for pool in [production, &testing] {
        seed_scoped_registration(pool).await?;
    }
    sqlx::raw_sql(include_str!(
        "../../../deploy/scoped/application-identity.sql"
    ))
    .execute(production)
    .await?;
    let auth = crate::features::applications::scoped_auth_router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::select_plane,
        ))
        .with_state(state.clone());
    let root = created["key"].as_str().context("created root")?;
    let other_root = other["key"].as_str().context("other root")?;
    ensure!(
        auth_call(
            &auth,
            "login",
            Some(root),
            &json!({"slt":"c:test_carbon"}),
            None,
            "before-import-world-0001"
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    sqlx::raw_sql("UPDATE iam.applications SET test_imported_from_production=true WHERE id='iam'; INSERT INTO iam.testing_application_imports(application_id,source_application_id,secret_ciphertext,secret_nonce,secret_key_version) VALUES('iam','iam',decode(repeat('11',17),'hex'),decode(repeat('22',12),'hex'),1);").execute(&testing).await?;
    let (status, tokens) = auth_call(
        &auth,
        "login",
        Some(root),
        &json!({"slt":"c:test_carbon"}),
        None,
        "imported-world-login-0001",
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "test root login failed {status} {tokens}"
    );
    ensure!(
        tokens["access_token"]
            .as_str()
            .is_some_and(|v| v.starts_with("oat_"))
    );
    ensure!(
        auth_call(
            &auth,
            "login",
            Some(root),
            &json!({"slt":"c:test_carbon"}),
            None,
            "imported-world-login-0001"
        )
        .await?
        .1 == tokens
    );
    ensure!(
        auth_call(
            &auth,
            "login",
            Some(other_root),
            &json!({"slt":"c:test_carbon"}),
            None,
            "other-world-login-0001"
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    ensure!(
        auth_call(
            &auth,
            "login",
            None,
            &json!({"slt":"c:test_carbon"}),
            None,
            "production-actor-login-0001"
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    let access = tokens["access_token"]
        .as_str()
        .context("test access token")?;
    let (status, snapshot) = auth_call(
        &auth,
        "introspect",
        Some(root),
        &Value::Null,
        Some(access),
        "test-introspection-0001",
    )
    .await?;
    ensure!(
        status == StatusCode::OK && snapshot["active"] == true,
        "test introspection failed {status} {snapshot}"
    );
    ensure!(
        auth_call(
            &auth,
            "introspect",
            None,
            &Value::Null,
            Some(access),
            "production-introspection-0001"
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED
    );
    ensure!(
        auth_call(
            &auth,
            "introspect",
            Some(other_root),
            &Value::Null,
            Some(access),
            "other-introspection-0001"
        )
        .await?
        .0
        .is_client_error()
    );
    let (status, refreshed) = auth_call(
        &auth,
        "refresh",
        Some(root),
        &json!({"refresh_token":tokens["refresh_token"]}),
        None,
        "test-world-refresh-0001",
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "test refresh failed {status} {refreshed}"
    );
    ensure!(
        auth_call(
            &auth,
            "logout",
            Some(root),
            &json!({"refresh_token":refreshed["refresh_token"]}),
            None,
            "test-world-logout-0001"
        )
        .await?
        .0
        .is_success()
    );
    ensure!(
        auth_call(
            &auth,
            "introspect",
            Some(root),
            &Value::Null,
            refreshed["access_token"].as_str(),
            "test-world-loggedout-0001"
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED
    );
    testing.close().await;
    Ok(())
}

async fn auth_call(
    app: &Router,
    route: &str,
    root: Option<&str>,
    body: &Value,
    bearer: Option<&str>,
    key: &str,
) -> anyhow::Result<(StatusCode, Value)> {
    let mut request = Request::post(format!("/api/v1/auth/{route}")).header("idempotency-key", key);
    if let Some(root) = root {
        request = request.header(super::ENVIRONMENT_KEY_HEADER, root);
    }
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let payload = if body.is_null() {
        Body::empty()
    } else {
        request = request.header("content-type", "application/json");
        Body::from(serde_json::to_vec(body)?)
    };
    let response = app.clone().oneshot(request.body(payload)?).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        },
    ))
}

async fn seed_scoped_registration(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(r"
        INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES ('00000000-0000-0000-0000-000000000022','tos','c:test_carbon','Scoped test organization');
        INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role,job_role) VALUES ('00000000-0000-0000-0000-000000000033','00000000-0000-0000-0000-000000000022','c:test_carbon','carbon','owner','');
        INSERT INTO iam.principals(id,kind,status,activated_at) VALUES ('iam','application','active',transaction_timestamp());
        INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,review_status,base_url) VALUES ('iam','iam','00000000-0000-0000-0000-000000000022','c:test_carbon','verified','https://scoped.backend.iam.teamofsilicons.com');
        INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES ('iam','self.organizations.read');
        INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES ('iam','self.organizations.read','c:test_carbon');
    ").execute(pool).await?;
    Ok(())
}
