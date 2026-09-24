#![allow(
    clippy::too_many_lines,
    reason = "One isolated lifecycle exercises the same token family across all auth routes"
)]

use super::*;
use crate::domain::id::Id;
use anyhow::ensure;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

#[test]
fn credentials_are_typed_and_never_accept_an_app_selector() -> anyhow::Result<()> {
    let slt = format!("oac_{}", "a".repeat(43));
    assert!(require_credential(&slt, "oac_").is_ok());
    for invalid in [
        "alice",
        "oac_bad",
        "ort_same",
        &format!("oac_{}", " ".repeat(43)),
    ] {
        assert!(require_credential(invalid, "oac_").is_err());
    }
    assert!(serde_json::from_value::<Login>(json!({"slt":slt,"app_id":"other"})).is_err());
    assert!(serde_json::from_value::<Refresh>(json!({"refresh_token":"x","token":"y"})).is_err());
    let access = format!("oat_{}", "b".repeat(43));
    let mut headers = HeaderMap::new();
    assert!(bearer(&headers).is_err());
    headers.insert("authorization", format!("Bearer {access}").parse()?);
    assert_eq!(
        bearer(&headers).map_err(|error| anyhow::anyhow!("{error:?}"))?,
        access
    );
    headers.append("authorization", format!("Bearer {access}").parse()?);
    assert!(bearer(&headers).is_err());
    Ok(())
}

#[test]
fn introspection_requires_the_same_ordinary_application_and_actor() {
    let client = ApplicationIdentity {
        application_id: Id::fixture("iam"),
        app_id: APP_ID.into(),
        organization_id: Id::from_u128(2),
        auth_epoch: 1,
    };
    let mut access = AccessContext {
        token_id: Id::from_u128(3),
        authentication_session_id: Id::from_u128(4),
        subject: crate::domain::actor::ActorRef {
            actor_type: ActorType::Carbon,
            id: Id::from_u128(5),
        },
        client_application_id: Some(client.application_id),
        audience_application_id: Some(client.application_id),
        audience: APP_ID.into(),
        organization_id: None,
        membership_id: None,
        scopes: vec!["self.identity.read".into()],
        assurance_level: 1,
    };
    assert!(is_service_session(&access, &client));
    access.subject.actor_type = ActorType::Silicon;
    assert!(is_service_session(&access, &client));
    for actor in [ActorType::Application, ActorType::Service] {
        access.subject.actor_type = actor;
        assert!(!is_service_session(&access, &client));
    }
    access.subject.actor_type = ActorType::Carbon;
    access.audience_application_id = Some(Id::from_u128(9));
    assert!(!is_service_session(&access, &client));
    access.audience_application_id = Some(client.application_id);
    access.client_application_id = None;
    assert!(!is_service_session(&access, &client));
    access.client_application_id = Some(client.application_id);
    access.audience = "silicon-iam".into();
    assert!(!is_service_session(&access, &client));
}

#[tokio::test]
async fn boundary_rejects_queries_duplicates_and_basic_auth() -> anyhow::Result<()> {
    let app = Router::new()
        .route(
            "/api/v1/auth/login",
            post(|| async { StatusCode::NO_CONTENT }),
        )
        .layer(middleware::from_fn(request_boundary));
    for mut request in [
        Request::post("/api/v1/auth/login?slt=not-accepted").body(Body::empty())?,
        Request::post("/api/v1/auth/login")
            .header("authorization", "Basic irrelevant")
            .body(Body::empty())?,
        Request::post("/api/v1/auth/login")
            .header("x-org-id", "tos")
            .body(Body::empty())?,
    ] {
        if request.headers().contains_key("x-org-id") {
            request.headers_mut().append("x-org-id", "tos".parse()?);
        }
        assert_eq!(
            app.clone().oneshot(request).await?.status(),
            StatusCode::BAD_REQUEST
        );
    }
    let selected = testing_plane::SelectedEnvironment {
        id: Id::from_u128(1),
        organization_id: Id::from_u128(2),
    };
    let response = testing_plane::scope(
        selected,
        app.oneshot(Request::post("/api/v1/auth/login").body(Body::empty())?),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker or an empty disposable IAM_TEST_DATABASE_URL and synthetic CI IAM settings"]
async fn scoped_slt_lifecycle_preserves_issuer_and_authorization_boundaries() -> anyhow::Result<()>
{
    use crate::{
        config::Settings,
        infrastructure::{crypto::CryptoService, providers::NotificationProviders},
    };
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    let native_url = std::env::var("IAM_TEST_DATABASE_URL").ok();
    let database = if native_url.is_none() {
        Some(crate::test_database::TestDatabase::start().await?)
    } else {
        None
    };
    let url = native_url
        .or_else(|| database.as_ref().map(|value| value.url.clone()))
        .ok_or_else(|| anyhow::anyhow!("missing disposable database"))?;
    let admin = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await?;
    sqlx::raw_sql("DO $$ BEGIN CREATE ROLE silicon_iam_api NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$; DO $$ BEGIN CREATE ROLE silicon_iam_worker NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$; DO $$ BEGIN CREATE ROLE silicon_iam_key_operator NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$; DO $$ BEGIN CREATE ROLE scoped_untrusted NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;").execute(&admin).await?;
    crate::infrastructure::postgres::migrate(&admin).await?;
    sqlx::raw_sql(include_str!(
        "../../../deploy/scoped/application-identity.sql"
    ))
    .execute(&admin)
    .await?;
    super::super::live_tests::seed_protocol_rows(&admin).await?;
    seed_scoped_registration(&admin).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(&admin)
        .await?;
    let restricted = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE silicon_iam_api")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await?;
    let settings = Settings::from_env()?;
    let state = ApiState {
        pool: restricted,
        crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
        notifications: NotificationProviders::from_settings(&settings.providers)?,
        workos: None,
        testing: None,
        settings: Arc::new(settings),
    };
    let app = router().with_state(state.clone());
    let main = super::super::router().with_state(state.clone());
    let main_response = main
        .oneshot(
            Request::post("/api/v1/app-auth/tokens")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("app_id=tos%3Eiam&slt=not-a-credential"))?,
        )
        .await?;
    assert_eq!(
        main_response.status(),
        StatusCode::UNAUTHORIZED,
        "main IAM still requires Basic credentials"
    );
    let oversized = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(vec![b' '; MAX_BODY_BYTES + 1]))?,
        )
        .await?;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        call(
            &app,
            "/api/v1/auth/introspect",
            &json!({"token":"not-accepted"}),
            None,
            None,
            None
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    let identity = service_identity(&state, "test", "synthetic-resolver-probe")
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    assert_eq!(identity.application_id, Id::fixture("iam"));
    assert_eq!(identity.app_id, APP_ID);
    let restricted_can_choose: bool = sqlx::query_scalar("SELECT has_function_privilege('scoped_untrusted','iam_private.resolve_scoped_iam_application()','execute')").fetch_one(&admin).await?;
    assert!(!restricted_can_choose);
    let resolver_arguments: i16 = sqlx::query_scalar("SELECT pronargs FROM pg_proc WHERE oid='iam_private.resolve_scoped_iam_application()'::regprocedure").fetch_one(&admin).await?;
    assert_eq!(resolver_arguments, 0);
    // One unauthenticated caller can exhaust its own credential budget without
    // consuming another user's SLT budget on the same application/route.
    let invalid = json!({"slt": format!("oac_{}", "z".repeat(43))});
    for _ in 0..120 {
        ensure!(
            call(
                &app,
                "/api/v1/auth/login",
                &invalid,
                Some("garbage-login-rate-limit"),
                None,
                None
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    ensure!(
        call(
            &app,
            "/api/v1/auth/login",
            &invalid,
            Some("garbage-login-rate-limit"),
            None,
            None
        )
        .await?
        .0 == StatusCode::TOO_MANY_REQUESTS
    );
    let slt = issued_slt(&state, APP_ID).await?;
    let body = json!({"slt":slt});
    let (status, issued) = call(
        &app,
        "/api/v1/auth/login",
        &body,
        Some("scoped-login-1"),
        None,
        None,
    )
    .await?;
    ensure!(status == StatusCode::OK, "login: {status}: {issued}");
    let (status, replay) = call(
        &app,
        "/api/v1/auth/login",
        &body,
        Some("scoped-login-1"),
        None,
        None,
    )
    .await?;
    ensure!(status == StatusCode::OK && issued == replay);
    ensure!(
        call(
            &app,
            "/api/v1/auth/login",
            &body,
            Some("scoped-login-spent"),
            None,
            None
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    let access = issued["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("access missing"))?;
    let refresh = issued["refresh_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("refresh missing"))?;
    let (status, snapshot) = call(
        &app,
        "/api/v1/auth/introspect",
        &Value::Null,
        None,
        Some(access),
        Some("tos"),
    )
    .await?;
    ensure!(
        status == StatusCode::OK && snapshot["active"] == true,
        "introspect: {status}: {snapshot}"
    );
    ensure!(
        snapshot["client_id"] == APP_ID
            && snapshot["audience"] == APP_ID
            && snapshot["org_id"] == "tos"
    );
    ensure!(
        call(
            &app,
            "/api/v1/auth/introspect",
            &Value::Null,
            None,
            Some(access),
            Some("unreachable")
        )
        .await?
        .1["active"]
            == false
    );
    let unrelated = issued_slt(&state, "app-alpha").await?;
    ensure!(
        call(
            &app,
            "/api/v1/auth/login",
            &json!({"slt":unrelated}),
            Some("wrong-app"),
            None,
            None
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    // The same wrong-app SLT remains redeemable by the proper main-IAM client.
    let other_client = super::super::security::ApplicationClient {
        identity: ApplicationIdentity {
            application_id: Id::fixture("app-alpha"),
            app_id: "app-alpha".into(),
            organization_id: Id::from_u128(0x21),
            auth_epoch: 1,
        },
        authenticated_secret: SecretString::from("synthetic-not-an-external-credential"),
    };
    let mut headers = HeaderMap::new();
    headers.insert("idempotency-key", "other-application-login".parse()?);
    let other = oauth::app_tokens(
        State(state.clone()),
        other_client,
        headers,
        axum::Form(AppTokenForm {
            app_id: Some("app-alpha".into()),
            slt: Some(unrelated),
            refresh_token: None,
        }),
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let other: Value = serde_json::from_slice(&to_bytes(other.into_body(), 65_536).await?)?;
    let other_refresh = other["refresh_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("other refresh missing"))?;
    ensure!(
        call(
            &app,
            "/api/v1/auth/refresh",
            &json!({"refresh_token":other_refresh}),
            Some("wrong-refresh"),
            None,
            None
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    ensure!(
        call(
            &app,
            "/api/v1/auth/logout",
            &json!({"refresh_token":other_refresh}),
            Some("wrong-revoke"),
            None,
            None
        )
        .await?
        .0 == StatusCode::OK
    );
    let other_access = other["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("other access missing"))?;
    ensure!(
        call(
            &app,
            "/api/v1/auth/introspect",
            &Value::Null,
            None,
            Some(other_access),
            None
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    ensure!(
        tokens::authenticate(state.db(), &state.crypto, &SecretString::from(other_access))
            .await?
            .is_some()
    );
    let (status, rotated) = call(
        &app,
        "/api/v1/auth/refresh",
        &json!({"refresh_token":refresh}),
        Some("scoped-refresh-1"),
        None,
        None,
    )
    .await?;
    ensure!(status == StatusCode::OK, "refresh: {status}: {rotated}");
    ensure!(
        call(
            &app,
            "/api/v1/auth/refresh",
            &json!({"refresh_token":refresh}),
            Some("scoped-refresh-1"),
            None,
            None
        )
        .await?
        .1 == rotated
    );
    let current_refresh = rotated["refresh_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("rotated refresh missing"))?;
    let current_access = rotated["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("rotated access missing"))?;
    ensure!(
        call(
            &app,
            "/api/v1/auth/logout",
            &json!({"refresh_token":current_refresh}),
            Some("scoped-logout-1"),
            None,
            None
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(
        call(
            &app,
            "/api/v1/auth/logout",
            &json!({"refresh_token":current_refresh}),
            Some("scoped-logout-1"),
            None,
            None
        )
        .await?
        .0 == StatusCode::OK
    );
    ensure!(
        call(
            &app,
            "/api/v1/auth/introspect",
            &Value::Null,
            None,
            Some(current_access),
            None
        )
        .await?
        .0 == StatusCode::UNAUTHORIZED
    );
    ensure!(
        call(
            &app,
            "/api/v1/auth/refresh",
            &json!({"refresh_token":current_refresh}),
            Some("revoked-refresh"),
            None,
            None
        )
        .await?
        .0 == StatusCode::BAD_REQUEST
    );
    let slt = issued_slt(&state, APP_ID).await?;
    sqlx::query("UPDATE iam.applications SET review_status='suspended' WHERE id=$1")
        .bind(identity.application_id)
        .execute(&admin)
        .await?;
    ensure!(
        call(
            &app,
            "/api/v1/auth/login",
            &json!({"slt":slt}),
            Some("suspended-app"),
            None,
            None
        )
        .await?
        .0 == StatusCode::FORBIDDEN
    );
    Ok(())
}

async fn call(
    app: &Router,
    path: &str,
    input: &Value,
    key: Option<&str>,
    token: Option<&str>,
    org: Option<&str>,
) -> anyhow::Result<(StatusCode, Value)> {
    let mut request = Request::post(path);
    if let Some(key) = key {
        request = request.header("idempotency-key", format!("scoped-test-{key}"));
    }
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(org) = org {
        request = request.header("x-org-id", org);
    }
    let body = if input.is_null() {
        Body::empty()
    } else {
        request = request.header("content-type", "application/json");
        Body::from(serde_json::to_vec(input)?)
    };
    let response = app.clone().oneshot(request.body(body)?).await?;
    let status = response.status();
    let body = to_bytes(response.into_body(), 65_536).await?;
    Ok((
        status,
        if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)?
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

async fn issued_slt(state: &ApiState, app_id: &str) -> anyhow::Result<String> {
    let carbon = Id::fixture("c:test_carbon");
    let mut tx = context::begin(state.db(), DatabaseContext::principal(carbon)).await?;
    let application_id: Id = sqlx::query_scalar("SELECT id FROM iam.applications WHERE app_id=$1")
        .bind(app_id)
        .fetch_one(&mut *tx)
        .await?;
    let policy = super::super::scopes::policy(&mut tx, application_id)
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let access = AccessContext {
        token_id: Id::from_u128(0x101),
        authentication_session_id: Id::from_u128(0x41),
        subject: crate::domain::actor::ActorRef {
            actor_type: ActorType::Carbon,
            id: carbon,
        },
        client_application_id: None,
        audience_application_id: None,
        audience: "silicon-iam".into(),
        organization_id: None,
        membership_id: None,
        scopes: vec!["iam.self".into()],
        assurance_level: 1,
    };
    let input = super::super::model::ShortLivedTokenRequest {
        app_id: app_id.into(),
        org_ids: vec!["tos".into()],
        approved_scopes: policy
            .scopes
            .iter()
            .map(|scope| scope.scope.clone())
            .collect(),
        scope_version: policy.scope_version,
        org_id: None,
        redirect_uri: None,
    };
    let issued = oauth::issue_for_selection(&mut tx, state, &access, &input)
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    tx.commit().await?;
    Ok(issued.slt)
}
