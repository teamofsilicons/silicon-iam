//! Reusable OBO protocol exercised against isolated PostgreSQL and the API role.
#![allow(clippy::too_many_lines)]
use super::*;
use crate::{
    config::Settings,
    infrastructure::{
        crypto::CryptoService,
        providers::NotificationProviders,
        testing_plane::{self, SelectedEnvironment},
    },
};
use anyhow::{Context as _, ensure};
use axum::body::to_bytes;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;

const SUBJECT: Id = Id::fixture("c:test_carbon");
const SESSION: Id = Id::from_u128(0x41);
const APP_TOKEN: Id = Id::from_u128(0x101);
const USER_TOKEN: Id = Id::from_u128(0x201);
const WORLD: Id = Id::from_u128(0x801);

fn app(name: &str) -> ApplicationClient {
    ApplicationClient {
        identity: super::super::security::ApplicationIdentity {
            application_id: Id::identity(name).unwrap_or_else(|_| Id::nil()),
            app_id: name.into(),
            organization_id: Id::from_u128(if name == "app-alpha" { 0x21 } else { 0x23 }),
            auth_epoch: 1,
        },
        authenticated_secret: SecretString::from("ask_fixture"),
    }
}
fn user() -> Bearer {
    Bearer(AccessContext {
        token_id: USER_TOKEN,
        authentication_session_id: SESSION,
        subject: crate::domain::actor::ActorRef {
            actor_type: ActorType::Carbon,
            id: SUBJECT,
        },
        client_application_id: None,
        audience_application_id: None,
        audience: "silicon-iam".into(),
        organization_id: None,
        membership_id: None,
        scopes: vec!["iam.self".into()],
        assurance_level: 1,
    })
}
fn headers(key: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "idempotency-key",
        HeaderValue::from_str(key)
            .unwrap_or_else(|_| HeaderValue::from_static("fixture-default-idempotency")),
    );
    headers
}
async fn value(result: Result<Response, ApiError>) -> anyhow::Result<Value> {
    let response = result.map_err(|error| anyhow::anyhow!("{error:?}"))?;
    ensure!(
        response.status().is_success(),
        "response status {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("cache-control")
            .is_some_and(|header| header == "no-store")
    );
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 1_048_576).await?,
    )?)
}
async fn approved(state: &ApiState, subject: &str, key: &str) -> anyhow::Result<(Id, String)> {
    let request = value(
        create(
            State(state.clone()),
            app("app-alpha"),
            headers(&format!("{key}-authorization")),
            Json(AuthorizationRequest {
                redirect_uri: Some("https://app.example/storage-authorization".into()),
                state: Some("state-value-at-least-32-characters-long".into()),
                subject_token: subject.into(),
                org_id: "test_org".into(),
                endpoints: vec![Endpoint {
                    audience: "target".into(),
                    endpoint_id: "files.read".into(),
                }],
            }),
        )
        .await,
    )
    .await
    .with_context(|| format!("create authorization {key}"))?;
    ensure!(request["status"] == "pending");
    ensure!(
        request["endpoints"][0]["downstream"][0]["audience"] == "store",
        "complete chain missing: {request}"
    );
    ensure!(request["endpoints"][0].get("_issuer_epoch").is_none());
    let id: Id = serde_json::from_value(request["id"].clone())?;
    let decision = value(
        decide(
            State(state.clone()),
            user(),
            headers(&format!("{key}-consent-decision")),
            Path(id),
            Json(Decision {
                iam_disclosures_reviewed: true,
                contexts: vec![],
                decision: DecisionKind::Approve,
                version: 1,
            }),
        )
        .await,
    )
    .await
    .context("approve authorization")?;
    let code = decision["authorization_code"]
        .as_str()
        .context("consent code")?
        .to_owned();
    let callback = url::Url::parse(decision["redirect_uri"].as_str().context("callback")?)?;
    ensure!(callback.origin().ascii_serialization() == "https://app.example");
    let query: std::collections::HashMap<_, _> = callback.query_pairs().collect();
    ensure!(query.get("code").map(std::convert::AsRef::as_ref) == Some(code.as_str()));
    ensure!(
        query.get("state").map(std::convert::AsRef::as_ref)
            == Some("state-value-at-least-32-characters-long")
    );
    Ok((id, code))
}
async fn exchange_pair(
    state: &ApiState,
    request: Id,
    code: &str,
    key: &str,
) -> anyhow::Result<Value> {
    let result = value(
        issue(
            State(state.clone()),
            app("app-alpha"),
            headers(key),
            Json(TokenRequest {
                grant_id: None,
                subject_token: None,
                authorization_id: Some(request),
                authorization_code: Some(code.into()),
                refresh_token: None,
            }),
        )
        .await,
    )
    .await?;
    ensure!(
        result["items"]
            .as_array()
            .is_some_and(|items| items.len() == 1)
    );
    Ok(result["items"][0].clone())
}
async fn verify_as(
    state: &ApiState,
    receiver: &str,
    token: &str,
    endpoint: &str,
    path: &str,
) -> Result<Response, ApiError> {
    verify(
        State(state.clone()),
        app(receiver),
        HeaderMap::new(),
        Json(Verification {
            access_token: token.into(),
            endpoint_id: endpoint.into(),
            request: Action {
                method: "POST".into(),
                path: path.into(),
            },
        }),
    )
    .await
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL and synthetic IAM settings"]
async fn reusable_obo_consent_refresh_chain_and_revocation() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("silicon_iam=info")
        .with_test_writer()
        .try_init();
    for testing in [false, true] {
        let database = crate::test_database::TestDatabase::start().await?;
        let pool = PgPoolOptions::new()
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    if testing {
                        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                            .bind(WORLD.to_string())
                            .execute(connection)
                            .await?;
                    }
                    Ok(())
                })
            })
            .connect(&database.url)
            .await?;
        if testing {
            crate::infrastructure::postgres::migrate_testing(&pool).await?;
        } else {
            crate::infrastructure::postgres::migrate(&pool).await?;
        }
        super::super::live_tests::seed_protocol_rows(&pool).await?;
        sqlx::raw_sql(include_str!("obo_disclosure_seed.sql"))
            .execute(&pool)
            .await?;
        seed_chain(&pool).await?;
        let runtime_grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");
        sqlx::raw_sql(sqlx::AssertSqlSafe(runtime_grants))
            .execute(&pool)
            .await?;
        let settings = Settings::from_env()?;
        let state = ApiState {
            pool: PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(std::time::Duration::from_secs(2))
                .after_connect(|connection, _| {
                    Box::pin(async move {
                        sqlx::query("SET ROLE silicon_iam_api")
                            .execute(connection)
                            .await?;
                        Ok(())
                    })
                })
                .connect(&database.url)
                .await?,
            testing: None,
            crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
            notifications: NotificationProviders::from_settings(&settings.providers)?,
            workos: None,
            settings: Arc::new(settings),
        };
        let checks = Box::pin(async {
            // Testing credentials must be hashed inside the selected environment,
            // just as issuance does: the digest is intentionally environment-bound.
            let raw = state
                .crypto
                .generate_secret(SecretKind::ApplicationAccessToken)?;
            let digest = state
                .crypto
                .digest_secret(DigestPurpose::ApplicationAccessToken, &raw)?;
            let app_secret = state.crypto.digest_secret(
                DigestPurpose::ApplicationSecret,
                &SecretString::from("ask_fixture"),
            )?;
            for name in ["app-alpha", "target", "store"] {
                let updated = sqlx::query("UPDATE iam.application_secrets SET secret_digest=$2,pepper_key_version=$3 WHERE application_id=$1 AND status='active'")
                .bind(name).bind(app_secret.as_bytes().as_slice()).bind(app_secret.key_version()).execute(&pool).await?;
                if updated.rows_affected() == 0 {
                    sqlx::query("INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id) VALUES($1,$2,2,'ask_fixture0',$3,$4,'c:test_admin')")
                .bind(Id::now_v7()).bind(name).bind(app_secret.as_bytes().as_slice()).bind(app_secret.key_version()).execute(&pool).await?;
                }
            }
            sqlx::query("UPDATE iam.access_tokens SET token_digest=$1,digest_key_version=$2,oauth_refresh_family_id='00000000-0000-0000-0000-000000000091' WHERE id=$3")
            .bind(digest.as_bytes().as_slice()).bind(digest.key_version()).bind(APP_TOKEN).execute(&pool).await?;
            directory_visibility_transport(&state).await?;
            check_protocol(&state, &pool, raw.expose_secret()).await
        });
        if testing {
            testing_plane::scope(
                SelectedEnvironment {
                    id: WORLD,
                    organization_id: Id::from_u128(0x21),
                },
                checks,
            )
            .await
            .context("testing-plane protocol")?;
        } else {
            checks.await.context("production-plane protocol")?;
        }
        state.pool.close().await;
        pool.close().await;
    }
    Ok(())
}

async fn directory_visibility_transport(state: &ApiState) -> anyhow::Result<()> {
    use axum::{body::Body, http::Request, middleware};
    use tower::ServiceExt as _;
    let router = crate::features::organizations::router()
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::membership_ids::transport,
        ))
        .with_state(state.clone());
    for (version, mode, targets) in [
        (1, "selected", vec!["c:test_carbon[test_org]"]),
        (2, "all", vec![]),
    ] {
        let mut request = Request::builder()
            .method("PUT")
            .uri("/api/v1/organizations/test_org/directory-visibility")
            .header("content-type", "application/json")
            .header("if-match", format!("\"{version}\""))
            .header("idempotency-key", format!("directory-transport-{version}"))
            .body(Body::from(
                json!({"mode":mode,"visible_membership_ids":targets}).to_string(),
            ))?;
        request
            .extensions_mut()
            .insert(crate::api::authentication::Authenticated(user().0));
        let response = crate::request_context::scope(
            uuid::Uuid::now_v7().to_string(),
            router.clone().oneshot(request),
        )
        .await?;
        let status = response.status();
        let result: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
        ensure!(
            status == StatusCode::OK,
            "directory HTTP transport rejected canonical member: {status} {result}"
        );
        ensure!(result["mode"] == mode && result["visible_membership_ids"] == json!(targets));
    }
    Ok(())
}

pub(super) async fn seed_chain(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(r#"
    INSERT INTO iam.principals(id,kind,status,activated_at) VALUES('store','application','active',now());
    INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,app_name,base_url,review_status,app_scope)
    VALUES('store','store','00000000-0000-0000-0000-000000000023','c:test_admin','Store','https://store.example.test','verified','{"iam":["self.identity.read","self.membership.read","self.tags.read"],"external":[]}');
    INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical)
    VALUES('00000000-0000-0000-0000-000000000023','store','blobs.write','/blobs','{}',false);
    UPDATE iam.application_obo_endpoints SET downstream='[{"audience":"store","endpoint_id":"blobs.write"}]' WHERE application_id='target';
    UPDATE iam.applications SET app_scope='{"iam":["self.identity.read","self.membership.read","self.tags.read"],"external":[{"app_id":"store","endpoint_id":"blobs.write"}]}' WHERE id='target';
    INSERT INTO iam.oauth_scope_catalog(scope,description) VALUES('obo:store:blobs.write','Write blobs');
    INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES('target','obo:store:blobs.write');
    INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id) VALUES('target','obo:store:blobs.write','c:test_carbon');
    INSERT INTO iam.application_requested_scopes(application_id,scope)
    SELECT 'store',scope FROM unnest(ARRAY['self.identity.read','self.membership.read','self.tags.read']) scope;
    INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
    SELECT 'store',scope,'c:test_carbon' FROM unnest(ARRAY['self.identity.read','self.membership.read','self.tags.read']) scope;
    INSERT INTO iam.access_tokens(id,token_class,token_digest,digest_key_version,token_prefix,authentication_session_id,subject_principal_id,subject_kind,audience,subject_auth_epoch,expires_at)
    VALUES('00000000-0000-0000-0000-000000000201','carbon_access',decode(repeat('88',32),'hex'),1,'cat_testuser','00000000-0000-0000-0000-000000000041','c:test_carbon','carbon','silicon-iam',1,now()+interval '1 hour');
    INSERT INTO iam.access_token_scopes(access_token_id,scope) VALUES('00000000-0000-0000-0000-000000000201','iam.self');
    "#).execute(pool).await?;
    Ok(())
}

async fn check_protocol(state: &ApiState, pool: &PgPool, subject: &str) -> anyhow::Result<()> {
    let policy: SqlJson<Value> =
        sqlx::query_scalar("SELECT iam_private.application_login_scope_policy('app-alpha')")
            .fetch_one(pool)
            .await?;
    ensure!(
        policy.0["scopes"]
            .as_array()
            .context("login scopes")?
            .iter()
            .all(|scope| !scope["scope"]
                .as_str()
                .unwrap_or_default()
                .starts_with("obo:")),
        "login still requests OBO"
    );
    let outsider = Bearer(AccessContext {
        client_application_id: Some(Id::fixture("app-alpha")),
        ..user().0
    });
    ensure!(
        grants(
            State(state.clone()),
            outsider,
            HeaderMap::new(),
            Query(GrantQuery {
                app_id: None,
                cursor: None,
                limit: None,
            })
        )
        .await
        .is_err(),
        "third-party bearer cannot approve its own grant"
    );
    let (request, code) = approved(state, subject, "root-first").await?;
    ensure!(
        issue(
            State(state.clone()),
            app("store"),
            headers("wrong-app-code-exchange"),
            Json(TokenRequest {
                grant_id: None,
                subject_token: None,
                authorization_id: Some(request),
                authorization_code: Some(code.clone()),
                refresh_token: None
            })
        )
        .await
        .is_err(),
        "code crossed app boundary"
    );
    let pair = exchange_pair(state, request, &code, "root-code-exchange").await?;
    ensure!(
        pair.get("refresh_token_id").is_none(),
        "internal refresh row leaked"
    );
    let replay = exchange_pair(state, request, &code, "root-code-exchange").await?;
    ensure!(pair == replay, "exact issuance retry changed credentials");
    let access = pair["access_token"].as_str().context("access")?;
    for _ in 0..2 {
        let checked =
            value(verify_as(state, "target", access, "files.read", "/files").await).await?;
        ensure!(checked["active"] == true);
        ensure!(checked["actor"]["public_id"] == "c:test_carbon");
    }
    ensure!(
        verify_as(state, "store", access, "files.read", "/files")
            .await
            .is_err(),
        "token crossed audience"
    );
    ensure!(
        verify_as(state, "target", access, "files.read", "/other")
            .await
            .is_err(),
        "token allowed wrong action path"
    );
    let delegated = value(
        delegate(
            State(state.clone()),
            app("target"),
            headers("derive-storage-access"),
            Json(Delegation {
                access_token: access.into(),
                audience: "store".into(),
                endpoint_id: "blobs.write".into(),
            }),
        )
        .await,
    )
    .await?;
    ensure!(
        delegated.get("refresh_token").is_none(),
        "downstream refresh escaped"
    );
    let child = delegated["access_token"].as_str().context("child access")?;
    ensure!(
        child == access,
        "chained endpoints must share the same access token"
    );
    value(verify_as(state, "store", access, "[store:obo:blobs.write]", "/blobs").await).await?;
    let child_verified =
        value(verify_as(state, "store", child, "blobs.write", "/blobs").await).await?;
    ensure!(
        child_verified["originating_app_id"] == "app-alpha"
            && child_verified["issuer_app_id"] == "target"
    );
    ensure!(
        child_verified["chain"]
            .as_array()
            .is_some_and(|items| items.len() == 2)
    );
    ensure!(
        delegate(
            State(state.clone()),
            app("app-alpha"),
            headers("forbidden-direct-storage"),
            Json(Delegation {
                access_token: access.into(),
                audience: "store".into(),
                endpoint_id: "blobs.write".into()
            })
        )
        .await
        .is_err(),
        "root caller stole downstream authority"
    );
    // Expiring the original ordinary login access token must not end consent.
    sqlx::query("UPDATE iam.access_tokens SET created_at=now()-interval '2 minutes',expires_at=now()-interval '1 second' WHERE id=$1").bind(APP_TOKEN).execute(pool).await?;
    value(verify_as(state, "target", access, "files.read", "/files").await).await?;
    let refresh = pair["refresh_token"].as_str().context("refresh")?;
    let rotated = value(
        issue(
            State(state.clone()),
            app("app-alpha"),
            headers("refresh-approved-root"),
            Json(TokenRequest {
                grant_id: None,
                subject_token: None,
                authorization_id: None,
                authorization_code: None,
                refresh_token: Some(refresh.into()),
            }),
        )
        .await,
    )
    .await?;
    ensure!(rotated["items"][0]["refresh_token"] != pair["refresh_token"]);
    ensure!(
        exchange_pair(state, request, &code, "root-code-exchange")
            .await
            .is_err(),
        "stale replay returned consumed refresh"
    );
    ensure!(
        issue(
            State(state.clone()),
            app("app-alpha"),
            headers("replay-stolen-refresh"),
            Json(TokenRequest {
                grant_id: None,
                subject_token: None,
                authorization_id: None,
                authorization_code: None,
                refresh_token: Some(refresh.into())
            })
        )
        .await
        .is_err()
    );
    ensure!(
        verify_as(state, "target", access, "files.read", "/files")
            .await
            .is_err(),
        "refresh reuse left old token active"
    );
    ensure!(
        verify_as(state, "store", child, "blobs.write", "/blobs")
            .await
            .is_err(),
        "refresh reuse left descendant active"
    );
    let newer = rotated["items"][0]["access_token"]
        .as_str()
        .context("rotated access")?;
    ensure!(
        verify_as(state, "target", newer, "files.read", "/files")
            .await
            .is_err(),
        "refresh reuse left successor active"
    );
    sqlx::query("UPDATE iam.access_tokens SET expires_at=now()+interval '15 minutes' WHERE id=$1")
        .bind(APP_TOKEN)
        .execute(pool)
        .await?;
    let (request, code) = approved(state, subject, "root-second").await?;
    let pair = exchange_pair(state, request, &code, "second-code-exchange").await?;
    let grant_id = serde_json::from_value(pair["grant_id"].clone())?;
    let listed = value(
        grants(
            State(state.clone()),
            user(),
            HeaderMap::new(),
            Query(GrantQuery {
                app_id: None,
                cursor: None,
                limit: None,
            }),
        )
        .await,
    )
    .await?;
    ensure!(
        listed["items"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    value(
        revoke(
            State(state.clone()),
            user(),
            headers("revoke-approved-grant"),
            Path(grant_id),
        )
        .await,
    )
    .await?;
    ensure!(
        verify_as(
            state,
            "target",
            pair["access_token"].as_str().context("second access")?,
            "files.read",
            "/files"
        )
        .await
        .is_err(),
        "grant revoke not enforced"
    );
    // Ordinary logout leaves explicitly approved OBO authority available.
    let (request, code) = approved(state, subject, "root-third").await?;
    let pair = exchange_pair(state, request, &code, "third-code-exchange").await?;
    let first_page = value(
        grants(
            State(state.clone()),
            user(),
            HeaderMap::new(),
            Query(GrantQuery {
                app_id: None,
                cursor: None,
                limit: Some(1),
            }),
        )
        .await,
    )
    .await?;
    ensure!(
        first_page["items"]
            .as_array()
            .is_some_and(|items| items.len() == 1)
    );
    ensure!(first_page["page"]["has_more"] == true);
    let next = first_page["page"]["next_cursor"]
        .as_str()
        .context("next grants cursor")?;
    let second_page = value(
        grants(
            State(state.clone()),
            user(),
            HeaderMap::new(),
            Query(GrantQuery {
                app_id: None,
                cursor: Some(next.into()),
                limit: Some(1),
            }),
        )
        .await,
    )
    .await?;
    ensure!(
        second_page["items"]
            .as_array()
            .is_some_and(|items| items.len() == 1)
    );
    ensure!(second_page["items"][0]["id"] != first_page["items"][0]["id"]);
    ensure!(second_page["page"]["has_more"] == false);
    let mut rotated_client = app("target");
    rotated_client.authenticated_secret = SecretString::from("ask_replaced-secret");
    ensure!(
        verify(
            State(state.clone()),
            rotated_client,
            HeaderMap::new(),
            Json(Verification {
                access_token: pair["access_token"]
                    .as_str()
                    .context("third access")?
                    .into(),
                endpoint_id: "files.read".into(),
                request: Action {
                    method: "POST".into(),
                    path: "/files".into()
                },
            })
        )
        .await
        .is_err(),
        "handler did not revalidate extracted application credentials"
    );
    sqlx::query(
        "UPDATE iam.authentication_sessions SET status='revoked',revoked_at=now() WHERE id=$1",
    )
    .bind(SESSION)
    .execute(pool)
    .await?;
    ensure!(
        verify_as(
            state,
            "target",
            pair["access_token"].as_str().context("third access")?,
            "files.read",
            "/files"
        )
        .await
        .is_ok(),
        "logout revoked durable OBO approval"
    );
    Ok(())
}
