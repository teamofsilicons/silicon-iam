//! Exercise the selector's OAuth reroute with canonical identity IDs and legacy membership IDs.
use super::*;
use crate::infrastructure::crypto::{DigestPurpose, SecretKind};
use axum::http::{HeaderValue, Method, Request, header};
use base64::Engine as _;
use sqlx::PgPool;
use tower::ServiceExt as _;

pub(super) async fn assert_selector_membership_transport(
    state: &ApiState,
    production: &PgPool,
    testing: &PgPool,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO iam.testing_environments(id,organization_id,created_by_membership_id,name,key_digest,key_digest_key_version,key_ciphertext,key_nonce,key_encryption_key_version) VALUES($1,$2,$3,'Selector transport regression',decode(repeat('61',32),'hex'),1,decode(repeat('62',17),'hex'),decode(repeat('63',12),'hex'),1)")
        .bind(ENVIRONMENT).bind(Id::from_u128(0x21)).bind(Id::from_u128(0x31))
        .execute(production).await?;
    let secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)?;
    let (status, tokens) = Box::pin(testing_plane::scope(
        SelectedEnvironment { id: ENVIRONMENT, organization_id: Id::from_u128(0x21) },
        async {
            let digest = state.crypto.digest_secret(DigestPurpose::ApplicationSecret, &secret)?;
            sqlx::query("UPDATE iam.application_secrets SET secret_digest=$1,pepper_key_version=$2 WHERE application_id=$3")
                .bind(digest.as_bytes().as_slice()).bind(digest.key_version()).bind(APP)
                .execute(testing).await?;
            let mut tx = context::begin(state.db(), DatabaseContext::principal(APP)).await?;
            crate::features::testing_environments::register_application_selector(&mut tx, APP, &secret).await?;
            tx.commit().await?;
            exchange(state, "c:test_carbon", "selector-membership-transport-login").await
        },
    )).await?;
    ensure!(
        status == StatusCode::OK,
        "selector test token issuance failed: {tokens}"
    );
    let bearer = tokens["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing test bearer"))?;
    let selector = HeaderValue::from_str(&format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("app-alpha:{}", secret.expose_secret()))
    ))?;
    // Match the full API's layer order: plane selection is outside transport.
    // Its OAuth selector branch reroutes before the original transport runs.
    let app = crate::features::organizations::router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::membership_ids::transport,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::features::testing_environments::select_plane,
        ))
        .with_state(state.clone());
    for agent in [
        None,
        Some("silicon-iam-client/2.0.0"),
        Some("silicon-iam-client/1.11.0"),
    ] {
        let legacy = agent == Some("silicon-iam-client/1.11.0");
        let membership = if legacy {
            "00000000-0000-0000-0000-000000000031"
        } else {
            "c:test_carbon%5Btest_org%5D"
        };
        let uri = format!("/api/v1/organizations/test_org/members/{membership}");
        let (status, headers, body) =
            request(&app, Method::GET, &uri, None, agent, bearer, &selector).await?;
        ensure!(
            status == StatusCode::OK,
            "selector member read failed: {status} {body}"
        );
        let expected = if legacy {
            "00000000-0000-0000-0000-000000000031"
        } else {
            "c:test_carbon[test_org]"
        };
        ensure!(
            body["id"] == expected,
            "selector membership format for {agent:?}: {body}"
        );
        ensure!(
            headers
                .get("silicon-iam-membership-format")
                .and_then(|value| value.to_str().ok())
                == legacy.then_some("uuid-legacy")
        );
        let target = if legacy {
            "00000000-0000-0000-0000-000000000531"
        } else {
            "si:worker[test_org]"
        };
        // The read-only token must reach ordinary authorization after decoding,
        // rather than failing JSON/query UUID extraction or gaining write access.
        let body = json!({"first_silicon_membership_id": target});
        let (status, _, error) = request(
            &app,
            Method::PATCH,
            &uri,
            Some(body),
            agent,
            bearer,
            &selector,
        )
        .await?;
        ensure!(
            status == StatusCode::FORBIDDEN,
            "selector body decode did not reach authorization: {status} {error}"
        );
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("reassign_reports_to", target)
            .finish();
        let (status, _, error) = request(
            &app,
            Method::DELETE,
            &format!("{uri}?{query}"),
            None,
            agent,
            bearer,
            &selector,
        )
        .await?;
        ensure!(
            status == StatusCode::FORBIDDEN,
            "selector query decode did not reach authorization: {status} {error}"
        );
    }
    assert_selector_obo_routes(state, testing, bearer, &selector).await?;
    Ok(())
}

async fn request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    agent: Option<&str>,
    bearer: &str,
    selector: &HeaderValue,
) -> anyhow::Result<(StatusCode, HeaderMap, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header("x-testing-application", selector.clone());
    if let Some(agent) = agent {
        request = request.header(header::USER_AGENT, agent);
    }
    let body = if let Some(body) = body {
        request = request.header(header::CONTENT_TYPE, "application/json");
        axum::body::Body::from(body.to_string())
    } else {
        axum::body::Body::empty()
    };
    let response = app.clone().oneshot(request.body(body)?).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 65536).await?;
    let body = serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({"body":String::from_utf8_lossy(&body)}));
    Ok((status, headers, body))
}

/// Real middleware, credentials, database role and request handlers. An app can
/// prepare/read its review, but the selector never gains the user's decision authority.
async fn assert_selector_obo_routes(
    state: &ApiState,
    testing: &PgPool,
    bearer: &str,
    selector: &HeaderValue,
) -> anyhow::Result<()> {
    sqlx::raw_sql(r#"
        INSERT INTO iam.principals(id,kind,status,activated_at)
        VALUES('selector-provider','application','active',now());
        INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,base_url,review_status)
        VALUES('selector-provider','selector-provider','00000000-0000-0000-0000-000000000021','c:test_carbon','https://provider.example.test','verified');
        INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical)
        VALUES('00000000-0000-0000-0000-000000000021','selector-provider','files.read','/files','{}',false);
        UPDATE iam.applications SET app_scope=jsonb_set(app_scope,'{external}','[{"app_id":"selector-provider","endpoint_id":"files.read"}]') WHERE id='app-alpha';
        INSERT INTO iam.oauth_scope_catalog(scope,description) VALUES('obo:selector-provider:files.read','Read synthetic files');
        INSERT INTO iam.application_requested_scopes(application_id,scope) VALUES('app-alpha','obo:selector-provider:files.read');
        INSERT INTO iam.application_approved_scopes(application_id,scope,approved_by_carbon_id)
        VALUES('app-alpha','obo:selector-provider:files.read','c:test_carbon');
    "#).execute(testing).await?;
    let router = crate::features::applications::router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::features::testing_environments::select_plane,
        ))
        .with_state(state.clone());
    let send = |method: Method, path: String, body: Value, selected: bool| {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, selector.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", "selector-obo-authorization");
        if selected {
            request = request.header("x-testing-application", selector.clone());
        }
        router.clone().oneshot(
            request
                .body(axum::body::Body::from(body.to_string()))
                .unwrap_or_else(|_| unreachable!("valid static synthetic request")),
        )
    };
    let body = json!({"subject_token":bearer,"org_id":"test_org","endpoints":[{"audience":"selector-provider","endpoint_id":"files.read"}]});
    let response = send(
        Method::POST,
        "/api/v1/obo-access/authorizations".into(),
        body.clone(),
        true,
    )
    .await?;
    let status = response.status();
    let created: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    ensure!(
        status == StatusCode::CREATED,
        "app selector OBO start failed: {status} {created}"
    );
    ensure!(created["status"] == "pending" && created["org_id"] == "test_org");
    let id = created["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("authorization id"))?;
    let read = send(
        Method::GET,
        format!("/api/v1/obo-access/authorizations/{id}"),
        json!({}),
        true,
    )
    .await?;
    ensure!(
        read.status() == StatusCode::OK,
        "app selector could not read its review"
    );
    let read: Value = serde_json::from_slice(&to_bytes(read.into_body(), 65536).await?)?;
    ensure!(read["id"] == id && read["status"] == "pending");
    let replay = send(
        Method::POST,
        "/api/v1/obo-access/authorizations".into(),
        body.clone(),
        true,
    )
    .await?;
    ensure!(replay.status() == StatusCode::CREATED);
    let replay: Value = serde_json::from_slice(&to_bytes(replay.into_body(), 65536).await?)?;
    ensure!(
        replay == created,
        "selector authorization retry changed its receipt"
    );
    for path in [
        format!("/api/v1/obo-access/consents/{id}/decision"),
        format!("/api/v1/obo-access/grants/{id}/revoke"),
        "/api/v1/app-auth/short-lived-tokens".into(),
    ] {
        let denied = send(
            Method::POST,
            path,
            json!({"decision":"approve","version":1,"iam_disclosures_reviewed":true}),
            true,
        )
        .await?;
        ensure!(
            denied.status() == StatusCode::FORBIDDEN,
            "app selector gained direct actor authority"
        );
    }
    ensure!(
        send(
            Method::POST,
            "/api/v1/obo-access/authorizations".into(),
            body,
            false
        )
        .await?
        .status()
            == StatusCode::UNAUTHORIZED,
        "test credential authenticated without a world selector"
    );
    Ok(())
}
