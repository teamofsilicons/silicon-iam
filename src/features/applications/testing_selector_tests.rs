//! Exercise the selector's real OAuth reroute with the published UUID schema.
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
        .bind(ENVIRONMENT).bind(Uuid::from_u128(0x21)).bind(Uuid::from_u128(0x31))
        .execute(production).await?;
    let secret = state
        .crypto
        .generate_secret(SecretKind::ApplicationSecret)?;
    let (status, tokens) = testing_plane::scope(
        SelectedEnvironment { id: ENVIRONMENT, organization_id: Uuid::from_u128(0x21) },
        async {
            let digest = state.crypto.digest_secret(DigestPurpose::ApplicationSecret, &secret)?;
            sqlx::query("UPDATE iam.application_secrets SET secret_digest=$1,pepper_key_version=$2 WHERE application_id=$3")
                .bind(digest.as_bytes().as_slice()).bind(digest.key_version()).bind(APP)
                .execute(testing).await?;
            let mut tx = context::begin(state.db(), DatabaseContext::principal(APP)).await?;
            crate::features::testing_environments::register_application_selector(&mut tx, APP, &secret).await?;
            tx.commit().await?;
            exchange(state, "test_carbon", "selector-membership-transport-login").await
        },
    ).await?;
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
            .encode(format!("test_org>app-alpha:{}", secret.expose_secret()))
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
            "test_carbon%5Btest_org%5D"
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
            "test_carbon[test_org]"
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
            "worker:test_org[test_org]"
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
