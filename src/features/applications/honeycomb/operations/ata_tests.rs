//! Exercise consent-free application authority through the protected manager API.
#![allow(clippy::too_many_lines)]
use crate::domain::id::Id;
use anyhow::ensure;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

pub(crate) async fn exercise(
    app: &axum::Router,
    admin: &sqlx::PgPool,
    service: &str,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = admin.begin().await?;
    sqlx::query("SELECT set_config('iam.principal_id','c:test_admin',true)")
        .execute(&mut *tx)
        .await?;
    for (id, endpoint, downstream) in [
        ("app-alpha", "store", json!([])),
        (
            "managed-app",
            "render",
            json!([{"audience":"app-alpha","endpoint_id":"store"}]),
        ),
    ] {
        sqlx::query("SELECT iam_private.configure_application_ata_endpoints($1,$2)").bind(id).bind(sqlx::types::Json(json!([{
            "endpoint_id":endpoint,"name":endpoint,"description":"Fixture application action","path":format!("/ata/{endpoint}"),"critical":false,"metadata":{},"note_to_user":null,"additional_warnings":[],"enabled":true,"downstream":downstream
        }]))).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let route = "/api/v1/honeycomb/applications/managed-app/ata-verifications";
    let request = |path: &str, method: &str, body: &Value| -> anyhow::Result<Request<Body>> {
        Ok(Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {service}"))
            .header("x-honeycomb-actor-token", actor)
            .header("content-type", "application/json")
            .header(
                "idempotency-key",
                body["operation_id"]
                    .as_str()
                    .unwrap_or("ata-preview-fixture"),
            )
            .body(Body::from(serde_json::to_vec(body)?))?)
    };
    let read = |response: axum::response::Response| async move {
        let status = response.status();
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
        Ok::<_, anyhow::Error>((status, value))
    };
    let root = json!({"endpoints":[{"audience":"managed-app","endpoint_id":"render"}],"app_ids":["managed-app"]});
    let (status, preview) = read(
        app.clone()
            .oneshot(request(&format!("{route}/preview"), "POST", &root)?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "ATA preview failed: {status} {preview}"
    );
    ensure!(
        preview["requires_expansion"] == true
            && preview["app_ids"].as_array().is_some_and(|v| v.len() == 2)
    );
    let operation = Id::now_v7();
    let mut input = root;
    input["operation_id"] = json!(operation);
    input["graph_version"] = preview["graph_version"].clone();
    let response = app.clone().oneshot(request(route, "POST", &input)?).await?;
    ensure!(
        !response.status().is_success(),
        "ATA silently expanded authority without review"
    );
    input["endpoints"] = preview["endpoints"].clone();
    input["app_ids"] = preview["app_ids"].clone();
    let (status, created) =
        read(app.clone().oneshot(request(route, "POST", &input)?).await?).await?;
    ensure!(
        status == StatusCode::OK,
        "ATA create failed: {status} {created}"
    );
    let secret = created["refresh_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing creation credential"))?;
    ensure!(secret.starts_with("atr_"));
    ensure!(created["signing_principal"]["id"] == "c:test_carbon");
    let (_, replay) = read(app.clone().oneshot(request(route, "POST", &input)?).await?).await?;
    ensure!(
        replay == created,
        "same operation regenerated its refresh credential"
    );
    let public: String = sqlx::query_scalar(
        "SELECT result::text FROM iam.honeycomb_operations WHERE operation_id=$1",
    )
    .bind(operation)
    .fetch_one(admin)
    .await?;
    let event: String = sqlx::query_scalar(
        "SELECT payload::text FROM iam.honeycomb_management_events WHERE operation_id=$1",
    )
    .bind(operation)
    .fetch_one(admin)
    .await?;
    ensure!(
        !public.contains(secret) && !event.contains(secret),
        "ATA refresh credential escaped encrypted replay storage"
    );
    let (status, list) = read(
        app.clone()
            .oneshot(request(route, "GET", &json!({}))?)
            .await?,
    )
    .await?;
    ensure!(status == StatusCode::OK && !list.to_string().contains(secret));
    sqlx::query("UPDATE iam.honeycomb_operations SET response_expires_at=now()-interval '1 second' WHERE operation_id=$1").bind(operation).execute(admin).await?;
    let (_, expired) = read(app.clone().oneshot(request(route, "POST", &input)?).await?).await?;
    ensure!(expired["secret_replay_expired"] == true && expired.get("refresh_token").is_none());
    let verification = created["id"]
        .as_str()
        .or_else(|| created["verification_id"].as_str())
        .ok_or_else(|| anyhow::anyhow!("missing verification identity"))?;
    let (status, revoked) = read(
        app.clone()
            .oneshot(request(
                &format!("{route}/{verification}/revoke"),
                "POST",
                &json!({"operation_id":Id::now_v7()}),
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "ATA revoke failed: {status} {revoked}"
    );
    Ok(())
}
