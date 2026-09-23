//! Recovery ordering through HTTP backed by the restricted database runtime.
use super::*;

pub(super) async fn exercise(
    app: &axum::Router,
    state: &ApiState,
    admin: &sqlx::PgPool,
    test_admin: &sqlx::PgPool,
    credential: &str,
    actor: &str,
    environment: Id,
    path: &str,
    original: &Value,
    accepted: &Value,
) -> anyhow::Result<()> {
    let original_id: Id = serde_json::from_value(original["operation_id"].clone())?;
    let current_revision: i64 =
        sqlx::query_scalar("SELECT version FROM iam.testing_environments WHERE id=$1")
            .bind(environment)
            .fetch_one(admin)
            .await?;
    ensure!(
        Some(current_revision) != original["expected_environment_revision"].as_i64(),
        "recovery fixture requires an advanced environment revision"
    );
    let before = credential_state(test_admin, environment).await?;
    let mut fresh = original.clone();
    fresh["operation_id"] = json!(Id::now_v7());
    fresh["expected_iam_revision"] = accepted["iam_revision"].clone();
    fresh["configuration_revision"] = json!(999);
    let (status, rejected) = actor_request(app, credential, actor, path, &fresh).await?;
    ensure!(
        status == StatusCode::CONFLICT
            && rejected["error"]["code"] == "configuration_revision_conflict",
        "stale environment hid definitive configuration rejection: {status} {rejected}"
    );
    fresh["configuration_revision"] = original["configuration_revision"].clone();
    let (status, rejected) = actor_request(app, credential, actor, path, &fresh).await?;
    ensure!(
        status == StatusCode::CONFLICT
            && rejected["error"]["code"] == "testing_revision_or_state_conflict",
        "valid configuration bypassed the stale environment fence: {status} {rejected}"
    );
    let fresh_id: Id = serde_json::from_value(fresh["operation_id"].clone())?;
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam_private.honeycomb_test_app_receipts WHERE environment_id=$1 AND operation_id=$2",
    ).bind(environment).bind(fresh_id).fetch_one(test_admin).await?;
    ensure!(receipts == 0, "rejected rotation created a target receipt");

    // Remove only the fixture's committed control-plane result. The target-plane
    // receipt and changed credential now model a lost control-plane commit.
    let mut tx = admin.begin().await?;
    sqlx::query("DELETE FROM iam.honeycomb_management_events WHERE operation_id=$1")
        .bind(original_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM iam.honeycomb_operations WHERE operation_id=$1")
        .bind(original_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    for (field, value) in [
        ("generation", json!(2)),
        ("key_version", json!(2)),
        ("configuration_revision", json!(999)),
        ("expected_environment_revision", json!(current_revision)),
    ] {
        let mut altered = original.clone();
        altered[field] = value;
        let (status, result) = actor_request(app, credential, actor, path, &altered).await?;
        ensure!(
            !status.is_success()
                && result.get("app_secret").is_none()
                && result["error"]["code"] != "configuration_revision_conflict",
            "target receipt accepted a changed {field}"
        );
    }
    // A valid environment root uses a different principal from the original
    // Carbon actor. Knowing that key must not expose the Carbon's exact receipt.
    let (status, result) = root_method(
        app,
        credential,
        Some(&"X".repeat(32)),
        "POST",
        path,
        original,
    )
    .await?;
    ensure!(
        status == StatusCode::CONFLICT && result.get("app_secret").is_none(),
        "target receipt lost its actor binding: {status}"
    );
    let foreign = Id::now_v7();
    let mut changed_context = original.clone();
    changed_context["environment_id"] = json!(foreign);
    let foreign_path = path.replace(&environment.to_string(), &foreign.to_string());
    let (status, result) =
        actor_request(app, credential, actor, &foreign_path, &changed_context).await?;
    ensure!(
        !status.is_success() && result.get("app_secret").is_none(),
        "receipt escaped its authorized environment"
    );

    let recovered = send(app, credential, None, Some(actor), "POST", path, original).await?;
    ensure!(
        recovered == *accepted,
        "target receipt did not recover the exact original result"
    );
    let replay = send(app, credential, None, Some(actor), "POST", path, original).await?;
    ensure!(
        replay == *accepted,
        "recovered control-plane replay changed result"
    );
    ensure!(
        credential_state(test_admin, environment).await? == before,
        "recovery or rejected requests rotated credentials again"
    );
    ensure!(
        current_snapshot_secret(state, admin, environment, "test_org>test-only").await?
            == accepted["app_secret"],
        "recovery changed the recoverable application credential"
    );
    let (completed, receipts): (bool, i64) = sqlx::query_as(
        "SELECT completed,(SELECT count(*) FROM iam.honeycomb_management_events WHERE operation_id=$1) FROM iam.honeycomb_operations WHERE operation_id=$1",
    ).bind(original_id).fetch_one(admin).await?;
    ensure!(
        completed && receipts == 1,
        "recovery did not restore one completed control-plane result"
    );
    Ok(())
}

async fn credential_state(
    admin: &sqlx::PgPool,
    environment: Id,
) -> anyhow::Result<(i64, i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT a.version,p.auth_epoch,(SELECT count(*) FROM iam.application_secrets s WHERE s.testing_environment_id=a.testing_environment_id AND s.application_id=a.id) FROM iam.applications a JOIN iam.principals p ON p.id=a.id AND p.testing_environment_id=a.testing_environment_id WHERE a.app_id='test_org>test-only' AND a.testing_environment_id=$1",
    ).bind(environment).fetch_one(admin).await?)
}

async fn actor_request(
    app: &axum::Router,
    credential: &str,
    actor: &str,
    path: &str,
    value: &Value,
) -> anyhow::Result<(StatusCode, Value)> {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("authorization", format!("Bearer {credential}"))
                .header("x-honeycomb-actor-token", actor)
                .header(
                    "idempotency-key",
                    value["operation_id"].as_str().unwrap_or_default(),
                )
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(value)?))?,
        )
        .await?;
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
    Ok((status, body))
}
