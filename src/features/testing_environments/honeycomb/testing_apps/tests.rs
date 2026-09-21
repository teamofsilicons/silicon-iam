//! End-to-end contract exercised from the shared restricted-role IAM fixture.
use super::*;
use anyhow::ensure;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tower::ServiceExt as _;

pub(crate) async fn exercise(
    app: &axum::Router,
    _state: &ApiState,
    admin: &sqlx::PgPool,
    test_admin: &sqlx::PgPool,
    credential: &str,
    actor: &str,
) -> anyhow::Result<()> {
    let production = json!({"operation_id":Id::now_v7(),"expected_iam_revision":0,"configuration_revision":1,
        "app_id":"test_org>testing-driver","org_id":"test_org","name":"Testing driver","logo_url":null,"base_url":null,
        "visibility":"private","availability":"active","webhook":{"url":"https://testing-driver.example.test/webhook","secret":"d".repeat(48),"scope":["membership"]},
        "app_scope":{"iam":["self.identity.read"],"external":[]},"obo_endpoints":[],"obo_review_message":null});
    let production = send(
        app,
        credential,
        None,
        Some(actor),
        "PUT",
        "/api/v1/honeycomb/applications/test_org%3Etesting-driver/configuration",
        &production,
    )
    .await?;
    let production_app: Id = serde_json::from_value(production["application_id"].clone())?;
    let authorization = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "test_org>testing-driver:{}",
            production["app_secret"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("new production app secret missing"))?
        ))
    );
    let identity = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/honeycomb/application-identity")
                .header("authorization", format!("Bearer {credential}"))
                .header("x-honeycomb-application-authorization", &authorization)
                .body(Body::empty())?,
        )
        .await?;
    let status = identity.status();
    let identity: Value =
        serde_json::from_slice(&to_bytes(identity.into_body(), 1024 * 1024).await?)?;
    ensure!(
        status == StatusCode::OK
            && identity["app_id"] == "test_org>testing-driver"
            && identity["org_id"] == "test_org"
            && identity.get("app_secret").is_none(),
        "standalone application verification failed: {status} {identity}"
    );
    let environment = Id::now_v7();
    let operation = Id::now_v7();
    let create = json!({"operation_id":operation,"environment_id":environment,"expected_iam_revision":0,"generation":1,"operation":"prepare","org_id":"test_org","name":"App-owned shared test","testing_key":"X".repeat(32),"key_version":1});
    let endpoint = format!("/api/v1/honeycomb/testing-environments/{environment}/operations");
    let result = send(
        app,
        credential,
        Some(&authorization),
        None,
        "POST",
        &endpoint,
        &create,
    )
    .await?;
    let owner: Option<Id> = sqlx::query_scalar(
        "SELECT created_by_application_id FROM iam.testing_environments WHERE id=$1",
    )
    .bind(environment)
    .fetch_one(admin)
    .await?;
    ensure!(
        owner == Some(production_app),
        "application credential must own its created environment"
    );
    let mut revision = result["iam_revision"].as_i64().unwrap_or_default();
    let configured_app = "test_org>test-only";
    let app_path = "test_org%3Etest-only";
    let config_endpoint = format!(
        "/api/v1/honeycomb/testing-environments/{environment}/applications/{app_path}/configuration"
    );
    let configuration = json!({"org_id":"test_org","name":"Test only","logo_url":null,"base_url":null,"visibility":"private","availability":"active","webhook":{"url":"https://test-only.example.test/webhook","secret":"s".repeat(48),"scope":["membership"]},"app_scope":{"iam":["self.identity.read"],"external":[]},"obo_endpoints":[],"obo_review_message":null});
    let operation = Id::now_v7();
    let mut configure = json!({"operation_id":operation,"environment_id":environment,"generation":1,"key_version":1,"expected_environment_revision":revision,"expected_iam_revision":0,"configuration_revision":1,"configuration":configuration});
    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&config_endpoint)
                .header("authorization", format!("Bearer {credential}"))
                .header("x-honeycomb-application-authorization", &authorization)
                .header("idempotency-key", Id::now_v7().to_string())
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&configure)?))?,
        )
        .await?;
    ensure!(
        denied.status() == StatusCode::FORBIDDEN,
        "owning an environment must not expose unrelated application credentials"
    );
    let first = send(
        app,
        credential,
        None,
        Some(actor),
        "PUT",
        &config_endpoint,
        &configure,
    )
    .await?;
    ensure!(
        first["ready"] == false && first["app_secret"].is_string(),
        "test registration must return own new secret while leaving runtime pending"
    );
    let retry = send(
        app,
        credential,
        None,
        Some(actor),
        "PUT",
        &config_endpoint,
        &configure,
    )
    .await?;
    ensure!(
        retry == first,
        "test-app registration replay changed secret or identifiers"
    );
    let production_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM iam.applications WHERE app_id=$1")
            .bind(configured_app)
            .fetch_one(admin)
            .await?;
    ensure!(
        production_count == 0,
        "test registration leaked to production"
    );
    let test_count:i64=sqlx::query_scalar("SELECT count(*) FROM iam.applications WHERE app_id=$1 AND testing_environment_id=$2 AND NOT test_imported_from_production").bind(configured_app).bind(environment).fetch_one(test_admin).await?;
    ensure!(
        test_count == 1,
        "test application missing or wrong provenance"
    );
    // Config edits preserve credentials; rotation is explicit and replay safe.
    configure["operation_id"] = json!(Id::now_v7());
    configure["configuration_revision"] = json!(2);
    configure["expected_iam_revision"] = first["iam_revision"].clone();
    configure["configuration"]["name"] = json!("Updated test app");
    let updated = send(
        app,
        credential,
        None,
        Some(actor),
        "PUT",
        &config_endpoint,
        &configure,
    )
    .await?;
    ensure!(
        updated.get("app_secret").is_none(),
        "ordinary test config must not rotate credentials"
    );
    let rotate = json!({"operation_id":Id::now_v7(),"environment_id":environment,"generation":1,"key_version":1,"expected_environment_revision":revision,"expected_iam_revision":updated["iam_revision"],"configuration_revision":2});
    let rotate_endpoint = format!(
        "/api/v1/honeycomb/testing-environments/{environment}/applications/{app_path}/secret-rotations"
    );
    let rotated = send(
        app,
        credential,
        None,
        Some(actor),
        "POST",
        &rotate_endpoint,
        &rotate,
    )
    .await?;
    ensure!(
        rotated["app_secret"] != first["app_secret"],
        "explicit test rotation did not change credential"
    );
    ensure!(
        send(
            app,
            credential,
            None,
            Some(actor),
            "POST",
            &rotate_endpoint,
            &rotate
        )
        .await?
            == rotated,
        "rotation repeated on retry"
    );
    let activation = json!({"operation_id":Id::now_v7(),"environment_id":environment,"expected_iam_revision":revision,"generation":1,"operation":"activate"});
    let activated = send(
        app,
        credential,
        Some(&authorization),
        None,
        "POST",
        &endpoint,
        &activation,
    )
    .await?;
    revision = activated["iam_revision"].as_i64().unwrap_or_default();
    ensure!(
        send(
            app,
            credential,
            None,
            Some(actor),
            "POST",
            &rotate_endpoint,
            &rotate
        )
        .await?
            == rotated,
        "completed secret replay must survive an unrelated environment revision advance"
    );
    let read_path = format!(
        "/api/v1/honeycomb/testing-environments/{environment}/applications/{app_path}?generation=1&key_version=1&expected_environment_revision={revision}"
    );
    let read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(read_path)
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())?,
        )
        .await?;
    ensure!(
        read.status() == StatusCode::OK,
        "test control-plane read failed"
    );
    let read: Value = serde_json::from_slice(&to_bytes(read.into_body(), 1024 * 1024).await?)?;
    ensure!(
        read.get("app_secret").is_none() && read["webhook_url"] == configuration["webhook"]["url"],
        "read omitted accepted destination or leaked secret"
    );
    let foreign_org = Id::now_v7();
    let foreign_member = Id::now_v7();
    let mut setup = admin.begin().await?;
    sqlx::query("INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES($1,'foreign_testing_org',$2,'Foreign testing organization')").bind(foreign_org).bind(Id::fixture("test_carbon")).execute(&mut *setup).await?;
    sqlx::query("INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES($1,$2,$3,'carbon','owner')").bind(foreign_member).bind(foreign_org).bind(Id::fixture("test_carbon")).execute(&mut *setup).await?;
    sqlx::query("UPDATE iam.oauth_consent_grants SET selected_membership_ids=array_append(selected_membership_ids,$1) WHERE id=$2").bind(foreign_member).bind(Id::from_u128(0x71)).execute(&mut *setup).await?;
    setup.commit().await?;
    // A real user-owned environment plus its key does not make an attached app owner.
    let other = Id::now_v7();
    let create = json!({"operation_id":Id::now_v7(),"environment_id":other,"expected_iam_revision":0,"generation":1,"operation":"prepare","org_id":"foreign_testing_org","name":"User-owned shared test","testing_key":"Y".repeat(32),"key_version":1});
    let other_endpoint = format!("/api/v1/honeycomb/testing-environments/{other}/operations");
    let other_record = send(
        app,
        credential,
        None,
        Some(actor),
        "POST",
        &other_endpoint,
        &create,
    )
    .await?;
    let attach = json!({"operation_id":Id::now_v7(),"environment_id":other,"expected_iam_revision":other_record["iam_revision"],"generation":1,"operation":"import","app_id":"test_org>testing-driver","source_revisions":{"test_org>testing-driver":production["iam_revision"]}});
    let attached = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&other_endpoint)
                .header("authorization", format!("Bearer {credential}"))
                .header("x-honeycomb-application-authorization", &authorization)
                .header("x-honeycomb-testing-key", "Y".repeat(32))
                .header(
                    "idempotency-key",
                    attach["operation_id"].as_str().unwrap_or_default(),
                )
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&attach)?))?,
        )
        .await?;
    let status = attached.status();
    let attached: Value =
        serde_json::from_slice(&to_bytes(attached.into_body(), 1024 * 1024).await?)?;
    ensure!(
        status == StatusCode::OK,
        "app attachment failed: {status} {attached}"
    );
    ensure!(
        attached["app_id"] == "test_org>testing-driver" && attached["app_secret"].is_string(),
        "attachment must return only caller's test credential"
    );
    let recovery = json!({"operation_id":Id::now_v7(),"environment_id":other,"generation":1,"key_version":1,"expected_environment_revision":attached["iam_revision"]});
    let recovery_path = format!(
        "/api/v1/honeycomb/testing-environments/{other}/applications/test_org%3Etesting-driver/credential-recovery"
    );
    let recover_request = |value: &Value| -> anyhow::Result<Request<Body>> {
        Ok(Request::builder()
            .method("POST")
            .uri(&recovery_path)
            .header("authorization", format!("Bearer {credential}"))
            .header("x-honeycomb-application-authorization", &authorization)
            .header("x-honeycomb-testing-key", "Y".repeat(32))
            .header(
                "idempotency-key",
                value["operation_id"].as_str().unwrap_or_default(),
            )
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(value)?))?)
    };
    let recovered = app.clone().oneshot(recover_request(&recovery)?).await?;
    let status = recovered.status();
    let recovered: Value =
        serde_json::from_slice(&to_bytes(recovered.into_body(), 1024 * 1024).await?)?;
    ensure!(
        status == StatusCode::OK && recovered["app_secret"] == attached["app_secret"],
        "protected own-app credential recovery failed: {status}"
    );
    let replay = app.clone().oneshot(recover_request(&recovery)?).await?;
    let replay: Value = serde_json::from_slice(&to_bytes(replay.into_body(), 1024 * 1024).await?)?;
    ensure!(replay == recovered, "recovery replay changed credential");
    sqlx::query("UPDATE iam.testing_application_imports SET source_application_id=$1 WHERE testing_environment_id=$2 AND application_id=$3").bind(Id::now_v7()).bind(other).bind(serde_json::from_value::<Id>(recovered["application_id"].clone())?).execute(test_admin).await?;
    let mut wrong_source = recovery.clone();
    wrong_source["operation_id"] = json!(Id::now_v7());
    let denied = app.clone().oneshot(recover_request(&wrong_source)?).await?;
    ensure!(
        denied.status() == StatusCode::FORBIDDEN,
        "same public handle inherited a predecessor's test credential"
    );
    sqlx::query("UPDATE iam.testing_application_imports SET source_application_id=$1 WHERE testing_environment_id=$2 AND application_id=$3").bind(production_app).bind(other).bind(serde_json::from_value::<Id>(recovered["application_id"].clone())?).execute(test_admin).await?;
    let other_owner: Option<Id> = sqlx::query_scalar(
        "SELECT created_by_application_id FROM iam.testing_environments WHERE id=$1",
    )
    .bind(other)
    .fetch_one(admin)
    .await?;
    ensure!(
        other_owner.is_none(),
        "attachment changed user-owned environment ownership"
    );
    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/honeycomb/testing-environments?status=all")
                .header("authorization", format!("Bearer {credential}"))
                .header("x-honeycomb-application-authorization", &authorization)
                .body(Body::empty())?,
        )
        .await?;
    let status = list.status();
    let list: Value = serde_json::from_slice(&to_bytes(list.into_body(), 1024 * 1024).await?)?;
    ensure!(status == StatusCode::OK, "app-owned list failed: {list}");
    let items = list["items"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("environment list items missing"))?;
    ensure!(
        items.len() == 2
            && items
                .iter()
                .any(|item| item["environment_id"] == environment.to_string()
                    && item["can_manage"] == true)
            && items
                .iter()
                .any(|item| item["environment_id"] == other.to_string()
                    && item["can_manage"] == false),
        "owned/attached list must preserve authority and omit unrelated environments"
    );
    ensure!(
        items
            .iter()
            .all(|item| item.get("key").is_none() && item.get("app_secret").is_none()),
        "list leaked reusable credentials"
    );
    let clean = json!({"operation_id":Id::now_v7(),"environment_id":other,"expected_iam_revision":attached["iam_revision"],"generation":1,"operation":"clean"});
    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&other_endpoint)
                .header("authorization", format!("Bearer {credential}"))
                .header("x-honeycomb-application-authorization", &authorization)
                .header("x-honeycomb-testing-key", "Y".repeat(32))
                .header(
                    "idempotency-key",
                    clean["operation_id"].as_str().unwrap_or_default(),
                )
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&clean)?))?,
        )
        .await?;
    ensure!(
        denied.status() == StatusCode::FORBIDDEN,
        "shared root key elevated attached app to environment owner"
    );
    exercise_root(
        app,
        admin,
        test_admin,
        credential,
        actor,
        production["iam_revision"].clone(),
    )
    .await?;
    Ok(())
}

async fn exercise_root(
    app: &axum::Router,
    admin: &sqlx::PgPool,
    test_admin: &sqlx::PgPool,
    credential: &str,
    actor: &str,
    source_revision: Value,
) -> anyhow::Result<()> {
    let environment = Id::now_v7();
    let endpoint = format!("/api/v1/honeycomb/testing-environments/{environment}/operations");
    let create = json!({"operation_id":Id::now_v7(),"environment_id":environment,
        "expected_iam_revision":0,"generation":1,"operation":"prepare","org_id":"test_org",
        "name":"Root-key authority","testing_key":"J".repeat(32),"key_version":1});
    let prepared = send(
        app,
        credential,
        None,
        Some(actor),
        "POST",
        &endpoint,
        &create,
    )
    .await?;
    let mut import = json!({"operation_id":Id::now_v7(),"environment_id":environment,
        "expected_iam_revision":prepared["iam_revision"],"generation":1,"expected_key_version":1,
        "operation":"import","app_id":"test_org>testing-driver",
        "source_revisions":{"test_org>testing-driver":source_revision}});
    for key in [None, Some("X".repeat(32)), Some("J".repeat(32))] {
        let (status, _) = root_send(app, credential, key.as_deref(), &endpoint, &import).await?;
        ensure!(
            status == StatusCode::FORBIDDEN,
            "missing/wrong root or root-only private production import accepted: {status}"
        );
    }
    let mut missing_version = import.clone();
    missing_version
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("instruction"))?
        .remove("expected_key_version");
    let (status, _) = root_send(
        app,
        credential,
        Some(&"J".repeat(32)),
        &endpoint,
        &missing_version,
    )
    .await?;
    ensure!(
        status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::BAD_REQUEST,
        "root authority accepted missing key version: {status}"
    );
    for (field, value) in [
        ("generation", json!(2)),
        ("expected_key_version", json!(2)),
        ("expected_iam_revision", json!(999)),
    ] {
        let mut invalid = import.clone();
        invalid[field] = value;
        let (status, _) =
            root_send(app, credential, Some(&"J".repeat(32)), &endpoint, &invalid).await?;
        ensure!(
            !status.is_success(),
            "root authority accepted stale {field}"
        );
    }
    // Publication is fixture setup; root authority itself never changes visibility.
    sqlx::query(
        "UPDATE iam.applications SET visibility='public' WHERE app_id='test_org>testing-driver'",
    )
    .execute(admin)
    .await?;
    let published_revision: i64 = sqlx::query_scalar(
        "SELECT version FROM iam.applications WHERE app_id='test_org>testing-driver'",
    )
    .fetch_one(admin)
    .await?;
    import["source_revisions"]["test_org>testing-driver"] = json!(published_revision);
    let (status, imported) =
        root_send(app, credential, Some(&"J".repeat(32)), &endpoint, &import).await?;
    ensure!(
        status == StatusCode::OK && imported["app_secret"].is_string(),
        "public root-only import failed: {status} {imported}"
    );
    let (_, replay) = root_send(app, credential, Some(&"J".repeat(32)), &endpoint, &import).await?;
    ensure!(replay == imported, "root import replay changed result");
    let owner: Option<Id> = sqlx::query_scalar(
        "SELECT created_by_application_id FROM iam.testing_environments WHERE id=$1",
    )
    .bind(environment)
    .fetch_one(admin)
    .await?;
    ensure!(
        owner.is_none(),
        "root authority fabricated application ownership"
    );
    let activate = json!({"operation_id":Id::now_v7(),"environment_id":environment,
        "expected_iam_revision":imported["iam_revision"],"generation":1,"operation":"activate"});
    let activated = send(
        app,
        credential,
        None,
        Some(actor),
        "POST",
        &endpoint,
        &activate,
    )
    .await?;
    let rotate = json!({"operation_id":Id::now_v7(),"environment_id":environment,
        "expected_iam_revision":activated["iam_revision"],"generation":1,"expected_key_version":1,
        "operation":"rotate-key","testing_key":"K".repeat(32),"key_version":2});
    let (status, rotated) =
        root_send(app, credential, Some(&"J".repeat(32)), &endpoint, &rotate).await?;
    ensure!(
        status == StatusCode::OK
            && rotated["key"] == "K".repeat(32)
            && rotated["environment"]["state"] == "prepared",
        "root rotation failed to leave environment pending coordinator: {status} {rotated}"
    );
    let (_, replay) = root_send(app, credential, Some(&"J".repeat(32)), &endpoint, &rotate).await?;
    ensure!(
        replay == rotated,
        "rotation lost exact operation replay for previous root"
    );
    let ready: bool = sqlx::query_scalar(
        "SELECT active FROM iam_private.testing_runtime_state WHERE environment_id=$1",
    )
    .bind(environment)
    .fetch_one(test_admin)
    .await?;
    ensure!(
        !ready,
        "root rotation left IAM runtime active before coordinator readiness"
    );
    let mut retry_import = import.clone();
    retry_import["operation_id"] = json!(Id::now_v7());
    retry_import["expected_iam_revision"] = rotated["iam_revision"].clone();
    retry_import["expected_key_version"] = json!(2);
    let (status, _) = root_send(
        app,
        credential,
        Some(&"J".repeat(32)),
        &endpoint,
        &retry_import,
    )
    .await?;
    ensure!(
        status == StatusCode::FORBIDDEN,
        "retired root authorized a new operation"
    );
    let (status, reimported) = root_send(
        app,
        credential,
        Some(&"K".repeat(32)),
        &endpoint,
        &retry_import,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && reimported["app_secret"] == imported["app_secret"],
        "new root did not preserve linked app credential: {status} {reimported}"
    );
    exercise_root_app_management(
        app,
        admin,
        credential,
        environment,
        &reimported["iam_revision"],
    )
    .await?;
    let clean = json!({"operation":"clean","operation_id":Id::now_v7(),
        "environment_id":environment,"generation":1,"expected_key_version":2,
        "expected_iam_revision":reimported["iam_revision"]});
    for (field, value) in [
        ("generation", json!(2)),
        ("expected_key_version", json!(1)),
        ("expected_iam_revision", json!(999)),
    ] {
        let mut stale = clean.clone();
        stale[field] = value;
        let (status, _) =
            root_send(app, credential, Some(&"K".repeat(32)), &endpoint, &stale).await?;
        ensure!(!status.is_success(), "root clean accepted stale {field}");
    }
    let (status, _) = root_send(app, credential, Some(&"J".repeat(32)), &endpoint, &clean).await?;
    ensure!(
        status == StatusCode::FORBIDDEN,
        "retired key authorized clean"
    );
    let sibling_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam.applications WHERE testing_environment_id<>$1",
    )
    .bind(environment)
    .fetch_one(test_admin)
    .await?;
    let (status, cleaned) =
        root_send(app, credential, Some(&"K".repeat(32)), &endpoint, &clean).await?;
    ensure!(
        status == StatusCode::OK
            && cleaned["environment"]["state"] == "cleaned"
            && cleaned["environment"]["generation"] == 2
            && cleaned["environment"]["key_version"] == 2,
        "root clean failed: {status} {cleaned}"
    );
    let (_, replay) = root_send(app, credential, Some(&"K".repeat(32)), &endpoint, &clean).await?;
    ensure!(
        replay == cleaned,
        "root clean replay changed result or generation"
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM iam.applications WHERE testing_environment_id=$1")
            .bind(environment)
            .fetch_one(test_admin)
            .await?;
    ensure!(rows == 0, "clean retained isolated test app data");
    let siblings: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam.applications WHERE testing_environment_id<>$1",
    )
    .bind(environment)
    .fetch_one(test_admin)
    .await?;
    ensure!(
        siblings == sibling_count,
        "root clean erased sibling environment data"
    );
    let mut activate = clean.clone();
    activate["operation"] = json!("activate");
    activate["operation_id"] = json!(Id::now_v7());
    activate["generation"] = json!(2);
    activate["expected_iam_revision"] = cleaned["iam_revision"].clone();
    let (status, _) =
        root_send(app, credential, Some(&"K".repeat(32)), &endpoint, &activate).await?;
    ensure!(
        status == StatusCode::FORBIDDEN,
        "root bypassed coordinated participant activation"
    );
    sqlx::query(
        "UPDATE iam.applications SET visibility='private' WHERE app_id='test_org>testing-driver'",
    )
    .execute(admin)
    .await?;
    Ok(())
}

async fn exercise_root_app_management(
    app: &axum::Router,
    admin: &sqlx::PgPool,
    credential: &str,
    environment: Id,
    revision: &Value,
) -> anyhow::Result<()> {
    let endpoint = format!(
        "/api/v1/honeycomb/testing-environments/{environment}/applications/test_org%3Eroot-only/configuration"
    );
    let config = json!({"org_id":"test_org","name":"Root test app","logo_url":null,"base_url":null,"visibility":"private","availability":"active","webhook":{"url":"https://root-test.example.test/webhook","secret":"z".repeat(48),"scope":["membership"]},"app_scope":{"iam":["self.identity.read"],"external":[]},"obo_endpoints":[]});
    let mut body = json!({"operation_id":Id::now_v7(),"environment_id":environment,"generation":1,"key_version":2,"expected_environment_revision":revision,"expected_iam_revision":0,"configuration_revision":1,"configuration":config});
    for key in [None, Some("J".repeat(32)), Some("Z".repeat(32))] {
        let (status, _) =
            root_method(app, credential, key.as_deref(), "PUT", &endpoint, &body).await?;
        ensure!(
            !status.is_success(),
            "test app accepted absent/retired/wrong root"
        );
    }
    for (field, value) in [
        ("generation", json!(2)),
        ("key_version", json!(1)),
        ("expected_environment_revision", json!(999)),
    ] {
        let mut stale = body.clone();
        stale[field] = value;
        let (status, _) = root_method(
            app,
            credential,
            Some(&"K".repeat(32)),
            "PUT",
            &endpoint,
            &stale,
        )
        .await?;
        ensure!(!status.is_success(), "test app accepted stale {field}");
    }
    let collision = endpoint.replace("root-only", "testing-driver");
    let (status, _) = root_method(
        app,
        credential,
        Some(&"K".repeat(32)),
        "PUT",
        &collision,
        &body,
    )
    .await?;
    ensure!(
        status == StatusCode::CONFLICT,
        "test-only registration claimed production app ID"
    );
    let (status, created) = root_method(
        app,
        credential,
        Some(&"K".repeat(32)),
        "PUT",
        &endpoint,
        &body,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && created["app_secret"].is_string(),
        "root app creation failed: {status} {created}"
    );
    let (_, replayed) = root_method(
        app,
        credential,
        Some(&"K".repeat(32)),
        "PUT",
        &endpoint,
        &body,
    )
    .await?;
    ensure!(
        created == replayed,
        "root app creation replay changed credentials"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam.applications WHERE app_id='test_org>root-only'",
    )
    .fetch_one(admin)
    .await?;
    ensure!(count == 0, "root test app leaked to production");
    body["operation_id"] = json!(Id::now_v7());
    body["expected_iam_revision"] = created["iam_revision"].clone();
    body["configuration_revision"] = json!(2);
    body["configuration"]["name"] = json!("Root app edited");
    let (status, updated) = root_method(
        app,
        credential,
        Some(&"K".repeat(32)),
        "PUT",
        &endpoint,
        &body,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "root update failed: {status} {updated}"
    );
    body["operation_id"] = json!(Id::now_v7());
    body["expected_iam_revision"] = updated["iam_revision"].clone();
    body.as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("mutation"))?
        .remove("configuration");
    let rotate = endpoint.replace("/configuration", "/secret-rotations");
    let (status, rotated) = root_method(
        app,
        credential,
        Some(&"K".repeat(32)),
        "POST",
        &rotate,
        &body,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && rotated["app_secret"].is_string()
            && rotated["app_secret"] != created["app_secret"],
        "root app rotation failed: {status} {rotated}"
    );
    let (_, replay) = root_method(
        app,
        credential,
        Some(&"K".repeat(32)),
        "POST",
        &rotate,
        &body,
    )
    .await?;
    ensure!(replay == rotated, "root app secret rotated twice on replay");
    Ok(())
}

async fn root_send(
    app: &axum::Router,
    credential: &str,
    key: Option<&str>,
    path: &str,
    value: &Value,
) -> anyhow::Result<(StatusCode, Value)> {
    root_method(app, credential, key, "POST", path, value).await
}

async fn root_method(
    app: &axum::Router,
    credential: &str,
    key: Option<&str>,
    method: &str,
    path: &str,
    value: &Value,
) -> anyhow::Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {credential}"))
        .header(
            "idempotency-key",
            value["operation_id"].as_str().unwrap_or_default(),
        )
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("x-honeycomb-testing-key", key);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(serde_json::to_vec(value)?))?)
        .await?;
    let status = response.status();
    let value = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
    Ok((status, value))
}
async fn send(
    app: &axum::Router,
    credential: &str,
    client: Option<&str>,
    actor: Option<&str>,
    method: &str,
    path: &str,
    value: &Value,
) -> anyhow::Result<Value> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {credential}"))
        .header(
            "idempotency-key",
            value["operation_id"].as_str().unwrap_or_default(),
        )
        .header("content-type", "application/json");
    if let Some(client) = client {
        request = request.header("x-honeycomb-application-authorization", client);
    }
    if let Some(actor) = actor {
        request = request.header("x-honeycomb-actor-token", actor);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(serde_json::to_vec(value)?))?)
        .await?;
    let status = response.status();
    let value: Value = serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
    ensure!(
        status == StatusCode::OK,
        "{method} {path}: {status} {value}"
    );
    Ok(value)
}
