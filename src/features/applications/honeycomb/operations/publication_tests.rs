//! Full immutable review and activation through HTTP under the runtime DB role.
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
    credential: &str,
    actor: &str,
    private: &Value,
) -> anyhow::Result<()> {
    let crypto = crate::infrastructure::crypto::CryptoService::from_settings(
        &crate::config::Settings::from_env()?.security,
    )?;
    for (id, address) in [
        (Id::from_u128(2), "owner@example.test"),
        (Id::from_u128(4), "admin@example.test"),
    ] {
        let encrypted = crypto.encrypt(
            crate::infrastructure::crypto::EncryptionContext::global(
                crate::infrastructure::crypto::ProtectedField::CarbonEmail,
                id,
            ),
            address.as_bytes(),
        )?;
        sqlx::query("UPDATE iam.carbon_contacts SET ciphertext=$2,nonce=$3,encryption_key_version=$4 WHERE id=$1")
            .bind(id).bind(encrypted.ciphertext).bind(encrypted.nonce.as_slice()).bind(encrypted.key_version).execute(admin).await?;
    }
    let name = "managed-app";
    let prefix = "/api/v1/honeycomb/applications/test_org%3Emanaged-app";
    let revision: i64 = sqlx::query_scalar("SELECT version FROM iam.applications WHERE app_id=$1")
        .bind(name)
        .fetch_one(admin)
        .await?;
    let mut desired = private.clone();
    desired["operation_id"] = json!(Id::now_v7());
    desired["configuration_revision"] = json!(2);
    desired["expected_iam_revision"] = json!(revision);
    desired["visibility"] = json!("public");
    desired["app_scope"]["iam"] = json!([
        "self.identity.read",
        "directory.carbons.read",
        "directory.silicons.read"
    ]);
    desired["publication_approved"] = json!(true);
    desired["webhook"]["secret"] = json!("b".repeat(48));
    let request = |path: &str, method: &str, body: &Value| -> anyhow::Result<Request<Body>> {
        Ok(Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {credential}"))
            .header("x-honeycomb-actor-token", actor)
            .header("content-type", "application/json")
            .header(
                "idempotency-key",
                body["operation_id"]
                    .as_str()
                    .or_else(|| body["request_id"].as_str())
                    .unwrap_or("publication-read"),
            )
            .body(Body::from(serde_json::to_vec(body)?))?)
    };
    let read_response =
        async |response: axum::response::Response| -> anyhow::Result<(StatusCode, Value)> {
            let status = response.status();
            let value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
            Ok((status, value))
        };
    let (status, pending) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/configuration"),
                "PUT",
                &desired,
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && pending["state"] == "pending"
            && pending["effective_configuration"]["visibility"] == "private",
        "boolean bypass: {pending}"
    );
    let pending_operation = desired["operation_id"].clone();
    let current: i64 = sqlx::query_scalar("SELECT version FROM iam.applications WHERE app_id=$1")
        .bind(name)
        .fetch_one(admin)
        .await?;
    ensure!(
        current == revision,
        "pending proposal mutated accepted application"
    );
    let plan_request = json!({"request_id":Id::now_v7(),"app_id":name,"configuration_revision":2,"configuration":desired,"visibility":"public"});
    let (status, plan) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-plans"),
                "POST",
                &plan_request,
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && plan["gates"]
                == json!([{"provider":"iam","scopes":["directory.carbons.read","directory.silicons.read"]},{"provider":"honeycomb","scopes":[]}]),
        "plan mismatch: {plan}"
    );
    let (_, replay) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-plans"),
                "POST",
                &plan_request,
            )?)
            .await?,
    )
    .await?;
    ensure!(replay == plan, "plan retry changed identity");
    let mut changed = plan_request.clone();
    changed["configuration"]["name"] = json!("Altered");
    let response = app
        .clone()
        .oneshot(request(
            &format!("{prefix}/publication-plans"),
            "POST",
            &changed,
        )?)
        .await?;
    ensure!(
        response.status() == StatusCode::CONFLICT,
        "request identity reused for another configuration"
    );
    let plan_id = plan["plan_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing receipt string"))?;
    let eligibility_path = format!(
        "/api/v1/honeycomb/publication-plans/{plan_id}/reviewer-eligibility?provider=honeycomb"
    );
    let (_, eligibility) = read_response(
        app.clone()
            .oneshot(request(&eligibility_path, "GET", &json!({}))?)
            .await?,
    )
    .await?;
    ensure!(
        eligibility["eligible"] == false,
        "ordinary org owner became a Honeycomb validator"
    );
    let mut decision = json!({"operation_id":Id::now_v7(),"request_id":plan["request_id"],"plan_id":plan["plan_id"],"app_id":name,"configuration_revision":2,"provider":"honeycomb","scopes":[],"decision":"approve","reason":"Reviewed exact configuration"});
    ensure!(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-decisions"),
                "POST",
                &decision
            )?)
            .await?
            .status()
            == StatusCode::FORBIDDEN,
        "owner approved validator gate"
    );
    let reviewer = Id::fixture("c:test_carbon");
    let validator_grant = Id::now_v7();
    sqlx::query("INSERT INTO iam.platform_role_grants(id,carbon_id,role,grant_source) VALUES($1,$3,'application_reviewer','bootstrap'),($2,$3,'honeycomb_validator','bootstrap')")
        .bind(Id::now_v7()).bind(validator_grant).bind(reviewer).execute(admin).await?;
    let (status, validator) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-decisions"),
                "POST",
                &decision,
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "validator decision failed: {validator}"
    );
    decision["operation_id"] = json!(Id::now_v7());
    decision["provider"] = json!("iam");
    decision["scopes"] = json!(["self.identity.read"]);
    ensure!(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-decisions"),
                "POST",
                &decision
            )?)
            .await?
            .status()
            == StatusCode::UNPROCESSABLE_ENTITY,
        "gate accepted wrong scopes"
    );
    decision["scopes"] = json!(["directory.carbons.read", "directory.silicons.read"]);
    let (status, iam) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-decisions"),
                "POST",
                &decision,
            )?)
            .await?,
    )
    .await?;
    ensure!(status == StatusCode::OK, "IAM review failed: {iam}");
    let mut activation = json!({"operation_id":Id::now_v7(),"request_id":plan["request_id"],"plan_id":plan["plan_id"],"app_id":name,"configuration_revision":2,"expected_iam_revision":revision,"configuration":desired,"visibility":"public","decision_ids":[validator["decision_id"],iam["decision_id"]],"configuration_operations":[pending_operation]});
    activation["configuration"]["name"] = json!("Unreviewed change");
    ensure!(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-activations"),
                "POST",
                &activation
            )?)
            .await?
            .status()
            == StatusCode::CONFLICT,
        "activation accepted changed config"
    );
    activation["configuration"] = desired.clone();
    sqlx::query("UPDATE iam.platform_role_grants SET revoked_at=clock_timestamp(),revoked_by_carbon_id=$2 WHERE id=$1").bind(validator_grant).bind(reviewer).execute(admin).await?;
    ensure!(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-activations"),
                "POST",
                &activation
            )?)
            .await?
            .status()
            == StatusCode::FORBIDDEN,
        "activation accepted revoked reviewer"
    );
    sqlx::query("INSERT INTO iam.platform_role_grants(id,carbon_id,role,grant_source) VALUES($1,$2,'honeycomb_validator','bootstrap')").bind(Id::now_v7()).bind(reviewer).execute(admin).await?;
    // A later denial prevents choosing an older approved decision.
    decision["operation_id"] = json!(Id::now_v7());
    decision["decision"] = json!("deny");
    let (status, denied) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-decisions"),
                "POST",
                &decision,
            )?)
            .await?,
    )
    .await?;
    ensure!(status == StatusCode::OK, "denial failed: {denied}");
    ensure!(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-activations"),
                "POST",
                &activation
            )?)
            .await?
            .status()
            == StatusCode::FORBIDDEN,
        "activation cherry-picked superseded approval"
    );
    decision["operation_id"] = json!(Id::now_v7());
    decision["decision"] = json!("approve");
    let (_, iam) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-decisions"),
                "POST",
                &decision,
            )?)
            .await?,
    )
    .await?;
    activation["decision_ids"] = json!([validator["decision_id"], iam["decision_id"]]);
    let (status, accepted) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-activations"),
                "POST",
                &activation,
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && accepted["state"] == "accepted"
            && accepted["effective_configuration"]["publication_request_id"] == plan["request_id"]
            && accepted["iam_revision"]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("missing receipt revision"))?
                > revision,
        "activation failed: {accepted}"
    );
    let (_, replay) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-activations"),
                "POST",
                &activation,
            )?)
            .await?,
    )
    .await?;
    ensure!(accepted == replay, "activation replay changed result");
    let (_, pending_result) = read_response(
        app.clone()
            .oneshot(request(
                &format!(
                    "/api/v1/honeycomb/operations/{}",
                    pending_operation
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing receipt string"))?
                ),
                "GET",
                &json!({}),
            )?)
            .await?,
    )
    .await?;
    ensure!(
        pending_result["state"] == "accepted"
            && pending_result["result"]["request_id"] == plan["request_id"],
        "pending configuration not completed: {pending_result}"
    );
    let immutable = sqlx::query(
        "UPDATE iam.honeycomb_publication_decisions SET decision='deny' WHERE decision_id=$1",
    )
    .bind(Id::parse_str(
        iam["decision_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing receipt string"))?,
    )?)
    .execute(admin)
    .await;
    ensure!(immutable.is_err(), "decision history mutable");
    let (_,recipients)=read_response(app.clone().oneshot(request(&format!("/api/v1/honeycomb/publication-plans/{plan_id}/notification-recipients?provider=owners"),"GET",&json!({}))?).await?).await?;
    ensure!(
        recipients["recipients"].as_array().is_some(),
        "recipient discovery failed: {recipients}"
    );
    ensure!(app.clone().oneshot(request(&format!("/api/v1/honeycomb/publication-plans/{plan_id}/notification-recipients?provider=unrelated%3Eapp"),"GET",&json!({}))?).await?.status()==StatusCode::UNPROCESSABLE_ENTITY,"unrelated recipient directory exposed");
    let mut next_desired = desired.clone();
    next_desired["configuration_revision"] = json!(3);
    next_desired["name"] = json!("Updated public name");
    let next_request = json!({"request_id":Id::now_v7(),"app_id":name,"configuration_revision":3,"configuration":next_desired,"visibility":"public"});
    let (status, next_plan) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-plans"),
                "POST",
                &next_request,
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && next_plan["gates"] == json!([{"provider":"honeycomb","scopes":[]}])
            && next_plan["reused_approvals"]
                .as_array()
                .is_some_and(|evidence| evidence.len() == 2),
        "existing exact provider approval was not reused: {next_plan}"
    );
    let revoke = json!({"operation_id":Id::now_v7(),"expected_iam_revision":accepted["iam_revision"],"environment_id":null,"scopes":["directory.carbons.read"],"decision":"revoke"});
    let (status, revoked) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/scope-decisions"),
                "POST",
                &revoke,
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "scope revocation failed: {revoked}"
    );
    let next_decision = json!({"operation_id":Id::now_v7(),"request_id":next_plan["request_id"],"plan_id":next_plan["plan_id"],"app_id":name,"configuration_revision":3,"provider":"honeycomb","scopes":[],"decision":"approve","reason":"reviewed"});
    ensure!(
        app.clone()
            .oneshot(request(
                &format!("{prefix}/publication-decisions"),
                "POST",
                &next_decision
            )?)
            .await?
            .status()
            == StatusCode::CONFLICT,
        "revoked approval reused by publication plan"
    );
    let (status, record) = read_response(
        app.clone()
            .oneshot(request(prefix, "GET", &json!({}))?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && record["publication_request_id"].is_null(),
        "revoked publication still reconciles as accepted: {record}"
    );
    // A saved private config publishes at the same desired revision. Only IAM's
    // acceptance revision advances; changing content at that revision is forbidden.
    let saved_name = "saved-publication";
    let saved_prefix = "/api/v1/honeycomb/applications/test_org%3Esaved-publication";
    let mut saved = private.clone();
    saved["app_id"] = json!(saved_name);
    saved["operation_id"] = json!(Id::now_v7());
    saved["expected_iam_revision"] = json!(0);
    let (status, created) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{saved_prefix}/configuration"),
                "PUT",
                &saved,
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "saved private config creation failed: {created}"
    );
    saved["visibility"] = json!("public");
    let mut saved_request = json!({"request_id":Id::now_v7(),"app_id":saved_name,"configuration_revision":1,"configuration":saved,"visibility":"public"});
    saved_request["configuration"]["name"] = json!("Unaccepted edit");
    ensure!(
        app.clone()
            .oneshot(request(
                &format!("{saved_prefix}/publication-plans"),
                "POST",
                &saved_request
            )?)
            .await?
            .status()
            == StatusCode::CONFLICT,
        "same revision accepted modified config"
    );
    saved_request["configuration"] = saved.clone();
    let (status, saved_plan) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{saved_prefix}/publication-plans"),
                "POST",
                &saved_request,
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "same revision plan rejected: {saved_plan}"
    );
    let mut saved_decisions = Vec::new();
    for (provider, scopes) in [
        ("iam", json!(["directory.carbons.read"])),
        ("honeycomb", json!([])),
    ] {
        let decision = json!({"operation_id":Id::now_v7(),"request_id":saved_plan["request_id"],"plan_id":saved_plan["plan_id"],"app_id":saved_name,"configuration_revision":1,"provider":provider,"scopes":scopes,"decision":"approve","reason":"Reviewed saved config"});
        let (status, decision) = read_response(
            app.clone()
                .oneshot(request(
                    &format!("{saved_prefix}/publication-decisions"),
                    "POST",
                    &decision,
                )?)
                .await?,
        )
        .await?;
        ensure!(
            status == StatusCode::OK,
            "saved revision decision failed: {decision}"
        );
        saved_decisions.push(decision["decision_id"].clone());
    }
    let mut saved_activation = json!({"operation_id":Id::now_v7(),"request_id":saved_plan["request_id"],"plan_id":saved_plan["plan_id"],"app_id":saved_name,"configuration_revision":1,"expected_iam_revision":created["iam_revision"],"configuration":saved,"visibility":"public","decision_ids":saved_decisions});
    saved_activation["configuration"]["webhook"]["secret"] = json!("z".repeat(48));
    ensure!(
        app.clone()
            .oneshot(request(
                &format!("{saved_prefix}/publication-activations"),
                "POST",
                &saved_activation
            )?)
            .await?
            .status()
            == StatusCode::CONFLICT,
        "same revision activation changed signing secret"
    );
    saved_activation["configuration"] = saved;
    let (status, saved_accepted) = read_response(
        app.clone()
            .oneshot(request(
                &format!("{saved_prefix}/publication-activations"),
                "POST",
                &saved_activation,
            )?)
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK
            && saved_accepted["configuration_revision"] == 1
            && saved_accepted["visibility"] == "public"
            && saved_accepted["iam_revision"].as_i64() > created["iam_revision"].as_i64(),
        "same revision activation failed: {saved_accepted}"
    );
    let (_, owners) = read_response(
        app.clone()
            .oneshot(request(
                "/api/v1/honeycomb/organizations/test_org/notification-recipients?limit=1",
                "GET",
                &json!({}),
            )?)
            .await?,
    )
    .await?;
    ensure!(
        owners["recipients"]
            .as_array()
            .is_some_and(|page| page.len() == 1)
            && owners["next_cursor"].is_string(),
        "owner recipient first page failed: {owners}"
    );
    let after = owners["next_cursor"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("recipient cursor"))?;
    let (_,owners_next)=read_response(app.clone().oneshot(request(&format!("/api/v1/honeycomb/organizations/test_org/notification-recipients?limit=1&after={after}"),"GET",&json!({}))?).await?).await?;
    ensure!(
        owners_next["recipients"]
            .as_array()
            .is_some_and(|page| page.len() == 1)
            && owners_next["next_cursor"].is_null()
            && owners["recipients"][0]["carbon_id"] != owners_next["recipients"][0]["carbon_id"],
        "owner recipient pagination failed: {owners_next}"
    );
    Ok(())
}
