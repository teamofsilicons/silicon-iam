//! Real-database checks for the new first-version application permission contract.
use anyhow::{Context as _, ensure};
use serde_json::{Value, json};
use sqlx::{postgres::PgPoolOptions, types::Json};
use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use uuid::Uuid;

#[allow(
    clippy::too_many_lines,
    reason = "one transaction exercises the entire review lifecycle under the runtime role"
)]
#[tokio::test]
#[ignore = "requires a local Docker daemon"]
async fn critical_scope_reviews_preserve_previous_authority_and_require_target_approval()
-> anyhow::Result<()> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            container.get_host().await?,
            container.get_host_port_ipv4(5432).await?
        ))
        .await?;
    crate::infrastructure::postgres::migrate(&pool).await?;
    super::live_tests::seed_protocol_rows(&pool).await?;
    sqlx::raw_sql("CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN;").execute(&pool).await?;
    let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n");
    sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
        .execute(&pool)
        .await
        .context("restricted runtime grants")?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/application_webhook_scopes.sql"
    ))
    .execute(&pool)
    .await
    .context("webhook scope boundaries")?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/account_onboarding_login.sql"
    ))
    .execute(&pool)
    .await
    .context("zero-organization Carbon onboarding and membership isolation")?;
    sqlx::raw_sql(include_str!(
        "../../../tests/sql/unscoped_membership_disclosure.sql"
    ))
    .execute(&pool)
    .await
    .context("unscoped membership disclosure and renewed consent")?;
    let app = Uuid::from_u128(0x11);
    let target = Uuid::from_u128(0x12);
    let actor = Uuid::from_u128(1);
    let org = Uuid::from_u128(0x21);
    sqlx::query("INSERT INTO iam.application_obo_endpoints(organization_id,application_id,endpoint_id,path,metadata_definition,critical) VALUES($1,$2,'files.read','/files','{}',true),($1,$2,'files.list','/files/list','{}',false)").bind(org).bind(target).execute(&pool).await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE silicon_iam_api")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('iam.principal_id',$1,true),set_config('iam.organization_id',$2,true),set_config('iam.application_id',$3,true)").bind(actor.to_string()).bind(org.to_string()).bind(app.to_string()).execute(&mut *tx).await?;
    let scope = json!({"iam":["self.identity.read","self.profile.read"],"external":[{"app_id":"test_org>app-beta","endpoint_id":"files.read"},{"app_id":"test_org>app-beta","endpoint_id":"files.list"}]});
    sqlx::query("SELECT iam_private.configure_application_scopes($1,$2,$3)")
        .bind(app)
        .bind(Json(&scope))
        .bind(actor)
        .execute(&mut *tx)
        .await
        .context("configure explicitly declared scopes")?;
    let active=sqlx::query_scalar::<_,String>("SELECT scope FROM iam.application_approved_scopes WHERE application_id=$1 AND revoked_at IS NULL ORDER BY scope").bind(app).fetch_all(&mut *tx).await?;
    ensure!(
        active
            == vec![
                "obo:test_org>app-beta:files.list",
                "self.identity.read",
                "self.profile.read"
            ],
        "an unreviewed external critical endpoint acquired authority"
    );
    let status =
        sqlx::query_scalar::<_, String>("SELECT review_status FROM iam.applications WHERE id=$1")
            .bind(app)
            .fetch_one(&mut *tx)
            .await?;
    ensure!(
        status == "verified",
        "an upgrade disabled the previous active version"
    );
    let ids = sqlx::query_scalar::<_, Vec<Uuid>>(
        "SELECT iam_private.submit_application_scope_requests($1,$2,$3)",
    )
    .bind(app)
    .bind(actor)
    .bind("Read files to organize the user's project.")
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
        ids.len() == 1,
        "one target application should produce one request"
    );
    let request = ids[0];
    let detail = sqlx::query_scalar::<_, Json<Value>>(
        "SELECT iam_private.application_scope_request_view($1)",
    )
    .bind(request)
    .fetch_one(&mut *tx)
    .await?
    .0;
    ensure!(
        detail["messages"].as_array().context("messages")?.len() == 2,
        "initial instructions and request message missing"
    );
    ensure!(detail["target_app_id"] == "test_org>app-beta");
    let context = detail["current_scope_context"]
        .as_array()
        .context("scope context")?;
    ensure!(
        context.len() == 2,
        "review context must include non-critical scopes but exclude IAM scopes"
    );
    ensure!(context[0]["scope"] == "obo:test_org>app-beta:files.list");
    ensure!(context[0]["critical"] == false && context[0]["in_review"] == false);
    ensure!(context[1]["in_review"] == true);
    let messages = detail["messages"].as_array().context("messages")?;
    ensure!(
        messages
            .iter()
            .any(|message| message["author"]["type"] == "system" && message["is_own"] == false)
    );
    ensure!(
        messages
            .iter()
            .any(|message| message["author"]["type"] == "carbon" && message["is_own"] == true)
    );
    let version = detail["version"].as_i64().context("version")?;
    let approved=sqlx::query_scalar::<_,Json<Value>>("SELECT iam_private.mutate_application_scope_request($1,$2,$3,'approve','Approved for project organization.')").bind(request).bind(actor).bind(version).fetch_one(&mut *tx).await?.0;
    ensure!(approved["status"] == "approved");
    let policy = sqlx::query_scalar::<_, Json<Value>>(
        "SELECT iam_private.application_login_scope_policy($1)",
    )
    .bind(app)
    .fetch_one(&mut *tx)
    .await?
    .0;
    ensure!(policy["consent_required"] == true);
    ensure!(policy["scopes"].as_array().context("scope policy")?.len() == 4);
    let version = approved["version"].as_i64().context("approved version")?;
    let reply=sqlx::query_scalar::<_,Json<Value>>("SELECT iam_private.mutate_application_scope_request($1,$2,$3,'message','Thank you; implementation is ready.')").bind(request).bind(actor).bind(version).fetch_one(&mut *tx).await?.0;
    ensure!(
        reply["status"] == "approved",
        "discussion must not rewrite a decision"
    );
    let minimal = json!({"iam":["self.identity.read"],"external":[]});
    sqlx::query("SELECT iam_private.configure_application_scopes($1,$2,$3)")
        .bind(app)
        .bind(Json(&minimal))
        .bind(actor)
        .execute(&mut *tx)
        .await?;
    let active=sqlx::query_scalar::<_,String>("SELECT scope FROM iam.application_approved_scopes WHERE application_id=$1 AND revoked_at IS NULL ORDER BY scope").bind(app).fetch_all(&mut *tx).await?;
    ensure!(
        active == vec!["self.identity.read"],
        "permission removal must be immediate"
    );
    tx.commit().await?;
    let notifications = sqlx::query_as::<_, (Uuid, i64)>(
        "SELECT c.carbon_id, count(*) FROM iam.notification_jobs j \
         JOIN iam.carbon_contacts c ON c.id=j.recipient_contact_id \
         JOIN iam.application_scope_messages m ON m.id=j.context_id \
         WHERE j.notification_kind='application_scope_review' AND m.request_id=$1 \
         AND c.kind='email' GROUP BY c.carbon_id ORDER BY c.carbon_id",
    )
    .bind(request)
    .fetch_all(&pool)
    .await?;
    ensure!(
        notifications == vec![(actor, 3), (Uuid::from_u128(2), 3)],
        "submission, decision, and reply must each email the owner and admin once, even when both apps share an organization"
    );
    Ok(())
}
