//! Signup contracts exercised with restricted runtime roles on both database planes.
#![allow(
    clippy::too_many_lines,
    clippy::large_futures,
    reason = "database journeys keep dependent setup, actions, and assertions in one readable sequence"
)]

use super::{http, idempotency::IdempotencyKey, model::SignupCompletionInput, signup, validation};
use crate::{
    api::ApiState,
    domain::id::Id,
    infrastructure::{
        crypto::CryptoService,
        postgres,
        providers::NotificationProviders,
        testing_plane::{self, SelectedEnvironment},
    },
};
use anyhow::{Context as _, ensure};
use axum::{
    Json,
    body::to_bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
};
use secrecy::SecretString;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt as _;

fn headers(key: &str) -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert("idempotency-key", HeaderValue::from_str(key)?);
    Ok(headers)
}
fn key(value: &str) -> anyhow::Result<IdempotencyKey> {
    Ok(IdempotencyKey::from_headers(&headers(value)?)?)
}
fn profile() -> SignupCompletionInput {
    SignupCompletionInput {
        carbon_id: None,
        display_name: None,
        timezone: Some("Asia/Kolkata".into()),
        profile_photo: None,
    }
}
async fn verified_email(state: &ApiState, email: &str, prefix: &str) -> anyhow::Result<Id> {
    let session = signup::create_session(state, &key(&format!("{prefix}-session-create"))?)
        .await?
        .value
        .session_id;
    let dispatch = signup::start_contact(
        state,
        &key(&format!("{prefix}-email-dispatch"))?,
        session,
        validation::email(email.into())?,
    )
    .await?
    .value;
    let code = dispatch
        .local_otp
        .context("local adapter must expose synthetic code")?;
    signup::verify_contact(
        state,
        &key(&format!("{prefix}-email-verify"))?,
        session,
        super::model::ContactChannel::Email,
        validation::verification_code(code)?,
    )
    .await?;
    Ok(session)
}
async fn complete(
    state: &ApiState,
    session: Id,
    prefix: &str,
) -> anyhow::Result<serde_json::Value> {
    let response = http::complete_signup(
        State(state.clone()),
        Path(session),
        headers(prefix)?,
        Ok(Json(profile())),
    )
    .await?;
    ensure!(response.status().is_success());
    ensure!(
        response.headers().get("set-cookie").is_some(),
        "signup establishes the browser session"
    );
    ensure!(
        response
            .headers()
            .get("cache-control")
            .is_some_and(|value| value == "no-store")
    );
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 1_048_576).await?,
    )?)
}

#[tokio::test]
#[ignore = "requires Docker or IAM_TEST_DATABASE_ADMIN_URL and synthetic IAM settings"]
async fn optional_phone_signup_authenticates_and_replays_in_both_planes() -> anyhow::Result<()> {
    for testing in [false, true] {
        let database = crate::test_database::TestDatabase::start().await?;
        let world = Id::from_u128(0x122);
        let pool = PgPoolOptions::new()
            .after_connect(move |connection, _| {
                Box::pin(async move {
                    if testing {
                        sqlx::query("SELECT set_config('iam.testing_environment_id',$1,false)")
                            .bind(world.to_string())
                            .execute(connection)
                            .await?;
                    }
                    Ok(())
                })
            })
            .connect(&database.url)
            .await?;
        if testing {
            postgres::migrate_testing(&pool).await?;
        } else {
            postgres::migrate(&pool).await?;
        }
        sqlx::raw_sql("INSERT INTO iam.cryptographic_key_versions(purpose,key_version) VALUES ('contact_aead',1),('contact_lookup_hmac',1),('token_hmac',1)").execute(&pool).await?;
        let grants = include_str!("../../../deploy/postgres/runtime-grants.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with('\\'))
            .collect::<Vec<_>>()
            .join("\n");
        sqlx::raw_sql(sqlx::AssertSqlSafe(grants))
            .execute(&pool)
            .await?;
        let mut settings = crate::config::Settings::from_env()?;
        // This test must never contact a real notification provider.
        settings.providers.postmark_server_token = None;
        settings.providers.twilio_account_sid = None;
        settings.providers.twilio_auth_token = None;
        settings.providers.twilio_messaging_service_sid = None;
        settings.providers.twilio_verify_service_sid = None;
        settings.providers.allow_local_providers = true;
        settings.providers.expose_local_otps = true;
        let runtime = PgPoolOptions::new()
            .max_connections(2)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET ROLE silicon_iam_api")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database.url)
            .await?;
        let state = ApiState {
            pool: runtime,
            crypto: Arc::new(CryptoService::from_settings(&settings.security)?),
            notifications: NotificationProviders::from_settings(&settings.providers)?,
            settings: Arc::new(settings),
            workos: None,
            testing: None,
        };
        let checks = async {
            let session = verified_email(&state, "ada@example.test", "first-carbon").await?;
            let first = complete(&state, session, "first-carbon-complete")
                .await
                .context("first Carbon completion")?;
            ensure!(first["carbon_id"] == "c:ada");
            ensure!(first["phone_number"].is_null());
            ensure!(first["display_name"] == "ada");
            ensure!(first["onboarding"]["requires_organization"] == true);
            let replay = complete(&state, session, "first-carbon-complete").await?;
            ensure!(
                first == replay,
                "signup replay must not issue another identity or session"
            );
            let access = postgres::tokens::authenticate(
                &state.pool,
                &state.crypto,
                &SecretString::from(
                    first["access_token"]
                        .as_str()
                        .context("access token")?
                        .to_owned(),
                ),
            )
            .await?
            .context("new session must authenticate immediately")?;
            let handle_login = super::login::create_challenge(
                &state,
                &key("email-only-handle-login")?,
                validation::login_identifier(super::model::LoginChallengeInput {
                    email: None,
                    phone_number: None,
                    carbon_id: Some("c:ada".into()),
                })?,
            )
            .await?;
            ensure!(
                handle_login.value.session_id != session,
                "email-only Carbon can log in by handle"
            );
            let mut profile_transaction = postgres::context::begin(
                &state.pool,
                postgres::context::DatabaseContext::principal(access.subject.id),
            )
            .await?;
            let me = serde_json::to_value(
                crate::api::me::read_profile(
                    &mut profile_transaction,
                    &state,
                    access.subject.id,
                    false,
                )
                .await?,
            )?;
            profile_transaction.commit().await?;
            ensure!(
                me["carbon_id"] == "c:ada" && me["phone_number"].is_null(),
                "email-only account can read its profile"
            );

            let access = postgres::tokens::authenticate(
                &state.pool,
                &state.crypto,
                &SecretString::from(
                    first["access_token"]
                        .as_str()
                        .context("access token")?
                        .to_owned(),
                ),
            )
            .await?
            .context("photo access")?;
            let mut photo_headers = headers("first-carbon-photo-upload")?;
            photo_headers.insert("if-match", HeaderValue::from_static("\"1\""));
            photo_headers.insert("content-type", HeaderValue::from_static("image/png"));
            let image = axum::body::Bytes::from_static(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR");
            let uploaded = crate::api::photos::upload(
                State(state.clone()),
                crate::api::authentication::Authenticated(access.clone()),
                photo_headers.clone(),
                image.clone(),
            )
            .await?;
            let uploaded: serde_json::Value =
                serde_json::from_slice(&to_bytes(uploaded.into_body(), 1_048_576).await?)?;
            ensure!(
                uploaded["version"] == 2,
                "photo upload advances the profile version exactly once"
            );
            let url = url::Url::parse(uploaded["profile_photo"].as_str().context("photo URL")?)?;
            let photo_id = Id::parse_str(
                url.path_segments()
                    .and_then(Iterator::last)
                    .context("photo id")?,
            )?;
            let served =
                crate::api::photos::get(State(state.clone()), Path(photo_id), HeaderMap::new())
                    .await?;
            ensure!(to_bytes(served.into_body(), 1_048_576).await? == image);
            let replayed = crate::api::photos::upload(
                State(state.clone()),
                crate::api::authentication::Authenticated(access),
                photo_headers,
                image,
            )
            .await?;
            let replayed: serde_json::Value =
                serde_json::from_slice(&to_bytes(replayed.into_body(), 1_048_576).await?)?;
            ensure!(
                replayed == uploaded,
                "photo replay must not create another asset or increment the profile again"
            );

            let session = verified_email(&state, "ada@another.test", "second-carbon").await?;
            let dispatch = signup::start_contact(
                &state,
                &key("second-carbon-phone-dispatch")?,
                session,
                validation::phone("+14155550122".into())?,
            )
            .await?
            .value;
            let input = validation::signup_completion(profile(), false)?;
            let blocked =
                signup::complete_signup(&state, &key("second-carbon-complete")?, session, input)
                    .await;
            ensure!(
                matches!(blocked, Err(crate::error::AppError::Conflict { code }) if code == "signup_contacts_not_verified"),
                "a supplied unverified phone must block completion"
            );
            signup::skip_phone(&state, &key("second-carbon-phone-skip")?, session).await?;
            let second = complete(&state, session, "second-carbon-complete").await?;
            ensure!(second["carbon_id"] == "c:ada_1" && second["phone_number"].is_null());
            let code = dispatch.local_otp.context("phone code")?;
            ensure!(
                signup::verify_contact(
                    &state,
                    &key("second-carbon-old-phone-code")?,
                    session,
                    super::model::ContactChannel::Phone,
                    validation::verification_code(code)?
                )
                .await
                .is_err(),
                "skipped phone cannot be verified after completion"
            );

            let session = verified_email(&state, "grace@example.test", "third-carbon").await?;
            let dispatch = signup::start_contact(
                &state,
                &key("third-carbon-phone-dispatch")?,
                session,
                validation::phone("+14155550123".into())?,
            )
            .await?
            .value;
            signup::verify_contact(
                &state,
                &key("third-carbon-phone-verify")?,
                session,
                super::model::ContactChannel::Phone,
                validation::verification_code(dispatch.local_otp.context("phone code")?)?,
            )
            .await?;
            let third = complete(&state, session, "third-carbon-complete").await?;
            ensure!(third["phone_number"] == "+14155550123");

            let duplicate = signup::create_session(&state, &key("duplicate-carbon-session")?)
                .await?
                .value
                .session_id;
            let result = signup::start_contact(
                &state,
                &key("duplicate-carbon-email")?,
                duplicate,
                validation::email("ada@example.test".into())?,
            )
            .await?
            .value;
            ensure!(
                result.already_exists && result.local_otp.is_none(),
                "duplicate email routes to login without dispatching an OTP"
            );
            silicon_checks(&state, &pool, &first, &second)
                .await
                .context("independent Silicon journey")?;
            // Authentication and profile data must never be available in a different testing environment.
            if testing {
                let raw = SecretString::from(
                    first["access_token"]
                        .as_str()
                        .context("access token")?
                        .to_owned(),
                );
                testing_plane::scope(
                    SelectedEnvironment {
                        id: Id::from_u128(0x123),
                        organization_id: Id::from_u128(0x21),
                    },
                    async {
                        ensure!(
                            postgres::tokens::authenticate(&state.pool, &state.crypto, &raw)
                                .await?
                                .is_none()
                        );
                        anyhow::Ok(())
                    },
                )
                .await?;
            }
            anyhow::Ok(())
        };
        if testing {
            testing_plane::scope(
                SelectedEnvironment {
                    id: world,
                    organization_id: Id::from_u128(0x21),
                },
                checks,
            )
            .await
            .context("testing signup")?;
        } else {
            checks.await.context("production signup")?;
        }
        state.pool.close().await;
        pool.close().await;
    }
    Ok(())
}

async fn response_json(response: axum::response::Response) -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 1_048_576).await?,
    )?)
}
async fn authenticated(
    state: &ApiState,
    tokens: &serde_json::Value,
) -> anyhow::Result<crate::api::authentication::Authenticated> {
    Ok(crate::api::authentication::Authenticated(
        postgres::tokens::authenticate(
            &state.pool,
            &state.crypto,
            &SecretString::from(
                tokens["access_token"]
                    .as_str()
                    .context("access token")?
                    .to_owned(),
            ),
        )
        .await?
        .context("authenticated session")?,
    ))
}
async fn silicon_checks(
    state: &ApiState,
    fixture_pool: &sqlx::PgPool,
    first: &serde_json::Value,
    second: &serde_json::Value,
) -> anyhow::Result<()> {
    use super::silicon_signup;
    let input = serde_json::json!({"silicon_id":"si:independent","custodian_email":"ada@example.test","timezone":"Asia/Kolkata","webhook_url":"https://example.test/silicon-created"});
    let created = response_json(
        silicon_signup::create(
            State(state.clone()),
            headers("independent-silicon-signup")?,
            Json(serde_json::from_value(input.clone())?),
        )
        .await?,
    )
    .await?;
    let replay = response_json(
        silicon_signup::create(
            State(state.clone()),
            headers("independent-silicon-signup")?,
            Json(serde_json::from_value(input)?),
        )
        .await?,
    )
    .await?;
    ensure!(
        created == replay,
        "pending signup credential returned only as exact replay"
    );
    ensure!(
        created["generated_silicon_token"]
            .as_str()
            .context("generated STK")?
            .len()
            == 24
    );
    let id = Id::parse_str(created["request_id"].as_str().context("request id")?)?;
    let login_input = serde_json::json!({"silicon_id":"si:independent","silicon_token":created["generated_silicon_token"]});
    ensure!(
        super::silicon::authenticate(
            State(state.clone()),
            headers("silicon-before-approval")?,
            Ok(Json(serde_json::from_value(login_input.clone())?))
        )
        .await
        .is_err(),
        "pending signup cannot authenticate"
    );
    let mut poll_headers = HeaderMap::new();
    poll_headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "Bearer {}",
            created["poll_token"].as_str().context("poll token")?
        ))?,
    );
    let status = response_json(
        silicon_signup::status(State(state.clone()), Path(id), poll_headers.clone())
            .await
            .context("initial Silicon status")?,
    )
    .await?;
    ensure!(status["status"] == "pending");
    ensure!(
        silicon_signup::review(
            State(state.clone()),
            authenticated(state, second).await?,
            Path(id)
        )
        .await
        .is_err(),
        "wrong verified Carbon cannot read custody request"
    );
    ensure!(
        silicon_signup::decide(
            State(state.clone()),
            authenticated(state, second).await?,
            Path(id),
            headers("wrong-custodian-approval")?,
            Json(serde_json::from_value(serde_json::json!({"approve":true}))?)
        )
        .await
        .is_err(),
        "wrong verified Carbon cannot approve"
    );
    let approved = response_json(
        silicon_signup::decide(
            State(state.clone()),
            authenticated(state, first).await?,
            Path(id),
            headers("approve-independent")?,
            Json(serde_json::from_value(
                serde_json::json!({"approve":true,"can_create_organizations":true}),
            )?),
        )
        .await
        .context("approve Silicon custody")?,
    )
    .await?;
    ensure!(approved["status"] == "approved");
    let status =
        response_json(silicon_signup::status(State(state.clone()), Path(id), poll_headers).await?)
            .await?;
    ensure!(status["status"] == "approved");
    let response = super::silicon::authenticate(
        State(state.clone()),
        headers("silicon-after-approval")?,
        Ok(Json(serde_json::from_value(login_input.clone())?)),
    )
    .await
    .context("approved Silicon login")?;
    ensure!(response.headers().contains_key("set-cookie"));
    let tokens = response_json(response).await?;
    let actor = authenticated(state, &tokens).await?;
    ensure!(
        actor.0.organization_id.is_none() && actor.0.membership_id.is_none(),
        "independent IAM session is identity-bound"
    );
    let profile = response_json(
        silicon_signup::profile(state.clone(), actor)
            .await
            .context("global Silicon profile")?,
    )
    .await?;
    ensure!(profile["silicon_id"] == "si:independent" && profile["timezone"] == "Asia/Kolkata");
    let mut photo_headers = headers("independent-silicon-photo")?;
    photo_headers.insert("if-match", HeaderValue::from_static("\"1\""));
    photo_headers.insert("content-type", HeaderValue::from_static("image/png"));
    let uploaded = response_json(
        crate::api::photos::upload(
            State(state.clone()),
            authenticated(state, &tokens).await?,
            photo_headers,
            axum::body::Bytes::from_static(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"),
        )
        .await?,
    )
    .await?;
    ensure!(
        uploaded["version"] == 2
            && uploaded["profile_photo"]
                .as_str()
                .is_some_and(|url| url.contains("/profile-photos/")),
        "Silicon profile supports photo uploads before joining an organization"
    );
    let organizations = crate::features::organizations::router().with_state(state.clone());
    let before = organizations
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/organizations?limit=1")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        tokens["access_token"].as_str().context("list access")?
                    ),
                )
                .body(axum::body::Body::empty())?,
        )
        .await?;
    ensure!(
        before.status() == 200,
        "new Silicon can check first-organization onboarding"
    );
    ensure!(response_json(before).await?["items"] == serde_json::json!([]));
    let org_response = crate::features::organizations::router()
        .with_state(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/organizations")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        tokens["access_token"].as_str().context("access")?
                    ),
                )
                .header("idempotency-key", "independent-first-organization")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"org_id":"independent-lab","name":"Independent lab"}"#,
                ))?,
        )
        .await?;
    let org_status = org_response.status();
    let org = response_json(org_response).await?;
    ensure!(
        org_status == 201,
        "Silicon organization creation failed: {org}"
    );
    let org_id = Id::parse_str(org["id"].as_str().context("org uuid")?)?;
    let owner_id = org["owner_membership_id"]
        .as_str()
        .context("owner membership")?;
    let mut owner_tx = postgres::context::begin(
        &state.pool,
        postgres::context::DatabaseContext::organization(
            authenticated(state, &tokens).await?.0.subject.id,
            org_id,
        ),
    )
    .await?;
    let owner=sqlx::query_as::<_,(String,String)>("SELECT principal_id,org_role::text FROM iam.organization_memberships WHERE id=$1 AND organization_id=$2").bind(Id::parse_str(owner_id)?).bind(org_id).fetch_one(&mut *owner_tx).await?;
    ensure!(
        owner.0 == "si:independent" && owner.1 == "owner",
        "Silicon owns its organization"
    );
    owner_tx.commit().await?;
    // A Silicon owner can seed another Silicon, promote it, and transfer ownership.
    let seeded = org_call(
        state,
        &tokens,
        "/api/v1/organizations/independent-lab/silicons",
        "seeded-silicon-created",
        serde_json::json!({"silicon_id":"seeded","job_description":"Test assistant"}),
        None,
        None,
    )
    .await?;
    let member = seeded["silicon"]["membership_id"]
        .as_str()
        .context("seeded membership")?;
    let member_id = Id::parse_str(member)?;
    sqlx::query("UPDATE iam.organization_memberships SET status='removed',removed_at=transaction_timestamp() WHERE id=$1")
        .bind(member_id).execute(fixture_pool).await?;
    let migrated = response_json(super::silicon::authenticate(
        State(state.clone()), headers("seeded-legacy-global-login")?,
        Ok(Json(serde_json::from_value(serde_json::json!({"silicon_id":"si:seeded","silicon_token":seeded["silicon_token"]}))?)),
    ).await.context("legacy STK login after leaving original membership")?).await?;
    ensure!(
        authenticated(state, &migrated)
            .await?
            .0
            .organization_id
            .is_none(),
        "legacy STKs establish a global identity session"
    );
    sqlx::query(
        "UPDATE iam.organization_memberships SET status='active',removed_at=NULL WHERE id=$1",
    )
    .bind(member_id)
    .execute(fixture_pool)
    .await?;
    let restored_version = sqlx::query_scalar::<_, i64>(
        "SELECT version FROM iam.organization_memberships WHERE id=$1",
    )
    .bind(member_id)
    .fetch_one(fixture_pool)
    .await?;
    organization_custody_checks(state, &tokens, &migrated).await?;
    let grant_proof = silicon_proof(
        state,
        &tokens,
        &created,
        "organization.authorization_change",
        member_id,
        "seeded-admin-proof",
    )
    .await?;
    let promoted = org_call(
        state,
        &tokens,
        "/api/v1/organizations/independent-lab/members/si:seeded[independent-lab]/admin-promotions",
        "seeded-admin-promoted",
        serde_json::json!({}),
        Some(restored_version),
        Some(&grant_proof),
    )
    .await?;
    ensure!(
        promoted["org_role"] == "admin",
        "Silicon may be an administrator"
    );
    let owner_proof = silicon_proof(
        state,
        &tokens,
        &created,
        "organization.transfer_ownership",
        org_id,
        "seeded-owner-proof",
    )
    .await?;
    let transferred = org_call(
        state,
        &tokens,
        "/api/v1/organizations/independent-lab/ownership-transfers",
        "seeded-ownership-transferred",
        serde_json::json!({"new_owner_membership_id":member_id}),
        Some(1),
        Some(&owner_proof),
    )
    .await?;
    ensure!(
        transferred["owner_membership_id"] == seeded["silicon"]["membership_id"],
        "Silicon may own an organization after transfer"
    );

    let custody = response_json(
        silicon_signup::list_custodies(State(state.clone()), authenticated(state, first).await?)
            .await
            .context("list existing custody settings")?,
    )
    .await?;
    let version = custody["items"][0]["version"]
        .as_i64()
        .context("custody version")?;
    let mut settings_headers = headers("custodian-disables-org-creation")?;
    settings_headers.insert(
        "if-match",
        HeaderValue::from_str(&format!("\"{version}\""))?,
    );
    silicon_signup::update_custody(
        State(state.clone()),
        authenticated(state, first).await?,
        Path("si:independent".to_owned()),
        settings_headers,
        Json(serde_json::from_value(
            serde_json::json!({"can_create_organizations":false}),
        )?),
    )
    .await
    .context("update existing custody setting")?;
    let denied = crate::features::organizations::router()
        .with_state(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/organizations")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        tokens["access_token"].as_str().context("access")?
                    ),
                )
                .header("idempotency-key", "independent-blocked-organization")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"org_id":"blocked-lab","name":"Blocked lab"}"#,
                ))?,
        )
        .await?;
    ensure!(
        denied.status() == 403,
        "custodian can prevent further organization creation"
    );
    let proof=response_json(super::silicon_step_up::create(State(state.clone()),authenticated(state,&tokens).await?,headers("independent-silicon-step-up")?,Json(serde_json::from_value(serde_json::json!({"silicon_token":created["generated_silicon_token"],"action":"organization.authorization_change","resource_id":org_id}))?)).await?).await?;
    let assertion = postgres::step_up::StepUpToken::parse(
        proof["step_up_token"].as_str().context("stepup token")?,
    )?;
    let actor = authenticated(state, &tokens).await?;
    let mut tx = postgres::context::begin(
        &state.pool,
        postgres::context::DatabaseContext::principal(actor.0.subject.id),
    )
    .await?;
    let expected = postgres::step_up::StepUpExpectation {
        carbon_id: actor.0.subject.id,
        authentication_session_id: actor.0.authentication_session_id,
        action: "organization.authorization_change",
        resource_id: Some(org_id),
        required_assurance: postgres::step_up::RequiredAssurance::VerifiedChannel,
    };
    ensure!(
        postgres::step_up::consume(
            &mut tx,
            &state.crypto,
            &assertion,
            postgres::step_up::StepUpExpectation {
                resource_id: Some(Id::now_v7()),
                ..expected
            }
        )
        .await
        .is_err(),
        "proof rejects wrong resource without consuming"
    );
    postgres::step_up::consume(&mut tx, &state.crypto, &assertion, expected).await?;
    ensure!(
        postgres::step_up::consume(&mut tx, &state.crypto, &assertion, expected)
            .await
            .is_err(),
        "proof is single use"
    );
    tx.commit().await?;
    let rotated = super::refresh::rotate(
        state,
        &key("independent-refresh")?,
        SecretString::from(
            tokens["refresh_token"]
                .as_str()
                .context("refresh")?
                .to_owned(),
        ),
    )
    .await
    .context("independent Silicon refresh")?;
    let super::model::RefreshMutationOutcome::Success(rotated) = rotated.value else {
        anyhow::bail!("new refresh unexpectedly revoked")
    };
    let actor = authenticated(state, &serde_json::to_value(rotated)?).await?;
    ensure!(
        actor.0.organization_id.is_none(),
        "refresh preserves identity-only binding"
    );
    let router = super::router().with_state(state.clone());
    for path in ["/api/v1/me/sessions", "/api/v1/me/login-history"] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .header(
                        "authorization",
                        format!(
                            "Bearer {}",
                            tokens["access_token"].as_str().context("session access")?
                        ),
                    )
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        let status = response.status();
        let body = response_json(response).await?;
        ensure!(
            status == 200
                && body["items"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty()),
            "Silicon self session page {path}: {body}"
        );
    }
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/logout")
                    .header(
                        "authorization",
                        format!(
                            "Bearer {}",
                            tokens["access_token"].as_str().context("logout access")?
                        ),
                    )
                    .header("idempotency-key", "silicon-current-logout-replay")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"mode":"current_session"}"#))?,
            )
            .await?;
        ensure!(
            response.status() == 204,
            "Silicon logout must succeed or replay: {}",
            response.status()
        );
    }
    ensure!(
        postgres::tokens::authenticate(
            &state.pool,
            &state.crypto,
            &SecretString::from(
                tokens["access_token"]
                    .as_str()
                    .context("revoked access")?
                    .to_owned()
            )
        )
        .await?
        .is_none(),
        "Silicon logout revokes current access"
    );
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "test request fixture names every security binding"
)]
async fn org_call(
    state: &ApiState,
    tokens: &serde_json::Value,
    path: &str,
    key: &str,
    body: serde_json::Value,
    version: Option<i64>,
    proof: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header(
            "authorization",
            format!(
                "Bearer {}",
                tokens["access_token"].as_str().context("access")?
            ),
        )
        .header("idempotency-key", key)
        .header("content-type", "application/json");
    if let Some(version) = version {
        request = request.header("if-match", format!("\"{version}\""));
    }
    if let Some(proof) = proof {
        request = request.header("x-step-up-token", proof);
    }
    let response = crate::features::organizations::router()
        .with_state(state.clone())
        .oneshot(request.body(axum::body::Body::from(serde_json::to_vec(&body)?))?)
        .await?;
    let status = response.status();
    let body = response_json(response).await?;
    ensure!(status.is_success(), "{path}: {status} {body}");
    Ok(body)
}
async fn silicon_proof(
    state: &ApiState,
    tokens: &serde_json::Value,
    signup: &serde_json::Value,
    action: &str,
    resource: Id,
    key: &str,
) -> anyhow::Result<String> {
    let proof=response_json(super::silicon_step_up::create(State(state.clone()),authenticated(state,tokens).await?,headers(key)?,Json(serde_json::from_value(serde_json::json!({"silicon_token":signup["generated_silicon_token"],"action":action,"resource_id":resource}))?)).await?).await?;
    Ok(proof["step_up_token"]
        .as_str()
        .context("action proof")?
        .to_owned())
}

async fn organization_custody_checks(
    state: &ApiState,
    manager: &serde_json::Value,
    member: &serde_json::Value,
) -> anyhow::Result<()> {
    let router = crate::features::organizations::router().with_state(state.clone());
    let path = "/api/v1/organizations/independent-lab/silicons/si:seeded/custody";
    for (tokens, method, target, version, key, expected) in [
        (manager, "GET", path, 1, "organization-custody-read", 200),
        (
            member,
            "GET",
            path,
            1,
            "organization-custody-member-read",
            403,
        ),
        (
            member,
            "PATCH",
            path,
            1,
            "organization-custody-member-write",
            403,
        ),
        (
            manager,
            "GET",
            "/api/v1/organizations/independent-lab/silicons/si:independent/custody",
            1,
            "organization-custody-foreign-read",
            404,
        ),
        (
            manager,
            "PATCH",
            "/api/v1/organizations/independent-lab/silicons/si:independent/custody",
            1,
            "organization-custody-foreign-write",
            404,
        ),
        (
            manager,
            "PATCH",
            path,
            1,
            "organization-custody-update",
            200,
        ),
        (
            manager,
            "PATCH",
            path,
            1,
            "organization-custody-update",
            200,
        ),
        (manager, "PATCH", path, 1, "organization-custody-stale", 412),
    ] {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(target)
            .header(
                "authorization",
                format!(
                    "Bearer {}",
                    tokens["access_token"].as_str().context("custody access")?
                ),
            )
            .header("if-match", format!("\"{version}\""))
            .header("idempotency-key", key)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(if method == "PATCH" {
                r#"{"can_create_organizations":false}"#
            } else {
                ""
            }))?;
        let response = router.clone().oneshot(request).await?;
        let status = response.status();
        let value = response_json(response).await?;
        ensure!(status.as_u16() == expected, "{key}: {status} {value}");
        if method == "PATCH" && status.is_success() {
            ensure!(
                value["can_create_organizations"] == false && value["version"] == 2,
                "custody version only advances once"
            );
        }
    }
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/organizations")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        member["access_token"].as_str().context("member access")?
                    ),
                )
                .header("idempotency-key", "organization-custody-creation-denied")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"org_id":"seeded-blocked","name":"Cannot create"}"#,
                ))?,
        )
        .await?;
    ensure!(
        response.status() == 403,
        "organization custodian can prevent its Silicon creating organizations"
    );
    Ok(())
}
