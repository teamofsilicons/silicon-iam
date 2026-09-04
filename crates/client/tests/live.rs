//! End-to-end checks against a running Silicon IAM.
//!
//! Ignored by default because they need a service. Point them at one and run:
//!
//! ```sh
//! SILICON_IAM_LIVE_URL=http://127.0.0.1:8097 \
//!   cargo test -p silicon-iam-client --test live -- --ignored --test-threads=1
//! ```
//!
//! The service must be running with `IAM_ALLOW_LOCAL_PROVIDERS=true` and
//! `IAM_EXPOSE_LOCAL_OTPS=true`, which is what lets a test read the
//! verification codes it is supposed to receive out of band.

// Direct OTP login exists only for the stateful CLI. Application integrations
// build the client without this feature and can begin a session only with an
// SLT through `OAuth::login`.
#![cfg(feature = "cli-session")]
// A failing step here should stop the test at the step that failed, naming it.
// The crate's own ban on panicking exists to keep library code from taking a
// caller's process down, which is not what a test binary does.
#![allow(clippy::expect_used)]
// Each test walks one whole flow end to end, and splitting the walk into
// helpers would hide the order the assertions depend on.
#![allow(clippy::too_many_lines)]

use silicon_iam_client::{
    Client, Credential, Mutation, Paging,
    api::{governance::ApprovalFilter, members::MemberFilter},
    models,
};

/// The verification code to present: the environment's fixed one, or the one
/// the local provider echoed back.
fn code_for(fixed: Option<&str>, echoed: Option<String>) -> String {
    fixed.map_or_else(
        || echoed.expect("the local provider echoes codes"),
        str::to_owned,
    )
}

fn service() -> Option<Client> {
    let base = std::env::var("SILICON_IAM_LIVE_URL").ok()?;
    Client::builder(&base)
        .and_then(|builder| builder.user_agent("silicon-iam-client-live-test").build())
        .ok()
}

/// A distinct handle per run, in the alphabet the contract accepts: lowercase
/// letters and 1-9, with zero excluded.
fn unique(prefix: &str) -> String {
    let suffix: String = uuid::Uuid::now_v7()
        .simple()
        .to_string()
        .chars()
        .filter(|character| *character != '0')
        .take(10)
        .collect();
    format!("{prefix}{suffix}")
}

/// A distinct E.164 number per run, inside the reserved 555 test range.
fn unique_phone() -> String {
    let digits = uuid::Uuid::now_v7().as_u128() % 10_000_000;
    format!("+1415{digits:07}")
}

/// Signs a fresh Carbon up and logs it in, returning an authenticated client.
///
/// `fixed_code` is `Some("000000")` inside a testing environment, which
/// delivers nothing and accepts that code in place of a delivered one.
async fn enrol(anonymous: &Client, handle: &str, fixed_code: Option<&str>) -> Client {
    let session = anonymous
        .signup()
        .start(&Mutation::new())
        .await
        .expect("a signup session")
        .session_id;

    let email = format!("{handle}@example.test");
    let phone = unique_phone();

    let dispatched = anonymous
        .signup()
        .send_email_code(session, &email, &Mutation::new())
        .await
        .expect("an email code");
    let code = code_for(fixed_code, dispatched.local_otp);
    anonymous
        .signup()
        .verify_email(session, &code, &Mutation::new())
        .await
        .expect("the emailed code verifies");

    let dispatched = anonymous
        .signup()
        .send_phone_code(session, &phone, &Mutation::new())
        .await
        .expect("a phone code");
    let code = code_for(fixed_code, dispatched.local_otp);
    anonymous
        .signup()
        .verify_phone(session, &code, &Mutation::new())
        .await
        .expect("the texted code verifies");

    anonymous
        .signup()
        .complete(
            session,
            &models::CarbonSignupComplete {
                carbon_id: handle.to_owned(),
                display_name: handle.to_owned(),
                timezone: None,
                description: None,
                profile_photo: None,
            },
            &Mutation::new(),
        )
        .await
        .expect("the Carbon is created");

    let challenge = anonymous
        .auth()
        .start_login(
            &models::LoginChallengeCreate {
                email: Some(email),
                phone_number: None,
                carbon_id: None,
            },
            &Mutation::new(),
        )
        .await
        .expect("a login challenge");
    let code = code_for(fixed_code, challenge.local_otp);
    let tokens = anonymous
        .auth()
        .verify_login(challenge.session_id, &code, &Mutation::new())
        .await
        .expect("the login code verifies");

    anonymous.with_credential(Credential::bearer(tokens.access_token))
}

#[tokio::test]
#[ignore = "needs a running Silicon IAM"]
async fn the_client_speaks_the_contract_end_to_end() {
    let Some(anonymous) = service() else {
        eprintln!("set SILICON_IAM_LIVE_URL to run this");
        return;
    };

    // The version handshake, before anything else depends on it.
    let negotiated = anonymous
        .system()
        .negotiate()
        .await
        .expect("a mutually supported version");
    assert_eq!(
        negotiated.selected_api_version,
        silicon_iam_client::API_VERSION
    );
    anonymous
        .system()
        .readiness()
        .await
        .expect("a ready service");

    let handle = unique("live");
    let client = enrol(&anonymous, &handle, None).await;

    let me = client.carbons().me().await.expect("the caller's profile");
    assert_eq!(me.carbon_id, handle);

    // A profile update, which exercises merge-patch and If-Match together.
    let renamed = client
        .carbons()
        .update_me(
            me.version,
            &models::CarbonProfilePatch {
                display_name: Some("Renamed".to_owned()),
                timezone: None,
                description: None,
                profile_photo: None,
            },
            &Mutation::new(),
        )
        .await
        .expect("the profile updates");
    assert_eq!(renamed.display_name, "Renamed");
    assert!(renamed.version > me.version);

    // A stale version has to be refused, or optimistic concurrency is a lie.
    let stale = client
        .carbons()
        .update_me(
            me.version,
            &models::CarbonProfilePatch {
                display_name: Some("Again".to_owned()),
                timezone: None,
                description: None,
                profile_photo: None,
            },
            &Mutation::new(),
        )
        .await;
    let Err(error) = stale else {
        panic!("a stale version must be refused");
    };
    assert!(
        error
            .api()
            .is_some_and(silicon_iam_client::ApiError::is_version_conflict),
        "{error}"
    );

    let org_id = unique("org");
    let availability = client
        .organizations()
        .handle_available(&org_id)
        .await
        .expect("an availability answer");
    assert!(availability.available);

    let organization = client
        .organizations()
        .create(
            &models::OrganizationCreate {
                org_id: org_id.clone(),
                name: "Live Test".to_owned(),
                logo: None,
                description: None,
            },
            &Mutation::new(),
        )
        .await
        .expect("the organization is created");
    assert_eq!(organization.org_id, org_id);

    // Listing, which exercises the paged shape.
    let listed = client
        .organizations()
        .list(&Paging::new().limit(10))
        .await
        .expect("the caller's organizations");
    assert!(listed.items.iter().any(|entry| entry.org_id == org_id));

    // Tags, through their whole lifecycle including the cascade on delete.
    let tag = client
        .tags()
        .create(
            &org_id,
            &models::TagCreate {
                name: "Engineering".to_owned(),
            },
            &Mutation::new(),
        )
        .await
        .expect("the tag is created");

    let membership_id = organization.owner_membership_id;
    let member = client
        .members()
        .get(&org_id, membership_id)
        .await
        .expect("the owner membership");
    client
        .governance()
        .replace_tags(
            &org_id,
            membership_id,
            member.version,
            &models::DirectTagSetReplace {
                tag_ids: vec![tag.id],
            },
            &Mutation::new(),
        )
        .await
        .expect("the tag is assigned");

    let tagged = client
        .members()
        .list(
            &org_id,
            &MemberFilter {
                tag_id: Some(tag.id),
                ..MemberFilter::default()
            },
            &Paging::new(),
        )
        .await
        .expect("members carrying the tag");
    assert_eq!(tagged.items.len(), 1);

    client
        .tags()
        .delete(&org_id, tag.id, tag.version, &Mutation::new())
        .await
        .expect("the tag is deleted");

    let gone = client.tags().get(&org_id, tag.id).await;
    let Err(error) = gone else {
        panic!("a deleted tag must be gone");
    };
    assert!(
        error
            .api()
            .is_some_and(silicon_iam_client::ApiError::is_not_found),
        "{error}"
    );

    // The cascade: the member no longer carries it.
    let after = client
        .members()
        .get(&org_id, membership_id)
        .await
        .expect("the owner membership");
    assert!(after.tags.is_empty());

    // Approvals list cleanly even when empty.
    let approvals = client
        .governance()
        .list_approvals(&org_id, &ApprovalFilter::actionable(), &Paging::new())
        .await
        .expect("the approval queue");
    assert!(!approvals.page.has_more);
}

#[tokio::test]
#[ignore = "needs a running Silicon IAM with a testing database"]
async fn a_testing_environment_is_the_same_api_against_its_own_data() {
    let Some(anonymous) = service() else {
        eprintln!("set SILICON_IAM_LIVE_URL to run this");
        return;
    };

    let handle = unique("env");
    let client = enrol(&anonymous, &handle, None).await;

    let org_id = unique("envorg");
    client
        .organizations()
        .create(
            &models::OrganizationCreate {
                org_id: org_id.clone(),
                name: "Environment Test".to_owned(),
                logo: None,
                description: None,
            },
            &Mutation::new(),
        )
        .await
        .expect("the organization is created");

    let created = match client
        .environments()
        .create(
            &org_id,
            &models::TestingEnvironmentCreate {
                name: "Sandbox".to_owned(),
                description: None,
            },
            &Mutation::new(),
        )
        .await
    {
        Ok(created) => created,
        Err(error) => {
            eprintln!("no testing database configured; skipping: {error}");
            return;
        }
    };

    let key = silicon_iam_client::EnvironmentKey::new(created.key.clone())
        .expect("the service returns a well-formed key");
    let sandbox = client.with_environment(key);

    // The key alone describes the environment it opens.
    let described = sandbox
        .environments()
        .current()
        .await
        .expect("the environment describes itself");
    assert_eq!(described.name, "Sandbox");

    // A production token is worthless inside the environment. This is the
    // isolation the whole feature rests on, so it is asserted before anything
    // that would depend on it.
    let refused = sandbox.carbons().me().await;
    let Err(error) = refused else {
        panic!("a production token must not authenticate inside an environment");
    };
    assert_eq!(error.api().map(|api| api.status), Some(401), "{error}");

    // An environment is the same API, so it is entered the same way: sign up
    // inside it. Nothing is delivered there, and 000000 stands in for a
    // delivered code.
    let inside_handle = unique("inenv");
    let inside = enrol(
        &anonymous.with_environment(
            silicon_iam_client::EnvironmentKey::new(created.key.clone())
                .expect("a well-formed key"),
        ),
        &inside_handle,
        Some("000000"),
    )
    .await;

    // The same Carbon handle exists in both planes without collision, and the
    // environment starts with nothing in it.
    let inside_me = inside
        .carbons()
        .me()
        .await
        .expect("the environment profile");
    assert_eq!(inside_me.carbon_id, inside_handle);
    let organizations = inside
        .organizations()
        .list(&Paging::new())
        .await
        .expect("organizations inside the environment");
    assert!(
        organizations.items.is_empty(),
        "a fresh environment must start empty"
    );

    // Production's organization handle is free inside the environment.
    let availability = inside
        .organizations()
        .handle_available(&org_id)
        .await
        .expect("an availability answer");
    assert!(
        availability.available,
        "an environment must not see production's handles"
    );

    // Meanwhile the environment itself is visible from production.
    let outside = client
        .environments()
        .get(&org_id, created.id)
        .await
        .expect("the environment is visible from production");
    assert_eq!(outside.status, models::TestingEnvironmentStatus::Active);

    let cleaning = sandbox
        .environments()
        .clean_current(&Mutation::new())
        .await
        .expect("the environment cleans itself");
    assert_eq!(cleaning.environment_id, created.id);

    let retired = client
        .environments()
        .delete(&org_id, created.id, &Mutation::new())
        .await
        .expect("the environment retires");
    assert_eq!(retired.status, models::TestingEnvironmentStatus::Deleted);
    assert!(retired.purge_after.is_some());

    // The key stops working the moment the environment is retired.
    let refused = sandbox.environments().current().await;
    assert!(
        refused.is_err(),
        "a retired environment must refuse its key"
    );
}
