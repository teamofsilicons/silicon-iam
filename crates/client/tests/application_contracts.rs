//! Wire-level tests for explicit consent and application management contracts.

#![allow(clippy::expect_used)]

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::mpsc,
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use silicon_iam_client::{Client, Credential, IdempotencyKey, Mutation, models};
use uuid::Uuid;

fn service(
    response: Value,
) -> (
    Client,
    mpsc::Receiver<(String, Value)>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock service");
    let address = listener.local_addr().expect("mock address");
    let (send, receive) = mpsc::channel();
    let task = thread::spawn(move || {
        let (mut connection, _) = listener.accept().expect("accept one request");
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut request = Vec::new();
        let boundary = loop {
            let mut bytes = [0; 4096];
            let length = connection.read(&mut bytes).expect("read request headers");
            assert!(length > 0, "request ended before its headers");
            request.extend_from_slice(&bytes[..length]);
            if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(request[..boundary].to_vec()).expect("ASCII HTTP headers");
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("body length"))
            })
            .unwrap_or(0);
        while request.len() - boundary < length {
            let mut bytes = [0; 4096];
            let count = connection.read(&mut bytes).expect("read request body");
            assert!(count > 0, "request ended before its declared body");
            request.extend_from_slice(&bytes[..count]);
        }
        let body =
            serde_json::from_slice(&request[boundary..boundary + length]).unwrap_or(Value::Null);
        send.send((headers, body)).expect("return captured request");
        let body = response.to_string();
        write!(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("send response");
    });
    let client = Client::builder(&format!("http://{address}"))
        .expect("local service URL")
        .auto_update(false)
        .build()
        .expect("client");
    (client, receive, task)
}

#[tokio::test]
async fn short_lived_token_sends_the_reviewed_version_and_exact_permission_set() {
    let (client, capture, server) = service(json!({"slt":"slt_one_use","expires_in":120}));
    let approved = vec![
        "self.identity.read".to_owned(),
        "obo:vendor>drive:files.read".to_owned(),
    ];
    client
        .auth()
        .short_lived_token_for_organizations(
            "acme>checkout",
            &["customer".to_owned()],
            17,
            &approved,
            &Mutation::new(),
        )
        .await
        .expect("issue explicit SLT");
    let (headers, body) = capture.recv().expect("captured token request");
    assert!(headers.starts_with("POST /api/v1/app-auth/short-lived-tokens "));
    assert_eq!(
        body,
        json!({"app_id":"acme>checkout","org_ids":["customer"],"scope_version":17,"approved_scopes":approved})
    );
    server.join().expect("mock completed");
}

#[tokio::test]
async fn a_review_decision_carries_concurrency_and_replay_protection() {
    let request_id = Uuid::from_u128(7);
    let response = json!({
        "id": request_id, "app_id":"acme>checkout", "target_app_id":null,
        "scopes":["directory.carbons.read"], "status":"denied", "version":3,
        "created_at":"2026-09-12T00:00:00Z", "updated_at":"2026-09-12T00:00:00Z",
        "can_decide":true, "messages":[{"id":Uuid::nil(),"author":{"principal_id":Uuid::nil(),"type":"system","public_id":"iam"},"message":"Explain each critical scope.","created_at":"2026-09-12T00:00:00Z"}]
    });
    let (client, capture, server) = service(response);
    let mutation =
        Mutation::with_key(IdempotencyKey::parse("scope-decision-replay-0001").expect("key"));
    let result = client
        .application_scopes()
        .decide(
            request_id,
            2,
            &models::ApplicationScopeDecision {
                decision: models::ApplicationScopeDecisionDecision::Deny,
                reason: Some("Please explain why directory data is needed.".to_owned()),
            },
            &mutation,
        )
        .await
        .expect("decision response including system author");
    assert!(matches!(
        result.messages[0].author.type_field,
        models::ApplicationScopeMessageAuthorType::System
    ));
    let (headers, body) = capture.recv().expect("captured decision");
    assert!(headers.starts_with(&format!(
        "POST /api/v1/application-scope-requests/{request_id}/decisions "
    )));
    let lower = headers.to_ascii_lowercase();
    assert!(lower.contains("if-match: \"2\"\r\n"));
    assert!(lower.contains("idempotency-key: scope-decision-replay-0001\r\n"));
    assert_eq!(body["decision"], "deny");
    assert!(
        body["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
    );
    server.join().expect("mock completed");
}

#[tokio::test]
async fn application_testing_keeps_the_production_credential_out_of_its_payload() {
    let environment_id = Uuid::from_u128(11);
    let (client, capture, server) = service(json!({
        "environment_id":environment_id,"org_id":"acme","name":"checkout integration",
        "description":null,"iam_test_key":"0123456789abcdefghijklmnopqrstuv","app_id":"acme>checkout",
        "app_secret":"ask_isolated_test_secret","dependencies":["vendor>drive","vendor>mail"],
        "secret_replay_expires_at":"2026-09-12T00:10:00Z"
    }));
    let client = client.with_credential(Credential::application(
        "acme>checkout",
        "production-secret",
    ));
    let result = client
        .applications()
        .create_testing_environment(
            &models::ApplicationTestingEnvironmentCreate {
                name: "checkout integration".to_owned(),
                description: None,
                iam_test_key: Some("existing-test-key".to_owned()),
            },
            &Mutation::new(),
        )
        .await
        .expect("provision test dependency graph");
    assert_eq!(result.environment_id, environment_id);
    assert_eq!(result.dependencies.len(), 2);
    let (headers, body) = capture.recv().expect("captured provisioning");
    assert!(headers.starts_with("POST /api/v1/application/testing-environments "));
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("authorization: basic ")
    );
    assert_eq!(
        body,
        json!({"name":"checkout integration","iam_test_key":"existing-test-key"})
    );
    assert!(!body.to_string().contains("production-secret"));
    server.join().expect("mock completed");
}

#[test]
fn unclassified_obo_endpoints_are_rejected_by_the_client_contract() {
    let endpoint = json!({"endpoint_id":"files.read","path":"/files","metadata":{}});
    assert!(serde_json::from_value::<models::ApplicationOboEndpoint>(endpoint).is_err());
}

#[tokio::test]
async fn scoped_profile_reads_preserve_undisclosed_fields_as_absent() {
    let (client, capture, server) = service(json!({"display_name":"Ada","version":8}));
    let client = client.with_credential(Credential::bearer("act_application_user"));
    let profile = client
        .application_reads()
        .me()
        .await
        .expect("scoped profile");
    assert_eq!(profile["display_name"], "Ada");
    for undisclosed in [
        "carbon_id",
        "type",
        "email",
        "phone_number",
        "org_role",
        "tags",
    ] {
        assert!(profile.get(undisclosed).is_none(), "invented {undisclosed}");
    }
    let (headers, body) = capture.recv().expect("captured profile read");
    assert!(headers.starts_with("GET /api/v1/me "));
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("authorization: bearer act_application_user\r\n")
    );
    assert_eq!(body, Value::Null);
    server.join().expect("mock completed");
}

#[tokio::test]
async fn contract_version_discovery_is_available_without_a_credential() {
    let manifest = json!({"items":[{"version":"v1","status":"current"}],"policy":{"sunset_after_idle_days":7}});
    let (client, capture, server) = service(manifest.clone());
    assert_eq!(
        client
            .system()
            .contracts()
            .await
            .expect("contract manifest"),
        manifest
    );
    let (headers, _) = capture.recv().expect("captured manifest read");
    assert!(headers.starts_with("GET /api/v1/contracts "));
    assert!(!headers.to_ascii_lowercase().contains("authorization:"));
    server.join().expect("mock completed");
}

#[tokio::test]
async fn bundle_availability_is_an_authenticated_organization_read() {
    let (client, capture, server) = service(json!({"available": false}));
    let client = client.with_credential(Credential::bearer("cat_direct_session"));
    let availability = client
        .bundles()
        .availability("acme")
        .await
        .expect("unavailable is a successful derived response");
    assert!(!availability.available);
    let (headers, body) = capture.recv().expect("captured availability request");
    assert!(headers.starts_with("GET /api/v1/organizations/acme/application-bundle-availability "));
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("authorization: bearer cat_direct_session\r\n")
    );
    assert_eq!(body, Value::Null);
    server.join().expect("mock completed");
}

#[tokio::test]
async fn organization_filtered_lists_preserve_pagination_and_return_the_next_cursor() {
    for bundles in [false, true] {
        let (client, capture, server) = service(json!({
            "items": [], "page": {"has_more": true, "next_cursor": "next-page"}
        }));
        let paging = silicon_iam_client::Paging::new().after("page+/=").limit(2);
        let page = if bundles {
            client
                .bundles()
                .list_for_organization("acme", &paging)
                .await
                .expect("organization bundle page")
                .page
        } else {
            client
                .applications()
                .list_for_organization("acme", Some("verified"), &paging)
                .await
                .expect("organization application page")
                .page
        };
        assert!(page.has_more);
        assert_eq!(page.next_cursor.as_deref(), Some("next-page"));
        let (headers, _) = capture.recv().expect("captured list request");
        let route = headers
            .split_whitespace()
            .nth(1)
            .expect("HTTP request target");
        let url = url::Url::parse(&format!("http://localhost{route}")).expect("request URL");
        let endpoint = if bundles {
            "application-bundles"
        } else {
            "applications"
        };
        assert_eq!(url.path(), format!("/api/v1/{endpoint}"));
        let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(
            query.get("org_id").map(std::borrow::Cow::as_ref),
            Some("acme")
        );
        assert_eq!(
            query.get("cursor").map(std::borrow::Cow::as_ref),
            Some("page+/=")
        );
        assert_eq!(query.get("limit").map(std::borrow::Cow::as_ref), Some("2"));
        if !bundles {
            assert_eq!(
                query.get("status").map(std::borrow::Cow::as_ref),
                Some("verified")
            );
        }
        server.join().expect("mock completed");
    }
}

#[tokio::test]
async fn bundle_logo_updates_distinguish_preserving_setting_and_clearing() {
    let original = "https://example.test/original.svg";
    let replacement = "https://example.test/replacement.svg";
    for (patch, expected) in [
        (None, Some(original)),
        (Some(Some(replacement.to_owned())), Some(replacement)),
        (Some(None), None),
    ] {
        let (client, capture, server) = service(json!({
            "id": Uuid::from_u128(17), "bundle_id": "acme>workspace", "org_id": "acme",
            "app_name": "Workspace", "app_logo": expected, "app_ids": ["acme>billing"],
            "version": 5, "created_at": "2026-09-12T00:00:00Z", "updated_at": "2026-09-12T01:00:00Z"
        }));
        let updated = client
            .bundles()
            .update(
                "acme>workspace",
                4,
                &models::ApplicationBundlePatch {
                    app_name: Some(Some("Workspace".to_owned())),
                    app_logo: patch.clone(),
                    app_ids: None,
                },
                &Mutation::new(),
            )
            .await
            .expect("bundle presentation update");
        assert_eq!(updated.app_logo.as_deref(), expected);
        let (headers, body) = capture.recv().expect("captured bundle patch");
        assert!(headers.starts_with("PATCH /api/v1/application-bundles/acme%3Eworkspace "));
        assert!(headers.to_ascii_lowercase().contains("if-match: \"4\"\r\n"));
        match patch {
            None => assert!(body.get("app_logo").is_none()),
            Some(None) => assert_eq!(body["app_logo"], Value::Null),
            Some(Some(logo)) => assert_eq!(body["app_logo"], logo),
        }
        server.join().expect("mock completed");
    }
}

#[tokio::test]
async fn application_login_history_preserves_events_with_private_actor_identifiers() {
    let principal_id = Uuid::from_u128(23);
    let (client, capture, server) = service(json!({
        "items": [{
            "id": Uuid::from_u128(24),
            "actor": {"principal_id": principal_id, "type": "silicon", "public_id": null},
            "app_id": "acme>workspace", "org_id": "customer",
            "event_type": "oauth_token_exchange", "success": true,
            "request_id": "history-private-actor", "occurred_at": "2026-09-12T00:00:00Z"
        }],
        "page": {"has_more": false, "next_cursor": null}
    }));
    let history = client
        .applications()
        .login_history("acme>workspace", &silicon_iam_client::Paging::new())
        .await
        .expect("private actor identifier must not invalidate the history page");
    assert_eq!(history.items.len(), 1);
    assert_eq!(history.items[0].actor.principal_id, principal_id);
    assert!(history.items[0].actor.public_id.is_none());
    assert!(history.items[0].success);
    let (headers, _) = capture.recv().expect("captured history request");
    assert!(headers.starts_with("GET /api/v1/applications/acme%3Eworkspace/login-history "));
    server.join().expect("mock completed");
}
