//! Provider signup keeps polling authority in request bodies and redacts diagnostics.

#![allow(clippy::expect_used)]

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    sync::mpsc,
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use silicon_iam_client::{Client, Mutation, models};
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

#[test]
fn existing_signup_provider_struct_literals_remain_source_compatible() {
    let provider = silicon_iam_client::api::signup::SocialProvider {
        id: "google".to_owned(),
        enabled: true,
    };
    assert_eq!(
        serde_json::to_value(provider).expect("provider"),
        json!({"id":"google","enabled":true})
    );
}

#[cfg(feature = "cli-session")]
#[tokio::test]
async fn login_discovery_has_an_additive_shape_and_old_servers_disable_login() {
    let (client, capture, server) = service(
        json!({"providers":[{"id":"google","enabled":true,"login_enabled":true},{"id":"apple","enabled":true}]}),
    );
    let providers = client
        .auth()
        .social_providers()
        .await
        .expect("login discovery");
    assert!(providers.providers[0].login_enabled);
    assert!(providers.providers[1].enabled);
    assert!(!providers.providers[1].login_enabled);
    assert!(
        capture
            .recv()
            .expect("discovery request")
            .0
            .starts_with("GET /api/v1/signup/social/providers HTTP/1.1")
    );
    server.join().expect("discovery completed");
}

#[tokio::test]
async fn social_start_and_status_use_fixed_signup_routes_and_redact_poll_tokens() {
    let id = Uuid::new_v4();
    let (client, capture, server) = service(
        json!({"request_id":id,"authorization_url":"https://accounts.google.com/o/oauth2/v2/auth?state=state","poll_token":"private-poll-capability","expires_at":"2030-01-01T00:00:00Z"}),
    );
    let start = client
        .signup()
        .social_start("google", &Mutation::new())
        .await
        .expect("start");
    let (headers, body) = capture.recv().expect("captured start");
    assert!(headers.starts_with("POST /api/v1/signup/social/google/start HTTP/1.1"));
    assert!(headers.to_ascii_lowercase().contains("idempotency-key:"));
    assert_eq!(body, json!({}));
    assert!(!format!("{start:?}").contains("private-poll-capability"));
    server.join().expect("mock completed");
    let (client, capture, server) =
        service(json!({"status":"verified","signup_session_id":id,"email":"person@example.test"}));
    let input = models::SocialSignupStatusInput {
        request_id: id,
        poll_token: start.poll_token,
    };
    assert!(!format!("{input:?}").contains("private-poll-capability"));
    let status = client
        .signup()
        .social_status("google", &input)
        .await
        .expect("status");
    assert_eq!(status.status, models::SocialSignupStatusStatus::Verified);
    let (headers, body) = capture.recv().expect("captured status");
    assert!(headers.starts_with("POST /api/v1/signup/social/google/status HTTP/1.1"));
    assert!(!headers.contains("private-poll-capability"));
    assert_eq!(
        body,
        json!({"request_id":id,"poll_token":"private-poll-capability"})
    );
    server.join().expect("mock completed");
}

#[tokio::test]
async fn provider_discovery_reports_configuration_and_unknown_providers_fail_before_network() {
    let (client, capture, server) = service(
        json!({"providers":[{"id":"google","enabled":true},{"id":"apple","enabled":false}]}),
    );
    let providers = client.signup().social_providers().await.expect("catalog");
    assert_eq!(providers.providers.len(), 2);
    assert!(!providers.providers[1].enabled);
    assert!(
        capture
            .recv()
            .expect("captured discovery")
            .0
            .starts_with("GET /api/v1/signup/social/providers HTTP/1.1")
    );
    server.join().expect("mock completed");
    assert!(
        client
            .signup()
            .social_start("https://attacker.example", &Mutation::new())
            .await
            .is_err()
    );
}

#[cfg(feature = "cli-session")]
#[tokio::test]
async fn social_login_contract_keeps_proof_in_body_and_link_uses_direct_credential() {
    use silicon_iam_client::Credential;
    let id = Uuid::new_v4();
    let proof = models::SocialSignupStatusInput {
        request_id: id,
        poll_token: "private-poll-proof".to_owned(),
    };
    let (client, capture, server) = service(
        json!({"request_id":id,"authorization_url":"https://appleid.apple.com/auth/authorize","poll_token":"private-poll-proof","expires_at":"2030-01-01T00:00:00Z"}),
    );
    let start = client
        .auth()
        .social_start("apple", &Mutation::new())
        .await
        .expect("start login");
    assert!(!format!("{start:?}").contains("private-poll-proof"));
    let (headers, body) = capture.recv().expect("start request");
    assert!(headers.starts_with("POST /api/v1/login/social/apple/start HTTP/1.1"));
    assert_eq!(body, json!({}));
    server.join().expect("start completed");
    let (client, capture, server) = service(
        json!({"status":"link_required","email":"person@example.test","display_name":null}),
    );
    let status = client
        .auth()
        .social_status("apple", &proof)
        .await
        .expect("poll login");
    assert_eq!(status.status, models::SocialLoginStatusStatus::LinkRequired);
    let (headers, body) = capture.recv().expect("status request");
    assert!(headers.starts_with("POST /api/v1/login/social/apple/status HTTP/1.1"));
    assert!(!headers.contains("private-poll-proof"));
    assert_eq!(
        body,
        json!({"request_id":id,"poll_token":"private-poll-proof"})
    );
    server.join().expect("status completed");
    let (client, capture, server) = service(json!({"linked":true,"provider":"apple"}));
    let result = client
        .with_credential(Credential::bearer("fresh-direct-carbon-token"))
        .auth()
        .social_link("apple", &proof, &Mutation::new())
        .await
        .expect("link");
    assert!(result.linked);
    let (headers, body) = capture.recv().expect("link request");
    assert!(headers.starts_with("POST /api/v1/login/social/apple/link HTTP/1.1"));
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("authorization: bearer fresh-direct-carbon-token")
    );
    assert!(headers.to_ascii_lowercase().contains("idempotency-key:"));
    assert!(!headers.contains("private-poll-proof"));
    assert_eq!(
        body,
        json!({"request_id":id,"poll_token":"private-poll-proof"})
    );
    server.join().expect("link completed");
    assert!(
        client
            .auth()
            .social_status("https://attacker.example", &proof)
            .await
            .is_err()
    );
}

#[cfg(feature = "cli-session")]
#[tokio::test]
async fn social_login_completion_reuses_exact_mutation_and_proof_for_retry() {
    let id = Uuid::new_v4();
    let proof = models::SocialSignupStatusInput {
        request_id: id,
        poll_token: "private-proof".to_owned(),
    };
    let mutation = Mutation::new();
    let response = json!({"access_token":"cat_private","refresh_token":"crt_private","token_type":"Bearer","expires_in":900,"refresh_expires_at":"2030-01-01T00:00:00Z","actor":{"public_id":"c:person","type":"carbon"},"session_id":id});
    let mut first = None;
    for _ in 0..2 {
        let (client, capture, server) = service(response.clone());
        let result = client
            .auth()
            .social_complete("google", &proof, &mutation)
            .await
            .expect("complete provider login");
        assert_eq!(result.access_token, "cat_private");
        let (headers, body) = capture.recv().expect("completion request");
        assert!(headers.starts_with("POST /api/v1/login/social/google/complete HTTP/1.1"));
        assert!(!headers.contains("private-proof"));
        let key = headers
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("idempotency-key:"))
            .expect("key")
            .to_owned();
        let request = (key, body);
        if let Some(expected) = &first {
            assert_eq!(&request, expected);
        } else {
            first = Some(request);
        }
        server.join().expect("complete response");
    }
}
