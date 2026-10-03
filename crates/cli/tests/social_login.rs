//! Verified provider email signs in directly; new accounts remain explicit and email OTP stays available.
#![allow(clippy::expect_used)]
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

fn run_auth(
    arguments: &[&str],
    responses: Vec<(u16, Value)>,
) -> (std::process::Output, Vec<(String, Value)>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        for (status, response) in responses {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            let mut stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "missing CLI request");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            stream
                .set_nonblocking(false)
                .expect("blocking accepted stream");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let mut bytes = Vec::new();
            let boundary = loop {
                let mut chunk = [0; 4096];
                let n = stream.read(&mut chunk).expect("read");
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(i) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let headers = String::from_utf8(bytes[..boundary].to_vec()).expect("headers");
            let size = headers
                .lines()
                .find_map(|line| {
                    let (n, v) = line.split_once(':')?;
                    n.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().expect("size"))
                })
                .unwrap_or(0);
            while bytes.len() < boundary + size {
                let mut chunk = [0; 4096];
                let n = stream.read(&mut chunk).expect("body");
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            let body = if size == 0 {
                Value::Null
            } else {
                serde_json::from_slice(&bytes[boundary..boundary + size]).expect("json")
            };
            tx.send((headers, body)).expect("capture");
            let response = response.to_string();
            write!(stream,"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).expect("respond");
        }
    });
    let home = std::env::temp_dir().join(format!("iam-social-login-{}", uuid::Uuid::new_v4()));
    let mut command = Command::new(env!("CARGO_BIN_EXE_iam"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SILICON_") {
            command.env_remove(key);
        }
    }
    let result = command
        .env("SILICON_IAM_HOME", &home)
        .env("SILICON_IAM_AUTO_UPDATE", "off")
        .env("IAM_TELEMETRY", "off")
        .stdin(Stdio::null())
        .args(["--url", &url, "--json"])
        .args(arguments)
        .output()
        .expect("run CLI");
    server.join().unwrap_or_else(|_| {
        panic!(
            "server failed; CLI stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        )
    });
    let requests = rx.try_iter().collect();
    let _ = std::fs::remove_dir_all(home);
    (result, requests)
}
fn run_login(responses: Vec<(u16, Value)>) -> (std::process::Output, Vec<(String, Value)>) {
    run_auth(&["login", "--provider", "google"], responses)
}
fn start(id: uuid::Uuid) -> Value {
    json!({"request_id":id,"authorization_url":"https://accounts.google.com/o/oauth2/v2/auth?state=public-oauth-state","poll_token":"secret-poll-proof","expires_at":"2099-01-01T00:00:00Z"})
}
fn tokens(id: uuid::Uuid) -> Value {
    json!({"access_token":"cat_provider","refresh_token":"crt_private","token_type":"Bearer","expires_in":900,"refresh_expires_at":"2099-01-01T00:00:00Z","actor":{"type":"carbon","public_id":"c:person"},"session_id":id})
}
fn profile() -> Value {
    json!({"carbon_id":"c:person","display_name":"Person","profile_photo":"https://example.test/photo.png","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","timezone":"UTC","email":"person@example.test","phone_number":null,"status":"active","version":1})
}
#[test]
fn new_verified_email_returns_signup_continuation_without_creating_an_account() {
    let id = uuid::Uuid::new_v4();
    let (result, requests) = run_login(vec![
        (201, start(id)),
        (
            200,
            json!({"status":"verified","signup_session_id":id,"email":"new@example.test","display_name":"New Person"}),
        ),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).expect("result");
    assert_eq!(value["authenticated"], false);
    assert_eq!(value["status"], "signup_required");
    assert_eq!(value["signup_session_id"], id.to_string());
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1]
            .0
            .starts_with("POST /api/v1/login/social/google/status ")
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("secret-poll-proof"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-poll-proof"));
}
#[test]
fn both_provider_entrypoints_sign_in_existing_email_without_otp_or_profile_mutation() {
    for provider in ["google", "apple"] {
        for command in ["login", "signup"] {
            let id = uuid::Uuid::new_v4();
            let mut begin = start(id);
            if provider == "apple" {
                begin["authorization_url"] =
                    json!("https://appleid.apple.com/auth/authorize?state=opaque");
            }
            let mut arguments = vec![command, "--provider", provider];
            if command == "signup" {
                arguments.extend(["--display-name", "Must not overwrite"]);
            }
            let (result, requests) = run_auth(
                &arguments,
                vec![
                    (201, begin),
                    (
                        200,
                        json!({"status":"login_ready","email":"person@example.test"}),
                    ),
                    (200, tokens(id)),
                    (200, profile()),
                ],
            );
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let output: Value = serde_json::from_slice(&result.stdout).expect("output");
            if command == "signup" {
                assert_eq!(output["authenticated"], true);
                assert_eq!(output["existing_account"], true);
                assert_eq!(output["profile"]["display_name"], "Person");
            } else {
                assert_eq!(output["display_name"], "Person");
            }
            assert_eq!(requests.len(), 4);
            assert!(
                requests[0]
                    .0
                    .starts_with(&format!("POST /api/v1/login/social/{provider}/start "))
            );
            assert!(
                requests[2]
                    .0
                    .starts_with(&format!("POST /api/v1/login/social/{provider}/complete "))
            );
            assert!(
                requests
                    .iter()
                    .all(|(headers, _)| !headers.contains("/login/challenges")
                        && !headers.contains("/link ")
                        && !headers.contains("/signup/sessions"))
            );
            assert!(!String::from_utf8_lossy(&result.stdout).contains("cat_provider"));
        }
    }
}
#[test]
fn provider_signup_new_email_completes_profile_without_email_otp() {
    let id = uuid::Uuid::new_v4();
    let mut completed = profile();
    for (key, value) in tokens(id).as_object().expect("tokens") {
        completed[key] = value.clone();
    }
    completed["onboarding"] = json!({"requires_organization":true});
    let (result, requests) = run_auth(
        &[
            "signup",
            "--provider",
            "google",
            "--carbon-id",
            "c:person",
            "--timezone",
            "UTC",
        ],
        vec![
            (201, start(id)),
            (
                200,
                json!({"status":"verified","signup_session_id":id,"email":"new@example.test","display_name":"New Person"}),
            ),
            (201, completed),
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(requests.len(), 3);
    assert!(
        requests[2]
            .0
            .starts_with(&format!("POST /api/v1/signup/sessions/{id}/complete "))
    );
    assert_eq!(requests[2].1["display_name"], "New Person");
    assert_eq!(requests[2].1["carbon_id"], "c:person");
    assert!(
        !requests.iter().any(
            |(headers, _)| headers.contains("/email/") || headers.contains("/login/challenges")
        )
    );
    let output: Value = serde_json::from_slice(&result.stdout).expect("output");
    assert_eq!(output["authenticated"], true);
    assert_eq!(output["onboarding"]["requires_organization"], true);
}

#[test]
fn retired_provider_status_restarts_without_sending_otp_or_linking() {
    let id = uuid::Uuid::new_v4();
    let (result, requests) = run_login(vec![
        (201, start(id)),
        (
            200,
            json!({"status":"link_required","email":"person@example.test"}),
        ),
    ]);
    assert!(!result.status.success());
    assert_eq!(requests.len(), 2);
    assert!(String::from_utf8_lossy(&result.stderr).contains("older flow"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-poll-proof"));
}

#[test]
fn ordinary_email_otp_remains_an_independent_sign_in_option() {
    let id = uuid::Uuid::new_v4();
    let (result, requests) = run_auth(
        &["login", "--email", "person@example.test"],
        vec![
            (
                201,
                json!({"session_id":id,"expires_at":"2099-01-01T00:00:00Z","local_otp":"123456"}),
            ),
            (200, tokens(id)),
            (200, profile()),
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(requests.len(), 3);
    assert!(requests[0].0.starts_with("POST /api/v1/login/challenges "));
    assert_eq!(requests[0].1, json!({"email":"person@example.test"}));
    assert_eq!(requests[1].1, json!({"code":"123456"}));
    assert!(
        !requests
            .iter()
            .any(|(headers, _)| headers.contains("/social/"))
    );
}

#[test]
fn verified_email_completes_with_same_proof_and_key_after_an_uncertain_response() {
    let id = uuid::Uuid::new_v4();
    let (result, requests) = run_login(vec![
        (201, start(id)),
        (
            200,
            json!({"status":"login_ready","email":"person@example.test"}),
        ),
        (
            503,
            json!({"error":{"code":"unavailable","message":"lost response","request_id":"test-request"}}),
        ),
        (200, tokens(id)),
        (200, profile()),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(requests.len(), 5);
    for request in [&requests[2], &requests[3]] {
        assert!(
            request
                .0
                .starts_with("POST /api/v1/login/social/google/complete ")
        );
        assert_eq!(
            request.1,
            json!({"request_id":id,"poll_token":"secret-poll-proof"})
        );
        assert!(!request.0.to_ascii_lowercase().contains("authorization:"));
    }
    let key = |headers: &str| {
        headers
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("idempotency-key:"))
            .expect("key")
            .to_owned()
    };
    assert_eq!(key(&requests[2].0), key(&requests[3].0));
    assert!(
        requests
            .iter()
            .all(|request| !request.0.contains("/login/challenges"))
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("cat_provider"));
}
