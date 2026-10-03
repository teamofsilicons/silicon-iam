//! Provider proof is separate from direct OTP authority and never silently creates accounts.
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

fn run_login(responses: Vec<(u16, Value)>) -> (std::process::Output, Vec<(String, Value)>) {
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
        .args(["--url", &url, "--json", "login", "--provider", "google"])
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
fn start(id: uuid::Uuid) -> Value {
    json!({"request_id":id,"authorization_url":"https://accounts.google.com/o/oauth2/v2/auth?state=public-oauth-state","poll_token":"secret-poll-proof","expires_at":"2099-01-01T00:00:00Z"})
}
fn tokens(id: uuid::Uuid) -> Value {
    json!({"access_token":"cat_fresh-otp","refresh_token":"crt_private","token_type":"Bearer","expires_in":900,"refresh_expires_at":"2099-01-01T00:00:00Z","actor":{"type":"carbon","public_id":"c:person"},"session_id":id})
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
fn email_match_requires_fresh_otp_and_link_retry_keeps_code_authority_and_key() {
    let id = uuid::Uuid::new_v4();
    let (result, requests) = run_login(vec![
        (201, start(id)),
        (
            200,
            json!({"status":"link_required","email":"person@example.test"}),
        ),
        (
            201,
            json!({"session_id":id,"expires_at":"2099-01-01T00:00:00Z","local_otp":"123456"}),
        ),
        (200, tokens(id)),
        (
            503,
            json!({"error":{"code":"unavailable","message":"lost response","request_id":"test-request"}}),
        ),
        (200, json!({"linked":true,"provider":"google"})),
        (200, profile()),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(requests.len(), 7);
    assert!(requests[2].0.starts_with("POST /api/v1/login/challenges "));
    assert_eq!(requests[2].1["email"], "person@example.test");
    assert!(requests[3].0.contains("/verify "));
    assert_eq!(requests[3].1, json!({"code":"123456"}));
    for request in [&requests[4], &requests[5]] {
        assert!(
            request
                .0
                .starts_with("POST /api/v1/login/social/google/link ")
        );
        assert!(
            request
                .0
                .to_ascii_lowercase()
                .contains("authorization: bearer cat_fresh-otp")
        );
        assert_eq!(
            request.1,
            json!({"request_id":id,"poll_token":"secret-poll-proof"})
        );
    }
    let key = |headers: &str| {
        headers
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("idempotency-key:"))
            .expect("key")
            .to_owned()
    };
    assert_eq!(key(&requests[4].0), key(&requests[5].0));
    assert!(requests[6].0.starts_with("GET /api/v1/me "));
    assert!(
        requests
            .iter()
            .all(|request| !request.0.contains("/social/google/complete"))
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("cat_fresh-otp"));
}

#[test]
fn linked_provider_completes_with_same_proof_and_key_after_an_uncertain_response() {
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
    assert!(!String::from_utf8_lossy(&result.stdout).contains("cat_fresh-otp"));
}
