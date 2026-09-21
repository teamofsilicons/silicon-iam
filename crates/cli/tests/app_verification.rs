//! Exercise app identity issuance and receiver authentication through the executable.

#![allow(clippy::expect_used)]

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

use serde_json::{Value, json};

struct Store(PathBuf);

impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("iam-app-verification-{}", uuid::Uuid::now_v7())))
    }

    fn command(&self, url: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_iam"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SILICON_") {
                command.env_remove(key);
            }
        }
        command
            .env("SILICON_IAM_HOME", &self.0)
            .env("IAM_TELEMETRY", "off")
            .stdin(Stdio::null())
            .args(["--url", url, "--json", "app", "verification"]);
        command
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn service(
    status: u16,
    response: Value,
) -> (
    String,
    mpsc::Receiver<(String, Value)>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock service");
    let address = listener.local_addr().expect("service address");
    let (send, receive) = mpsc::channel();
    let task = thread::spawn(move || {
        let (mut connection, _) = listener.accept().expect("accept app request");
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut request = Vec::new();
        let boundary = loop {
            let mut bytes = [0; 4096];
            let count = connection.read(&mut bytes).expect("read headers");
            assert!(count > 0);
            request.extend_from_slice(&bytes[..count]);
            if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(request[..boundary].to_vec()).expect("HTTP headers");
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("body length"))
            })
            .expect("JSON body length");
        while request.len() - boundary < length {
            let mut bytes = [0; 4096];
            let count = connection.read(&mut bytes).expect("read body");
            assert!(count > 0);
            request.extend_from_slice(&bytes[..count]);
        }
        let body =
            serde_json::from_slice(&request[boundary..boundary + length]).expect("JSON body");
        send.send((headers, body)).expect("capture request");
        let body = response.to_string();
        write!(connection, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("respond");
    });
    (format!("http://{address}"), receive, task)
}

#[test]
fn issue_prints_the_key_without_requiring_or_storing_a_user_session() {
    let store = Store::new();
    let issued = json!({
        "app_id":"acme>checkout", "app_access_key":"aak_cli_generated_key",
        "valid_till":"2026-09-22T00:05:00Z"
    });
    let (url, captured, task) = service(200, issued.clone());
    let output = store
        .command(&url)
        .args([
            "issue",
            "acme>checkout",
            "--ttl-seconds",
            "60",
            "--app-secret",
            "ask_issuer",
        ])
        .output()
        .expect("run CLI");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (headers, body) = captured
        .recv_timeout(Duration::from_secs(5))
        .expect("request");
    assert!(headers.starts_with("POST /api/v1/app-verification/keys "));
    assert!(headers.contains("authorization: Basic YWNtZT5jaGVja291dDphc2tfaXNzdWVy\r\n"));
    assert_eq!(body, json!({"ttl_seconds":60}));
    let result: Value = serde_json::from_slice(&output.stdout).expect("issued JSON");
    assert_eq!(result["app_access_key"], issued["app_access_key"]);
    assert_eq!(result["app_id"], issued["app_id"]);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("aak_cli_generated_key"));
    assert!(!store.0.join("credentials.json").exists());
    task.join().expect("server finished");
}

#[test]
fn verify_uses_the_receiver_and_keeps_invalid_keys_distinct_from_authentication_errors() {
    for valid in [Some(true), Some(false), None] {
        let store = Store::new();
        let response = match valid {
            Some(true) => {
                json!({"valid_key":true,"app_id":"acme>checkout","valid_till":"2026-09-22T00:05:00Z"})
            }
            Some(false) => json!({"valid_key":false}),
            None => {
                json!({"error":{"code":"unauthorized","message":"Invalid application credentials"}})
            }
        };
        let (url, captured, task) = service(if valid.is_some() { 200 } else { 401 }, response);
        let output = store
            .command(&url)
            .args([
                "verify",
                "acme>checkout",
                "--as-app-id",
                "vendor>billing",
                "--app-secret",
                "ask_receiver",
                "--app-access-key",
                "aak_caller_key",
            ])
            .output()
            .expect("run CLI");
        assert_eq!(
            output.status.success(),
            valid.is_some(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (headers, body) = captured
            .recv_timeout(Duration::from_secs(5))
            .expect("request");
        assert!(headers.starts_with("POST /api/v1/app-verification/verify "));
        assert!(headers.contains("authorization: Basic dmVuZG9yPmJpbGxpbmc6YXNrX3JlY2VpdmVy\r\n"));
        assert_eq!(
            body,
            json!({"app_id":"acme>checkout","app_access_key":"aak_caller_key"})
        );
        if let Some(valid) = valid {
            let result: Value = serde_json::from_slice(&output.stdout).expect("verification JSON");
            assert_eq!(result["valid_key"], valid);
            if !valid {
                assert_eq!(result, json!({"valid_key":false}));
            }
        }
        for secret in ["aak_caller_key", "ask_receiver"] {
            assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
            assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
        }
        assert!(!store.0.join("credentials.json").exists());
        task.join().expect("server finished");
    }
}
