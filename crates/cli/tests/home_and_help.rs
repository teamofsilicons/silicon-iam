//! Exercise home selection and offline help through the installed command grammar.

use std::{fs, path::PathBuf, process::Command};

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("iam-home-help-{}", uuid::Uuid::now_v7())))
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_iam"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SILICON_") {
                command.env_remove(key);
            }
        }
        command
            .env("HOME", self.0.join("user"))
            .env("SILICON_IAM_AUTO_UPDATE", "off");
        command
    }

    fn store(command: &mut Command) -> PathBuf {
        let output = command.args(["-o", "json", "config", "show"]).output();
        let output = output.unwrap_or_else(|error| panic!("start CLI: {error}"));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("decode config: {error}"));
        PathBuf::from(value["store"].as_str().unwrap_or_default())
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn silicon_home_replaces_user_home_but_explicit_iam_home_wins() {
    let sandbox = Sandbox::new();
    assert_eq!(
        Sandbox::store(&mut sandbox.command()),
        sandbox.0.join("user/.silicon-iam")
    );
    let base = sandbox.0.join("silicon base");
    assert_eq!(
        Sandbox::store(
            sandbox
                .command()
                .env("SILICON_HOME", &base)
                .env_remove("HOME")
        ),
        base.join(".silicon-iam")
    );
    let exact = sandbox.0.join("exact");
    assert_eq!(
        Sandbox::store(
            sandbox
                .command()
                .env("SILICON_HOME", &base)
                .env("SILICON_IAM_HOME", &exact)
        ),
        exact
    );
}

#[test]
fn configured_home_is_saved_under_the_selected_base() {
    let sandbox = Sandbox::new();
    let base = sandbox.0.join("silicon");
    let selected = sandbox.0.join("selected");
    // Have the CLI create a private store using its normal permissions.
    Sandbox::store(sandbox.command().env("SILICON_IAM_HOME", &selected));
    let output = sandbox
        .command()
        .env("SILICON_HOME", &base)
        .args(["config", "home"])
        .arg(&selected)
        .output()
        .unwrap_or_else(|error| panic!("configure home: {error}"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(base.join(".silicon-iam/.silicon-iam-home").is_file());
    assert!(!sandbox.0.join("user").exists());
    assert_eq!(
        Sandbox::store(sandbox.command().env("SILICON_HOME", &base)),
        selected
    );
    assert_eq!(
        Sandbox::store(&mut sandbox.command()),
        sandbox.0.join("user/.silicon-iam")
    );
    let exact = sandbox.0.join("explicit");
    assert_eq!(
        Sandbox::store(
            sandbox
                .command()
                .env("SILICON_HOME", &base)
                .env("SILICON_IAM_HOME", &exact)
        ),
        exact
    );
    let output = sandbox
        .command()
        .env("SILICON_HOME", &base)
        .args(["config", "home"])
        .arg(base.join("missing"))
        .output()
        .unwrap_or_else(|error| panic!("reject invalid home: {error}"));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a directory"));
    assert_eq!(
        Sandbox::store(sandbox.command().env("SILICON_HOME", &base)),
        selected
    );
}

#[test]
fn full_help_covers_every_command_without_accessing_state() {
    let sandbox = Sandbox::new();
    let run = |args: &[&str]| {
        let output = sandbox
            .command()
            .env("SILICON_HOME", sandbox.0.join("unused"))
            .env("SILICON_IAM_HOME", sandbox.0.join("unavailable"))
            .env("SILICON_IAM_AUTO_UPDATE", "on")
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("read help: {error}"));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("help text: {error}"))
    };
    let help = run(&["--help"]);
    assert_eq!(help, run(&["-h"]));
    let entries: serde_json::Value = serde_json::from_str(&run(&["-o", "json", "commands"]))
        .unwrap_or_else(|error| panic!("command catalog: {error}"));
    let normalized_help = help.split_whitespace().collect::<Vec<_>>().join(" ");
    for entry in entries.as_array().into_iter().flatten() {
        let command = entry["command"].as_str().unwrap_or_default();
        assert!(
            help.contains(&format!("=== {command} ===")),
            "missing {command}"
        );
        assert!(
            normalized_help.contains(
                &entry["help"]
                    .as_str()
                    .unwrap_or_default()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            "incomplete {command}"
        );
    }
    let scoped = run(&["app", "create", "--help"]);
    assert!(scoped.contains("--webhook-secret"));
    assert!(!scoped.contains("=== iam config home ==="));
    assert!(
        !sandbox.0.exists(),
        "reference commands must not create local state"
    );
}

#[test]
fn issuer_discovery_is_offline_and_status_handles_missing_sessions() {
    let sandbox = Sandbox::new();
    let output = sandbox
        .command()
        .env("SILICON_IAM_HOME", "/dev/null/invalid")
        .args(["iam", "--json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(value["credential_issuer"], true);
    assert!(value["app_id"].is_null());
    assert!(
        value["repository"]
            .as_str()
            .unwrap_or_default()
            .ends_with("/silicon-iam")
    );
    let output = sandbox
        .command()
        .args(["login", "status", "--json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(value["authenticated"], false);
    assert!(!sandbox.0.join("user/.silicon-iam/update.json").exists());
}

#[cfg(unix)]
fn private_write(path: &std::path::Path, body: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::write(path, body).unwrap_or_else(|e| panic!("{e}"));
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap_or_else(|e| panic!("{e}"));
}

#[cfg(unix)]
#[test]
fn reports_pass_exact_text_and_pr_to_github_without_collecting_session_data() {
    let sandbox = Sandbox::new();
    let bin = sandbox.0.join("bin");
    fs::create_dir_all(&bin).unwrap_or_else(|e| panic!("{e}"));
    private_write(
        &bin.join("gh"),
        "#!/bin/sh\ncat > \"$CAPTURE_BODY\"\nprintf '%s\\n' \"$@\" > \"$CAPTURE_ARGS\"\nprintf '%s\\n' 'https://github.com/teamofsilicons/silicon-iam/issues/42'\n",
        0o700,
    );
    let message = "Login fails\nSteps: literal $(secret) and `code`";
    let body = sandbox.0.join("body");
    let args = sandbox.0.join("args");
    let mut command = sandbox.command();
    command
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("CAPTURE_BODY", &body)
        .env("CAPTURE_ARGS", &args)
        .env("ISI", "must-not-collect")
        .env("SILICON_IAM_SECRET", "must-not-collect");
    let output = command
        .args([
            "report",
            message,
            "--pr",
            "https://github.com/teamofsilicons/silicon-iam/pull/5",
            "--json",
        ])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let submitted = fs::read_to_string(body).unwrap_or_else(|e| panic!("{e}"));
    assert!(submitted.starts_with(message));
    assert!(submitted.contains("/pull/5"));
    assert!(!submitted.contains("must-not-collect"));
    let args = fs::read_to_string(args).unwrap_or_else(|e| panic!("{e}"));
    assert!(args.ends_with("--body-file\n-\n"));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(value["submitted"], true);
    assert!(value["hint"].is_null());
}

#[cfg(unix)]
#[test]
fn status_checks_the_server_and_does_not_turn_outages_into_logout() {
    use std::{
        io::{Read as _, Write as _},
        net::TcpListener,
    };
    for status in [200, 401, 503] {
        let sandbox = Sandbox::new();
        let store = Sandbox::store(&mut sandbox.command());
        let credentials = serde_json::json!({"sessions":{"default":{
            "access_token":"sat_test", "refresh_token":"rft_test",
            "expires_at":"2099-01-01T00:00:00Z", "actor_type":"carbon", "actor_id":"alice"
        }}});
        private_write(
            &store.join("credentials.json"),
            &credentials.to_string(),
            0o600,
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
        let address = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap_or_else(|e| panic!("{e}"));
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap_or_else(|e| panic!("{e}"));
            let mut request = Vec::new();
            loop {
                let mut buf = [0; 4096];
                let n = stream.read(&mut buf).unwrap_or_else(|e| panic!("{e}"));
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /api/v1/me "));
            assert!(
                request
                    .to_lowercase()
                    .contains("authorization: bearer sat_test")
            );
            let body = if status == 200 {
                serde_json::json!({"principal_id":uuid::Uuid::from_u128(1), "carbon_id":"alice", "display_name":"Alice", "profile_photo":"https://example.com/avatar", "created_at":"2026-01-01T00:00:00Z", "updated_at":"2026-01-01T00:00:00Z", "timezone":"UTC", "email":"alice@example.com", "phone_number":"+14155550123", "status":"active", "version":1})
            } else { serde_json::json!({"error":{"code":"test_failure", "message":"Test failure"}}) }.to_string();
            write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap_or_else(|e| panic!("{e}"));
        });
        let output = sandbox
            .command()
            .args([
                "--url",
                &format!("http://{address}"),
                "login",
                "status",
                "--json",
            ])
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        server.join().unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            output.status.success(),
            status != 503,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if status != 503 {
            let value: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(value["authenticated"], status == 200);
            assert!(!String::from_utf8_lossy(&output.stdout).contains("sat_test"));
        }
    }
}

#[test]
fn daemon_runs_without_login_and_excludes_duplicate_workers() {
    struct Worker(std::process::Child);
    impl Drop for Worker {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let sandbox = Sandbox::new();
    let mut worker = Worker(
        sandbox
            .command()
            .args(["daemon", "run"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("{e}")),
    );
    let mut running = false;
    for _ in 0..40 {
        let output = sandbox
            .command()
            .args(["daemon", "status", "--json"])
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}"));
        if value["running"] == true {
            running = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(running);
    let output = sandbox
        .command()
        .args(["daemon", "run"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(output.status.success());
    assert!(
        worker
            .0
            .try_wait()
            .unwrap_or_else(|e| panic!("{e}"))
            .is_none()
    );
    assert!(
        !sandbox.0.join("user/.silicon-iam/update.json").exists(),
        "opt-out must not query or reserve registry checks"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn service_installation_preserves_selected_home_and_uninstalls_cleanly() {
    let sandbox = Sandbox::new();
    let store = Sandbox::store(&mut sandbox.command());
    let bin = sandbox.0.join("bin");
    fs::create_dir_all(&bin).unwrap_or_else(|e| panic!("{e}"));
    for program in ["launchctl", "systemctl"] {
        private_write(
            &bin.join(program),
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$SERVICE_CALLS\"\n",
            0o700,
        );
    }
    let calls = sandbox.0.join("calls");
    let output = sandbox
        .command()
        .env("XDG_CONFIG_HOME", sandbox.0.join("user/.config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("SERVICE_CALLS", &calls)
        .args(["daemon", "install", "--json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}"));
    let path = PathBuf::from(result["service_file"].as_str().unwrap_or_default());
    let definition = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{e}"));
    assert!(definition.contains("SILICON_IAM_HOME"));
    assert!(
        definition.contains(
            &fs::canonicalize(store)
                .unwrap_or_else(|e| panic!("{e}"))
                .to_string_lossy()
                .to_string()
        )
    );
    assert!(!definition.contains("SERVICE_CALLS"));
    if cfg!(target_os = "macos") {
        let parsed = Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            parsed.status.success(),
            "{}",
            String::from_utf8_lossy(&parsed.stdout)
        );
    }
    let output = sandbox
        .command()
        .env("XDG_CONFIG_HOME", sandbox.0.join("user/.config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("SERVICE_CALLS", &calls)
        .args(["daemon", "uninstall", "--json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!path.exists());
    let calls = fs::read_to_string(calls).unwrap_or_else(|e| panic!("{e}"));
    assert!(calls.contains(if cfg!(target_os = "macos") {
        "bootstrap"
    } else {
        "enable"
    }));
    assert!(calls.contains(if cfg!(target_os = "macos") {
        "bootout"
    } else {
        "disable"
    }));
}

#[test]
fn telemetry_settings_default_on_and_can_be_persistently_disabled() {
    let sandbox = Sandbox::new();
    let config = sandbox
        .command()
        .args(["config", "show", "--json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let value: serde_json::Value =
        serde_json::from_slice(&config.stdout).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(value["telemetry"], true);
    let off = sandbox
        .command()
        .args(["config", "set", "telemetry", "off", "--json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        off.status.success(),
        "{}",
        String::from_utf8_lossy(&off.stderr)
    );
    let config = sandbox
        .command()
        .args(["config", "show", "--json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let value: serde_json::Value =
        serde_json::from_slice(&config.stdout).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(value["telemetry"], false);
    assert_eq!(value["telemetry_effective"], false);
    assert!(!sandbox.0.join("user/.silicon-iam/telemetry-spool").exists());
    let reset = sandbox
        .command()
        .args(["config", "unset", "telemetry", "--json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(reset.status.success());
}
