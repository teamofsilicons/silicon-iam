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
