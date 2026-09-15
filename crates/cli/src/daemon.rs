//! A per-user supervisor keeps hourly maintenance alive without CLI activity.
use crate::{
    cli::DaemonCommand,
    error::{CliError, Result},
    output::{Format, json},
    store,
};
use std::fmt::Write as _;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

const LABEL: &str = "com.teamofsilicons.iam-updater";

pub fn run(command: &DaemonCommand, format: Format) -> Result<()> {
    match command {
        DaemonCommand::Run => worker(),
        DaemonCommand::Check => Ok(()),
        DaemonCommand::Install => install(format),
        DaemonCommand::Uninstall => uninstall(format),
        DaemonCommand::Status => {
            let running = store::try_lock_daemon()?.is_none();
            let state = store::load_update_state()?;
            let enabled = false;
            match format {
                Format::Json => json(
                    &serde_json::json!({"running": running, "auto_update": enabled, "update_manager": "honeycomb", "last_check": state.checked_at, "home": store::home()?}),
                ),
                Format::Text => {
                    println!(
                        "IAM daemon running: {running}\nIAM automatic updates: {enabled} (managed by Honeycomb)\nHome: {}",
                        store::home()?.display()
                    );
                    Ok(())
                }
            }
        }
    }
}

fn worker() -> Result<()> {
    let Some(_lock) = store::try_lock_daemon()? else {
        return Ok(());
    };
    // Keep the recording daemon alive between short-lived CLI/update children.
    // It can replay their durable spool even while no commands are being run.
    let mut telemetry: Option<silicon_iam_client::telemetry::Telemetry> = None;
    loop {
        let enabled =
            store::load_config().is_ok_and(|c| silicon_iam_client::telemetry::enabled(c.telemetry));
        if !enabled && telemetry.is_some() {
            // Space Station's in-process sender outlives its client handle.
            // Exit so the supervisor restarts with collection disabled.
            return Ok(());
        } else if enabled && telemetry.is_none() {
            telemetry = silicon_iam_client::telemetry::Telemetry::from_env("iam-daemon", true)
                .ok()
                .flatten();
            if let Some(sender) = &telemetry {
                sender.record("lifecycle", "daemon.started", serde_json::json!({}));
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

fn user_home() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| CliError::Config("HOME is required to install an operating-system user service; use `iam daemon run` with your own supervisor instead.".into()))
}

fn service_path() -> Result<PathBuf> {
    let home = user_home()?;
    match std::env::consts::OS {
        "macos" => Ok(home.join("Library/LaunchAgents").join(format!("{LABEL}.plist"))),
        "linux" => Ok(std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| home.join(".config"), PathBuf::from).join("systemd/user/silicon-iam-updater.service")),
        _ => Err(CliError::Usage("Automatic service installation supports macOS and Linux. Run `iam daemon run` with your OS process supervisor on this platform.".into())),
    }
}

fn checked(program: &str, args: &[&str]) -> Result<()> {
    let result = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if !result.status.success() {
        return Err(CliError::Config(format!(
            "{program} {} failed: {}. Ensure a logged-in user service manager is available, or supervise `iam daemon run` directly.",
            args.join(" "),
            String::from_utf8_lossy(&result.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn domain() -> String {
    format!("gui/{}", rustix::process::getuid().as_raw())
}
#[cfg(not(unix))]
fn domain() -> String {
    String::new()
}

fn install(format: Format) -> Result<()> {
    let path = service_path()?;
    let executable = std::env::current_exe()?;
    // Validate/create the private store before registering a service.
    let _config = store::load_config()?;
    let home = std::fs::canonicalize(store::home()?)?;
    // Anchor this service to the explicitly selected store; never persist auth
    // tokens, app secrets or unrelated environment variables in its definition.
    let mut environment = vec![(
        "SILICON_IAM_HOME".to_owned(),
        home.to_string_lossy().into_owned(),
    )];
    for key in [
        "PATH",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "IAM_TELEMETRY",
        "IAM_TELEMETRY_KEY_FILE",
        "IAM_TELEMETRY_URL",
        "IAM_TELEMETRY_HOME",
    ] {
        if let Ok(value) = std::env::var(key) {
            environment.push((key.to_owned(), value));
        }
    }
    let contents = service_definition(
        &executable.to_string_lossy(),
        &environment,
        cfg!(target_os = "macos"),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    if cfg!(target_os = "macos") {
        let domain = domain();
        let target = format!("{domain}/{LABEL}");
        let _ = Command::new("launchctl")
            .args(["bootout", &target])
            .output();
        checked("launchctl", &["enable", &target])?;
        checked(
            "launchctl",
            &["bootstrap", &domain, &path.to_string_lossy()],
        )?;
    } else {
        checked("systemctl", &["--user", "daemon-reload"])?;
        checked(
            "systemctl",
            &["--user", "enable", "--now", "silicon-iam-updater.service"],
        )?;
        checked(
            "systemctl",
            &["--user", "restart", "silicon-iam-updater.service"],
        )?;
    }
    report(format, "installed", &path)
}

fn uninstall(format: Format) -> Result<()> {
    let path = service_path()?;
    if path.exists() {
        if cfg!(target_os = "macos") {
            let target = format!("{}/{LABEL}", domain());
            checked("launchctl", &["bootout", &target])?;
        } else {
            checked(
                "systemctl",
                &["--user", "disable", "--now", "silicon-iam-updater.service"],
            )?;
        }
        std::fs::remove_file(&path)?;
        if cfg!(target_os = "linux") {
            checked("systemctl", &["--user", "daemon-reload"])?;
        }
    }
    report(format, "uninstalled", &path)
}

fn report(format: Format, action: &str, path: &std::path::Path) -> Result<()> {
    match format {
        Format::Json => json(&serde_json::json!({"action": action, "service_file": path})),
        Format::Text => {
            println!("Updater {action}: {}", path.display());
            Ok(())
        }
    }
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn systemd_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
fn service_definition(executable: &str, environment: &[(String, String)], macos: bool) -> String {
    if macos {
        let mut env = String::new();
        for (k, v) in environment {
            let _ = write!(env, "<key>{}</key><string>{}</string>", xml(k), xml(v));
        }
        let log = environment
            .iter()
            .find(|(k, _)| k == "SILICON_IAM_HOME")
            .map_or_else(String::new, |(_, v)| {
                format!(
                    "<key>StandardErrorPath</key><string>{}/updater.log</string>",
                    xml(v)
                )
            });
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{LABEL}</string><key>ProgramArguments</key><array><string>{}</string><string>daemon</string><string>run</string></array><key>EnvironmentVariables</key><dict>{env}</dict>{log}<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>60</integer></dict></plist>\n",
            xml(executable)
        )
    } else {
        let mut env = String::new();
        for (k, v) in environment {
            let _ = writeln!(env, "Environment={}", systemd_quote(&format!("{k}={v}")));
        }
        // ExecStart expands dollars, whereas Environment= does not.
        let executable = systemd_quote(executable).replace('$', "$$");
        format!(
            "[Unit]\nDescription=Silicon IAM hourly updater\n[Service]\nExecStart={executable} daemon run\n{env}Restart=always\nRestartSec=60\n[Install]\nWantedBy=default.target\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::service_definition;
    #[test]
    fn service_paths_are_escaped_and_both_supervisors_restart_workers() {
        let environment = vec![("SILICON_IAM_HOME".into(), "/tmp/a & b".into())];
        let mac = service_definition("/tmp/a & b/iam", &environment, true);
        assert!(mac.contains("/tmp/a &amp; b/iam"));
        assert!(mac.contains("<key>KeepAlive</key><true/>"));
        let linux = service_definition("/tmp/a % $x/iam", &environment, false);
        assert!(linux.contains("ExecStart=\"/tmp/a %% $$x/iam\" daemon run"));
        assert!(linux.contains("Restart=always"));
    }
}
