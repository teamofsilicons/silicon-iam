//! The Silicon IAM command-line client.
//!
//! A thin, stateful shell over `silicon-iam-client`. Everything it can do, the
//! client crate can do; what the CLI adds is memory -- which service, which
//! profile, whose session -- and a terminal to read a verification code from.

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod context;
mod daemon;
mod error;
mod experience;
mod guidance;
mod manual;
mod output;
mod store;
mod updater;

use crate::{cli::Cli, context::Context};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let (cli, path) = match experience::parse() {
        Ok(parsed) => parsed,
        Err(exit) => return exit,
    };
    let observed = !matches!(
        &cli.command,
        cli::Command::Docs { .. }
            | cli::Command::Commands
            | cli::Command::Iam
            | cli::Command::Config(_)
            | cli::Command::Daemon(cli::DaemonCommand::Run)
    );
    let telemetry = observed
        .then(|| store::load_config().ok())
        .flatten()
        .and_then(|config| {
            silicon_iam_client::telemetry::Telemetry::from_env(
                if matches!(&cli.command, cli::Command::Daemon(_)) {
                    "iam-daemon"
                } else {
                    "iam-cli"
                },
                config.telemetry,
            )
            .ok()
            .flatten()
        });
    let invocation_id = uuid::Uuid::now_v7();
    let started = std::time::Instant::now();
    if let Some(telemetry) = &telemetry {
        telemetry.record(
            "command",
            "command.started",
            serde_json::json!({"command":path.join(" "), "invocation_id":invocation_id}),
        );
    }
    let result = run(cli).await;
    if let Some(telemetry) = &telemetry {
        telemetry.record("command", "command.completed", serde_json::json!({"command":path.join(" "), "invocation_id":invocation_id, "success":result.is_ok(), "exit_code":result.as_ref().err().map_or(0, error::CliError::exit_code), "duration_ms":u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)}));
        let _ = telemetry.flush();
    }
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let message = error.to_string();
            eprintln!("error: {message}");
            if let Some(hint) = error.hint() {
                eprintln!("hint: {hint}");
            }
            if matches!(error, error::CliError::Usage(_)) {
                experience::print_help(&path);
            } else {
                eprintln!("help: iam {} --help", path.join(" "));
            }
            // The correlation identifier makes failures actionable server-side.
            if let Some(request_id) = error.request_id()
                && !message.contains(request_id)
            {
                eprintln!("request: {request_id}");
            }
            std::process::ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(1))
        }
    }
}

async fn run(mut cli: Cli) -> error::Result<()> {
    if cli.global.json {
        cli.global.output = output::Format::Json;
    }
    // Discovery, reports and daemon lifecycle do not need an IAM session.
    // Reference commands also remain usable with a broken credential store.
    match &cli.command {
        cli::Command::Iam => return commands::discovery::run(cli.global.output),
        cli::Command::Daemon(command) => return daemon::run(command, cli.global.output).await,
        cli::Command::Report { message, pr } => {
            return commands::discovery::report(cli.global.output, message, pr.as_deref());
        }
        cli::Command::Docs { topic, search } => {
            return manual::run(cli.global.output, topic.as_deref(), search.as_deref());
        }
        cli::Command::Commands => return experience::print_commands(cli.global.output),
        _ => {}
    }
    let requested_profile = cli
        .global
        .profile
        .clone()
        .or_else(|| std::env::var("SILICON_IAM_PROFILE").ok());
    let requested_environment = cli.global.test;
    let context = Context::new(
        cli.global.output,
        cli.global.profile,
        cli.global.url,
        cli.global.org,
        cli.global.no_org,
        cli.global.test,
        cli.global.step_up,
    )
    .inspect_err(|_| {
        // Stored defaults may be unreadable. Report only what is known from
        // this invocation, never guessed settings or credential-bearing argv.
        eprintln!(
            "Context setup failed before the command ran: requested profile={}, environment={}",
            requested_profile
                .as_deref()
                .unwrap_or("(configured/default; unresolved)"),
            requested_environment
                .map_or_else(|| "production".to_owned(), |id| format!("test {id}")),
        );
    })?;
    let guidance = guidance::Plan::capture(&context, &cli.command);
    match commands::dispatch(&context, cli.command).await {
        Ok(()) => {
            guidance.emit();
            Ok(())
        }
        Err(error) => {
            eprintln!(
                "Context: profile={}, service={}, environment={}, organization={}",
                context.profile_name,
                context.profile.url,
                context
                    .testing_environment_id()
                    .map_or_else(|| "production".to_owned(), |id| format!("test {id}")),
                context.organization_if_set().unwrap_or("(none)"),
            );
            Err(error)
        }
    }
}
