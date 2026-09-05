//! The Silicon IAM command-line client.
//!
//! A thin, stateful shell over `silicon-iam-client`. Everything it can do, the
//! client crate can do; what the CLI adds is memory -- which service, which
//! profile, whose session -- and a terminal to read a verification code from.

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod context;
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
    let maintain_after_command = updater::follows(&cli.command);
    let exit = match run(cli).await {
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
    };
    if maintain_after_command {
        // Publish all result bytes before a registry check or Cargo install.
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        match updater::automatic().await {
            Ok(updater::Outcome::Updated { from, to }) => {
                eprintln!(
                    "Updated iam from {from} to {to} after the command completed. The next invocation will use {to}."
                );
            }
            Ok(_) => {}
            Err(error) => eprintln!("warning: post-command automatic update skipped: {error}"),
        }
    }
    exit
}

async fn run(cli: Cli) -> error::Result<()> {
    // Reference commands must work offline, including with a broken credential
    // store or unavailable service. They never start background maintenance.
    match &cli.command {
        cli::Command::Docs { topic, search } => {
            return manual::run(cli.global.output, topic.as_deref(), search.as_deref());
        }
        cli::Command::Commands => return experience::print_commands(cli.global.output),
        _ => {}
    }
    let context = Context::new(
        cli.global.output,
        cli.global.profile,
        cli.global.url,
        cli.global.org,
        cli.global.no_org,
        cli.global.test,
        cli.global.step_up,
    )?;
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
