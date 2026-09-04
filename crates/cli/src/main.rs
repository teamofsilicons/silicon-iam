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
mod output;
mod store;

use clap::Parser as _;

use crate::{cli::Cli, context::Context, error::CliError};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            if let Some(hint) = error.hint() {
                eprintln!("hint: {hint}");
            }
            // The correlation identifier is what makes a report actionable on
            // the service side, so it is printed whenever there is one.
            if let CliError::Client(client_error) = &error
                && let Some(request_id) = client_error.request_id()
            {
                eprintln!("request: {request_id}");
            }
            std::process::ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(1))
        }
    }
}

async fn run(cli: Cli) -> error::Result<()> {
    let context = Context::new(
        cli.global.output,
        cli.global.profile,
        cli.global.url,
        cli.global.org,
        cli.global.test,
        cli.global.step_up,
    )?;
    commands::dispatch(&context, cli.command).await
}
