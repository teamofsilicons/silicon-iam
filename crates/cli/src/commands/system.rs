//! The service itself.

use crate::{
    cli::SystemCommand,
    context::Context,
    error::Result,
    output::{Format, Table, json, plain},
};

/// Runs a system command.
///
/// # Errors
///
/// Returns an error when the service cannot be reached.
pub async fn run(context: &Context, command: SystemCommand) -> Result<()> {
    match command {
        SystemCommand::Version => version(context).await,
        SystemCommand::Update => update(context).await,
        SystemCommand::Health => health(context).await,
    }
}

async fn update(context: &Context) -> Result<()> {
    let outcome = crate::updater::update_now().await?;
    match context.format {
        Format::Json => json(&match outcome {
            crate::updater::Outcome::Current { version } => serde_json::json!({
                "updated": false,
                "current_version": version.to_string(),
                "latest_version": version.to_string(),
            }),
            crate::updater::Outcome::Updated { from, to } => serde_json::json!({
                "updated": true,
                "current_version": from.to_string(),
                "latest_version": to.to_string(),
                "restart_required": true,
            }),
            crate::updater::Outcome::Skipped => serde_json::json!({
                "updated": false,
            }),
        }),
        Format::Text => {
            match outcome {
                crate::updater::Outcome::Current { version } => {
                    println!("iam {version} is current.");
                }
                crate::updater::Outcome::Updated { from, to } => {
                    println!("Updated iam from {from} to {to}. Run iam again to use it.");
                }
                crate::updater::Outcome::Skipped => {}
            }
            Ok(())
        }
    }
}

async fn version(context: &Context) -> Result<()> {
    let client = context.anonymous();
    let negotiated = client.system().negotiate().await?;
    match context.format {
        Format::Json => json(&negotiated),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["service", &plain(&negotiated.service)]);
            table.row(["api_version", &negotiated.selected_api_version]);
            table.row(["build", &negotiated.build]);
            table.row(["commit", &negotiated.commit]);
            table.row(["client", env!("CARGO_PKG_VERSION")]);
            table.print();
            Ok(())
        }
    }
}

async fn health(context: &Context) -> Result<()> {
    let client = context.anonymous();
    client.system().liveness().await?;
    // Liveness only says the process answered. Readiness is the one that
    // matters before pointing anything at it.
    client.system().readiness().await?;
    match context.format {
        Format::Json => json(&serde_json::json!({
            "live": true,
            "ready": true,
        })),
        Format::Text => {
            println!("live:  yes");
            println!("ready: yes");
            Ok(())
        }
    }
}
