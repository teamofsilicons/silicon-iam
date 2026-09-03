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
        SystemCommand::Health => health(context).await,
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
    let ready = client.system().readiness().await;
    match context.format {
        Format::Json => json(&serde_json::json!({
            "live": true,
            "ready": ready.is_ok(),
        })),
        Format::Text => {
            println!("live:  yes");
            println!("ready: {}", if ready.is_ok() { "yes" } else { "no" });
            Ok(())
        }
    }
}
