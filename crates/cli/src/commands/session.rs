//! Your own sessions and login history.

use crate::{
    cli::SessionCommand,
    context::Context,
    error::Result,
    output::{Format, Table, json, or_dash, timestamp},
};

/// Runs a session command.
///
/// # Errors
///
/// Returns whatever the service reports.
pub async fn run(context: &Context, command: SessionCommand) -> Result<()> {
    let client = context.authenticated().await?;
    match command {
        SessionCommand::List(page) => {
            let listed = client.carbons().sessions(&page.paging()).await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["session", "status", "created", "last seen"]);
                    for session in &listed.items {
                        table.row([
                            session.session_id.to_string(),
                            format!("{:?}", session.status).to_lowercase(),
                            timestamp(session.created_at),
                            timestamp(session.last_used_at),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        SessionCommand::Revoke { session_id } => {
            client
                .carbons()
                .revoke_session(session_id, &context.mutation())
                .await?;
            println!("Revoked {session_id}.");
            Ok(())
        }
        SessionCommand::History(page) => {
            let listed = client.carbons().login_history(&page.paging()).await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["when", "event", "outcome", "application"]);
                    for event in &listed.items {
                        table.row([
                            timestamp(event.occurred_at),
                            format!("{:?}", event.event_type).to_lowercase(),
                            if event.success { "ok" } else { "failed" }.to_owned(),
                            or_dash(event.app_id.as_deref()),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
    }
}
