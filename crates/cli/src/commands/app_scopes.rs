//! Scope declarations and review discussions.

use silicon_iam_client::models;

use crate::{
    cli::AppScopesCommand,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, label, timestamp},
};

/// Runs a scope discovery or review operation.
///
/// # Errors
/// Returns validation or authorization failures from IAM.
#[allow(
    clippy::too_many_lines,
    reason = "one compact branch per public subcommand"
)]
pub async fn run(context: &Context, command: AppScopesCommand) -> Result<()> {
    let client = context.authenticated().await?;
    let scopes = client.application_scopes();
    match command {
        AppScopesCommand::Catalog { app_id } => {
            let app_id = app_id
                .as_deref()
                .map(|id| context.application_id(id))
                .transpose()?;
            let catalog = scopes.catalog(app_id.as_deref()).await?;
            match context.format {
                Format::Json => json(&catalog),
                Format::Text => {
                    let mut table = Table::new(["scope", "critical", "description"]);
                    for scope in catalog.items {
                        table.row([scope.scope, scope.critical.to_string(), scope.description]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        AppScopesCommand::Requests { status } => {
            let requests = scopes.requests(status.as_deref()).await?;
            report_list(context, &requests)
        }
        AppScopesCommand::Request {
            app_id,
            app_scope,
            message,
        } => {
            nonempty(&message, "--message")?;
            let app_id = context.application_id(&app_id)?;
            let application = client.applications().get(&app_id).await?;
            let requests = scopes
                .request(
                    &app_id,
                    application.version,
                    &models::ApplicationScopeRequestCreate {
                        app_scope: super::app::scope_definition(&app_scope)?,
                        message,
                    },
                    &context.mutation(),
                )
                .await?;
            report_list(context, &requests)
        }
        AppScopesCommand::Show { request_id } => report(context, &scopes.get(request_id).await?),
        AppScopesCommand::Reply {
            request_id,
            message,
        } => {
            nonempty(&message, "--message")?;
            let request = scopes.get(request_id).await?;
            report(
                context,
                &scopes
                    .reply(
                        request_id,
                        request.version,
                        &models::ApplicationScopeMessageCreate { message },
                        &context.mutation(),
                    )
                    .await?,
            )
        }
        AppScopesCommand::Approve { request_id } => {
            let request = scopes.get(request_id).await?;
            report(
                context,
                &scopes
                    .decide(
                        request_id,
                        request.version,
                        &models::ApplicationScopeDecision {
                            decision: models::ApplicationScopeDecisionDecision::Approve,
                            reason: None,
                        },
                        &context.mutation(),
                    )
                    .await?,
            )
        }
        AppScopesCommand::Deny { request_id, reason } => {
            nonempty(&reason, "--reason")?;
            let request = scopes.get(request_id).await?;
            report(
                context,
                &scopes
                    .decide(
                        request_id,
                        request.version,
                        &models::ApplicationScopeDecision {
                            decision: models::ApplicationScopeDecisionDecision::Deny,
                            reason: Some(reason),
                        },
                        &context.mutation(),
                    )
                    .await?,
            )
        }
    }
}

fn nonempty(text: &str, argument: &str) -> Result<()> {
    if text.trim().is_empty() {
        Err(CliError::Usage(format!(
            "{argument} must contain a nonempty explanation"
        )))
    } else {
        Ok(())
    }
}

fn report_list(context: &Context, requests: &models::ApplicationScopeRequestList) -> Result<()> {
    match context.format {
        Format::Json => json(requests),
        Format::Text => {
            let mut table = Table::new(["request", "app", "reviewer", "status", "version"]);
            for request in &requests.items {
                table.row([
                    request.id.to_string(),
                    request.app_id.clone(),
                    request
                        .target_app_id
                        .clone()
                        .unwrap_or_else(|| "IAM".to_owned()),
                    label(&request.status),
                    request.version.to_string(),
                ]);
            }
            table.print();
            Ok(())
        }
    }
}

fn report(context: &Context, request: &models::ApplicationScopeRequest) -> Result<()> {
    match context.format {
        Format::Json => json(request),
        Format::Text => {
            println!(
                "{}: {} ({})",
                request.id,
                request.app_id,
                label(&request.status)
            );
            println!("Scopes: {}", request.scopes.join(", "));
            println!("You may decide: {}", request.can_decide);
            for message in &request.messages {
                println!(
                    "\n{} — {}\n{}",
                    message.author.public_id,
                    timestamp(message.created_at),
                    message.message
                );
            }
            Ok(())
        }
    }
}
