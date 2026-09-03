//! Applications.

use silicon_iam_client::models;

use crate::{
    cli::AppCommand,
    commands::silicon::dead_letters,
    context::Context,
    error::Result,
    output::{Format, Table, json, or_dash, timestamp},
};

/// Runs an application command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting them would only move the match elsewhere"
)]
pub async fn run(context: &Context, command: AppCommand) -> Result<()> {
    let client = context.authenticated().await?;
    match command {
        AppCommand::List { status, page } => {
            let listed = client
                .applications()
                .list(status.as_deref(), &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["app", "name", "status", "org", "version"]);
                    for app in &listed.items {
                        table.row([
                            app.app_id.clone(),
                            or_dash(app.app_name.as_deref()),
                            format!("{:?}", app.status).to_lowercase(),
                            app.org_id.clone(),
                            app.version.to_string(),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        AppCommand::Create {
            app_id,
            name,
            org,
            scopes,
            webhook_url,
            redirect_uri,
        } => {
            let organization = context.organization_or(org.as_deref())?;
            let created = client
                .applications()
                .create(
                    &models::ApplicationCreate {
                        app_id,
                        org_id: organization.to_owned(),
                        app_name: Some(name),
                        app_logo: None,
                        redirect_uris: redirect_uri,
                        webhook_url,
                        requested_scopes: scopes,
                        obo_endpoints: None,
                    },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&created),
                Format::Text => {
                    println!("Created {}.", created.application.app_id);
                    println!("Client secret: {}", created.app_secret);
                    println!("Webhook signing secret: {}", created.webhook_signing_secret);
                    println!("Both are shown once. Store them now; they can only be rotated.");
                    println!("The application is under review until the platform verifies it.");
                    Ok(())
                }
            }
        }
        AppCommand::Show { app_id } => {
            let application = client.applications().get(&app_id).await?;
            report(context, &application)
        }
        AppCommand::Update { app_id, name } => {
            let current = client.applications().get(&app_id).await?;
            let updated = client
                .applications()
                .update(
                    &app_id,
                    current.version,
                    &models::ApplicationPatch {
                        app_name: name,
                        app_logo: None,
                        redirect_uris: None,
                        requested_scopes: None,
                        obo_endpoints: None,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &updated)
        }
        AppCommand::RotateSecret { app_id } => {
            let current = client.applications().get(&app_id).await?;
            let rotated = client
                .applications()
                .rotate_secret(&app_id, current.version, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&rotated),
                Format::Text => {
                    println!("Client secret: {}", rotated.app_secret);
                    println!("The previous one stopped working.");
                    Ok(())
                }
            }
        }
        AppCommand::Redirects { app_id, page } => {
            let listed = client
                .applications()
                .redirect_uris(&app_id, &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["id", "uri", "status"]);
                    for entry in &listed.items {
                        table.row([
                            entry.id.to_string(),
                            entry.redirect_uri.clone(),
                            format!("{:?}", entry.status).to_lowercase(),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        AppCommand::AddRedirect { app_id, uri } => {
            let current = client.applications().get(&app_id).await?;
            let added = client
                .applications()
                .add_redirect_uri(
                    &app_id,
                    current.version,
                    &models::ApplicationRedirectUriCreate { redirect_uri: uri },
                    &context.mutation(),
                )
                .await?;
            json(&added)
        }
        AppCommand::RetireRedirect {
            app_id,
            redirect_uri_id,
        } => {
            let current = client.applications().get(&app_id).await?;
            let retired = client
                .applications()
                .retire_redirect_uri(
                    &app_id,
                    redirect_uri_id,
                    current.version,
                    &context.mutation(),
                )
                .await?;
            json(&retired)
        }
        AppCommand::Webhook { app_id } => {
            let webhook = client.applications().webhook(&app_id).await?;
            json(&webhook)
        }
        AppCommand::SetWebhook { app_id, url } => {
            let current = client.applications().get(&app_id).await?;
            let proposed = client
                .applications()
                .replace_webhook(
                    &app_id,
                    current.version,
                    &models::ApplicationWebhookReplace { url },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&proposed),
                Format::Text => {
                    println!("Proposed. The service verifies the endpoint before activating it.");
                    Ok(())
                }
            }
        }
        AppCommand::DeadLetters { app_id, page } => {
            let listed = client
                .applications()
                .dead_letters(&app_id, &page.paging())
                .await?;
            dead_letters(context, &listed)
        }
        AppCommand::Replay { app_id, deliveries } => {
            let replayed = client
                .applications()
                .replay_dead_letters(
                    &app_id,
                    &models::WebhookReplayRequest {
                        delivery_ids: deliveries,
                    },
                    &context.mutation(),
                )
                .await?;
            json(&replayed)
        }
        AppCommand::History { app_id, page } => {
            let listed = client
                .applications()
                .login_history(&app_id, &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["when", "event", "carbon"]);
                    for event in &listed.items {
                        table.row([
                            timestamp(event.occurred_at),
                            format!("{:?}", event.event_type).to_lowercase(),
                            event.actor.public_id.clone(),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
    }
}

fn report(context: &Context, application: &models::Application) -> Result<()> {
    match context.format {
        Format::Json => json(application),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["app", &application.app_id]);
            table.row(["name", &or_dash(application.app_name.as_deref())]);
            table.row([
                "status",
                &format!("{:?}", application.status).to_lowercase(),
            ]);
            table.row(["org", &application.org_id]);
            table.row(["scopes", &application.approved_scopes.join(", ")]);
            table.row(["version", &application.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}
