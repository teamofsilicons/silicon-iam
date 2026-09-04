//! Organization single sign-on configuration.

use silicon_iam_client::models;

use crate::{
    cli::SsoCommand,
    context::Context,
    error::Result,
    output::{Format, Table, json, json_empty, label, or_dash, timestamp},
};

/// Runs an organization SSO command.
///
/// # Errors
///
/// Returns whatever the service reports.
pub async fn run(context: &Context, command: SsoCommand) -> Result<()> {
    let client = context.authenticated().await?;
    let org = context.organization()?;
    match command {
        SsoCommand::Show => {
            // Distinguish an unknown/inaccessible organization from a real
            // organization that simply has no SSO configuration yet.
            client.organizations().get(org).await?;
            match client.sso().get(org).await {
                Ok(configuration) => report_configuration(context, &configuration),
                Err(error)
                    if error
                        .api()
                        .is_some_and(silicon_iam_client::ApiError::is_not_found) =>
                {
                    report_unconfigured(context);
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        }
        SsoCommand::SetupLink => {
            let setup = client.sso().setup_link(org, &context.mutation()).await?;
            match context.format {
                Format::Json => json(&setup),
                Format::Text => {
                    println!("{}", setup.url);
                    println!("Expires: {}", timestamp(setup.expires_at));
                    Ok(())
                }
            }
        }
        SsoCommand::Test => {
            let result = client.sso().test(org, &context.mutation()).await?;
            match context.format {
                Format::Json => json(&result),
                Format::Text => {
                    println!("SSO check: {}", if result.ok { "ok" } else { "failed" });
                    if let Some(message) = result.message {
                        println!("{message}");
                    }
                    println!("Checked: {}", timestamp(result.checked_at));
                    Ok(())
                }
            }
        }
        SsoCommand::Disable => {
            let current = client.sso().get(org).await?;
            client
                .sso()
                .disable(org, current.version, &context.mutation())
                .await?;
            match context.format {
                Format::Json => {
                    json_empty();
                    Ok(())
                }
                Format::Text => {
                    println!("Disabled SSO for {org}.");
                    Ok(())
                }
            }
        }
    }
}

fn report_unconfigured(context: &Context) {
    match context.format {
        Format::Json => json_empty(),
        Format::Text => {
            println!("SSO is not configured for this organization.");
        }
    }
}

fn report_configuration(context: &Context, configuration: &models::SsoConfiguration) -> Result<()> {
    match context.format {
        Format::Json => json(configuration),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["organization", &configuration.org_id]);
            table.row(["entitled", &configuration.entitled.to_string()]);
            table.row(["status", &label(&configuration.status)]);
            table.row(["join_method", &label(&configuration.join_method)]);
            table.row([
                "workos_organization_id",
                &or_dash(configuration.workos_organization_id.as_deref()),
            ]);
            table.row([
                "connection_id",
                &or_dash(configuration.connection_id.as_deref()),
            ]);
            table.row(["version", &configuration.version.to_string()]);
            table.row(["updated", &timestamp(configuration.updated_at)]);
            table.print();
            Ok(())
        }
    }
}
