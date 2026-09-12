//! Application-initiated isolated environments.

use silicon_iam_client::models;

use crate::{
    cli::AppTestingCommand,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, next_cursor, timestamp},
};

/// Runs an application test environment operation using production app credentials.
///
/// # Errors
/// Returns errors for invalid app credentials, test keys, or environment configuration.
pub async fn run(context: &Context, command: AppTestingCommand) -> Result<()> {
    if context.testing_environment_id().is_some() {
        return Err(CliError::Usage("Application testing management uses production credentials. Omit --test; pass --iam-test-key to attach to an existing environment.".to_owned()));
    }
    match command {
        AppTestingCommand::Create {
            app_id,
            name,
            description,
            iam_test_key,
            app_secret,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = super::app::prompted(
                app_secret,
                "Production application secret: ",
                "--app-secret",
            )?;
            let result = super::app::application_client(context, &app_id, &secret)
                .applications()
                .create_testing_environment(
                    &models::ApplicationTestingEnvironmentCreate {
                        name,
                        description,
                        iam_test_key,
                    },
                    &context.mutation(),
                )
                .await?;
            context
                .remember_testing_environment(result.environment_id, result.iam_test_key.clone())?;
            match context.format {
                Format::Json => json(&result),
                Format::Text => {
                    println!("Testing environment: {}", result.environment_id);
                    println!("IAM test key: {}", result.iam_test_key);
                    println!("Application test secret: {}", result.app_secret);
                    println!(
                        "Dependencies provisioned: {}",
                        result.dependencies.join(", ")
                    );
                    Ok(())
                }
            }
        }
        AppTestingCommand::List {
            app_id,
            app_secret,
            page,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = super::app::prompted(
                app_secret,
                "Production application secret: ",
                "--app-secret",
            )?;
            let result = super::app::application_client(context, &app_id, &secret)
                .applications()
                .testing_environments(&page.paging())
                .await?;
            match context.format {
                Format::Json => json(&result),
                Format::Text => {
                    let mut table =
                        Table::new(["environment", "name", "last activity", "retention days"]);
                    for item in result.items {
                        table.row([
                            item.environment_id.to_string(),
                            item.name,
                            timestamp(item.last_activity_at),
                            item.retention_days.to_string(),
                        ]);
                    }
                    table.print();
                    next_cursor(result.page.has_more, result.page.next_cursor.as_deref());
                    Ok(())
                }
            }
        }
    }
}
