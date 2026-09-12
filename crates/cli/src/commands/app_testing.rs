//! Application-initiated isolated environments.

use silicon_iam_client::models;

use crate::{
    cli::{AppEnvironmentCommand, AppTestingCommand, EnvCommand},
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, next_cursor, timestamp},
};

/// Runs an application test environment operation using production app credentials.
///
/// # Errors
/// Returns errors for invalid app credentials, test keys, or environment configuration.
#[allow(clippy::too_many_lines)]
pub async fn run(context: &Context, command: AppTestingCommand) -> Result<()> {
    if let AppTestingCommand::View {
        app_id,
        app_secret,
        iam_test_key,
    } = command
    {
        let app_id = context.application_id(&app_id)?;
        let secret = super::app::prompted(app_secret, "Test application secret: ", "--app-secret")?;
        let key = super::app::prompted(iam_test_key, "IAM test key: ", "--iam-test-key")?;
        let result = super::app::application_client(context, &app_id, &secret)
            .with_environment(silicon_iam_client::EnvironmentKey::new(key)?)
            .applications()
            .testing_context()
            .await?;
        return json(&result);
    }
    if context.testing_environment_id().is_some() {
        return Err(CliError::Usage("Application testing management uses production credentials. Omit --test; pass --iam-test-key to attach to an existing environment.".to_owned()));
    }
    match command {
        AppTestingCommand::View { .. } => unreachable!(),
        AppTestingCommand::Manage {
            app_id,
            app_secret,
            command,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = super::app::prompted(
                app_secret,
                "Production application secret: ",
                "--app-secret",
            )?;
            let client = super::app::application_client(context, &app_id, &secret);
            let (org, _) = app_id
                .split_once('>')
                .ok_or_else(|| CliError::Usage("Expected org>app ID".to_owned()))?;
            let command = match command {
                AppEnvironmentCommand::Show { environment_id } => {
                    EnvCommand::Show { environment_id }
                }
                AppEnvironmentCommand::Update {
                    environment_id,
                    name,
                    description,
                    clear_description,
                } => EnvCommand::Update {
                    environment_id,
                    name,
                    description,
                    clear_description,
                },
                AppEnvironmentCommand::Delete { environment_id } => {
                    EnvCommand::Delete { environment_id }
                }
                AppEnvironmentCommand::Restore { environment_id } => {
                    EnvCommand::Restore { environment_id }
                }
                AppEnvironmentCommand::Key { environment_id } => EnvCommand::Key { environment_id },
                AppEnvironmentCommand::RotateKey { environment_id } => {
                    EnvCommand::RotateKey { environment_id }
                }
                AppEnvironmentCommand::Clean { environment_id } => EnvCommand::Clean {
                    environment_id: Some(environment_id),
                },
            };
            super::env::run_with_client(context, command, &client, org).await
        }
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
            status,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = super::app::prompted(
                app_secret,
                "Production application secret: ",
                "--app-secret",
            )?;
            let result = super::app::application_client(context, &app_id, &secret)
                .applications()
                .testing_environments(status.as_deref(), &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&result),
                Format::Text => {
                    let mut table = Table::new([
                        "environment",
                        "name",
                        "status",
                        "can manage",
                        "last activity",
                        "retention days",
                    ]);
                    for item in result.items {
                        table.row([
                            item.environment_id.to_string(),
                            item.name,
                            format!("{:?}", item.status).to_lowercase(),
                            item.can_manage.to_string(),
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
