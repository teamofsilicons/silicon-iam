//! Testing environments.

use silicon_iam_client::{Error as ClientError, models};

use crate::{
    cli::EnvCommand,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, label, next_cursor, or_dash, timestamp, timestamp_or_dash},
};

/// Runs a testing environment command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting the match would only move it elsewhere"
)]
pub async fn run(context: &Context, command: EnvCommand) -> Result<()> {
    // The two key-authorized commands work without a signed-in session, which
    // is the point of an environment key.
    if let EnvCommand::Current = command {
        let environment_id = context.require_test()?;
        let described = context
            .anonymous()
            .environments()
            .current()
            .await
            .map_err(|error| environment_error(environment_id, error))?;
        return match context.format {
            Format::Json => json(&described),
            Format::Text => {
                let mut table = Table::new(["field", "value"]);
                table.row(["id", &described.id.to_string()]);
                table.row(["name", &described.name]);
                table.row(["description", &or_dash(described.description.as_deref())]);
                table.row(["key_generation", &described.key_generation.to_string()]);
                table.row(["created", &timestamp(described.created_at)]);
                table.print();
                Ok(())
            }
        };
    }

    if let EnvCommand::Clean {
        environment_id: None,
    } = command
    {
        let environment_id = context.require_test()?;
        let cleaned = context
            .anonymous()
            .environments()
            .clean_current(&context.mutation())
            .await
            .map_err(|error| environment_error(environment_id, error))?;
        return report_cleaning(context, &cleaned);
    }

    let client = context.authenticated().await?;
    let org = context.organization()?;
    match command {
        EnvCommand::Current
        | EnvCommand::Clean {
            environment_id: None,
        } => unreachable!(),
        EnvCommand::List { status, page } => {
            let listed = client
                .environments()
                .list(org, status.as_deref(), &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table =
                        Table::new(["id", "name", "status", "key gen", "last activity"]);
                    for entry in &listed.items {
                        table.row([
                            entry.id.to_string(),
                            entry.name.clone(),
                            label(&entry.status),
                            entry.key_generation.to_string(),
                            timestamp(entry.last_activity_at),
                        ]);
                    }
                    table.print();
                    next_cursor(
                        listed
                            .page
                            .get("has_more")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false),
                        listed
                            .page
                            .get("next_cursor")
                            .and_then(serde_json::Value::as_str),
                    );
                    Ok(())
                }
            }
        }
        EnvCommand::Create { name, description } => {
            let created = client
                .environments()
                .create(
                    org,
                    &models::TestingEnvironmentCreate { name, description },
                    &context.mutation(),
                )
                .await?;
            context.remember_testing_environment(created.id, created.key.clone())?;
            match context.format {
                Format::Json => json(&created),
                Format::Text => {
                    println!("Created {} ({}).", created.name, created.id);
                    println!("Key: {}", created.key);
                    crate::guidance::environment_created(context, created.id);
                    Ok(())
                }
            }
        }
        EnvCommand::Show { environment_id } => {
            let environment = client.environments().get(org, environment_id).await?;
            report(context, &environment)
        }
        EnvCommand::Update {
            environment_id,
            name,
            description,
            clear_description,
        } => {
            let current = client.environments().get(org, environment_id).await?;
            let updated = client
                .environments()
                .update(
                    org,
                    environment_id,
                    current.version,
                    &models::TestingEnvironmentPatch {
                        name,
                        description: nullable_patch(description, clear_description),
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &updated)
        }
        EnvCommand::Delete { environment_id } => {
            let retired = client
                .environments()
                .delete(org, environment_id, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&retired),
                Format::Text => {
                    println!("Retired {}.", retired.name);
                    if let Some(purge_after) = retired.purge_after {
                        println!("Recoverable until {}.", timestamp(purge_after));
                    }
                    crate::guidance::environment_retired(context, retired.id);
                    Ok(())
                }
            }
        }
        EnvCommand::Restore { environment_id } => {
            let restored = client
                .environments()
                .restore(org, environment_id, &context.mutation())
                .await?;
            report(context, &restored)
        }
        EnvCommand::Key { environment_id } => {
            let key = client.environments().key(org, environment_id).await?;
            context.remember_testing_environment(environment_id, key.key.clone())?;
            match context.format {
                Format::Json => json(&key),
                Format::Text => {
                    println!("{}", key.key);
                    Ok(())
                }
            }
        }
        EnvCommand::RotateKey { environment_id } => {
            let rotated = client
                .environments()
                .rotate_key(org, environment_id, &context.mutation())
                .await?;
            context.remember_testing_environment(environment_id, rotated.key.clone())?;
            match context.format {
                Format::Json => json(&rotated),
                Format::Text => {
                    println!("Key: {}", rotated.key);
                    println!("The previous key stopped working.");
                    Ok(())
                }
            }
        }
        EnvCommand::Clean {
            environment_id: Some(environment_id),
        } => {
            let cleaned = client
                .environments()
                .clean(org, environment_id, &context.mutation())
                .await?;
            report_cleaning(context, &cleaned)
        }
    }
}

fn environment_error(environment_id: uuid::Uuid, error: ClientError) -> CliError {
    if error
        .api()
        .is_some_and(silicon_iam_client::ApiError::is_unauthenticated)
    {
        CliError::TestingEnvironmentUnavailable {
            environment_id,
            source: error,
        }
    } else {
        CliError::Client(error)
    }
}

#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch has distinct omitted, null, and value states"
)]
fn nullable_patch<T>(value: Option<T>, clear: bool) -> Option<Option<T>> {
    if clear { Some(None) } else { value.map(Some) }
}

fn report(context: &Context, environment: &models::TestingEnvironment) -> Result<()> {
    match context.format {
        Format::Json => json(environment),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["id", &environment.id.to_string()]);
            table.row(["name", &environment.name]);
            table.row(["description", &or_dash(environment.description.as_deref())]);
            table.row(["status", &label(&environment.status)]);
            table.row(["key_generation", &environment.key_generation.to_string()]);
            table.row(["last_activity", &timestamp(environment.last_activity_at)]);
            table.row(["purge_after", &timestamp_or_dash(environment.purge_after)]);
            table.row(["version", &environment.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}

fn report_cleaning(context: &Context, cleaning: &models::TestingEnvironmentCleaning) -> Result<()> {
    match context.format {
        Format::Json => json(cleaning),
        Format::Text => {
            println!("Erased {} rows.", cleaning.erased_rows);
            Ok(())
        }
    }
}
