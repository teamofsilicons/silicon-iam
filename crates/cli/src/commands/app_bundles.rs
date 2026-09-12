//! Configure and sign in to application bundles.

use silicon_iam_client::models;

use crate::{
    cli::AppBundleCommand,
    context::Context,
    error::Result,
    output::{Format, Table, json, next_cursor},
};

/// Runs one application bundle operation.
///
/// # Errors
/// Returns configuration, authorization, or stale-version errors.
#[allow(
    clippy::too_many_lines,
    reason = "one compact branch per public subcommand"
)]
pub async fn run(context: &Context, command: AppBundleCommand) -> Result<()> {
    let client = context.authenticated().await?;
    match command {
        AppBundleCommand::Availability => {
            let availability = client
                .bundles()
                .availability(context.organization()?)
                .await?;
            match context.format {
                Format::Json => json(&availability),
                Format::Text => {
                    println!(
                        "available: {}",
                        if availability.available { "yes" } else { "no" }
                    );
                    Ok(())
                }
            }
        }
        AppBundleCommand::List { page } => {
            let bundles = match context.organization_if_set() {
                Some(org_id) => {
                    client
                        .bundles()
                        .list_for_organization(org_id, &page.paging())
                        .await?
                }
                None => client.bundles().list_page(&page.paging()).await?,
            };
            match context.format {
                Format::Json => json(&bundles),
                Format::Text => {
                    let mut table = Table::new(["bundle", "name", "applications", "version"]);
                    for bundle in bundles.items {
                        table.row([
                            bundle.bundle_id,
                            bundle.app_name.unwrap_or_default(),
                            bundle.app_ids.join(", "),
                            bundle.version.to_string(),
                        ]);
                    }
                    table.print();
                    next_cursor(bundles.page.has_more, bundles.page.next_cursor.as_deref());
                    Ok(())
                }
            }
        }
        AppBundleCommand::Create {
            bundle_id,
            app_ids,
            name,
            logo,
        } => {
            let (app_id, org_id) = context.application_creation_identity(&bundle_id)?;
            let bundle = client
                .bundles()
                .create(
                    &models::ApplicationBundleCreate {
                        org_id,
                        app_id,
                        app_name: name,
                        app_logo: logo,
                        app_ids,
                    },
                    &context.mutation(),
                )
                .await?;
            json(&bundle)
        }
        AppBundleCommand::Show { bundle_id } => {
            let bundle_id = context.application_id(&bundle_id)?;
            json(&client.bundles().get(&bundle_id).await?)
        }
        AppBundleCommand::Update {
            bundle_id,
            app_ids,
            name,
            logo,
            clear_logo,
        } => {
            let bundle_id = context.application_id(&bundle_id)?;
            let current = client.bundles().get(&bundle_id).await?;
            json(
                &client
                    .bundles()
                    .update(
                        &bundle_id,
                        current.version,
                        &models::ApplicationBundlePatch {
                            app_name: name.map(Some),
                            app_logo: if clear_logo {
                                Some(None)
                            } else {
                                logo.map(Some)
                            },
                            app_ids,
                        },
                        &context.mutation(),
                    )
                    .await?,
            )
        }
        AppBundleCommand::Delete { bundle_id } => {
            let bundle_id = context.application_id(&bundle_id)?;
            let current = client.bundles().get(&bundle_id).await?;
            client
                .bundles()
                .delete(&bundle_id, current.version, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&serde_json::json!({"deleted":true,"bundle_id":bundle_id})),
                Format::Text => {
                    println!("Deleted bundle {bundle_id}.");
                    Ok(())
                }
            }
        }
        AppBundleCommand::Login {
            bundle_id,
            grant_orgs,
            all_orgs,
            approve_scopes,
        } => {
            let bundle_id = context.application_id(&bundle_id)?;
            let choices = client.auth().bundle_login_organizations(&bundle_id).await?;
            if context.format == Format::Text {
                println!(
                    "Bundle: {}",
                    choices.bundle.app_name.as_deref().unwrap_or(&bundle_id)
                );
            }
            let applications = super::auth::select_batch_applications(
                &choices.items,
                &grant_orgs,
                all_orgs,
                approve_scopes,
            )?;
            let result = client
                .auth()
                .bundle_short_lived_tokens(
                    &bundle_id,
                    &models::BatchLoginRequest {
                        applications,
                        redirect_uri: None,
                    },
                    &context.mutation(),
                )
                .await?;
            super::auth::report_batch_tokens(context, &result)
        }
    }
}
