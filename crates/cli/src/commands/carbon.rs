//! The signed-in Carbon's profile and privacy-preserving Carbon lookup.

use silicon_iam_client::models;

use crate::{
    cli::CarbonCommand,
    context::Context,
    error::Result,
    output::{Format, Table, json, label, or_dash, timestamp},
};

/// Runs a Carbon profile or lookup command.
///
/// # Errors
///
/// Returns whatever the service reports.
pub async fn run(context: &Context, command: CarbonCommand) -> Result<()> {
    let command = match command {
        CarbonCommand::Available { carbon_id } => {
            let availability = context
                .anonymous()
                .signup()
                .carbon_id_available(&carbon_id)
                .await?;
            return match context.format {
                Format::Json => json(&availability),
                Format::Text => {
                    println!(
                        "{carbon_id} is {}",
                        if availability.available {
                            "available"
                        } else {
                            "taken"
                        }
                    );
                    Ok(())
                }
            };
        }
        command => command,
    };

    let client = context.authenticated().await?;
    match command {
        CarbonCommand::Show => {
            let profile = client.carbons().me().await?;
            report_profile(context, &profile)
        }
        CarbonCommand::Update {
            display_name,
            timezone,
            description,
            clear_description,
            profile_photo,
            clear_profile_photo,
        } => {
            let current = client.carbons().me().await?;
            let updated = client
                .carbons()
                .update_me(
                    current.version,
                    &models::CarbonProfilePatch {
                        display_name,
                        timezone,
                        description: nullable_patch(description, clear_description),
                        profile_photo: nullable_patch(profile_photo, clear_profile_photo),
                    },
                    &context.mutation(),
                )
                .await?;
            report_profile(context, &updated)
        }
        CarbonCommand::Search { query, limit } => {
            let suggestions = client.carbons().search(&query, limit).await?;
            match context.format {
                Format::Json => json(&suggestions),
                Format::Text => {
                    let mut table = Table::new(["carbon"]);
                    for suggestion in &suggestions.items {
                        table.row([suggestion.carbon_id.clone()]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        CarbonCommand::ResolveEmail { email } => {
            let resolution = client.carbons().resolve_email(&email).await?;
            report_resolution(context, &resolution)
        }
        CarbonCommand::ResolvePhone { phone } => {
            let resolution = client.carbons().resolve_phone(&phone).await?;
            report_resolution(context, &resolution)
        }
        CarbonCommand::Available { .. } => unreachable!(),
    }
}

#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch has distinct omitted, null, and value states"
)]
fn nullable_patch<T>(value: Option<T>, clear: bool) -> Option<Option<T>> {
    if clear { Some(None) } else { value.map(Some) }
}

fn report_profile(context: &Context, profile: &models::CarbonSelf) -> Result<()> {
    match context.format {
        Format::Json => json(profile),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["principal_id", &profile.principal_id.to_string()]);
            table.row(["carbon_id", &profile.carbon_id]);
            table.row(["display_name", &profile.display_name]);
            table.row(["description", &or_dash(profile.description.as_deref())]);
            table.row(["profile_photo", &profile.profile_photo]);
            table.row(["timezone", &profile.timezone]);
            table.row(["email", &profile.email]);
            table.row(["phone", &profile.phone_number]);
            table.row(["status", &label(&profile.status)]);
            table.row(["version", &profile.version.to_string()]);
            table.row(["created", &timestamp(profile.created_at)]);
            table.row(["updated", &timestamp(profile.updated_at)]);
            table.print();
            Ok(())
        }
    }
}

fn report_resolution(context: &Context, resolution: &models::CarbonResolution) -> Result<()> {
    match context.format {
        Format::Json => json(resolution),
        Format::Text => {
            println!("{}", resolution.carbon_id);
            Ok(())
        }
    }
}
