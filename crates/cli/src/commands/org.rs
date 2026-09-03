//! Organizations.

use silicon_iam_client::models;

use crate::{
    cli::OrgCommand,
    context::Context,
    error::Result,
    output::{Format, Table, json, or_dash, timestamp},
};

/// Runs an organization command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting the match would only move it elsewhere"
)]
pub async fn run(context: &Context, command: OrgCommand) -> Result<()> {
    let client = context.authenticated().await?;
    match command {
        OrgCommand::List(page) => {
            let listed = client.organizations().list(&page.paging()).await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["handle", "name", "join", "sso", "version"]);
                    for entry in &listed.items {
                        table.row([
                            entry.org_id.clone(),
                            entry.name.clone(),
                            format!("{:?}", entry.join_method).to_lowercase(),
                            format!("{:?}", entry.sso_status).to_lowercase(),
                            entry.version.to_string(),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        OrgCommand::Create {
            handle,
            name,
            description,
        } => {
            let created = client
                .organizations()
                .create(
                    &models::OrganizationCreate {
                        org_id: handle,
                        name,
                        logo: None,
                        description,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &created)
        }
        OrgCommand::Show { handle } => {
            let org = context.organization_or(handle.as_deref())?;
            let organization = client.organizations().get(org).await?;
            report(context, &organization)
        }
        OrgCommand::Update {
            handle,
            name,
            description,
            join_method,
        } => {
            let org = context.organization_or(handle.as_deref())?;
            let current = client.organizations().get(org).await?;
            let updated = client
                .organizations()
                .update(
                    org,
                    current.version,
                    &models::OrganizationPatch {
                        name,
                        logo: None,
                        description,
                        join_method: join_method.as_deref().map(parse_join_method),
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &updated)
        }
        OrgCommand::Available { handle } => {
            let availability = client.organizations().handle_available(&handle).await?;
            match context.format {
                Format::Json => json(&availability),
                Format::Text => {
                    println!(
                        "{handle} is {}",
                        if availability.available {
                            "available"
                        } else {
                            "taken"
                        }
                    );
                    Ok(())
                }
            }
        }
        OrgCommand::Transfer { membership_id, org } => {
            let handle = context.organization_or(org.as_deref())?;
            let current = client.organizations().get(handle).await?;
            let transferred = client
                .organizations()
                .transfer_ownership(
                    handle,
                    current.version,
                    &models::OwnershipTransfer {
                        new_owner_membership_id: membership_id,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &transferred)
        }
    }
}

fn parse_join_method(value: &str) -> models::OrganizationPatchJoinMethod {
    match value {
        "sso" => models::OrganizationPatchJoinMethod::Sso,
        "email" => models::OrganizationPatchJoinMethod::Email,
        other => models::OrganizationPatchJoinMethod::Other(other.to_owned()),
    }
}

fn report(context: &Context, organization: &models::Organization) -> Result<()> {
    match context.format {
        Format::Json => json(organization),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["handle", &organization.org_id]);
            table.row(["name", &organization.name]);
            table.row(["id", &organization.id.to_string()]);
            table.row(["description", &or_dash(organization.description.as_deref())]);
            table.row(["owner", &organization.owner_membership_id.to_string()]);
            table.row([
                "join_method",
                &format!("{:?}", organization.join_method).to_lowercase(),
            ]);
            table.row(["version", &organization.version.to_string()]);
            table.row(["created", &timestamp(organization.created_at)]);
            table.print();
            Ok(())
        }
    }
}
