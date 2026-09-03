//! Members of an organization.

use silicon_iam_client::{api::members::MemberFilter, models};

use crate::{
    cli::MemberCommand,
    context::Context,
    error::Result,
    output::{Format, Table, json, or_dash},
};

/// Runs a member command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting the match would only move it elsewhere"
)]
pub async fn run(context: &Context, command: MemberCommand) -> Result<()> {
    let client = context.authenticated().await?;
    let org = context.organization()?;
    match command {
        MemberCommand::List {
            principal_type,
            tag,
            status,
            page,
        } => {
            let listed = client
                .members()
                .list(
                    org,
                    &MemberFilter {
                        principal_type,
                        tag_id: tag,
                        status,
                    },
                    &page.paging(),
                )
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table =
                        Table::new(["membership", "principal", "type", "role", "status", "tags"]);
                    for member in &listed.items {
                        table.row([
                            member.id.to_string(),
                            member.principal.public_id.clone(),
                            format!("{:?}", member.principal.type_field).to_lowercase(),
                            format!("{:?}", member.org_role).to_lowercase(),
                            format!("{:?}", member.status).to_lowercase(),
                            member
                                .tags
                                .iter()
                                .map(|tag| tag.name.clone())
                                .collect::<Vec<_>>()
                                .join(","),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        MemberCommand::Show { membership_id } => {
            let member = client.members().get(org, membership_id).await?;
            report(context, &member)
        }
        MemberCommand::Authorization { membership_id } => {
            let authorization = client.members().authorization(org, membership_id).await?;
            match context.format {
                Format::Json => json(&authorization),
                Format::Text => {
                    let mut table = Table::new(["field", "value"]);
                    table.row(["membership", &authorization.membership_id.to_string()]);
                    table.row([
                        "role",
                        &format!("{:?}", authorization.org_role).to_lowercase(),
                    ]);
                    table.row([
                        "capabilities",
                        &authorization
                            .capabilities
                            .iter()
                            .map(|capability| format!("{capability:?}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ]);
                    table.row(["epoch", &authorization.authorization_epoch.to_string()]);
                    table.print();
                    Ok(())
                }
            }
        }
        MemberCommand::Update {
            membership_id,
            reports_to,
            profile_photo,
        } => {
            let current = client.members().get(org, membership_id).await?;
            let updated = client
                .members()
                .update(
                    org,
                    membership_id,
                    current.version,
                    &models::MembershipDirectoryPatch {
                        first_silicon_membership_id: None,
                        extra_silicon_membership_ids: None,
                        default_trust: None,
                        reports_to_membership_id: reports_to,
                        profile_photo,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &updated)
        }
        MemberCommand::Remove {
            membership_id,
            reassign_reports_to,
        } => {
            let current = client.members().get(org, membership_id).await?;
            client
                .members()
                .remove(
                    org,
                    membership_id,
                    current.version,
                    reassign_reports_to,
                    &context.mutation(),
                )
                .await?;
            println!("Removed {}.", current.principal.public_id);
            Ok(())
        }
        MemberCommand::Promote { membership_id } => {
            let current = client.members().get(org, membership_id).await?;
            let authorization = client
                .members()
                .promote_admin(org, membership_id, current.version, &context.mutation())
                .await?;
            json_or_line(context, &authorization, "Promoted to administrator.")
        }
        MemberCommand::Demote { membership_id } => {
            let current = client.members().get(org, membership_id).await?;
            let authorization = client
                .members()
                .demote_admin(org, membership_id, current.version, &context.mutation())
                .await?;
            json_or_line(context, &authorization, "Demoted to member.")
        }
        MemberCommand::Capabilities {
            membership_id,
            capabilities,
        } => {
            let current = client.members().get(org, membership_id).await?;
            let updated = client
                .members()
                .replace_capabilities(
                    org,
                    membership_id,
                    current.version,
                    &models::OrganizationCapabilitiesReplace {
                        capabilities: capabilities.into_iter().map(capability).collect(),
                    },
                    &context.mutation(),
                )
                .await?;
            json_or_line(context, &updated, "Capabilities replaced.")
        }
        MemberCommand::Directory { fields, page } => {
            let listed = client
                .members()
                .directory(org, fields.as_deref(), &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["id", "name", "tags"]);
                    for entry in &listed.items {
                        table.row([
                            or_dash(entry.id.as_deref()),
                            or_dash(entry.name.as_deref()),
                            entry
                                .tags
                                .as_ref()
                                .map(|tags| {
                                    tags.iter()
                                        .map(|tag| tag.name.clone())
                                        .collect::<Vec<_>>()
                                        .join(",")
                                })
                                .unwrap_or_default(),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        MemberCommand::Self_ { fields } => {
            let entry = client
                .members()
                .directory_self(org, fields.as_deref())
                .await?;
            json(&entry)
        }
    }
}

/// Maps a capability name onto the contract's closed vocabulary, keeping
/// anything unrecognized verbatim so the service rejects it by name.
fn capability(name: String) -> models::OrganizationCapability {
    serde_json::from_value(serde_json::Value::String(name.clone()))
        .unwrap_or(models::OrganizationCapability::Other(name))
}

fn report(context: &Context, member: &models::Membership) -> Result<()> {
    match context.format {
        Format::Json => json(member),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["membership", &member.id.to_string()]);
            table.row(["principal", &member.principal.public_id]);
            table.row(["role", &format!("{:?}", member.org_role).to_lowercase()]);
            table.row(["job_role", &member.job_role]);
            table.row(["status", &format!("{:?}", member.status).to_lowercase()]);
            table.row([
                "tags",
                &member
                    .tags
                    .iter()
                    .map(|tag| tag.name.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            ]);
            table.row(["version", &member.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}

fn json_or_line<T: serde::Serialize>(context: &Context, value: &T, line: &str) -> Result<()> {
    match context.format {
        Format::Json => json(value),
        Format::Text => {
            println!("{line}");
            Ok(())
        }
    }
}
