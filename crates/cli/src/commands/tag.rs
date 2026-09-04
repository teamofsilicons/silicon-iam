//! Organization tags.

use silicon_iam_client::models;

use crate::{
    cli::TagCommand,
    context::Context,
    error::Result,
    output::{Format, Table, json, label, next_cursor, timestamp},
};

/// Runs a tag command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting the match would only move it elsewhere"
)]
pub async fn run(context: &Context, command: TagCommand) -> Result<()> {
    let client = context.authenticated().await?;
    let org = context.organization()?;
    match command {
        TagCommand::List(page) => {
            let listed = client.tags().list(org, &page.paging()).await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["id", "name", "version"]);
                    for tag in &listed.items {
                        table.row([
                            tag.id.to_string(),
                            tag.name.clone(),
                            tag.version.to_string(),
                        ]);
                    }
                    table.print();
                    next_cursor(listed.page.has_more, listed.page.next_cursor.as_deref());
                    Ok(())
                }
            }
        }
        TagCommand::Create { name } => {
            let created = client
                .tags()
                .create(org, &models::TagCreate { name }, &context.mutation())
                .await?;
            report(context, &created)
        }
        TagCommand::Show { tag_id } => {
            let tag = client.tags().get(org, tag_id).await?;
            report(context, &tag)
        }
        TagCommand::Rename { tag_id, name } => {
            let current = client.tags().get(org, tag_id).await?;
            let renamed = client
                .tags()
                .update(
                    org,
                    tag_id,
                    current.version,
                    &models::TagPatch { name },
                    &context.mutation(),
                )
                .await?;
            report(context, &renamed)
        }
        TagCommand::Delete { tag_id } => {
            let current = client.tags().get(org, tag_id).await?;
            client
                .tags()
                .delete(org, tag_id, current.version, &context.mutation())
                .await?;
            // Worth saying out loud: deleting a tag is not only a rename away
            // from existing, it takes the access it conferred with it.
            println!(
                "Deleted {}. Members lost it, and tag-scoped trust rules were archived.",
                current.name
            );
            Ok(())
        }
        TagCommand::Members { tag_id, page } => {
            let listed = client.tags().members(org, tag_id, &page.paging()).await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["membership", "principal", "role", "status"]);
                    for member in &listed.items {
                        table.row([
                            member.id.to_string(),
                            member.principal.public_id.clone(),
                            label(&member.org_role),
                            label(&member.status),
                        ]);
                    }
                    table.print();
                    next_cursor(listed.page.has_more, listed.page.next_cursor.as_deref());
                    Ok(())
                }
            }
        }
    }
}

fn report(context: &Context, tag: &models::Tag) -> Result<()> {
    match context.format {
        Format::Json => json(tag),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["id", &tag.id.to_string()]);
            table.row(["name", &tag.name]);
            table.row(["org", &tag.org_id]);
            table.row(["version", &tag.version.to_string()]);
            table.row(["created", &timestamp(tag.created_at)]);
            table.print();
            Ok(())
        }
    }
}
