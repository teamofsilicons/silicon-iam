//! Approvals, direct changes, and history.

use silicon_iam_client::{api::governance::ApprovalFilter, models};

use crate::{
    cli::ApprovalCommand,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, label, next_cursor, or_dash, timestamp, timestamp_or_dash},
};

/// Runs a governance command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting the match would only move it elsewhere"
)]
pub async fn run(context: &Context, command: ApprovalCommand) -> Result<()> {
    let client = context.authenticated().await?;
    let org = context.organization()?;
    match command {
        ApprovalCommand::List {
            status,
            kind,
            mine,
            page,
        } => {
            let listed = client
                .governance()
                .list_approvals(
                    org,
                    &ApprovalFilter {
                        status,
                        kind,
                        actionable_by_me: mine.then_some(true),
                    },
                    &page.paging(),
                )
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["id", "kind", "status", "requested"]);
                    for request in &listed.items {
                        table.row([
                            request.id.to_string(),
                            label(&request.kind),
                            label(&request.status),
                            timestamp(request.created_at),
                        ]);
                    }
                    table.print();
                    next_cursor(listed.page.has_more, listed.page.next_cursor.as_deref());
                    Ok(())
                }
            }
        }
        ApprovalCommand::Show { request_id } => {
            let request = client.governance().get_approval(org, request_id).await?;
            report(context, &request)
        }
        ApprovalCommand::Decide {
            request_id,
            decision,
            reason,
        } => {
            let current = client.governance().get_approval(org, request_id).await?;
            let decision = match decision.as_str() {
                "approve" => models::ApprovalDecisionCreateDecision::Approve,
                "reject" => models::ApprovalDecisionCreateDecision::Reject,
                other => {
                    return Err(CliError::Usage(format!(
                        "unknown decision `{other}`; expected approve or reject"
                    )));
                }
            };
            let decided = client
                .governance()
                .decide(
                    org,
                    request_id,
                    current.version,
                    &models::ApprovalDecisionCreate {
                        decision,
                        comment: reason,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &decided)
        }
        ApprovalCommand::RequestRole {
            membership_id,
            job_role,
        } => {
            let requested = client
                .governance()
                .request_role_change(
                    org,
                    &models::RoleChangeRequestCreate {
                        target_membership_id: membership_id,
                        proposed_job_role: job_role,
                        reason: None,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &requested)
        }
        ApprovalCommand::RequestTags {
            membership_id,
            add,
            remove,
        } => {
            let requested = client
                .governance()
                .request_tag_change(
                    org,
                    membership_id,
                    &models::TagChangeRequestCreate {
                        add_tag_ids: (!add.is_empty()).then_some(add),
                        remove_tag_ids: (!remove.is_empty()).then_some(remove),
                        reason: None,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &requested)
        }
        ApprovalCommand::SetRole {
            membership_id,
            job_role,
        } => {
            let current = client.members().get(org, membership_id).await?;
            let updated = client
                .governance()
                .replace_job_role(
                    org,
                    membership_id,
                    current.version,
                    &models::DirectJobRoleReplace { job_role },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&updated),
                Format::Text => {
                    println!("Job role is now {}.", updated.job_role);
                    Ok(())
                }
            }
        }
        ApprovalCommand::SetTags {
            membership_id,
            tags,
        } => {
            let current = client.members().get(org, membership_id).await?;
            let updated = client
                .governance()
                .replace_tags(
                    org,
                    membership_id,
                    current.version,
                    &models::DirectTagSetReplace { tag_ids: tags },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&updated),
                Format::Text => {
                    println!(
                        "Tags are now {}.",
                        updated
                            .tags
                            .iter()
                            .map(|tag| tag.name.clone())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    Ok(())
                }
            }
        }
        ApprovalCommand::RoleHistory {
            membership_id,
            page,
        } => {
            let listed = client
                .governance()
                .job_role_history(org, membership_id, &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["when", "from", "to"]);
                    for entry in &listed.items {
                        table.row([
                            timestamp(entry.applied_at),
                            entry.old_job_role.clone(),
                            entry.new_job_role.clone(),
                        ]);
                    }
                    table.print();
                    next_cursor(listed.page.has_more, listed.page.next_cursor.as_deref());
                    Ok(())
                }
            }
        }
        ApprovalCommand::TagHistory {
            membership_id,
            page,
        } => {
            let listed = client
                .governance()
                .tag_history(org, membership_id, &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["when", "tags"]);
                    for entry in &listed.items {
                        table.row([
                            timestamp(entry.applied_at),
                            entry
                                .applied_tag_ids
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(","),
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

fn report(context: &Context, request: &models::ApprovalRequest) -> Result<()> {
    match context.format {
        Format::Json => json(request),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["id", &request.id.to_string()]);
            table.row(["org", &request.org_id]);
            table.row(["kind", &label(&request.kind)]);
            table.row(["status", &label(&request.status)]);
            table.row([
                "requested_by",
                &format!(
                    "{}:{} ({})",
                    label(&request.requested_by.type_field),
                    request.requested_by.public_id,
                    request.requested_by.principal_id
                ),
            ]);
            table.row([
                "target_membership",
                &request.target_membership_id.to_string(),
            ]);
            table.row(["immutable_payload", &request.immutable_payload.to_string()]);
            table.row([
                "required_approvals",
                &request.required_approvals.to_string(),
            ]);
            for (index, decision) in request.decisions.iter().enumerate() {
                table.row([
                    format!("decision[{}]", index + 1),
                    format!(
                        "{} by {}:{} ({}) at {}; comment: {}; id: {}",
                        label(&decision.decision),
                        label(&decision.approver.type_field),
                        decision.approver.public_id,
                        decision.approver.principal_id,
                        timestamp(decision.decided_at),
                        or_dash(decision.comment.as_deref()),
                        decision.id
                    ),
                ]);
            }
            if request.decisions.is_empty() {
                table.row(["decisions".to_owned(), "(none)".to_owned()]);
            }
            table.row(["completed", &timestamp_or_dash(request.completed_at)]);
            table.row(["version", &request.version.to_string()]);
            table.row(["created", &timestamp(request.created_at)]);
            table.print();
            Ok(())
        }
    }
}
