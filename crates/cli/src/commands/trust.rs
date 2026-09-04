//! Advisory trust.

use silicon_iam_client::models;

use crate::{
    cli::TrustCommand,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, json_empty, label, next_cursor, plain},
};

/// Parses a boundary and level into the contract's trust value.
///
/// Shared with invitations, which set a new member's starting trust.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for a value outside the closed vocabulary.
///
/// Runs a trust command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting the match would only move it elsewhere"
)]
pub async fn run(context: &Context, command: TrustCommand) -> Result<()> {
    let client = context.authenticated().await?;
    let org = context.organization()?;
    match command {
        TrustCommand::Default => {
            let value = client.trust().default(org).await?;
            report_value(context, &value)
        }
        TrustCommand::SetDefault { boundary, level } => {
            // The default resource carries no version of its own, so the
            // organization's is what guards the replacement.
            let organization = client.organizations().get(org).await?;
            let replaced = client
                .trust()
                .replace_default(
                    org,
                    organization.version,
                    &trust_value(&boundary, &level)?,
                    &context.mutation(),
                )
                .await?;
            report_value(context, &replaced)
        }
        TrustCommand::List(page) => {
            let listed = client.trust().list_rules(org, &page.paging()).await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["id", "subject", "target", "trust", "version"]);
                    for rule in &listed.items {
                        table.row([
                            rule.id.to_string(),
                            selector(&rule.subject),
                            selector(&rule.target),
                            format!(
                                "{}/{}",
                                label(&rule.trust.boundary),
                                label(&rule.trust.level)
                            ),
                            rule.version.to_string(),
                        ]);
                    }
                    table.print();
                    next_cursor(listed.page.has_more, listed.page.next_cursor.as_deref());
                    Ok(())
                }
            }
        }
        TrustCommand::Create {
            subject_tag,
            subject_membership,
            target_tag,
            target_membership,
            boundary,
            level,
        } => {
            let created = client
                .trust()
                .create_rule(
                    org,
                    &models::TrustRuleCreate {
                        subject: build_selector(subject_tag, subject_membership, "subject")?,
                        target: build_selector(target_tag, target_membership, "target")?,
                        trust: trust_value(&boundary, &level)?,
                    },
                    &context.mutation(),
                )
                .await?;
            report_rule(context, &created)
        }
        TrustCommand::Show { rule_id } => {
            let rule = client.trust().get_rule(org, rule_id).await?;
            report_rule(context, &rule)
        }
        TrustCommand::Update {
            rule_id,
            boundary,
            level,
        } => {
            let current = client.trust().get_rule(org, rule_id).await?;
            let updated = client
                .trust()
                .update_rule(
                    org,
                    rule_id,
                    current.version,
                    &models::TrustRulePatch {
                        subject: None,
                        target: None,
                        trust: Some(trust_value(&boundary, &level)?),
                    },
                    &context.mutation(),
                )
                .await?;
            report_rule(context, &updated)
        }
        TrustCommand::Delete { rule_id } => {
            let current = client.trust().get_rule(org, rule_id).await?;
            client
                .trust()
                .delete_rule(org, rule_id, current.version, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json_empty(),
                Format::Text => println!("Archived {rule_id}."),
            }
            Ok(())
        }
        TrustCommand::Evaluate { subject, target } => {
            let evaluation = client
                .trust()
                .evaluate(
                    org,
                    &models::TrustEvaluationRequest {
                        subject_membership_id: subject,
                        target_silicon_membership_id: target,
                    },
                )
                .await?;
            match context.format {
                Format::Json => json(&evaluation),
                Format::Text => {
                    let mut table = Table::new(["field", "value"]);
                    table.row([
                        "trust",
                        &format!(
                            "{}/{}",
                            label(&evaluation.trust.boundary),
                            label(&evaluation.trust.level)
                        ),
                    ]);
                    table.row(["advisory", &plain(&evaluation.advisory)]);
                    table.row(["source", &label(&evaluation.source)]);
                    table.row([
                        "matched_rules",
                        &evaluation
                            .matching_rule_ids
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", "),
                    ]);
                    table.print();
                    Ok(())
                }
            }
        }
    }
}

fn build_selector(
    tag: Option<uuid::Uuid>,
    membership: Option<uuid::Uuid>,
    side: &str,
) -> Result<models::TrustSelector> {
    match (tag, membership) {
        (Some(tag), None) => Ok(models::TrustSelector::tag(tag)),
        (None, Some(membership)) => Ok(models::TrustSelector::membership(membership)),
        _ => Err(CliError::Usage(format!(
            "give exactly one of --{side}-tag or --{side}-membership"
        ))),
    }
}

pub fn trust_value(boundary: &str, level: &str) -> Result<models::TrustValue> {
    let boundary = match boundary {
        "internal" => models::TrustValueBoundary::Internal,
        "external" => models::TrustValueBoundary::External,
        other => {
            return Err(CliError::Usage(format!(
                "unknown boundary `{other}`; expected internal or external"
            )));
        }
    };
    let level = match level {
        "not_trusted" => models::TrustValueLevel::NotTrusted,
        "needs_approval" => models::TrustValueLevel::NeedsApproval,
        "trusted" => models::TrustValueLevel::Trusted,
        other => {
            return Err(CliError::Usage(format!(
                "unknown level `{other}`; expected not_trusted, needs_approval or trusted"
            )));
        }
    };
    Ok(models::TrustValue { boundary, level })
}

fn selector(selector: &models::TrustSelector) -> String {
    match selector {
        models::TrustSelector::Tag { tag_id } => format!("tag:{tag_id}"),
        models::TrustSelector::Membership { membership_id } => {
            format!("membership:{membership_id}")
        }
    }
}

fn report_value(context: &Context, value: &models::TrustValue) -> Result<()> {
    match context.format {
        Format::Json => json(value),
        Format::Text => {
            println!("{}/{}", label(&value.boundary), label(&value.level));
            Ok(())
        }
    }
}

fn report_rule(context: &Context, rule: &models::TrustRule) -> Result<()> {
    match context.format {
        Format::Json => json(rule),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["id", &rule.id.to_string()]);
            table.row(["subject", &selector(&rule.subject)]);
            table.row(["target", &selector(&rule.target)]);
            table.row([
                "trust",
                &format!(
                    "{}/{}",
                    label(&rule.trust.boundary),
                    label(&rule.trust.level)
                ),
            ]);
            table.row(["version", &rule.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}
