//! Invitations, from both ends.

use silicon_iam_client::models;

use crate::{
    cli::InviteCommand,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, timestamp},
};

/// Runs an invitation command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting the match would only move it elsewhere"
)]
pub async fn run(context: &Context, command: InviteCommand) -> Result<()> {
    let client = context.authenticated().await?;
    let org = context.organization()?;
    match command {
        InviteCommand::List { status, page } => {
            let listed = client
                .invitations()
                .list(org, status.as_deref(), &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["id", "invitee", "status", "expires"]);
                    for invite in &listed.items {
                        table.row([
                            invite.id.to_string(),
                            invite.target_carbon.carbon_id.clone(),
                            format!("{:?}", invite.status).to_lowercase(),
                            timestamp(invite.expires_at),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        InviteCommand::Create {
            carbon_id,
            email,
            job_role,
            boundary,
            level,
        } => {
            if carbon_id.is_none() && email.is_none() {
                return Err(CliError::Usage("give --carbon-id or --email".to_owned()));
            }
            let created = client
                .invitations()
                .create(
                    org,
                    &models::CarbonInviteCreate {
                        carbon_id,
                        email,
                        job_role,
                        tag_ids: None,
                        first_silicon_membership_id: None,
                        extra_silicon_membership_ids: None,
                        default_trust: crate::commands::trust::trust_value(&boundary, &level)?,
                        tag_trust_overrides: None,
                        silicon_trust_overrides: None,
                        redirect_app_id: None,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &created)
        }
        InviteCommand::Show { invite_id } => {
            let invite = client.invitations().get(org, invite_id).await?;
            report(context, &invite)
        }
        InviteCommand::Revoke { invite_id } => {
            let current = client.invitations().get(org, invite_id).await?;
            client
                .invitations()
                .revoke(org, invite_id, current.version, &context.mutation())
                .await?;
            println!("Revoked {invite_id}.");
            Ok(())
        }
        InviteCommand::Code { email } => {
            let dispatched = client
                .invitations()
                .send_join_code(org, &email, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&dispatched),
                Format::Text => {
                    println!("Sent. Accept with `iam invite accept --code <code>`.");
                    Ok(())
                }
            }
        }
        InviteCommand::Accept { invite_id, code } => {
            let membership = client
                .invitations()
                .join(
                    org,
                    &models::InvitationAcceptance {
                        invite_id,
                        verification_code: code,
                    },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&membership),
                Format::Text => {
                    println!("Joined {} as {}.", membership.org_id, membership.job_role);
                    Ok(())
                }
            }
        }
    }
}

fn report(context: &Context, invite: &models::Invite) -> Result<()> {
    match context.format {
        Format::Json => json(invite),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["id", &invite.id.to_string()]);
            table.row(["invitee", &invite.target_carbon.carbon_id]);
            table.row(["status", &format!("{:?}", invite.status).to_lowercase()]);
            table.row(["expires", &timestamp(invite.expires_at)]);
            table.row(["version", &invite.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}
