//! Existing Silicon account invitations.
use crate::{cli::SiliconInvitationCommand, context::Context, error::Result, output::json};
pub(super) async fn run(context: &Context, command: SiliconInvitationCommand) -> Result<()> {
    let client = context.authenticated().await?;
    let result = match command {
        SiliconInvitationCommand::Candidates => {
            client
                .invitations()
                .silicon_candidates(context.organization()?)
                .await?
        }
        SiliconInvitationCommand::List => {
            client
                .invitations()
                .silicon_list(context.organization()?)
                .await?
        }
        SiliconInvitationCommand::Create { silicon_id } => {
            client
                .invitations()
                .silicon_create(context.organization()?, &silicon_id, &context.mutation())
                .await?
        }
        SiliconInvitationCommand::Inbox => client.invitations().silicon_inbox().await?,
        SiliconInvitationCommand::Accept { id } => {
            client
                .invitations()
                .silicon_decide(id, true, &context.mutation())
                .await?
        }
        SiliconInvitationCommand::Decline { id } => {
            client
                .invitations()
                .silicon_decide(id, false, &context.mutation())
                .await?
        }
        SiliconInvitationCommand::Revoke { id } => {
            client
                .invitations()
                .silicon_revoke(context.organization()?, id, &context.mutation())
                .await?
        }
    };
    json(&result)
}
