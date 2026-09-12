//! Application user reads preserve absent fields in their output.

use silicon_iam_client::{Credential, models};

use crate::{
    cli::{AppReadArgs, AppReadCommand},
    context::Context,
    error::Result,
    output::json,
};

/// Runs a scope-projected read using an explicitly supplied application token.
///
/// # Errors
/// Returns missing-context, credential, and scope authorization errors.
pub async fn run(context: &Context, args: AppReadArgs) -> Result<()> {
    let token = super::app::prompted(args.token, "Application user access token: ", "--token")?;
    let client = context
        .anonymous()
        .with_credential(Credential::bearer(token));
    let reads = client.application_reads();
    let value = match args.command {
        AppReadCommand::Me => reads.me().await?,
        AppReadCommand::Organizations { page } => reads.organizations(&page.paging()).await?,
        AppReadCommand::Organization => reads.organization(context.organization()?).await?,
        AppReadCommand::Members { page } => {
            reads
                .members(context.organization()?, &page.paging())
                .await?
        }
        AppReadCommand::Member { membership_id } => {
            reads.member(context.organization()?, membership_id).await?
        }
        AppReadCommand::Authorization { membership_id } => {
            reads
                .member_authorization(context.organization()?, membership_id)
                .await?
        }
        AppReadCommand::SelfDirectory => reads.directory_self(context.organization()?).await?,
        AppReadCommand::Directory { page } => {
            reads
                .directory(context.organization()?, &page.paging())
                .await?
        }
        AppReadCommand::Silicons { page } => {
            reads
                .silicons(context.organization()?, &page.paging())
                .await?
        }
        AppReadCommand::Silicon { silicon_id } => {
            reads.silicon(context.organization()?, &silicon_id).await?
        }
        AppReadCommand::Tags { page } => {
            reads.tags(context.organization()?, &page.paging()).await?
        }
        AppReadCommand::Trust {
            subject_membership_id,
            target_silicon_membership_id,
        } => {
            reads
                .evaluate_trust(
                    context.organization()?,
                    &models::TrustEvaluationRequest {
                        subject_membership_id,
                        target_silicon_membership_id,
                    },
                )
                .await?
        }
    };
    json(&value)
}
