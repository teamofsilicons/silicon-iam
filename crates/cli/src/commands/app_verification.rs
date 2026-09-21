//! Application identity issuance and verification without an IAM user session.

use silicon_iam_client::models;

use crate::{
    cli::AppVerificationCommand,
    context::Context,
    error::Result,
    output::{Format, json, timestamp},
};

/// Runs an application verification operation using the app's own credentials.
///
/// # Errors
/// Returns credential, request, or testing context failures from IAM.
pub async fn run(context: &Context, command: AppVerificationCommand) -> Result<()> {
    match command {
        AppVerificationCommand::Issue {
            app_id,
            ttl_seconds,
            app_secret,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret =
                super::app::prompted(app_secret, "Issuing application secret: ", "--app-secret")?;
            let issued = super::app::application_client(context, &app_id, &secret)
                .app_verification()
                .issue(&models::AppAccessKeyIssue { ttl_seconds })
                .await?;
            match context.format {
                Format::Json => json(&issued),
                Format::Text => {
                    println!("Application: {}", issued.app_id);
                    println!("App access key: {}", issued.app_access_key);
                    println!("Valid till: {}", timestamp(issued.valid_till));
                    Ok(())
                }
            }
        }
        AppVerificationCommand::Verify {
            app_id,
            receiver_app_id,
            app_access_key,
            app_secret,
        } => {
            let app_id = context.application_id(&app_id)?;
            let receiver_app_id = context.application_id(&receiver_app_id)?;
            let secret =
                super::app::prompted(app_secret, "Receiving application secret: ", "--app-secret")?;
            let app_access_key = super::app::prompted(
                app_access_key,
                "Calling application access key: ",
                "--app-access-key",
            )?;
            let verified = super::app::application_client(context, &receiver_app_id, &secret)
                .app_verification()
                .verify(&models::AppAccessKeyVerify {
                    app_id,
                    app_access_key,
                })
                .await?;
            match context.format {
                Format::Json => json(&verified),
                Format::Text => {
                    println!("Valid key: {}", verified.valid_key);
                    if verified.valid_key {
                        if let Some(app_id) = verified.app_id {
                            println!("Application: {app_id}");
                        }
                        if let Some(valid_till) = verified.valid_till {
                            println!("Valid till: {}", timestamp(valid_till));
                        }
                    }
                    Ok(())
                }
            }
        }
    }
}
