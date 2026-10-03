//! Application-only delegated credentials and receiver verification.
use super::app::{application_client, prompted};
use crate::{
    cli::AppAtaCommand,
    context::Context,
    error::Result,
    output::{Format, json, timestamp},
};
use silicon_iam_client::{Client, IdempotencyKey, Mutation};
fn app(context: &Context, id: &str, secret: Option<String>) -> Result<Client> {
    let id = context.application_id(id)?;
    let secret = prompted(secret, "Application secret: ", "--app-secret")?;
    Ok(application_client(context, &id, &secret))
}
pub async fn run(context: &Context, command: AppAtaCommand) -> Result<()> {
    match command {
        AppAtaCommand::Endpoints {
            app_id,
            requester_app_id,
            app_secret,
        } => {
            let response = app(context, &requester_app_id, app_secret)?
                .ata()
                .endpoints(&context.application_id(&app_id)?)
                .await?;
            json(&response)
        }
        AppAtaCommand::Token {
            app_id,
            refresh_token,
            app_secret,
            idempotency_key,
        } => {
            let token = prompted(refresh_token, "ATA refresh token: ", "--refresh-token")?;
            let mutation = idempotency_key.map_or_else(
                || Ok(Mutation::new()),
                |key| IdempotencyKey::parse(key).map(Mutation::with_key),
            )?;
            let response = app(context, &app_id, app_secret)?
                .ata()
                .refresh(&token, &mutation)
                .await?;
            match context.format {
                Format::Json => json(&response),
                Format::Text => {
                    println!(
                        "Access token: {}\nRefresh token: {}\nAccess expires: {}",
                        response.access_token,
                        response.refresh_token,
                        timestamp(response.expires_at)
                    );
                    Ok(())
                }
            }
        }
        AppAtaCommand::Verify {
            app_id,
            endpoint,
            recipient_app_id,
            app_proof_token,
            app_secret,
        } => {
            let token = prompted(app_proof_token, "ATA proof token: ", "--app-proof-token")?;
            let response = app(context, &recipient_app_id, app_secret)?
                .ata()
                .verify(&context.application_id(&app_id)?, &token, &endpoint)
                .await?;
            match context.format {
                Format::Json => json(&response),
                Format::Text => {
                    println!("Verified: {}", response.verified);
                    if let Some(expiry) = response.valid_till {
                        println!("Valid until (UTC YYYYMMDDHHMMSS): {expiry}");
                    }
                    Ok(())
                }
            }
        }
    }
}
