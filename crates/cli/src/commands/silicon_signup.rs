//! Silicon account creation and custody decisions.
use super::auth::session_from_actor;
use crate::{
    cli::{SiliconCustodyArgs, SiliconSignupArgs},
    context::Context,
    error::{CliError, Result},
    output::{Format, json},
    store::SessionActor,
};
use silicon_iam_client::{Client, models};

pub async fn signup(context: &Context, args: SiliconSignupArgs) -> Result<()> {
    let client = context.anonymous();
    let (request, poll, stk) = if let Some(request) = args.request_id {
        (
            request,
            args.poll_token
                .ok_or_else(|| CliError::Usage("--poll-token is required to resume".into()))?,
            args.stk.clone(),
        )
    } else {
        let created = client
            .signup()
            .silicon(
                &models::SiliconSignupRequest {
                    silicon_id: args.sid.clone(),
                    silicon_token: args.stk.clone(),
                    custodian_email: args
                        .custodian_email
                        .ok_or_else(|| CliError::Usage("--custodian-email is required".into()))?,
                    display_name: args.display_name,
                    timezone: Some(args.timezone.unwrap_or_else(|| {
                        iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".into())
                    })),
                    webhook_url: args.webhook_url,
                },
                &context.mutation(),
            )
            .await?;
        let stk = args.stk.clone().or(created.generated_silicon_token.clone());
        // The generated password and polling capability are returned exactly once.
        // In wait mode stdout is an event stream so callers receive these secrets
        // before a potentially long approval wait, including if interrupted later.
        match context.format {
            Format::Json => json(&created)?,
            Format::Text => {
                println!(
                    "Custody request {} is pending for {}.",
                    created.request_id, created.silicon_id
                );
                println!("Polling token: {}", created.poll_token);
                if let Some(password) = &created.generated_silicon_token {
                    println!("Save this Silicon password; it is shown once: {password}");
                }
                if let Some(secret) = &created.webhook_signing_secret {
                    println!("Webhook signing secret: {secret}");
                }
            }
        }
        if !args.wait {
            return Ok(());
        }
        (created.request_id, created.poll_token, stk)
    };
    loop {
        let status = client.signup().silicon_status(request, &poll).await?;
        match status.status.as_str() {
            "approved" => {
                let Some(stk) = stk else {
                    json(&status)?;
                    return Err(CliError::Usage("Approved. Sign in using `iam silicon-login --sid <id> --stk <saved-password>`.".into()));
                };
                let tokens = client
                    .auth()
                    .authenticate_silicon(
                        &models::SiliconAuthenticationRequest {
                            silicon_id: status.silicon_id.clone(),
                            silicon_token: stk,
                        },
                        &context.mutation(),
                    )
                    .await?;
                context.remember(session_from_actor(
                    &tokens,
                    &status.silicon_id,
                    SessionActor::Silicon,
                ))?;
                let authenticated = context.authenticated().await?;
                let mut profile = authenticated.silicons().identity().await?;
                if let Some(path) = &args.photo {
                    profile = upload_photo(context, &authenticated, profile.version, path).await?;
                }
                match context.format {
                    Format::Json => json(
                        &serde_json::json!({"authenticated":true,"profile":profile,"onboarding":{"requires_organization":true}}),
                    )?,
                    Format::Text => println!(
                        "Signed in as {}. Create or join your first organization to continue.",
                        profile.silicon_id
                    ),
                }
                return Ok(());
            }
            "pending" if args.wait => tokio::time::sleep(std::time::Duration::from_secs(3)).await,
            _ => return json(&status),
        }
    }
}

pub async fn custody(context: &Context, args: SiliconCustodyArgs) -> Result<()> {
    let client = context.authenticated().await?;
    let status = if args.approve || args.reject {
        client
            .signup()
            .decide_silicon_custody(
                args.request_id,
                args.approve,
                !args.no_create_organizations,
                &context.mutation(),
            )
            .await?
    } else {
        client.signup().silicon_custody(args.request_id).await?
    };
    match context.format {
        Format::Json => json(&status),
        Format::Text => {
            println!(
                "{}: {} (may create organizations: {})",
                status.silicon_id, status.status, status.can_create_organizations
            );
            Ok(())
        }
    }
}

pub(super) async fn upload_photo(
    context: &Context,
    client: &Client,
    version: i64,
    path: &std::path::Path,
) -> Result<models::SiliconIdentityProfile> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| CliError::Usage(format!("Cannot read profile photo: {e}")))?;
    if metadata.len() > 512 * 1024 {
        return Err(CliError::Usage(
            "Profile photo must be at most 512 KiB".into(),
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|e| CliError::Usage(format!("Cannot read profile photo: {e}")))?;
    let mime = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        "image/jpeg"
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        return Err(CliError::Usage(
            "Profile photo must be PNG, JPEG or WebP".into(),
        ));
    };
    Ok(client
        .silicons()
        .upload_photo(version, mime, bytes, &context.mutation())
        .await?)
}
