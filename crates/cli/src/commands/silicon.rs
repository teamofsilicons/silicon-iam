//! Silicons.

use silicon_iam_client::models;

use crate::{
    cli::SiliconCommand,
    context::Context,
    error::Result,
    output::{Format, Table, json, or_dash, timestamp_or_dash},
};

/// Runs a Silicon command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting them would only move the match elsewhere"
)]
pub async fn run(context: &Context, command: SiliconCommand) -> Result<()> {
    let client = context.authenticated().await?;
    let org = context.organization()?;
    match command {
        SiliconCommand::List { tag, page } => {
            let listed = client.silicons().list(org, tag, &page.paging()).await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["silicon", "display name", "membership", "status"]);
                    for silicon in &listed.items {
                        table.row([
                            silicon.silicon_id.clone(),
                            silicon.display_name.clone(),
                            silicon.membership_id.to_string(),
                            format!("{:?}", silicon.status).to_lowercase(),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        SiliconCommand::Create {
            handle,
            job_role,
            display_name,
            reports_to,
            tags,
        } => {
            let created = client
                .silicons()
                .create(
                    org,
                    &models::SiliconCreate {
                        silicon_id: handle.clone(),
                        display_name: Some(display_name.unwrap_or(handle)),
                        job_role,
                        timezone: None,
                        description: None,
                        profile_photo: None,
                        reports_to_membership_id: reports_to,
                        tag_ids: if tags.is_empty() { None } else { Some(tags) },
                    },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&created),
                Format::Text => {
                    println!("Created {}.", created.silicon.silicon_id);
                    println!("Credential: {}", created.silicon_token);
                    println!("It is shown once. Store it now; it can only be rotated.");
                    Ok(())
                }
            }
        }
        SiliconCommand::Show { silicon_id } => {
            let silicon = client.silicons().get(org, &silicon_id).await?;
            report(context, &silicon)
        }
        SiliconCommand::Update {
            silicon_id,
            display_name,
            reports_to,
        } => {
            let current = client.silicons().get(org, &silicon_id).await?;
            let updated = client
                .silicons()
                .update(
                    org,
                    &silicon_id,
                    current.version,
                    &models::SiliconPatch {
                        display_name,
                        timezone: None,
                        description: None,
                        profile_photo: None,
                        reports_to_membership_id: reports_to,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &updated)
        }
        SiliconCommand::Remove {
            silicon_id,
            reassign_reports_to,
        } => {
            let current = client.silicons().get(org, &silicon_id).await?;
            client
                .silicons()
                .remove(
                    org,
                    &silicon_id,
                    current.version,
                    reassign_reports_to,
                    &context.mutation(),
                )
                .await?;
            println!("Removed {silicon_id}.");
            Ok(())
        }
        SiliconCommand::RotateRequest { silicon_id } => {
            let request = client
                .silicons()
                .request_token_rotation(org, &silicon_id, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&request),
                Format::Text => {
                    println!("Requested. Approve it, then run:");
                    println!("  siam silicon rotate-complete {silicon_id} {}", request.id);
                    Ok(())
                }
            }
        }
        SiliconCommand::RotateComplete {
            silicon_id,
            request_id,
        } => {
            let rotated = client
                .silicons()
                .complete_token_rotation(org, &silicon_id, request_id, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&rotated),
                Format::Text => {
                    println!("Credential: {}", rotated.silicon_token);
                    println!("The previous one stopped working.");
                    Ok(())
                }
            }
        }
        SiliconCommand::Webhook { silicon_id } => {
            let webhook = client.silicons().webhook(org, &silicon_id).await?;
            json(&webhook)
        }
        SiliconCommand::SetWebhook { silicon_id, url } => {
            // The first configuration has nothing to match against; a
            // replacement does.
            let version = client
                .silicons()
                .webhook(org, &silicon_id)
                .await
                .ok()
                .map(|webhook| webhook.version);
            let configured = client
                .silicons()
                .replace_webhook(
                    org,
                    &silicon_id,
                    version,
                    &models::SiliconWebhookReplace { url },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&configured),
                Format::Text => {
                    println!("Signing secret: {}", configured.webhook_signing_secret);
                    println!("It is shown once. Store it now.");
                    Ok(())
                }
            }
        }
        SiliconCommand::DeleteWebhook { silicon_id } => {
            let current = client.silicons().webhook(org, &silicon_id).await?;
            client
                .silicons()
                .delete_webhook(org, &silicon_id, current.version, &context.mutation())
                .await?;
            println!("Removed the webhook endpoint.");
            Ok(())
        }
        SiliconCommand::Subscription { silicon_id } => {
            let subscription = client.silicons().subscription(org, &silicon_id).await?;
            json(&subscription)
        }
        SiliconCommand::SetSubscription {
            silicon_id,
            mode,
            topics,
            tags,
        } => {
            let version = client
                .silicons()
                .subscription(org, &silicon_id)
                .await
                .ok()
                .map(|subscription| subscription.version);
            let replaced = client
                .silicons()
                .replace_subscription(
                    org,
                    &silicon_id,
                    version,
                    &models::SiliconWebhookSubscriptionReplace {
                        mode: match mode.as_str() {
                            "selected" => models::SiliconWebhookSubscriptionReplaceMode::Selected,
                            "all" => models::SiliconWebhookSubscriptionReplaceMode::All,
                            other => models::SiliconWebhookSubscriptionReplaceMode::Other(
                                other.to_owned(),
                            ),
                        },
                        topics: if topics.is_empty() {
                            None
                        } else {
                            Some(topics.into_iter().map(topic).collect())
                        },
                        tag_filter: (!tags.is_empty())
                            .then(|| serde_json::json!({ "additional_tag_ids": tags })),
                    },
                    &context.mutation(),
                )
                .await?;
            json(&replaced)
        }
        SiliconCommand::DeleteSubscription { silicon_id } => {
            let current = client.silicons().subscription(org, &silicon_id).await?;
            client
                .silicons()
                .delete_subscription(org, &silicon_id, current.version, &context.mutation())
                .await?;
            println!("Removed the subscription.");
            Ok(())
        }
        SiliconCommand::DeadLetters { silicon_id, page } => {
            let listed = client
                .silicons()
                .dead_letters(org, &silicon_id, &page.paging())
                .await?;
            dead_letters(context, &listed)
        }
        SiliconCommand::Replay {
            silicon_id,
            deliveries,
        } => {
            let replayed = client
                .silicons()
                .replay_dead_letters(
                    org,
                    &silicon_id,
                    &models::WebhookReplayRequest {
                        delivery_ids: deliveries,
                    },
                    &context.mutation(),
                )
                .await?;
            json(&replayed)
        }
    }
}

/// Maps a topic name onto the contract's closed vocabulary, keeping anything
/// unrecognized verbatim so the service can reject it with its own message.
fn topic(name: String) -> models::SiliconWebhookSubscriptionTopic {
    match name.as_str() {
        "membership_lifecycle" => models::SiliconWebhookSubscriptionTopic::MembershipLifecycle,
        "member_updates" => models::SiliconWebhookSubscriptionTopic::MemberUpdates,
        "trust_updates" => models::SiliconWebhookSubscriptionTopic::TrustUpdates,
        _ => models::SiliconWebhookSubscriptionTopic::Other(name),
    }
}

fn report(context: &Context, silicon: &models::Silicon) -> Result<()> {
    match context.format {
        Format::Json => json(silicon),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["silicon", &silicon.silicon_id]);
            table.row(["display_name", &silicon.display_name]);
            table.row(["membership", &silicon.membership_id.to_string()]);
            table.row(["status", &format!("{:?}", silicon.status).to_lowercase()]);
            table.row(["version", &silicon.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}

/// Shared by Silicons and applications: both dead-letter listings are the same
/// shape, and a person reading one should not have to learn two layouts.
pub fn dead_letters(context: &Context, listed: &models::WebhookDeadLetterPage) -> Result<()> {
    match context.format {
        Format::Json => json(listed),
        Format::Text => {
            let mut table = Table::new(["delivery", "event", "attempts", "last error", "failed"]);
            for entry in &listed.items {
                table.row([
                    entry.delivery_id.to_string(),
                    entry.event_type.clone(),
                    entry.attempt_count.to_string(),
                    or_dash(entry.last_error_code.as_deref()),
                    timestamp_or_dash(entry.dead_lettered_at),
                ]);
            }
            table.print();
            Ok(())
        }
    }
}
