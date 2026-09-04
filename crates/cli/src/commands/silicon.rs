//! Silicons.

use silicon_iam_client::models;

use crate::{
    cli::SiliconCommand,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, json_empty, label, next_cursor, or_dash, timestamp_or_dash},
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
    if let SiliconCommand::SetSubscription { mode, topics, .. } = &command
        && mode == "all"
        && !topics.is_empty()
    {
        return Err(CliError::Usage(
            "--topic can only be used with --mode selected".to_owned(),
        ));
    }

    let client = context.authenticated().await?;
    match command {
        SiliconCommand::List { tag, page } => {
            let org = context.organization()?;
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
                            label(&silicon.status),
                        ]);
                    }
                    table.print();
                    next_cursor(listed.page.has_more, listed.page.next_cursor.as_deref());
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
            let (global_id, org) = context.silicon_identity(&handle)?;
            let handle = context.local_silicon_id(&global_id, &org)?;
            let created = client
                .silicons()
                .create(
                    &org,
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
                    println!("Principal ID: {}", created.silicon.principal_id);
                    println!("Membership ID: {}", created.silicon.membership_id);
                    println!("Credential: {}", created.silicon_token);
                    println!("It is shown once. Store it now; it can only be rotated.");
                    Ok(())
                }
            }
        }
        SiliconCommand::Show { silicon_id } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let silicon = client.silicons().get(&org, &silicon_id).await?;
            report(context, &silicon)
        }
        SiliconCommand::Update {
            silicon_id,
            display_name,
            timezone,
            description,
            clear_description,
            profile_photo,
            clear_profile_photo,
            reports_to,
            clear_reports_to,
        } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let current = client.silicons().get(&org, &silicon_id).await?;
            let updated = client
                .silicons()
                .update(
                    &org,
                    &silicon_id,
                    current.version,
                    &models::SiliconPatch {
                        display_name,
                        timezone,
                        description: optional_nullable(description, clear_description),
                        profile_photo: optional_nullable(profile_photo, clear_profile_photo),
                        reports_to_membership_id: optional_nullable(reports_to, clear_reports_to),
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
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let current = client.silicons().get(&org, &silicon_id).await?;
            client
                .silicons()
                .remove(
                    &org,
                    &silicon_id,
                    current.version,
                    reassign_reports_to,
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json_empty(),
                Format::Text => println!("Removed {silicon_id}."),
            }
            Ok(())
        }
        SiliconCommand::RotateRequest { silicon_id } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let request = client
                .silicons()
                .request_token_rotation(&org, &silicon_id, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&request),
                Format::Text => {
                    println!("Requested. Approve it, then run:");
                    println!("  iam silicon rotate-complete {silicon_id} {}", request.id);
                    Ok(())
                }
            }
        }
        SiliconCommand::RotateComplete {
            silicon_id,
            request_id,
        } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let rotated = client
                .silicons()
                .complete_token_rotation(&org, &silicon_id, request_id, &context.mutation())
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
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            client.silicons().get(&org, &silicon_id).await?;
            match client.silicons().webhook(&org, &silicon_id).await {
                Ok(webhook) => report_webhook(context, &webhook),
                Err(error)
                    if error
                        .api()
                        .is_some_and(silicon_iam_client::ApiError::is_not_found) =>
                {
                    report_unconfigured(context);
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        }
        SiliconCommand::SetWebhook {
            silicon_id,
            webhook_url,
        } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            // The first configuration has nothing to match against; a
            // replacement does.
            let version = match client.silicons().webhook(&org, &silicon_id).await {
                Ok(webhook) => Some(webhook.version),
                Err(error)
                    if error
                        .api()
                        .is_some_and(silicon_iam_client::ApiError::is_not_found) =>
                {
                    None
                }
                Err(error) => return Err(error.into()),
            };
            let configured = client
                .silicons()
                .replace_webhook(
                    &org,
                    &silicon_id,
                    version,
                    &models::SiliconWebhookReplace { url: webhook_url },
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
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let current = client.silicons().webhook(&org, &silicon_id).await?;
            client
                .silicons()
                .delete_webhook(&org, &silicon_id, current.version, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json_empty(),
                Format::Text => println!("Removed the webhook endpoint."),
            }
            Ok(())
        }
        SiliconCommand::Subscription { silicon_id } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            client.silicons().get(&org, &silicon_id).await?;
            match client.silicons().subscription(&org, &silicon_id).await {
                Ok(subscription) => report_subscription(context, &subscription),
                Err(error)
                    if error
                        .api()
                        .is_some_and(silicon_iam_client::ApiError::is_not_found) =>
                {
                    report_unconfigured(context);
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        }
        SiliconCommand::SetSubscription {
            silicon_id,
            mode,
            topics,
            tags,
            own_tags_only,
        } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let version = match client.silicons().subscription(&org, &silicon_id).await {
                Ok(subscription) => Some(subscription.version),
                Err(error)
                    if error
                        .api()
                        .is_some_and(silicon_iam_client::ApiError::is_not_found) =>
                {
                    None
                }
                Err(error) => return Err(error.into()),
            };
            let replaced = client
                .silicons()
                .replace_subscription(
                    &org,
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
                        tag_filter: (own_tags_only || !tags.is_empty())
                            .then(|| serde_json::json!({ "additional_tag_ids": tags })),
                    },
                    &context.mutation(),
                )
                .await?;
            report_subscription(context, &replaced)
        }
        SiliconCommand::DeleteSubscription { silicon_id } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let current = client.silicons().subscription(&org, &silicon_id).await?;
            client
                .silicons()
                .delete_subscription(&org, &silicon_id, current.version, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json_empty(),
                Format::Text => println!("Removed the subscription."),
            }
            Ok(())
        }
        SiliconCommand::DeadLetters { silicon_id, page } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let listed = client
                .silicons()
                .dead_letters(&org, &silicon_id, &page.paging())
                .await?;
            dead_letters(context, &listed)
        }
        SiliconCommand::Replay {
            silicon_id,
            deliveries,
        } => {
            let (silicon_id, org) = context.silicon_identity(&silicon_id)?;
            let replayed = client
                .silicons()
                .replay_dead_letters(
                    &org,
                    &silicon_id,
                    &models::WebhookReplayRequest {
                        delivery_ids: deliveries,
                    },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&replayed),
                Format::Text => {
                    println!("Re-queued {} delivery(s).", replayed.replayed_count);
                    Ok(())
                }
            }
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

#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch has distinct omitted, null, and value states"
)]
fn optional_nullable<T>(value: Option<T>, clear: bool) -> Option<Option<T>> {
    if clear { Some(None) } else { value.map(Some) }
}

fn report(context: &Context, silicon: &models::Silicon) -> Result<()> {
    match context.format {
        Format::Json => json(silicon),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["silicon", &silicon.silicon_id]);
            table.row(["principal_id", &silicon.principal_id.to_string()]);
            table.row(["display_name", &silicon.display_name]);
            table.row(["membership_id", &silicon.membership_id.to_string()]);
            table.row(["job_role", &silicon.job_role]);
            table.row(["timezone", &silicon.timezone]);
            table.row(["description", &or_dash(silicon.description.as_deref())]);
            table.row(["profile_photo", &silicon.profile_photo]);
            table.row([
                "reports_to",
                &silicon
                    .reports_to_membership_id
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            ]);
            table.row([
                "tags",
                &silicon
                    .tags
                    .iter()
                    .map(|tag| format!("{} ({})", tag.name, tag.id))
                    .collect::<Vec<_>>()
                    .join(", "),
            ]);
            table.row(["status", &label(&silicon.status)]);
            table.row(["version", &silicon.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}

fn report_webhook(context: &Context, webhook: &models::SiliconWebhook) -> Result<()> {
    match context.format {
        Format::Json => json(webhook),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["silicon", &webhook.silicon_id]);
            table.row(["url", &webhook.url]);
            table.row(["status", &crate::output::plain(&webhook.status)]);
            table.row(["secret_version", &webhook.secret_version.to_string()]);
            table.row(["version", &webhook.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}

fn report_subscription(
    context: &Context,
    subscription: &models::SiliconWebhookSubscription,
) -> Result<()> {
    match context.format {
        Format::Json => json(subscription),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["silicon", &subscription.silicon_id]);
            table.row(["mode", &label(&subscription.mode)]);
            table.row([
                "topics",
                &subscription
                    .topics
                    .iter()
                    .map(label)
                    .collect::<Vec<_>>()
                    .join(", "),
            ]);
            table.row([
                "tag_filter",
                &if subscription.tag_filter.is_null() {
                    "-".to_owned()
                } else {
                    subscription.tag_filter.to_string()
                },
            ]);
            table.row(["version", &subscription.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}

fn report_unconfigured(context: &Context) {
    match context.format {
        Format::Json => json_empty(),
        Format::Text => println!("(none configured)"),
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
            next_cursor(listed.page.has_more, listed.page.next_cursor.as_deref());
            Ok(())
        }
    }
}
