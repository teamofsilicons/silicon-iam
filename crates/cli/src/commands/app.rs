//! Applications.

use std::{io::Read as _, path::Path, time::Duration};

use crate::{
    cli::{AppCommand, AppTokenCommand, AppTokenType},
    commands::silicon::dead_letters,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, label, next_cursor, or_dash, timestamp, timestamp_or_dash},
};
use http::{HeaderMap, HeaderValue};
use silicon_iam_client::{
    Client, Credential, IdempotencyKey, Mutation, WebhookSecret, WebhookSecretKeyring,
    WebhookVerifier, models,
};

/// Runs an application command.
///
/// # Errors
///
/// Returns whatever the service reports.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting them would only move the match elsewhere"
)]
pub async fn run(context: &Context, command: AppCommand) -> Result<()> {
    let command = match command {
        AppCommand::Discover {
            app_id,
            requester_app_id,
            app_secret,
        } => return discover(context, &app_id, &requester_app_id, app_secret).await,
        AppCommand::Read(args) => return super::app_reads::run(context, args).await,
        AppCommand::Token(command) => return token(context, command).await,
        AppCommand::Verification(command) => {
            return super::app_verification::run(context, command).await;
        }
        AppCommand::Scopes(command) => return super::app_scopes::run(context, command).await,
        AppCommand::Bundle(command) => return super::app_bundles::run(context, command).await,
        AppCommand::Testing(command) => return super::app_testing::run(context, command).await,
        AppCommand::Ata(command) => return super::app_ata::run(context, command).await,
        AppCommand::Obo(command) => return super::app_obo::run(context, command).await,
        AppCommand::VerifyWebhook {
            body_file,
            event_id,
            timestamp,
            key_version,
            signature,
            webhook_secret,
            tolerance_seconds,
        } => {
            return verify_webhook(
                context,
                &body_file,
                &event_id,
                &timestamp,
                &key_version,
                &signature,
                webhook_secret,
                tolerance_seconds,
            );
        }
        command => command,
    };

    if matches!(&command, AppCommand::Import { .. }) {
        context.require_test()?;
    }
    if matches!(&command, AppCommand::ApproveWebhook { .. }) && context.step_up.is_none() {
        return Err(CliError::Usage(
            "--step-up is required: run `iam step-up application.webhook.approve <APPLICATION_UUID>` first, then pass the returned assertion to `iam app approve-webhook`.".to_owned(),
        ));
    }

    let client = context.authenticated().await?;
    match command {
        AppCommand::List { status, page } => {
            let listed = match context.organization_if_set() {
                Some(org_id) => {
                    client
                        .applications()
                        .list_for_organization(org_id, status.as_deref(), &page.paging())
                        .await?
                }
                None => {
                    client
                        .applications()
                        .list(status.as_deref(), &page.paging())
                        .await?
                }
            };
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["app", "name", "status", "org", "version"]);
                    for app in &listed.items {
                        table.row([
                            app.app_id.clone(),
                            or_dash(app.app_name.as_deref()),
                            label(&app.status),
                            app.org_id.clone(),
                            app.version.to_string(),
                        ]);
                    }
                    table.print();
                    next_cursor(listed.page.has_more, listed.page.next_cursor.as_deref());
                    Ok(())
                }
            }
        }
        AppCommand::Create {
            app_id,
            name,
            org: _,
            webhook_url,
            webhook_secret,
            base_url,
            obo_endpoints,
            app_scope,
            webhook_scope,
            obo_review_message,
            testing_idle_days,
        } => {
            let (app_id, organization) = context.application_creation_identity(&app_id)?;
            let created = client
                .applications()
                .create(
                    &models::ApplicationCreate {
                        app_scope: app_scope.as_deref().map(scope_definition).transpose()?,
                        webhook_scope: webhook_scope
                            .map(|values| values.into_iter().map(webhook_scope_value).collect()),
                        obo_review_message,
                        testing_idle_days: testing_idle_days.map(i64::from),
                        app_id,
                        org_id: organization,
                        app_name: Some(name),
                        app_logo: None,
                        webhook_url,
                        webhook_secret,
                        base_url,
                        obo_endpoints: obo_endpoints
                            .as_deref()
                            .map(obo_endpoint_definitions)
                            .transpose()?,
                    },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&created),
                Format::Text => {
                    println!("Created {}.", created.application.app_id);
                    println!("Application ID: {}", created.application.id);
                    println!("Client secret: {}", created.app_secret);
                    println!("IAM stored the webhook signing secret you supplied.");
                    println!("The client secret is shown once. Store it now.");
                    crate::guidance::application_created(context, &created.application);
                    Ok(())
                }
            }
        }
        AppCommand::Show { app_id } => {
            let app_id = context.application_id(&app_id)?;
            let application = client.applications().get(&app_id).await?;
            report(context, &application)
        }
        AppCommand::Update {
            app_id,
            name,
            clear_name,
            logo,
            clear_logo,
            base_url,
            obo_endpoints,
            app_scope,
            webhook_scope,
            obo_review_message,
            testing_idle_days,
        } => {
            let app_id = context.application_id(&app_id)?;
            let current = client.applications().get(&app_id).await?;
            let updated = client
                .applications()
                .update(
                    &app_id,
                    current.version,
                    &models::ApplicationPatch {
                        app_scope: app_scope.as_deref().map(scope_definition).transpose()?,
                        webhook_scope: webhook_scope
                            .map(|values| values.into_iter().map(webhook_scope_value).collect()),
                        obo_review_message,
                        testing_idle_days: testing_idle_days.map(i64::from),
                        app_name: nullable_patch(name, clear_name),
                        app_logo: nullable_patch(logo, clear_logo),
                        base_url,
                        obo_endpoints: obo_endpoints
                            .as_deref()
                            .map(obo_endpoint_definitions)
                            .transpose()?,
                    },
                    &context.mutation(),
                )
                .await?;
            report(context, &updated)
        }
        AppCommand::RotateSecret { app_id } => {
            let app_id = context.application_id(&app_id)?;
            let current = client.applications().get(&app_id).await?;
            let rotated = client
                .applications()
                .rotate_secret(&app_id, current.version, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&rotated),
                Format::Text => {
                    println!("Client secret: {}", rotated.app_secret);
                    println!("The previous one stopped working.");
                    Ok(())
                }
            }
        }
        AppCommand::RotateWebhookSecret {
            app_id,
            webhook_secret,
        } => {
            let app_id = context.application_id(&app_id)?;
            let current = client.applications().get(&app_id).await?;
            let rotated = client
                .applications()
                .rotate_webhook_secret(
                    &app_id,
                    current.version,
                    &models::ApplicationWebhookSecretRotate { webhook_secret },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&rotated),
                Format::Text => {
                    println!(
                        "Installed webhook signing secret version {}.",
                        rotated.webhook_secret_version
                    );
                    println!("The previous secret stopped signing new deliveries.");
                    Ok(())
                }
            }
        }
        AppCommand::Discover { .. }
        | AppCommand::Read(_)
        | AppCommand::Token(_)
        | AppCommand::Verification(_)
        | AppCommand::Scopes(_)
        | AppCommand::Bundle(_)
        | AppCommand::Testing(_)
        | AppCommand::Obo(_)
        | AppCommand::Ata(_)
        | AppCommand::VerifyWebhook { .. } => unreachable!(),
        AppCommand::Import { app_id } => {
            let imported = client
                .applications()
                .import_from_production(&app_id, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&imported),
                Format::Text => {
                    println!("Imported {app_id} into this testing environment.");
                    println!("Test client secret: {}", imported.app_secret);
                    println!("Its inherited production webhook signing secret was not revealed.");
                    Ok(())
                }
            }
        }
        AppCommand::Webhook { app_id } => {
            let app_id = context.application_id(&app_id)?;
            let webhook = client.applications().webhook(&app_id).await?;
            report_webhook(context, &webhook)
        }
        AppCommand::ApproveWebhook { app_id } => {
            let app_id = context.application_id(&app_id)?;
            let current = client.applications().webhook(&app_id).await?;
            let approved = client
                .applications()
                .approve_webhook(&app_id, current.version, &context.mutation())
                .await?;
            if context.format == Format::Text {
                println!("Approved and activated the webhook endpoint.");
            }
            report_webhook(context, &approved)
        }
        AppCommand::SetWebhook {
            app_id,
            webhook_url,
            webhook_secret,
        } => {
            let app_id = context.application_id(&app_id)?;
            let current = client.applications().get(&app_id).await?;
            let proposed = client
                .applications()
                .replace_webhook(
                    &app_id,
                    current.version,
                    &models::ApplicationWebhookReplace {
                        url: webhook_url,
                        webhook_secret,
                    },
                    &context.mutation(),
                )
                .await?;
            match context.format {
                Format::Json => json(&proposed),
                Format::Text => {
                    if context.testing_environment_id().is_some() {
                        println!("Activated the test webhook endpoint.");
                    } else {
                        println!(
                            "Proposed. An owning-org owner/admin or IAM reviewer can activate it with `iam app approve-webhook` and a fresh approval step-up."
                        );
                    }
                    if let Some(secret) = proposed.webhook_signing_secret.as_deref() {
                        println!("Webhook signing secret: {secret}");
                        if let Some(expires_at) = proposed.secret_replay_expires_at {
                            println!("Secret replay expires: {}", timestamp(expires_at));
                        }
                        println!(
                            "Store this secret for the test receiver's signature verification."
                        );
                    }
                    report_webhook(context, &proposed)
                }
            }
        }
        AppCommand::DeadLetters { app_id, page } => {
            let app_id = context.application_id(&app_id)?;
            let listed = client
                .applications()
                .dead_letters(&app_id, &page.paging())
                .await?;
            dead_letters(context, &listed)
        }
        AppCommand::Replay { app_id, deliveries } => {
            let app_id = context.application_id(&app_id)?;
            let replayed = client
                .applications()
                .replay_dead_letters(
                    &app_id,
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
        AppCommand::History { app_id, page } => {
            let app_id = context.application_id(&app_id)?;
            let listed = client
                .applications()
                .login_history(&app_id, &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["when", "event", "actor", "outcome"]);
                    for event in &listed.items {
                        table.row([
                            timestamp(event.occurred_at),
                            label(&event.event_type),
                            event
                                .actor
                                .public_id
                                .clone()
                                .unwrap_or_else(|| "Unavailable".to_owned()),
                            if event.success { "success" } else { "failed" }.to_owned(),
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

async fn discover(
    context: &Context,
    app_id: &str,
    requester_app_id: &str,
    app_secret: Option<String>,
) -> Result<()> {
    let secret = prompted(
        app_secret,
        "Requesting Application secret: ",
        "--app-secret",
    )?;
    let app_id = context.application_id(app_id)?;
    let requester_app_id = context.application_id(requester_app_id)?;
    let discovered = application_client(context, &requester_app_id, &secret)
        .applications()
        .discover_base_url(&app_id)
        .await?;
    match context.format {
        Format::Json => json(&discovered),
        Format::Text => {
            println!("{}", discovered.base_url);
            Ok(())
        }
    }
}

#[allow(
    clippy::option_option,
    reason = "JSON Merge Patch has distinct omitted, null, and value states"
)]
fn nullable_patch<T>(value: Option<T>, clear: bool) -> Option<Option<T>> {
    if clear { Some(None) } else { value.map(Some) }
}

#[allow(clippy::too_many_lines)]
async fn token(context: &Context, command: AppTokenCommand) -> Result<()> {
    match command {
        AppTokenCommand::Authorization {
            app_id,
            token,
            org_context,
            app_secret,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = prompted(app_secret, "Application secret: ", "--app-secret")?;
            let token = prompted(token, "Application access token: ", "--token")?;
            let authorization = application_client(context, &app_id, &secret)
                .oauth()
                .authorization(&token, org_context.as_deref())
                .await?;
            match context.format {
                Format::Json => json(&authorization),
                Format::Text => {
                    if let Some(authorization) = &authorization {
                        print_authorization(authorization);
                    } else {
                        println!(
                            "No current organization authorization (inactive, mismatched, or an unscoped token with no --org-context)."
                        );
                    }
                    Ok(())
                }
            }
        }
        AppTokenCommand::Authorizations {
            app_id,
            token,
            app_secret,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = prompted(app_secret, "Application secret: ", "--app-secret")?;
            let token = prompted(token, "Application access token: ", "--token")?;
            let authorizations = application_client(context, &app_id, &secret)
                .oauth()
                .authorizations(&token)
                .await?;
            match context.format {
                Format::Json => json(&authorizations),
                Format::Text => {
                    match authorizations.as_deref() {
                        None => {
                            println!(
                                "The token is inactive or is not an Application access token."
                            );
                        }
                        Some([]) => println!(
                            "The token is active and reaches no organization: its subject holds no active membership."
                        ),
                        Some(authorizations) => {
                            for (index, authorization) in authorizations.iter().enumerate() {
                                if index > 0 {
                                    println!();
                                }
                                print_authorization(authorization);
                            }
                        }
                    }
                    Ok(())
                }
            }
        }
        AppTokenCommand::Exchange {
            app_id,
            testing_org,
            slt,
            app_secret,
            idempotency_key,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = prompted(app_secret, "Application secret: ", "--app-secret")?;
            let slt = prompted(slt, "Short-lived token: ", "--slt")?;
            let client = application_client(context, &app_id, &secret);
            let mutation = mutation_with_optional_key(idempotency_key)?;
            let tokens = if let Some(org_id) = testing_org {
                client
                    .oauth()
                    .login_testing_actor(&app_id, &slt, &org_id, &mutation)
                    .await?
            } else {
                client.oauth().login(&app_id, &slt, &mutation).await?
            };
            report_oauth_tokens(context, &tokens)
        }
        AppTokenCommand::Refresh {
            app_id,
            refresh_token,
            app_secret,
            idempotency_key,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = prompted(app_secret, "Application secret: ", "--app-secret")?;
            let refresh_token = prompted(
                refresh_token,
                "Application refresh token: ",
                "--refresh-token",
            )?;
            let tokens = application_client(context, &app_id, &secret)
                .oauth()
                .refresh(
                    &app_id,
                    &refresh_token,
                    &mutation_with_optional_key(idempotency_key)?,
                )
                .await?;
            report_oauth_tokens(context, &tokens)
        }
        AppTokenCommand::Introspect {
            app_id,
            token,
            token_type,
            org_context,
            app_secret,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = prompted(app_secret, "Application secret: ", "--app-secret")?;
            let token = prompted(token, "Token to introspect: ", "--token")?;
            let inspected = application_client(context, &app_id, &secret)
                .oauth()
                .introspect(
                    &models::TokenIntrospectionRequest {
                        token,
                        token_type_hint: token_type.map(token_type_hint),
                    },
                    org_context.as_deref(),
                )
                .await?;
            report_introspection(context, &inspected)
        }
        AppTokenCommand::Revoke {
            app_id,
            token,
            token_type,
            app_secret,
            idempotency_key,
        } => {
            let app_id = context.application_id(&app_id)?;
            let secret = prompted(app_secret, "Application secret: ", "--app-secret")?;
            let token = prompted(token, "Token to revoke: ", "--token")?;
            application_client(context, &app_id, &secret)
                .oauth()
                .revoke(
                    &models::OAuthRevocationRequest {
                        token,
                        token_type_hint: token_type.map(revocation_token_type_hint),
                    },
                    &mutation_with_optional_key(idempotency_key)?,
                )
                .await?;
            match context.format {
                Format::Json => json(&serde_json::json!({ "accepted": true })),
                Format::Text => {
                    println!("Revocation accepted.");
                    Ok(())
                }
            }
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "each argument is one captured security header or verifier input"
)]
fn verify_webhook(
    context: &Context,
    body_file: &Path,
    event_id: &str,
    timestamp: &str,
    key_version: &str,
    signature: &str,
    webhook_secret: String,
    tolerance_seconds: u64,
) -> Result<()> {
    let secret = WebhookSecret::new(webhook_secret)?;
    let parsed_key_version = key_version.parse::<i64>().map_err(|_| {
        CliError::Usage("X-Silicon-IAM-Key-Version must be a signed integer".to_owned())
    })?;
    let keyring = WebhookSecretKeyring::new(parsed_key_version, secret)?;
    let verifier =
        WebhookVerifier::new(keyring).with_tolerance(Duration::from_secs(tolerance_seconds));
    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "x-silicon-iam-event-id", event_id)?;
    insert_header(&mut headers, "x-silicon-iam-timestamp", timestamp)?;
    insert_header(&mut headers, "x-silicon-iam-key-version", key_version)?;
    insert_header(&mut headers, "x-silicon-iam-signature", signature)?;
    let body = read_body(body_file)?;
    let delivery = verifier.verify(&headers, &body)?;

    match context.anonymous().environment() {
        Some(environment) => delivery.verify_testing_environment(environment)?,
        None if delivery.is_testing() => {
            return Err(CliError::Usage(
                "a testing webhook must be verified with `--test <environment-id>` so its embedded root key is authenticated"
                    .to_owned(),
            ));
        }
        None => {}
    }

    match context.format {
        Format::Json => json(delivery.event()),
        Format::Text => {
            println!("Verified webhook {}.", delivery.event_id());
            if let Some(environment_id) = context.testing_environment_id() {
                println!("Testing environment: {environment_id}");
            }
            json(delivery.event())
        }
    }
}

pub(super) fn application_client(context: &Context, app_id: &str, secret: &str) -> Client {
    context
        .anonymous()
        .with_credential(Credential::application(app_id, secret))
}

pub(super) fn prompted(value: Option<String>, label: &str, flag: &str) -> Result<String> {
    match value {
        Some(value) if value.trim().is_empty() => {
            Err(CliError::Usage(format!("{flag} cannot be empty")))
        }
        Some(value) => Ok(value),
        None => crate::commands::auth::prompt_secret(
            label,
            &format!(
                "Supply {flag} <value> for noninteractive use, or run this command in an interactive terminal to enter the secret without echoing it. Keep credentials out of shared command logs."
            ),
        ),
    }
}

fn mutation_with_optional_key(key: Option<String>) -> Result<Mutation> {
    match key {
        Some(key) => Ok(Mutation::with_key(IdempotencyKey::parse(key)?)),
        None => Ok(Mutation::new()),
    }
}

const fn token_type_hint(kind: AppTokenType) -> models::TokenIntrospectionRequestTokenTypeHint {
    match kind {
        AppTokenType::AccessToken => models::TokenIntrospectionRequestTokenTypeHint::AccessToken,
        AppTokenType::RefreshToken => models::TokenIntrospectionRequestTokenTypeHint::RefreshToken,
    }
}

const fn revocation_token_type_hint(
    kind: AppTokenType,
) -> models::OAuthRevocationRequestTokenTypeHint {
    match kind {
        AppTokenType::AccessToken => models::OAuthRevocationRequestTokenTypeHint::AccessToken,
        AppTokenType::RefreshToken => models::OAuthRevocationRequestTokenTypeHint::RefreshToken,
    }
}

fn report_oauth_tokens(context: &Context, tokens: &models::OAuthTokenResponse) -> Result<()> {
    match context.format {
        Format::Json => json(tokens),
        Format::Text => {
            println!("Access token: {}", tokens.access_token);
            println!("Refresh token: {}", tokens.refresh_token);
            println!("Expires in: {} seconds", tokens.expires_in);
            println!("Scope: {}", tokens.scope);
            println!(
                "Actor: {}",
                tokens
                    .actor
                    .as_ref()
                    .map_or("undisclosed (requires self.identity.read)", |actor| actor
                        .public_id
                        .as_str())
            );
            Ok(())
        }
    }
}

fn report_introspection(context: &Context, inspected: &models::TokenIntrospection) -> Result<()> {
    match context.format {
        Format::Json => json(inspected),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["active", &inspected.active.to_string()]);
            table.row([
                "actor_type",
                &inspected
                    .actor_type
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), label),
            ]);
            table.row(["client_id", &or_dash(inspected.client_id.as_deref())]);
            table.row(["org_id", &or_dash(inspected.org_id.as_deref())]);
            table.row(["scope", &or_dash(inspected.scope.as_deref())]);
            table.row(["audience", &or_dash(inspected.audience.as_deref())]);
            table.row([
                "expires_at",
                &inspected.expires_at.map_or_else(
                    || "-".to_owned(),
                    |value| {
                        time::OffsetDateTime::from_unix_timestamp(value)
                            .map_or_else(|_| value.to_string(), timestamp)
                    },
                ),
            ]);
            table.print();
            if let Some(authorization) = &inspected.authorization {
                print_authorization(authorization);
            }
            Ok(())
        }
    }
}

pub(super) fn print_authorization(authorization: &models::ApplicationAuthorization) {
    println!(
        "Authorization: {} in {}",
        authorization.public_id.as_deref().unwrap_or("undisclosed"),
        authorization.org_id
    );
    println!(
        "Membership: {} (version {}, epoch {})",
        authorization.membership_id,
        authorization.membership_version,
        authorization.authorization_epoch
    );
    println!("Audience: {}", authorization.audience);
    println!(
        "Testing environment: {}",
        authorization
            .testing_environment_id
            .map_or_else(|| "production".to_owned(), |id| id.to_string())
    );
    println!(
        "Role: {}",
        authorization.org_role.as_ref().map_or_else(
            || "undisclosed (requires self.membership.read)".to_owned(),
            label
        )
    );
    println!(
        "Tags: {}",
        authorization.tags.as_ref().map_or_else(
            || "undisclosed (requires self.tags.read)".to_owned(),
            |tags| if tags.is_empty() {
                "none".to_owned()
            } else {
                tags.iter()
                    .map(|tag| format!("{} ({})", tag.name, tag.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        )
    );
    println!("Disclosure scopes: {}", authorization.scopes.join(" "));
}

fn read_body(path: &Path) -> Result<Vec<u8>> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes)?;
        Ok(bytes)
    } else {
        Ok(std::fs::read(path)?)
    }
}

fn obo_endpoint_definitions(input: &str) -> Result<Vec<models::ApplicationOboEndpoint>> {
    serde_json::from_str(input)
        .map_err(|error| CliError::Usage(format!("--obo-endpoints is not valid JSON: {error}")))
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<()> {
    let value = HeaderValue::from_str(value)
        .map_err(|_| CliError::Usage(format!("{name} is not a valid HTTP header value")))?;
    headers.insert(name, value);
    Ok(())
}

fn report(context: &Context, application: &models::Application) -> Result<()> {
    match context.format {
        Format::Json => json(application),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["id", &application.id]);
            table.row(["app", &application.app_id]);
            table.row(["name", &or_dash(application.app_name.as_deref())]);
            table.row(["base_url", &application.base_url]);
            table.row(["status", &label(&application.status)]);
            table.row(["org", &application.org_id]);
            table.row(["active_scopes", &application.approved_scopes.join(", ")]);
            table.row(["requested_scopes", &application.requested_scopes.join(", ")]);
            table.row(["scope_version", &application.scope_version.to_string()]);
            table.row([
                "pending_review",
                &application.has_pending_changes.to_string(),
            ]);
            table.row(["version", &application.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}

fn report_webhook(context: &Context, webhook: &models::ApplicationWebhook) -> Result<()> {
    match context.format {
        Format::Json => json(webhook),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            if let Some(application_id) = &webhook.application_id {
                table.row(["application_id", application_id.as_str()]);
            }
            table.row(["active_url", &or_dash(webhook.active_url.as_deref())]);
            table.row(["pending_url", &or_dash(webhook.pending_url.as_deref())]);
            table.row(["status", &label(&webhook.status)]);
            table.row(["secret_version", &webhook.secret_version.to_string()]);
            table.row([
                "secret_replay_expires_at",
                &timestamp_or_dash(webhook.secret_replay_expires_at),
            ]);
            table.row(["version", &webhook.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}

/// Parses the structured IAM and external permission declaration.
pub(super) fn scope_definition(input: &str) -> Result<models::ApplicationScope> {
    serde_json::from_str(input)
        .map_err(|error| CliError::Usage(format!("--app-scope is not valid scope JSON: {error}")))
}

fn webhook_scope_value(value: String) -> models::ApplicationWebhookScope {
    match value.as_str() {
        "full" => models::ApplicationWebhookScope::Full,
        "membership" => models::ApplicationWebhookScope::Membership,
        "updates" => models::ApplicationWebhookScope::Updates,
        "trust" => models::ApplicationWebhookScope::Trust,
        _ => models::ApplicationWebhookScope::Other(value),
    }
}

#[cfg(test)]
mod tests {
    use super::obo_endpoint_definitions;

    #[test]
    fn endpoint_catalog_requires_explicit_critical_classification() {
        assert!(obo_endpoint_definitions(r#"[{"endpoint_id":"files.upload","path":"/v1/files","critical":true,"metadata":{}}]"#).is_ok());
        assert!(
            obo_endpoint_definitions(
                r#"[{"endpoint_id":"files.upload","path":"/v1/files","metadata":{}}]"#
            )
            .is_err()
        );
        assert!(obo_endpoint_definitions("{}").is_err());
    }
}
