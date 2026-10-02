//! Explicit OBO consent and reusable endpoint tokens.

use crate::{
    cli::{AppOboCommand, AppOboDecision},
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, label, next_cursor, timestamp},
};
use silicon_iam_client::{Client, IdempotencyKey, Mutation, Paging, models};

use super::app::{application_client, print_authorization, prompted};

#[allow(
    clippy::too_many_lines,
    reason = "each arm maps a distinct OBO protocol step"
)]
pub async fn run(context: &Context, command: AppOboCommand) -> Result<()> {
    match command {
        AppOboCommand::Endpoints {
            audience_app_id,
            requester_app_id,
            app_secret,
        } => {
            let client = app(context, &requester_app_id, app_secret)?;
            let catalog = client
                .obo()
                .endpoints(&context.application_id(&audience_app_id)?)
                .await?;
            match context.format {
                Format::Json => json(&catalog),
                Format::Text => {
                    println!("Application: {}", catalog.application.app_id);
                    let mut table =
                        Table::new(["endpoint", "path", "classification", "ttl", "dependencies"]);
                    for endpoint in &catalog.endpoints {
                        table.row([
                            endpoint.endpoint_id.clone(),
                            endpoint.path.clone(),
                            if endpoint.critical {
                                "Critical"
                            } else {
                                "Non critical"
                            }
                            .to_owned(),
                            endpoint
                                .ttl_seconds
                                .map_or_else(|| "300".to_owned(), |v| v.to_string()),
                            endpoint
                                .downstream
                                .as_deref()
                                .unwrap_or_default()
                                .iter()
                                .map(|edge| format!("{}: {}", edge.audience, edge.endpoint_id))
                                .collect::<Vec<_>>()
                                .join(", "),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        AppOboCommand::Authorize {
            redirect_uri,
            state,
            app_id,
            endpoints,
            org_context,
            subject_token,
            app_secret,
            idempotency_key,
        } => {
            let endpoints = serde_json::from_str::<Vec<models::OboAuthorizationEndpoint>>(
                &endpoints,
            )
            .map_err(|error| {
                CliError::Usage(format!(
                    "--endpoints must be an array of audience/endpoint_id objects: {error}"
                ))
            })?;
            if endpoints.is_empty() {
                return Err(CliError::Usage(
                    "--endpoints must contain at least one root endpoint".to_owned(),
                ));
            }
            let client = app(context, &app_id, app_secret)?;
            let request = models::OboAuthorizationRequest {
                redirect_uri,
                state,
                subject_token: prompted(
                    subject_token,
                    "Normal application access token: ",
                    "--subject-token",
                )?,
                org_id: org_context,
                endpoints,
            };
            let detail = client
                .obo()
                .authorize(&request, &mutation(idempotency_key)?)
                .await?;
            consent(context, &detail)
        }
        AppOboCommand::Status {
            app_id,
            request_id,
            app_secret,
        } => {
            let detail = app(context, &app_id, app_secret)?
                .obo()
                .authorization(request_id)
                .await?;
            consent(context, &detail)
        }
        AppOboCommand::Consent { request_id } => {
            let detail = context
                .authenticated()
                .await?
                .obo()
                .consent(request_id)
                .await?;
            consent(context, &detail)
        }
        AppOboCommand::Decide {
            request_id,
            decision,
            consent_version,
            contexts_file,
            idempotency_key,
        } => {
            let decision = match decision {
                AppOboDecision::Approve => models::OboConsentDecisionDecision::Approve,
                AppOboDecision::Decline => models::OboConsentDecisionDecision::Decline,
            };
            let contexts = contexts_file
                .map(|path| {
                    let contents = std::fs::read_to_string(path).map_err(|error| {
                        CliError::Usage(format!("Could not read provider contexts: {error}"))
                    })?;
                    serde_json::from_str::<Vec<models::OboProviderContext>>(&contents).map_err(
                        |error| CliError::Usage(format!("Invalid provider context file: {error}")),
                    )
                })
                .transpose()?;
            let result = context
                .authenticated()
                .await?
                .obo()
                .decide(
                    request_id,
                    &models::OboConsentDecision {
                        contexts,
                        decision,
                        version: consent_version,
                    },
                    &mutation(idempotency_key)?,
                )
                .await?;
            match context.format {
                Format::Json => json(&result),
                Format::Text => {
                    println!("Request {}: {}", result.request_id, label(&result.status));
                    if let Some(code) = &result.authorization_code {
                        println!("Authorization code: {code}");
                        println!(
                            "Give this code to the requesting app before {}.",
                            timestamp(result.expires_at)
                        );
                    }
                    Ok(())
                }
            }
        }
        AppOboCommand::Token {
            app_id,
            request_id,
            authorization_code,
            app_secret,
            idempotency_key,
        } => {
            let client = app(context, &app_id, app_secret)?;
            let code = prompted(
                authorization_code,
                "OBO authorization code: ",
                "--authorization-code",
            )?;
            let response = client
                .obo()
                .exchange_code(request_id, &code, &mutation(idempotency_key)?)
                .await?;
            tokens(context, &response)
        }
        AppOboCommand::Recover {
            app_id,
            grant_id,
            subject_token,
            app_secret,
            idempotency_key,
        } => {
            let subject = prompted(
                subject_token,
                "Current application login token: ",
                "--subject-token",
            )?;
            let result = app(context, &app_id, app_secret)?
                .obo()
                .recover(grant_id, &subject, &mutation(idempotency_key)?)
                .await?;
            tokens(context, &result)
        }
        AppOboCommand::Refresh {
            app_id,
            refresh_token,
            app_secret,
            idempotency_key,
        } => {
            let client = app(context, &app_id, app_secret)?;
            let refresh = prompted(refresh_token, "OBO refresh token: ", "--refresh-token")?;
            let response = client
                .obo()
                .refresh(&refresh, &mutation(idempotency_key)?)
                .await?;
            tokens(context, &response)
        }
        AppOboCommand::Verify {
            audience_app_id,
            endpoint_id,
            app_secret,
            access_token,
            method,
            path,
        } => {
            let client = app(context, &audience_app_id, app_secret)?;
            let result = client
                .obo()
                .verify(&models::OboTokenVerificationRequest {
                    access_token: prompted(access_token, "OBO access token: ", "--access-token")?,
                    endpoint_id,
                    request: models::OboTokenRequestBinding {
                        method: canonical_method(&method)?,
                        path,
                    },
                })
                .await?;
            match context.format {
                Format::Json => json(&result),
                Format::Text => {
                    println!("Verified reusable token {}.", result.token_id);
                    println!("Actor: {}", result.actor.public_id);
                    println!("Organization: {}", result.org_id);
                    println!("Caller: {}", result.issuer_app_id);
                    println!("Originating app: {}", result.originating_app_id);
                    println!(
                        "Endpoint: {}: {}",
                        result.endpoint.app_id, result.endpoint.endpoint_id
                    );
                    print_authorization(&result.authorization);
                    println!("Expires: {}", timestamp(result.expires_at));
                    Ok(())
                }
            }
        }
        AppOboCommand::Delegate {
            app_id,
            audience_app_id,
            endpoint_id,
            access_token,
            app_secret,
            idempotency_key,
        } => {
            let client = app(context, &app_id, app_secret)?;
            let result = client
                .obo()
                .delegate(
                    &models::OboDelegationRequest {
                        access_token: prompted(
                            access_token,
                            "Incoming OBO access token: ",
                            "--access-token",
                        )?,
                        audience: context.application_id(&audience_app_id)?,
                        endpoint_id,
                    },
                    &mutation(idempotency_key)?,
                )
                .await?;
            match context.format {
                Format::Json => json(&result),
                Format::Text => {
                    println!("Grant: {}", result.grant_id);
                    println!("Endpoint: {}: {}", result.audience, result.endpoint_id);
                    println!("Access token: {}", result.access_token);
                    println!("Expires: {}", timestamp(result.expires_at));
                    Ok(())
                }
            }
        }
        AppOboCommand::Grants { cursor, limit } => {
            let mut paging = Paging::new();
            if let Some(cursor) = cursor {
                paging = paging.after(cursor);
            }
            if let Some(limit) = limit {
                paging = paging.limit(limit);
            }
            let grants = context
                .authenticated()
                .await?
                .obo()
                .grants_page(&paging)
                .await?;
            match context.format {
                Format::Json => json(&grants),
                Format::Text => {
                    for grant in &grants.items {
                        println!(
                            "{} | {} | {} | {} | {}: {}",
                            grant.id,
                            grant.status,
                            grant.app_id,
                            grant.org_id,
                            grant.audience,
                            grant.endpoint_id
                        );
                        nodes(&grant.endpoints, 1);
                    }
                    next_cursor(grants.page.has_more, grants.page.next_cursor.as_deref());
                    Ok(())
                }
            }
        }
        AppOboCommand::Revoke {
            grant_id,
            idempotency_key,
        } => {
            let result = context
                .authenticated()
                .await?
                .obo()
                .revoke(grant_id, &mutation(idempotency_key)?)
                .await?;
            match context.format {
                Format::Json => json(&result),
                Format::Text => {
                    println!(
                        "Revoked OBO grant {} and its delegated authority.",
                        result.id
                    );
                    Ok(())
                }
            }
        }
    }
}

fn app(context: &Context, app_id: &str, secret: Option<String>) -> Result<Client> {
    let app_id = context.application_id(app_id)?;
    let secret = prompted(secret, "Application secret: ", "--app-secret")?;
    Ok(application_client(context, &app_id, &secret))
}

fn mutation(key: Option<String>) -> Result<Mutation> {
    key.map_or_else(
        || Ok(Mutation::new()),
        |key| Ok(Mutation::with_key(IdempotencyKey::parse(key)?)),
    )
}

fn consent(context: &Context, detail: &models::OboConsentDetail) -> Result<()> {
    match context.format {
        Format::Json => json(detail),
        Format::Text => {
            println!(
                "Request: {} (version {}, {})",
                detail.id,
                detail.version,
                label(&detail.status)
            );
            println!(
                "User: {} | Organization: {}",
                detail.actor.public_id, detail.org_id
            );
            println!(
                "{} ({})",
                detail.app_name.as_deref().unwrap_or(&detail.app_id),
                detail.app_id
            );
            nodes(&detail.endpoints, 1);
            println!(
                "Approval remains valid until revoked in IAM; ordinary logout does not remove it."
            );
            println!("Expires: {}", timestamp(detail.expires_at));
            if let Some(url) = &detail.authorization_url {
                println!("Review in IAM: {url}");
            }
            Ok(())
        }
    }
}

fn nodes(items: &[models::OboConsentNode], depth: usize) {
    for node in items {
        println!(
            "{}-> {} ({}): {} [{}]",
            "  ".repeat(depth),
            node.app_name.as_deref().unwrap_or(&node.audience),
            node.audience,
            node.description,
            if node.critical {
                "Critical"
            } else {
                "Non critical"
            }
        );
        if let Some(note) = &node.note_to_user {
            println!("{}Note: {note}", "  ".repeat(depth + 1));
        }
        if let Some(warnings) = node
            .additional_warnings
            .as_ref()
            .filter(|items| !items.is_empty())
        {
            println!(
                "{}Warnings: {}",
                "  ".repeat(depth + 1),
                warnings
                    .iter()
                    .filter_map(|warning| serde_json::to_value(warning)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned)))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        nodes(&node.downstream, depth + 1);
    }
}

fn tokens(context: &Context, response: &models::OboTokenResponse) -> Result<()> {
    match context.format {
        Format::Json => json(response),
        Format::Text => {
            for token in &response.items {
                println!(
                    "Grant: {} | {} | {}: {}",
                    token.grant_id, token.org_id, token.audience, token.endpoint_id
                );
                println!("Access token: {}", token.access_token);
                println!("Refresh token: {}", token.refresh_token);
                println!("Expires: {}", timestamp(token.expires_at));
            }
            Ok(())
        }
    }
}

fn canonical_method(input: &str) -> Result<String> {
    let method = input.to_ascii_uppercase();
    http::Method::from_bytes(method.as_bytes())
        .map_err(|_| CliError::Usage(format!("{input:?} is not a valid HTTP request method")))?;
    Ok(method)
}
