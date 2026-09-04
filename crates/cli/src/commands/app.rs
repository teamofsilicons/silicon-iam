//! Applications.

use std::{io::Read as _, path::Path, time::Duration};

use hmac::{Hmac, Mac as _};
use http::{HeaderMap, HeaderValue};
use sha2::{Digest as _, Sha256};
use silicon_iam_client::{
    Client, Credential, IdempotencyKey, Mutation, WebhookSecret, WebhookSecretKeyring,
    WebhookVerifier, models,
};
use time::OffsetDateTime;

use crate::{
    cli::{AppCommand, AppOboCommand, AppTokenCommand, AppTokenType, RequestBodyArgs},
    commands::silicon::dead_letters,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, or_dash, timestamp},
};

type HmacSha256 = Hmac<Sha256>;

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
        AppCommand::Token(command) => return token(context, command).await,
        AppCommand::Obo(command) => return obo(context, command).await,
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

    let client = context.authenticated().await?;
    match command {
        AppCommand::List { status, page } => {
            let listed = client
                .applications()
                .list(status.as_deref(), &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["app", "name", "status", "org", "version"]);
                    for app in &listed.items {
                        table.row([
                            app.app_id.clone(),
                            or_dash(app.app_name.as_deref()),
                            format!("{:?}", app.status).to_lowercase(),
                            app.org_id.clone(),
                            app.version.to_string(),
                        ]);
                    }
                    table.print();
                    Ok(())
                }
            }
        }
        AppCommand::Create {
            app_id,
            name,
            org,
            webhook_url,
            base_url,
            obo_endpoints,
        } => {
            let organization = context.organization_or(org.as_deref())?;
            let created = client
                .applications()
                .create(
                    &models::ApplicationCreate {
                        app_id,
                        org_id: organization.to_owned(),
                        app_name: Some(name),
                        app_logo: None,
                        webhook_url,
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
                    println!("Client secret: {}", created.app_secret);
                    println!("Webhook signing secret: {}", created.webhook_signing_secret);
                    println!("Both are shown once. Store them now; they can only be rotated.");
                    Ok(())
                }
            }
        }
        AppCommand::Show { app_id } => {
            let application = client.applications().get(&app_id).await?;
            report(context, &application)
        }
        AppCommand::Update {
            app_id,
            name,
            base_url,
            obo_endpoints,
        } => {
            let current = client.applications().get(&app_id).await?;
            let updated = client
                .applications()
                .update(
                    &app_id,
                    current.version,
                    &models::ApplicationPatch {
                        app_name: name,
                        app_logo: None,
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
        AppCommand::RotateWebhookSecret { app_id } => {
            let current = client.applications().get(&app_id).await?;
            let rotated = client
                .applications()
                .rotate_webhook_secret(&app_id, current.version, &context.mutation())
                .await?;
            match context.format {
                Format::Json => json(&rotated),
                Format::Text => {
                    println!("Webhook signing secret: {}", rotated.webhook_signing_secret);
                    println!("The previous secret stopped signing new deliveries.");
                    Ok(())
                }
            }
        }
        AppCommand::Discover { .. }
        | AppCommand::Token(_)
        | AppCommand::Obo(_)
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
            let webhook = client.applications().webhook(&app_id).await?;
            json(&webhook)
        }
        AppCommand::SetWebhook { app_id, url } => {
            let current = client.applications().get(&app_id).await?;
            let proposed = client
                .applications()
                .replace_webhook(
                    &app_id,
                    current.version,
                    &models::ApplicationWebhookReplace { url },
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
                            "Proposed. The service verifies the endpoint before activating it."
                        );
                    }
                    if let Some(secret) = &proposed.webhook_signing_secret {
                        println!("Test webhook signing secret: {secret}");
                        if let Some(expires_at) = proposed.secret_replay_expires_at {
                            println!("Secret replay expires: {}", timestamp(expires_at));
                        }
                        println!("Store it now; the inherited production key was replaced.");
                    }
                    Ok(())
                }
            }
        }
        AppCommand::DeadLetters { app_id, page } => {
            let listed = client
                .applications()
                .dead_letters(&app_id, &page.paging())
                .await?;
            dead_letters(context, &listed)
        }
        AppCommand::Replay { app_id, deliveries } => {
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
            json(&replayed)
        }
        AppCommand::History { app_id, page } => {
            let listed = client
                .applications()
                .login_history(&app_id, &page.paging())
                .await?;
            match context.format {
                Format::Json => json(&listed),
                Format::Text => {
                    let mut table = Table::new(["when", "event", "carbon"]);
                    for event in &listed.items {
                        table.row([
                            timestamp(event.occurred_at),
                            format!("{:?}", event.event_type).to_lowercase(),
                            event.actor.public_id.clone(),
                        ]);
                    }
                    table.print();
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
    let secret = prompted(app_secret, "Requesting Application secret: ")?;
    let discovered = application_client(context, requester_app_id, &secret)
        .applications()
        .discover_base_url(app_id)
        .await?;
    match context.format {
        Format::Json => json(&discovered),
        Format::Text => {
            println!("{}", discovered.base_url);
            Ok(())
        }
    }
}

async fn token(context: &Context, command: AppTokenCommand) -> Result<()> {
    match command {
        AppTokenCommand::Exchange {
            app_id,
            slt,
            app_secret,
            idempotency_key,
        } => {
            let secret = prompted(app_secret, "Application secret: ")?;
            let slt = prompted(slt, "Short-lived token: ")?;
            let tokens = application_client(context, &app_id, &secret)
                .oauth()
                .token(
                    &models::ApplicationTokenRequest {
                        app_id,
                        slt: Some(slt),
                        refresh_token: None,
                    },
                    &mutation_with_optional_key(idempotency_key)?,
                )
                .await?;
            report_oauth_tokens(context, &tokens)
        }
        AppTokenCommand::Refresh {
            app_id,
            refresh_token,
            app_secret,
            idempotency_key,
        } => {
            let secret = prompted(app_secret, "Application secret: ")?;
            let refresh_token = prompted(refresh_token, "Application refresh token: ")?;
            let tokens = application_client(context, &app_id, &secret)
                .oauth()
                .token(
                    &models::ApplicationTokenRequest {
                        app_id,
                        slt: None,
                        refresh_token: Some(refresh_token),
                    },
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
            let secret = prompted(app_secret, "Application secret: ")?;
            let token = prompted(token, "Token to introspect: ")?;
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
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the three protocol steps stay adjacent so their shared binding is auditable"
)]
async fn obo(context: &Context, command: AppOboCommand) -> Result<()> {
    match command {
        AppOboCommand::Endpoints {
            audience_app_id,
            requester_app_id,
            app_secret,
        } => {
            let secret = prompted(app_secret, "Requesting Application secret: ")?;
            let catalog = application_client(context, &requester_app_id, &secret)
                .obo()
                .endpoints(&audience_app_id)
                .await?;
            report_obo_catalog(context, &catalog)
        }
        AppOboCommand::Exchange {
            audience_app_id,
            endpoint_id,
            requester_app_id,
            app_secret,
            subject_token,
            method,
            metadata,
            idempotency_key,
            timestamp,
            body,
        } => {
            let secret = prompted(app_secret, "Requesting Application secret: ")?;
            let subject_token = prompted(subject_token, "Application access token: ")?;
            let client = application_client(context, &requester_app_id, &secret);
            let catalog = client.obo().endpoints(&audience_app_id).await?;
            let endpoint = catalog
                .endpoints
                .iter()
                .find(|endpoint| endpoint.endpoint_id == endpoint_id)
                .ok_or_else(|| {
                    CliError::Usage(format!(
                        "endpoint {endpoint_id} is not in {audience_app_id}'s current OBO catalog"
                    ))
                })?;
            let method = canonical_method(&method)?;
            let body = request_body(&body)?;
            let body_sha256 = body_sha256(&body);
            let metadata = metadata_object(&metadata)?;
            let timestamp = timestamp.unwrap_or_else(|| OffsetDateTime::now_utc().unix_timestamp());
            if timestamp <= 0 {
                return Err(CliError::Usage(
                    "an OBO timestamp must be a positive Unix timestamp".to_owned(),
                ));
            }
            let mutation = mutation_with_optional_key(idempotency_key)?;
            let signature = obo_signature(
                &secret,
                timestamp,
                &method,
                &endpoint.path,
                &body_sha256,
                mutation.key().as_str(),
            )?;
            let proof = client
                .obo()
                .exchange(
                    &models::OboExchangeRequest {
                        subject_token,
                        audience: audience_app_id,
                        endpoint_id,
                        metadata,
                        request: models::OboExchangeRequestBinding {
                            method,
                            body_sha256,
                        },
                    },
                    &timestamp.to_string(),
                    &signature,
                    &mutation,
                )
                .await?;
            report_obo_proof(context, &proof)
        }
        AppOboCommand::Verify {
            audience_app_id,
            app_secret,
            access_proof,
            method,
            path,
            body,
        } => {
            let secret = prompted(app_secret, "Audience Application secret: ")?;
            let access_proof = prompted(access_proof, "OBO access proof: ")?;
            let result = application_client(context, &audience_app_id, &secret)
                .obo()
                .verify(&models::OboVerifyRequest {
                    access_proof,
                    request: models::OboVerifyRequestBinding {
                        method: canonical_method(&method)?,
                        path,
                        body_sha256: body_sha256(&request_body(&body)?),
                    },
                })
                .await?;
            match context.format {
                Format::Json => json(&result),
                Format::Text => {
                    println!("Verified and consumed proof {}.", result.proof_id);
                    println!("Actor: {}", result.actor.public_id);
                    println!("Endpoint: {}", result.endpoint.endpoint_id);
                    println!("Metadata: {}", result.metadata);
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
    webhook_secret: Option<String>,
    tolerance_seconds: u64,
) -> Result<()> {
    let secret = WebhookSecret::new(prompted(webhook_secret, "Webhook signing secret: ")?)?;
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

fn application_client(context: &Context, app_id: &str, secret: &str) -> Client {
    context
        .anonymous()
        .with_credential(Credential::application(app_id, secret))
}

fn prompted(value: Option<String>, label: &str) -> Result<String> {
    match value {
        Some(value) => Ok(value),
        None => crate::commands::auth::prompt(label),
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

fn report_oauth_tokens(context: &Context, tokens: &models::OAuthTokenResponse) -> Result<()> {
    match context.format {
        Format::Json => json(tokens),
        Format::Text => {
            println!("Access token: {}", tokens.access_token);
            println!("Refresh token: {}", tokens.refresh_token);
            println!("Expires in: {} seconds", tokens.expires_in);
            println!("Scope: {}", tokens.scope);
            println!("Actor: {}", tokens.actor.public_id);
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
                &inspected.actor_type.as_ref().map_or_else(
                    || "-".to_owned(),
                    |value| format!("{value:?}").to_lowercase(),
                ),
            ]);
            table.row(["client_id", &or_dash(inspected.client_id.as_deref())]);
            table.row(["org_id", &or_dash(inspected.org_id.as_deref())]);
            table.row(["scope", &or_dash(inspected.scope.as_deref())]);
            table.row(["audience", &or_dash(inspected.audience.as_deref())]);
            table.row([
                "expires_at",
                &inspected
                    .expires_at
                    .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            ]);
            table.print();
            Ok(())
        }
    }
}

fn report_obo_catalog(context: &Context, catalog: &models::OboEndpointCatalog) -> Result<()> {
    match context.format {
        Format::Json => json(catalog),
        Format::Text => {
            let mut table = Table::new(["endpoint", "path", "metadata"]);
            for endpoint in &catalog.endpoints {
                table.row([
                    endpoint.endpoint_id.clone(),
                    endpoint.path.clone(),
                    endpoint.metadata.to_string(),
                ]);
            }
            table.print();
            Ok(())
        }
    }
}

fn report_obo_proof(context: &Context, proof: &models::OboProofResponse) -> Result<()> {
    match context.format {
        Format::Json => json(proof),
        Format::Text => {
            println!("OBO access proof: {}", proof.access_proof);
            println!("Proof ID: {}", proof.proof_id);
            println!("Expires: {}", timestamp(proof.expires_at));
            Ok(())
        }
    }
}

fn request_body(input: &RequestBodyArgs) -> Result<Vec<u8>> {
    match (&input.body, &input.body_file) {
        (Some(body), None) => Ok(body.as_bytes().to_vec()),
        (None, Some(path)) => read_body(path),
        (None, None) => Ok(Vec::new()),
        (Some(_), Some(_)) => Err(CliError::Usage(
            "give either --body or --body-file, not both".to_owned(),
        )),
    }
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

fn body_sha256(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

fn canonical_method(input: &str) -> Result<String> {
    let canonical = input.to_ascii_uppercase();
    http::Method::from_bytes(canonical.as_bytes())
        .map_err(|_| CliError::Usage(format!("{input:?} is not a valid HTTP request method")))?;
    Ok(canonical)
}

fn metadata_object(input: &str) -> Result<serde_json::Value> {
    let value = serde_json::from_str::<serde_json::Value>(input)
        .map_err(|error| CliError::Usage(format!("--metadata is not valid JSON: {error}")))?;
    if !value.is_object() {
        return Err(CliError::Usage(
            "--metadata must be a JSON object".to_owned(),
        ));
    }
    Ok(value)
}

fn obo_endpoint_definitions(input: &str) -> Result<Vec<models::ApplicationOboEndpoint>> {
    serde_json::from_str(input)
        .map_err(|error| CliError::Usage(format!("--obo-endpoints is not valid JSON: {error}")))
}

fn obo_signature(
    app_secret: &str,
    timestamp: i64,
    method: &str,
    path: &str,
    body_sha256: &str,
    idempotency_key: &str,
) -> Result<String> {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(app_secret.as_bytes())
        .map_err(|error| CliError::Config(format!("cannot initialize OBO signing: {error}")))?;
    mac.update(format!("{timestamp}.{method}.{path}.{body_sha256}.{idempotency_key}").as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
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
            table.row(["app", &application.app_id]);
            table.row(["name", &or_dash(application.app_name.as_deref())]);
            table.row(["base_url", &application.base_url]);
            table.row([
                "status",
                &format!("{:?}", application.status).to_lowercase(),
            ]);
            table.row(["org", &application.org_id]);
            table.row(["scopes", &application.approved_scopes.join(", ")]);
            table.row(["version", &application.version.to_string()]);
            table.print();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        body_sha256, canonical_method, metadata_object, obo_endpoint_definitions, obo_signature,
        request_body,
    };
    use crate::cli::RequestBodyArgs;

    #[test]
    fn request_binding_hashes_the_exact_body_bytes() {
        assert_eq!(
            body_sha256(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_ne!(body_sha256(b"hello"), body_sha256(b"hello\n"));
    }

    #[test]
    fn obo_signature_covers_the_contracts_canonical_string() {
        let signature = obo_signature(
            "app_secret",
            1_700_000_000,
            "POST",
            "/v1/files",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "018bcfe5680070008000000000000000",
        );
        let Ok(signature) = signature else {
            panic!("a non-empty HMAC key is valid");
        };
        assert_eq!(
            signature,
            "ddc63ca12795e78a577134cbef558e212f11cc94d3a2ccaa1b98c22a3317c2ce"
        );
    }

    #[test]
    fn obo_inputs_are_canonical_and_metadata_is_an_object() {
        assert_eq!(canonical_method("post").ok().as_deref(), Some("POST"));
        assert!(canonical_method("not a method").is_err());
        assert!(metadata_object(r#"{"reason":"checkout"}"#).is_ok());
        assert!(metadata_object("[]").is_err());
        assert!(metadata_object("not-json").is_err());
        assert!(
            obo_endpoint_definitions(
                r#"[{"endpoint_id":"files.upload","path":"/v1/files","metadata":{}}]"#
            )
            .is_ok()
        );
        assert!(obo_endpoint_definitions("{}").is_err());
    }

    #[test]
    fn inline_bodies_preserve_their_utf8_bytes_and_empty_is_explicit() {
        let inline = RequestBodyArgs {
            body: Some("{}\n".to_owned()),
            body_file: None,
        };
        assert_eq!(
            request_body(&inline).ok().as_deref(),
            Some(b"{}\n".as_slice())
        );

        let empty = RequestBodyArgs {
            body: None,
            body_file: None,
        };
        assert_eq!(request_body(&empty).ok().as_deref(), Some([].as_slice()));
    }
}
