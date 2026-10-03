//! Signing in, signing out, and creating an account.

use std::io::{IsTerminal as _, Write as _};

use silicon_iam_client::{Client, Credential, IdempotencyKey, Mutation, models};
use time::OffsetDateTime;

use crate::{
    cli::{
        LoginArgs, LogoutArgs, SignupArgs, SiliconLoginArgs, StepUpActionArg, StepUpArgs,
        StepUpChannel,
    },
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json},
    store::{PendingLogout, PendingLogoutMode, Session, SessionActor},
};

/// Builds a stored session from a token response.
pub fn session_from(tokens: &models::IamTokenResponse, carbon_id: &str) -> Session {
    session_from_actor(tokens, carbon_id, SessionActor::Carbon)
}

/// Builds a stored session while preserving the authenticated actor kind.
pub fn session_from_actor(
    tokens: &models::IamTokenResponse,
    actor_id: &str,
    actor_type: SessionActor,
) -> Session {
    Session {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(tokens.expires_in),
        actor_type,
        actor_id: actor_id.to_owned(),
        pending_refresh_key: None,
        pending_refresh_started_at: None,
        pending_logout: None,
    }
}

/// Signs in and stores the session.
///
/// # Errors
///
/// Returns an error when no identity was given, the code is refused, or the
/// session cannot be stored.
pub async fn login(context: &Context, args: LoginArgs) -> Result<()> {
    if args.status.is_some() {
        return login_status(context).await;
    }
    if args.email.is_none() && args.phone.is_none() && args.carbon_id.is_none() {
        if let Some(app_id) = args.app_id.as_deref() {
            let authenticated = context.authenticated().await?;
            return report_short_lived_token(
                context,
                &authenticated,
                app_id,
                &args.grant_orgs,
                args.all_orgs,
                args.approve_scopes,
            )
            .await;
        }
        return Err(CliError::Usage(
            "give one of --email, --phone or --carbon-id, or use --app-id with the stored session"
                .to_owned(),
        ));
    }

    let client = context.anonymous();
    let challenge = client
        .auth()
        .start_login(
            &models::LoginChallengeCreate {
                email: args.email.clone(),
                phone_number: args.phone.clone(),
                carbon_id: args.carbon_id.clone(),
            },
            &context.mutation(),
        )
        .await?;

    let code = match args.code {
        Some(code) => code,
        // The service echoes the code only where a deployment has explicitly
        // allowed it, which is how a local run avoids needing a real inbox.
        None => match challenge.local_otp.clone() {
            Some(code) => code,
            None => prompt_secret(
                "IAM sign-in verification code (input hidden): ",
                "Run this login command in an interactive terminal to enter the code sent to your verified contact, or supply --code when the code is already known. Application login uses an SLT, never an OTP.",
            )?,
        },
    };

    let tokens = client
        .auth()
        .verify_login(challenge.session_id, &code, &context.mutation())
        .await?;

    let signed_in = client
        .with_credential(Credential::bearer(tokens.access_token.clone()))
        .carbons()
        .me()
        .await?;
    context.remember(session_from(&tokens, &signed_in.carbon_id))?;

    if let Some(app_id) = args.app_id.as_deref() {
        let authenticated = context.authenticated().await?;
        return report_short_lived_token(
            context,
            &authenticated,
            app_id,
            &args.grant_orgs,
            args.all_orgs,
            args.approve_scopes,
        )
        .await;
    }

    match context.format {
        Format::Json => json(&signed_in),
        Format::Text => {
            println!(
                "Signed in as {} on profile {}.",
                signed_in.carbon_id, context.profile_name
            );
            Ok(())
        }
    }
}

/// Signs a Silicon in with its credential.
///
/// A Silicon has no inbox and no browser, so it authenticates with the pair it
/// was issued -- the Silicon ID and its token -- rather than a code. Naming an
/// application additionally mints a short-lived token that application can
/// exchange, which is the only way a Silicon can sign in to one.
///
/// # Errors
///
/// Returns an error when the credential is refused, or when the application is
/// unknown.
pub async fn silicon_login(context: &Context, args: SiliconLoginArgs) -> Result<()> {
    if args.sid.is_none()
        && args.stk.is_none()
        && let Some(app_id) = args.app_id.as_deref()
    {
        if context.session()?.actor_type != SessionActor::Silicon {
            return Err(CliError::Usage(
                "the stored session is not a Silicon; use `iam login --app-id` for the current Carbon, or provide --sid and --stk to sign in as a Silicon".to_owned(),
            ));
        }
        let authenticated = context.authenticated().await?;
        return report_short_lived_token(
            context,
            &authenticated,
            app_id,
            &args.grant_orgs,
            args.all_orgs,
            args.approve_scopes,
        )
        .await;
    }
    let sid = match args.sid {
        Some(value) => value,
        None => prompt(
            "Silicon ID (si:handle): ",
            "Supply --sid <si:handle> and --stk <token> for noninteractive Silicon sign-in. With an existing Silicon session, use only --app-id to mint an SLT without entering credentials again.",
        )?,
    };
    let sid = context.silicon_id(&sid, "")?;
    // Prompted rather than flagged by default so the token stays out of shell
    // history and out of the process table.
    let stk = match args.stk {
        Some(value) => value,
        None => prompt_secret(
            "Silicon token (input hidden): ",
            "Supply --stk <token> for noninteractive Silicon sign-in, or run in an interactive terminal to keep the token out of shell history. With an existing Silicon session, use only --app-id to mint an SLT without entering credentials again.",
        )?,
    };
    if stk.trim().is_empty() {
        return Err(CliError::Usage("--stk cannot be empty".to_owned()));
    }

    let client = context.anonymous();
    let tokens = client
        .auth()
        .authenticate_silicon(
            &models::SiliconAuthenticationRequest {
                silicon_id: sid.clone(),
                silicon_token: stk,
            },
            &context.mutation(),
        )
        .await?;

    context.remember(session_from_actor(&tokens, &sid, SessionActor::Silicon))?;
    let authenticated = context.authenticated().await?;

    if let Some(app_id) = args.app_id.as_deref() {
        return report_short_lived_token(
            context,
            &authenticated,
            app_id,
            &args.grant_orgs,
            args.all_orgs,
            args.approve_scopes,
        )
        .await;
    }

    let signed_in = authenticated.silicons().identity().await?;
    report_silicon_login(context, &signed_in)
}

fn report_silicon_login(
    context: &Context,
    signed_in: &models::SiliconIdentityProfile,
) -> Result<()> {
    match context.format {
        Format::Json => json(&signed_in),
        Format::Text => {
            println!(
                "Signed in as {} on profile {}.",
                signed_in.silicon_id, context.profile_name
            );
            Ok(())
        }
    }
}

/// Asks for a short-lived token on an existing session and prints it.
async fn report_short_lived_token(
    context: &Context,
    client: &Client,
    app_id: &str,
    requested: &[String],
    all_orgs: bool,
    approve_scopes: bool,
) -> Result<()> {
    let app_id = context.application_id(app_id)?;
    let choices = client.auth().login_organizations(&app_id).await?;
    let consented = approve_login_scopes(&choices, approve_scopes)?;
    let org_ids = select_login_organizations(&choices, requested, all_orgs)?;
    let issued = client
        .auth()
        .short_lived_token_for_organizations(
            &app_id,
            &org_ids,
            choices.scope_version,
            &consented,
            &context.mutation(),
        )
        .await?;
    match context.format {
        Format::Json => json(&issued),
        Format::Text => {
            println!("Short-lived token for {app_id}: {}", issued.slt);
            println!(
                "It is good for {} seconds and one exchange.",
                issued.expires_in
            );
            Ok(())
        }
    }
}

fn select_login_organizations(
    choices: &models::LoginOrganizations,
    requested: &[String],
    all_orgs: bool,
) -> Result<Vec<String>> {
    if all_orgs {
        return Err(CliError::Usage("Application login uses exactly one account and organization. Replace --all-orgs with --grant-org <org>.".to_owned()));
    }
    if choices.items.is_empty() {
        return Err(CliError::Usage(
            "Create or join an organization in IAM before signing in to an application.".to_owned(),
        ));
    }
    let selected = if requested.is_empty() {
        eprintln!(
            "Choose one organization for {}:",
            choices.app_name.as_deref().unwrap_or(&choices.app_id)
        );
        for org in &choices.items {
            eprintln!("  {} — {}", org.org_id, org.name);
        }
        prompt(
            "Organization handle: ",
            "Pass --grant-org <org>. The stored --org default does not choose application access.",
        )?
    } else if requested.len() == 1 {
        requested[0].clone()
    } else {
        return Err(CliError::Usage(
            "Application login uses exactly one organization. Pass one --grant-org <org>."
                .to_owned(),
        ));
    };
    if !choices.items.iter().any(|item| item.org_id == selected) {
        return Err(CliError::Usage(
            "Choose one of the available organization handles. No application token was issued."
                .to_owned(),
        ));
    }
    Ok(vec![selected])
}

/// Authorizes multiple apps atomically, retaining their separate credentials.
///
/// # Errors
/// Requires a stored direct IAM login, valid targets and explicit organization selection.
pub async fn batch_login(context: &Context, args: crate::cli::BatchLoginArgs) -> Result<()> {
    if args.app_ids.is_empty()
        || args.app_ids.len() > 100
        || args
            .app_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != args.app_ids.len()
    {
        return Err(CliError::Usage(
            "Select 1–100 unique canonical app IDs using --app-id.".to_owned(),
        ));
    }
    let client = context.authenticated().await?;
    let choices = client
        .auth()
        .batch_login_organizations(&args.app_ids)
        .await?;
    let applications = select_batch_applications(
        &choices.items,
        &args.grant_orgs,
        args.all_orgs,
        args.approve_scopes,
    )?;
    let response = client
        .auth()
        .batch_short_lived_tokens(
            &models::BatchLoginRequest {
                applications,
                redirect_uri: None,
            },
            &context.mutation(),
        )
        .await?;
    report_batch_tokens(context, &response)
}

/// Reviews scopes before selecting organizations for every app in a batch.
pub(super) fn select_batch_applications(
    choices: &[models::LoginOrganizations],
    requested: &[String],
    all_orgs: bool,
    approve_scopes: bool,
) -> Result<Vec<models::BatchLoginSelection>> {
    choices
        .iter()
        .map(|app| {
            let consented = approve_login_scopes(app, approve_scopes)?;
            Ok(models::BatchLoginSelection {
                app_id: app.app_id.clone(),
                scope_version: app.scope_version,
                approved_scopes: consented,
                org_ids: select_login_organizations(app, requested, all_orgs)?,
            })
        })
        .collect()
}

fn approve_login_scopes(
    choices: &models::LoginOrganizations,
    approve_scopes: bool,
) -> Result<Vec<String>> {
    if choices.scopes.iter().any(|scope| {
        scope.scope.starts_with("obo:")
            || scope.app_id.is_some()
            || scope
                .downstream
                .as_ref()
                .is_some_and(|calls| !calls.is_empty())
    }) {
        return Err(CliError::Usage("OBO permissions require a separate approval. IAM returned an outdated login policy; retry after updating IAM.".to_owned()));
    }
    if choices.consent_required && choices.scopes.iter().any(|scope| scope.critical) {
        eprintln!(
            "Permissions requested by {}:",
            choices.app_name.as_deref().unwrap_or(&choices.app_id)
        );
        for scope in &choices.scopes {
            eprintln!(
                "  [{}] {} — {}",
                if scope.critical {
                    "critical"
                } else {
                    "noncritical"
                },
                scope.scope,
                scope.description
            );
        }
        if !approve_scopes {
            let answer = prompt(
                "Approve these permissions? [yes/no]: ",
                "Review the requested permissions, then pass --approve-scopes to authorize them in noninteractive use.",
            )?;
            if !matches!(answer.trim().to_ascii_lowercase().as_str(), "yes" | "y") {
                return Err(CliError::Usage(
                    "Application scope consent was declined; no application tokens were issued."
                        .to_owned(),
                ));
            }
        }
    }
    Ok(choices
        .scopes
        .iter()
        .map(|scope| scope.scope.clone())
        .collect())
}

/// Prints the distinct SLTs without combining application credentials.
pub(super) fn report_batch_tokens(
    context: &Context,
    response: &models::BatchLoginTokens,
) -> Result<()> {
    match context.format {
        Format::Json => json(response),
        Format::Text => {
            for item in &response.items {
                println!(
                    "{}: {} ({} seconds, one exchange)",
                    item.app_id, item.slt, item.expires_in
                );
            }
            Ok(())
        }
    }
}

/// Ends an identity session remotely and then forgets the local credential.
///
/// The idempotency key is persisted before sending so a retry after response
/// loss can confirm the exact already-committed logout with the now-revoked
/// bearer. Carbon and Silicon sessions use the same revocation workflow.
///
/// # Errors
///
/// Returns an error when the remote logout is refused or the credential file
/// cannot be written.
pub async fn logout(context: &Context, args: LogoutArgs) -> Result<()> {
    if args.local_only {
        let existed = context.forget().inspect_err(|_| {
            eprintln!("Local credential removal could not be confirmed.");
        })?;
        return report_local_logout(context, existed);
    }

    // Keep one session-transition lock through refresh, logout reservation,
    // network replay and deletion. A concurrent login must not be erased.
    let stored = context.lock_session()?;
    let initial = stored.session()?;
    let requested_mode = if args.all {
        PendingLogoutMode::AllSessions
    } else {
        PendingLogoutMode::CurrentSession
    };
    if let Some(pending) = initial.pending_logout.as_ref()
        && pending.mode != requested_mode
    {
        let prior = match pending.mode {
            PendingLogoutMode::CurrentSession => "`iam logout`",
            PendingLogoutMode::AllSessions => "`iam logout --all`",
        };
        return Err(CliError::Usage(format!(
            "a previous remote logout may already have committed; retry {prior} exactly, or use --local-only to forget the credential"
        )));
    }

    // Refresh, when needed, before reserving the logout key. Once the key is
    // pending, the bearer must remain byte-for-byte stable for replay.
    let client = context.authenticated_for_logout(&stored).await?;
    let mut session = stored.session()?;
    let pending = if let Some(pending) = session.pending_logout.clone() {
        pending
    } else {
        let key = IdempotencyKey::generate();
        let pending = PendingLogout {
            mode: requested_mode,
            idempotency_key: key.as_str().to_owned(),
        };
        session.pending_logout = Some(pending.clone());
        stored.remember(session)?;
        pending
    };

    let mode = match pending.mode {
        PendingLogoutMode::CurrentSession => models::LogoutRequestMode::CurrentSession,
        PendingLogoutMode::AllSessions => models::LogoutRequestMode::AllSessions,
    };
    let mutation = Mutation::with_key(IdempotencyKey::parse(pending.idempotency_key)?);
    let mutation = match context.step_up.as_ref() {
        Some(assertion) => mutation.step_up(assertion.clone()),
        None => mutation,
    };
    client
        .auth()
        .logout(&models::LogoutRequest { mode: Some(mode) }, &mutation)
        .await?;
    stored.forget().inspect_err(|_| {
        eprintln!(
            "IAM confirmed remote logout, but local credential removal could not be confirmed."
        );
    })?;

    match context.format {
        Format::Json => json(&serde_json::json!({
            "mode": match pending.mode {
                PendingLogoutMode::CurrentSession => "current_session",
                PendingLogoutMode::AllSessions => "all_sessions",
            },
            "remote": true,
        })),
        Format::Text => {
            let scope = match pending.mode {
                PendingLogoutMode::CurrentSession => "the current remote session",
                PendingLogoutMode::AllSessions => "all remote sessions",
            };
            println!(
                "Ended {scope} and signed out profile {}.",
                context.profile_name
            );
            Ok(())
        }
    }
}

fn report_local_logout(context: &Context, existed: bool) -> Result<()> {
    match context.format {
        Format::Json => json(&serde_json::json!({
            "mode": "local_only",
            "remote": false,
            "forgotten": existed,
        })),
        Format::Text => {
            if existed {
                println!("Signed out profile {} locally.", context.profile_name);
            } else {
                println!("Profile {} was not signed in.", context.profile_name);
            }
            Ok(())
        }
    }
}

/// Shows who is signed in.
///
/// # Errors
///
/// Returns an error when there is no session, or the service refuses it.
pub async fn whoami(context: &Context) -> Result<()> {
    let session = context.session()?;
    let client = context.authenticated().await?;
    if session.actor_type == SessionActor::Silicon {
        let silicon = client.silicons().identity().await?;
        return match context.format {
            Format::Json => json(&silicon),
            Format::Text => {
                let mut table = Table::new(["field", "value"]);
                table.row(["silicon_id", &silicon.silicon_id]);
                table.row(["display_name", &silicon.display_name]);
                table.row(["timezone", &silicon.timezone]);
                table.row(["profile", &context.profile_name]);
                table.row(["service", context.anonymous().base_url().as_str()]);
                if let Some(environment_id) = context.testing_environment_id() {
                    table.row(["test_environment", &environment_id.to_string()]);
                }
                table.print();
                Ok(())
            }
        };
    }

    let me = client.carbons().me().await?;
    match context.format {
        Format::Json => json(&me),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["carbon_id", &me.carbon_id]);
            table.row(["display_name", &me.display_name]);
            table.row(["email", &me.email]);
            table.row(["phone", me.phone_number.as_deref().unwrap_or("Not added")]);
            table.row(["timezone", &me.timezone]);
            table.row(["profile", &context.profile_name]);
            table.row(["service", context.anonymous().base_url().as_str()]);
            if let Some(environment_id) = context.testing_environment_id() {
                table.row(["test_environment", &environment_id.to_string()]);
            }
            table.print();
            Ok(())
        }
    }
}

/// Mints a token bound to one sensitive action and one resource.
///
/// # Errors
///
/// Returns an error when the resource is not eligible, delivery fails, the
/// code or Silicon credential is refused, or the current session is invalid.
pub async fn step_up(context: &Context, args: StepUpArgs) -> Result<()> {
    let client = context.authenticated().await?;
    if context.session()?.actor_type == SessionActor::Silicon {
        let credential = match args.stk {
            Some(value) => value,
            None => prompt_secret(
                "Current Silicon password (hidden): ",
                "Supply --stk or use an interactive terminal to confirm this Silicon action.",
            )?,
        };
        let token = client
            .auth()
            .silicon_step_up(
                &step_up_action(args.action),
                &args.resource_id,
                &credential,
                &context.mutation(),
            )
            .await?;
        return match context.format {
            Format::Json => json(&token),
            Format::Text => {
                println!(
                    "Step-up token: {}\nValid for {} seconds and only this action/resource.",
                    token.step_up_token, token.expires_in
                );
                Ok(())
            }
        };
    }

    let challenge = client
        .auth()
        .start_step_up(
            &models::StepUpChallengeCreate {
                channel: match args.channel {
                    StepUpChannel::Email => models::StepUpChallengeCreateChannel::Email,
                    StepUpChannel::Phone => models::StepUpChallengeCreateChannel::PhoneNumber,
                },
                action: step_up_action(args.action),
                resource_id: args.resource_id,
            },
            &context.mutation(),
        )
        .await?;
    let code = match args.code.or(challenge.local_otp) {
        Some(code) => code,
        None => prompt_secret(
            "Step-up verification code (input hidden): ",
            "Run this step-up command in an interactive terminal to enter the code sent through the selected --channel, or supply --code when the code is already known.",
        )?,
    };
    let token = client
        .auth()
        .verify_step_up(challenge.session_id, &code, &context.mutation())
        .await?;
    match context.format {
        Format::Json => json(&token),
        Format::Text => {
            println!("Step-up token: {}", token.step_up_token);
            println!(
                "It is valid for {} seconds and only this action/resource.",
                token.expires_in
            );
            Ok(())
        }
    }
}

const fn step_up_action(action: StepUpActionArg) -> models::StepUpAction {
    match action {
        StepUpActionArg::AccountSessionRevoke => models::StepUpAction::AccountSessionRevoke,
        StepUpActionArg::AccountSessionsRevokeAll => models::StepUpAction::AccountSessionsRevokeAll,
        StepUpActionArg::OrganizationTransferOwnership => {
            models::StepUpAction::OrganizationTransferOwnership
        }
        StepUpActionArg::OrganizationAuthorizationChange => {
            models::StepUpAction::OrganizationAuthorizationChange
        }
        StepUpActionArg::OrganizationSsoChange => models::StepUpAction::OrganizationSsoChange,
        StepUpActionArg::OrganizationSiliconWebhookRedirect => {
            models::StepUpAction::OrganizationSiliconWebhookRedirect
        }
        StepUpActionArg::ApplicationClientSecretRotate => {
            models::StepUpAction::ApplicationClientSecretRotate
        }
        StepUpActionArg::ApplicationWebhookSecretRotate => {
            models::StepUpAction::ApplicationWebhookSecretRotate
        }
        StepUpActionArg::ApplicationWebhookApprove => {
            models::StepUpAction::ApplicationWebhookApprove
        }
        StepUpActionArg::SiliconRotateToken => models::StepUpAction::SiliconRotateToken,
        StepUpActionArg::PlatformAdminSsoEntitlement => {
            models::StepUpAction::PlatformAdminSsoEntitlement
        }
        StepUpActionArg::PlatformAdminApplicationReview => {
            models::StepUpAction::PlatformAdminApplicationReview
        }
    }
}

/// Creates a Carbon using provider email verification or email OTP, plus any supplied phone.
///
/// # Errors
///
/// Returns an error when a contact is rejected, a code is wrong, or the handle
/// is taken.
#[allow(
    clippy::too_many_lines,
    clippy::single_match_else,
    reason = "sequential signup prompts and resumable paths share the same session state"
)]
pub async fn signup(context: &Context, mut args: SignupArgs) -> Result<()> {
    if let Some(id) = &mut args.carbon_id
        && !id.starts_with("c:")
    {
        *id = format!("c:{id}");
    }
    let client = context.anonymous();
    let resuming = args.session_id.is_some();
    let social = match args.provider.as_deref() {
        Some(provider) => Some(social_signup(client, context, provider).await?),
        None => None,
    };
    if args.display_name.is_none() {
        args.display_name = social.as_ref().and_then(|value| value.display_name.clone());
    }
    let session = match social
        .as_ref()
        .and_then(|value| value.signup_session_id)
        .or(args.session_id)
    {
        Some(id) => id,
        None => client.signup().start(&context.mutation()).await?.session_id,
    };
    if social.is_none() && !resuming {
        let email = args.email.as_deref().ok_or_else(|| {
            CliError::Usage("Give --email or --provider google|apple.".to_owned())
        })?;
        let dispatched = client
            .signup()
            .send_email_code(session, email, &context.mutation())
            .await?;
        if dispatched.already_exists {
            return Err(CliError::Usage(format!(
                "This email is already registered. Sign in with `iam login --email {email}`."
            )));
        }
        let code = match dispatched.local_otp {
            Some(code) => code,
            None if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() => {
                return report_signup_pending(context, session, "email_verification_required");
            }
            None => collect_code(None, "Email verification code (input hidden): ")?,
        };
        client
            .signup()
            .verify_email(session, &code, &context.mutation())
            .await?;
    } else if let Some(code) = args.email_code {
        client
            .signup()
            .verify_email(session, &code, &context.mutation())
            .await?;
    }
    if args.skip_phone {
        client
            .signup()
            .skip_phone(session, &context.mutation())
            .await?;
    }
    if let Some(phone) = &args.phone {
        let code = match args.phone_code {
            Some(code) => code,
            None => {
                let dispatched = client
                    .signup()
                    .send_phone_code(session, phone, &context.mutation())
                    .await?;
                if dispatched.already_exists {
                    return Err(CliError::Usage("This phone belongs to an existing account. Sign in to that account or resume without adding this phone.".to_owned()));
                }
                match dispatched.local_otp {
                    Some(code) => code,
                    None if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() => {
                        return report_signup_pending(
                            context,
                            session,
                            "phone_verification_required",
                        );
                    }
                    None => collect_code(None, "Phone verification code (input hidden): ")?,
                }
            }
        };
        client
            .signup()
            .verify_phone(session, &code, &context.mutation())
            .await?;
    }
    let mut created = client
        .signup()
        .complete(
            session,
            &models::CarbonSignupComplete {
                carbon_id: args.carbon_id,
                display_name: args.display_name,
                timezone: args
                    .timezone
                    .or_else(|| iana_time_zone::get_timezone().ok()),
                profile_photo: None,
            },
            &context.mutation(),
        )
        .await?;
    context.remember(session_from(&created.tokens, &created.profile.carbon_id))?;
    if let Some(path) = args.photo {
        let authenticated =
            client.with_credential(Credential::bearer(created.tokens.access_token.clone()));
        created.profile =
            super::carbon::upload_photo(&authenticated, context, created.profile.version, &path)
                .await?;
    }
    match context.format {
        Format::Json => json(&serde_json::json!({
            "profile": created.profile,
            "authenticated": true,
            "onboarding": created.onboarding,
        })),
        Format::Text => {
            println!("Created and signed in as {}.", created.profile.carbon_id);
            if created.onboarding.requires_organization {
                println!(
                    "Create your first organization with `iam org create --help`, or accept an invitation with `iam invite --help`."
                );
            }
            Ok(())
        }
    }
}

async fn social_signup(
    client: &Client,
    context: &Context,
    provider: &str,
) -> Result<models::SocialSignupStatus> {
    let started = client
        .signup()
        .social_start(provider, &context.mutation())
        .await?;
    validate_social_destination(provider, &started.authorization_url)?;
    // Keep polling capability in memory; the browser URL carries only OAuth
    // state and never IAM credentials. stdout remains one final JSON result.
    eprintln!(
        "Open this {provider} sign-up page in your browser:\n{}",
        started.authorization_url
    );
    eprintln!("This command will continue when email verification completes.");
    let input = models::SocialSignupStatusInput {
        request_id: started.request_id,
        poll_token: started.poll_token,
    };
    while OffsetDateTime::now_utc() < started.expires_at {
        let status = client.signup().social_status(provider, &input).await;
        match status {
            Ok(value) => match value.status {
                models::SocialSignupStatusStatus::Verified if value.signup_session_id.is_some() => return Ok(value),
                models::SocialSignupStatusStatus::Pending => {},
                models::SocialSignupStatusStatus::AlreadyRegistered => return Err(CliError::Usage("This provider email is already registered. Sign in to the existing account with `iam login --email <email>`.".to_owned())),
                models::SocialSignupStatusStatus::Expired => break,
                _ => return Err(CliError::Usage("Provider sign-up could not be verified. Run signup again, or use --email.".to_owned())),
            },
            Err(silicon_iam_client::Error::Transport(_)) => {},
            Err(silicon_iam_client::Error::Api(ref error)) if error.status >= 500 => {},
            Err(error) => return Err(error.into()),
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    Err(CliError::Usage(
        "Provider sign-up expired. Run signup again to open a fresh verification request."
            .to_owned(),
    ))
}

fn validate_social_destination(provider: &str, value: &str) -> Result<()> {
    let url = url::Url::parse(value)
        .map_err(|_| CliError::Usage("IAM returned an invalid provider URL.".to_owned()))?;
    let host = match provider {
        "google" => "accounts.google.com",
        "apple" => "appleid.apple.com",
        _ => return Err(CliError::Usage("Choose Google or Apple.".to_owned())),
    };
    if url.scheme() != "https"
        || url.host_str() != Some(host)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err(CliError::Usage(
            "IAM returned an invalid provider destination. No browser was opened.".to_owned(),
        ));
    }
    Ok(())
}

fn report_signup_pending(context: &Context, session: uuid::Uuid, status: &str) -> Result<()> {
    match context.format {
        Format::Json => json(&serde_json::json!({ "session_id": session, "status": status })),
        Format::Text => {
            println!("Signup session: {session}");
            println!(
                "{status}. Resume with the same signup options plus --session-id {session} and --email-code or --phone-code."
            );
            Ok(())
        }
    }
}

fn collect_code(echoed: Option<String>, prompt_text: &str) -> Result<String> {
    match echoed {
        Some(code) => Ok(code),
        None => prompt_secret(
            prompt_text,
            "Run signup in an interactive terminal: email verification and verification of any supplied phone are required. Noninteractive signup works only when your local/testing IAM deployment explicitly returns verification codes; the CLI never guesses or bypasses them.",
        ),
    }
}

/// Reads one nonempty secret from an interactive terminal without echoing it.
///
/// Never opens `/dev/tty` for a piped or agent invocation. Standard input may
/// contain an explicitly supplied request body and must not become a credential.
pub(crate) fn prompt_secret(label: &str, noninteractive_help: &str) -> Result<String> {
    require_interactive(label, noninteractive_help)?;
    let value = rpassword::prompt_password_with_config(
        label,
        rpassword::ConfigBuilder::new()
            .output_writer(std::io::stderr())
            .build(),
    )?;
    require_prompt_value(value, label)
}

/// Reads one nonempty line from an interactive terminal; prompts use stderr.
pub(crate) fn prompt(label: &str, noninteractive_help: &str) -> Result<String> {
    require_interactive(label, noninteractive_help)?;
    eprint!("{label}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    require_prompt_value(line.trim().to_owned(), label)
}

fn require_interactive(label: &str, noninteractive_help: &str) -> Result<()> {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        return Ok(());
    }
    Err(CliError::Usage(format!(
        "{} is required; interactive prompting needs terminal input and stderr. {noninteractive_help} Piped input was not read.",
        label.trim().trim_end_matches(':')
    )))
}

fn require_prompt_value(value: String, label: &str) -> Result<String> {
    if value.trim().is_empty() {
        return Err(CliError::Usage(format!(
            "{} cannot be empty; no credential was submitted",
            label.trim().trim_end_matches(':')
        )));
    }
    Ok(value)
}

/// Validate the selected session against IAM; never infer validity from disk alone.
pub async fn login_status(context: &Context) -> Result<()> {
    let checked = async {
        let session = context.session()?;
        if session.pending_logout.is_some() {
            return Err(CliError::NotSignedIn);
        }
        let client = context.authenticated().await?;
        if session.actor_type == SessionActor::Silicon {
            client.silicons().identity().await?;
        } else {
            client.carbons().me().await?;
        }
        Ok::<_, CliError>(session)
    }
    .await;
    let session = match checked {
        Ok(session) => Some(session),
        Err(CliError::NotSignedIn) => None,
        Err(CliError::Client(silicon_iam_client::Error::Api(ref error))) if error.status == 401 => {
            None
        }
        Err(error) => return Err(error),
    };
    match context.format {
        Format::Json => json(&serde_json::json!({
            "authenticated": session.is_some(),
            "actor_id": session.as_ref().map(|s| &s.actor_id),
            "actor_type": session.as_ref().map(|s| s.actor_type),
            "profile": context.profile_name,
            "testing_environment_id": context.testing_environment_id(),
        })),
        Format::Text => {
            println!(
                "{}",
                session.map_or_else(
                    || "Not authenticated.".to_owned(),
                    |s| format!("Authenticated as {}.", s.actor_id)
                )
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::select_login_organizations;
    use silicon_iam_client::models;

    #[test]
    fn social_signup_urls_are_bound_to_the_selected_provider() {
        assert!(
            super::validate_social_destination(
                "google",
                "https://accounts.google.com/o/oauth2/v2/auth?state=opaque"
            )
            .is_ok()
        );
        assert!(
            super::validate_social_destination("apple", "https://appleid.apple.com/auth/authorize")
                .is_ok()
        );
        for value in [
            "http://accounts.google.com/auth",
            "https://evil.example/auth",
            "https://accounts.google.com.evil.example/auth",
            "https://user@accounts.google.com/auth",
            "https://accounts.google.com:444/auth",
            "https://appleid.apple.com/auth/authorize",
        ] {
            assert!(super::validate_social_destination("google", value).is_err());
        }
    }

    fn choices(allow_empty: bool) -> models::LoginOrganizations {
        models::LoginOrganizations {
            app_id: "interface".into(),
            app_name: None,
            scope_version: 1,
            consent_required: true,
            allow_empty_organization_selection: allow_empty,
            scopes: Vec::new(),
            items: Vec::new(),
        }
    }

    #[test]
    fn ordinary_login_skips_noncritical_iam_prompt_and_refuses_obo_approval() {
        let mut policy = choices(false);
        policy.scopes.push(models::ApplicationConsentScope {
            scope: "self.identity.read".into(),
            description: "Read account identity".into(),
            critical: false,
            app_id: None,
            downstream: None,
        });
        assert_eq!(
            super::approve_login_scopes(&policy, false).ok(),
            Some(vec!["self.identity.read".to_owned()])
        );
        policy.scopes[0].scope = "obo:waveform:tts".into();
        assert!(super::approve_login_scopes(&policy, true).is_err());
    }

    #[test]
    fn application_login_selects_exactly_one_available_organization() {
        assert!(select_login_organizations(&choices(true), &[], true).is_err());
        assert!(select_login_organizations(&choices(false), &[], false).is_err());
        let mut available = choices(false);
        available.items.push(models::LoginOrganization {
            org_id: "work".into(),
            name: "Work".into(),
            authorized: false,
        });
        assert_eq!(
            select_login_organizations(&available, &["work".into()], false).ok(),
            Some(vec!["work".to_owned()])
        );
        assert!(
            select_login_organizations(&available, &["work".into(), "other".into()], false)
                .is_err()
        );
        assert!(select_login_organizations(&available, &["unknown".into()], false).is_err());
    }
}
