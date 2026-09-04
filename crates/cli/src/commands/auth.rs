//! Signing in, signing out, and creating an account.

use std::io::Write as _;

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
    if args.email.is_none() && args.phone.is_none() && args.carbon_id.is_none() {
        if let Some(app_id) = args.app_id.as_deref() {
            let authenticated = context.authenticated().await?;
            return report_short_lived_token(context, &authenticated, app_id).await;
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
            None => prompt_secret("Verification code: ")?,
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
        return report_short_lived_token(context, &authenticated, app_id).await;
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
    let sid = match args.sid {
        Some(value) => value,
        None => prompt("Silicon ID: ")?,
    };
    let (sid, org) = context.silicon_identity(&sid)?;
    // Prompted rather than flagged by default so the token stays out of shell
    // history and out of the process table.
    let stk = match args.stk {
        Some(value) => value,
        None => prompt_secret("Silicon token: ")?,
    };

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
        return report_short_lived_token(context, &authenticated, app_id).await;
    }

    let signed_in = authenticated.silicons().get(&org, &sid).await?;
    report_silicon_login(context, &signed_in)
}

fn report_silicon_login(context: &Context, signed_in: &models::Silicon) -> Result<()> {
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
async fn report_short_lived_token(context: &Context, client: &Client, app_id: &str) -> Result<()> {
    let app_id = context.application_id(app_id)?;
    let issued = client
        .auth()
        .short_lived_token_in_organization(
            &app_id,
            context.organization_if_set(),
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

/// Ends a Carbon session remotely and then forgets the local credential.
///
/// The idempotency key is persisted before sending so a retry after response
/// loss can confirm the exact already-committed logout with the now-revoked
/// bearer. Silicon sessions are forgotten locally because the public logout
/// endpoint deliberately accepts Carbon authority only; rotate or remove a
/// Silicon to revoke its server-side authority.
///
/// # Errors
///
/// Returns an error when the remote logout is refused or the credential file
/// cannot be written.
pub async fn logout(context: &Context, args: LogoutArgs) -> Result<()> {
    if args.local_only {
        return report_local_logout(context, context.forget()?);
    }

    let initial = context.session()?;
    if initial.actor_type == SessionActor::Silicon {
        if args.all {
            return Err(CliError::Usage(
                "--all applies only to Carbon sessions; use `iam logout --local-only`, or rotate/remove the Silicon to revoke its authority"
                    .to_owned(),
            ));
        }
        let existed = context.forget()?;
        return report_local_logout(context, existed);
    }

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
    let client = context.authenticated_for_logout().await?;
    let mut session = context.session()?;
    let pending = if let Some(pending) = session.pending_logout.clone() {
        pending
    } else {
        let key = IdempotencyKey::generate();
        let pending = PendingLogout {
            mode: requested_mode,
            idempotency_key: key.as_str().to_owned(),
        };
        session.pending_logout = Some(pending.clone());
        context.remember(session)?;
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
    context.forget()?;

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
        let (silicon_id, org) = context.silicon_identity(&session.actor_id)?;
        let silicon = client.silicons().get(&org, &silicon_id).await?;
        return match context.format {
            Format::Json => json(&silicon),
            Format::Text => {
                let mut table = Table::new(["field", "value"]);
                table.row(["silicon_id", &silicon.silicon_id]);
                table.row(["display_name", &silicon.display_name]);
                table.row(["organization", &silicon.org_id]);
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
            table.row(["phone", &me.phone_number]);
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
/// code is refused, or the current session is not a Carbon session.
pub async fn step_up(context: &Context, args: StepUpArgs) -> Result<()> {
    let client = context.authenticated().await?;
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
        None => prompt_secret("Step-up verification code: ")?,
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
        StepUpActionArg::SiliconRotateToken => models::StepUpAction::SiliconRotateToken,
        StepUpActionArg::PlatformAdminSsoEntitlement => {
            models::StepUpAction::PlatformAdminSsoEntitlement
        }
        StepUpActionArg::PlatformAdminApplicationReview => {
            models::StepUpAction::PlatformAdminApplicationReview
        }
    }
}

/// Creates a Carbon, verifying both contacts.
///
/// # Errors
///
/// Returns an error when a contact is rejected, a code is wrong, or the handle
/// is taken.
pub async fn signup(context: &Context, args: SignupArgs) -> Result<()> {
    let client = context.anonymous();
    let session = client.signup().start(&context.mutation()).await?.session_id;

    let dispatched = client
        .signup()
        .send_email_code(session, &args.email, &context.mutation())
        .await?;
    if dispatched.already_exists {
        return Err(CliError::Usage(format!(
            "{} already belongs to a Carbon; sign in instead",
            args.email
        )));
    }
    let code = collect_code(dispatched.local_otp, "Email verification code: ")?;
    client
        .signup()
        .verify_email(session, &code, &context.mutation())
        .await?;

    let dispatched = client
        .signup()
        .send_phone_code(session, &args.phone, &context.mutation())
        .await?;
    if dispatched.already_exists {
        return Err(CliError::Usage(format!(
            "{} already belongs to a Carbon; sign in instead",
            args.phone
        )));
    }
    let code = collect_code(dispatched.local_otp, "Phone verification code: ")?;
    client
        .signup()
        .verify_phone(session, &code, &context.mutation())
        .await?;

    let created = client
        .signup()
        .complete(
            session,
            &models::CarbonSignupComplete {
                carbon_id: args.carbon_id.clone(),
                display_name: args.display_name.unwrap_or_else(|| args.carbon_id.clone()),
                timezone: args.timezone,
                description: None,
                profile_photo: None,
            },
            &context.mutation(),
        )
        .await?;

    match context.format {
        Format::Json => json(&created),
        Format::Text => {
            println!(
                "Created {}. Run `iam login --carbon-id {}` to sign in.",
                created.carbon_id, created.carbon_id
            );
            Ok(())
        }
    }
}

fn collect_code(echoed: Option<String>, prompt_text: &str) -> Result<String> {
    match echoed {
        Some(code) => Ok(code),
        None => prompt_secret(prompt_text),
    }
}

/// Reads one line without echoing it to the terminal.
pub(crate) fn prompt_secret(label: &str) -> Result<String> {
    Ok(rpassword::prompt_password(label)?)
}

/// Reads one line from the terminal.
pub(crate) fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}
