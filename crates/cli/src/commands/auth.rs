//! Signing in, signing out, and creating an account.

use std::io::Write as _;

use silicon_iam_client::{Credential, models};
use time::OffsetDateTime;

use crate::{
    cli::{LoginArgs, SignupArgs, SiliconLoginArgs},
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json},
    store::Session,
};

/// Builds a stored session from a token response.
pub fn session_from(tokens: &models::IamTokenResponse, carbon_id: &str) -> Session {
    Session {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(tokens.expires_in),
        carbon_id: carbon_id.to_owned(),
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
        return Err(CliError::Usage(
            "give one of --email, --phone or --carbon-id".to_owned(),
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
            None => prompt("Verification code: ")?,
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
        return report_short_lived_token(context, &tokens.access_token, app_id).await;
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
    // Prompted rather than flagged by default so the token stays out of shell
    // history and out of the process table.
    let stk = match args.stk {
        Some(value) => value,
        None => prompt("Silicon token: ")?,
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

    if let Some(app_id) = args.app_id.as_deref() {
        return report_short_lived_token(context, &tokens.access_token, app_id).await;
    }

    match context.format {
        Format::Json => json(&tokens),
        Format::Text => {
            println!("Signed in as {sid}.");
            println!("Access token: {}", tokens.access_token);
            println!("Refresh token: {}", tokens.refresh_token);
            Ok(())
        }
    }
}

/// Asks for a short-lived token on an existing session and prints it.
async fn report_short_lived_token(
    context: &Context,
    access_token: &str,
    app_id: &str,
) -> Result<()> {
    let issued = context
        .anonymous()
        .with_credential(Credential::bearer(access_token.to_owned()))
        .auth()
        .short_lived_token(app_id, &context.mutation())
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

/// Forgets the stored session.
///
/// Local only: it does not end the session on the service, because a person
/// clearing a laptop should not silently sign out their other devices. Use
/// `iam session revoke` for that.
///
/// # Errors
///
/// Returns an error when the credential file cannot be written.
pub fn logout(context: &Context) -> Result<()> {
    if context.forget()? {
        println!("Signed out of profile {}.", context.profile_name);
    } else {
        println!("Profile {} was not signed in.", context.profile_name);
    }
    Ok(())
}

/// Shows who is signed in.
///
/// # Errors
///
/// Returns an error when there is no session, or the service refuses it.
pub async fn whoami(context: &Context) -> Result<()> {
    let me = context.authenticated().await?.carbons().me().await?;
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
                timezone: args.timezone.map(serde_json::Value::String),
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
        None => prompt(prompt_text),
    }
}

/// Reads one line from the terminal.
pub(crate) fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}
