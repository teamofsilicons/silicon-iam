//! Stored settings.

use crate::{
    cli::ConfigCommand,
    context::Context,
    error::{CliError, Result},
    output::{Format, Table, json, or_dash},
    store::{self, Profile},
};

/// Runs a settings command.
///
/// # Errors
///
/// Returns an error when the settings file cannot be read or written.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per verb; splitting the match would only move it elsewhere"
)]
pub fn run(context: &Context, command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Show => show(context),
        ConfigCommand::Profiles => profiles(context),
        ConfigCommand::Set { key, value } => set(context, &key, value),
        ConfigCommand::Unset { key } => unset(context, &key),
        ConfigCommand::Use { profile } => use_profile(&profile),
    }
}

fn show(context: &Context) -> Result<()> {
    let config = store::load_config()?;
    let signed_in = context.session().ok();
    match context.format {
        Format::Json => json(&serde_json::json!({
            "auto_update": config.auto_update,
            "profile": context.profile_name,
            "url": context.profile.url,
            "org": context.profile.org,
            "test_environment": context.testing_environment_id(),
            "signed_in_as": signed_in.map(|session| session.carbon_id),
            "store": store::home()?.display().to_string(),
        })),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["auto_update", if config.auto_update { "on" } else { "off" }]);
            table.row(["profile", &context.profile_name]);
            table.row(["url", &context.profile.url]);
            table.row(["org", &or_dash(context.profile.org.as_deref())]);
            table.row([
                "test_environment",
                &context
                    .testing_environment_id()
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            ]);
            table.row([
                "signed_in_as",
                &or_dash(signed_in.as_ref().map(|session| session.carbon_id.as_str())),
            ]);
            table.row(["store", &store::home()?.display().to_string()]);
            table.print();
            Ok(())
        }
    }
}

fn profiles(context: &Context) -> Result<()> {
    let config = store::load_config()?;
    let credentials = store::load_credentials()?;
    match context.format {
        Format::Json => json(&config),
        Format::Text => {
            let mut table = Table::new(["profile", "url", "org", "signed in"]);
            for (name, profile) in &config.profiles {
                let marker = if *name == context.profile_name {
                    format!("* {name}")
                } else {
                    format!("  {name}")
                };
                table.row([
                    &marker,
                    &profile.url,
                    &or_dash(profile.org.as_deref()),
                    &if credentials.sessions.contains_key(name) {
                        "yes".to_owned()
                    } else {
                        "no".to_owned()
                    },
                ]);
            }
            table.print();
            Ok(())
        }
    }
}

fn set(context: &Context, key: &str, value: String) -> Result<()> {
    let mut config = store::load_config()?;
    if key == "auto-update" {
        config.auto_update = parse_switch(&value)?;
        store::save_config(&config)?;
        println!(
            "Automatic updates are {}.",
            if config.auto_update { "on" } else { "off" }
        );
        return Ok(());
    }
    let profile = config
        .profiles
        .entry(context.profile_name.clone())
        .or_insert_with(|| Profile {
            url: crate::context::DEFAULT_URL.to_owned(),
            ..Profile::default()
        });
    match key {
        "url" => profile.url = value,
        "org" => profile.org = Some(value),
        other => {
            return Err(CliError::Usage(format!(
                "unknown setting `{other}`; expected url, org, or auto-update"
            )));
        }
    }
    if config.current_profile.is_none() {
        config.current_profile = Some(context.profile_name.clone());
    }
    store::save_config(&config)?;
    println!("Set {key} on profile {}.", context.profile_name);
    Ok(())
}

fn unset(context: &Context, key: &str) -> Result<()> {
    let mut config = store::load_config()?;
    if key == "auto-update" {
        config.auto_update = true;
        store::save_config(&config)?;
        println!("Automatic updates are on (default).");
        return Ok(());
    }
    let Some(profile) = config.profiles.get_mut(&context.profile_name) else {
        return Err(CliError::Usage(format!(
            "profile {} has no settings to clear",
            context.profile_name
        )));
    };
    match key {
        "org" => profile.org = None,
        other => {
            return Err(CliError::Usage(format!(
                "unknown setting `{other}`; expected org or auto-update"
            )));
        }
    }
    store::save_config(&config)?;
    println!("Cleared {key} on profile {}.", context.profile_name);
    Ok(())
}

fn parse_switch(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        _ => Err(CliError::Usage("auto-update must be on or off".to_owned())),
    }
}

fn use_profile(profile: &str) -> Result<()> {
    let mut config = store::load_config()?;
    config.current_profile = Some(profile.to_owned());
    config
        .profiles
        .entry(profile.to_owned())
        .or_insert_with(|| Profile {
            url: crate::context::DEFAULT_URL.to_owned(),
            ..Profile::default()
        });
    store::save_config(&config)?;
    println!("Now using profile {profile}.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_switch;

    #[test]
    fn automatic_update_switch_has_clear_values() {
        assert_eq!(parse_switch("on").ok(), Some(true));
        assert_eq!(parse_switch("FALSE").ok(), Some(false));
        assert!(parse_switch("maybe").is_err());
    }
}
