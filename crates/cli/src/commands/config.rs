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
        ConfigCommand::Use { profile } => use_profile(context, &profile),
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
            "org": context.organization_if_set(),
            "test_environment": context.testing_environment_id(),
            "signed_in_as": signed_in.map(|session| session.actor_id),
            "store": store::home()?.display().to_string(),
        })),
        Format::Text => {
            let mut table = Table::new(["field", "value"]);
            table.row(["auto_update", if config.auto_update { "on" } else { "off" }]);
            table.row(["profile", &context.profile_name]);
            table.row(["url", &context.profile.url]);
            table.row(["org", &or_dash(context.organization_if_set())]);
            table.row([
                "test_environment",
                &context
                    .testing_environment_id()
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            ]);
            table.row([
                "signed_in_as",
                &or_dash(signed_in.as_ref().map(|session| session.actor_id.as_str())),
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
            let configured_default = config
                .current_profile
                .as_deref()
                .unwrap_or(crate::context::DEFAULT_PROFILE);
            for (name, profile) in &config.profiles {
                let marker = if name == configured_default {
                    format!("* {name}")
                } else {
                    format!("  {name}")
                };
                table.row([
                    &marker,
                    &profile.url,
                    &or_dash(profile.org.as_deref()),
                    &if credentials.sessions.contains_key(name)
                        || credentials
                            .test_sessions
                            .get(name)
                            .is_some_and(|sessions| !sessions.is_empty())
                    {
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
    let store = store::lock()?;
    let mut config = store.load_config()?;
    if key == "auto-update" {
        config.auto_update = parse_switch(&value)?;
        store.save_config(&config)?;
        let reported_value = serde_json::Value::Bool(config.auto_update);
        let message = if config.auto_update {
            "Automatic updates are on."
        } else {
            "Automatic updates are off."
        };
        return report_setting(context, key, Some(&reported_value), message);
    }
    let profile = config
        .profiles
        .entry(context.profile_name.clone())
        .or_insert_with(|| Profile {
            url: crate::context::DEFAULT_URL.to_owned(),
            ..Profile::default()
        });
    let reported_value = value.clone();
    match key {
        "url" => {
            silicon_iam_client::Client::new(&value)?;
            profile.url = value;
        }
        "org" => match context.testing_environment_id() {
            Some(environment_id) => {
                profile.test_orgs.insert(environment_id, value);
            }
            None => profile.org = Some(value),
        },
        other => {
            return Err(CliError::Usage(format!(
                "unknown setting `{other}`; expected url, org, or auto-update"
            )));
        }
    }
    if config.current_profile.is_none() {
        config.current_profile = Some(context.profile_name.clone());
    }
    store.save_config(&config)?;
    let message = if let Some(environment_id) = context.testing_environment_id() {
        format!(
            "Set {key} on profile {} for testing environment {environment_id}.",
            context.profile_name
        )
    } else {
        format!("Set {key} on profile {}.", context.profile_name)
    };
    let reported_value = serde_json::Value::String(reported_value);
    report_setting(context, key, Some(&reported_value), &message)
}

fn unset(context: &Context, key: &str) -> Result<()> {
    let store = store::lock()?;
    let mut config = store.load_config()?;
    if key == "auto-update" {
        config.auto_update = true;
        store.save_config(&config)?;
        let reported_value = serde_json::Value::Bool(true);
        return report_setting(
            context,
            key,
            Some(&reported_value),
            "Automatic updates are on (default).",
        );
    }
    let Some(profile) = config.profiles.get_mut(&context.profile_name) else {
        return Err(CliError::Usage(format!(
            "profile {} has no settings to clear",
            context.profile_name
        )));
    };
    match key {
        "org" => match context.testing_environment_id() {
            Some(environment_id) => {
                profile.test_orgs.remove(&environment_id);
            }
            None => profile.org = None,
        },
        other => {
            return Err(CliError::Usage(format!(
                "unknown setting `{other}`; expected org or auto-update"
            )));
        }
    }
    store.save_config(&config)?;
    let message = if let Some(environment_id) = context.testing_environment_id() {
        format!(
            "Cleared {key} on profile {} for testing environment {environment_id}.",
            context.profile_name
        )
    } else {
        format!("Cleared {key} on profile {}.", context.profile_name)
    };
    report_setting(context, key, None, &message)
}

fn parse_switch(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        _ => Err(CliError::Usage("auto-update must be on or off".to_owned())),
    }
}

fn use_profile(context: &Context, profile: &str) -> Result<()> {
    let store = store::lock()?;
    let mut config = store.load_config()?;
    config.current_profile = Some(profile.to_owned());
    config
        .profiles
        .entry(profile.to_owned())
        .or_insert_with(|| Profile {
            url: crate::context::DEFAULT_URL.to_owned(),
            ..Profile::default()
        });
    store.save_config(&config)?;
    match context.format {
        Format::Json => json(&serde_json::json!({ "current_profile": profile })),
        Format::Text => {
            println!("Now using profile {profile}.");
            Ok(())
        }
    }
}

fn report_setting(
    context: &Context,
    key: &str,
    value: Option<&serde_json::Value>,
    message: &str,
) -> Result<()> {
    match context.format {
        Format::Json => json(&serde_json::json!({
            "profile": context.profile_name,
            "test_environment": context.testing_environment_id(),
            "key": key,
            "value": value,
        })),
        Format::Text => {
            println!("{message}");
            Ok(())
        }
    }
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
