//! One module per noun, matching the command grammar.

pub mod app;
pub mod approval;
pub mod auth;
pub mod carbon;
pub mod config;
pub mod env;
pub mod invite;
pub mod member;
pub mod org;
pub mod session;
pub mod silicon;
pub mod sso;
pub mod system;
pub mod tag;
pub mod trust;

use crate::{cli::Command, context::Context, error::Result};

/// Runs one command.
///
/// # Errors
///
/// Returns whatever the command reports.
pub async fn dispatch(context: &Context, command: Command) -> Result<()> {
    match command {
        Command::Login(args) => auth::login(context, args).await,
        Command::SiliconLogin(args) => auth::silicon_login(context, args).await,
        Command::Logout(args) => auth::logout(context, args).await,
        Command::Whoami => auth::whoami(context).await,
        Command::StepUp(args) => auth::step_up(context, args).await,
        Command::Signup(args) => auth::signup(context, args).await,
        Command::Carbon(command) => carbon::run(context, command).await,
        Command::Commands => {
            print_commands();
            Ok(())
        }
        Command::Org(command) => org::run(context, command).await,
        Command::Sso(command) => sso::run(context, command).await,
        Command::Member(command) => member::run(context, command).await,
        Command::Invite(command) => invite::run(context, command).await,
        Command::Tag(command) => tag::run(context, command).await,
        Command::Trust(command) => trust::run(context, command).await,
        Command::Approval(command) => approval::run(context, command).await,
        Command::Silicon(command) => silicon::run(context, command).await,
        Command::App(command) => app::run(context, command).await,
        Command::Env(command) => env::run(context, command).await,
        Command::Session(command) => session::run(context, command).await,
        Command::Config(command) => config::run(context, command),
        Command::System(command) => system::run(context, command).await,
    }
}

/// Prints every command, at every depth.
///
/// `--help` shows one level at a time, which is right when you know roughly
/// where you are going. This is for when you do not.
fn print_commands() {
    use clap::CommandFactory as _;

    fn walk(command: &clap::Command, prefix: &str) {
        for sub in command.get_subcommands() {
            if sub.get_name() == "help" {
                continue;
            }
            let path = if prefix.is_empty() {
                sub.get_name().to_owned()
            } else {
                format!("{prefix} {}", sub.get_name())
            };
            let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
            println!("  {path:<34} {about}");
            walk(sub, &path);
        }
    }

    let command = crate::cli::Cli::command();
    println!("iam <command> [options]\n");
    walk(&command, "");
    println!("\nRun `iam <command> --help` for the options each one takes.");
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    /// Every command the grammar declares is reachable from `dispatch`.
    ///
    /// The check is structural rather than behavioural: `dispatch` matches
    /// exhaustively on the command enum, so the compiler already refuses a
    /// missing arm. What this catches is a command declared and then never
    /// given a `run` at all -- a group whose subcommands exist only in help.
    #[test]
    fn every_group_has_subcommands_behind_it() {
        let command = crate::cli::Cli::command();
        let groups: Vec<_> = command
            .get_subcommands()
            .filter(|sub| {
                !matches!(
                    sub.get_name(),
                    "login"
                        | "silicon-login"
                        | "logout"
                        | "whoami"
                        | "step-up"
                        | "signup"
                        | "commands"
                        | "help"
                )
            })
            .collect();
        assert!(!groups.is_empty());
        for group in groups {
            assert!(
                group.get_subcommands().next().is_some(),
                "{} declares no subcommands",
                group.get_name()
            );
        }
    }

    #[test]
    fn every_command_carries_a_description() {
        fn walk(command: &clap::Command) {
            for sub in command.get_subcommands() {
                if sub.get_name() == "help" {
                    continue;
                }
                assert!(
                    sub.get_about().is_some(),
                    "{} has no description, so `iam commands` would list it blank",
                    sub.get_name()
                );
                walk(sub);
            }
        }
        walk(&crate::cli::Cli::command());
    }
}
