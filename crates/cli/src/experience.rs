//! Offline command discovery and help, derived from the executable grammar.

use clap::{Arg, ArgAction, Command, CommandFactory as _, FromArgMatches as _};
use serde::Serialize;

use crate::{cli::Cli, error::Result, output::Format};

/// Use one grammar for parsing, help, error recovery and machine discovery.
pub fn command() -> Command {
    let mut command = enrich(Cli::command(), "iam");
    command = command
        .disable_help_flag(true)
        .disable_version_flag(true)
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .global(true)
                .action(ArgAction::HelpLong)
                .help_heading("Help and version")
                .help("Show detailed help, requirements and related documentation"),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .global(true)
                .action(ArgAction::Version)
                .help_heading("Help and version")
                .help("Show the installed CLI version; use `iam system version` for the backend"),
        );
    command.build();
    command
}

fn enrich(mut command: Command, path: &str) -> Command {
    command = command.mut_args(|arg| {
        let heading = if arg.is_global_set() {
            "Context and output"
        } else if arg.is_required_set() && !arg.is_positional() {
            "Required options"
        } else if matches!(
            arg.get_id().as_str(),
            "stk"
                | "app_secret"
                | "slt"
                | "refresh_token"
                | "token"
                | "subject_token"
                | "access_proof"
        ) {
            "Credentials (supply flags without a terminal)"
        } else if arg.is_positional() {
            "Arguments"
        } else {
            "Options"
        };
        arg.help_heading(heading).hide_env_values(true)
    });
    for child in command.get_subcommands_mut() {
        let child_path = format!("{path} {}", child.get_name());
        *child = enrich(child.clone(), &child_path);
    }
    let mut notes = notes(path);
    if path == "iam" {
        notes.push_str("\n\nAll commands (also available as JSON with `iam -o json commands`):\n");
        append_paths(&command, "iam", &mut notes);
    }
    command.after_help(notes.clone()).after_long_help(notes)
}

fn append_paths(command: &Command, path: &str, text: &mut String) {
    use std::fmt::Write as _;
    for child in command.get_subcommands().filter(|child| public(child)) {
        let path = format!("{path} {}", child.get_name());
        let description = child
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default();
        let _ = writeln!(
            text,
            "  {path:<38} {}",
            description.lines().next().unwrap_or("")
        );
        append_paths(child, &path, text);
    }
}

fn public(command: &Command) -> bool {
    !command.is_hide_set() && command.get_name() != "help"
}

/// Parse without reading configuration or starting an updater on help/errors.
pub fn parse() -> std::result::Result<(Cli, Vec<String>), std::process::ExitCode> {
    let mut command = command();
    let matches = match command.try_get_matches_from_mut(std::env::args_os()) {
        Ok(matches) => matches,
        Err(error) => {
            let _ = error.print();
            if matches!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            ) {
                // Clap's usage context contains grammar, never values from argv.
                // Selecting from it avoids mistaking a flag value for a command.
                if let Some(usage) = error.get(clap::error::ContextKind::Usage) {
                    let usage = usage.to_string();
                    let mut entries = Vec::new();
                    collect_help(&mut command, &mut Vec::new(), &mut entries);
                    if let Some((_, help)) = entries.iter().rev().find(|(path, _)| {
                        let prefix = format!("Usage: iam{}", path_suffix(path));
                        usage.lines().any(|line| {
                            line.strip_prefix(&prefix)
                                .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
                        })
                    }) {
                        eprintln!("\n{help}");
                    }
                }
            }
            return Err(std::process::ExitCode::from(
                u8::try_from(error.exit_code()).unwrap_or(2),
            ));
        }
    };
    let mut path = Vec::new();
    let mut selected = &matches;
    while let Some((name, child)) = selected.subcommand() {
        path.push(name.to_owned());
        selected = child;
    }
    let cli = Cli::from_arg_matches(&matches).map_err(|error| {
        let _ = error.print();
        std::process::ExitCode::from(2)
    })?;
    Ok((cli, path))
}

fn path_suffix(path: &[String]) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!(" {}", path.join(" "))
    }
}

fn collect_help(
    command: &mut Command,
    path: &mut Vec<String>,
    entries: &mut Vec<(Vec<String>, String)>,
) {
    entries.push((path.clone(), command.render_long_help().to_string()));
    for child in command.get_subcommands_mut().filter(|child| public(child)) {
        path.push(child.get_name().to_owned());
        collect_help(child, path, entries);
        path.pop();
    }
}

/// Show the exact leaf's help when runtime validation rejects an argument combination.
pub fn print_help(path: &[String]) {
    let mut command = command();
    let mut selected = &mut command;
    for name in path {
        let Some(child) = selected.find_subcommand_mut(name) else {
            return;
        };
        selected = child;
    }
    eprintln!("\n{}", selected.render_long_help());
}

#[derive(Serialize)]
struct Parameter {
    name: String,
    long: Option<String>,
    short: Option<char>,
    positional: bool,
    required: bool,
    global: bool,
    description: String,
    possible_values: Vec<String>,
}

#[derive(Serialize)]
struct Entry {
    command: String,
    description: String,
    usage: String,
    help: String,
    group: bool,
    arguments: Vec<Parameter>,
}

/// All public commands, directly from the same grammar used by the parser.
pub fn print_commands(format: Format) -> Result<()> {
    let mut entries = Vec::new();
    collect_entries(&mut command(), "iam", &mut entries);
    match format {
        Format::Json => crate::output::json(&entries),
        Format::Text => {
            println!("iam <command> [options]\n");
            for entry in entries {
                println!(
                    "  {:<38} {}",
                    entry.command,
                    entry.description.lines().next().unwrap_or("")
                );
            }
            println!(
                "\nRun `iam <command> --help` for exact requirements and examples.\nRun `iam docs` for offline guides, or `iam -o json commands` for machine-readable help."
            );
            Ok(())
        }
    }
}

fn collect_entries(command: &mut Command, path: &str, entries: &mut Vec<Entry>) {
    for child in command.get_subcommands_mut().filter(|child| public(child)) {
        let path = format!("{path} {}", child.get_name());
        let help = child.render_long_help().to_string();
        entries.push(Entry {
            command: path.clone(),
            description: child
                .get_long_about()
                .or_else(|| child.get_about())
                .map(ToString::to_string)
                .unwrap_or_default(),
            usage: child.render_usage().to_string(),
            help,
            group: child.get_subcommands().any(public),
            arguments: child
                .get_arguments()
                .filter(|arg| !arg.is_hide_set())
                .map(|arg| Parameter {
                    name: arg.get_id().to_string(),
                    long: arg.get_long().map(str::to_owned),
                    short: arg.get_short(),
                    positional: arg.is_positional(),
                    required: arg.is_required_set(),
                    global: arg.is_global_set(),
                    description: arg
                        .get_long_help()
                        .or_else(|| arg.get_help())
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    possible_values: arg
                        .get_possible_values()
                        .into_iter()
                        .filter(|value| !value.is_hide_set())
                        .map(|value| value.get_name().to_owned())
                        .collect(),
                })
                .collect(),
        });
        collect_entries(child, &path, entries);
    }
}

fn notes(path: &str) -> String {
    use std::fmt::Write as _;
    let specific = match path {
        "iam" => {
            "Start here:\n  iam login --email you@example.com\n  iam org list\n  iam config set org <organization-handle>\n  iam docs cli\n\nFor agents:\n  iam -o json commands                 Discover exact syntax without signing in\n  iam docs --search 'short-lived'       Search the bundled integration docs\n  iam --test <ENVIRONMENT_ID> <command> Use an isolated testing environment\n\nHelp, commands and docs are offline: no login, configuration writes or update checks.\nUse --output json for machine-readable results; next-step suggestions are text-only."
        }
        "iam docs" => {
            "Examples:\n  iam docs                             List available guides\n  iam docs cli                         Read the CLI guide\n  iam docs testing                     Read the testing workflow\n  iam docs --search 'webhook'           Find a contract or example\n  iam -o json docs authorization       Read a guide as JSON\n\nBundled documentation describes this installed version. No network or login is needed."
        }
        "iam commands" => {
            "Examples:\n  iam commands\n  iam -o json commands\n\nJSON includes full help and argument metadata for every public command.\nThe usage/help fields also describe required argument groups and conditional requirements."
        }
        "iam login" => {
            "Examples:\n  iam login --email you@example.com\n  iam --org tos login --app-id 'tos>space-station'\n\nDirect IAM Carbon login verifies a channel. With --app-id and no identity flags,\nreuse the stored session and return a single-use SLT. Give only that SLT to the\nApplication, never your IAM verification code or credential. Exchange the SLT promptly.\nA selected organization binds the Application login to that organization; --no-org\nexplicitly requests an unscoped login. Non-interactive verification needs --code."
        }
        "iam silicon-login" => {
            "Examples:\n  iam silicon-login --sid 'assistant:tos'\n  iam --org tos silicon-login --app-id 'tos>space-station'\n\nThe first command prompts for an STK on a terminal. In an agent/non-interactive\nprocess provide --stk explicitly. With only --app-id, reuse a stored Silicon\nsession and return an SLT; do not give the STK to the Application."
        }
        "iam signup" => {
            "Example:\n  iam signup --email you@example.com --phone '+14155552671' --carbon-id space-pilot\n\nIAM verifies both channels before account creation. Production signup requires\ninteractive verification. Carbon IDs use lowercase letters, digits 1-9 (not 0),\nunderscores or hyphens, and must be 3-30 characters. Signup does not select an organization."
        }
        "iam app create" => {
            "Example (replace the secret placeholder before running):\n  iam --org tos app create space-station --name 'Space Station' \\\n    --webhook-url https://spacestation.example.com/webhooks/ \\\n    --webhook-secret '<32-512-non-whitespace-ASCII-characters>' \\\n    --base-url https://spacestation.example.com\n\nRequired: APP_ID, --name, --webhook-url, --webhook-secret, --base-url.\nAPP_ID can appear before or after flags. Use a local handle with --org, or a\nquoted canonical ID such as 'tos>space-station'. Quote `>` to prevent shell redirection.\nThe Application is owned by that organization; a selected --org must match it.\n\nThe webhook secret is supplied by you. IAM returns a separate client secret\nonce: keep both in your server's secret store, never in a browser or a report.\nThe base URL is an origin: no path or trailing slash (the scheme's // is required).\nA webhook URL may have a path and trailing slash; IAM uses the supplied endpoint.\n\nProduction registrations enter review; testing registrations are verified in\nthe selected environment. Successful output includes relevant next commands."
        }
        "iam app import" => {
            "Example:\n  iam --test <ENVIRONMENT_ID> app import 'tos>space-station'\n\nFirst obtain the environment key with `iam env key <ENVIRONMENT_ID>` in the\nproduction control plane, then sign in or sign up inside that test environment.\nThe source ID must be canonical. The test Carbon must administer any existing\ntarget organization. A fresh import does not change production or other environments.\nKeep the returned test client secret separate from the production credential."
        }
        "iam app token exchange" => {
            "Workflow:\n  iam --org tos login --app-id 'tos>space-station'\n  iam --org tos app token exchange 'tos>space-station'\n\nSupply the SLT and Application secret at the protected terminal prompts, or use\n--slt and --app-secret for a non-interactive process. SLTs expire quickly and\nare single-use: do not retry a consumed SLT as a new login. Preserve the returned\nrefresh token securely. Read `iam docs authorization` for initial access synchronization."
        }
        "iam app token authorization" | "iam app token introspect" => {
            "Use the same Application ID/secret, organization and testing environment that\nissued the access token. Immediately fetch authorization after login, including\non an empty application cache; no directory edit or webhook round-trip is needed.\nMissing/undisclosed role or tag fields do not grant authority. Re-check current\nauthority after epoch changes. See `iam docs authorization` for the exact contract."
        }
        "iam app obo exchange" | "iam app obo verify" => {
            "OBO proofs bind the subject, audience, registered endpoint, HTTP method and exact\nbody bytes. Keep those inputs identical; verification consumes a proof once.\nA valid actor alone is not an admin/tag grant: use the verified authorization\nbinding. Role/tag changes can invalidate a previously issued proof.\nSee `iam docs obo` before implementing a downstream authorization decision."
        }
        "iam app verify-webhook" => {
            "Verify the exact raw body bytes and all signed headers before parsing or acting.\nUse --body-file where offered on OBO commands; this command takes BODY_FILE as\na positional argument. `-` reads stdin. Do not reserialize JSON before verification.\nUse the configured signing secret for the delivered key version, not the client secret."
        }
        "iam step-up" => {
            "Workflow:\n  1. Read the target with its show command to obtain its internal UUID.\n  2. Run `iam step-up <ACTION> <RESOURCE_ID>` in the same organization/environment.\n  3. Pass the returned assertion using --step-up on the intended mutation.\n\nUse the exact action and resource type printed in that mutation's help.\nA handle is not a resource UUID. Assertions are short-lived and cannot authorize\na different action or resource. A direct Carbon session is required."
        }
        "iam env" | "iam env create" | "iam env key" => {
            "Testing workflow:\n  iam --org tos env create 'integration-check'\n  iam env key <ENVIRONMENT_ID>\n  iam --test <ENVIRONMENT_ID> signup --help\n  iam --test <ENVIRONMENT_ID> app import 'tos>space-station'\n\nLifecycle commands use the production control plane: omit --test and unset\nSILICON_IAM_TEST if set. A production organization/member is not automatically\ncopied into the test plane; sign up or log in there separately. Pass the public\nenvironment UUID to --test, never its root key. Keys are stored privately per profile."
        }
        "iam env clean" => {
            "WARNING: deletes data inside the targeted testing environment. There is no undo.\nWith an explicit ID, use the production control plane (no --test). Without an ID,\n--test selects the environment and uses this profile's stored key.\nRead `iam env show <ENVIRONMENT_ID>` or `iam --test <ENVIRONMENT_ID> env current`\nfirst to confirm the target. After cleaning, sign up and import again; old tokens\nand memberships no longer provide access. Other environments remain separate."
        }
        "iam config" | "iam config set" | "iam config use" => {
            "Examples:\n  iam config show\n  iam config set org tos\n  iam --profile local config set url http://127.0.0.1:58080\n  iam --test <ENVIRONMENT_ID> config set org tos\n  iam config set auto-update off\n\nCommand flags override environment variables, which override profile defaults.\nTest organizations/sessions are stored separately; setting a test org does not\nchange the production default. SILICON_IAM_HOME chooses a private credential\ndirectory. Help and docs remain usable even when that directory is unavailable."
        }
        _ => "",
    };
    let mut text = specific.to_owned();
    if path == "iam" || matches!(path, "iam docs" | "iam commands") {
        return text;
    }
    let family = path.split_whitespace().nth(1).unwrap_or("cli");
    let topic = match family {
        "app" => "applications",
        "env" => "testing",
        "config" => "storage",
        _ => "cli",
    };
    if !text.is_empty() {
        text.push_str("\n\n");
    }
    let _ = write!(
        text,
        "Reference:\n  iam docs {topic}\n  iam docs --search '{family}'\n  iam commands"
    );
    if !matches!(family, "config" | "system") {
        text.push_str("\n\nContext:\n  Keep --profile, --url and --test consistent across a workflow. Use --org for\n  organization-scoped actions. `iam config show` reveals resolved settings.\n  --output json returns structured data without next-step suggestions.\n  In non-interactive use, supply credential/code flags explicitly; no hidden prompts.");
    }
    text
}
