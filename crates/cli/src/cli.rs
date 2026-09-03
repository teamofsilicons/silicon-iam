//! The command grammar.
//!
//! Nouns then verbs -- `siam tag create`, `siam member remove` -- because that
//! is what a person guesses, and because it keeps related commands together in
//! `--help`. Global flags come before the command and are accepted anywhere.

use clap::{Args, Parser, Subcommand};
use uuid::Uuid;

use crate::output::Format;

/// The Silicon IAM command-line client.
#[derive(Debug, Parser)]
#[command(
    name = "siam",
    version,
    about = "Silicon IAM from the command line",
    long_about = "Silicon IAM from the command line.\n\n\
        Sign in once with `siam login`; the session is stored under \
        ~/.silicon-iam/ and renewed automatically. Most commands act on an \
        organization: pass --org, or set a default with \
        `siam config set org <handle>`.",
    propagate_version = true,
    disable_help_subcommand = false
)]
pub struct Cli {
    /// Global options.
    #[command(flatten)]
    pub global: Global,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Options accepted by every command.
#[derive(Debug, Args)]
pub struct Global {
    /// Service base URL.
    #[arg(long, global = true, env = "SILICON_IAM_URL")]
    pub url: Option<String>,

    /// Stored profile to use.
    #[arg(long, global = true, env = "SILICON_IAM_PROFILE")]
    pub profile: Option<String>,

    /// Organization handle to act on.
    #[arg(long, global = true, env = "SILICON_IAM_ORG")]
    pub org: Option<String>,

    /// Run inside a testing environment, by key.
    #[arg(long, global = true, env = "SILICON_IAM_ENVIRONMENT")]
    pub environment: Option<String>,

    /// Step-up assertion for commands that require one.
    #[arg(long, global = true)]
    pub step_up: Option<String>,

    /// Output format.
    #[arg(long, short = 'o', global = true, value_enum, default_value_t = Format::Text)]
    pub output: Format,
}

/// Everything the CLI can do.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign in as a Carbon.
    Login(LoginArgs),
    /// Sign in as a Silicon with its credential.
    SiliconLogin(SiliconLoginArgs),
    /// Sign out, forgetting the stored session.
    Logout,
    /// Show who is signed in.
    Whoami,
    /// Create a Carbon account.
    Signup(SignupArgs),
    /// Print every command this CLI accepts.
    Commands,

    /// Organizations.
    #[command(subcommand)]
    Org(OrgCommand),
    /// Members of an organization.
    #[command(subcommand)]
    Member(MemberCommand),
    /// Invitations, from both ends.
    #[command(subcommand)]
    Invite(InviteCommand),
    /// Organization tags.
    #[command(subcommand)]
    Tag(TagCommand),
    /// Advisory trust.
    #[command(subcommand)]
    Trust(TrustCommand),
    /// Approvals, direct changes, and history.
    #[command(subcommand)]
    Approval(ApprovalCommand),
    /// Silicons.
    #[command(subcommand)]
    Silicon(SiliconCommand),
    /// Applications.
    #[command(subcommand)]
    App(AppCommand),
    /// Testing environments.
    #[command(subcommand)]
    Env(EnvCommand),
    /// Your own sessions and login history.
    #[command(subcommand)]
    Session(SessionCommand),
    /// Stored settings.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// The service itself.
    #[command(subcommand)]
    System(SystemCommand),
}

/// Arguments for signing in.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Email address to sign in with.
    #[arg(long, group = "identity")]
    pub email: Option<String>,
    /// Phone number, in E.164 form.
    #[arg(long, group = "identity")]
    pub phone: Option<String>,
    /// Carbon ID.
    #[arg(long, group = "identity")]
    pub carbon_id: Option<String>,
    /// Verification code, if you already have it. Prompted for otherwise.
    #[arg(long)]
    pub code: Option<String>,
    /// Application to sign in to. Prints a short-lived token for it.
    #[arg(long = "app-id", value_name = "APP_ID")]
    pub app_id: Option<String>,
}

/// Arguments for signing a Silicon in.
#[derive(Debug, Args)]
pub struct SiliconLoginArgs {
    /// Silicon ID, in `handle:org` form. Prompted for when omitted.
    #[arg(long = "sid")]
    pub sid: Option<String>,
    /// Silicon token. Prompted for when omitted, so it stays out of shell history.
    #[arg(long = "stk")]
    pub stk: Option<String>,
    /// Application to sign in to. Prints a short-lived token for it.
    #[arg(long = "app-id", value_name = "APP_ID")]
    pub app_id: Option<String>,
}

/// Arguments for creating an account.
#[derive(Debug, Args)]
pub struct SignupArgs {
    /// Email address to verify.
    #[arg(long)]
    pub email: String,
    /// Phone number to verify, in E.164 form.
    #[arg(long)]
    pub phone: String,
    /// The Carbon ID to claim.
    #[arg(long)]
    pub carbon_id: String,
    /// Display name. Defaults to the Carbon ID.
    #[arg(long)]
    pub display_name: Option<String>,
    /// IANA time zone, such as `Asia/Kolkata`.
    #[arg(long)]
    pub timezone: Option<String>,
}

/// Organization commands.
#[derive(Debug, Subcommand)]
pub enum OrgCommand {
    /// List organizations you belong to.
    List(PageArgs),
    /// Create an organization.
    Create {
        /// Handle to claim.
        handle: String,
        /// Display name.
        #[arg(long)]
        name: String,
        /// Description.
        #[arg(long)]
        description: Option<String>,
    },
    /// Show one organization.
    Show {
        /// Handle. Defaults to --org.
        handle: Option<String>,
    },
    /// Rename or re-describe an organization.
    Update {
        /// Handle. Defaults to --org.
        handle: Option<String>,
        /// New display name.
        #[arg(long)]
        name: Option<String>,
        /// New description.
        #[arg(long)]
        description: Option<String>,
        /// Join method: `email` or `sso`.
        #[arg(long)]
        join_method: Option<String>,
    },
    /// Check whether a handle can be claimed.
    Available {
        /// Handle to check.
        handle: String,
    },
    /// Hand ownership to another member. Needs --step-up.
    Transfer {
        /// Membership that becomes the owner.
        membership_id: Uuid,
        /// Handle. Defaults to --org.
        #[arg(long)]
        org: Option<String>,
    },
}

/// Member commands.
#[derive(Debug, Subcommand)]
pub enum MemberCommand {
    /// List members.
    List {
        /// Only Carbons, or only Silicons.
        #[arg(long, value_name = "carbon|silicon")]
        principal_type: Option<String>,
        /// Only members carrying this tag.
        #[arg(long)]
        tag: Option<Uuid>,
        /// Only members in this state.
        #[arg(long)]
        status: Option<String>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Show one member.
    Show {
        /// Membership identifier.
        membership_id: Uuid,
    },
    /// Show a member's role and capabilities.
    Authorization {
        /// Membership identifier.
        membership_id: Uuid,
    },
    /// Update a member's directory metadata.
    Update {
        /// Membership identifier.
        membership_id: Uuid,
        /// New reporting line.
        #[arg(long)]
        reports_to: Option<Uuid>,
        /// New profile photo URL.
        #[arg(long)]
        profile_photo: Option<String>,
    },
    /// Remove a member.
    Remove {
        /// Membership identifier.
        membership_id: Uuid,
        /// Membership to inherit anyone reporting to them.
        #[arg(long)]
        reassign_reports_to: Option<Uuid>,
    },
    /// Promote a member to administrator. Needs --step-up.
    Promote {
        /// Membership identifier.
        membership_id: Uuid,
    },
    /// Demote an administrator. Needs --step-up.
    Demote {
        /// Membership identifier.
        membership_id: Uuid,
    },
    /// Replace an administrator's capabilities. Needs --step-up.
    Capabilities {
        /// Membership identifier.
        membership_id: Uuid,
        /// The complete set to grant; anything omitted is revoked.
        #[arg(long = "capability", value_name = "CAPABILITY")]
        capabilities: Vec<String>,
    },
    /// Show the organization directory.
    Directory {
        /// Field selector the service understands.
        #[arg(long)]
        fields: Option<String>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Show your own directory entry.
    Self_ {
        /// Field selector the service understands.
        #[arg(long)]
        fields: Option<String>,
    },
}

/// Invitation commands.
#[derive(Debug, Subcommand)]
pub enum InviteCommand {
    /// List invitations this organization issued.
    List {
        /// Only invitations in this state.
        #[arg(long)]
        status: Option<String>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Invite a Carbon by handle or email.
    Create {
        /// Carbon ID to invite.
        #[arg(long, group = "identity")]
        carbon_id: Option<String>,
        /// Email address to invite.
        #[arg(long, group = "identity")]
        email: Option<String>,
        /// Job role granted on acceptance.
        #[arg(long)]
        job_role: String,
        /// Trust boundary the new member starts with.
        #[arg(long, default_value = "internal")]
        boundary: String,
        /// Trust level the new member starts with.
        #[arg(long, default_value = "not_trusted")]
        level: String,
    },
    /// Show one invitation.
    Show {
        /// Invitation identifier.
        invite_id: Uuid,
    },
    /// Revoke a pending invitation.
    Revoke {
        /// Invitation identifier.
        invite_id: Uuid,
    },
    /// Send yourself the verification code for an email invitation.
    Code {
        /// The invited email address.
        email: String,
    },
    /// Accept an invitation and join.
    Accept {
        /// The invitation being accepted.
        invite_id: Uuid,
        /// Verification code from the invitation email.
        #[arg(long)]
        code: String,
    },
}

/// Tag commands.
#[derive(Debug, Subcommand)]
pub enum TagCommand {
    /// List tags.
    List(PageArgs),
    /// Create a tag.
    Create {
        /// Tag name.
        name: String,
    },
    /// Show one tag.
    Show {
        /// Tag identifier.
        tag_id: Uuid,
    },
    /// Rename a tag.
    Rename {
        /// Tag identifier.
        tag_id: Uuid,
        /// New name.
        name: String,
    },
    /// Delete a tag, and everything it conferred.
    Delete {
        /// Tag identifier.
        tag_id: Uuid,
    },
    /// List members carrying a tag.
    Members {
        /// Tag identifier.
        tag_id: Uuid,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
}

/// Trust commands.
#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    /// Show the organization-wide default.
    Default,
    /// Replace the organization-wide default.
    SetDefault {
        /// `internal` or `external`.
        #[arg(long)]
        boundary: String,
        /// `not_trusted`, `needs_approval`, or `trusted`.
        #[arg(long)]
        level: String,
    },
    /// List trust rules.
    List(PageArgs),
    /// Create a trust rule.
    Create {
        /// Subject tag.
        #[arg(long, group = "subject")]
        subject_tag: Option<Uuid>,
        /// Subject membership.
        #[arg(long, group = "subject")]
        subject_membership: Option<Uuid>,
        /// Target tag.
        #[arg(long, group = "target")]
        target_tag: Option<Uuid>,
        /// Target Silicon membership.
        #[arg(long, group = "target")]
        target_membership: Option<Uuid>,
        /// `internal` or `external`.
        #[arg(long)]
        boundary: String,
        /// `not_trusted`, `needs_approval`, or `trusted`.
        #[arg(long)]
        level: String,
    },
    /// Show one trust rule.
    Show {
        /// Rule identifier.
        rule_id: Uuid,
    },
    /// Change a rule's trust value.
    Update {
        /// Rule identifier.
        rule_id: Uuid,
        /// `internal` or `external`.
        #[arg(long)]
        boundary: String,
        /// `not_trusted`, `needs_approval`, or `trusted`.
        #[arg(long)]
        level: String,
    },
    /// Archive a trust rule.
    Delete {
        /// Rule identifier.
        rule_id: Uuid,
    },
    /// Explain the trust between a subject and a target Silicon.
    Evaluate {
        /// Subject membership.
        #[arg(long)]
        subject: Uuid,
        /// Target Silicon membership.
        #[arg(long)]
        target: Uuid,
    },
}

/// Governance commands.
#[derive(Debug, Subcommand)]
pub enum ApprovalCommand {
    /// List approval requests.
    List {
        /// Only requests in this state.
        #[arg(long)]
        status: Option<String>,
        /// Only requests of this kind.
        #[arg(long)]
        kind: Option<String>,
        /// Only requests you can decide now.
        #[arg(long)]
        mine: bool,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Show one approval request.
    Show {
        /// Request identifier.
        request_id: Uuid,
    },
    /// Approve or reject a request.
    Decide {
        /// Request identifier.
        request_id: Uuid,
        /// `approve` or `reject`.
        #[arg(long)]
        decision: String,
        /// Reason recorded with the decision.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Request a job-role change.
    RequestRole {
        /// Membership whose role should change.
        #[arg(long)]
        membership_id: Uuid,
        /// The role being asked for.
        #[arg(long)]
        job_role: String,
    },
    /// Request a tag change for a member.
    RequestTags {
        /// Membership whose tags should change.
        #[arg(long)]
        membership_id: Uuid,
        /// Tags to add.
        #[arg(long = "add", value_name = "TAG_ID")]
        add: Vec<Uuid>,
        /// Tags to remove.
        #[arg(long = "remove", value_name = "TAG_ID")]
        remove: Vec<Uuid>,
    },
    /// Set a member's job role directly.
    SetRole {
        /// Membership identifier.
        membership_id: Uuid,
        /// The role to set.
        job_role: String,
    },
    /// Replace a member's tags directly.
    SetTags {
        /// Membership identifier.
        membership_id: Uuid,
        /// The complete tag set; anything omitted is removed.
        #[arg(long = "tag", value_name = "TAG_ID")]
        tags: Vec<Uuid>,
    },
    /// Show a member's job-role history.
    RoleHistory {
        /// Membership identifier.
        membership_id: Uuid,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Show a member's tag history.
    TagHistory {
        /// Membership identifier.
        membership_id: Uuid,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
}

/// Silicon commands.
#[derive(Debug, Subcommand)]
pub enum SiliconCommand {
    /// List Silicons.
    List {
        /// Only Silicons carrying this tag.
        #[arg(long)]
        tag: Option<Uuid>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Create a Silicon, returning its credential once.
    Create {
        /// Handle component; the global ID becomes `handle:org`.
        handle: String,
        /// Job role this Silicon holds.
        #[arg(long)]
        job_role: String,
        /// Display name.
        #[arg(long)]
        display_name: Option<String>,
        /// Membership this Silicon reports to.
        #[arg(long)]
        reports_to: Option<Uuid>,
        /// Tags to assign at creation.
        #[arg(long = "tag", value_name = "TAG_ID")]
        tags: Vec<Uuid>,
    },
    /// Show one Silicon.
    Show {
        /// Global Silicon ID.
        silicon_id: String,
    },
    /// Update a Silicon's directory configuration.
    Update {
        /// Global Silicon ID.
        silicon_id: String,
        /// New display name.
        #[arg(long)]
        display_name: Option<String>,
        /// New reporting line.
        #[arg(long)]
        reports_to: Option<Uuid>,
    },
    /// Remove a Silicon.
    Remove {
        /// Global Silicon ID.
        silicon_id: String,
        /// Membership to inherit anyone reporting to it.
        #[arg(long)]
        reassign_reports_to: Option<Uuid>,
    },
    /// Request credential rotation. Needs --step-up.
    RotateRequest {
        /// Global Silicon ID.
        silicon_id: String,
    },
    /// Complete an approved rotation. Needs --step-up.
    RotateComplete {
        /// Global Silicon ID.
        silicon_id: String,
        /// The approved request.
        request_id: Uuid,
    },
    /// Show the webhook endpoint.
    Webhook {
        /// Global Silicon ID.
        silicon_id: String,
    },
    /// Configure or replace the webhook endpoint.
    SetWebhook {
        /// Global Silicon ID.
        silicon_id: String,
        /// HTTPS endpoint to deliver to.
        #[arg(long)]
        url: String,
    },
    /// Remove the webhook endpoint.
    DeleteWebhook {
        /// Global Silicon ID.
        silicon_id: String,
    },
    /// Show the webhook subscription.
    Subscription {
        /// Global Silicon ID.
        silicon_id: String,
    },
    /// Replace the webhook subscription.
    SetSubscription {
        /// Global Silicon ID.
        silicon_id: String,
        /// `all` for every event, or `selected` with --topic.
        #[arg(long, default_value = "all")]
        mode: String,
        /// Topics to receive when mode is `selected`.
        #[arg(long = "topic", value_name = "TOPIC")]
        topics: Vec<String>,
        /// Additional tags whose events should also be delivered.
        #[arg(long = "tag", value_name = "TAG_ID")]
        tags: Vec<Uuid>,
    },
    /// Remove the webhook subscription.
    DeleteSubscription {
        /// Global Silicon ID.
        silicon_id: String,
    },
    /// List deliveries that exhausted their retries.
    DeadLetters {
        /// Global Silicon ID.
        silicon_id: String,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Re-queue dead-lettered deliveries.
    Replay {
        /// Global Silicon ID.
        silicon_id: String,
        /// Deliveries to replay.
        #[arg(long = "delivery", value_name = "DELIVERY_ID")]
        deliveries: Vec<Uuid>,
    },
}

/// Application commands.
#[derive(Debug, Subcommand)]
pub enum AppCommand {
    /// List applications you can administer.
    List {
        /// Only applications in this state.
        #[arg(long)]
        status: Option<String>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Register an application, returning its secrets once.
    Create {
        /// Application identifier to claim.
        app_id: String,
        /// Display name.
        #[arg(long)]
        name: String,
        /// Owning organization. Defaults to --org.
        #[arg(long)]
        org: Option<String>,
        /// HTTPS endpoint the service delivers webhooks to.
        #[arg(long)]
        webhook_url: String,
    },
    /// Show one application.
    Show {
        /// Application identifier.
        app_id: String,
    },
    /// Update an application.
    Update {
        /// Application identifier.
        app_id: String,
        /// New display name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Rotate the client secret. Needs --step-up.
    RotateSecret {
        /// Application identifier.
        app_id: String,
    },
    /// Show the webhook endpoint.
    Webhook {
        /// Application identifier.
        app_id: String,
    },
    /// Propose a webhook endpoint.
    SetWebhook {
        /// Application identifier.
        app_id: String,
        /// HTTPS endpoint to deliver to.
        #[arg(long)]
        url: String,
    },
    /// List deliveries that exhausted their retries.
    DeadLetters {
        /// Application identifier.
        app_id: String,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Re-queue dead-lettered deliveries.
    Replay {
        /// Application identifier.
        app_id: String,
        /// Deliveries to replay.
        #[arg(long = "delivery", value_name = "DELIVERY_ID")]
        deliveries: Vec<Uuid>,
    },
    /// Show logins performed through an application.
    History {
        /// Application identifier.
        app_id: String,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
}

/// Testing environment commands.
#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// List environments.
    List {
        /// `active`, `deleted`, or `all`.
        #[arg(long)]
        status: Option<String>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Create an environment, returning its key.
    Create {
        /// Environment name.
        name: String,
        /// Description.
        #[arg(long)]
        description: Option<String>,
    },
    /// Show one environment.
    Show {
        /// Environment identifier.
        environment_id: Uuid,
    },
    /// Rename or re-describe an environment.
    Update {
        /// Environment identifier.
        environment_id: Uuid,
        /// New name.
        #[arg(long)]
        name: Option<String>,
        /// New description.
        #[arg(long)]
        description: Option<String>,
    },
    /// Retire an environment, keeping it recoverable.
    Delete {
        /// Environment identifier.
        environment_id: Uuid,
    },
    /// Bring a retired environment back.
    Restore {
        /// Environment identifier.
        environment_id: Uuid,
    },
    /// Show an environment's key.
    Key {
        /// Environment identifier.
        environment_id: Uuid,
    },
    /// Issue a new key, invalidating the old one.
    RotateKey {
        /// Environment identifier.
        environment_id: Uuid,
    },
    /// Erase everything inside an environment.
    Clean {
        /// Environment identifier. Omit to clean the one --environment names.
        environment_id: Option<Uuid>,
    },
    /// Describe the environment --environment names.
    Current,
}

/// Session commands.
#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// List your active sessions.
    List(PageArgs),
    /// Revoke one of your sessions. Needs --step-up.
    Revoke {
        /// Session identifier.
        session_id: Uuid,
    },
    /// Show your login history.
    History(PageArgs),
}

/// Settings commands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Show the current settings.
    Show,
    /// List configured profiles.
    Profiles,
    /// Set a value on the current profile.
    Set {
        /// One of `url`, `org`, `environment`.
        key: String,
        /// The value to store.
        value: String,
    },
    /// Clear a value on the current profile.
    Unset {
        /// One of `org`, `environment`.
        key: String,
    },
    /// Switch the default profile.
    Use {
        /// Profile name.
        profile: String,
    },
}

/// Service commands.
#[derive(Debug, Subcommand)]
pub enum SystemCommand {
    /// Show the service's version, and agree an API version.
    Version,
    /// Check that the service is alive and ready.
    Health,
}

/// Where a listing starts, and how much of it to take.
#[derive(Debug, Args, Default)]
pub struct PageArgs {
    /// Continue from a cursor a previous page returned.
    #[arg(long)]
    pub cursor: Option<String>,
    /// Maximum entries to return.
    #[arg(long)]
    pub limit: Option<u16>,
}

impl PageArgs {
    /// The client's paging value for these arguments.
    #[must_use]
    pub fn paging(&self) -> silicon_iam_client::Paging {
        let mut paging = silicon_iam_client::Paging::new();
        if let Some(cursor) = &self.cursor {
            paging = paging.after(cursor.clone());
        }
        if let Some(limit) = self.limit {
            paging = paging.limit(limit);
        }
        paging
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::Cli;

    #[test]
    fn the_grammar_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn global_flags_are_accepted_after_the_command_too() {
        use clap::Parser as _;

        let parsed = Cli::try_parse_from(["siam", "tag", "list", "--org", "acme"]);
        assert!(parsed.is_ok(), "{parsed:?}");
        let Ok(cli) = parsed else { return };
        assert_eq!(cli.global.org.as_deref(), Some("acme"));
    }

    #[test]
    fn login_admits_exactly_one_identity() {
        use clap::Parser as _;

        assert!(Cli::try_parse_from(["siam", "login", "--email", "a@b.test"]).is_ok());
        // Two identities is ambiguous, and the grammar says so rather than
        // silently preferring one.
        assert!(
            Cli::try_parse_from([
                "siam",
                "login",
                "--email",
                "a@b.test",
                "--carbon-id",
                "someone"
            ])
            .is_err()
        );
    }
}
