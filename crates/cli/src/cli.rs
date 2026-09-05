//! The command grammar.
//!
//! Nouns then verbs -- `iam tag create`, `iam member remove` -- because that
//! is what a person guesses, and because it keeps related commands together in
//! `--help`. Global flags come before the command and are accepted anywhere.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::output::Format;

/// The Silicon IAM command-line client.
#[derive(Debug, Parser)]
#[command(
    name = "iam",
    version,
    about = "Silicon IAM from the command line",
    long_about = "Silicon IAM from the command line.\n\n\
        Sign in once with `iam login`; the session is stored under \
        ~/.silicon-iam/ and renewed automatically. Most commands act on an \
        organization: pass --org, or set a default with \
        `iam config set org <handle>`.",
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
    /// Service base URL. HTTPS is required except for localhost or a loopback
    /// IP address; credentials, port zero, query, and fragment are rejected.
    #[arg(long, global = true, env = "SILICON_IAM_URL")]
    pub url: Option<String>,

    /// Stored profile to use.
    #[arg(long, global = true, env = "SILICON_IAM_PROFILE")]
    pub profile: Option<String>,

    /// Organization handle to act on. Falls back to `SILICON_IAM_ORG`, then the
    /// current profile's stored organization.
    #[arg(long, global = true)]
    pub org: Option<String>,

    /// Ignore any stored or environment organization for this invocation.
    /// Useful with a canonical app ID for an unscoped Application login.
    #[arg(long, global = true, conflicts_with = "org")]
    pub no_org: bool,

    /// Run inside a testing environment, by its hyphenated UUID (never its
    /// root key).
    #[arg(
        long,
        global = true,
        env = "SILICON_IAM_TEST",
        value_name = "ENVIRONMENT_ID",
        value_parser = parse_testing_environment_id
    )]
    pub test: Option<Uuid>,

    /// Step-up assertion minted by `iam step-up <ACTION> <RESOURCE_ID>`.
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
    /// End a Carbon session remotely; forget a Silicon session locally.
    Logout(LogoutArgs),
    /// Show who is signed in.
    Whoami,
    /// Mint a one-action, one-resource step-up token.
    StepUp(StepUpArgs),
    /// Create a Carbon account.
    Signup(SignupArgs),
    /// Your Carbon profile and public Carbon lookup.
    #[command(subcommand)]
    Carbon(CarbonCommand),
    /// Print every command; --output json includes its usage, arguments and full help.
    Commands,
    /// Read or search the bundled CLI, API and client documentation offline.
    Docs {
        /// Documentation topic from `iam docs`, such as cli, testing, applications or obo.
        topic: Option<String>,
        /// Find text across the bundled documentation, or within the selected topic.
        #[arg(long, value_name = "TEXT")]
        search: Option<String>,
    },

    /// Organizations.
    #[command(subcommand)]
    Org(OrgCommand),
    /// Organization single sign-on.
    #[command(subcommand)]
    Sso(SsoCommand),
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
    ///
    /// Lifecycle commands use a production Carbon session and organization;
    /// omit --test for them. `env current`, `app import`, and `env clean`
    /// without an explicit environment ID are test-only and require --test.
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
#[command(group(
    clap::ArgGroup::new("identity")
        .args(["email", "phone", "carbon_id"])
        .required(false)
        .multiple(false)
))]
#[command(group(
    clap::ArgGroup::new("login_source")
        .args(["email", "phone", "carbon_id", "app_id"])
        .required(true)
        .multiple(true)
))]
pub struct LoginArgs {
    /// Email address to sign in with.
    #[arg(long)]
    pub email: Option<String>,
    /// Phone number, in E.164 form.
    #[arg(long)]
    pub phone: Option<String>,
    /// Carbon ID.
    #[arg(long)]
    pub carbon_id: Option<String>,
    /// Verification code, if you already have it. Prompted for otherwise.
    #[arg(long)]
    pub code: Option<String>,
    /// Application to sign in to. Prints a short-lived token for it.
    #[arg(long = "app-id", value_name = "APP_ID")]
    pub app_id: Option<String>,
}

/// Arguments for signing out.
#[derive(Debug, Args)]
pub struct LogoutArgs {
    /// End every Carbon session. Needs --step-up: action
    /// `account.sessions_revoke_all`, resource = the signed-in Carbon's
    /// principal UUID. Every affected session must be at least 12 hours old.
    #[arg(long, conflicts_with = "local_only")]
    pub all: bool,
    /// Only forget this device's stored credential; do not call IAM.
    #[arg(long, conflicts_with = "all")]
    pub local_only: bool,
}

/// Arguments for signing a Silicon in.
#[derive(Debug, Args)]
pub struct SiliconLoginArgs {
    /// Silicon ID, in `handle:org` form. With only --app-id, reuse the stored Silicon session.
    #[arg(long = "sid")]
    pub sid: Option<String>,
    /// Silicon token. Prompted for when omitted, so it stays out of shell history.
    #[arg(long = "stk")]
    pub stk: Option<String>,
    /// Application to sign in to. Prints an SLT; omit --sid and --stk to reuse the stored Silicon session.
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
    /// Carbon ID: 3-30 lowercase letters, digits 1-9, underscores or hyphens (no 0).
    #[arg(long, value_parser = parse_carbon_id)]
    pub carbon_id: String,
    /// Display name. Defaults to the Carbon ID.
    #[arg(long)]
    pub display_name: Option<String>,
    /// IANA time zone, such as `Asia/Kolkata`.
    #[arg(long)]
    pub timezone: Option<String>,
}

/// Carbon profile and lookup commands.
#[derive(Debug, Subcommand)]
pub enum CarbonCommand {
    /// Show the signed-in Carbon's complete profile.
    Show,
    /// Update the signed-in Carbon's profile.
    #[command(group(
        clap::ArgGroup::new("changes")
            .args([
                "display_name",
                "timezone",
                "description",
                "clear_description",
                "profile_photo",
                "clear_profile_photo"
            ])
            .required(true)
            .multiple(true)
    ))]
    Update {
        /// New display name.
        #[arg(long)]
        display_name: Option<String>,
        /// New IANA time zone, such as `Asia/Kolkata`.
        #[arg(long)]
        timezone: Option<String>,
        /// New profile description.
        #[arg(long)]
        description: Option<String>,
        /// Remove the current profile description.
        #[arg(long, conflicts_with = "description")]
        clear_description: bool,
        /// New profile-photo URL.
        #[arg(long)]
        profile_photo: Option<String>,
        /// Restore the generated default profile photo.
        #[arg(long, conflicts_with = "profile_photo")]
        clear_profile_photo: bool,
    },
    /// Check whether a Carbon ID can be claimed.
    Available {
        /// Carbon ID to check; this does not reserve it.
        carbon_id: String,
    },
    /// Suggest public Carbon IDs matching a partial handle.
    Search {
        /// Non-empty partial Carbon ID, up to 100 characters.
        query: String,
        /// Maximum suggestions to return, from 1 through 10.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=10))]
        limit: Option<u16>,
    },
    /// Resolve an exact verified email address to a Carbon ID.
    ResolveEmail {
        /// Exact verified email address.
        email: String,
    },
    /// Resolve an exact verified E.164 phone number to a Carbon ID.
    ResolvePhone {
        /// Exact verified phone number, such as `+12025550123`.
        phone: String,
    },
}

/// Arguments for verified-channel step-up.
#[derive(Debug, Args)]
pub struct StepUpArgs {
    /// Sensitive action the token will authorize.
    #[arg(value_enum)]
    pub action: StepUpActionArg,
    /// Internal UUID of the exact resource being changed.
    pub resource_id: Uuid,
    /// Verified channel that receives the code.
    #[arg(long, value_enum, default_value_t = StepUpChannel::Email)]
    pub channel: StepUpChannel,
    /// Verification code, if already known. Prompted for otherwise.
    #[arg(long)]
    pub code: Option<String>,
}

/// Sensitive actions supported by the IAM step-up contract.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum StepUpActionArg {
    /// Revoke one of the current Carbon's sessions.
    #[value(name = "account.session_revoke")]
    AccountSessionRevoke,
    /// Revoke every session belonging to the current Carbon.
    #[value(name = "account.sessions_revoke_all")]
    AccountSessionsRevokeAll,
    /// Transfer an organization's ownership.
    #[value(name = "organization.transfer_ownership")]
    OrganizationTransferOwnership,
    /// Change organization roles, capabilities, members, or Silicon access.
    #[value(name = "organization.authorization_change")]
    OrganizationAuthorizationChange,
    /// Change organization SSO configuration.
    #[value(name = "organization.sso_change")]
    OrganizationSsoChange,
    /// Create, redirect, delete, or resubscribe a Silicon webhook.
    #[value(name = "organization.silicon_webhook.redirect")]
    OrganizationSiliconWebhookRedirect,
    /// Rotate an Application client secret.
    #[value(name = "application.client_secret.rotate")]
    ApplicationClientSecretRotate,
    /// Rotate an Application webhook signing secret.
    #[value(name = "application.webhook_secret.rotate")]
    ApplicationWebhookSecretRotate,
    /// Approve an Application's pending webhook destination.
    #[value(name = "application.webhook.approve")]
    ApplicationWebhookApprove,
    /// Rotate a Silicon credential.
    #[value(name = "silicon.rotate_token")]
    SiliconRotateToken,
    /// Change an organization's platform SSO entitlement.
    #[value(name = "platform_admin.sso_entitlement")]
    PlatformAdminSsoEntitlement,
    /// Record a platform Application review decision.
    #[value(name = "platform_admin.application_review")]
    PlatformAdminApplicationReview,
}

/// Verified channel used by step-up.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum StepUpChannel {
    /// Send the code to the primary email address.
    #[default]
    Email,
    /// Send the code to the primary phone number.
    Phone,
}

/// Organization commands.
#[derive(Debug, Subcommand)]
pub enum OrgCommand {
    /// List organizations you belong to.
    List {
        /// Only active or removed memberships.
        #[arg(long, value_parser = ["active", "removed"])]
        status: Option<String>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
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
    #[command(group(
        clap::ArgGroup::new("changes")
            .args([
                "name",
                "logo",
                "clear_logo",
                "description",
                "clear_description",
                "join_method"
            ])
            .required(true)
            .multiple(true)
    ))]
    Update {
        /// Handle. Defaults to --org.
        handle: Option<String>,
        /// New display name.
        #[arg(long)]
        name: Option<String>,
        /// New logo URL.
        #[arg(long)]
        logo: Option<String>,
        /// Remove the current logo.
        #[arg(long, conflicts_with = "logo")]
        clear_logo: bool,
        /// New description.
        #[arg(long)]
        description: Option<String>,
        /// Remove the current description.
        #[arg(long, conflicts_with = "description")]
        clear_description: bool,
        /// Join method: `email` or `sso`.
        #[arg(long, value_parser = ["email", "sso"])]
        join_method: Option<String>,
    },
    /// Check whether a handle can be claimed.
    Available {
        /// Handle to check.
        handle: String,
    },
    /// Hand ownership to another member. Needs --step-up: action
    /// `organization.transfer_ownership`, resource = the organization UUID.
    Transfer {
        /// Membership that becomes the owner.
        membership_id: Uuid,
        /// Reserved for handler compatibility; use the global --org option.
        #[arg(skip)]
        org: Option<String>,
    },
}

/// Organization SSO commands.
#[derive(Debug, Subcommand)]
pub enum SsoCommand {
    /// Show the selected organization's SSO configuration. Requires `sso.manage`.
    Show,
    /// Create a five-minute `WorkOS` setup link. Requires entitlement and `sso.manage`.
    SetupLink,
    /// Check the active `WorkOS` connection end to end. Requires `sso.manage`.
    Test,
    /// Disable SSO. Requires `sso.manage` and --step-up: action
    /// `organization.sso_change`, resource = the organization UUID.
    Disable,
}

/// Member commands.
#[derive(Debug, Subcommand)]
pub enum MemberCommand {
    /// List members.
    List {
        /// Only Carbons, or only Silicons.
        #[arg(long, value_parser = ["carbon", "silicon"])]
        principal_type: Option<String>,
        /// Only members carrying this tag UUID from `iam tag list`.
        #[arg(long, value_name = "TAG_ID", value_parser = parse_tag_id)]
        tag: Option<Uuid>,
        /// Only members in this state.
        #[arg(long, value_parser = ["active", "removed"])]
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
    ///
    /// `--first-silicon` applies only to Carbon memberships. Reporting-line
    /// and profile-photo options apply only to Silicon memberships.
    #[command(group(
        clap::ArgGroup::new("changes")
            .args([
                "first_silicon",
                "clear_first_silicon",
                "reports_to",
                "clear_reports_to",
                "profile_photo",
                "clear_profile_photo"
            ])
            .required(true)
            .multiple(true)
    ))]
    Update {
        /// Membership identifier.
        membership_id: Uuid,
        /// Carbon only: assign the Carbon's first Silicon membership.
        #[arg(long)]
        first_silicon: Option<Uuid>,
        /// Carbon only: unassign the Carbon's first Silicon.
        #[arg(long, conflicts_with = "first_silicon")]
        clear_first_silicon: bool,
        /// Silicon only: assign a new reporting line.
        #[arg(long)]
        reports_to: Option<Uuid>,
        /// Silicon only: remove the current reporting line.
        #[arg(long, conflicts_with = "reports_to")]
        clear_reports_to: bool,
        /// Silicon only: set a profile-photo override URL.
        #[arg(long)]
        profile_photo: Option<String>,
        /// Silicon only: remove the profile-photo override.
        #[arg(long, conflicts_with = "profile_photo")]
        clear_profile_photo: bool,
    },
    /// Remove a member. Needs --step-up: action
    /// `organization.authorization_change`, resource = this membership UUID.
    Remove {
        /// Membership identifier.
        membership_id: Uuid,
        /// Membership to inherit anyone reporting to them.
        #[arg(long)]
        reassign_reports_to: Option<Uuid>,
    },
    /// Promote a member to administrator. Needs --step-up: action
    /// `organization.authorization_change`, resource = this membership UUID.
    Promote {
        /// Membership identifier.
        membership_id: Uuid,
    },
    /// Demote an administrator. Needs --step-up: action
    /// `organization.authorization_change`, resource = this membership UUID.
    Demote {
        /// Membership identifier.
        membership_id: Uuid,
    },
    /// Replace an administrator's capabilities. Needs --step-up: action
    /// `organization.authorization_change`, resource = this membership UUID.
    Capabilities {
        /// Membership identifier.
        membership_id: Uuid,
        /// The complete set to grant; anything omitted is revoked.
        #[arg(
            long = "capability",
            value_name = "CAPABILITY",
            value_parser = [
                "organization.update",
                "members.invite",
                "members.update_directory",
                "members.remove",
                "silicons.create",
                "silicons.update_directory",
                "silicons.manage_hierarchy",
                "silicons.remove",
                "silicons.rotate_token",
                "tags.manage",
                "trust.manage",
                "roles.request",
                "roles.approve",
                "admins.create",
                "admins.manage",
                "sso.manage"
            ]
        )]
        capabilities: Vec<String>,
    },
    /// Show the organization directory.
    Directory {
        /// Comma-separated fields: name,id,role,org,tags,trust.
        #[arg(long, value_parser = parse_directory_fields)]
        fields: Option<String>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Show your own directory entry.
    Self_ {
        /// Comma-separated fields: name,id,role,org,tags,trust.
        #[arg(long, value_parser = parse_directory_fields)]
        fields: Option<String>,
    },
    /// Show one member through the sparse organization directory.
    DirectoryMember {
        /// Membership identifier.
        membership_id: Uuid,
        /// Comma-separated fields: name,id,role,org,tags,trust.
        #[arg(long, value_parser = parse_directory_fields)]
        fields: Option<String>,
    },
}

/// Invitation commands.
#[derive(Debug, Subcommand)]
pub enum InviteCommand {
    /// List invitations this organization issued.
    List {
        /// Only invitations in this state.
        #[arg(
            long,
            value_parser = ["pending", "accepted", "revoked", "expired"]
        )]
        status: Option<String>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Invite a Carbon by handle or email.
    #[command(group(
        clap::ArgGroup::new("identity")
            .args(["carbon_id", "email"])
            .required(true)
            .multiple(false)
    ))]
    Create {
        /// Carbon ID to invite.
        #[arg(long)]
        carbon_id: Option<String>,
        /// Email address to invite.
        #[arg(long)]
        email: Option<String>,
        /// Job role granted on acceptance.
        #[arg(long)]
        job_role: String,
        /// Trust boundary the new member starts with.
        #[arg(
            long,
            default_value = "internal",
            value_parser = ["internal", "external"]
        )]
        boundary: String,
        /// Trust level the new member starts with.
        #[arg(
            long,
            default_value = "not_trusted",
            value_parser = ["not_trusted", "needs_approval", "trusted"]
        )]
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
        #[arg(long, value_parser = ["internal", "external"])]
        boundary: String,
        /// `not_trusted`, `needs_approval`, or `trusted`.
        #[arg(
            long,
            value_parser = ["not_trusted", "needs_approval", "trusted"]
        )]
        level: String,
    },
    /// List trust rules.
    List(PageArgs),
    /// Create a trust rule.
    #[command(
        group(
            clap::ArgGroup::new("subject")
                .args(["subject_tag", "subject_membership"])
                .required(true)
                .multiple(false)
        ),
        group(
            clap::ArgGroup::new("target")
                .args(["target_tag", "target_membership"])
                .required(true)
                .multiple(false)
        )
    )]
    Create {
        /// Subject tag UUID from `iam tag list`.
        #[arg(long, value_name = "TAG_ID")]
        subject_tag: Option<Uuid>,
        /// Subject membership UUID from `iam member list`.
        #[arg(long, value_name = "MEMBERSHIP_ID")]
        subject_membership: Option<Uuid>,
        /// Target tag UUID from `iam tag list`.
        #[arg(long, value_name = "TAG_ID")]
        target_tag: Option<Uuid>,
        /// Target active Silicon membership UUID from `iam silicon show`.
        #[arg(long, value_name = "SILICON_MEMBERSHIP_ID")]
        target_membership: Option<Uuid>,
        /// `internal` or `external`.
        #[arg(long, value_parser = ["internal", "external"])]
        boundary: String,
        /// `not_trusted`, `needs_approval`, or `trusted`.
        #[arg(
            long,
            value_parser = ["not_trusted", "needs_approval", "trusted"]
        )]
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
        #[arg(long, value_parser = ["internal", "external"])]
        boundary: String,
        /// `not_trusted`, `needs_approval`, or `trusted`.
        #[arg(
            long,
            value_parser = ["not_trusted", "needs_approval", "trusted"]
        )]
        level: String,
    },
    /// Archive a trust rule.
    Delete {
        /// Rule identifier.
        rule_id: Uuid,
    },
    /// Explain the trust between a subject and a target Silicon.
    Evaluate {
        /// Subject membership UUID from `iam member list`.
        #[arg(long, value_name = "MEMBERSHIP_ID")]
        subject: Uuid,
        /// Target active Silicon membership UUID from `iam silicon show`.
        #[arg(long, value_name = "SILICON_MEMBERSHIP_ID")]
        target: Uuid,
    },
}

/// Governance commands.
#[derive(Debug, Subcommand)]
pub enum ApprovalCommand {
    /// List approval requests.
    List {
        /// Only requests in this state.
        #[arg(
            long,
            value_parser = ["pending", "approved", "rejected", "completed"]
        )]
        status: Option<String>,
        /// Only requests of this kind.
        #[arg(
            long,
            value_parser = [
                "carbon_job_role_change",
                "silicon_job_role_change",
                "carbon_tag_change",
                "silicon_tag_change",
                "silicon_token_rotation"
            ]
        )]
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
    /// Approve or reject a request. A Silicon token rotation needs --step-up:
    /// action `silicon.rotate_token`, resource = the Silicon principal UUID.
    Decide {
        /// Request identifier.
        request_id: Uuid,
        /// `approve` or `reject`.
        #[arg(long, value_parser = ["approve", "reject"])]
        decision: String,
        /// Reason recorded with the decision.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Request a Silicon job-role change. Silicon-only; Carbon callers are forbidden.
    RequestRole {
        /// Membership whose role should change.
        #[arg(long)]
        membership_id: Uuid,
        /// The role being asked for.
        #[arg(long)]
        job_role: String,
    },
    /// Request a Silicon tag change. Silicon-only; Carbon callers are forbidden.
    #[command(group(
        clap::ArgGroup::new("changes")
            .args(["add", "remove"])
            .required(true)
            .multiple(true)
    ))]
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
        /// Only Silicons carrying this tag UUID from `iam tag list`.
        #[arg(long, value_name = "TAG_ID", value_parser = parse_tag_id)]
        tag: Option<Uuid>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Create a Silicon, returning its credential once.
    Create {
        /// Local handle using --org, or canonical `handle:org`. A canonical ID
        /// supplies its organization when none is selected and must match one
        /// that is selected.
        handle: String,
        /// Job role this Silicon holds.
        #[arg(long)]
        job_role: String,
        /// Display name.
        #[arg(long)]
        display_name: Option<String>,
        /// Active Silicon membership this Silicon reports to.
        #[arg(long)]
        reports_to: Option<Uuid>,
        /// Tags to assign at creation.
        #[arg(long = "tag", value_name = "TAG_ID")]
        tags: Vec<Uuid>,
    },
    /// Show one Silicon.
    Show {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
    },
    /// Update a Silicon's directory configuration.
    #[command(group(
        clap::ArgGroup::new("changes")
            .args([
                "display_name",
                "timezone",
                "description",
                "clear_description",
                "profile_photo",
                "clear_profile_photo",
                "reports_to",
                "clear_reports_to"
            ])
            .required(true)
            .multiple(true)
    ))]
    Update {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
        /// New display name.
        #[arg(long)]
        display_name: Option<String>,
        /// New IANA time-zone identifier.
        #[arg(long)]
        timezone: Option<String>,
        /// New description.
        #[arg(long)]
        description: Option<String>,
        /// Remove the current description.
        #[arg(long, conflicts_with = "description")]
        clear_description: bool,
        /// New profile photo URL.
        #[arg(long)]
        profile_photo: Option<String>,
        /// Remove the profile-photo override.
        #[arg(long, conflicts_with = "profile_photo")]
        clear_profile_photo: bool,
        /// New active Silicon membership to report to.
        #[arg(long)]
        reports_to: Option<Uuid>,
        /// Remove the current reporting line.
        #[arg(long, conflicts_with = "reports_to")]
        clear_reports_to: bool,
    },
    /// Remove a Silicon. Needs --step-up: action
    /// `organization.authorization_change`, resource = its membership UUID.
    Remove {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
        /// Active Silicon membership to inherit anyone reporting to it.
        #[arg(long)]
        reassign_reports_to: Option<Uuid>,
    },
    /// Request credential rotation. Needs --step-up: action
    /// `silicon.rotate_token`, resource = the Silicon principal UUID.
    RotateRequest {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
    },
    /// Complete an approved rotation. Needs --step-up: action
    /// `silicon.rotate_token`, resource = the Silicon principal UUID.
    RotateComplete {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
        /// The approved request.
        request_id: Uuid,
    },
    /// Show the webhook endpoint.
    Webhook {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
    },
    /// Configure or replace the webhook endpoint. Needs --step-up: action
    /// `organization.silicon_webhook.redirect`, resource = its membership UUID.
    SetWebhook {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
        /// HTTPS endpoint to deliver to.
        #[arg(long = "webhook-url")]
        webhook_url: String,
    },
    /// Remove the webhook endpoint. Needs --step-up: action
    /// `organization.silicon_webhook.redirect`, resource = its membership UUID.
    DeleteWebhook {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
    },
    /// Show the webhook subscription.
    Subscription {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
    },
    /// Replace the webhook subscription. Needs --step-up: action
    /// `organization.silicon_webhook.redirect`, resource = its membership UUID.
    SetSubscription {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
        /// `all` for every event, or `selected` with --topic.
        #[arg(long, default_value = "all", value_parser = ["all", "selected"])]
        mode: String,
        /// Topics to receive when mode is `selected`.
        #[arg(
            long = "topic",
            value_name = "TOPIC",
            value_parser = [
                "membership_lifecycle",
                "member_updates",
                "trust_updates"
            ],
            required_if_eq("mode", "selected")
        )]
        topics: Vec<String>,
        /// Additional tags whose events should also be delivered.
        #[arg(long = "tag", value_name = "TAG_ID")]
        tags: Vec<Uuid>,
        /// Filter to the Silicon's own event-time tags, with no additional tags.
        #[arg(long, conflicts_with = "tags")]
        own_tags_only: bool,
    },
    /// Remove the webhook subscription. Needs --step-up: action
    /// `organization.silicon_webhook.redirect`, resource = its membership UUID.
    DeleteSubscription {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
    },
    /// List deliveries that exhausted their retries.
    DeadLetters {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Re-queue dead-lettered deliveries.
    Replay {
        /// Local handle, or global `handle:org`; local uses --org.
        silicon_id: String,
        /// Deliveries to replay.
        #[arg(long = "delivery", value_name = "DELIVERY_ID", required = true)]
        deliveries: Vec<Uuid>,
    },
}

/// Application commands.
#[derive(Debug, Subcommand)]
pub enum AppCommand {
    /// List applications across all organizations you can administer.
    ///
    /// This is an intentionally cross-organization view. --org does not
    /// filter it; use --status to filter by Application state.
    List {
        /// Only applications in this state.
        #[arg(
            long,
            value_parser = [
                "under_review",
                "verified",
                "rejected",
                "suspended",
                "deleted"
            ]
        )]
        status: Option<String>,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Register an application, returning its generated client secret once.
    Create {
        /// Local handle using --org, or canonical `org>handle`. A canonical ID
        /// supplies its organization when none is selected and must match one
        /// that is selected.
        app_id: String,
        /// Display name.
        #[arg(long)]
        name: String,
        /// Reserved for handler compatibility; use the global --org option.
        #[arg(skip)]
        org: Option<String>,
        /// HTTPS endpoint the service delivers webhooks to.
        #[arg(long)]
        webhook_url: String,
        /// Caller-chosen secret: 32-512 non-whitespace ASCII characters. IAM never generates it.
        #[arg(long)]
        webhook_secret: String,
        /// Pathless public origin without a trailing slash, credentials,
        /// query, or fragment. HTTP localhost/loopback IP is for a local IAM
        /// runtime; the hosted edge may require a public HTTPS origin.
        #[arg(long)]
        base_url: String,
        /// JSON array of OBO endpoint definitions.
        #[arg(long, value_name = "JSON")]
        obo_endpoints: Option<String>,
    },
    /// Show one application.
    Show {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
    },
    /// Activate a verified application's pending webhook. Requires a direct
    /// Carbon session as owning-org owner/admin or an IAM applications.review
    /// reviewer, and --step-up for action `application.webhook.approve`,
    /// resource = the internal Application UUID. Does not grant scopes.
    ApproveWebhook {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
    },
    /// Update an application.
    #[command(group(
        clap::ArgGroup::new("changes")
            .args([
                "name",
                "clear_name",
                "logo",
                "clear_logo",
                "base_url",
                "obo_endpoints"
            ])
            .required(true)
            .multiple(true)
    ))]
    Update {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// New display name.
        #[arg(long)]
        name: Option<String>,
        /// Remove the current display name.
        #[arg(long, conflicts_with = "name")]
        clear_name: bool,
        /// New logo URL.
        #[arg(long)]
        logo: Option<String>,
        /// Remove the current logo.
        #[arg(long, conflicts_with = "logo")]
        clear_logo: bool,
        /// New pathless public origin without a trailing slash, credentials,
        /// query, or fragment. HTTP localhost/loopback IP is for a local IAM
        /// runtime; the hosted edge may require a public HTTPS origin.
        #[arg(long)]
        base_url: Option<String>,
        /// Complete replacement OBO endpoint array as JSON.
        #[arg(long, value_name = "JSON")]
        obo_endpoints: Option<String>,
    },
    /// Rotate the client secret. Needs --step-up: action
    /// `application.client_secret.rotate`, resource = the Application UUID.
    RotateSecret {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
    },
    /// Rotate the webhook signing secret. Needs --step-up: action
    /// `application.webhook_secret.rotate`, resource = the Application UUID.
    RotateWebhookSecret {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Caller-chosen secret: 32-512 non-whitespace ASCII characters. IAM never generates it.
        #[arg(long)]
        webhook_secret: String,
    },
    /// Discover an application's base URL as another application.
    Discover {
        /// Target local handle or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Requester local handle or canonical `org>handle`; local uses --org.
        #[arg(long = "as-app-id", value_name = "APP_ID")]
        requester_app_id: String,
        /// Requester's application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
    },
    /// Application token exchange, refresh, introspection, and revocation.
    #[command(subcommand)]
    Token(AppTokenCommand),
    /// Same-organization on-behalf-of access.
    #[command(subcommand)]
    Obo(AppOboCommand),
    /// Verify a captured webhook locally, before parsing or acting on it.
    VerifyWebhook {
        /// File containing the exact delivered body bytes; use `-` for stdin.
        #[arg(value_name = "BODY_FILE")]
        body_file: PathBuf,
        /// Value of `X-Silicon-IAM-Event-ID`.
        #[arg(long)]
        event_id: String,
        /// Value of `X-Silicon-IAM-Timestamp`.
        #[arg(long)]
        timestamp: String,
        /// Value of `X-Silicon-IAM-Key-Version`.
        #[arg(long)]
        key_version: String,
        /// Value of `X-Silicon-IAM-Signature`.
        #[arg(long)]
        signature: String,
        /// Signing secret for this key version: 32-512 non-whitespace ASCII characters.
        #[arg(long)]
        webhook_secret: String,
        /// Maximum accepted clock distance in seconds.
        #[arg(long, default_value_t = 300)]
        tolerance_seconds: u64,
    },
    /// Import a production application into the selected testing environment.
    /// Requires --test and a signed-in test Carbon; an existing target
    /// organization must be administered by that Carbon.
    Import {
        /// Canonical production application identifier, such as `google>drive`.
        app_id: String,
    },
    /// Show the webhook endpoint.
    Webhook {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
    },
    /// Propose a webhook endpoint.
    SetWebhook {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// HTTPS endpoint to deliver to.
        #[arg(long = "webhook-url")]
        webhook_url: String,
        /// New 32-512 non-whitespace ASCII secret; required when replacing an
        /// imported test webhook.
        #[arg(long)]
        webhook_secret: Option<String>,
    },
    /// List deliveries that exhausted their retries.
    DeadLetters {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Re-queue dead-lettered deliveries.
    Replay {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Deliveries to replay.
        #[arg(long = "delivery", value_name = "DELIVERY_ID", required = true)]
        deliveries: Vec<Uuid>,
    },
    /// Show logins performed through an application.
    History {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
}

/// Application token commands.
#[derive(Debug, Subcommand)]
pub enum AppTokenCommand {
    /// Fetch current organization authorization, including permitted role/tags.
    ///
    /// Use immediately after login or to rebuild an empty application cache.
    /// Requires an organization-bound Application access token and its own
    /// Application secret. Role requires roles.read; tags require memberships.read.
    /// Undisclosed fields grant no authority. Inactive, mismatched, refresh and
    /// unscoped tokens return no organization snapshot. No webhook or directory
    /// edit is needed. The backend must support authorization snapshots.
    Authorization {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Application access token. Prompted for when omitted.
        #[arg(long)]
        token: Option<String>,
        /// Exact organization handle; a mismatch returns no authority.
        #[arg(long)]
        org_context: Option<String>,
        /// Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
    },
    /// Exchange a single-use short-lived token for an Application session.
    Exchange {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Short-lived token. Prompted for when omitted.
        #[arg(long)]
        slt: Option<String>,
        /// Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
        /// A 16-255 character visible-ASCII key. Reuse it after an uncertain
        /// exchange of the same short-lived token; generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Rotate an Application refresh token and its access token.
    Refresh {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Refresh token. Prompted for when omitted.
        #[arg(long)]
        refresh_token: Option<String>,
        /// Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
        /// A 16-255 character visible-ASCII key. Reuse it after an uncertain
        /// refresh; never retry with a new key. Generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Ask IAM for a token's current, authoritative state.
    Introspect {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Access or refresh token. Prompted for when omitted.
        #[arg(long)]
        token: Option<String>,
        /// Hint which kind of token is being checked.
        #[arg(long, value_enum)]
        token_type: Option<AppTokenType>,
        /// Exact organization handle sent as `X-Org-ID`; a mismatch makes the token inactive.
        #[arg(long)]
        org_context: Option<String>,
        /// Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
    },
    /// Revoke one access token, or the complete family of a refresh token.
    Revoke {
        /// Local handle, or canonical `org>handle`; local uses --org.
        app_id: String,
        /// Access or refresh token. Prompted for when omitted.
        #[arg(long)]
        token: Option<String>,
        /// Hint which kind of token is being revoked.
        #[arg(long, value_enum)]
        token_type: Option<AppTokenType>,
        /// Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
        /// A 16-255 character visible-ASCII key. Reuse it after an uncertain
        /// revocation of the same token; generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

/// Token type hints accepted by Application introspection and revocation.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AppTokenType {
    /// An Application access token.
    AccessToken,
    /// An Application refresh token.
    RefreshToken,
}

/// OBO commands called by Applications as themselves.
#[derive(Debug, Subcommand)]
pub enum AppOboCommand {
    /// Discover an Application's callable OBO endpoint catalog.
    Endpoints {
        /// Audience local handle or canonical `org>handle`; local uses --org.
        audience_app_id: String,
        /// Requester local handle or canonical `org>handle`; local uses --org.
        #[arg(long = "as-app-id", value_name = "APP_ID")]
        requester_app_id: String,
        /// Requester's Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
    },
    /// Bind a single-use proof to one exact downstream request.
    Exchange {
        /// Audience local handle or canonical `org>handle`; local uses --org.
        audience_app_id: String,
        /// Registered endpoint identifier from `app obo endpoints`.
        endpoint_id: String,
        /// Requester local handle or canonical `org>handle`; local uses --org.
        #[arg(long = "as-app-id", value_name = "APP_ID")]
        requester_app_id: String,
        /// Requester's Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
        /// Actor-bound Application access token. Prompted for when omitted.
        #[arg(long)]
        subject_token: Option<String>,
        /// Downstream HTTP method; normalized to uppercase.
        #[arg(long)]
        method: String,
        /// JSON object required by the registered endpoint.
        #[arg(long, default_value = "{}")]
        metadata: String,
        /// A 16-255 character visible-ASCII key. Reuse it with the same request
        /// after an uncertain exchange; the timestamp may refresh. Generated
        /// when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Override the OBO Unix timestamp; normally omit so the client uses now.
        #[arg(long)]
        timestamp: Option<i64>,
        /// Exact downstream body bytes.
        #[command(flatten)]
        body: RequestBodyArgs,
    },
    /// Consume and verify an OBO proof as its audience Application.
    Verify {
        /// Audience local handle or canonical `org>handle`; local uses --org.
        audience_app_id: String,
        /// Audience Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
        /// Single-use OBO proof. Prompted for when omitted.
        #[arg(long)]
        access_proof: Option<String>,
        /// Actual downstream HTTP method; normalized to uppercase.
        #[arg(long)]
        method: String,
        /// Exact registered path of the actual downstream request.
        #[arg(long)]
        path: String,
        /// Exact downstream body bytes.
        #[command(flatten)]
        body: RequestBodyArgs,
    },
}

/// A downstream request body supplied losslessly from a file or conveniently inline.
#[derive(Debug, Args)]
pub struct RequestBodyArgs {
    /// UTF-8 request body given directly; defaults to an empty body.
    #[arg(long, conflicts_with = "body_file")]
    pub body: Option<String>,
    /// File containing exact request bytes; use `-` for stdin.
    #[arg(long, value_name = "PATH", conflicts_with = "body")]
    pub body_file: Option<PathBuf>,
}

/// Testing environment commands.
#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// List environments.
    List {
        /// `active`, `deleted`, or `all`.
        #[arg(long, value_parser = ["active", "deleted", "all"])]
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
    #[command(group(
        clap::ArgGroup::new("changes")
            .args(["name", "description", "clear_description"])
            .required(true)
            .multiple(true)
    ))]
    Update {
        /// Environment identifier.
        environment_id: Uuid,
        /// New name.
        #[arg(long)]
        name: Option<String>,
        /// New description.
        #[arg(long)]
        description: Option<String>,
        /// Remove the current description.
        #[arg(long, conflicts_with = "description")]
        clear_description: bool,
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
    ///
    /// With an ID, run outside --test using the production control plane.
    /// Without an ID, --test is required and authorizes cleaning with the
    /// locally stored environment key.
    Clean {
        /// Environment identifier. Omit to clean the one selected by --test.
        environment_id: Option<Uuid>,
    },
    /// Describe the environment selected by --test. Requires --test.
    Current,
}

/// Session commands.
#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// List active and recently revoked sessions.
    List(PageArgs),
    /// Revoke one of your sessions. Needs --step-up: action
    /// `account.session_revoke`, resource = this session UUID. The target,
    /// and the current session when different, must be at least 12 hours old.
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
        /// One of `url`, `org`, `auto-update`.
        #[arg(value_parser = ["url", "org", "auto-update"])]
        key: String,
        /// The value to store. For auto-update use on/off; URL follows --url's
        /// security rules; org is an organization handle.
        value: String,
    },
    /// Clear a value on the current profile.
    Unset {
        /// `org`, or `auto-update` to restore its default-on policy.
        #[arg(value_parser = ["org", "auto-update"])]
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
    /// Check crates.io now and install the latest CLI release.
    Update,
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
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=100))]
    pub limit: Option<u16>,
}

/// Validate and normalize the directory's comma-separated field selector.
fn parse_carbon_id(value: &str) -> Result<String, String> {
    silicon_iam_client::api::signup::validate_carbon_id(value)
        .map_err(|error| error.to_string())?;
    Ok(value.to_owned())
}

fn parse_directory_fields(value: &str) -> Result<String, String> {
    const ALLOWED: [&str; 6] = ["name", "id", "role", "org", "tags", "trust"];

    let fields = value.split(',').map(str::trim).collect::<Vec<_>>();
    if fields.iter().any(|field| field.is_empty()) {
        return Err(format!(
            "expected a comma-separated field list: {}",
            ALLOWED.join(",")
        ));
    }
    if let Some(invalid) = fields.iter().find(|field| !ALLOWED.contains(field)) {
        return Err(format!(
            "unknown directory field `{invalid}`; expected one of {}",
            ALLOWED.join(",")
        ));
    }
    Ok(fields.join(","))
}

/// Parses a tag filter with a message that points to the command that supplies
/// the UUID. A tag name is deliberately not accepted here.
fn parse_tag_id(value: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|_| "expected a tag UUID from `iam tag list`".to_owned())
}

/// Accepts only the familiar hyphenated UUID form.
///
/// `uuid` deliberately also parses a 32-hex-digit simple UUID. Testing root
/// keys are 32 alphanumeric characters, so accepting that alternate form here
/// would let some secrets be mistaken for public environment ids.
fn parse_testing_environment_id(value: &str) -> Result<Uuid, String> {
    let bytes = value.as_bytes();
    let hyphenated = bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes.get(index) == Some(&b'-'));
    if !hyphenated {
        return Err(
            "expected a hyphenated testing-environment UUID, never its root key".to_owned(),
        );
    }
    Uuid::parse_str(value).map_err(|_| "expected a valid testing-environment UUID".to_owned())
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
        assert_eq!(Cli::command().get_name(), "iam");
    }

    #[test]
    fn updater_controls_are_reachable() {
        use clap::Parser as _;

        assert!(Cli::try_parse_from(["iam", "system", "update"]).is_ok());
        assert!(Cli::try_parse_from(["iam", "config", "set", "auto-update", "off"]).is_ok());
    }

    #[test]
    fn global_flags_are_accepted_after_the_command_too() {
        use clap::Parser as _;

        let parsed = Cli::try_parse_from(["iam", "tag", "list", "--org", "acme"]);
        assert!(parsed.is_ok(), "{parsed:?}");
        let Ok(cli) = parsed else { return };
        assert_eq!(cli.global.org.as_deref(), Some("acme"));
    }

    #[test]
    fn organization_scope_has_one_unambiguous_global_flag() {
        use clap::Parser as _;

        let parsed = Cli::try_parse_from([
            "iam",
            "app",
            "create",
            "billing",
            "--name",
            "Billing",
            "--webhook-url",
            "https://billing.example/hooks",
            "--webhook-secret",
            "caller-chosen-webhook-secret-0001",
            "--base-url",
            "https://billing.example",
            "--org",
            "acme",
        ]);
        assert!(parsed.is_ok(), "the global --org must work: {parsed:?}");
        let Ok(cli) = parsed else { return };
        assert_eq!(cli.global.org.as_deref(), Some("acme"));
        assert!(matches!(
            cli.command,
            super::Command::App(super::AppCommand::Create { org: None, .. })
        ));

        let member_id = "0198aa41-52e7-7f32-8ab3-bd42110a6e2c";
        let parsed = Cli::try_parse_from(["iam", "org", "transfer", member_id, "--org", "acme"]);
        assert!(parsed.is_ok(), "the global --org must work: {parsed:?}");
        let Ok(cli) = parsed else { return };
        assert_eq!(cli.global.org.as_deref(), Some("acme"));
        assert!(matches!(
            cli.command,
            super::Command::Org(super::OrgCommand::Transfer { org: None, .. })
        ));
    }

    #[test]
    fn webhook_urls_cannot_overwrite_the_service_url() {
        use clap::Parser as _;

        let parsed = Cli::try_parse_from([
            "iam",
            "--url",
            "http://127.0.0.1:8080",
            "silicon",
            "set-webhook",
            "builder",
            "--webhook-url",
            "https://hooks.example/events",
        ]);
        assert!(parsed.is_ok(), "{parsed:?}");
        let Ok(cli) = parsed else { return };
        assert_eq!(cli.global.url.as_deref(), Some("http://127.0.0.1:8080"));
        assert!(matches!(
            cli.command,
            super::Command::Silicon(super::SiliconCommand::SetWebhook {
                webhook_url,
                ..
            }) if webhook_url == "https://hooks.example/events"
        ));

        let parsed = Cli::try_parse_from([
            "iam",
            "app",
            "set-webhook",
            "acme>console",
            "--webhook-url",
            "https://hooks.example/app",
        ]);
        assert!(matches!(
            parsed,
            Ok(Cli {
                command: super::Command::App(super::AppCommand::SetWebhook {
                    webhook_url,
                    ..
                }),
                ..
            }) if webhook_url == "https://hooks.example/app"
        ));
    }

    #[test]
    fn login_admits_exactly_one_identity() {
        use clap::Parser as _;

        assert!(Cli::try_parse_from(["iam", "login", "--email", "a@b.test"]).is_ok());
        assert!(Cli::try_parse_from(["iam", "login"]).is_err());
        // Two identities is ambiguous, and the grammar says so rather than
        // silently preferring one.
        assert!(
            Cli::try_parse_from([
                "iam",
                "login",
                "--email",
                "a@b.test",
                "--carbon-id",
                "someone"
            ])
            .is_err()
        );
    }

    #[test]
    fn page_limits_are_bounded_by_the_service_contract() {
        use clap::Parser as _;

        assert!(Cli::try_parse_from(["iam", "org", "list", "--limit", "1"]).is_ok());
        assert!(Cli::try_parse_from(["iam", "org", "list", "--limit", "100"]).is_ok());
        assert!(Cli::try_parse_from(["iam", "org", "list", "--limit", "0"]).is_err());
        assert!(Cli::try_parse_from(["iam", "org", "list", "--limit", "101"]).is_err());
    }

    #[test]
    fn closed_contract_values_are_rejected_before_network_io() {
        use clap::Parser as _;

        let invalid = [
            vec!["iam", "org", "update", "--join-method", "password"],
            vec!["iam", "member", "list", "--principal-type", "robot"],
            vec!["iam", "member", "list", "--status", "pending"],
            vec!["iam", "invite", "list", "--status", "unknown"],
            vec![
                "iam",
                "trust",
                "set-default",
                "--boundary",
                "partner",
                "--level",
                "trusted",
            ],
            vec!["iam", "approval", "list", "--status", "cancelled"],
            vec!["iam", "approval", "list", "--kind", "role_change"],
            vec![
                "iam",
                "approval",
                "decide",
                "0198aa41-52e7-7f32-8ab3-bd42110a6e2c",
                "--decision",
                "abstain",
            ],
            vec!["iam", "app", "list", "--status", "active"],
            vec!["iam", "env", "list", "--status", "retired"],
            vec!["iam", "config", "set", "unknown", "value"],
            vec!["iam", "config", "unset", "url"],
            vec!["iam", "member", "directory", "--fields", "name,password"],
        ];
        for argv in invalid {
            assert!(
                Cli::try_parse_from(argv.clone()).is_err(),
                "unexpectedly accepted {argv:?}"
            );
        }

        assert!(Cli::try_parse_from(["iam", "org", "update", "--join-method", "sso"]).is_ok());
        assert!(
            Cli::try_parse_from(["iam", "member", "list", "--principal-type", "silicon"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["iam", "member", "directory", "--fields", "name, tags"]).is_ok()
        );
        assert!(Cli::try_parse_from(["iam", "app", "list", "--status", "verified"]).is_ok());
    }

    #[test]
    fn silicon_subscriptions_use_closed_modes_and_topics() {
        use clap::Parser as _;

        assert!(
            Cli::try_parse_from([
                "iam",
                "silicon",
                "set-subscription",
                "builder",
                "--mode",
                "all",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "silicon",
                "set-subscription",
                "builder",
                "--mode",
                "selected",
                "--topic",
                "member_updates",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "silicon",
                "set-subscription",
                "builder",
                "--mode",
                "selected",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "silicon",
                "set-subscription",
                "builder",
                "--mode",
                "some",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "silicon",
                "set-subscription",
                "builder",
                "--topic",
                "everything",
            ])
            .is_err()
        );
    }

    #[test]
    fn mutating_commands_reject_missing_payloads() {
        use clap::Parser as _;

        let id = "0198aa41-52e7-7f32-8ab3-bd42110a6e2c";
        let missing = [
            vec!["iam", "org", "update"],
            vec!["iam", "member", "update", id],
            vec!["iam", "invite", "create", "--job-role", "Engineer"],
            vec![
                "iam",
                "trust",
                "create",
                "--boundary",
                "internal",
                "--level",
                "trusted",
            ],
            vec!["iam", "approval", "request-tags", "--membership-id", id],
            vec!["iam", "silicon", "update", "builder"],
            vec!["iam", "app", "update", "billing"],
            vec!["iam", "env", "update", id],
            vec!["iam", "silicon", "replay", "builder"],
            vec!["iam", "app", "replay", "billing"],
        ];
        for argv in missing {
            assert!(
                Cli::try_parse_from(argv.clone()).is_err(),
                "unexpectedly accepted no-op mutation {argv:?}"
            );
        }
    }

    #[test]
    fn mutating_commands_accept_a_real_payload() {
        use clap::Parser as _;

        let id = "0198aa41-52e7-7f32-8ab3-bd42110a6e2c";

        assert!(Cli::try_parse_from(["iam", "org", "update", "--name", "Acme"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "iam",
                "member",
                "update",
                id,
                "--profile-photo",
                "https://example.test/a.png"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "invite",
                "create",
                "--email",
                "person@example.test",
                "--job-role",
                "Engineer",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "trust",
                "create",
                "--subject-membership",
                id,
                "--target-membership",
                id,
                "--boundary",
                "internal",
                "--level",
                "trusted",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "approval",
                "request-tags",
                "--membership-id",
                id,
                "--add",
                id,
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "silicon",
                "update",
                "builder",
                "--display-name",
                "Builder"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["iam", "app", "update", "billing", "--name", "Billing"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["iam", "env", "update", id, "--description", "proof"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["iam", "silicon", "replay", "builder", "--delivery", id]).is_ok()
        );
        assert!(Cli::try_parse_from(["iam", "app", "replay", "billing", "--delivery", id]).is_ok());
    }

    #[test]
    fn privileged_help_names_the_step_up_contract() {
        fn command_at<'a>(root: &'a clap::Command, path: &[&str]) -> &'a clap::Command {
            path.iter().fold(root, |command, name| {
                command
                    .find_subcommand(name)
                    .unwrap_or_else(|| panic!("missing command {}", path.join(" ")))
            })
        }

        let command = Cli::command();
        let contracts = [
            (&["org", "transfer"][..], "organization.transfer_ownership"),
            (
                &["member", "remove"][..],
                "organization.authorization_change",
            ),
            (
                &["member", "promote"][..],
                "organization.authorization_change",
            ),
            (
                &["member", "demote"][..],
                "organization.authorization_change",
            ),
            (
                &["member", "capabilities"][..],
                "organization.authorization_change",
            ),
            (
                &["silicon", "remove"][..],
                "organization.authorization_change",
            ),
            (&["silicon", "rotate-request"][..], "silicon.rotate_token"),
            (&["silicon", "rotate-complete"][..], "silicon.rotate_token"),
            (
                &["silicon", "set-webhook"][..],
                "organization.silicon_webhook.redirect",
            ),
            (
                &["silicon", "delete-webhook"][..],
                "organization.silicon_webhook.redirect",
            ),
            (
                &["silicon", "set-subscription"][..],
                "organization.silicon_webhook.redirect",
            ),
            (
                &["silicon", "delete-subscription"][..],
                "organization.silicon_webhook.redirect",
            ),
            (
                &["app", "rotate-secret"][..],
                "application.client_secret.rotate",
            ),
            (
                &["app", "rotate-webhook-secret"][..],
                "application.webhook_secret.rotate",
            ),
            (&["session", "revoke"][..], "account.session_revoke"),
            (&["approval", "decide"][..], "silicon.rotate_token"),
        ];

        for (path, action) in contracts {
            let subcommand = command_at(&command, path);
            let about = subcommand
                .get_long_about()
                .or_else(|| subcommand.get_about())
                .map(ToString::to_string)
                .unwrap_or_default();
            assert!(
                about.to_ascii_lowercase().contains("needs --step-up"),
                "{} help omits the step-up requirement: {about}",
                path.join(" ")
            );
            assert!(
                about.contains(action) && about.contains("resource"),
                "{} help omits {action} or its resource: {about}",
                path.join(" ")
            );
        }
    }

    #[test]
    fn silicon_only_approval_requests_say_so_in_help() {
        let command = Cli::command();
        let Some(approval) = command.find_subcommand("approval") else {
            panic!("approval exists")
        };
        for name in ["request-role", "request-tags"] {
            let Some(subcommand) = approval.find_subcommand(name) else {
                panic!("approval {name} exists")
            };
            let about = subcommand
                .get_long_about()
                .or_else(|| subcommand.get_about())
                .map(ToString::to_string)
                .unwrap_or_default();
            assert!(
                about.contains("Silicon-only") && about.contains("Carbon callers are forbidden"),
                "approval {name} help must state its caller boundary: {about}"
            );
        }
    }

    #[test]
    fn test_context_accepts_an_environment_id_and_never_a_raw_key() {
        use clap::Parser as _;

        let id = "0198aa41-52e7-7f32-8ab3-bd42110a6e2c";
        let parsed = Cli::try_parse_from(["iam", "--test", id, "whoami"]);
        assert!(parsed.is_ok(), "{parsed:?}");
        let Ok(cli) = parsed else { return };
        assert_eq!(
            cli.global.test.map(|value| value.to_string()).as_deref(),
            Some(id)
        );

        assert!(
            Cli::try_parse_from(["iam", "--test", &"a".repeat(32), "whoami"]).is_err(),
            "a root key must never be accepted where the public test id belongs"
        );
    }

    #[test]
    fn application_creation_requires_every_contract_input() {
        use clap::Parser as _;

        // Missing base URL.
        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "create",
                "billing",
                "--name",
                "Billing",
                "--webhook-url",
                "https://billing.example/hooks",
                "--webhook-secret",
                "caller-chosen-webhook-secret-0001",
            ])
            .is_err()
        );
        // Missing caller-chosen webhook secret.
        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "create",
                "billing",
                "--name",
                "Billing",
                "--webhook-url",
                "https://billing.example/hooks",
                "--base-url",
                "https://billing.example",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "create",
                "billing",
                "--name",
                "Billing",
                "--webhook-url",
                "https://billing.example/hooks",
                "--base-url",
                "https://billing.example",
                "--webhook-secret",
                "caller-chosen-webhook-secret-0001",
            ])
            .is_ok()
        );
    }

    #[test]
    fn application_help_surfaces_required_webhook_secrets() {
        let command = Cli::command();
        let Some(app) = command.find_subcommand("app") else {
            panic!("app must exist");
        };
        for name in ["create", "rotate-webhook-secret", "verify-webhook"] {
            let Some(subcommand) = app.find_subcommand(name) else {
                panic!("app {name} must exist");
            };
            let secret = subcommand
                .get_arguments()
                .find(|argument| argument.get_id() == "webhook_secret");
            assert!(
                secret.is_some_and(clap::Arg::is_required_set),
                "app {name} must require --webhook-secret in its generated usage"
            );
        }
        let Some(create) = app.find_subcommand("create") else {
            return;
        };
        let usage = create.clone().render_usage().to_string();
        assert!(usage.contains("--webhook-secret <WEBHOOK_SECRET>"));
    }

    #[test]
    fn every_user_supplied_argument_has_help() {
        fn walk(command: &clap::Command, path: &str) {
            for argument in command.get_arguments() {
                if matches!(argument.get_id().as_str(), "help" | "version") {
                    continue;
                }
                assert!(
                    argument.get_help().is_some(),
                    "{path} argument {} has no help",
                    argument.get_id()
                );
            }
            for subcommand in command.get_subcommands() {
                let child = format!("{path} {}", subcommand.get_name());
                walk(subcommand, &child);
            }
        }

        walk(&Cli::command(), "iam");
    }

    #[test]
    fn application_token_protocol_is_reachable_without_putting_secrets_in_argv() {
        use clap::Parser as _;

        assert!(Cli::try_parse_from(["iam", "app", "token", "exchange", "acme>checkout"]).is_ok());
        assert!(Cli::try_parse_from(["iam", "app", "token", "refresh", "acme>checkout"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "token",
                "revoke",
                "acme>checkout",
                "--token-type",
                "refresh-token",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "token",
                "introspect",
                "acme>checkout",
                "--token-type",
                "access-token",
            ])
            .is_ok()
        );
    }

    #[test]
    fn application_obo_protocol_has_all_three_steps_and_lossless_body_input() {
        use clap::Parser as _;

        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "obo",
                "endpoints",
                "acme>billing",
                "--as-app-id",
                "acme>checkout",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "obo",
                "exchange",
                "acme>billing",
                "invoices.create",
                "--as-app-id",
                "acme>checkout",
                "--method",
                "post",
                "--body-file",
                "invoice.json",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "obo",
                "verify",
                "acme>billing",
                "--method",
                "POST",
                "--path",
                "/v1/invoices",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "obo",
                "exchange",
                "acme>billing",
                "invoices.create",
                "--as-app-id",
                "acme>checkout",
                "--method",
                "POST",
                "--body",
                "{}",
                "--body-file",
                "invoice.json",
            ])
            .is_err(),
            "inline and file bodies are mutually exclusive"
        );
    }

    #[test]
    fn offline_webhook_verification_requires_every_signed_header() {
        use clap::Parser as _;

        let complete = [
            "iam",
            "app",
            "verify-webhook",
            "delivery.json",
            "--event-id",
            "0198aa41-52e7-7f32-8ab3-bd42110a6e2c",
            "--timestamp",
            "1700000000",
            "--key-version",
            "1",
            "--signature",
            "v1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--webhook-secret",
            "caller-chosen-webhook-secret-0001",
        ];
        assert!(Cli::try_parse_from(complete).is_ok());
        assert!(
            Cli::try_parse_from([
                "iam",
                "app",
                "verify-webhook",
                "delivery.json",
                "--event-id",
                "0198aa41-52e7-7f32-8ab3-bd42110a6e2c",
                "--timestamp",
                "1700000000",
                "--key-version",
                "1",
                "--webhook-secret",
                "caller-chosen-webhook-secret-0001",
            ])
            .is_err()
        );
    }
}
