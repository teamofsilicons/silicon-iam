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
    /// Service base URL.
    #[arg(long, global = true, env = "SILICON_IAM_URL")]
    pub url: Option<String>,

    /// Stored profile to use.
    #[arg(long, global = true, env = "SILICON_IAM_PROFILE")]
    pub profile: Option<String>,

    /// Organization handle to act on.
    #[arg(long, global = true, env = "SILICON_IAM_ORG")]
    pub org: Option<String>,

    /// Run inside a testing environment, by its UUID.
    #[arg(
        long,
        global = true,
        env = "SILICON_IAM_TEST",
        value_name = "ENVIRONMENT_ID",
        value_parser = parse_testing_environment_id
    )]
    pub test: Option<Uuid>,

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
    /// Register an application, returning its generated client secret once.
    Create {
        /// Local Application handle to claim; IAM prefixes the organization.
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
        /// Caller-chosen webhook signing secret.
        #[arg(long)]
        webhook_secret: String,
        /// Pathless public origin, without a trailing slash, that other applications discover.
        #[arg(long)]
        base_url: String,
        /// JSON array of OBO endpoint definitions.
        #[arg(long, value_name = "JSON")]
        obo_endpoints: Option<String>,
    },
    /// Show one application.
    Show {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
    },
    /// Update an application.
    Update {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
        /// New display name.
        #[arg(long)]
        name: Option<String>,
        /// New pathless public origin, without a trailing slash.
        #[arg(long)]
        base_url: Option<String>,
        /// Complete replacement OBO endpoint array as JSON.
        #[arg(long, value_name = "JSON")]
        obo_endpoints: Option<String>,
    },
    /// Rotate the client secret. Needs --step-up.
    RotateSecret {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
    },
    /// Rotate the webhook signing secret. Needs --step-up.
    RotateWebhookSecret {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
        /// Caller-chosen successor webhook signing secret.
        #[arg(long)]
        webhook_secret: String,
    },
    /// Discover an application's base URL as another application.
    Discover {
        /// Canonical Application whose base URL to discover.
        app_id: String,
        /// Canonical Application making the request.
        #[arg(long = "as-app-id", value_name = "APP_ID")]
        requester_app_id: String,
        /// Requester's application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
    },
    /// Application token exchange, refresh, and introspection.
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
        /// Signing secret for this key version.
        #[arg(long)]
        webhook_secret: String,
        /// Maximum accepted clock distance in seconds.
        #[arg(long, default_value_t = 300)]
        tolerance_seconds: u64,
    },
    /// Import a production application into the selected testing environment.
    Import {
        /// Canonical production application identifier, such as `google>drive`.
        app_id: String,
    },
    /// Show the webhook endpoint.
    Webhook {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
    },
    /// Propose a webhook endpoint.
    SetWebhook {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
        /// HTTPS endpoint to deliver to.
        #[arg(long)]
        url: String,
        /// New signing secret; required when replacing an imported test webhook.
        #[arg(long)]
        webhook_secret: Option<String>,
    },
    /// List deliveries that exhausted their retries.
    DeadLetters {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
    /// Re-queue dead-lettered deliveries.
    Replay {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
        /// Deliveries to replay.
        #[arg(long = "delivery", value_name = "DELIVERY_ID")]
        deliveries: Vec<Uuid>,
    },
    /// Show logins performed through an application.
    History {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
        /// Paging.
        #[command(flatten)]
        page: PageArgs,
    },
}

/// Application token commands.
#[derive(Debug, Subcommand)]
pub enum AppTokenCommand {
    /// Exchange a single-use short-lived token for an Application session.
    Exchange {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
        /// Short-lived token. Prompted for when omitted.
        #[arg(long)]
        slt: Option<String>,
        /// Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
        /// Reuse this after an uncertain exchange of the same short-lived token.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Rotate an Application refresh token and its access token.
    Refresh {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
        /// Refresh token. Prompted for when omitted.
        #[arg(long)]
        refresh_token: Option<String>,
        /// Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
        /// Reuse this after an uncertain refresh; never retry with a new key.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Ask IAM for a token's current, authoritative state.
    Introspect {
        /// Canonical Application identifier (`org>handle`).
        app_id: String,
        /// Access or refresh token. Prompted for when omitted.
        #[arg(long)]
        token: Option<String>,
        /// Hint which kind of token is being checked.
        #[arg(long, value_enum)]
        token_type: Option<AppTokenType>,
        /// Optional organization context sent as `X-Org-ID`.
        #[arg(long)]
        org_context: Option<String>,
        /// Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
    },
}

/// Token type hints accepted by Application introspection.
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
        /// Canonical audience Application identifier (`org>handle`).
        audience_app_id: String,
        /// Canonical Application making the request.
        #[arg(long = "as-app-id", value_name = "APP_ID")]
        requester_app_id: String,
        /// Requester's Application secret. Prompted for when omitted.
        #[arg(long)]
        app_secret: Option<String>,
    },
    /// Bind a single-use proof to one exact downstream request.
    Exchange {
        /// Canonical audience Application identifier (`org>handle`).
        audience_app_id: String,
        /// Registered endpoint identifier from `app obo endpoints`.
        endpoint_id: String,
        /// Canonical Application making the request.
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
        /// Reuse this with the same timestamp and request after an uncertain exchange.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Unix timestamp used in the OBO signature. Defaults to now.
        #[arg(long)]
        timestamp: Option<i64>,
        /// Exact downstream body bytes.
        #[command(flatten)]
        body: RequestBodyArgs,
    },
    /// Consume and verify an OBO proof as its audience Application.
    Verify {
        /// Canonical audience Application identifier (`org>handle`).
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
        /// Environment identifier. Omit to clean the one selected by --test.
        environment_id: Option<Uuid>,
    },
    /// Describe the environment selected by --test.
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
        /// One of `url`, `org`, `auto-update`.
        key: String,
        /// The value to store.
        value: String,
    },
    /// Clear a value on the current profile.
    Unset {
        /// `org`, or `auto-update` to restore its default-on policy.
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
    #[arg(long)]
    pub limit: Option<u16>,
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
    fn login_admits_exactly_one_identity() {
        use clap::Parser as _;

        assert!(Cli::try_parse_from(["iam", "login", "--email", "a@b.test"]).is_ok());
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
