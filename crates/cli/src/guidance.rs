//! Contextual next steps, separate from the service's result payload.
//!
//! Capture only public identifiers before dispatch consumes a command. Emit
//! only after success, and never in JSON mode. Suggested invocations carry the
//! resolved service, profile, environment and organization so a local/testing
//! workflow does not silently become a production one when copied.

use silicon_iam_client::models;

use crate::{
    cli::{
        AppCommand, AppOboCommand, AppTokenCommand, ApprovalCommand, Command, EnvCommand,
        InviteCommand, MemberCommand, OrgCommand, SiliconCommand, TagCommand, TrustCommand,
    },
    context::Context,
    output::Format,
};

/// Advice prepared before an operation and printed only if it succeeds.
#[derive(Default)]
pub struct Plan {
    prefix: Vec<String>,
    organization: Option<String>,
    enabled: bool,
    notes: Vec<&'static str>,
    next: Vec<(&'static str, String)>,
}

impl Plan {
    /// Captures public command arguments, never credentials, for later advice.
    #[must_use]
    pub fn capture(context: &Context, command: &Command) -> Self {
        let mut plan = Self::new(context);
        if !plan.enabled {
            return plan;
        }
        match command {
            Command::Login(args) => {
                if let Some(app_id) = args.app_id.as_deref() {
                    plan.short_lived_token(context, app_id);
                } else {
                    plan.add("Confirm the signed-in identity", &["whoami"]);
                    plan.add("Find your organization handles", &["org", "list"]);
                    plan.docs(
                        "Application login uses an SLT, never your IAM credentials",
                        "applications",
                    );
                }
            }
            Command::SiliconLogin(args) => {
                if let Some(app_id) = args.app_id.as_deref() {
                    plan.short_lived_token(context, app_id);
                } else {
                    if let Some(sid) = args.sid.as_deref()
                        && let Ok((_, org)) = context.silicon_identity(sid)
                    {
                        plan.organization = Some(org);
                    }
                    plan.add("Confirm the signed-in Silicon", &["whoami"]);
                    if plan.organization.is_some() {
                        plan.add("Inspect your organization membership", &["member", "self"]);
                    }
                    plan.docs(
                        "Use the stored Silicon session to mint application SLTs",
                        "applications",
                    );
                }
            }
            Command::Signup(args) => {
                plan.note("Your account is created; signup does not sign this device in.");
                plan.add(
                    "Sign in to the account you just created",
                    &["login", "--carbon-id", &args.carbon_id],
                );
            }
            Command::Org(command) => plan.organization_command(command),
            Command::App(command) => plan.application_command(context, command),
            Command::Env(command) => plan.environment_command(command),
            Command::Member(command) => plan.member_command(command),
            Command::Invite(command) => plan.invitation_command(command),
            Command::Tag(command) => plan.tag_command(command),
            Command::Silicon(command) => plan.silicon_command(context, command),
            Command::Approval(command) => plan.approval_command(command),
            Command::Trust(
                TrustCommand::Create { .. }
                | TrustCommand::Update { .. }
                | TrustCommand::Delete { .. }
                | TrustCommand::SetDefault { .. },
            ) => {
                plan.note("Trust is advisory; it does not replace role, capability or application authorization checks.");
                plan.add("Review the current trust rules", &["trust", "list"]);
                plan.add(
                    "Learn how to evaluate a concrete subject and target",
                    &["trust", "evaluate", "--help"],
                );
            }
            _ => {}
        }
        plan
    }

    fn new(context: &Context) -> Self {
        let custom_home = std::env::var("SILICON_IAM_HOME");
        let production = context.testing_environment_id().is_none();
        let mut prefix = Vec::new();
        if production || custom_home.is_ok() {
            prefix.push("env".to_owned());
        }
        if production {
            // A copied production command must not inherit a later shell's
            // SILICON_IAM_TEST and turn into a different environment's action.
            prefix.extend(["-u".to_owned(), "SILICON_IAM_TEST".to_owned()]);
        }
        if let Ok(home) = &custom_home {
            // The same profile name is not sufficient when credentials and
            // testing keys live in an invocation-specific private directory.
            prefix.push(format!("SILICON_IAM_HOME={home}"));
        }
        prefix.extend([
            "iam".to_owned(),
            "--url".to_owned(),
            context.profile.url.clone(),
            "--profile".to_owned(),
            context.profile_name.clone(),
        ]);
        if let Some(environment_id) = context.testing_environment_id() {
            prefix.extend(["--test".to_owned(), environment_id.to_string()]);
        }
        Self {
            prefix,
            organization: context.organization_if_set().map(str::to_owned),
            enabled: matches!(context.format, Format::Text)
                && !matches!(custom_home, Err(std::env::VarError::NotUnicode(_))),
            ..Self::default()
        }
    }

    fn note(&mut self, note: &'static str) {
        self.notes.push(note);
    }

    fn add(&mut self, description: &'static str, command: &[&str]) {
        let mut words = self.prefix.clone();
        if let Some(organization) = self.organization.as_ref() {
            words.extend(["--org".to_owned(), organization.clone()]);
        } else {
            words.push("--no-org".to_owned());
        }
        words.extend(command.iter().map(|word| (*word).to_owned()));
        // Do not render attacker-controlled terminal control sequences from a
        // profile or identifier, even inside an otherwise shell-safe quote.
        if words.iter().any(|word| word.chars().any(char::is_control)) {
            return;
        }
        self.next.push((
            description,
            words
                .iter()
                .map(|word| shell_word(word))
                .collect::<Vec<_>>()
                .join(" "),
        ));
    }

    fn docs(&mut self, description: &'static str, topic: &'static str) {
        // Embedded documentation is offline and independent of credentials or
        // profile selection, so carrying a service context would add noise.
        self.next.push((description, format!("iam docs {topic}")));
    }

    /// Prints human guidance without changing the result's exit status.
    pub fn emit(self) {
        if !self.enabled || (self.notes.is_empty() && self.next.is_empty()) {
            return;
        }
        println!();
        for note in self.notes {
            println!("{note}");
        }
        if !self.next.is_empty() {
            println!("Next steps (POSIX shell suggestions; nothing has been run):");
            for (description, command) in self.next {
                println!("  {description}:\n    {command}");
            }
        }
    }

    fn short_lived_token(&mut self, context: &Context, app_id: &str) {
        self.note("Give only the short-lived token to the application. It is short-lived and single-use; never send the application your OTP, Silicon credential or IAM session tokens.");
        if let Ok(app_id) = context.application_id(app_id) {
            self.add(
                "If you own this application's backend, inspect the exchange inputs",
                &["app", "token", "exchange", &app_id, "--help"],
            );
        }
        self.docs(
            "Follow the application login and initial authorization flow",
            "applications",
        );
    }

    fn organization_command(&mut self, command: &OrgCommand) {
        match command {
            OrgCommand::Create { handle, .. } => {
                self.organization = Some(handle.clone());
                self.add(
                    "Keep this organization selected for the same profile and environment",
                    &["config", "set", "org", handle],
                );
                self.add(
                    "Invite your first teammate",
                    &["invite", "create", "--help"],
                );
                self.add(
                    "Register an application inside this organization",
                    &["app", "create", "--help"],
                );
            }
            OrgCommand::Show { handle } | OrgCommand::Update { handle, .. } => {
                if let Some(handle) = handle {
                    self.organization = Some(handle.clone());
                }
                self.add(
                    "Inspect members and their membership UUIDs",
                    &["member", "list"],
                );
                self.add(
                    "Inspect the organization directory",
                    &["member", "directory"],
                );
            }
            OrgCommand::List { .. } => {
                self.note("Use an organization handle, not its internal UUID, with --org. Application listing is cross-organization and is not filtered by --org.");
                self.add(
                    "Learn how to select an organization",
                    &["config", "set", "--help"],
                );
            }
            OrgCommand::Transfer { .. } => {
                self.note("Ownership has changed. Your previous owner authority is not retained automatically.");
                self.add("Review current organization ownership", &["org", "show"]);
            }
            OrgCommand::Available { .. } => {}
        }
    }

    fn application_command(&mut self, context: &Context, command: &AppCommand) {
        match command {
            AppCommand::Import { app_id } => {
                if let Some((org, _)) = app_id.split_once('>') {
                    self.organization = Some(org.to_owned());
                }
                self.note("The test client secret is separate from production. Keep it private. The inherited production webhook secret was not revealed; replace the test endpoint and secret before testing deliveries you need to verify locally.");
                self.add(
                    "Review the imported application's status and scopes",
                    &["app", "show", app_id],
                );
                self.add(
                    "Learn how to install your test webhook endpoint and signing secret",
                    &["app", "set-webhook", app_id, "--help"],
                );
                self.add(
                    "Mint an SLT using this testing session",
                    &["login", "--app-id", app_id],
                );
            }
            AppCommand::Show { app_id } | AppCommand::Update { app_id, .. } => {
                let app_id = context
                    .application_id(app_id)
                    .unwrap_or_else(|_| app_id.clone());
                self.add(
                    "Inspect the webhook's active and pending configuration",
                    &["app", "webhook", &app_id],
                );
                self.docs(
                    "Understand application login, scopes and initial authorization",
                    "applications",
                );
            }
            AppCommand::ApproveWebhook { app_id } => {
                self.add(
                    "Review the activated webhook configuration",
                    &["app", "webhook", app_id],
                );
            }
            AppCommand::SetWebhook { app_id, .. }
            | AppCommand::RotateWebhookSecret { app_id, .. }
            | AppCommand::Replay { app_id, .. } => {
                let app_id = context
                    .application_id(app_id)
                    .unwrap_or_else(|_| app_id.clone());
                self.add(
                    "Review the webhook's effective configuration",
                    &["app", "webhook", &app_id],
                );
                self.add(
                    "Inspect deliveries that exhausted retries",
                    &["app", "dead-letters", &app_id],
                );
            }
            AppCommand::RotateSecret { app_id } => {
                self.note("Update your application's private credential store now. The previous application secret no longer works; the webhook signing secret is separate.");
                self.add("Review the application", &["app", "show", app_id]);
            }
            AppCommand::Token(command) => self.application_token_command(context, command),
            AppCommand::Obo(AppOboCommand::Exchange { .. }) => {
                self.note("Send the proof only to its audience with the exact method, path and body it binds. Verification consumes it; do not pre-verify it as a health check.");
                self.docs(
                    "Understand request binding and delegated authorization",
                    "obo",
                );
            }
            AppCommand::Obo(AppOboCommand::Verify { .. }) => {
                self.note("The proof was consumed. Enforce the returned current authorization binding; absent role or tags grant no authority. Identity alone is not permission to perform the downstream operation.");
                self.docs("Apply the delegated authority contract", "obo");
            }
            AppCommand::List { .. } => {
                self.note("This list spans organizations you can administer. Quote canonical app IDs such as 'org>app' so your shell does not interpret > as output redirection.");
                self.add(
                    "Learn the fields needed to inspect one application",
                    &["app", "show", "--help"],
                );
            }
            _ => {}
        }
    }

    fn application_token_command(&mut self, context: &Context, command: &AppTokenCommand) {
        match command {
            AppTokenCommand::Exchange { app_id, .. } | AppTokenCommand::Refresh { app_id, .. } => {
                self.note("Application tokens are not stored as this CLI's IAM management session. Keep tokens on your backend. Before serving organization data, obtain the current authorization snapshot; do not wait for an unrelated webhook.");
                let app_id = context
                    .application_id(app_id)
                    .unwrap_or_else(|_| app_id.clone());
                self.add(
                    "Fetch current authorization (interactive terminals prompt for secrets)",
                    &["app", "token", "authorization", &app_id],
                );
                self.docs(
                    "Handle inactive tokens, missing scopes and authorization epochs",
                    "authorization",
                );
            }
            AppTokenCommand::Authorization { .. } | AppTokenCommand::Introspect { .. } => {
                self.note("Only current, disclosed authorization grants authority. No snapshot means no organization authority; a successful HTTP response alone does not mean a token is active.");
                self.docs(
                    "Interpret authorization snapshots and absent fields",
                    "authorization",
                );
            }
            AppTokenCommand::Revoke { app_id, .. } => {
                self.note("Discard the token submitted for revocation locally. Revoking a refresh token ends its token family; obtain a new SLT when another application session is needed.");
                self.add(
                    "Inspect the application-login command",
                    &["login", "--app-id", app_id, "--help"],
                );
            }
        }
    }

    fn environment_command(&mut self, command: &EnvCommand) {
        match command {
            EnvCommand::Key { environment_id } | EnvCommand::RotateKey { environment_id } => {
                self.note("Use the environment UUID with --test, never the secret root key.");
                self.prefix
                    .extend(["--test".to_owned(), environment_id.to_string()]);
                self.organization = None;
                self.add(
                    "Inspect this testing environment using the stored key",
                    &["env", "current"],
                );
                self.docs(
                    "Understand test-key storage and isolated sessions",
                    "testing",
                );
            }
            EnvCommand::Restore { environment_id } => {
                self.add(
                    "Fetch and store this environment's current key on this device",
                    &["env", "key", &environment_id.to_string()],
                );
                self.docs("Resume using the restored environment", "testing");
            }
            EnvCommand::Clean { .. } => {
                self.note("Cleaned data and previous test identities/sessions cannot be reused. Create and sign in to a fresh test Carbon before importing an application again.");
                self.docs("Rebuild the testing workflow after a clean", "testing");
            }
            EnvCommand::Current => {
                self.add(
                    "Check signup's required fields for a separate test identity",
                    &["signup", "--help"],
                );
                self.add(
                    "Inspect production-application import requirements",
                    &["app", "import", "--help"],
                );
            }
            _ => {}
        }
    }

    fn member_command(&mut self, command: &MemberCommand) {
        let membership = match command {
            MemberCommand::Show { membership_id }
            | MemberCommand::Update { membership_id, .. }
            | MemberCommand::Promote { membership_id }
            | MemberCommand::Demote { membership_id }
            | MemberCommand::Capabilities { membership_id, .. } => Some(membership_id.to_string()),
            _ => None,
        };
        if let Some(membership_id) = membership {
            self.add(
                "Review this membership's current role and capabilities",
                &["member", "authorization", &membership_id],
            );
        } else if matches!(command, MemberCommand::List { .. }) {
            self.note("Member commands take the membership UUID in the membership column, not Carbon IDs, Silicon IDs or principal UUIDs.");
            self.add(
                "Inspect member lookup options",
                &["member", "show", "--help"],
            );
        } else if matches!(command, MemberCommand::Directory { .. }) {
            self.note("The sparse directory's id is a public Carbon or Silicon identifier, not a membership UUID. Mutation and authorization commands need the membership UUID from member list.");
            self.add("Find membership UUIDs", &["member", "list"]);
        } else if matches!(command, MemberCommand::Remove { .. }) {
            self.add(
                "Review the remaining active members",
                &["member", "list", "--status", "active"],
            );
        }
    }

    fn invitation_command(&mut self, command: &InviteCommand) {
        match command {
            InviteCommand::Create { .. } => {
                self.note("The invitation is not an accepted membership yet. The recipient must sign in as the invited Carbon and accept it with the verification code.");
                self.add(
                    "Review pending invitations",
                    &["invite", "list", "--status", "pending"],
                );
                self.add(
                    "Read the recipient's acceptance requirements",
                    &["invite", "accept", "--help"],
                );
            }
            InviteCommand::Accept { .. } => {
                self.add(
                    "Find the organization handle you just joined",
                    &["org", "list"],
                );
                self.add(
                    "Learn how to select that organization",
                    &["config", "set", "--help"],
                );
            }
            InviteCommand::Revoke { .. } => {
                self.add(
                    "Review remaining pending invitations",
                    &["invite", "list", "--status", "pending"],
                );
            }
            _ => {}
        }
    }

    fn tag_command(&mut self, command: &TagCommand) {
        match command {
            TagCommand::Create { .. } | TagCommand::Delete { .. } => {
                self.add("Find current tag UUIDs", &["tag", "list"]);
                self.add(
                    "Review how to replace a member's complete tag set",
                    &["approval", "set-tags", "--help"],
                );
            }
            TagCommand::Show { tag_id } | TagCommand::Rename { tag_id, .. } => {
                self.add(
                    "Inspect memberships carrying this tag",
                    &["tag", "members", &tag_id.to_string()],
                );
            }
            _ => {}
        }
    }

    fn silicon_command(&mut self, context: &Context, command: &SiliconCommand) {
        match command {
            SiliconCommand::Create { handle, .. } => {
                self.note("Store the Silicon credential privately now; it is shown once. Logging in as a Silicon replaces the current profile/environment session, so use a separate profile if you need to retain both identities.");
                if let Ok((silicon_id, organization)) = context.silicon_identity(handle) {
                    self.organization = Some(organization);
                    self.add(
                        "Review the Silicon's principal and membership identifiers",
                        &["silicon", "show", &silicon_id],
                    );
                }
                self.add(
                    "Read Silicon login and profile options before switching identity",
                    &["silicon-login", "--help"],
                );
                self.docs(
                    "Understand separate profiles and credential storage",
                    "storage",
                );
            }
            SiliconCommand::Update { silicon_id, .. }
            | SiliconCommand::RotateComplete { silicon_id, .. } => {
                self.add(
                    "Review the current Silicon",
                    &["silicon", "show", silicon_id],
                );
            }
            SiliconCommand::RotateRequest { .. } => {
                self.add(
                    "Review requests that can be decided",
                    &["approval", "list", "--mine", "--status", "pending"],
                );
                self.add(
                    "Read how to complete an approved rotation",
                    &["silicon", "rotate-complete", "--help"],
                );
            }
            SiliconCommand::SetWebhook { silicon_id, .. }
            | SiliconCommand::SetSubscription { silicon_id, .. } => {
                self.add(
                    "Review the webhook subscription",
                    &["silicon", "subscription", silicon_id],
                );
                self.add(
                    "Inspect failed deliveries",
                    &["silicon", "dead-letters", silicon_id],
                );
            }
            _ => {}
        }
    }

    fn approval_command(&mut self, command: &ApprovalCommand) {
        match command {
            ApprovalCommand::RequestRole { .. } | ApprovalCommand::RequestTags { .. } => {
                self.note("A request is not an applied authorization change. An eligible approver must decide it.");
                self.add(
                    "Review pending requests",
                    &["approval", "list", "--status", "pending"],
                );
            }
            ApprovalCommand::Decide { request_id, .. } => {
                self.add(
                    "Inspect the resulting request state",
                    &["approval", "show", &request_id.to_string()],
                );
            }
            ApprovalCommand::SetRole { membership_id, .. }
            | ApprovalCommand::SetTags { membership_id, .. } => {
                self.note("Authorization changes can invalidate previously issued application tokens and proofs. Obtain a fresh SLT when IAM reports an old token inactive.");
                self.add(
                    "Review the updated member",
                    &["member", "show", &membership_id.to_string()],
                );
                self.docs(
                    "Refresh application authorization after directory changes",
                    "authorization",
                );
            }
            _ => {}
        }
    }
}

/// Uses the actual create response so review status is never guessed.
pub fn application_created(context: &Context, application: &models::Application) {
    let mut plan = Plan::new(context);
    if !plan.enabled {
        return;
    }
    plan.organization = Some(application.org_id.clone());
    match application.status {
        models::ApplicationStatus::Verified => plan.note("This application is verified. Your current IAM session can mint an application-specific SLT; the application backend exchanges it using its own secret."),
        models::ApplicationStatus::UnderReview => plan.note("This application is under review, not ready for application login yet. Check its status below; organization approval requests do not approve application registrations."),
        _ => plan.note("Check the application's returned status and approved scopes before attempting application login."),
    }
    plan.add(
        "Review status, approved scopes and the application UUID",
        &["app", "show", &application.app_id],
    );
    plan.add(
        "Inspect webhook configuration",
        &["app", "webhook", &application.app_id],
    );
    if application.status == models::ApplicationStatus::Verified {
        if context.testing_environment_id().is_none() {
            plan.add(
                "Learn how to approve this application's pending webhook",
                &["app", "approve-webhook", &application.app_id, "--help"],
            );
        }
        plan.add(
            "Mint an SLT from this stored IAM session",
            &["login", "--app-id", &application.app_id],
        );
    }
    plan.docs(
        "Prepare SLT exchange, webhook verification and initial authorization",
        "applications",
    );
    plan.emit();
}

/// Offers a real testing invocation using the UUID returned by creation.
pub fn environment_created(context: &Context, environment_id: uuid::Uuid) {
    let mut plan = Plan::new(context);
    if !plan.enabled {
        return;
    }
    plan.prefix
        .extend(["--test".to_owned(), environment_id.to_string()]);
    plan.organization = None;
    plan.note("The environment key is stored on this device. Testing starts with a separate identity/session; your production account is not automatically signed in inside the environment. Pass the UUID to --test, never the secret key.");
    plan.add(
        "Inspect the environment you just created",
        &["env", "current"],
    );
    plan.add(
        "Create a separate test Carbon using these signup requirements",
        &["signup", "--help"],
    );
    plan.docs(
        "Complete test signup, app import, SLT login and authorization",
        "testing",
    );
    plan.emit();
}

/// Keeps recovery advice in the original service, profile and organization.
pub fn environment_retired(context: &Context, environment_id: uuid::Uuid) {
    let mut plan = Plan::new(context);
    if !plan.enabled {
        return;
    }
    plan.add(
        "Restore this environment before its scheduled purge",
        &["env", "restore", &environment_id.to_string()],
    );
    plan.emit();
}

fn shell_word(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-./:=@".contains(&byte))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
