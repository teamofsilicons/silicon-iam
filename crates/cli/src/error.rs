//! What the CLI reports, and how it exits.

use silicon_iam_client::Error as ClientError;

/// A failure worth telling the person at the terminal about.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// The service refused or could not be reached.
    #[error(transparent)]
    Client(#[from] ClientError),

    /// Checking or installing a crates.io release failed.
    #[error(transparent)]
    Update(#[from] silicon_iam_client::update::UpdateError),

    /// A captured webhook failed local cryptographic or envelope validation.
    #[error("webhook verification failed: {0}")]
    Webhook(#[from] silicon_iam_client::WebhookError),

    /// Stored settings or credentials could not be used.
    #[error("{0}")]
    Config(String),

    /// The command needs a signed-in session and there is none.
    #[error("not signed in; run `iam login` first")]
    NotSignedIn,

    /// The command needs an organization and none was given or configured.
    #[error("no organization given; pass --org or run `iam config set org <handle>`")]
    NoOrganization,

    /// A command exists only inside a testing environment.
    #[error(
        "this action is only possible in a testing environment; rerun with `--test <environment-id>`"
    )]
    TestEnvironmentRequired,

    /// A public testing-environment id has no locally stored root key.
    #[error("testing environment {0} is not registered on this profile")]
    UnknownTestingEnvironment(uuid::Uuid),

    /// A stored environment key reached IAM but no longer opens that plane.
    #[error("testing environment {environment_id} rejected its stored key: {source}")]
    TestingEnvironmentUnavailable {
        /// Public environment identifier selected by `--test`.
        environment_id: uuid::Uuid,
        /// The service response, retained for its correlation identifier.
        #[source]
        source: ClientError,
    },

    /// The arguments were valid to clap but wrong in combination.
    #[error("{0}")]
    Usage(String),

    /// Reading from or writing to the terminal failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Result alias used throughout the CLI.
pub type Result<T> = std::result::Result<T, CliError>;

impl CliError {
    /// The process exit code for this failure.
    ///
    /// Distinguished so a script can react without parsing messages: `2` is a
    /// usage mistake, `3` means authenticate, `4` means the service said no,
    /// `5` means it could not be reached at all.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NotSignedIn => 3,
            Self::Client(ClientError::Transport(_)) | Self::Update(_) => 5,
            // Everything else is the invocation's own fault: bad arguments,
            // a missing organization, an unreadable store.
            Self::Client(ClientError::Invalid(_))
            | Self::Usage(_)
            | Self::NoOrganization
            | Self::TestEnvironmentRequired
            | Self::UnknownTestingEnvironment(_)
            | Self::Config(_)
            | Self::Io(_) => 2,
            Self::Client(_) | Self::Webhook(_) | Self::TestingEnvironmentUnavailable { .. } => 4,
        }
    }

    /// A hint worth printing under the message, when there is an obvious one.
    #[allow(
        clippy::too_many_lines,
        reason = "keeping the stable API error-to-hint catalogue together makes omissions auditable"
    )]
    #[must_use]
    pub fn hint(&self) -> Option<String> {
        if let Self::UnknownTestingEnvironment(id) = self {
            return Some(format!(
                "Run `iam env key {id}` outside a test environment to authorize this device."
            ));
        }
        if let Self::TestingEnvironmentUnavailable { environment_id, .. } = self {
            return Some(format!(
                "Outside --test, run `iam env restore {environment_id}` if it was deleted, or `iam env key {environment_id}` to refresh this profile's stored key."
            ));
        }
        let Self::Client(error) = self else {
            return None;
        };
        if let ClientError::RateLimited { retry_after, .. } = error {
            return Some(format!("Retry in {} seconds.", retry_after.as_secs()));
        }
        let api = error.api()?;
        if api.code == "invalid_client" {
            return Some(
                "Check the Application ID and secret; Application authentication does not use `iam login`."
                    .to_owned(),
            );
        }
        if api.is_unauthenticated() {
            return Some("Run `iam login` to sign in again.".to_owned());
        }
        if api.requires_step_up() {
            return Some(
                "This action needs step-up verification; re-run with --step-up.".to_owned(),
            );
        }
        if api.is_version_conflict() {
            return Some("Someone changed this first. Read it again, then retry.".to_owned());
        }
        if api.is_idempotency_conflict() {
            return Some(
                "An idempotency key can only replay its original request. Restore the exact original input, or use a new key for a genuinely new operation."
                    .to_owned(),
            );
        }
        if matches!(
            api.code.as_str(),
            "session_revocation_target_too_young"
                | "session_revocation_authority_too_young"
                | "session_revoke_all_target_too_young"
        ) {
            return Some(
                "For takeover resistance, the session doing the revocation and every session it targets must be at least 12 hours old."
                    .to_owned(),
            );
        }
        match api.code.as_str() {
            "obo_organization_required" => {
                return Some(
                    "Mint an organization-bound subject token with `iam --org <handle> login --app-id <requester-app>`, then exchange that SLT."
                        .to_owned(),
                );
            }
            "obo_organization_mismatch" => {
                return Some(
                    "The subject token must be bound to the requesting Application's organization."
                        .to_owned(),
                );
            }
            "obo_subject_token_forbidden" => {
                return Some(
                    "Use an active Application access token issued to --as-app-id with the obo.issue scope."
                        .to_owned(),
                );
            }
            "obo_request_binding_mismatch" => {
                return Some(
                    "The method, registered path, and body bytes must exactly match the request bound into this proof."
                        .to_owned(),
                );
            }
            "obo_proof_consumed" => {
                return Some(
                    "OBO proofs are single-use. Issue a new proof for the next downstream request."
                        .to_owned(),
                );
            }
            "obo_proof_expired" => {
                return Some(
                    "This OBO proof exceeded its 60-second lifetime. Issue a fresh proof immediately before the downstream request."
                        .to_owned(),
                );
            }
            "obo_proof_revoked" | "obo_authority_revoked" => {
                return Some(
                    "Authority changed after this proof was issued. Re-check access and issue a new proof."
                        .to_owned(),
                );
            }
            "idempotency_response_expired" => {
                return Some(
                    "The original response can no longer be replayed. Issue a new request with a new idempotency key."
                        .to_owned(),
                );
            }
            "approval_request_exists" => {
                return Some(
                    "A matching governance request is already pending. List pending requests instead of submitting another."
                        .to_owned(),
                );
            }
            "approval_request_closed" | "approval_already_decided" => {
                return Some(
                    "This approval is already closed. Read its current state instead of deciding it again."
                        .to_owned(),
                );
            }
            "job_role_changed_since_request" => {
                return Some(
                    "The target's job role changed after this request was opened. Close the stale request and submit a new one."
                        .to_owned(),
                );
            }
            "testing_application_already_exists" => {
                return Some(
                    "That Application is already imported in this testing environment. Use `iam app show`, or clean the environment before importing it again."
                        .to_owned(),
                );
            }
            "sso_not_active" => {
                return Some(
                    "SSO has no active provider connection. Finish provider setup before testing or using SSO."
                        .to_owned(),
                );
            }
            "sso_entitlement_required" => {
                return Some(
                    "This organization does not have the SSO entitlement. Enable it before requesting a setup link."
                        .to_owned(),
                );
            }
            "sso_join_method_active" => {
                return Some(
                    "This organization currently requires SSO joins. Change that policy before disabling SSO."
                        .to_owned(),
                );
            }
            "testing_environment_required" => {
                return Some(
                    "Select the isolated plane with `--test <environment-id>` and use that environment's stored key."
                        .to_owned(),
                );
            }
            "testing_environment_deleted" => {
                return Some(
                    "Run `iam env restore <environment-id>` from the production control plane before using it again."
                        .to_owned(),
                );
            }
            "testing_environment_not_deleted" => {
                return Some(
                    "This environment is already active; it does not need restoring.".to_owned(),
                );
            }
            "testing_environment_not_recoverable" => {
                return Some(
                    "The recovery window has closed. Create a new testing environment instead."
                        .to_owned(),
                );
            }
            "testing_environment_limit_reached" => {
                return Some(
                    "Retire an unused active testing environment before creating another."
                        .to_owned(),
                );
            }
            "testing_environment_unchanged" => {
                return Some(
                    "Supply a name or description that actually changes the environment."
                        .to_owned(),
                );
            }
            "reassign_reports_to_required" => {
                return Some(
                    "This member has direct reports. Pass --reassign-reports-to with an active Silicon membership UUID."
                        .to_owned(),
                );
            }
            "owner_cannot_be_removed" => {
                return Some(
                    "Transfer organization ownership before removing this membership.".to_owned(),
                );
            }
            "invalid_reporting_hierarchy" => {
                return Some(
                    "Choose an active Silicon membership that does not create a reporting cycle."
                        .to_owned(),
                );
            }
            "trust_selector_inactive" => {
                return Some(
                    "Both selectors must be active memberships in the selected organization, and the target must be a Silicon membership."
                        .to_owned(),
                );
            }
            "dead_letter_not_replayable" => {
                return Some(
                    "Only deliveries that are still in the dead-letter state can be replayed. Refresh the list first."
                        .to_owned(),
                );
            }
            "application_webhook_not_configured" => {
                return Some(
                    "Configure the Application webhook before performing this operation."
                        .to_owned(),
                );
            }
            "application_webhook_not_active" => {
                return Some(
                    "The webhook destination is not active yet. Check its pending review state with `iam app webhook`."
                        .to_owned(),
                );
            }
            "application_unchanged" | "application_webhook_unchanged" => {
                return Some("Supply a value that actually changes the Application.".to_owned());
            }
            "job_role_unchanged" => {
                return Some(
                    "Supply a job role different from the member's current role.".to_owned(),
                );
            }
            _ => {}
        }
        if api.is_forbidden() {
            return Some("Your role in this organization does not allow it.".to_owned());
        }
        if api.is_not_found() {
            return Some(
                "Check the identifier and the active --org/--test scope; testing environments have their own organizations."
                    .to_owned(),
            );
        }
        None
    }

    /// Correlation identifier retained from a service response, if any.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Client(error) => error.request_id(),
            Self::TestingEnvironmentUnavailable { source, .. } => source.request_id(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use silicon_iam_client::{ApiError, Error as ClientError};

    use super::CliError;

    fn api(status: u16, code: &str) -> ClientError {
        ClientError::Api(Box::new(ApiError {
            status,
            code: code.to_owned(),
            message: "no".to_owned(),
            details: None,
            request_id: None,
        }))
    }

    #[test]
    fn exit_codes_separate_the_cases_a_script_reacts_to() {
        assert_eq!(CliError::NotSignedIn.exit_code(), 3);
        assert_eq!(CliError::Usage("bad".to_owned()).exit_code(), 2);
        assert_eq!(CliError::Client(api(403, "forbidden")).exit_code(), 4);
    }

    #[test]
    fn hints_name_the_next_step_where_there_is_one() {
        assert!(
            CliError::Client(api(401, "unauthenticated"))
                .hint()
                .is_some_and(|hint| hint.contains("iam login"))
        );
        assert!(
            CliError::Client(api(428, "step_up_required"))
                .hint()
                .is_some_and(|hint| hint.contains("--step-up"))
        );
        assert!(
            CliError::Client(ClientError::RateLimited {
                retry_after: Duration::from_secs(12),
                limit: None,
                remaining: None,
                source: Box::new(ApiError {
                    status: 429,
                    code: "rate_limited".to_owned(),
                    message: "slow down".to_owned(),
                    details: None,
                    request_id: None,
                }),
            })
            .hint()
            .is_some_and(|hint| hint.contains("12 seconds"))
        );
        assert!(CliError::Client(api(409, "conflict")).hint().is_none());
        assert!(
            CliError::Client(api(404, "not_found"))
                .hint()
                .is_some_and(|hint| hint.contains("--org/--test"))
        );
    }
}
