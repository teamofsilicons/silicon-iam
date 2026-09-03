//! What the CLI reports, and how it exits.

use silicon_iam_client::Error as ClientError;

/// A failure worth telling the person at the terminal about.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// The service refused or could not be reached.
    #[error(transparent)]
    Client(#[from] ClientError),

    /// Stored settings or credentials could not be used.
    #[error("{0}")]
    Config(String),

    /// The command needs a signed-in session and there is none.
    #[error("not signed in; run `siam login` first")]
    NotSignedIn,

    /// The command needs an organization and none was given or configured.
    #[error("no organization given; pass --org or run `siam config set org <handle>`")]
    NoOrganization,

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
            Self::Client(ClientError::Transport(_)) => 5,
            Self::Client(_) => 4,
            // Everything else is the invocation's own fault: bad arguments,
            // a missing organization, an unreadable store.
            Self::Usage(_) | Self::NoOrganization | Self::Config(_) | Self::Io(_) => 2,
        }
    }

    /// A hint worth printing under the message, when there is an obvious one.
    #[must_use]
    pub fn hint(&self) -> Option<String> {
        let Self::Client(error) = self else {
            return None;
        };
        if let ClientError::RateLimited { retry_after, .. } = error {
            return Some(format!("Retry in {} seconds.", retry_after.as_secs()));
        }
        let api = error.api()?;
        if api.is_unauthenticated() {
            return Some("Run `siam login` to sign in again.".to_owned());
        }
        if api.requires_step_up() {
            return Some(
                "This action needs step-up verification; re-run with --step-up.".to_owned(),
            );
        }
        if api.is_version_conflict() {
            return Some("Someone changed this first. Read it again, then retry.".to_owned());
        }
        if api.is_forbidden() {
            return Some("Your role in this organization does not allow it.".to_owned());
        }
        None
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
                .is_some_and(|hint| hint.contains("siam login"))
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
    }
}
