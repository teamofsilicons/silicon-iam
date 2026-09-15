//! Compatibility with older updater services. Honeycomb owns CLI installation.
use crate::error::{CliError, Result};

/// Direct callers receive an actionable migration error.
pub fn update_now() -> Result<()> {
    Err(CliError::Usage("IAM CLI updates are managed by Honeycomb. Run `honeycomb update <configured-iam-app-id>`. For a direct bootstrap installation, rebuild the CLI from its pinned source revision.".into()))
}
