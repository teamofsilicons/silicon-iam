//! Offline discovery and explicitly requested source-repository bug reports.
use crate::{
    error::{CliError, Result},
    output::{Format, json},
};
use silicon_iam_client::support;

pub fn run(format: Format) -> Result<()> {
    let info = serde_json::json!({
        "app_id": null,
        "credential_issuer": true,
        "name": "Silicon IAM",
        "version": env!("CARGO_PKG_VERSION"),
        "api_url": crate::context::DEFAULT_URL,
        "auth_url": "https://auth.iam.teamofsilicons.com",
        "repository": support::REPOSITORY,
        "docs": support::DOCUMENTATION,
        "rust_package": support::PACKAGE,
        "cli_package": "https://crates.io/crates/silicon-iam-cli",
        "login": "IAM issues application SLTs; use iam login or iam silicon-login, then --app-id to authorize an application.",
    });
    if format == Format::Json {
        return json(&info);
    }
    println!(
        "Silicon IAM {} — identity and credential issuer\nRepository: {}\nDocs: {}\nRust package: {}\n\nStart: iam login --help\nApplications: iam docs client/login\nBackground updates: iam daemon --help",
        env!("CARGO_PKG_VERSION"),
        support::REPOSITORY,
        support::DOCUMENTATION,
        support::PACKAGE
    );
    Ok(())
}

pub fn report(format: Format, message: &str, pr: Option<&str>) -> Result<()> {
    let url = support::report(message, pr).map_err(CliError::Usage)?;
    let hint = pr.is_none().then(|| {
        format!(
            "You can also submit a fix at {} and attach its PR with --pr.",
            support::REPOSITORY
        )
    });
    match format {
        Format::Json => json(&serde_json::json!({"submitted": true, "url": url, "hint": hint})),
        Format::Text => {
            println!("Report submitted: {url}");
            if let Some(hint) = hint {
                println!("{hint}");
            }
            Ok(())
        }
    }
}
