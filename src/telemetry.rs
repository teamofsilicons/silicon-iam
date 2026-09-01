//! Structured process telemetry without secret-bearing payloads.

use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::config::{RuntimeEnvironment, Settings};

/// Installs the global tracing subscriber.
///
/// # Errors
///
/// Returns an error when the filter is invalid or a global subscriber has
/// already been installed.
pub fn init(settings: &Settings) -> anyhow::Result<()> {
    init_process(settings.environment, &settings.log_filter)
}

/// Installs telemetry for a process that intentionally has minimal settings.
///
/// # Errors
///
/// Returns an error when the filter is invalid or a global subscriber has
/// already been installed.
pub fn init_process(environment: RuntimeEnvironment, log_filter: &str) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(log_filter)?;
    let registry = tracing_subscriber::registry().with(filter);

    match environment {
        RuntimeEnvironment::Development | RuntimeEnvironment::Test => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .with_target(true)
                    .with_thread_ids(false),
            )
            .try_init()?,
        RuntimeEnvironment::Production => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true)
                    .with_span_list(false),
            )
            .try_init()?,
    }

    Ok(())
}
