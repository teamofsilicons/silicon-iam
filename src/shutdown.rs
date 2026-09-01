//! Cross-platform process shutdown coordination.

/// Waits for `SIGINT` or `SIGTERM` and then resolves.
///
/// On platforms without Unix signals, only `SIGINT` is observed.
///
/// # Errors
///
/// Returns an error if an operating-system signal handler cannot be installed.
pub async fn signal() -> Result<(), std::io::Error> {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    let mut terminate_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    #[cfg(unix)]
    let terminate = async move {
        terminate_signal.recv().await;
        Ok(())
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<Result<(), std::io::Error>>();

    let result = tokio::select! {
        result = ctrl_c => result,
        result = terminate => result,
    };
    result?;
    tracing::info!("shutdown signal received");
    Ok(())
}
