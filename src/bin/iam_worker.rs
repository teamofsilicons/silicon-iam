//! Silicon IAM asynchronous outbox worker process.

use silicon_iam::{config::WorkerProcessSettings, telemetry, worker};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = WorkerProcessSettings::from_env()?;
    let _telemetry = telemetry::init_process(settings.environment, &settings.log_filter)?;
    worker::run(settings).await
}
