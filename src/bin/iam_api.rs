//! Silicon IAM HTTP API process.

use silicon_iam::{api, config::Settings, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let settings = Settings::from_env()?;
    telemetry::init(&settings)?;
    api::serve(settings).await
}
