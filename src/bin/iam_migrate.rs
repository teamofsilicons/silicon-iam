//! Silicon IAM one-shot database migration process.

use silicon_iam::{config::MigrationSettings, infrastructure::postgres, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let settings = MigrationSettings::from_env()?;
    telemetry::init_process(settings.environment, &settings.log_filter)?;

    let pool = postgres::connect(&settings.database, "iam-migrate").await?;
    postgres::migrate(&pool).await?;
    pool.close().await;
    Ok(())
}
