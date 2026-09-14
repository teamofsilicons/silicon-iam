//! Install the IAM-owned scoped application's private database identity helper.
//! This one-shot operator leaves the shared IAM migration ledger unchanged.

use silicon_iam::{config::MigrationSettings, infrastructure::postgres, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let settings = MigrationSettings::from_env()?;
    let _telemetry = telemetry::init_process(settings.environment, &settings.log_filter)?;
    let pool = postgres::connect(&settings.database, "iam-scoped-auth-init").await?;
    sqlx::raw_sql(include_str!("../../deploy/scoped/application-identity.sql"))
        .execute(&pool)
        .await?;
    pool.close().await;
    Ok(())
}
