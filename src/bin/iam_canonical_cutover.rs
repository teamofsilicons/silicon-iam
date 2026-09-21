//! Offline, retryable preparation and encrypted-payload conversion for 0111.
use clap::{Parser, ValueEnum};
use silicon_iam::{
    config::Settings,
    infrastructure::{canonical_replay::cutover, postgres},
};
#[derive(Clone, Copy, ValueEnum)]
enum Phase {
    Prepare,
    Convert,
}
#[derive(Parser)]
#[command(
    about = "Preserve replay history across the canonical identity cutover. Stop APIs and workers before both phases; use operator IAM_DATABASE_URL and unchanged keyrings."
)]
struct Arguments {
    #[arg(value_enum)]
    phase: Phase,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = Arguments::parse();
    let settings = Settings::from_env()?;
    let pool = postgres::connect(&settings.database, "iam-canonical-cutover").await?;
    match arguments.phase {
        Phase::Prepare => cutover::prepare(&pool).await?,
        Phase::Convert => cutover::convert(&pool, &settings.security.encryption_keys).await?,
    }
    pool.close().await;
    Ok(())
}
