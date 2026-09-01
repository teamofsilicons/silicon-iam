//! One-shot bootstrap for the first Silicon IAM platform administrator.

use clap::Parser;
use silicon_iam::{
    config::MigrationSettings, domain::auth::CarbonId, infrastructure::postgres, telemetry,
};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "iam-bootstrap-admin",
    about = "Grant the first platform-administrator role to an existing active Carbon"
)]
struct Arguments {
    /// Existing Carbon handle that will receive the first administrator grant.
    #[arg(long)]
    carbon_id: CarbonId,
}

#[derive(Debug, sqlx::FromRow)]
struct CarbonRow {
    id: Uuid,
    carbon_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let arguments = Arguments::parse();
    let settings = MigrationSettings::from_env()?;
    telemetry::init_process(settings.environment, &settings.log_filter)?;

    let pool = postgres::connect(&settings.database, "iam-bootstrap-admin").await?;
    if !postgres::ready(&pool).await {
        anyhow::bail!("database migrations are not current");
    }

    let carbon = bootstrap(&pool, &arguments.carbon_id).await?;
    tracing::info!(
        carbon_id = %carbon.carbon_id,
        principal_id = %carbon.id,
        "first platform administrator bootstrapped"
    );
    pool.close().await;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the one-shot grant, audit, and outbox writes must remain visibly atomic"
)]
async fn bootstrap(pool: &PgPool, carbon_id: &CarbonId) -> anyhow::Result<CarbonRow> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "SELECT pg_catalog.pg_advisory_xact_lock(\
            pg_catalog.hashtextextended('silicon-iam:platform-admin-bootstrap', 0)\
        )",
    )
    .execute(&mut *transaction)
    .await?;

    let administrator_history_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (\
            SELECT 1 FROM iam.platform_role_grants \
            WHERE role = 'platform_administrator'\
        )",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if administrator_history_exists {
        anyhow::bail!("platform-administrator bootstrap has already been consumed");
    }

    let carbon = sqlx::query_as::<_, CarbonRow>(
        r"
        SELECT carbon.id, carbon.carbon_id
        FROM iam.carbons AS carbon
        JOIN iam.principals AS principal
          ON principal.id = carbon.id
         AND principal.kind = 'carbon'
         AND principal.status = 'active'
        WHERE carbon.carbon_id = $1
          AND carbon.deleted_at IS NULL
        FOR UPDATE OF carbon, principal
        ",
    )
    .bind(carbon_id.as_str())
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("the requested active Carbon does not exist"))?;

    let grant_id = Uuid::now_v7();
    let request_id = Uuid::now_v7();
    sqlx::query(
        r"
        INSERT INTO iam.platform_role_grants (
            id,
            carbon_id,
            role,
            grant_source,
            reason
        ) VALUES (
            $1,
            $2,
            'platform_administrator',
            'bootstrap',
            'one-time operator bootstrap'
        )
        ",
    )
    .bind(grant_id)
    .bind(carbon.id)
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        r"
        INSERT INTO iam.audit_events (
            id,
            request_id,
            action,
            target_type,
            target_id,
            authentication_method,
            aggregate_type,
            aggregate_id,
            aggregate_version,
            after_state,
            metadata
        ) VALUES (
            $1,
            $2,
            'platform.administrator.bootstrap',
            'platform_administrator',
            $3,
            'operator_migrator_credential',
            'platform_role_grant',
            $4,
            1,
            pg_catalog.jsonb_build_object('status', 'active'),
            pg_catalog.jsonb_build_object('source', 'one_time_operator_command')
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(request_id)
    .bind(carbon.id)
    .bind(grant_id)
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        r"
        INSERT INTO iam.outbox_events (
            id,
            aggregate_type,
            aggregate_id,
            aggregate_version,
            event_ordinal,
            event_type,
            schema_version,
            payload
        ) VALUES (
            $1,
            'platform_role_grant',
            $2,
            1,
            1,
            'platform_administrator.granted.v1',
            1,
            pg_catalog.jsonb_build_object(
                'platform_principal_id', $3::uuid,
                'role', 'platform_administrator'
            )
        )
        ",
    )
    .bind(Uuid::now_v7())
    .bind(grant_id)
    .bind(carbon.id)
    .execute(&mut *transaction)
    .await?;

    transaction.commit().await?;
    Ok(carbon)
}
