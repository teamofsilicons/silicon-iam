//! Provision initial IAM and Honeycomb authentication without a catalog.
use clap::Parser;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use silicon_iam::domain::id::Id;
use silicon_iam::{
    config::Settings,
    infrastructure::{
        crypto::{CryptoService, DigestPurpose, SecretKind},
        postgres,
    },
};
use std::{collections::BTreeMap, io::Write as _, path::PathBuf};

#[derive(Parser)]
#[command(
    about = "Create or reuse IAM and Honeycomb app identities using operator database authority"
)]
struct Arguments {
    /// Existing owning organization handle.
    #[arg(long)]
    org_id: String,
    /// Active Carbon owner of the selected organization.
    #[arg(long)]
    carbon_id: String,
    /// Canonical org>app identity to create or reuse for IAM.
    #[arg(long)]
    iam_app_id: String,
    /// Distinct canonical org>app identity for Honeycomb.
    #[arg(long)]
    honeycomb_app_id: String,
    /// Protected file retained across bootstrap retries; never print or publish it.
    #[arg(long)]
    output: PathBuf,
}
#[derive(Serialize, Deserialize)]
struct Bootstrap {
    org_id: String,
    carbon_id: String,
    iam_app_id: String,
    honeycomb_app_id: String,
    service_credential: String,
    notification_signing_key: String,
    apps: BTreeMap<String, Option<String>>,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    bootstrap(Arguments::parse(), Settings::from_env()?).await
}
#[allow(
    clippy::too_many_lines,
    reason = "atomic operator bootstrap and durable private output file"
)]
async fn bootstrap(input: Arguments, settings: Settings) -> anyhow::Result<()> {
    anyhow::ensure!(
        input.iam_app_id != input.honeycomb_app_id,
        "IAM and Honeycomb need distinct app identities"
    );
    for id in [&input.iam_app_id, &input.honeycomb_app_id] {
        anyhow::ensure!(
            id.split_once('>')
                .is_some_and(|(org, app)| org == input.org_id
                    && !app.is_empty()
                    && app.bytes().all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-'))),
            "app IDs must use the selected organization and canonical lowercase handles"
        );
    }
    let crypto = CryptoService::from_settings(&settings.security)?;
    let pool = postgres::connect(&settings.database, "iam-bootstrap-apps").await?;
    anyhow::ensure!(
        postgres::ready(&pool).await,
        "apply IAM migrations before bootstrapping"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('iam:bootstrap-apps',0))")
        .execute(&mut *tx)
        .await?;
    let (org,actor):(Id,Id)=sqlx::query_as("SELECT org.id,carbon.id FROM iam.organizations org JOIN iam.organization_memberships member ON member.organization_id=org.id AND member.status='active' AND member.org_role='owner' AND member.principal_kind='carbon' JOIN iam.carbons carbon ON carbon.id=member.principal_id JOIN iam.principals principal ON principal.id=carbon.id AND principal.status='active' WHERE org.org_id=$1 AND carbon.carbon_id=$2 AND org.status='active' FOR SHARE OF org,member,principal").bind(&input.org_id).bind(&input.carbon_id).fetch_one(&mut *tx).await?;
    let mut file = if input.output.exists() {
        anyhow::ensure!(
            !std::fs::symlink_metadata(&input.output)?
                .file_type()
                .is_symlink(),
            "bootstrap output must not be a symlink"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            anyhow::ensure!(
                std::fs::metadata(&input.output)?
                    .permissions()
                    .mode()
                    .trailing_zeros()
                    >= 6,
                "bootstrap output must be private to its owner"
            );
        }
        serde_json::from_slice::<Bootstrap>(&std::fs::read(&input.output)?)?
    } else {
        let mut apps = BTreeMap::new();
        for id in [&input.iam_app_id, &input.honeycomb_app_id] {
            let existing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM iam.applications WHERE app_id=$1 AND organization_id=$2)").bind(id).bind(org).fetch_one(&mut *tx).await?;
            let secret = if existing {
                None
            } else {
                Some(
                    crypto
                        .generate_secret(SecretKind::ApplicationSecret)?
                        .expose_secret()
                        .to_owned(),
                )
            };
            apps.insert(id.to_owned(), secret);
        }
        // ApplicationSecret has 32 random bytes; only its independent random
        // suffix is reused to encode each new dedicated credential.
        let random = crypto.generate_secret(SecretKind::ApplicationSecret)?;
        let service_credential = format!(
            "hck_{}",
            random
                .expose_secret()
                .strip_prefix("ask_")
                .ok_or_else(|| anyhow::anyhow!("secret encoding"))?
        );
        let notification_signing_key = crypto
            .generate_secret(SecretKind::ApplicationSecret)?
            .expose_secret()
            .to_owned();
        let record = Bootstrap {
            org_id: input.org_id.clone(),
            carbon_id: input.carbon_id.clone(),
            iam_app_id: input.iam_app_id.clone(),
            honeycomb_app_id: input.honeycomb_app_id.clone(),
            service_credential,
            notification_signing_key,
            apps,
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut output = options.open(&input.output)?;
        output.write_all(&serde_json::to_vec_pretty(&record)?)?;
        output.sync_all()?;
        record
    };
    anyhow::ensure!(
        file.org_id == input.org_id
            && file.carbon_id == input.carbon_id
            && file.iam_app_id == input.iam_app_id
            && file.honeycomb_app_id == input.honeycomb_app_id,
        "bootstrap file belongs to a different setup"
    );
    for id in [&input.iam_app_id, &input.honeycomb_app_id] {
        let present: Option<(Id, Id)> =
            sqlx::query_as("SELECT id,organization_id FROM iam.applications WHERE app_id=$1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some((_, owning_org)) = present {
            anyhow::ensure!(owning_org == org, "existing app has different ownership");
            continue;
        }
        let secret = file.apps.remove(id).flatten().ok_or_else(|| {
            anyhow::anyhow!(
                "previously existing app is missing; reconcile without regenerating credentials"
            )
        })?;
        let id_uuid = Id::identity(id)?;
        let digest =
            crypto.digest_secret(DigestPurpose::ApplicationSecret, &secret.clone().into())?;
        sqlx::query("INSERT INTO iam.principals(id,kind,status,activated_at) VALUES($1,'application','active',transaction_timestamp())").bind(id_uuid).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO iam.applications(id,app_id,organization_id,created_by_carbon_id,app_name,review_status,visibility) VALUES($1,$2,$3,$4,$5,'verified','public')").bind(id_uuid).bind(id).bind(org).bind(actor).bind(if id==&input.iam_app_id {"IAM"} else {"Honeycomb"}).execute(&mut *tx).await?;
        sqlx::query("SELECT set_config('iam.principal_id',$1,true)")
            .bind(actor.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT iam_private.configure_application_scopes($1,$2,$3)")
            .bind(id_uuid)
            .bind(sqlx::types::Json(
                serde_json::json!({"iam": if id == &input.honeycomb_app_id {
                    vec!["self.identity.read", "self.profile.read", "self.membership.read"]
                } else {
                    vec!["self.identity.read", "self.profile.read"]
                }, "external":[]}),
            ))
            .bind(actor)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO iam.application_secrets(id,application_id,secret_version,secret_prefix,secret_digest,pepper_key_version,created_by_carbon_id) VALUES($1,$2,1,$3,$4,$5,$6)").bind(Id::now_v7()).bind(id_uuid).bind(secret.chars().take(12).collect::<String>()).bind(digest.as_bytes().as_slice()).bind(digest.key_version()).bind(actor).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO iam.audit_events(id,request_id,actor_principal_id,actor_kind,organization_id,application_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'carbon',$4,$5,'application.authentication.bootstrap','application',$5,'{}')").bind(Id::now_v7()).bind(Id::now_v7()).bind(actor).bind(org).bind(id_uuid).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    println!(
        "Authentication identities are ready. Keep the protected bootstrap file for retries and credential delivery."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    #[tokio::test]
    #[ignore = "requires Docker and synthetic development IAM settings"]
    async fn bootstrap_reuses_identity_and_private_credentials() -> anyhow::Result<()> {
        let container = testcontainers_modules::postgres::Postgres::default()
            .with_tag("16-alpine")
            .start()
            .await?;
        let url = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            container.get_host().await?,
            container.get_host_port_ipv4(5432).await?
        );
        let pool = sqlx::PgPool::connect(&url).await?;
        postgres::migrate(&pool).await?;
        let mut settings = Settings::from_env()?;
        settings.database.url = url.into();
        postgres::register_runtime_key_versions(&pool, &settings.security).await?;
        let actor = Id::identity("bootstrap_owner")?;
        let org = Id::now_v7();
        let mut tx = pool.begin().await?;
        sqlx::query("INSERT INTO iam.principals(id,kind,status,activated_at) VALUES($1,'carbon','active',transaction_timestamp())").bind(actor).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO iam.carbons(id,carbon_id,display_name) VALUES($1,'bootstrap_owner','Owner')").bind(actor).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO iam.organizations(id,org_id,created_by_carbon_id,name) VALUES($1,'bootstrap_org',$2,'Bootstrap')").bind(org).bind(actor).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO iam.organization_memberships(id,organization_id,principal_id,principal_kind,org_role) VALUES($1,$2,$3,'carbon','owner')").bind(Id::now_v7()).bind(org).bind(actor).execute(&mut *tx).await?;
        for (index, kind) in ["email", "phone"].iter().enumerate() {
            sqlx::query("INSERT INTO iam.carbon_contacts(id,carbon_id,kind,ciphertext,nonce,encryption_key_version,verified_at) VALUES($1,$2,$3::iam.contact_kind,$4,$5,1,transaction_timestamp())").bind(Id::now_v7()).bind(actor).bind(kind).bind(vec![2u8;17]).bind(vec![u8::try_from(index)?;12]).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        let directory = std::env::temp_dir().join(format!("iam-bootstrap-test-{}", Id::now_v7()));
        std::fs::create_dir(&directory)?;
        let output = directory.join("credentials.json");
        let arguments = || Arguments {
            org_id: "bootstrap_org".into(),
            carbon_id: "bootstrap_owner".into(),
            iam_app_id: "bootstrap_org>iam".into(),
            honeycomb_app_id: "bootstrap_org>honeycomb".into(),
            output: output.clone(),
        };
        bootstrap(arguments(), settings.clone()).await?;
        let original = std::fs::read(&output)?;
        let identities: Vec<Id> =
            sqlx::query_scalar("SELECT id FROM iam.applications ORDER BY app_id")
                .fetch_all(&pool)
                .await?;
        bootstrap(arguments(), settings).await?;
        anyhow::ensure!(
            std::fs::read(&output)? == original,
            "bootstrap rewrote credentials"
        );
        let after: Vec<Id> = sqlx::query_scalar("SELECT id FROM iam.applications ORDER BY app_id")
            .fetch_all(&pool)
            .await?;
        anyhow::ensure!(
            identities == after && after.len() == 2,
            "bootstrap recreated identities"
        );
        let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM iam.application_secrets),(SELECT count(*) FROM iam.audit_events WHERE action='application.authentication.bootstrap')").fetch_one(&pool).await?;
        anyhow::ensure!(
            counts == (2, 2),
            "bootstrap duplicated credentials or audit records"
        );
        let honeycomb_scopes: Vec<String> = sqlx::query_scalar(
            "SELECT scope FROM iam.application_approved_scopes WHERE application_id=(SELECT id FROM iam.applications WHERE app_id='bootstrap_org>honeycomb') AND revoked_at IS NULL ORDER BY scope",
        ).fetch_all(&pool).await?;
        anyhow::ensure!(
            honeycomb_scopes
                == [
                    "self.identity.read",
                    "self.membership.read",
                    "self.profile.read"
                ],
            "Honeycomb bootstrap omitted its membership disclosure permission"
        );
        std::fs::remove_file(output)?;
        std::fs::remove_dir(directory)?;
        Ok(())
    }
}
