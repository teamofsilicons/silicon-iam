use secrecy::{ExposeSecret as _, SecretString};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    error::AppError,
    infrastructure::crypto::{
        BlindIndexPurpose, CryptoService, EncryptedValue, EncryptionContext, ProtectedField,
        SecretDigest,
    },
};

use super::model::{ContactChannel, ValidatedContact, ValidatedLoginIdentifier};

#[derive(Debug)]
pub(super) struct ResolvedCarbon {
    pub(super) principal_id: Uuid,
    pub(super) contacts: Vec<ResolvedContact>,
}

#[derive(Debug)]
pub(super) struct ResolvedContact {
    pub(super) id: Uuid,
    pub(super) channel: ContactChannel,
    pub(super) recipient: SecretString,
}

#[derive(FromRow)]
struct ContactResolutionRow {
    principal_id: Uuid,
    contact_id: Uuid,
    contact_ciphertext: Vec<u8>,
    contact_nonce: Vec<u8>,
    contact_encryption_key_version: i16,
}

#[derive(FromRow)]
struct HandleResolutionRow {
    principal_id: Uuid,
}

#[derive(FromRow)]
struct LoginContactRow {
    id: Uuid,
    kind: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    encryption_key_version: i16,
}

pub(super) async fn resolve_login_identifier(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    identifier: &ValidatedLoginIdentifier,
) -> Result<Option<ResolvedCarbon>, AppError> {
    match identifier {
        ValidatedLoginIdentifier::Contact(contact) => {
            resolve_by_contact(transaction, crypto, contact).await
        }
        ValidatedLoginIdentifier::CarbonId(carbon_id) => {
            resolve_by_handle(transaction, crypto, carbon_id.as_str()).await
        }
    }
}

pub(super) async fn contact_associated_with_non_deleted_carbon(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    contact: &ValidatedContact,
) -> Result<bool, AppError> {
    for index in blind_indexes(crypto, contact)? {
        let exists = sqlx::query_scalar::<_, bool>(
            r"
            SELECT iam_private.non_deleted_carbon_contact_exists(
                $1::iam.contact_kind,
                $2,
                $3
            )
            ",
        )
        .bind(contact.channel.database_value())
        .bind(index.key_version())
        .bind(index.as_bytes().as_slice())
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "signup_contact_association_check",
        })?;
        if exists {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) async fn resolve_carbon_id_by_contact(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    contact: &ValidatedContact,
) -> Result<Option<String>, AppError> {
    let Some(row) = resolve_contact_row(transaction, crypto, contact).await? else {
        return Ok(None);
    };
    sqlx::query_scalar::<_, String>(
        r"
        SELECT carbon_id
        FROM iam.carbons
        WHERE id = $1
          AND deleted_at IS NULL
        ",
    )
    .bind(row.principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "carbon_contact_id_resolve",
    })
}

pub(super) async fn carbon_id_available(
    transaction: &mut Transaction<'_, Postgres>,
    carbon_id: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar::<_, bool>("SELECT iam_private.carbon_handle_is_available($1)")
        .bind(carbon_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "carbon_handle_availability",
        })
}

pub(super) fn encrypt_contact(
    crypto: &CryptoService,
    contact: &ValidatedContact,
    entity_id: Uuid,
) -> Result<EncryptedValue, AppError> {
    crypto
        .encrypt(
            EncryptionContext::global(protected_field(contact.channel), entity_id),
            contact.presentation.expose_secret().as_bytes(),
        )
        .map_err(|_| AppError::Internal {
            category: "contact_encrypt",
        })
}

pub(super) fn blind_indexes(
    crypto: &CryptoService,
    contact: &ValidatedContact,
) -> Result<Vec<SecretDigest>, AppError> {
    crypto
        .blind_indexes(blind_index_purpose(contact.channel), &contact.normalized)
        .map_err(|_| AppError::Internal {
            category: "contact_blind_index",
        })
}

async fn resolve_by_contact(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    contact: &ValidatedContact,
) -> Result<Option<ResolvedCarbon>, AppError> {
    let Some(row) = resolve_contact_row(transaction, crypto, contact).await? else {
        return Ok(None);
    };
    let recipient = decrypt_contact(
        crypto,
        contact.channel,
        row.contact_id,
        row.contact_encryption_key_version,
        row.contact_nonce,
        row.contact_ciphertext,
    )?;
    Ok(Some(ResolvedCarbon {
        principal_id: row.principal_id,
        contacts: vec![ResolvedContact {
            id: row.contact_id,
            channel: contact.channel,
            recipient,
        }],
    }))
}

async fn resolve_contact_row(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    contact: &ValidatedContact,
) -> Result<Option<ContactResolutionRow>, AppError> {
    let indexes = blind_indexes(crypto, contact)?;
    for index in indexes {
        let row = sqlx::query_as::<_, ContactResolutionRow>(
            r"
            SELECT
                principal_id,
                contact_id,
                contact_ciphertext,
                contact_nonce,
                contact_encryption_key_version
            FROM iam_private.resolve_active_carbon_by_contact_digest(
                $1::iam.contact_kind,
                $2,
                $3
            )
            ",
        )
        .bind(contact.channel.database_value())
        .bind(index.key_version())
        .bind(index.as_bytes().as_slice())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| AppError::Internal {
            category: "login_contact_resolve",
        })?;
        if row.is_some() {
            return Ok(row);
        }
    }
    Ok(None)
}

async fn resolve_by_handle(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    carbon_id: &str,
) -> Result<Option<ResolvedCarbon>, AppError> {
    let row = sqlx::query_as::<_, HandleResolutionRow>(
        r"
        SELECT principal_id
        FROM iam_private.resolve_active_carbon_by_handle($1)
        ",
    )
    .bind(carbon_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_handle_resolve",
    })?;
    let Some(row) = row else {
        return Ok(None);
    };
    let contact_rows = sqlx::query_as::<_, LoginContactRow>(
        r"
        SELECT
            contact_id AS id,
            contact_kind::text AS kind,
            contact_ciphertext AS ciphertext,
            contact_nonce AS nonce,
            contact_encryption_key_version AS encryption_key_version
        FROM iam_private.list_active_carbon_login_contacts($1)
        ",
    )
    .bind(row.principal_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| AppError::Internal {
        category: "login_contacts_list",
    })?;
    let contacts = contact_rows
        .into_iter()
        .map(|contact| {
            let channel = parse_channel(&contact.kind)?;
            let recipient = decrypt_contact(
                crypto,
                channel,
                contact.id,
                contact.encryption_key_version,
                contact.nonce,
                contact.ciphertext,
            )?;
            Ok(ResolvedContact {
                id: contact.id,
                channel,
                recipient,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    if contacts.len() != 2
        || !contacts
            .iter()
            .any(|contact| contact.channel == ContactChannel::Email)
        || !contacts
            .iter()
            .any(|contact| contact.channel == ContactChannel::Phone)
    {
        return Err(AppError::Internal {
            category: "login_contacts_invariant",
        });
    }
    Ok(Some(ResolvedCarbon {
        principal_id: row.principal_id,
        contacts,
    }))
}

pub(super) fn decrypt_contact(
    crypto: &CryptoService,
    channel: ContactChannel,
    contact_id: Uuid,
    key_version: i16,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<SecretString, AppError> {
    let nonce = <[u8; 12]>::try_from(nonce).map_err(|_| AppError::Internal {
        category: "contact_ciphertext_shape",
    })?;
    let plaintext = crypto
        .decrypt(
            EncryptionContext::global(protected_field(channel), contact_id),
            &EncryptedValue {
                key_version,
                nonce,
                ciphertext,
            },
        )
        .map_err(|_| AppError::Internal {
            category: "contact_decrypt",
        })?;
    let value = String::from_utf8(plaintext.to_vec()).map_err(|_| AppError::Internal {
        category: "contact_plaintext_shape",
    })?;
    Ok(SecretString::from(value))
}

pub(super) const fn protected_field(channel: ContactChannel) -> ProtectedField {
    match channel {
        ContactChannel::Email => ProtectedField::CarbonEmail,
        ContactChannel::Phone => ProtectedField::CarbonPhone,
    }
}

pub(super) const fn blind_index_purpose(channel: ContactChannel) -> BlindIndexPurpose {
    match channel {
        ContactChannel::Email => BlindIndexPurpose::CarbonEmail,
        ContactChannel::Phone => BlindIndexPurpose::CarbonPhone,
    }
}

pub(super) fn parse_channel(value: &str) -> Result<ContactChannel, AppError> {
    match value {
        "email" => Ok(ContactChannel::Email),
        "phone" => Ok(ContactChannel::Phone),
        _ => Err(AppError::Internal {
            category: "contact_kind",
        }),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::ensure;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres;
    use uuid::Uuid;

    #[tokio::test]
    #[ignore = "requires a local Docker daemon"]
    #[allow(
        clippy::too_many_lines,
        reason = "one fresh-database test validates the resolver and related forward constraints"
    )]
    async fn signup_contact_association_includes_suspended_non_deleted_carbons()
    -> anyhow::Result<()> {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await?;
        crate::infrastructure::postgres::migrate(&pool).await?;

        let carbon_id = Uuid::from_u128(0x35_01);
        let email_contact_id = Uuid::from_u128(0x35_02);
        let phone_contact_id = Uuid::from_u128(0x35_03);
        let email_digest = vec![0x35_u8; 32];
        let phone_digest = vec![0x36_u8; 32];
        let mut transaction = pool.begin().await?;
        sqlx::query(
            r"
            INSERT INTO iam.cryptographic_key_versions (purpose, key_version)
            VALUES
                ('contact_aead', 1),
                ('contact_lookup_hmac', 1),
                ('token_hmac', 1)
            ",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.principals (id, kind, status, activated_at)
            VALUES ($1, 'carbon', 'active', transaction_timestamp())
            ",
        )
        .bind(carbon_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.carbons (id, carbon_id, display_name)
            VALUES ($1, 'contract-test-carbon', 'Contract Test Carbon')
            ",
        )
        .bind(carbon_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.carbon_contacts (
                id, carbon_id, kind, ciphertext, nonce,
                encryption_key_version, verified_at
            ) VALUES
                ($1, $3, 'email', decode(repeat('11', 17), 'hex'),
                    decode(repeat('12', 12), 'hex'), 1, transaction_timestamp()),
                ($2, $3, 'phone', decode(repeat('21', 17), 'hex'),
                    decode(repeat('22', 12), 'hex'), 1, transaction_timestamp())
            ",
        )
        .bind(email_contact_id)
        .bind(phone_contact_id)
        .bind(carbon_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO iam.contact_blind_indexes (
                contact_id, contact_kind, hmac_key_version, digest
            ) VALUES ($1, 'email', 1, $3), ($2, 'phone', 1, $4)
            ",
        )
        .bind(email_contact_id)
        .bind(phone_contact_id)
        .bind(&email_digest)
        .bind(&phone_digest)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        let active = association_exists(&pool, &email_digest).await?;
        let authentication_session_id = Uuid::from_u128(0x35_04);
        sqlx::query(
            r"
            INSERT INTO iam.authentication_sessions (
                id, subject_principal_id, subject_kind, authentication_method,
                assurance_level, subject_auth_epoch, idle_expires_at,
                absolute_expires_at
            ) VALUES (
                $1, $2, 'carbon', 'email_otp', 1, 1,
                transaction_timestamp() + interval '1 day',
                transaction_timestamp() + interval '900 days'
            )
            ",
        )
        .bind(authentication_session_id)
        .bind(carbon_id)
        .execute(&pool)
        .await?;
        let generic_admin_action = insert_step_up_challenge(
            &pool,
            authentication_session_id,
            carbon_id,
            "platform_admin.manage",
            Some(carbon_id),
        )
        .await;
        let missing_resource = insert_step_up_challenge(
            &pool,
            authentication_session_id,
            carbon_id,
            "platform_admin.sso_entitlement",
            None,
        )
        .await;
        let narrow_action = insert_step_up_challenge(
            &pool,
            authentication_session_id,
            carbon_id,
            "platform_admin.sso_entitlement",
            Some(carbon_id),
        )
        .await;
        sqlx::query(
            r"
            UPDATE iam.principals
            SET status = 'suspended', suspended_at = transaction_timestamp(),
                auth_epoch = auth_epoch + 1
            WHERE id = $1
            ",
        )
        .bind(carbon_id)
        .execute(&pool)
        .await?;
        let suspended = association_exists(&pool, &email_digest).await?;
        let active_login_resolution = sqlx::query_scalar::<_, bool>(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM iam_private.resolve_active_carbon_by_contact_digest(
                    'email', 1::smallint, $1
                )
            )
            ",
        )
        .bind(&email_digest)
        .fetch_one(&pool)
        .await?;

        let mut transaction = pool.begin().await?;
        sqlx::query("UPDATE iam.carbons SET deleted_at = transaction_timestamp() WHERE id = $1")
            .bind(carbon_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            r"
            UPDATE iam.principals
            SET status = 'deleted', deleted_at = transaction_timestamp(),
                auth_epoch = auth_epoch + 1
            WHERE id = $1
            ",
        )
        .bind(carbon_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let deleted = association_exists(&pool, &email_digest).await?;

        ensure!(active, "active Carbon contact was not recognized");
        ensure!(
            generic_admin_action.is_err(),
            "generic platform-admin step-up authority remained insertable"
        );
        ensure!(
            missing_resource.is_err(),
            "a new step-up challenge accepted a null resource"
        );
        ensure!(
            narrow_action.is_ok(),
            "the narrow SSO-entitlement step-up action was not insertable"
        );
        ensure!(
            suspended,
            "suspended non-deleted Carbon contact was not recognized"
        );
        ensure!(
            !active_login_resolution,
            "signup association hardening weakened active-only login resolution"
        );
        ensure!(!deleted, "deleted Carbon contact remained signup-blocking");
        Ok(())
    }

    async fn association_exists(pool: &sqlx::PgPool, digest: &[u8]) -> anyhow::Result<bool> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT iam_private.non_deleted_carbon_contact_exists('email', 1::smallint, $1)",
        )
        .bind(digest)
        .fetch_one(pool)
        .await?)
    }

    async fn insert_step_up_challenge(
        pool: &sqlx::PgPool,
        authentication_session_id: Uuid,
        carbon_id: Uuid,
        purpose: &str,
        resource_id: Option<Uuid>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"
            INSERT INTO iam.step_up_challenges (
                id, authentication_session_id, carbon_id, purpose, resource_id,
                channel, challenge_digest, digest_key_version, max_attempts,
                expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, 'email', decode(repeat('41', 32), 'hex'),
                1, 10, transaction_timestamp() + interval '10 minutes'
            )
            ",
        )
        .bind(Uuid::now_v7())
        .bind(authentication_session_id)
        .bind(carbon_id)
        .bind(purpose)
        .bind(resource_id)
        .execute(pool)
        .await
        .map(|_| ())
    }
}
