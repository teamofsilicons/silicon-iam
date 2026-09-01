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

pub(super) async fn active_contact_exists(
    transaction: &mut Transaction<'_, Postgres>,
    crypto: &CryptoService,
    contact: &ValidatedContact,
) -> Result<bool, AppError> {
    Ok(resolve_contact_row(transaction, crypto, contact)
        .await?
        .is_some())
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
