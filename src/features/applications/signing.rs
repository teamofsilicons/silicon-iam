//! Fail-closed reconciliation of the configured OIDC signing key.

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::SecuritySettings,
    infrastructure::{
        crypto::{CryptoService, EncryptionContext, ProtectedField},
        postgres::context::{self, DatabaseContext},
    },
};

const EDDSA_ALGORITHM: &str = "EdDSA";
const MINIMUM_VERIFICATION_OVERLAP_SECONDS: u64 = 900;

struct DerivedSigningKey {
    public_x: String,
    public_jwk: Value,
    private_pkcs8: Zeroizing<Vec<u8>>,
}

#[derive(FromRow)]
struct ExistingSigningKey {
    id: Uuid,
    algorithm: String,
    public_x: Option<String>,
    status: String,
}

/// Reconciles the configured Ed25519 seed into one active, encrypted database key.
///
/// The transition is serialized across API replicas. A configured key identifier
/// or public key that collides with different stored material aborts startup.
#[allow(
    clippy::too_many_lines,
    reason = "one serialized key-reconciliation transaction is intentionally reviewed as a unit"
)]
pub(crate) async fn reconcile(
    pool: &PgPool,
    crypto: &CryptoService,
    settings: &SecuritySettings,
) -> anyhow::Result<()> {
    let derived = derive_key(&settings.jwt_key_id, &settings.jwt_ed25519_private_key)?;
    let overlap_seconds = i64::try_from(
        settings
            .access_token_ttl
            .as_secs()
            .max(MINIMUM_VERIFICATION_OVERLAP_SECONDS),
    )
    .context("OIDC verification overlap exceeds PostgreSQL interval range")?;
    let mut transaction = context::begin(
        pool,
        DatabaseContext {
            principal_id: None,
            organization_id: None,
            application_id: None,
            signup_session_id: None,
        },
    )
    .await
    .context("begin OIDC signing-key reconciliation")?;

    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('silicon-iam:oidc-signing-key', 0))",
    )
    .execute(&mut *transaction)
    .await
    .context("lock OIDC signing-key reconciliation")?;

    sqlx::query(
        r"
        UPDATE iam.oidc_signing_keys
        SET status = 'retired', retired_at = transaction_timestamp()
        WHERE status = 'retiring'
          AND retires_at <= transaction_timestamp()
        ",
    )
    .execute(&mut *transaction)
    .await
    .context("retire expired OIDC signing keys")?;

    let existing = sqlx::query_as::<_, ExistingSigningKey>(
        r"
        SELECT id, algorithm, public_jwk ->> 'x' AS public_x, status
        FROM iam.oidc_signing_keys
        WHERE key_id = $1
        FOR UPDATE
        ",
    )
    .bind(&settings.jwt_key_id)
    .fetch_optional(&mut *transaction)
    .await
    .context("read configured OIDC signing key")?;

    if let Some(collision) = sqlx::query_as::<_, (Uuid, String)>(
        r"
        SELECT id, key_id
        FROM iam.oidc_signing_keys
        WHERE algorithm = 'EdDSA'
          AND public_jwk ->> 'x' = $1
          AND key_id <> $2
        LIMIT 1
        FOR UPDATE
        ",
    )
    .bind(&derived.public_x)
    .bind(&settings.jwt_key_id)
    .fetch_optional(&mut *transaction)
    .await
    .context("check OIDC public-key collision")?
    {
        bail!(
            "configured OIDC public key collides with stored key id {} ({})",
            collision.1,
            collision.0
        );
    }

    let key_id = match existing {
        Some(existing) => {
            validate_existing(&existing, &derived.public_x)?;
            existing.id
        }
        None => Uuid::now_v7(),
    };

    let encrypted = crypto
        .encrypt(
            EncryptionContext::global(ProtectedField::OidcSigningPrivateKey, key_id),
            &derived.private_pkcs8,
        )
        .context("encrypt configured OIDC private key")?;

    sqlx::query(
        r"
        UPDATE iam.oidc_signing_keys
        SET status = 'retiring',
            retires_at = transaction_timestamp() + ($2::bigint * interval '1 second'),
            retired_at = NULL
        WHERE status = 'active' AND id <> $1
        ",
    )
    .bind(key_id)
    .bind(overlap_seconds)
    .execute(&mut *transaction)
    .await
    .context("place previous OIDC signing key into verification overlap")?;

    sqlx::query(
        r"
        INSERT INTO iam.oidc_signing_keys (
            id, key_id, algorithm, public_jwk,
            private_key_ciphertext, private_key_nonce, encryption_key_version,
            status, not_before
        ) VALUES (
            $1, $2, 'EdDSA', $3, $4, $5, $6, 'active', transaction_timestamp()
        )
        ON CONFLICT (key_id) DO UPDATE
        SET public_jwk = EXCLUDED.public_jwk,
            private_key_ciphertext = EXCLUDED.private_key_ciphertext,
            private_key_nonce = EXCLUDED.private_key_nonce,
            encryption_key_version = EXCLUDED.encryption_key_version,
            status = 'active',
            not_before = LEAST(iam.oidc_signing_keys.not_before, transaction_timestamp()),
            retires_at = NULL,
            retired_at = NULL
        ",
    )
    .bind(key_id)
    .bind(&settings.jwt_key_id)
    .bind(derived.public_jwk)
    .bind(encrypted.ciphertext)
    .bind(encrypted.nonce.as_slice())
    .bind(encrypted.key_version)
    .execute(&mut *transaction)
    .await
    .context("activate configured OIDC signing key")?;

    let active = sqlx::query_as::<_, (Uuid, String, String)>(
        r"
        SELECT id, key_id, algorithm
        FROM iam.oidc_signing_keys
        WHERE status = 'active' AND not_before <= transaction_timestamp()
        ",
    )
    .fetch_all(&mut *transaction)
    .await
    .context("verify active OIDC signing key")?;
    if active.as_slice()
        != [(
            key_id,
            settings.jwt_key_id.clone(),
            EDDSA_ALGORITHM.to_owned(),
        )]
    {
        bail!("OIDC signing-key reconciliation did not produce exactly one configured active key");
    }

    transaction
        .commit()
        .await
        .context("commit OIDC signing-key reconciliation")?;
    Ok(())
}

fn validate_existing(
    existing: &ExistingSigningKey,
    configured_public_x: &str,
) -> anyhow::Result<()> {
    if existing.algorithm != EDDSA_ALGORITHM
        || existing.public_x.as_deref() != Some(configured_public_x)
    {
        bail!("configured OIDC key id collides with different stored key material");
    }
    if matches!(existing.status.as_str(), "retired" | "compromised") {
        bail!("configured OIDC signing key has been irreversibly retired");
    }
    Ok(())
}

fn derive_key(key_id: &str, encoded_seed: &SecretString) -> anyhow::Result<DerivedSigningKey> {
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded_seed.expose_secret())
            .context("decode configured Ed25519 seed")?,
    );
    if decoded.len() != 32 {
        bail!("configured Ed25519 seed must contain exactly 32 bytes");
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&decoded);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());
    let private_document = signing_key
        .to_pkcs8_der()
        .context("encode configured Ed25519 key as PKCS#8")?;
    let private_pkcs8 = Zeroizing::new(private_document.as_bytes().to_vec());
    Ok(DerivedSigningKey {
        public_x: public_x.clone(),
        public_jwk: json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": public_x,
            "kid": key_id,
            "use": "sig",
            "alg": EDDSA_ALGORITHM,
        }),
        private_pkcs8,
    })
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{SigningKey, pkcs8::DecodePrivateKey as _};
    use secrecy::SecretString;

    use uuid::Uuid;

    use super::{ExistingSigningKey, derive_key, validate_existing};

    #[test]
    fn derives_a_matching_public_jwk_and_pkcs8_private_key() {
        let encoded = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let derived = derive_key("test-key-01", &SecretString::from(encoded));
        assert!(derived.is_ok());
        let derived = match derived {
            Ok(value) => value,
            Err(error) => panic!("unexpected derivation error: {error}"),
        };
        assert_eq!(derived.public_jwk["alg"], "EdDSA");
        assert_eq!(derived.public_jwk["kid"], "test-key-01");
        assert_eq!(derived.public_jwk["x"], derived.public_x);

        let decoded = SigningKey::from_pkcs8_der(&derived.private_pkcs8);
        assert!(decoded.is_ok());
        if let Ok(decoded) = decoded {
            assert_eq!(
                URL_SAFE_NO_PAD.encode(decoded.verifying_key().as_bytes()),
                derived.public_x
            );
        }
    }

    #[test]
    fn rejects_a_seed_with_the_wrong_length() {
        let encoded = URL_SAFE_NO_PAD.encode([7_u8; 31]);
        assert!(derive_key("test-key-01", &SecretString::from(encoded)).is_err());
    }

    #[test]
    fn rejects_key_id_rebinding_and_retired_configured_keys() {
        let existing = ExistingSigningKey {
            id: Uuid::nil(),
            algorithm: "EdDSA".to_owned(),
            public_x: Some("configured-public-key".to_owned()),
            status: "active".to_owned(),
        };
        assert!(validate_existing(&existing, "different-public-key").is_err());

        let retired = ExistingSigningKey {
            status: "retired".to_owned(),
            ..existing
        };
        assert!(validate_existing(&retired, "configured-public-key").is_err());
    }
}
