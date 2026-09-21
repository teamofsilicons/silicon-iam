//! Central cryptographic primitives for opaque credentials and protected PII.
//!
//! Feature modules receive this component rather than selecting algorithms,
//! domains, token formats, or key versions independently.

use std::collections::BTreeMap;

use crate::domain::id::Id;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use rand::{TryRngCore as _, rngs::OsRng};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::config::{KeyringSettings, SecuritySettings};
use crate::infrastructure::testing_plane;

type HmacSha256 = Hmac<Sha256>;

/// Fixed wire length of a testing environment key.
pub const TESTING_ENVIRONMENT_KEY_LENGTH: usize = 32;

const DIGEST_DOMAIN: &[u8] = b"silicon-iam:v1:digest";
const TESTING_ENVIRONMENT_DOMAIN: &[u8] = b"silicon-iam:v1:testing-environment";
const BLIND_INDEX_DOMAIN: &[u8] = b"silicon-iam:v1:blind-index";
const ENCRYPTION_DOMAIN: &[u8] = b"silicon-iam:v1:encryption";
const ENCRYPTION_SCHEMA_VERSION: u8 = 1;

/// Versioned cryptographic material used by the process.
#[derive(Clone)]
pub struct CryptoService {
    token_peppers: Keyring,
    blind_index_keys: Keyring,
    encryption: EncryptionService,
}

/// Restricted authenticated-encryption capability for delivery workers.
///
/// Unlike [`CryptoService`], this type has no token pepper or blind-index key
/// and exposes no credential generation, digest, or verification operations.
#[derive(Clone)]
pub struct EncryptionService {
    encryption_keys: Keyring,
    // Legacy values are cryptographic context metadata only. They cannot be
    // used to look up or authenticate an identity.
    application_contexts: BTreeMap<(Option<Id>, Id), Id>,
}

#[derive(Clone)]
struct Keyring {
    current_version: i16,
    keys: BTreeMap<i16, Zeroizing<[u8; 32]>>,
}

/// Keyed digest retained in PostgreSQL instead of an opaque credential.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecretDigest {
    key_version: i16,
    bytes: [u8; 32],
}

/// Authenticated encrypted value safe to persist.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedValue {
    /// Encryption-key version needed for rotation-aware decryption.
    pub key_version: i16,
    /// Unique 96-bit AES-GCM nonce.
    pub nonce: [u8; 12],
    /// Ciphertext including the authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Supported high-entropy credential wire formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretKind {
    /// Carbon access token.
    CarbonAccessToken,
    /// Silicon access token.
    SiliconAccessToken,
    /// Application access token.
    ApplicationAccessToken,
    /// Rotating refresh token.
    RefreshToken,
    /// Rotating OAuth client refresh token.
    OAuthRefreshToken,
    /// Two-minute OAuth authorization code.
    AuthorizationCode,
    /// `WorkOS` SSO authorization state.
    SsoState,
    /// `WorkOS` SSO OIDC nonce.
    SsoNonce,
    /// Single-use OBO capability proof.
    OboProof,
    /// Single-use action-bound step-up assertion.
    StepUpAssertion,
    /// Application client secret.
    ApplicationSecret,
    /// Application webhook signing secret generated for isolated testing.
    ApplicationWebhookSigningSecret,
    /// Organization Silicon webhook signing secret.
    SiliconWebhookSigningSecret,
}

/// Closed domain separation for credential digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestPurpose {
    /// Carbon access-token lookup.
    CarbonAccessToken,
    /// Silicon access-token lookup.
    SiliconAccessToken,
    /// Application access-token lookup.
    ApplicationAccessToken,
    /// Refresh-token lookup.
    RefreshToken,
    /// OAuth refresh-token lookup, separated from first-party Carbon sessions.
    OAuthRefreshToken,
    /// OAuth authorization-code lookup.
    AuthorizationCode,
    /// `WorkOS` SSO authorization-state lookup.
    SsoState,
    /// `WorkOS` SSO OIDC nonce lookup.
    SsoNonce,
    /// OBO proof lookup.
    OboProof,
    /// One-time code used to produce a step-up assertion.
    StepUpOtp,
    /// Action-bound step-up assertion lookup.
    StepUpAssertion,
    /// Silicon long-lived credential verification.
    SiliconCredential,
    /// Application client-secret verification.
    ApplicationSecret,
    /// Webhook signing-key verification.
    WebhookSigningSecret,
    /// Email signup verification code.
    SignupEmailOtp,
    /// Phone signup verification code.
    SignupPhoneOtp,
    /// Email login verification code.
    LoginEmailOtp,
    /// Phone login verification code.
    LoginPhoneOtp,
    /// Organization invitation verification code.
    InvitationOtp,
    /// Distributed rate-limit scope.
    RateLimitScope,
    /// Idempotency caller boundary.
    IdempotencyCallerScope,
    /// Client-supplied idempotency key.
    IdempotencyKey,
    /// Canonical mutation request body.
    IdempotencyRequest,
    /// Testing environment key lookup.
    TestingEnvironmentKey,
}

/// Closed domain separation for exact contact lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlindIndexPurpose {
    /// Normalized Carbon email address.
    CarbonEmail,
    /// Normalized Carbon E.164 phone number.
    CarbonPhone,
}

/// Sensitive field protected by authenticated encryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedField {
    /// Carbon email address.
    CarbonEmail,
    /// Invitation email before Carbon registration.
    InvitationEmail,
    /// Exact invitation recipient retained for sensitive-action approval.
    ActionApprovalEmail,
    /// Carbon phone number.
    CarbonPhone,
    /// Bounded idempotency replay envelope containing a one-time secret.
    IdempotencySecretResponse,
    /// Provider credential stored by IAM.
    ProviderCredential,
    /// Browser return URI retained for one `WorkOS` SSO transaction.
    SsoReturnUri,
    /// Application credential shared only within one isolated testing environment.
    TestingApplicationSecret,
    /// Application webhook endpoint URL.
    ApplicationWebhookUrl,
    /// Application webhook HMAC signing secret.
    ApplicationWebhookSigningSecret,
    /// Immutable, recipient-specific application webhook event projection.
    ApplicationWebhookEventPayload,
    /// Organization Silicon webhook endpoint URL.
    SiliconWebhookUrl,
    /// Organization Silicon webhook HMAC signing secret.
    SiliconWebhookSigningSecret,
    /// Legacy provisioned Silicon Hook endpoint URL retained for ciphertext compatibility.
    SiliconHookUrl,
    /// Testing environment key, which administrators can read back on demand.
    TestingEnvironmentKey,
}

/// Typed, row-bound associated data for authenticated encryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptionContext {
    field: ProtectedField,
    tenant_id: Option<Id>,
    entity_id: Id,
    production_application: bool,
}

/// Cryptographic operation failure whose display never contains plaintext.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CryptoError {
    /// Configured key is not valid base64url or has the wrong length.
    #[error("configured {0} is invalid")]
    InvalidKey(&'static str),
    /// The retained keyring does not contain a stored value's version.
    #[error("cryptographic key version {0} is unavailable")]
    MissingKeyVersion(i16),
    /// The operating system could not provide secure entropy.
    #[error("secure operating-system entropy is unavailable")]
    EntropyUnavailable,
    /// HMAC rejected configured key material.
    #[error("keyed digest initialization failed")]
    DigestInitialization,
    /// AES-GCM encryption failed.
    #[error("data encryption failed")]
    Encryption,
    /// AES-GCM authentication or decryption failed.
    #[error("data decryption failed")]
    Decryption,
}

impl CryptoService {
    /// Loads immutable authenticated-encryption context metadata after a
    /// canonical-identity migration, before accepting requests.
    ///
    /// # Errors
    /// Fails startup if metadata cannot be read or contains invalid handles.
    pub async fn load_application_contexts(&mut self, pool: &sqlx::PgPool) -> anyhow::Result<()> {
        self.encryption.load_application_contexts(pool).await
    }
    /// Builds the service from already validated runtime settings.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] when a configured key does not
    /// decode to exactly 32 bytes or the current version is absent.
    pub fn from_settings(settings: &SecuritySettings) -> Result<Self, CryptoError> {
        Ok(Self {
            token_peppers: Keyring::from_settings(
                "IAM_TOKEN_PEPPER_KEYRING",
                &settings.token_peppers,
            )?,
            blind_index_keys: Keyring::from_settings(
                "IAM_BLIND_INDEX_KEYRING",
                &settings.blind_index_keys,
            )?,
            encryption: EncryptionService::from_settings(&settings.encryption_keys)?,
        })
    }

    /// Generates a uniformly random 256-bit opaque credential.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EntropyUnavailable`] if secure bytes cannot be
    /// obtained from the operating system.
    pub fn generate_secret(&self, kind: SecretKind) -> Result<SecretString, CryptoError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        fill_random(bytes.as_mut())?;
        let encoded = URL_SAFE_NO_PAD.encode(bytes.as_ref());
        Ok(SecretString::from(format!(
            "{}{encoded}",
            secret_prefix(kind)
        )))
    }

    /// Generates a Silicon token in the product-compatible `stk-<hex>` format.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EntropyUnavailable`] if secure bytes cannot be
    /// obtained from the operating system.
    pub fn generate_silicon_token(&self) -> Result<SecretString, CryptoError> {
        let mut bytes = Zeroizing::new([0_u8; 16]);
        fill_random(bytes.as_mut())?;
        Ok(SecretString::from(format!(
            "stk-{}",
            hex::encode(bytes.as_ref())
        )))
    }

    /// Generates a 32-character alphanumeric testing environment key.
    ///
    /// The product contract fixes both the length and the alphabet, so this
    /// cannot go through [`Self::generate_secret`], whose values are
    /// prefixed base64url. Rejection sampling keeps the 62-symbol alphabet
    /// uniform; the result carries roughly 190 bits.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EntropyUnavailable`] if secure bytes cannot be
    /// obtained from the operating system.
    pub fn generate_testing_environment_key(&self) -> Result<SecretString, CryptoError> {
        const ALPHABET: &[u8; 62] =
            b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        const ACCEPTANCE_ZONE: u8 = 248; // 256 - (256 % 62)

        let mut key = Zeroizing::new(Vec::with_capacity(TESTING_ENVIRONMENT_KEY_LENGTH));
        let mut candidates = Zeroizing::new([0_u8; 64]);
        while key.len() < TESTING_ENVIRONMENT_KEY_LENGTH {
            fill_random(candidates.as_mut())?;
            for candidate in candidates.iter().copied() {
                if candidate < ACCEPTANCE_ZONE {
                    key.push(ALPHABET[usize::from(candidate % 62)]);
                    if key.len() == TESTING_ENVIRONMENT_KEY_LENGTH {
                        break;
                    }
                }
            }
        }
        String::from_utf8(key.to_vec())
            .map(SecretString::from)
            .map_err(|_| CryptoError::EntropyUnavailable)
    }

    /// Generates an unbiased, zero-padded six-digit verification code.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EntropyUnavailable`] if secure randomness cannot
    /// be obtained from the operating system.
    pub fn generate_otp(&self) -> Result<SecretString, CryptoError> {
        const RANGE: u32 = 1_000_000;
        const ACCEPTANCE_ZONE: u32 = u32::MAX - (u32::MAX % RANGE);
        let value = loop {
            let candidate = OsRng
                .try_next_u32()
                .map_err(|_| CryptoError::EntropyUnavailable)?;
            if candidate < ACCEPTANCE_ZONE {
                break candidate % RANGE;
            }
        };
        Ok(SecretString::from(format!("{value:06}")))
    }

    /// Produces a purpose-separated keyed digest for a credential.
    ///
    /// # Errors
    ///
    /// Returns an error if the current digest key is unavailable or rejected.
    pub fn digest_secret(
        &self,
        purpose: DigestPurpose,
        secret: &SecretString,
    ) -> Result<SecretDigest, CryptoError> {
        let (version, key) = self.token_peppers.current()?;
        keyed_digest(
            key,
            version,
            DIGEST_DOMAIN,
            purpose.label(),
            secret.expose_secret().as_bytes(),
        )
    }

    /// Produces credential digests for every retained key version.
    ///
    /// This is used only for lookup during a pepper rotation; verification
    /// still uses the exact key version stored with the matched record.
    ///
    /// # Errors
    ///
    /// Returns an error if any retained digest key is rejected.
    pub fn digest_secrets(
        &self,
        purpose: DigestPurpose,
        secret: &SecretString,
    ) -> Result<Vec<SecretDigest>, CryptoError> {
        self.token_peppers
            .keys
            .iter()
            .map(|(version, key)| {
                keyed_digest(
                    key.as_ref(),
                    *version,
                    DIGEST_DOMAIN,
                    purpose.label(),
                    secret.expose_secret().as_bytes(),
                )
            })
            .collect()
    }

    /// Compares a supplied secret with a retained digest in constant time.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained digest's key version is unavailable or
    /// rejected.
    pub fn verify_secret(
        &self,
        purpose: DigestPurpose,
        supplied: &SecretString,
        expected: SecretDigest,
    ) -> Result<bool, CryptoError> {
        let key = self.token_peppers.key(expected.key_version)?;
        let actual = keyed_digest(
            key,
            expected.key_version,
            DIGEST_DOMAIN,
            purpose.label(),
            supplied.expose_secret().as_bytes(),
        )?;
        Ok(bool::from(subtle::ConstantTimeEq::ct_eq(
            actual.as_bytes().as_slice(),
            expected.as_bytes().as_slice(),
        )))
    }

    /// Produces the current versioned blind index for normalized contact data.
    ///
    /// # Errors
    ///
    /// Returns an error if the current blind-index key is unavailable or
    /// rejected.
    pub fn blind_index(
        &self,
        purpose: BlindIndexPurpose,
        normalized: &str,
    ) -> Result<SecretDigest, CryptoError> {
        let (version, key) = self.blind_index_keys.current()?;
        keyed_digest(
            key,
            version,
            BLIND_INDEX_DOMAIN,
            purpose.label(),
            normalized.as_bytes(),
        )
    }

    /// Produces blind indexes for all retained versions during key rotation.
    ///
    /// # Errors
    ///
    /// Returns an error if any retained key is rejected by the HMAC primitive.
    pub fn blind_indexes(
        &self,
        purpose: BlindIndexPurpose,
        normalized: &str,
    ) -> Result<Vec<SecretDigest>, CryptoError> {
        self.blind_index_keys
            .keys
            .iter()
            .map(|(version, key)| {
                keyed_digest(
                    key.as_ref(),
                    *version,
                    BLIND_INDEX_DOMAIN,
                    purpose.label(),
                    normalized.as_bytes(),
                )
            })
            .collect()
    }

    /// Encrypts sensitive data using AES-256-GCM and row-bound context.
    ///
    /// # Errors
    ///
    /// Returns an error if the current key is unavailable, secure nonce
    /// generation fails, or authenticated encryption fails.
    pub fn encrypt(
        &self,
        context: EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedValue, CryptoError> {
        self.encryption.encrypt(context, plaintext)
    }

    /// Authenticates and decrypts sensitive data under the same row context.
    ///
    /// # Errors
    ///
    /// Returns an error when the key version is unavailable or authentication
    /// of the ciphertext and associated data fails.
    pub fn decrypt(
        &self,
        context: EncryptionContext,
        encrypted: &EncryptedValue,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.encryption.decrypt(context, encrypted)
    }
}

impl EncryptionService {
    /// Builds an AEAD-only service from the validated encryption keyring.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] when a configured key does not
    /// decode to exactly 32 bytes or the current version is absent.
    pub fn from_settings(settings: &KeyringSettings) -> Result<Self, CryptoError> {
        Ok(Self {
            encryption_keys: Keyring::from_settings("IAM_ENCRYPTION_KEYRING", settings)?,
            application_contexts: BTreeMap::new(),
        })
    }

    /// Loads the AAD-only metadata retained for existing encrypted values.
    ///
    /// # Errors
    /// Rejects unavailable metadata and conflicting context registrations.
    pub async fn load_application_contexts(&mut self, pool: &sqlx::PgPool) -> anyhow::Result<()> {
        let rows: Vec<(String, Option<uuid::Uuid>, uuid::Uuid)> = sqlx::query_as(
            "SELECT application_id, testing_environment_id, context_id FROM iam_private.application_encryption_contexts()",
        ).fetch_all(pool).await?;
        for (application, environment, context) in rows {
            let key = (environment.map(Id::from), Id::identity(&application)?);
            let context = Id::from(context);
            if let Some(previous) = self.application_contexts.insert(key, context) {
                anyhow::ensure!(
                    previous == context,
                    "conflicting application encryption context"
                );
            }
        }
        Ok(())
    }

    fn retained_context(&self, mut context: EncryptionContext) -> EncryptionContext {
        let application_id = match context.field {
            ProtectedField::ApplicationWebhookUrl
            | ProtectedField::ApplicationWebhookSigningSecret
            | ProtectedField::ApplicationWebhookEventPayload => context.tenant_id,
            ProtectedField::TestingApplicationSecret => Some(context.entity_id),
            _ => None,
        };
        if let Some(retained) = application_id.and_then(|application| {
            self.application_contexts.get(&(
                if context.production_application {
                    None
                } else {
                    testing_plane::current_id()
                },
                application,
            ))
        }) {
            if context.field == ProtectedField::TestingApplicationSecret {
                context.entity_id = *retained;
            } else {
                context.tenant_id = Some(*retained);
            }
        }
        context
    }

    /// Encrypts sensitive data using AES-256-GCM and row-bound context.
    ///
    /// # Errors
    ///
    /// Returns an error if the current key is unavailable, secure nonce
    /// generation fails, or authenticated encryption fails.
    pub fn encrypt(
        &self,
        context: EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedValue, CryptoError> {
        let (key_version, key) = self.encryption_keys.current()?;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey("IAM_ENCRYPTION_KEYRING"))?;
        let mut nonce = [0_u8; 12];
        fill_random(&mut nonce)?;
        // New writes always use canonical identity handles. The retained UUID
        // metadata is a read-only bridge for ciphertext created before the
        // migration, including across testing-environment clean/recreate.
        let aad = encryption_aad(context, key_version);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Encryption)?;

        Ok(EncryptedValue {
            key_version,
            nonce,
            ciphertext,
        })
    }

    /// Authenticates and decrypts sensitive data under the same row context.
    ///
    /// # Errors
    ///
    /// Returns an error when the key version is unavailable or authentication
    /// of the ciphertext and associated data fails.
    pub fn decrypt(
        &self,
        context: EncryptionContext,
        encrypted: &EncryptedValue,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let key = self.encryption_keys.key(encrypted.key_version)?;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey("IAM_ENCRYPTION_KEYRING"))?;
        let aad = encryption_aad(context, encrypted.key_version);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&encrypted.nonce),
                Payload {
                    msg: &encrypted.ciphertext,
                    aad: &aad,
                },
            )
            .or_else(|error| {
                let retained = self.retained_context(context);
                if retained == context {
                    return Err(error);
                }
                cipher.decrypt(
                    Nonce::from_slice(&encrypted.nonce),
                    Payload {
                        msg: &encrypted.ciphertext,
                        aad: &encryption_aad(retained, encrypted.key_version),
                    },
                )
            })
            .map_err(|_| CryptoError::Decryption)?;

        Ok(Zeroizing::new(plaintext))
    }
}

impl Keyring {
    fn from_settings(name: &'static str, settings: &KeyringSettings) -> Result<Self, CryptoError> {
        let mut keys = BTreeMap::new();
        for (version, encoded) in &settings.keys {
            keys.insert(*version, Zeroizing::new(decode_key(name, encoded)?));
        }
        if !keys.contains_key(&settings.current_version) {
            return Err(CryptoError::InvalidKey(name));
        }
        Ok(Self {
            current_version: settings.current_version,
            keys,
        })
    }

    fn current(&self) -> Result<(i16, &[u8; 32]), CryptoError> {
        Ok((self.current_version, self.key(self.current_version)?))
    }

    fn key(&self, version: i16) -> Result<&[u8; 32], CryptoError> {
        self.keys
            .get(&version)
            .map(|key| &**key)
            .ok_or(CryptoError::MissingKeyVersion(version))
    }
}

impl SecretDigest {
    /// Builds a digest from separately stored database fields.
    #[must_use]
    pub fn from_parts(key_version: i16, value: &[u8]) -> Option<Self> {
        value
            .try_into()
            .ok()
            .map(|bytes| Self { key_version, bytes })
    }

    /// Returns the key version required to verify this digest.
    #[must_use]
    pub const fn key_version(&self) -> i16 {
        self.key_version
    }

    /// Returns the raw digest bytes for a PostgreSQL `bytea` binding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl EncryptionContext {
    /// Binds ciphertext to a global entity row.
    #[must_use]
    pub const fn global(field: ProtectedField, entity_id: Id) -> Self {
        Self {
            field,
            tenant_id: None,
            entity_id,
            production_application: false,
        }
    }

    /// Binds ciphertext to a tenant/application scope and one entity row.
    #[must_use]
    pub const fn tenant(field: ProtectedField, tenant_id: Id, entity_id: Id) -> Self {
        Self {
            field,
            tenant_id: Some(tenant_id),
            entity_id,
            production_application: false,
        }
    }

    /// Selects production metadata when importing a production application
    /// while the request itself executes inside a testing environment.
    #[must_use]
    pub const fn production_application(mut self) -> Self {
        self.production_application = true;
        self
    }
}

impl DigestPurpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::CarbonAccessToken => b"carbon-access-token",
            Self::SiliconAccessToken => b"silicon-access-token",
            Self::ApplicationAccessToken => b"application-access-token",
            Self::RefreshToken => b"refresh-token",
            Self::OAuthRefreshToken => b"oauth-refresh-token",
            Self::AuthorizationCode => b"authorization-code",
            Self::SsoState => b"sso-state",
            Self::SsoNonce => b"sso-nonce",
            Self::OboProof => b"obo-proof",
            Self::StepUpOtp => b"step-up-otp",
            Self::StepUpAssertion => b"step-up-assertion",
            Self::SiliconCredential => b"silicon-credential",
            Self::ApplicationSecret => b"application-secret",
            Self::WebhookSigningSecret => b"webhook-signing-secret",
            Self::SignupEmailOtp => b"signup-email-otp",
            Self::SignupPhoneOtp => b"signup-phone-otp",
            Self::LoginEmailOtp => b"login-email-otp",
            Self::LoginPhoneOtp => b"login-phone-otp",
            Self::InvitationOtp => b"invitation-otp",
            Self::RateLimitScope => b"rate-limit-scope",
            Self::IdempotencyCallerScope => b"idempotency-caller-scope",
            Self::IdempotencyKey => b"idempotency-key",
            Self::IdempotencyRequest => b"idempotency-request",
            Self::TestingEnvironmentKey => b"testing-environment-key",
        }
    }
}

impl BlindIndexPurpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::CarbonEmail => b"carbon-email",
            Self::CarbonPhone => b"carbon-phone",
        }
    }
}

impl ProtectedField {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::InvitationEmail => b"invitation-email",
            Self::ActionApprovalEmail => b"action-approval-email",
            Self::CarbonEmail => b"carbon-email",
            Self::CarbonPhone => b"carbon-phone",
            Self::IdempotencySecretResponse => b"idempotency-secret-response",
            Self::ProviderCredential => b"provider-credential",
            Self::SsoReturnUri => b"sso-return-uri",
            Self::TestingApplicationSecret => b"testing-application-secret",
            Self::ApplicationWebhookUrl => b"application-webhook-url",
            Self::ApplicationWebhookSigningSecret => b"application-webhook-signing-secret",
            Self::ApplicationWebhookEventPayload => b"application-webhook-event-payload",
            Self::SiliconWebhookUrl => b"silicon-webhook-url",
            Self::SiliconWebhookSigningSecret => b"silicon-webhook-signing-secret",
            Self::SiliconHookUrl => b"silicon-hook-url",
            Self::TestingEnvironmentKey => b"testing-environment-key",
        }
    }
}

fn decode_key(name: &'static str, value: &SecretString) -> Result<[u8; 32], CryptoError> {
    let mut decoded = URL_SAFE_NO_PAD
        .decode(value.expose_secret())
        .map_err(|_| CryptoError::InvalidKey(name))?;
    let result = decoded
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey(name));
    decoded.zeroize();
    result
}

/// Derives a keyed digest, separated by the testing environment in scope.
///
/// Two environments must be able to hold the same email address, the same
/// handle, and the same idempotency key without colliding. Separating them here
/// rather than by widening every unique index keeps the digest columns
/// globally unique, which in turn keeps `ON CONFLICT` inference -- and the
/// upserts built on it -- working unchanged in both databases.
///
/// The environment contributes nothing when none is selected, so a production
/// digest is byte-for-byte what it was before this existed and every value
/// already at rest still verifies.
fn keyed_digest(
    key: &[u8],
    key_version: i16,
    domain: &[u8],
    purpose: &[u8],
    value: &[u8],
) -> Result<SecretDigest, CryptoError> {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key)
        .map_err(|_| CryptoError::DigestInitialization)?;
    mac.update(domain);
    mac.update(&key_version.to_be_bytes());
    mac.update(&[0]);
    mac.update(purpose);
    mac.update(&[0]);
    if let Some(testing_environment_id) = testing_plane::current_id() {
        mac.update(TESTING_ENVIRONMENT_DOMAIN);
        mac.update(testing_environment_id.as_bytes());
        mac.update(&[0]);
    }
    mac.update(value);
    Ok(SecretDigest {
        key_version,
        bytes: mac.finalize().into_bytes().into(),
    })
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "bounded canonical handles preserve Copy authority snapshots without interning or lifetime coupling"
)]
fn encryption_aad(context: EncryptionContext, key_version: i16) -> Vec<u8> {
    let field = context.field.label();
    let mut aad = Vec::with_capacity(96);
    aad.extend_from_slice(ENCRYPTION_DOMAIN);
    aad.push(ENCRYPTION_SCHEMA_VERSION);
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad.push(0);
    aad.extend_from_slice(field);
    aad.push(0);
    if let Some(tenant_id) = context.tenant_id {
        aad.push(1);
        aad.extend_from_slice(tenant_id.as_bytes());
    } else {
        aad.push(0);
    }
    aad.extend_from_slice(context.entity_id.as_bytes());
    aad
}

fn fill_random(destination: &mut [u8]) -> Result<(), CryptoError> {
    OsRng
        .try_fill_bytes(destination)
        .map_err(|_| CryptoError::EntropyUnavailable)
}

const fn secret_prefix(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::CarbonAccessToken => "cat_",
        SecretKind::SiliconAccessToken => "sat_",
        SecretKind::ApplicationAccessToken => "oat_",
        SecretKind::RefreshToken => "rft_",
        SecretKind::OAuthRefreshToken => "ort_",
        SecretKind::AuthorizationCode => "oac_",
        SecretKind::SsoState => "sss_",
        SecretKind::SsoNonce => "ssn_",
        SecretKind::OboProof => "obo_",
        SecretKind::StepUpAssertion => "sup_",
        SecretKind::ApplicationSecret => "ask_",
        SecretKind::SiliconWebhookSigningSecret => "swhs_",
        SecretKind::ApplicationWebhookSigningSecret => "whs_",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::domain::id::Id;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use secrecy::{ExposeSecret as _, SecretString};

    use crate::config::{KeyringSettings, SecuritySettings};

    use super::{
        CryptoError, CryptoService, DigestPurpose, EncryptionContext, EncryptionService,
        ProtectedField, SecretKind,
    };

    fn keyring(version: i16, byte: u8) -> KeyringSettings {
        KeyringSettings {
            current_version: version,
            keys: BTreeMap::from([(
                version,
                SecretString::from(URL_SAFE_NO_PAD.encode([byte; 32])),
            )]),
        }
    }

    fn service() -> CryptoService {
        let key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let settings = SecuritySettings {
            token_peppers: keyring(2, 7),
            blind_index_keys: keyring(3, 8),
            encryption_keys: keyring(4, 9),
            cookie_key: SecretString::from(key),
            access_token_ttl: std::time::Duration::from_mins(30),
            refresh_family_ttl: std::time::Duration::from_hours(21_600),
            authorization_code_ttl: std::time::Duration::from_secs(120),
            otp_ttl: std::time::Duration::from_secs(600),
            otp_max_attempts: 10,
        };
        let Ok(service) = CryptoService::from_settings(&settings) else {
            panic!("valid test keyrings must initialize");
        };
        service
    }

    #[test]
    fn canonical_application_context_decrypts_retained_ciphertext_without_uuid_identity()
    -> anyhow::Result<()> {
        let mut service = service();
        let legacy_context = Id::from_u128(71);
        let application = Id::identity("bricks>remind")?;
        let row = Id::from_u128(72);
        let legacy =
            EncryptionContext::tenant(ProtectedField::ApplicationWebhookUrl, legacy_context, row);
        let canonical =
            EncryptionContext::tenant(ProtectedField::ApplicationWebhookUrl, application, row);
        let ciphertext = service.encrypt(legacy, b"https://example.test/webhook")?;
        service
            .encryption
            .application_contexts
            .insert((None, application), legacy_context);
        assert_eq!(
            service.decrypt(canonical, &ciphertext)?.as_slice(),
            b"https://example.test/webhook"
        );
        let other = EncryptionContext::tenant(
            ProtectedField::ApplicationWebhookUrl,
            Id::identity("bricks>waveform")?,
            row,
        );
        assert_eq!(
            service.decrypt(other, &ciphertext),
            Err(CryptoError::Decryption)
        );

        // New ciphertext remains decryptable after a cleaned testing identity
        // is recreated without any retained legacy metadata.
        let fresh = service.encrypt(canonical, b"new canonical ciphertext")?;
        service.encryption.application_contexts.clear();
        assert_eq!(
            service.decrypt(canonical, &fresh)?.as_slice(),
            b"new canonical ciphertext"
        );
        Ok(())
    }

    #[tokio::test]
    async fn retained_application_contexts_are_isolated_between_testing_environments()
    -> anyhow::Result<()> {
        use crate::infrastructure::testing_plane::{SelectedEnvironment, scope};
        let mut service = service();
        let application = Id::identity("bricks>remind")?;
        let first = SelectedEnvironment {
            id: Id::from_u128(81),
            organization_id: Id::from_u128(91),
        };
        let second = SelectedEnvironment {
            id: Id::from_u128(82),
            organization_id: Id::from_u128(91),
        };
        let row = Id::from_u128(83);
        let old = Id::from_u128(84);
        let ciphertext = service.encrypt(
            EncryptionContext::tenant(ProtectedField::ApplicationWebhookUrl, old, row),
            b"first environment",
        )?;
        service
            .encryption
            .application_contexts
            .insert((Some(first.id), application), old);
        service
            .encryption
            .application_contexts
            .insert((Some(second.id), application), Id::from_u128(85));
        let canonical =
            EncryptionContext::tenant(ProtectedField::ApplicationWebhookUrl, application, row);
        assert!(
            scope(first, async { service.decrypt(canonical, &ciphertext) })
                .await
                .is_ok()
        );
        assert_eq!(
            scope(second, async { service.decrypt(canonical, &ciphertext) }).await,
            Err(CryptoError::Decryption)
        );
        assert_eq!(
            service.decrypt(canonical, &ciphertext),
            Err(CryptoError::Decryption)
        );
        Ok(())
    }

    #[test]
    fn generated_secrets_have_distinct_class_prefixes() {
        let service = service();
        let first = service.generate_secret(SecretKind::CarbonAccessToken);
        let second = service.generate_secret(SecretKind::SiliconAccessToken);
        let webhook = service.generate_secret(SecretKind::SiliconWebhookSigningSecret);
        let (Ok(first), Ok(second), Ok(webhook)) = (first, second, webhook) else {
            panic!("test environment must provide secure entropy");
        };

        assert!(first.expose_secret().starts_with("cat_"));
        assert!(second.expose_secret().starts_with("sat_"));
        assert!(webhook.expose_secret().starts_with("swhs_"));
        assert_ne!(first.expose_secret(), second.expose_secret());
    }

    #[test]
    fn silicon_tokens_have_the_exact_product_hex_payload() {
        let Ok(token) = service().generate_silicon_token() else {
            panic!("test environment must provide secure entropy");
        };
        let value = token.expose_secret();
        assert!(value.starts_with("stk-"));
        assert_eq!(value.len(), 36);
        assert!(value[4..].bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn secret_verification_is_purpose_and_version_bound() {
        let service = service();
        let Ok(token) = service.generate_secret(SecretKind::CarbonAccessToken) else {
            panic!("test environment must provide secure entropy");
        };
        let Ok(digest) = service.digest_secret(DigestPurpose::CarbonAccessToken, &token) else {
            panic!("valid HMAC key must work");
        };

        assert_eq!(digest.key_version(), 2);
        assert_eq!(
            service.verify_secret(DigestPurpose::CarbonAccessToken, &token, digest),
            Ok(true)
        );
        assert_eq!(
            service.verify_secret(DigestPurpose::RefreshToken, &token, digest),
            Ok(false)
        );
    }

    #[tokio::test]
    async fn opaque_credentials_are_bound_to_exactly_one_data_plane() {
        use crate::infrastructure::testing_plane::{SelectedEnvironment, scope};

        let service = service();
        let credential = SecretString::from("same-opaque-credential".to_owned());
        let Ok(production) = service.digest_secret(DigestPurpose::ApplicationSecret, &credential)
        else {
            panic!("the configured test keyring must produce a digest");
        };
        let first_environment = SelectedEnvironment {
            id: Id::from_u128(101),
            organization_id: Id::from_u128(201),
        };
        let second_environment = SelectedEnvironment {
            id: Id::from_u128(102),
            organization_id: Id::from_u128(201),
        };
        let Ok(first) = scope(first_environment, async {
            service.digest_secret(DigestPurpose::ApplicationSecret, &credential)
        })
        .await
        else {
            panic!("the first environment must produce a digest");
        };
        let Ok(second) = scope(second_environment, async {
            service.digest_secret(DigestPurpose::ApplicationSecret, &credential)
        })
        .await
        else {
            panic!("the second environment must produce a digest");
        };

        assert_ne!(production, first);
        assert_ne!(first, second);
        assert_eq!(
            service.verify_secret(DigestPurpose::ApplicationSecret, &credential, production),
            Ok(true)
        );
        assert_eq!(
            service.verify_secret(DigestPurpose::ApplicationSecret, &credential, first),
            Ok(false)
        );
        scope(first_environment, async {
            assert_eq!(
                service.verify_secret(DigestPurpose::ApplicationSecret, &credential, first),
                Ok(true)
            );
            assert_eq!(
                service.verify_secret(DigestPurpose::ApplicationSecret, &credential, production),
                Ok(false)
            );
            assert_eq!(
                service.verify_secret(DigestPurpose::ApplicationSecret, &credential, second),
                Ok(false)
            );
        })
        .await;
    }

    #[test]
    fn encryption_is_row_bound_and_randomized() {
        let service = service();
        let entity_id = Id::now_v7();
        let context = EncryptionContext::global(ProtectedField::CarbonEmail, entity_id);
        let first = service.encrypt(context, b"user@example.com");
        let second = service.encrypt(context, b"user@example.com");
        let (Ok(first), Ok(second)) = (first, second) else {
            panic!("valid encryption must succeed");
        };

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(
            service.decrypt(context, &first).map(|value| value.to_vec()),
            Ok(b"user@example.com".to_vec())
        );
        let wrong_row = EncryptionContext::global(ProtectedField::CarbonEmail, Id::now_v7());
        assert!(matches!(
            service.decrypt(wrong_row, &first),
            Err(CryptoError::Decryption)
        ));
    }

    #[test]
    fn application_event_projection_is_bound_to_recipient_and_row() {
        let service = service();
        let application_id = Id::now_v7();
        let projection_id = Id::now_v7();
        let context = EncryptionContext::tenant(
            ProtectedField::ApplicationWebhookEventPayload,
            application_id,
            projection_id,
        );
        let Ok(encrypted) = service.encrypt(context, br#"{"current":{"version":7}}"#) else {
            panic!("valid encryption must succeed");
        };
        let wrong_application = EncryptionContext::tenant(
            ProtectedField::ApplicationWebhookEventPayload,
            Id::now_v7(),
            projection_id,
        );
        let wrong_row = EncryptionContext::tenant(
            ProtectedField::ApplicationWebhookEventPayload,
            application_id,
            Id::now_v7(),
        );

        assert!(matches!(
            service.decrypt(wrong_application, &encrypted),
            Err(CryptoError::Decryption)
        ));
        assert!(matches!(
            service.decrypt(wrong_row, &encrypted),
            Err(CryptoError::Decryption)
        ));
    }

    #[test]
    fn encryption_only_service_needs_only_the_contact_aead_keyring() {
        let Ok(service) = EncryptionService::from_settings(&keyring(4, 9)) else {
            panic!("valid encryption keyring must initialize");
        };
        let entity_id = Id::now_v7();
        let context = EncryptionContext::global(ProtectedField::CarbonEmail, entity_id);
        let Ok(encrypted) = service.encrypt(context, b"worker@example.com") else {
            panic!("valid encryption must succeed");
        };

        assert_eq!(encrypted.key_version, 4);
        assert_eq!(
            service
                .decrypt(context, &encrypted)
                .map(|value| value.to_vec()),
            Ok(b"worker@example.com".to_vec())
        );
        let wrong_context = EncryptionContext::global(ProtectedField::CarbonEmail, Id::now_v7());
        assert!(matches!(
            service.decrypt(wrong_context, &encrypted),
            Err(CryptoError::Decryption)
        ));
    }

    #[test]
    fn otp_is_six_digits() {
        let Ok(otp) = service().generate_otp() else {
            panic!("test environment must provide secure entropy");
        };
        let value = otp.expose_secret();
        assert_eq!(value.len(), 6);
        assert!(value.bytes().all(|byte| byte.is_ascii_digit()));
    }
}
