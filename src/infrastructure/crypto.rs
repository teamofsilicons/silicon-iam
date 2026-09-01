//! Central cryptographic primitives for opaque credentials and protected PII.
//!
//! Feature modules receive this component rather than selecting algorithms,
//! domains, token formats, or key versions independently.

use std::collections::BTreeMap;

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
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

use crate::config::{KeyringSettings, SecuritySettings};

type HmacSha256 = Hmac<Sha256>;

const DIGEST_DOMAIN: &[u8] = b"silicon-iam:v1:digest";
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
    /// Application webhook signing secret.
    WebhookSigningSecret,
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
    /// Carbon phone number.
    CarbonPhone,
    /// Bounded idempotency replay envelope containing a one-time secret.
    IdempotencySecretResponse,
    /// Provider credential stored by IAM.
    ProviderCredential,
    /// Browser return URI retained for one `WorkOS` SSO transaction.
    SsoReturnUri,
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
}

/// Typed, row-bound associated data for authenticated encryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptionContext {
    field: ProtectedField,
    tenant_id: Option<Uuid>,
    entity_id: Uuid,
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
        })
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
    pub const fn global(field: ProtectedField, entity_id: Uuid) -> Self {
        Self {
            field,
            tenant_id: None,
            entity_id,
        }
    }

    /// Binds ciphertext to a tenant/application scope and one entity row.
    #[must_use]
    pub const fn tenant(field: ProtectedField, tenant_id: Uuid, entity_id: Uuid) -> Self {
        Self {
            field,
            tenant_id: Some(tenant_id),
            entity_id,
        }
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
            Self::CarbonEmail => b"carbon-email",
            Self::CarbonPhone => b"carbon-phone",
            Self::IdempotencySecretResponse => b"idempotency-secret-response",
            Self::ProviderCredential => b"provider-credential",
            Self::SsoReturnUri => b"sso-return-uri",
            Self::ApplicationWebhookUrl => b"application-webhook-url",
            Self::ApplicationWebhookSigningSecret => b"application-webhook-signing-secret",
            Self::ApplicationWebhookEventPayload => b"application-webhook-event-payload",
            Self::SiliconWebhookUrl => b"silicon-webhook-url",
            Self::SiliconWebhookSigningSecret => b"silicon-webhook-signing-secret",
            Self::SiliconHookUrl => b"silicon-hook-url",
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
    mac.update(value);
    Ok(SecretDigest {
        key_version,
        bytes: mac.finalize().into_bytes().into(),
    })
}

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
        SecretKind::WebhookSigningSecret => "whs_",
        SecretKind::SiliconWebhookSigningSecret => "swhs_",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use secrecy::{ExposeSecret as _, SecretString};
    use uuid::Uuid;

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

    #[test]
    fn encryption_is_row_bound_and_randomized() {
        let service = service();
        let entity_id = Uuid::now_v7();
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
        let wrong_row = EncryptionContext::global(ProtectedField::CarbonEmail, Uuid::now_v7());
        assert!(matches!(
            service.decrypt(wrong_row, &first),
            Err(CryptoError::Decryption)
        ));
    }

    #[test]
    fn application_event_projection_is_bound_to_recipient_and_row() {
        let service = service();
        let application_id = Uuid::now_v7();
        let projection_id = Uuid::now_v7();
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
            Uuid::now_v7(),
            projection_id,
        );
        let wrong_row = EncryptionContext::tenant(
            ProtectedField::ApplicationWebhookEventPayload,
            application_id,
            Uuid::now_v7(),
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
        let entity_id = Uuid::now_v7();
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
        let wrong_context = EncryptionContext::global(ProtectedField::CarbonEmail, Uuid::now_v7());
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
