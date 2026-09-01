//! Canonical integrity protection for the browser authentication-session cookie.
//!
//! The cookie is host-only (there is deliberately no `Domain` attribute), so
//! the API origin selected by deployment configuration is its sole authority.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use http::{HeaderMap, HeaderValue, header};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "iam_session";
const COOKIE_VERSION: &str = "v1";
const COOKIE_SIGNATURE_DOMAIN: &[u8] = b"silicon-iam:v1:session-cookie\0";
const CSRF_DERIVATION_DOMAIN: &[u8] = b"silicon-iam:v1:session-cookie-csrf\0";
const MAX_COOKIE_VALUE_BYTES: usize = 1_024;

/// Authenticated fields carried by the browser session cookie.
pub(crate) struct VerifiedSessionCookie {
    pub(crate) session_id: Uuid,
    pub(crate) csrf_token: String,
}

/// Redacted browser-cookie failure classification.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum BrowserSessionCookieError {
    /// The configured cookie key cannot be used.
    #[error("browser session cookie configuration is invalid")]
    InvalidConfiguration,
    /// The cookie is missing, ambiguous, malformed, or unauthenticated.
    #[error("browser session cookie is invalid")]
    InvalidCookie,
    /// The requested browser session is already expired.
    #[error("browser session cookie has expired")]
    Expired,
}

/// Issues a secure, host-only browser session cookie bounded by the session's
/// absolute expiry.
pub(crate) fn issue(
    session_id: Uuid,
    absolute_expires_at: OffsetDateTime,
    encoded_key: &SecretString,
) -> Result<HeaderValue, BrowserSessionCookieError> {
    issue_at(
        session_id,
        absolute_expires_at,
        OffsetDateTime::now_utc(),
        encoded_key,
    )
}

/// Returns an immediate host-only deletion instruction using the same security
/// attributes as issued cookies.
pub(crate) fn clear() -> HeaderValue {
    HeaderValue::from_static("iam_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
}

/// Extracts exactly one session cookie and authenticates all of its fields.
pub(crate) fn verify_headers(
    headers: &HeaderMap,
    encoded_key: &SecretString,
) -> Result<VerifiedSessionCookie, BrowserSessionCookieError> {
    let mut found = None;
    for header_value in headers.get_all(header::COOKIE) {
        let value = header_value
            .to_str()
            .map_err(|_| BrowserSessionCookieError::InvalidCookie)?;
        for pair in value.split(';') {
            let Some((name, cookie_value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name != COOKIE_NAME {
                continue;
            }
            if found.replace(cookie_value).is_some() {
                return Err(BrowserSessionCookieError::InvalidCookie);
            }
        }
    }
    verify(
        found.ok_or(BrowserSessionCookieError::InvalidCookie)?,
        encoded_key,
    )
}

fn issue_at(
    session_id: Uuid,
    absolute_expires_at: OffsetDateTime,
    now: OffsetDateTime,
    encoded_key: &SecretString,
) -> Result<HeaderValue, BrowserSessionCookieError> {
    let max_age = (absolute_expires_at - now).whole_seconds();
    if max_age <= 0 {
        return Err(BrowserSessionCookieError::Expired);
    }
    let key = decode_key(encoded_key)?;
    let session = session_id.to_string();
    let csrf = derive_csrf(&key, session_id)?;
    let signature = sign(&key, &session, &csrf)?;
    let value = format!("{COOKIE_VERSION}.{session}.{csrf}.{signature}");
    let header_value =
        format!("{COOKIE_NAME}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax");
    HeaderValue::from_str(&header_value)
        .map_err(|_| BrowserSessionCookieError::InvalidConfiguration)
}

fn verify(
    value: &str,
    encoded_key: &SecretString,
) -> Result<VerifiedSessionCookie, BrowserSessionCookieError> {
    if value.is_empty() || value.len() > MAX_COOKIE_VALUE_BYTES {
        return Err(BrowserSessionCookieError::InvalidCookie);
    }
    let mut parts = value.split('.');
    let version = parts.next();
    let session = parts.next();
    let csrf = parts.next();
    let signature = parts.next();
    if version != Some(COOKIE_VERSION) || parts.next().is_some() {
        return Err(BrowserSessionCookieError::InvalidCookie);
    }
    let session = session.ok_or(BrowserSessionCookieError::InvalidCookie)?;
    let csrf = csrf.ok_or(BrowserSessionCookieError::InvalidCookie)?;
    let signature = signature.ok_or(BrowserSessionCookieError::InvalidCookie)?;
    let session_id =
        Uuid::parse_str(session).map_err(|_| BrowserSessionCookieError::InvalidCookie)?;
    if session != session_id.to_string() {
        return Err(BrowserSessionCookieError::InvalidCookie);
    }

    let mut decoded_csrf = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(csrf)
            .map_err(|_| BrowserSessionCookieError::InvalidCookie)?,
    );
    let mut decoded_signature = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| BrowserSessionCookieError::InvalidCookie)?,
    );
    if decoded_csrf.len() != 32 || decoded_signature.len() != 32 {
        return Err(BrowserSessionCookieError::InvalidCookie);
    }

    let key = decode_key(encoded_key)?;
    let expected_csrf = derive_csrf_bytes(&key, session_id)?;
    let csrf_matches = bool::from(decoded_csrf.as_slice().ct_eq(&expected_csrf));
    let mut mac = new_mac(key.as_ref())?;
    mac.update(COOKIE_SIGNATURE_DOMAIN);
    mac.update(session.as_bytes());
    mac.update(b"\0");
    mac.update(csrf.as_bytes());
    let signature_matches = mac.verify_slice(&decoded_signature).is_ok();
    decoded_csrf.zeroize();
    decoded_signature.zeroize();
    if !csrf_matches || !signature_matches {
        return Err(BrowserSessionCookieError::InvalidCookie);
    }
    Ok(VerifiedSessionCookie {
        session_id,
        csrf_token: csrf.to_owned(),
    })
}

fn decode_key(
    encoded_key: &SecretString,
) -> Result<Zeroizing<[u8; 32]>, BrowserSessionCookieError> {
    let mut decoded = URL_SAFE_NO_PAD
        .decode(encoded_key.expose_secret())
        .map_err(|_| BrowserSessionCookieError::InvalidConfiguration)?;
    let result = decoded
        .as_slice()
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| BrowserSessionCookieError::InvalidConfiguration);
    decoded.zeroize();
    result
}

fn derive_csrf(key: &[u8; 32], session_id: Uuid) -> Result<String, BrowserSessionCookieError> {
    derive_csrf_bytes(key, session_id).map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
}

fn derive_csrf_bytes(
    key: &[u8; 32],
    session_id: Uuid,
) -> Result<[u8; 32], BrowserSessionCookieError> {
    let mut mac = new_mac(key)?;
    mac.update(CSRF_DERIVATION_DOMAIN);
    mac.update(session_id.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn sign(key: &[u8; 32], session: &str, csrf: &str) -> Result<String, BrowserSessionCookieError> {
    let mut mac = new_mac(key)?;
    mac.update(COOKIE_SIGNATURE_DOMAIN);
    mac.update(session.as_bytes());
    mac.update(b"\0");
    mac.update(csrf.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn new_mac(key: &[u8]) -> Result<HmacSha256, BrowserSessionCookieError> {
    <HmacSha256 as hmac::Mac>::new_from_slice(key)
        .map_err(|_| BrowserSessionCookieError::InvalidConfiguration)
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use http::{HeaderMap, HeaderValue, header};
    use secrecy::SecretString;
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::{clear, issue_at, verify_headers};

    fn key() -> SecretString {
        SecretString::from(URL_SAFE_NO_PAD.encode([9_u8; 32]))
    }

    #[test]
    fn issued_cookie_authenticates_and_is_host_only() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let session_id = Uuid::now_v7();
        let result = issue_at(session_id, now + Duration::hours(1), now, &key());
        assert!(result.is_ok());
        let Ok(set_cookie) = result else {
            unreachable!("valid test key must issue a cookie");
        };
        let value = set_cookie.to_str().unwrap_or_default();
        assert!(value.contains("; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"));
        assert!(!value.contains("Domain="));
        let cookie_pair = value.split(';').next().unwrap_or_default();
        let mut headers = HeaderMap::new();
        let cookie_header = HeaderValue::from_str(cookie_pair);
        assert!(cookie_header.is_ok());
        if let Ok(cookie_header) = cookie_header {
            headers.insert(header::COOKIE, cookie_header);
        }
        let verified = verify_headers(&headers, &key());
        assert!(verified.is_ok());
        if let Ok(verified) = verified {
            assert_eq!(verified.session_id, session_id);
            assert!(!verified.csrf_token.is_empty());
        }
    }

    #[test]
    fn rejects_duplicate_or_tampered_cookie() {
        let mut duplicate = HeaderMap::new();
        duplicate.insert(
            header::COOKIE,
            HeaderValue::from_static("iam_session=a; iam_session=b"),
        );
        assert!(verify_headers(&duplicate, &key()).is_err());

        let now = OffsetDateTime::UNIX_EPOCH;
        let result = issue_at(Uuid::now_v7(), now + Duration::minutes(5), now, &key());
        assert!(result.is_ok());
        if let Ok(header_value) = result {
            let pair = header_value
                .to_str()
                .unwrap_or_default()
                .split(';')
                .next()
                .unwrap_or_default();
            let tampered = format!("{pair}x");
            let mut headers = HeaderMap::new();
            let value = HeaderValue::from_str(&tampered);
            assert!(value.is_ok());
            if let Ok(value) = value {
                headers.insert(header::COOKIE, value);
            }
            assert!(verify_headers(&headers, &key()).is_err());
        }
    }

    #[test]
    fn deletion_cookie_preserves_security_attributes() {
        assert_eq!(
            clear(),
            HeaderValue::from_static(
                "iam_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
            )
        );
    }
}
