//! Fixed-provider OIDC token exchange. Provider responses and credentials are
//! deliberately absent from error messages and diagnostics.
use std::time::Duration;

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use reqwest::{Client, Response, redirect::Policy};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, de::DeserializeOwned};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::error::AppError;

const RESPONSE_LIMIT: usize = 64 * 1024;

pub(super) struct VerifiedIdentity {
    pub(super) subject: String,
    pub(super) email: String,
    pub(super) display_name: Option<String>,
}

#[derive(Deserialize)]
struct TokenReply {
    id_token: String,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Deserialize)]
struct Claims {
    sub: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    nonce: String,
    email: String,
    email_verified: serde_json::Value,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    azp: Option<String>,
}

fn provider_endpoints(
    provider: &str,
) -> Result<(&'static str, &'static str, &'static [&'static str]), AppError> {
    match provider {
        "google" => Ok((
            "https://oauth2.googleapis.com/token",
            "https://www.googleapis.com/oauth2/v3/certs",
            &["https://accounts.google.com", "accounts.google.com"],
        )),
        "apple" => Ok((
            "https://appleid.apple.com/auth/token",
            "https://appleid.apple.com/auth/keys",
            &["https://appleid.apple.com"],
        )),
        _ => Err(AppError::Unauthenticated),
    }
}

async fn bounded_json<T: DeserializeOwned>(mut response: Response) -> Result<T, AppError> {
    if response
        .content_length()
        .is_some_and(|size| size > RESPONSE_LIMIT as u64)
    {
        return Err(AppError::ProviderUnavailable);
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppError::ProviderUnavailable)?
    {
        if body.len().saturating_add(chunk.len()) > RESPONSE_LIMIT {
            return Err(AppError::ProviderUnavailable);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| AppError::ProviderUnavailable)
}

pub(super) async fn exchange(
    provider: &str,
    client_id: &str,
    client_secret: &SecretString,
    redirect_uri: &str,
    code: &str,
    nonce: &str,
    pkce: &str,
) -> Result<VerifiedIdentity, AppError> {
    let (token_url, jwks_url, _) = provider_endpoints(provider)?;
    if client_id.is_empty()
        || code.is_empty()
        || code.len() > 8192
        || nonce.is_empty()
        || (provider == "google" && !(43..=128).contains(&pkce.len()))
    {
        return Err(AppError::Unauthenticated);
    }
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .redirect(Policy::none())
        .user_agent(concat!("silicon-iam/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| AppError::ProviderUnavailable)?;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("client_secret", client_secret.expose_secret()),
        ("redirect_uri", redirect_uri),
        ("code", code),
    ];
    if provider == "google" {
        form.push(("code_verifier", pkce));
    }
    let response = client
        .post(token_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|_| AppError::ProviderUnavailable)?;
    if !response.status().is_success() {
        return Err(if response.status().is_client_error() {
            AppError::Unauthenticated
        } else {
            AppError::ProviderUnavailable
        });
    }
    let reply: TokenReply = bounded_json(response).await?;
    let token = Zeroizing::new(reply.id_token);
    if token.len() > RESPONSE_LIMIT {
        return Err(AppError::Unauthenticated);
    }
    let response = client
        .get(jwks_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| AppError::ProviderUnavailable)?;
    if !response.status().is_success() {
        return Err(AppError::ProviderUnavailable);
    }
    let keys: JwkSet = bounded_json(response).await?;
    validate_identity(provider, client_id, &token, nonce, &keys)
}

fn validate_identity(
    provider: &str,
    client_id: &str,
    token: &str,
    nonce: &str,
    keys: &JwkSet,
) -> Result<VerifiedIdentity, AppError> {
    let (_, _, issuers) = provider_endpoints(provider)?;
    let header = decode_header(token).map_err(|_| AppError::Unauthenticated)?;
    if header.alg != Algorithm::RS256
        || header
            .crit
            .as_ref()
            .is_some_and(|values| !values.is_empty())
        || header.jku.is_some()
        || header.jwk.is_some()
        || header.x5u.is_some()
    {
        return Err(AppError::Unauthenticated);
    }
    let kid = header
        .kid
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(AppError::Unauthenticated)?;
    let mut matches = keys
        .keys
        .iter()
        .filter(|key| key.common.key_id.as_deref() == Some(&kid));
    let key = matches.next().ok_or(AppError::Unauthenticated)?;
    if matches.next().is_some()
        || !matches!(key.algorithm, AlgorithmParameters::RSA(_))
        || key
            .common
            .key_algorithm
            .is_some_and(|algorithm| algorithm != KeyAlgorithm::RS256)
        || key
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|usage| *usage != PublicKeyUse::Signature)
        || key
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        return Err(AppError::Unauthenticated);
    }
    let decoding_key = DecodingKey::from_jwk(key).map_err(|_| AppError::Unauthenticated)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(issuers);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.validate_nbf = true;
    validation.leeway = 0;
    let claims = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::Unauthenticated)?
        .claims;
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| AppError::Unauthenticated)?;
    let audience_valid = match &claims.aud {
        Audience::Single(audience) => audience == client_id,
        Audience::Multiple(audiences) => {
            !audiences.is_empty()
                && audiences.iter().any(|audience| audience == client_id)
                && (audiences.len() == 1 || claims.azp.as_deref() == Some(client_id))
        }
    };
    let verified_email = claims.email_verified == serde_json::Value::Bool(true)
        || (provider == "apple"
            && claims.email_verified == serde_json::Value::String("true".to_owned()));
    if !audience_valid
        || claims
            .azp
            .as_deref()
            .is_some_and(|party| party != client_id)
        || claims.sub.is_empty()
        || claims.sub.len() > 255
        || claims.sub.chars().any(char::is_control)
        || claims.iat == 0
        || claims.iat > now.saturating_add(60)
        || claims.iat >= claims.exp
        || claims.exp <= now
        || nonce.is_empty()
        || !bool::from(claims.nonce.as_bytes().ct_eq(nonce.as_bytes()))
        || !verified_email
        || claims.email.is_empty()
        || claims.email.len() > 254
        || claims.email.trim() != claims.email
        || claims.email.chars().any(char::is_control)
        || !claims.email.contains('@')
    {
        return Err(AppError::Unauthenticated);
    }
    Ok(VerifiedIdentity {
        subject: claims.sub,
        email: claims.email,
        display_name: claims.name.filter(|name| {
            !name.trim().is_empty() && name.len() <= 200 && !name.chars().any(char::is_control)
        }),
    })
}

#[allow(clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::{Value, json};
    // Public test fixture only; this key is never used by the application.
    const TEST_PRIVATE_KEY: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3SPxLTv0hY4sJ
BUuhOMv7VlpxrncvfDL2BX5bOq9UudblQo8d/S3fi9if74zy9ezVgS1O8zRZBKju
cwZ5FaQplkAvS0Ril3lGtInSmOiFY55WKhlGlMx5EQw/756YDmJkUUrEmC3sQ9z4
9RjDe10Kgez3Ppr3Sd2LanEfw5YPeqFgL9VKSXIaYFwBmj+qXbgs++ddzRPrLW0t
2+9VEzbZRbHVOdlLxixv9aajB9eubMppO5GQxYzQLNHb0Of/04TcalpwusWB9tdP
8exjXrnv0VtdrPYDIUIGOirHGw5sGMkf+Xi2mZbSWB7mzDFhFxU64Z9JyuoC8FDa
aEPHNg/fAgMBAAECggEASDlRedeRdfPE2PQmPkykTNFVaJCoVKTra/j0NrzkVE26
+bKFtPqMdhekcDm0YBU6k1OI6CB8E0v7yaK3/UTi4KRdfIV7WCJ6XrtLyBoLHm0H
+soyFZcTD+4A1rz00NRyPzetb9TL29tOGyhx7q4RFs/l8fPQmvuXepWiKDMpUcWD
lDueGNW+K31LclN+JdlNjchZt9sNqLqCq9dBO5yp/vUAjtTy+S0HnJhFFkVgvZOB
VhDcEbTZlc3fcId5R2SJ/MlAAgzHtS9jWV0KMMJHAza/yrnXcS/7/B/RZZqrsPqe
uRbz6c3ZgeSYkpJEfNZLTWDZlxssT0ewAOOHnamVgQKBgQD58ZAlUPxqFskXPBnR
Vor+esSMlrMEtPHp0y1nqYyShu82UP3zmq8M2Vw29Og083zXhVqjz5k/zcnlGr4C
tcD464e+VEBWXMMD+L3mAcTWqPsJ5/A9rf5Mn8cP2E+fYDEc3hueSWi5mLwFYY6+
SZdIygxRe9dj8ubaUL45/zl5HwKBgQC7ue4Qsv2PSvBs+NI8utzugE5MRe3sFTDx
J9lpjlftJ8CLjqW6oQWCpDX+UjJmjz0pOhQ8hs6NRyXCjRTmZBh1+xA4krYSiiJn
QMvYU/nn+v8Cr/+wlJWrLnGfflUZ0a7+d7dw2M6xoXnQ/H5Ws0W1MDrAqli4WJ57
ALPgbsTRQQKBgBZm8laF5bnUhP2SI3ZB3X9lnYxETZNUbIJarS0nYzQW6AXkSH63
FI2AReWfGdj1IfFnQHKCPugbF8dzGCjCBaPJ6IbEomebNNd8Sfj9m5jp2GZQ5ZWB
rNNNVtgyuSA9zOkbdzo+tiY8bE3HKrYffnHFukjrYqjQsqRKrGIiYBJdAoGAOnCt
TgGKsfsQUbw8Jq+9a3oB5fi3EpGeRNS0+AlaEfgYFtn3edv6zSq1rFCGZCsfTSBJ
gHYvAwgtFx24beinPMNFz3bMu4TJJP+k9dleqPsYPAvyO1RmK34v3QkFER6XrZwz
PSwhXGb6dzbDVdZFUxyKjcP6Dpl37K7RUILrPoECgYEA6thQ9YxsfLz0o12aEQpM
vcpamLvxkxdw8mhCyfsjeV/BSHQ6kfHZDmWJGckMR4Vzvd4uFsR7kv8A84alzYYO
VM5Mka3D7F7Ctmfshiivdy0uC09o0j6bEpV6MvHD2wwPcAnSvjqTo+4Ignejjhc1
IrGq/9Lz/9jPEqvE1azV+ns=
-----END PRIVATE KEY-----
";
    const MODULUS: &str = "t0j8S079IWOLCQVLoTjL-1Zaca53L3wy9gV-WzqvVLnW5UKPHf0t34vYn--M8vXs1YEtTvM0WQSo7nMGeRWkKZZAL0tEYpd5RrSJ0pjohWOeVioZRpTMeREMP--emA5iZFFKxJgt7EPc-PUYw3tdCoHs9z6a90ndi2pxH8OWD3qhYC_VSklyGmBcAZo_ql24LPvnXc0T6y1tLdvvVRM22UWx1TnZS8Ysb_WmowfXrmzKaTuRkMWM0CzR29Dn_9OE3GpacLrFgfbXT_HsY16579FbXaz2AyFCBjoqxxsObBjJH_l4tpmW0lge5swxYRcVOuGfScrqAvBQ2mhDxzYP3w";
    fn keys() -> JwkSet {
        serde_json::from_value(json!({"keys":[{"kty":"RSA","kid":"fixture","use":"sig","alg":"RS256","n":MODULUS,"e":"AQAB"}]})).expect("fixture JWKS")
    }
    fn claims(provider: &str) -> Value {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        json!({"iss":if provider=="apple" {"https://appleid.apple.com"} else {"https://accounts.google.com"},"aud":"iam-client","sub":"subject-123","exp":now+600,"iat":now,"nonce":"request-bound-nonce","email":"member@example.test","email_verified":true,"name":"Test Member"})
    }
    fn token(claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("fixture".to_owned());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).expect("fixture RSA"),
        )
        .expect("signed fixture")
    }
    fn check(provider: &str, claims: &Value) -> Result<VerifiedIdentity, AppError> {
        validate_identity(
            provider,
            "iam-client",
            &token(claims),
            "request-bound-nonce",
            &keys(),
        )
    }
    #[test]
    fn valid_provider_signatures_return_only_verified_identity() {
        for provider in ["google", "apple"] {
            let identity = check(provider, &claims(provider)).expect("valid provider claims");
            assert_eq!(identity.subject, "subject-123");
            assert_eq!(identity.email, "member@example.test");
            assert_eq!(identity.display_name.as_deref(), Some("Test Member"));
        }
    }
    #[test]
    fn rejects_wrong_audience_issuer_nonce_expiry_issued_at_and_subject() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        for (field, replacement) in [
            ("aud", json!("different-client")),
            ("iss", json!("https://attacker.example")),
            ("nonce", json!("different-request")),
            ("exp", json!(now - 1)),
            ("iat", json!(now + 120)),
            ("sub", json!("")),
            ("azp", json!("different-client")),
            ("email_verified", json!(false)),
            ("email_verified", json!("true")),
        ] {
            let mut value = claims("google");
            value[field] = replacement;
            assert!(check("google", &value).is_err(), "must reject {field}");
        }
    }
    #[test]
    fn apple_accepts_true_string_but_never_unverified_email() {
        let mut value = claims("apple");
        value["email_verified"] = json!("true");
        assert!(check("apple", &value).is_ok());
        for unverified in [json!("false"), json!(false), json!(null), json!(1)] {
            value["email_verified"] = unverified;
            assert!(check("apple", &value).is_err());
        }
    }
    #[test]
    fn missing_required_or_multiple_audience_claims_fail_closed() {
        for field in [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "nonce",
            "email",
            "email_verified",
        ] {
            let mut value = claims("google");
            value.as_object_mut().expect("object").remove(field);
            assert!(check("google", &value).is_err(), "missing {field}");
        }
        let mut value = claims("google");
        value["aud"] = json!(["iam-client", "other"]);
        assert!(check("google", &value).is_err());
        value["azp"] = json!("iam-client");
        assert!(check("google", &value).is_ok());
    }
    #[test]
    fn rejects_wrong_signature_unknown_kid_duplicate_kid_and_injected_keys() {
        let original = token(&claims("google"));
        let mut altered = original.as_bytes().to_vec();
        let start = original.rfind('.').expect("signature") + 1;
        altered[start] = if altered[start] == b'A' { b'B' } else { b'A' };
        assert!(
            validate_identity(
                "google",
                "iam-client",
                std::str::from_utf8(&altered).expect("jwt"),
                "request-bound-nonce",
                &keys()
            )
            .is_err()
        );
        let mut missing = keys();
        missing.keys[0].common.key_id = Some("different".into());
        assert!(
            validate_identity(
                "google",
                "iam-client",
                &original,
                "request-bound-nonce",
                &missing
            )
            .is_err()
        );
        let mut duplicate = keys();
        duplicate.keys.push(duplicate.keys[0].clone());
        assert!(
            validate_identity(
                "google",
                "iam-client",
                &original,
                "request-bound-nonce",
                &duplicate
            )
            .is_err()
        );
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("fixture".into());
        header.jku = Some("https://attacker.example/keys".into());
        let injected = encode(
            &header,
            &claims("google"),
            &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).expect("key"),
        )
        .expect("token");
        assert!(
            validate_identity(
                "google",
                "iam-client",
                &injected,
                "request-bound-nonce",
                &keys()
            )
            .is_err()
        );
    }
    #[test]
    fn rejects_hmac_algorithm_confusion_and_wrong_key_purpose() {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("fixture".into());
        let token = encode(
            &header,
            &claims("google"),
            &EncodingKey::from_secret(b"public-key-like-input"),
        )
        .expect("HMAC fixture");
        assert!(
            validate_identity(
                "google",
                "iam-client",
                &token,
                "request-bound-nonce",
                &keys()
            )
            .is_err()
        );
        let mut encryption = keys();
        encryption.keys[0].common.public_key_use = Some(PublicKeyUse::Encryption);
        assert!(
            validate_identity(
                "google",
                "iam-client",
                &super::tests::token(&claims("google")),
                "request-bound-nonce",
                &encryption
            )
            .is_err()
        );
    }
}
