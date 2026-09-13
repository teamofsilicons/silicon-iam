//! Signed notifications for the registered scoped IAM application.
//!
//! IAM itself remains the authoritative store, and every application request
//! revalidates its session and grants there. This receiver deliberately keeps no
//! second user/session cache and emits no domain events, preventing webhook loops.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use silicon_iam_client::webhook::{
    DEFAULT_MAX_WEBHOOK_BODY_BYTES, WebhookSecret, WebhookSecretKeyring, WebhookVerifier,
};
use tower_http::limit::RequestBodyLimitLayer;

use super::ApiState;
use crate::error::AppError;

const KEYRING_ENV: &str = "IAM_SCOPED_WEBHOOK_KEYRING";

pub(super) fn router() -> anyhow::Result<Router<ApiState>> {
    match std::env::var(KEYRING_ENV) {
        Ok(value) => Ok(configured_router(Arc::new(verifier(&value)?))),
        Err(std::env::VarError::NotPresent) => Ok(Router::new()),
        Err(_) => anyhow::bail!("invalid scoped webhook keyring encoding"),
    }
}

fn verifier(value: &str) -> anyhow::Result<WebhookVerifier> {
    let entries: BTreeMap<i64, String> = serde_json::from_str(value)
        .map_err(|_| anyhow::anyhow!("scoped webhook keyring must map versions to secrets"))?;
    anyhow::ensure!(
        !entries.is_empty(),
        "scoped webhook keyring cannot be empty"
    );
    let mut keyring = WebhookSecretKeyring::default();
    for (version, secret) in entries {
        keyring.insert(version, WebhookSecret::new(secret)?)?;
    }
    Ok(WebhookVerifier::new(keyring))
}

fn configured_router<S: Clone + Send + Sync + 'static>(
    verifier: Arc<WebhookVerifier>,
) -> Router<S> {
    Router::new()
        .route("/webhooks/iam", post(receive))
        .layer(RequestBodyLimitLayer::new(DEFAULT_MAX_WEBHOOK_BODY_BYTES))
        .with_state(verifier)
}

async fn receive(
    State(verifier): State<Arc<WebhookVerifier>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let event = verifier
        .verify(&headers, &body)
        .map_err(|_| AppError::Unauthenticated)?;
    // Test imports have independent keys and environment identities. Never
    // accept a testing envelope through this production receiver.
    if event.is_testing() {
        return Err(AppError::Unauthenticated);
    }
    // A repeated valid delivery is harmless: no data is logged, persisted,
    // forwarded, or mutated, and live authorization never depends on delivery.
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use hmac::{Hmac, Mac as _};
    use serde_json::{Value, json};
    use sha2::Sha256;
    use time::OffsetDateTime;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    const SECRET: &str = "scoped-iam-webhook-test-secret-at-least-32";

    fn event() -> Value {
        json!({
            "spec_version": "1.0", "event_id": Uuid::from_u128(1),
            "event_type": "organization.membership.created.v1",
            "occurred_at": "2026-09-13T00:00:00Z",
            "aggregate": {"type": "membership", "id": Uuid::from_u128(2), "version": 1},
            "data": {}
        })
    }

    fn signed(body: &[u8], timestamp: i64, version: i64) -> anyhow::Result<HeaderMap> {
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes())?;
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        let mut headers = HeaderMap::new();
        for (key, value) in [
            ("x-silicon-iam-event-id", Uuid::from_u128(1).to_string()),
            ("x-silicon-iam-timestamp", timestamp.to_string()),
            ("x-silicon-iam-key-version", version.to_string()),
            (
                "x-silicon-iam-signature",
                format!("v1={}", hex::encode(mac.finalize().into_bytes())),
            ),
        ] {
            headers.insert(key, value.parse()?);
        }
        Ok(headers)
    }

    async fn status(body: Vec<u8>, headers: HeaderMap) -> anyhow::Result<StatusCode> {
        let verifier = verifier(&json!({"1": SECRET}).to_string())?;
        // The receiver's own state is complete; these tests need no database.
        let app: Router = configured_router(Arc::new(verifier));
        let mut request = Request::post("/webhooks/iam").body(Body::from(body))?;
        *request.headers_mut() = headers;
        Ok(app.oneshot(request).await?.status())
    }

    #[tokio::test]
    async fn authenticates_raw_bytes_and_accepts_harmless_retries() -> anyhow::Result<()> {
        let body = serde_json::to_vec(&event())?;
        let headers = signed(&body, OffsetDateTime::now_utc().unix_timestamp(), 1)?;
        for _ in 0..2 {
            assert_eq!(
                status(body.clone(), headers.clone()).await?,
                StatusCode::NO_CONTENT
            );
        }
        let mut tampered = body.clone();
        tampered.push(b' ');
        assert_eq!(status(tampered, headers).await?, StatusCode::UNAUTHORIZED);
        assert_eq!(
            status(body, HeaderMap::new()).await?,
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_stale_versions_duplicates_and_testing_envelopes() -> anyhow::Result<()> {
        let body = serde_json::to_vec(&event())?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        for headers in [signed(&body, now - 301, 1)?, signed(&body, now, 2)?] {
            assert_eq!(
                status(body.clone(), headers).await?,
                StatusCode::UNAUTHORIZED
            );
        }
        let mut headers = signed(&body, now, 1)?;
        headers.append("x-silicon-iam-key-version", "1".parse()?);
        assert_eq!(status(body, headers).await?, StatusCode::UNAUTHORIZED);
        let mut metadata = event();
        metadata
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("fixture"))?
            .remove("data");
        let test = serde_json::to_vec(&json!({"test": {
            "testing_key": "silicon_iam_test_abcdefghijklmnopqrstuvwxyz0123456789",
            "metadata": metadata, "data": {}
        }}))?;
        let headers = signed(&test, now, 1)?;
        assert_eq!(status(test, headers).await?, StatusCode::UNAUTHORIZED);
        let oversized = vec![b' '; DEFAULT_MAX_WEBHOOK_BODY_BYTES + 1];
        assert_eq!(
            status(oversized, HeaderMap::new()).await?,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        Ok(())
    }

    #[test]
    fn configuration_is_fail_closed_and_redacts_secrets() -> anyhow::Result<()> {
        for input in [
            "{}",
            "[]",
            "not-json",
            r#"{"0":"scoped-iam-webhook-test-secret-at-least-32"}"#,
        ] {
            assert!(verifier(input).is_err());
        }
        let configured = verifier(&json!({"1": SECRET, "2": SECRET}).to_string())?;
        assert!(configured.keyring().contains_version(1));
        assert!(configured.keyring().contains_version(2));
        assert!(!format!("{configured:?}").contains(SECRET));
        Ok(())
    }
}
