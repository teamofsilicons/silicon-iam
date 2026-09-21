//! Independent, signed, durable management notifications to Honeycomb.
use super::WorkerContext;
use crate::domain::id::Id;
use hmac::{Hmac, Mac as _};
use secrecy::ExposeSecret as _;
use serde_json::Value;
use sha2::Sha256;

fn signature(key: &[u8], timestamp: i64, body: &[u8]) -> anyhow::Result<String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid signing key"))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!(
        "t={timestamp},v1={}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

pub(super) async fn process_batch(context: &WorkerContext) -> anyhow::Result<()> {
    let Some(settings) = &context.settings.honeycomb_notifications else {
        return Ok(());
    };
    // Destination is an operator-controlled subscription. No redirects and no
    // application-provided URL can influence the recipient or signing key.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let rows=sqlx::query_as::<_,(Id,i32,sqlx::types::Json<Value>)>("SELECT event_id,attempt_count,envelope FROM iam_private.claim_honeycomb_management_events($1)")
        .bind(&settings.app_id).fetch_all(&context.pool).await?;
    for (id, attempt, envelope) in rows {
        let body = serde_json::to_vec(&envelope.0)?;
        let signature = signature(
            settings.signing_key.expose_secret().as_bytes(),
            time::OffsetDateTime::now_utc().unix_timestamp(),
            &body,
        )?;
        let delivered = client
            .post(settings.url.clone())
            .header("content-type", "application/json")
            .header("x-iam-management-signature", signature)
            .body(body)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success());
        sqlx::query("SELECT iam_private.finish_honeycomb_management_event($1,$2,$3)")
            .bind(id)
            .bind(attempt)
            .bind(delivered)
            .execute(&context.pool)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_binds_timestamp_and_complete_raw_body() -> anyhow::Result<()> {
        let key = b"independent-management-signing-key";
        let signed = signature(key, 123, b"{\"revision\":1}")?;
        assert_ne!(signed, signature(key, 124, b"{\"revision\":1}")?);
        assert_ne!(signed, signature(key, 123, b"{\"revision\":2}")?);
        assert_ne!(
            signed,
            signature(b"different-key", 123, b"{\"revision\":1}")?
        );
        assert_eq!(signed, signature(key, 123, b"{\"revision\":1}")?);
        Ok(())
    }
}
