//! Explicit live verification against the operator-configured IAM telemetry table.
//! Run only when you intend to write diagnostic verification events.
use silicon_iam::{config::RuntimeEnvironment, telemetry};
use silicon_iam_client::telemetry::Telemetry;

fn main() -> anyhow::Result<()> {
    let _guard = telemetry::init_process(RuntimeEnvironment::Development, "silicon_iam=info")?;
    let recorder = Telemetry::from_env("verification", true)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| {
            anyhow::anyhow!("Configure IAM_TELEMETRY_KEY_FILE and enable telemetry first")
        })?;
    let request_id = uuid::Uuid::now_v7();
    let span = tracing::info_span!(target: "silicon_iam::telemetry::verification", "verification.request", request_id=%request_id, method="GET", route="/api/v1/me", status=200, latency_ms=1_u64, telemetry_enabled=true);
    span.in_scope(|| tracing::info!(target: "silicon_iam::telemetry::verification", "explicit verification completed"));
    recorder.record(
        "verification",
        "verification.completed",
        serde_json::json!({"request_id":request_id, "success":true}),
    );
    for _ in 0..10 {
        if recorder.flush() {
            println!(
                "Telemetry handed off. Verify request {request_id} by querying tos.siliconiam; handoff alone is not proof of acceptance."
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    anyhow::bail!(
        "Telemetry remains queued; inspect the private spool and Space Station availability"
    )
}
