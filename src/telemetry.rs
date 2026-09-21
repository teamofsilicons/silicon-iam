//! Local structured logs plus optional, allowlisted Space Station diagnostics.

use crate::config::{RuntimeEnvironment, Settings};
use serde_json::{Value, json};
use silicon_iam_client::telemetry::Telemetry;
use std::{collections::BTreeMap, fmt};
use tracing::{
    Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{
    EnvFilter, Layer,
    layer::{Context, SubscriberExt as _},
    registry::LookupSpan,
    util::SubscriberInitExt as _,
};

/// Keep this guard until process shutdown so the final records reach the spool.
pub struct Guard(Option<Telemetry>);
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(sender) = &self.0 {
            sender.record("lifecycle", "process.stopped", json!({}));
            let _ = sender.flush();
        }
    }
}

/// Install local logs and the dedicated IAM recorder.
///
/// # Errors
/// Returns an error for an invalid log filter or an already installed subscriber.
pub fn init(settings: &Settings) -> anyhow::Result<Guard> {
    init_process(settings.environment, &settings.log_filter)
}

/// Install diagnostics for APIs, workers and minimal operator processes.
///
/// # Errors
/// Returns an error for an invalid log filter or an already installed subscriber.
pub fn init_process(environment: RuntimeEnvironment, log_filter: &str) -> anyhow::Result<Guard> {
    let source = match std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|n| n.to_string_lossy().into_owned()))
        .as_deref()
    {
        Some("iam-worker") => "iam-worker",
        Some("iam-scoped-api") => "iam-scoped-api",
        Some("iam-api") => "iam-api",
        _ => "iam-operator",
    };
    let sender = match Telemetry::from_env(source, true) {
        Ok(sender) => sender,
        Err(error) => {
            eprintln!("IAM telemetry disabled: {error}");
            None
        }
    };
    let filter = EnvFilter::try_new(log_filter)?;
    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(sender.clone().map(StationLayer));
    match environment {
        RuntimeEnvironment::Development | RuntimeEnvironment::Test => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .with_target(true)
                    .with_thread_ids(false),
            )
            .try_init()?,
        RuntimeEnvironment::Production => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true)
                    .with_span_list(false),
            )
            .try_init()?,
    }
    if let Some(sender) = &sender {
        sender.record("lifecycle", "process.started", json!({}));
    }
    Ok(Guard(sender))
}

#[derive(Clone, Default)]
struct Fields {
    values: BTreeMap<String, Value>,
    opted_out: bool,
}
impl Visit for Fields {
    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "telemetry_enabled" {
            self.opted_out |= !value;
        }
        self.values.insert(field.name().into(), Value::Bool(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.values.insert(field.name().into(), Value::from(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.values.insert(field.name().into(), Value::from(value));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        // Free-form message/error fields can contain request or provider data.
        // The static tracing callsite remains the event name for diagnosis.
        let key = match field.name() {
            "worker.stage" => "stage",
            "request_id" | "route" | "method" => field.name(),
            _ => return,
        };
        self.values.insert(key.into(), Value::String(value.into()));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if matches!(
            field.name(),
            "request_id" | "route" | "method" | "worker.stage"
        ) {
            self.record_str(field, &format!("{value:?}"));
        }
    }
}
struct StationLayer(Telemetry);
impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for StationLayer {
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, context: Context<'_, S>) {
        let mut values = Fields::default();
        attributes.record(&mut values);
        if let Some(span) = context.span(id) {
            span.extensions_mut().insert(values);
        }
    }
    fn on_record(&self, id: &Id, record: &Record<'_>, context: Context<'_, S>) {
        if let Some(span) = context.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<Fields>()
        {
            record.record(fields);
        }
    }
    fn on_event(&self, event: &tracing::Event<'_>, context: Context<'_, S>) {
        if !event.metadata().target().starts_with("silicon_iam") {
            return;
        }
        let mut fields = Fields::default();
        if let Some(scope) = context.event_scope(event) {
            for span in scope.from_root() {
                if let Some(values) = span.extensions().get::<Fields>() {
                    fields.opted_out |= values.opted_out;
                    fields.values.extend(values.values.clone());
                }
            }
        }
        event.record(&mut fields);
        if fields.opted_out {
            return;
        }
        fields
            .values
            .insert("level".into(), event.metadata().level().as_str().into());
        fields
            .values
            .insert("target".into(), event.metadata().target().into());
        fields.values.insert(
            "line".into(),
            Value::from(event.metadata().line().unwrap_or(0)),
        );
        self.0.record(
            "diagnostic",
            event.metadata().name(),
            serde_json::to_value(fields.values).unwrap_or(Value::Null),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn request_span_opt_out_blocks_descendant_events_and_preserves_safe_context()
    -> anyhow::Result<()> {
        let home = std::env::temp_dir().join(format!(
            "iam-telemetry-test-{}",
            crate::domain::id::Id::now_v7()
        ));
        let sender = Telemetry::new(
            "table-siliconiam-0123456789abcdef0123456789abcdef",
            "http://127.0.0.1:1",
            &home,
            "test",
        )
        .map_err(anyhow::Error::msg)?;
        let subscriber = tracing_subscriber::registry().with(StationLayer(sender.clone()));
        tracing::subscriber::with_default(subscriber, || {
            let hidden = tracing::info_span!("request", telemetry_enabled = false);
            hidden.in_scope(|| {
                let child = tracing::info_span!("child", telemetry_enabled = true);
                child.in_scope(|| tracing::warn!(target: "silicon_iam::test", "must not collect"));
            });
            let allowed = tracing::info_span!(
                "request",
                telemetry_enabled = true,
                request_id = "00000000-0000-0000-0000-000000000001",
                route = "/api/v1/me",
                status = 201_u64
            );
            allowed.in_scope(|| tracing::info!(target: "silicon_iam::test", error = "secret-canary", "private-canary"));
        });
        let _ = sender.flush();
        let spool = std::fs::read_to_string(home.join("spool.jsonl"))?;
        let rows: Vec<Value> = spool
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0]["record"]["context"]["request_id"],
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(rows[0]["record"]["context"]["status"], 201);
        assert!(!spool.contains("secret-canary") && !spool.contains("private-canary"));
        let _ = std::fs::remove_dir_all(home);
        Ok(())
    }

    #[test]
    fn diagnostic_fields_omit_dynamic_messages_and_honor_request_opt_out() {
        #[derive(Clone)]
        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<Fields>>>);
        impl<S: Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                let mut fields = Fields::default();
                event.record(&mut fields);
                if let Ok(mut values) = self.0.lock() {
                    values.push(fields);
                }
            }
        }
        let values = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Capture(values.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                telemetry_enabled = false,
                request_id = "00000000-0000-0000-0000-000000000001",
                error = "stk-secret",
                "email@example.com"
            );
        });
        let Ok(values) = values.lock() else {
            panic!("capture lock");
        };
        assert!(values[0].opted_out);
        assert!(!values[0].values.contains_key("message"));
        assert!(!values[0].values.contains_key("error"));
    }
}
