# Telemetry

IAM records operational diagnostics and browser analytics in the dedicated Space
Station table **`tos.siliconiam`**. Telemetry defaults to enabled when its private
recording key is configured. Missing or invalid configuration leaves IAM usable
without sending telemetry. This table is separate from IAM's authoritative
PostgreSQL database and security audit history.

## What is recorded

Every record includes `schema_version`, `service`, `source`, `step`, `event`,
`version`, `environment`, an instance identifier, `progress`, and structured
`context`. Sources distinguish `iam-api`, `iam-scoped-api`, `iam-worker`,
`iam-operator`, `rust-client`, `iam-cli`, `iam-daemon`, and `iam-web`.

Native events cover process lifecycle, request outcomes and durations, CLI
command names and exit status, update attempts, and worker stage progress.
Worker success heartbeats are limited to once per minute per stage. Backend
tracing records use a static callsite and level, with request IDs and span
context for correlation. The configured log filter also controls diagnostics.
Browser analytics cover page views/exits, click counts, scrolling, timings and
network outcomes; explicit events cover IAM requests, expired sessions and
render failures. Analytics and explicit events share the table and have distinct
`step` values. Browser records are marked `client_reported` and are not audit
proof.

IAM strips request/response bodies, argument values, input text, credentials,
cookies, authorization headers, email addresses, query strings, referrers and
free-form error messages. API paths are matched to contract templates so resource
IDs are omitted. Unknown paths become `<unmatched>`. Native Space Station
metadata additionally describes the runtime system and resource usage. Events
can correlate a request/invocation or a browser session without storing account
identities.

## Opt out

```sh
iam config set telemetry off
iam config show --json
# Restore the default preference:
iam config set telemetry on
```

This preference covers CLI, SDK requests made by the CLI, and its maintenance
worker. The supervised worker reloads preferences within a minute and restarts
itself when disabled to stop the embedded sender. If supervising `iam daemon
run` yourself, restart it on exit. Events already sent cannot be recalled;
previously queued records remain private on disk and can be replayed if enabled
again.

In the console or login page, expand **Telemetry settings** and clear **Share
usage and diagnostic events**. The preference persists for that browser on that
IAM site, including across tabs. Disabling clears the browser queue. CLI and web
requests propagate opt-out through `X-IAM-Telemetry: off` so backend request
spans are excluded too. Operational process events and required local security
audit records are independent of a particular user's request preference.

Set `IAM_TELEMETRY=off` before starting any IAM process for a deployment-wide
kill switch. Rust integrators can use `Client::builder(url)?.telemetry(false)`;
explicit opt-out always wins over defaults. Server configuration changes require
a restart. CI disables collection.

## Recording key and deployment

The new table's one-time write key is kept in a private `telemetry.key` file in
the operator's IAM home. It is never committed or sent to browser code. Provision
that key into each deployment's secret store, then configure either:

```sh
IAM_TELEMETRY_KEY_FILE=/run/secrets/iam-telemetry.key
IAM_TELEMETRY_HOME=/var/lib/silicon-iam/telemetry-spool
IAM_TELEMETRY=on
```

Alternatively set the server-only secret `IAM_TELEMETRY_KEY`. The key must belong
to `siliconiam`; another table's key is rejected. A key file must be a small,
regular file, mode `0600` on Unix, readable by the runtime user.

Without an explicit key-file or spool setting, IAM uses `SILICON_IAM_HOME`, then
the saved `iam config home` selection, then `$SILICON_HOME/.silicon-iam`, then
`$HOME/.silicon-iam`. Default paths are `telemetry.key` and `telemetry-spool`
inside that directory. `IAM_TELEMETRY_URL` optionally overrides the default
`https://backend.spacestation.teamofsilicons.com` with an HTTPS origin; HTTP is
permitted only on loopback for tests.

The frontend gateway accepts the same key and kill-switch settings. Never use a
`VITE_` prefix for a telemetry key. `/api/config` exposes only an enabled flag.
Browser batches go to the same-origin `/api/web/telemetry` collector, which
checks the origin, limits payload size and rate, sanitizes again, injects the
key server-side and verifies Space Station's acknowledgement. No login is
required to measure the authentication page.

Native recording uses `space-station` on macOS and Linux, with a bounded memory
queue and a private durable spool. IAM's supervised daemon keeps the sender alive
between short commands. Long-running backend processes run their own sender;
short commands without a running daemon may leave records for the next process.
A successful `flush()` means handoff, not necessarily remote acceptance.
Telemetry failure never changes an IAM operation's result.

Give each container its own writable spool volume owned by its runtime user.
Do not share Unix sockets across containers. The Compose configuration accepts
the secret through its environment and uses a private `/tmp` spool by default;
that queue is ephemeral across container recreation. For durable deployment,
mount a persistent volume and set `IAM_TELEMETRY_HOME` to it. This implementation
does not provision secrets into or restart existing production services.

## Verify delivery

Use Space Station's SQL console for organization `tos`:

```sql
SELECT record.source::String AS source,
       record.event::String AS event,
       count() AS n
FROM siliconiam
GROUP BY source, event
ORDER BY source, event
```

For an explicit native smoke event, configure the key, keep `iam daemon run`
running, and run `cargo run --example telemetry_verify`. Query its printed
request UUID under `record.context.request_id` to confirm ingestion. Never use
real credentials or personal data as diagnostic canaries.

The official integration documentation is at
[Space Station](https://spacestation.teamofsilicons.com/docs).
