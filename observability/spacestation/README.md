# IAM Space Windows

Four published windows read `tos.siliconiam`. IDs, URLs, access and published
versions are recorded in `windows.json`. Access matches the telemetry table
(`@saket`). The sources contain no credentials or production event fixtures.

| Window | Contents |
| --- | --- |
| IAM Overview | Production event volume, errors, warnings and source freshness |
| IAM Requests | Production API traffic, 4xx/5xx counts, route latency and recent requests |
| IAM Diagnostics | Production diagnostic signals and worker stage progress |
| IAM Web & CLI | Browser pages, sessions, SDK requests, CLI and daemon activity |

Each window covers the last 24 hours and initializes from live SQL before
subscribing to table changes. Opening a window starts Space Station's live
runtime; a cached snapshot remains available when no runtime is connected.
No additional IAM deployment or permanent local process is required.

## Metric definitions

- Requests exclude `/healthz` and `/readyz`. The overall P95 is queried over all
  included requests, independently of the top-50 route table. 4xx responses
  include expected refusals and are displayed separately from 5xx responses.
- Error counts represent events, not unique incidents. Source freshness records
  the last telemetry event; it does not prove service availability. Worker stage
  signals include sampled heartbeats and are not processed-job counts.
- Client activity includes client environments, shown separately. Sessions are
  browser sessions, not unique people; per-page session counts overlap.
- Optional status, success and latency fields use `Nullable` casts. Plain casts
  turn missing JSON fields into zero/false, which incorrectly classifies events.
- Recent rows and grouped tables are bounded. The client cards summarize the
  displayed source/environment/event groups (up to 70). Filters only affect
  visible table rows. Window JSON stores each table's rows once under `raw` and
  trims large arrays to stay below the 64 KB runtime limit.
- `summary` returns the current cards. `trace_request` validates a request UUID
  and returns up to 40 correlated events across sources, in chronological order,
  from the last 24 hours. Its SQL projects diagnostic metadata only.

## Editing and publishing

Edit query definitions and presentation logic in `build.py`, then regenerate:

```sh
python3 observability/spacestation/build.py
```

`renderer.html` is shared by all windows. It runs inside Space Station's sandbox
and uses the injected `mission_control` interface for state and tools. Vue and
D3 are loaded from pinned CDN URLs.

Publish a new version to each existing window ID (do not create duplicates):
`POST /api/orgs/tos/windows/{id}/versions` with JSON fields `name`, `processor`
and `renderer`. Use that window's generated `processor.js` and the shared HTML.
Authenticate with a Space Station CLI session obtained through Silicon IAM;
keep its bearer token outside the repository and command arguments. Update
`windows.json` after successful publication. The recording key is not a window
query/publishing credential.

The official Space Station `mission-control.js run` command can verify live
processor execution, and `mission-control.js tool` can verify tools. Supply an
existing organization access token through `SPACE_STATION_ACCESS_TOKEN`; stop
temporary runners after testing. Confirm the window state endpoint reports the
expected title and versions, and compare published processor/renderer content
with the local source. Finally open each URL and inspect the renderer.

## Initial verification

On 2026-09-13, every SQL query executed successfully against the production
table. All four generated processors initialized, replayed snapshot updates
without changing metric semantics, rejected an invalid request UUID, and stayed
within the runtime state limit. The official runtime connected and published
live snapshots for all four windows. The request trace tool returned a matching
production event for a known request UUID.

Version `v1.1` replaces sandbox-blocked form submission with a direct tool button
and Enter-key handler. Browser verification confirmed the request trace returned
a matching event and table filtering selected only the requested source.
