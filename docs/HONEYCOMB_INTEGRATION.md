# IAM integration for Honeycomb

IAM accepts authentication configuration and enforces current identity, consent,
organization and provider permissions. Honeycomb owns the app catalog, review
workflow, releases, bundle editing and shared test-environment coordination.
The canonical wire contract is [OpenAPI](openapi.yaml); the stateless Rust entry
point is `silicon_iam_client::honeycomb::ManagementClient`.

## Provision the integration

Migrate both IAM databases and apply `deploy/postgres/runtime-grants.sql` to each.
Keep the production and testing databases separate. The API uses its restricted
runtime role; bootstrap uses operator database authority.

Once an active Carbon owner and organization exist, provision the two initial
app identities without a catalog:

```sh
iam-bootstrap-apps --org-id '<org>' --carbon-id '<owner>' \
  --iam-app-id '<org>iam' --honeycomb-app-id '<org>honeycomb' \
  --output /secure/operator/iam-honeycomb-bootstrap.json
```

Use the normal IAM encryption/keyring settings and an operator `IAM_DATABASE_URL`.
The command creates a private, exclusive output file before committing changes.
Retain that same file across retries. Existing app IDs and credentials are
preserved; new app secrets appear only for newly created identities. The file
contains a separate random `hck_` service credential and an independent management
notification signing key. Deliver them through deployment secret storage. Do not
put this file in a release archive or repository.

Configure the IAM API:

- `IAM_HONEYCOMB_APP_ID`: the Honeycomb authentication app ID.
- `IAM_HONEYCOMB_CREDENTIAL_SHA256`: lowercase SHA-256 hex of the complete random
  `hck_` credential. Only Honeycomb stores the plaintext service credential.
- `IAM_HONEYCOMB_SCHEDULED_TESTING`: default `false`; explicitly enable to allow
  service-authored maintenance on environments already assigned to Honeycomb.

Configure the IAM worker independently:

- `IAM_HONEYCOMB_APP_ID`: the same identity.
- `IAM_HONEYCOMB_NOTIFICATION_URL`: Honeycomb's HTTPS management receiver.
- `IAM_HONEYCOMB_NOTIFICATION_SIGNING_KEY`: the separate shared HMAC key.

The worker does not require the service credential. App webhook URLs and keys do
not control management notifications. Initial signup, login, backend deployment
and direct CLI installation work before Honeycomb exists. See
[CLI packaging and direct installation](HONEYCOMB_RELEASE.md).

## Authentication and mutation envelope

All `/api/v1/honeycomb/*` requests use `Authorization: Bearer hck_…`. Ordinary
`ask_`, user tokens and test root keys never grant this authority. Do not send
`X-Testing-Environment-Key`; test instructions name their environment explicitly.

User-triggered writes additionally use `X-Honeycomb-Actor-Token: oat_…`, a live
Carbon token whose client and audience are the provisioned Honeycomb identity.
IAM checks the current session, selected organization grant, live membership
and required manager/reviewer authority. A supplied identity or role is not proof.
Silicons cannot act as organization owners/admins in this IAM contract.

Writes carry an `operation_id` UUID, `Idempotency-Key` and
`expected_iam_revision` (zero only when creating). Keep the exact serialized body,
operation ID and key for retries. Keys are bound to service, actor, operation,
resource and body. Changed content conflicts. IAM revisions are read from IAM;
`configuration_revision` is Honeycomb's increasing configuration number.
Neither is a release version, and revisions need not increase by exactly one.
Production configuration uses absent/null `environment_id`.

Sensitive mutations require `X-Step-Up-Token`, obtained through the existing IAM
verified-channel flow for the same actor session, action and application UUID:

| Mutation | Step-up action |
| --- | --- |
| App secret rotation | `application.client_secret.rotate` |
| Webhook destination approval | `application.webhook.approve` |
| Webhook signing-secret rotation | `application.webhook_secret.rotate` |

An authorized retry of a completed operation does not consume a second proof.
The mutation response has `Idempotency-Replayed`. Secrets are encrypted for a
10-minute replay window; afterward the original durable receipt remains and
returns `secret_replay_expired: true` without generating new credentials.
Reconciliation and notifications never contain secrets. Recover a lost expired
secret with a new explicitly authorized rotation.

## Accepted app and bundle configuration

| Method and path, relative to `/api/v1/honeycomb` | Purpose |
| --- | --- |
| `GET /scope-catalog?org_id=…&app_id=…` | Current scope definitions, review requirements and organization eligibility; filters optional |
| `PUT /applications/{app_id}/configuration` | Accept identity-bound authentication configuration |
| `POST /applications/{app_id}/scope-decisions` | Record an exact live provider/IAM reviewer decision |
| `POST /applications/{app_id}/webhook-approvals` | Activate the exact pending destination |
| `POST /applications/{app_id}/secret-rotations` | Rotate the app credential once |
| `POST /applications/{app_id}/webhook-secret-rotations` | Rotate supplied signing material, with ten-minute old-key overlap |
| `PUT /bundles/{bundle_id}/configuration` | Accept eligible same-organization app membership or deletion |
| `GET /applications/{app_id}` | Current accepted record and revisions |
| `GET /bundles/{bundle_id}` | Current accepted bundle, including deletion state |
| `GET /operations/{operation_id}` | Durable progress and secret-free result |
| `GET /inventory?kind=applications\|bundles\|testing-environments` | Adoption inventory; paginate with returned `next_after` as `after` |

IDs and owning organizations are immutable. Changing metadata does not rotate
an app credential. The backend origin is optional without OBO endpoints; OBO
requires a valid origin. Endpoint paths remain immutable. `ttl_seconds` is a
positive integer with default 300. Existing proofs keep their original expiry;
new proofs use the newly accepted duration, and verification remains one-use.

Private apps require live owning-organization membership and the selected grant
through login, exchange, refresh, introspection, API access and OBO. Their
critical-scope exemption is recorded separately from provider approval. Private
apps are excluded from anonymous discovery. Public activation requires both
Honeycomb publication approval and actual critical provider/IAM approval.
A pending public proposal does not overwrite the current accepted private
configuration. Submit a new operation and fresh IAM revision after approval.
`state: pending` can therefore describe a completed proposal awaiting a separate
decision: inspect the operation's `completed` field.

A changed webhook URL stays pending until its stepped-up approval. The previous
active receiver remains active. An unchanged URL can omit its secret; changing
that secret uses the dedicated rotation operation. Bundle acceptance remains
subject to IAM's current eligibility checks; catalog publication cannot override
them. Bundle membership creates no new credential or principal.

## IAM-local testing lifecycle

Send `POST /testing-environments/{environment_id}/operations` with explicit
`environment_id`, current `generation`, `expected_iam_revision`, `operation_id`
and `operation`. Reconcile with `GET /testing-environments/{environment_id}`.
The user must have a live selected grant in the owning organization; an existing
environment additionally requires its creator or an owner/admin.

| Operation | IAM behavior |
| --- | --- |
| `prepare` | New UUID, revision 0, generation 1 and `org_id`/`name`; returns a protected root key while access stays disabled |
| `import` | Prepared/cleaned environment only; accepts `app_id` and exact `source_revisions` for the complete dependency graph |
| `activate` | Enables prepared/cleaned IAM state after Honeycomb decides all participants are ready |
| `rotate-key` | Changes root key/version; old key stops authenticating |
| `disable` | Blocks runtime access and retains recoverable IAM data |
| `restore` | Changes disabled state to prepared; explicit activation still required |
| `clean` | Blocks access, advances cleaning generation once and erases IAM's isolated data; leaves cleaned state |
| `purge` | Requires disabled access; erases IAM data/keys and leaves a minimal completion tombstone |

To refresh an active environment: disable, restore, import the accepted graph,
then activate. Source snapshots are encrypted and retained across interrupted
imports. Refresh preserves imported app identities and rotates test credentials;
replaying the same import never regenerates them. Cleaned imports get fresh
credentials. Imported webhook signing material is marked inherited, never exposed
in notifications. Test webhook metadata identifies environment and generation.

Lifecycle progress is committed before test-data work. Retry the exact pending
operation after transport/process failure; a different operation conflicts until
it completes. Renewed actor credentials may be used for the same actor, with
current authority rechecked. Service-only status reads remain available even
when test sessions/root keys are invalid. User-authored operations still require
that user's current authority to resume. With scheduled testing explicitly
enabled, Honeycomb can author clean/disable/restore/purge/activate operations
without an actor for its managed environments; prepare/import/rotation always
require a user.

`iam_completion: true` acknowledges only IAM's work. Honeycomb must collect
completion from every participant before shared activation or reporting a shared
clean/purge complete. IAM has no independent idle-retirement or purge worker.
Generation/key-version fences reject requests admitted under stale runtime state.

## Notifications, reconciliation and adoption

The management envelope contains `event_id`, `operation_id`, `resource_id`,
`environment_id`, `revision`, `event_type` and secret-free `data`. Verify the raw
body before JSON parsing. `X-IAM-Management-Signature` is
`t=<unix-seconds>,v1=<hex-HMAC-SHA256(timestamp + "." + raw-body)>`.
Use `honeycomb::verify_notification`, a bounded timestamp tolerance, durable event
ID deduplication and per-resource revision ordering. Respond 2xx only after durable
receipt. IAM retries failed delivery with backoff; redirects are not followed.

`GET /events?after=<event-id>` reads the durable archive.
`POST /events/{event_id}/replay` queues that same event again. Archive/inventory
UUID pagination is not a transactional change cursor: concurrent commits may
appear behind a cursor. Use notifications plus periodic full inventory/current
record reconciliation, including after a disconnected period.

Roll out databases and IAM first, then provision the API integration and worker
subscription when Honeycomb's adapter is ready. Provisioning the API integration
retires legacy production app/bundle/review/test lifecycle writers with
`410 management_moved_to_honeycomb`; IAM's identity, login and runtime APIs stay
available. The console directs users to Honeycomb for the moved management surfaces.

Enumerate existing records, preserve IDs and read current revisions. Existing
apps retain visibility `public`, IDs, credentials and accepted scopes. Existing
environments begin as `legacy`; submit `prepare` with their current IAM revision
and generation to adopt them while preserving their root key and active/disabled
state. Test database upgrades include isolation for the new management tables.
Stage the writer switch with Honeycomb; do not create duplicate identities to
work around an unconfigured adapter.
