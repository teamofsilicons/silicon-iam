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

Honeycomb's authentication app declares `self.identity.read`, `self.profile.read`
and `self.membership.read`. Enable `self.tags.read` when tag disclosure is needed.
New scopes require renewed user consent; adding an app permission never expands
previously issued tokens. Unscoped token
introspection discloses organization roles through `self.membership.read`,
intersected with current application approval and that session's live consent.
The historical `roles.read` scope does not grant role disclosure, and
`memberships.read` does not grant tag disclosure. Tags require `self.tags.read`
in the token, current app approval and live consent. Bootstrap seeds identity,
profile and membership access only for a new Honeycomb identity; update existing
app records and optional tag access through the authorized configuration flow.

Configure the IAM API:

- `IAM_HONEYCOMB_APP_ID`: the Honeycomb authentication app ID.
- `IAM_HONEYCOMB_CREDENTIAL_SHA256`: lowercase SHA-256 hex of the complete random
  `hck_` credential. Only Honeycomb stores the plaintext service credential.
- `IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS`: default `false`; set `true` only after
  Honeycomb adoption and replacement management flows are ready. Service API
  credentials can be provisioned while legacy writers remain available.
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

Human-authored writes use `X-Honeycomb-Actor-Token: oat_…`, a live
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
Production configuration uses absent/null `environment_id`. Publication planning
uses `request_id` as its durable operation identity; subsequent decisions and
activation have distinct `operation_id` values. Some service-only control reads
and exports have no user actor, as specified below.

Sensitive mutations require `X-Step-Up-Token`, obtained through the existing IAM
verified-channel flow for the same actor session, action and application UUID:

| Mutation | Step-up action |
| --- | --- |
| App secret rotation | `application.client_secret.rotate` |
| Webhook destination approval | `application.webhook.approve` |
| Webhook signing-secret rotation | `application.webhook_secret.rotate` |

An authorized retry of a completed operation does not consume a second proof.
The mutation response has `Idempotency-Replayed`. Secrets are encrypted for a
10-minute replay window; afterward the original durable receipt remains. Retrying the mutation returns
`secret_replay_expired: true` without generating new credentials.
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
apps are excluded from anonymous discovery. Public publication uses the immutable review flow below. A public proposal sent
to `/configuration` remains pending without overwriting accepted configuration;
`publication_approved: true` cannot authorize publication. New app identities
must first be registered privately. A completed proposal can still have
`state: pending`; the separate activation accepts its reviewed configuration.

`GET /applications/{app_id}` includes authoritative `webhook_url` and
`pending_webhook_url`; absent destinations are null. It never returns the signing
key. An app without any webhook remains listable with a disabled webhook and
secret version zero. A changed webhook URL stays pending until its stepped-up approval. The previous
active receiver remains active. An unchanged URL can omit its secret; changing
that secret uses the dedicated rotation operation. Bundle acceptance remains
subject to IAM's current eligibility checks; catalog publication cannot override
them. Bundle membership creates no new credential or principal.

## Immutable publication and notification recipients

All paths below are relative to `/api/v1/honeycomb`. Review plans contain exact
provider/scopes gates derived from IAM's current catalog. Resolve provider app
IDs and origins from accepted configuration and catalog records; do not embed
particular organization/app handles in business logic.

| Method and path | Request and authority |
| --- | --- |
| `POST /applications/{app_id}/publication-plans` | Owner/admin actor; `request_id`, `app_id`, `configuration_revision`, `configuration`, `visibility: public` |
| `GET /publication-plans/{plan_id}` | Service read of the immutable plan |
| `GET /publication-plans/{plan_id}/reviewer-eligibility?provider=…` | Service plus proposed reviewer actor; returns current `eligible` |
| `POST /applications/{app_id}/publication-decisions` | Live reviewer; `operation_id`, `request_id`, `plan_id`, `app_id`, `configuration_revision`, exact `provider`/`scopes`, `decision: approve\|deny`, optional `reason` |
| `POST /applications/{app_id}/publication-activations` | Owner/admin actor; exact request/plan/app/configuration revision and configuration, `visibility: public`, current `expected_iam_revision`, `decision_ids`, optional `configuration_operations` |
| `GET /publication-plans/{plan_id}/notification-recipients?provider=…` | Service-only recipients for a plan gate, or `provider=owners` for the applicant organization's owners/admins |
| `GET /organizations/{org_id}/notification-recipients` | Service-only current owners/admins for that organization's operational notices |

The configuration uses the accepted configuration shape, with `availability:
active`. Envelope app ID, visibility and configuration revision may be repeated
inside it but must agree. Plans bind the complete normalized configuration,
including supplied webhook signing material. Changing it requires a new plan.
Retain the returned `plan_id`, `gates` and `reused_approvals`. Existing live
provider approvals can satisfy matching critical scopes without a duplicate
review, but IAM records the exact evidence and rechecks it later.

Review authority is distinct from applicant administration:

- `provider: iam` requires the current `applications.review` platform capability.
- `provider: honeycomb` requires `honeycomb.applications.review`, assigned through
  the separate `honeycomb_validator` role. Organization ownership does not grant it.
- A qualified provider app such as `org>provider` requires current management
  authority in the provider's organization and the actor's selected grant.

Copy each gate's exact scope list. Activation requires the latest approving
decision for every outstanding gate, rejects duplicate or mismatched decision
IDs, and rechecks reviewer membership/capabilities, catalog requirements and scope
revocation. `configuration_operations` names only pending `/configuration`
operations for this same app, revision and configuration digest; their durable
receipts become accepted in the activation transaction. The result includes a
strictly newer `iam_revision`, `effective_configuration`, `request_id`, `plan_id`
and `publication_request_id`. Reconcile against the current app record: its
`publication_request_id` becomes null when its review evidence is no longer current.

Recipient responses contain only eligible principal IDs and verified primary
emails, scoped to the requested organization or plan gate. Use `after` with the
returned `next_cursor`; `limit` defaults to 100 and is bounded to 1–1000. Recipient
discovery does not grant approval authority. Honeycomb owns sending its notices.

## Shared testing keys and authority

Testing always has an explicit environment identity. There is no global testing
key or deployment-wide switch that grants test access. Honeycomb supplies a
random 32-character ASCII alphanumeric root key for each new environment and
shares that exact key/version only with the participating services. IAM encrypts
its copy and binds runtime requests to the selected environment, generation and
key version. Invalid test context never falls back to production.

These header credentials have different purposes:

| Header | Authority |
| --- | --- |
| `Authorization: Bearer hck_…` | Honeycomb service transport for all management routes |
| `X-Honeycomb-Actor-Token: oat_…` | Live Carbon creator/owner/admin or reviewer authority |
| `X-Honeycomb-Application-Authorization: Basic …` | Base64 of the production `app_id:app_secret`; IAM verifies it as an ordinary production app client |
| `X-Honeycomb-Testing-Key: …` | A specific environment's current root key; alone authorizes public imports/key rotation/clean, or with production app credentials proves attachment |
| `X-Testing-Environment-Key: …` | Ordinary runtime test requests only; forbidden on Honeycomb management routes |

Use either actor or production application authorization, never both. An
environment root key alone can authorize `import`, `rotate-key` and `clean`, always with
Honeycomb service authentication and exact `expected_key_version`, `generation`
and `expected_iam_revision`. This grants no private production app visibility.
No separate credential enables testing. The
service-only `GET /application-identity` with production application authorization
returns the verified app/organization IDs and current IAM revision without a
secret. It does not accept a supplied identity as proof.

A production app may create an environment in its own organization and becomes
its application owner. It may manage that environment even after its test key
is disabled. A different app may attach/import only itself by presenting that
environment's root key and its own valid production credentials, including
across organizations. Attachment grants neither lifecycle ownership nor another
app's test credential. Its private dependencies still require the appropriate
source-organization authority. `GET /testing-environments` with production app
authorization lists owned and attached environments, with `can_manage` reflecting
actual ownership; it supports `status`, `cursor` and `limit` pagination.

## IAM-local testing lifecycle

Send `POST /testing-environments/{environment_id}/operations` with explicit
`environment_id`, current `generation`, `expected_iam_revision`, `operation_id`
and `operation`. Reconcile with `GET /testing-environments/{environment_id}`.
An actor needs a live selected grant in the owning organization and, for an
existing environment, creator or owner/admin authority. Application authority
follows the ownership/attachment rules above.

| Operation | IAM behavior |
| --- | --- |
| `prepare` | New UUID, IAM revision 0, generation 1, `org_id`/`name`, supplied `testing_key` and `key_version: 1`; returns that key while runtime remains disabled |
| `import` | Accepts `app_id` and exact `source_revisions` for its dependency graph; works in prepared, cleaned or active environments |
| `activate` | Enables prepared/cleaned IAM state after Honeycomb confirms every participant is ready |
| `activate-apps` | In an active environment, enables only the exact pending `app_ids` after shared readiness |
| `rotate-key` | Supplies fresh `testing_key`, next `key_version` and current `expected_key_version`; leaves prepared state until shared activation; old or retired key material cannot be reused |
| `disable` | Blocks runtime access and retains recoverable IAM data |
| `restore` | Changes disabled state to prepared; activation is still explicit |
| `clean` | Blocks access, advances generation once, erases IAM's isolated data and leaves cleaned state |
| `purge` | Requires disabled access; erases IAM data/keys and leaves a completion tombstone |

For Honeycomb-coordinated creation/rotation, always supply the shared key and
version. Omitting key material remains compatible with old IAM-generated-key
clients; independent participant-generated keys cannot form a shared environment.
`testing_key`/new `key_version` are accepted only for fresh prepare or rotation.
Existing legacy prepare preserves its original key. `expected_key_version` can
also guard other existing-environment lifecycle instructions.

`source_revisions` are IAM production application versions, distinct from
Honeycomb configuration revisions. Supply the complete dependency graph, including
the requested root. Imports retain each source's accepted public/private visibility;
read the returned IAM configuration instead of assuming every imported app is private.

Imports preserve existing pinned source revisions and credentials. Adding an app
to an active environment leaves already-ready apps working; new imports remain
pending until `activate-apps`. To refresh particular imports, include only their
IDs in `refresh_app_ids` and supply the exact resulting graph `source_revisions`.
The refresh changes those selected pins, preserves their application IDs and
rotates their test credentials. Unselected existing imports keep their pins and
credentials. Refresh targets must belong to the requested dependency graph.

Source snapshots are encrypted and retained across interrupted imports. The
receipt returns `imports` with accepted revisions/configuration and readiness,
plus only the requested root app's `app_secret`; dependency credentials are not
returned. Same-operation retries reuse committed target identities and secrets.
Cleaned imports receive fresh credentials. Imported production webhook signing
material remains marked inherited and is never disclosed as a test-owned key.

Lifecycle reservations commit before target-plane work. Retry the exact pending
operation after transport/process failure; a different operation conflicts until
it completes. User/app authority is checked again before replay. Renewed user
tokens may resume the same actor's operation. Service-only reconciliation remains
available when test sessions/root keys are invalid.

With `IAM_HONEYCOMB_SCHEDULED_TESTING` explicitly enabled, the service may author
clean/disable/restore/purge/activate/activate-apps for its managed environments
without inventing a user actor. The flag does not grant runtime testing access,
app ownership or permission to prepare/import/rotate arbitrary environments.

`iam_completion: true` acknowledges only IAM's work. Honeycomb must collect all
participant receipts before shared activation or reporting a shared clean/purge
complete. IAM has no independent idle-retirement or purge worker. Generation and
key-version fences reject stale requests. Signed test webhook metadata supports
direct `environment_id` and positive `generation`; the SDK also accepts legacy
aggregate placement and rejects conflicting direct/aggregate values.

## Test application administration

These routes address only the named isolated environment:

| Method and path under `/testing-environments/{environment_id}` | Purpose |
| --- | --- |
| `GET /applications/{app_id}` | Accepted test configuration and active destination; no signing/app secret |
| `PUT /applications/{app_id}/configuration` | Configure an existing test app or register a new test-only private app |
| `POST /applications/{app_id}/secret-rotations` | Explicit test credential rotation |
| `POST /applications/{app_id}/credential-recovery` | Production app retrieves only its own current test credential without rotating it |

Reads require query fields `generation`, `key_version` and
`expected_environment_revision`. Writes carry those same fields, `environment_id`,
`operation_id`, the target app's `expected_iam_revision`, and
`configuration_revision`. Configuration writes additionally carry `configuration`;
rotation omits it and names the current configuration revision. Environment and
application revisions are separate preconditions.
An unchanged production import has IAM configuration revision `0`; rotation accepts
that exact revision. Honeycomb must read the accepted IAM revision rather than
substitute its own local configuration counter. Configuration writes still require
a positive, increasing revision.

Service-only reads are secret-free. Configuration and secret rotation also accept
`ManagementAuthority::Environment` with the current root key, generation, key
version and environment revision; this grants authority only inside that environment.
Test login tokens must never be presented as production actor tokens. Other writes
require the live human environment manager or a production app acting on only its own immutable source identity;
an attached app additionally presents the matching root key. Environment ownership
does not let a production app read or change another app's credential. A human
environment manager registers new test-only apps. Registration uses revision zero, requires
private visibility and an app ID in the environment's owning organization.
The configuration accepts the ordinary IAM authentication fields; a new webhook
destination needs its signing secret. Existing app configuration preserves its
app credential; a new registration or explicit rotation returns one protected
`app_secret`. Configuration changes leave that app pending coordinated activation.
Target-plane receipts prevent a lost production commit from rotating twice.
Exact retries recover an existing receipt before checking an unrelated environment
revision advance; current actor authorization, generation and key version still
apply. If no target receipt exists for the operation, rotation rejects a configuration mismatch
with `configuration_revision_conflict` before checking the environment revision.
That rejection proves this request did not rotate. A valid configuration with a
stale environment revision still fails with `testing_revision_or_state_conflict`
without a mutation. Other conflicts and uncertain outcomes must remain recoverable;
retry the original body, actor and idempotency key without changing its revisions.
Rotation commits the active authentication digest and the encrypted credential
used by OBO and credential recovery together. Install migration `0117` on both
databases before starting the updated API. For a testing app affected by an older
rotation that left a stale encrypted credential, perform one new authorized
rotation after deployment; ordinary configuration edits do not repair credentials.

Credential recovery requires service plus production app authorization, and the
root key for an attached app. Its body carries `operation_id`, `environment_id`,
`generation`, `key_version` and `expected_environment_revision`. It validates the
current production source UUID and returns only that app's existing credential.
A fresh recovery operation can recover a lost credential after an earlier replay
window expired; it never rotates the secret.

## Exact application retention

`POST /testing-environments/{environment_id}/retention` is a service-only,
scheduled-testing-gated instruction with `operation_id`, `environment_id`,
Honeycomb's `environment_revision`, IAM's `expected_iam_revision`, current
`generation`/`key_version`, and 1–100 unique `retired_apps` IDs. IAM verifies exact
production links or actual applications in the named testing plane; it does not
accept a caller-asserted app identity as environment authority.

IAM erases only those apps and their dependent IAM rows, including credentials,
and marks matching production links retired. Sibling apps, shared identities and
other environments remain intact. Test-only apps are supported. A target-plane
receipt commits with erasure so a retry after a lost control-plane commit cannot
erase a subsequently imported app again. The response echoes the requested IDs,
Honeycomb revision, generation and key version, returns current `iam_revision`
and `iam_completion: true`, and remains an IAM-local `state: accepted` receipt.
Honeycomb separately coordinates each participating service's owned data.

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
subscription when Honeycomb's adapter is ready. Enabling
`IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS=true` retires legacy production
app/bundle/review/test lifecycle writers with
`410 management_moved_to_honeycomb`; IAM's identity, login and runtime APIs stay
available. The new console directs users to Honeycomb for the moved management surfaces;
retain the existing frontend until those replacement flows are ready.

Enumerate existing records, preserve IDs and read current revisions. For each
retained environment, call service-authorized
`POST /testing-environments/{environment_id}/adoption-export` with `operation_id`,
`expected_iam_revision` and an idempotency key. The protected response contains the
unchanged root `key`, owner IDs, source/target app links, retention metadata,
accepted import/configuration revisions and credential versions. The export does
not rotate credentials or change ownership. Its key is excluded from durable
public receipts and notifications; secret response replay lasts ten minutes.
Store the transferred root key in Honeycomb's encrypted per-environment storage.

Existing apps retain their current visibility, IDs, credentials and accepted
scopes. Unadopted environments have state `legacy`; submit `prepare` with their
current IAM revision
and generation to adopt them while preserving their root key and active/disabled
state. Test database upgrades include isolation for the new management tables.
Stage the writer switch with Honeycomb; do not create duplicate identities to
work around an unconfigured adapter.

## Cutover acceptance

Deploying IAM contracts does not establish cross-service readiness. Keep legacy
writer retirement and automatic scheduled testing disabled until Honeycomb's
replacement flows pass authenticated end-to-end checks: owner/app authority,
reviewer decisions and revocation, exact publication activation, webhook
approval, lost-response reconciliation, additive import and key/generation
fencing, adoption preserving credentials, and coordinated retention/recovery.
These checks must exercise actual configured participant apps and services.
Missing participant transport stays unavailable; it must not trigger a global
test unlock, production fallback or recreated legacy identity.
