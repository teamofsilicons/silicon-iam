# IAM implementation for the Honeycomb handoff

Implemented against the human-owned `UNDERSTANDING.md` and Honeycomb's
`docs/IAM-HANDOFF.md`, inspected September 15–16, 2026. The buildable IAM-side
contract is documented in [HONEYCOMB_INTEGRATION.md](HONEYCOMB_INTEGRATION.md).
Neither architecture document was edited by this implementation.

## Implemented

- [x] Provider-configured OBO lifetime, default 300 seconds; existing expiry,
  one-use verification and current authorization remain enforced.
- [x] Private/public accepted app configuration, membership-bound access,
  protected private discovery and distinct private scope exemptions.
- [x] Dedicated Honeycomb service credentials, live actor and reviewer checks,
  step-up for sensitive changes, configuration revisions and durable operations.
- [x] App creation/configuration, app-secret rotation, provider decisions,
  webhook approval/rotation and accepted bundle membership.
- [x] Secret-free inventory and reconciliation; independently signed durable
  management notifications with retry and explicit replay.
- [x] IAM-local prepare/import/refresh/activate/rotate/disable/restore/clean/purge,
  current key versions, cleaning generations and isolated test-data fences.
- [x] Adoption of existing identities/environments, protected bootstrap output,
  fresh and upgraded test database isolation and retirement of legacy writers
  when the explicit writer-cutover flag is enabled.
- [x] Removal of independent testing retirement and runtime library/CLI updating.
- [x] Stateless Rust management client, generated OpenAPI types, CLI/console
  ownership guidance, offline documentation and deterministic six-target
  Honeycomb archive packaging. Client/CLI source version is 1.11.0.
- [x] Rustls patched to 0.23.45 to satisfy the dependency advisory check.

## September 16 integration update

- Typed publication plans, exact gate decisions, current-reviewer checks and
  immutable acceptance receipts; no boolean publication bypass.
- Consent-bound membership and tag disclosure, accepted webhook destination
  reconciliation, and paginated organization notification recipients.
- Shared per-environment keys with no testing-enable key; public root-key imports,
  fenced key rotation, app-owned environments and cross-organization attachment.
- Preserved dependency pins, additive activation, immutable source UUID checks,
  isolated test configuration and application-owned credential recovery.
- Protected legacy adoption, selective retention and replay-safe key non-reuse.
- Populated0099/9009 database upgrade regression preserves source identities,
  credentials and environment links under the restricted runtime role.

SDK source is committed and handed to Honeycomb. The native six-target release
build runs independently. Backend release and participant activation remain
separate verified steps; the sections below record the preceding rollout checks.

## Prior validation

Final local validation passed 496 workspace tests, all 33 live PostgreSQL tests,
and the separate bootstrap replay test. Backend and CLI binaries built locally;
strict Clippy and dependency advisories/bans/licenses/sources checks passed.

The repository checks cover formatting, strict workspace Clippy, workspace tests,
SQL security boundaries and least-privilege grants, OpenAPI/router agreement,
generated models/manuals/route templates, dependency policy, frontend checking,
build and tests, direct installer behavior and archive packaging.

Disposable PostgreSQL tests exercise the real restricted runtime role through
Honeycomb HTTP routes: credential separation, live actor requirements, exact-body
replay, expired secret replay, private/public approval separation, stepped-up
rotations, webhook activation, bundles, inventory and notification replay. The
lifecycle sequence includes same-environment configuration refresh, stable app
identity, fresh credentials, key rotation, clean generations and purge. Bootstrap
retries preserve identities, secrets and one-time audit records. Existing live
protocol and fresh/historical database-upgrade tests are retained.

The archive layout was also accepted by the current local Honeycomb validator
using synthetic payloads. This validates packaging, not executable compatibility:
the six native release binaries still need to be built on their release targets.
The four existing client live-HTTP tests require a separately running configured
API and are not part of the default workspace test run.

## Work that requires integration or release coordination

Honeycomb must implement its adapter against the published service contract,
retain exact mutation bodies/IDs, obtain current actor/step-up credentials, verify
management notifications and coordinate every application's lifecycle completion.
Provision production credentials and the notification subscription, migrate both
IAM databases, adopt existing records, then switch legacy writers in a coordinated
rollout. IAM only acknowledges its own test cleanup.

The preceding production rollout provisioned the service integration and signed
management notification receiver. The missing-webhook app-list hotfix is deployed
at `72767708d9ac2e7bf11873aee9bc8800da3c4835`; main/scoped readiness, worker health
and owner-console recovery were verified without changing migration ledgers.
The additional September16 migrations remain pending until the final release gate.
Honeycomb owns normal IAM app registration and publication; preserve existing app
identities and require current approval/renewed consent for expanded access.
