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
  Honeycomb archive packaging. Client/CLI source version is 1.10.0.
- [x] Rustls patched to 0.23.45 to satisfy the dependency advisory check.

## Validation

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

No production migration, deployment, credential provisioning, package publication
or Honeycomb source change is included. Build the six native release binaries,
package and validate the archive, then register/publish it through Honeycomb.
