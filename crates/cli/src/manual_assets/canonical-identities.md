# Canonical identity migration

IAM identity keys are the permanent public identifiers: `carbon_id` for a Carbon,
the complete `silicon_id` for a Silicon, `app_id` for an application, and
`service/<service_id>` for an internal service. The service prefix prevents a
service handle from colliding with an account handle. Memberships, organizations,
sessions, credentials, events, and other independent resources retain UUIDs.

Migration 0111 backfills existing identity references in place. Its UUID-to-handle
translation exists only in temporary migration tables. No legacy UUID remains an
alternative authentication identity or a supported identity lookup key. Historical
migrations retain their checksums. Testing overlays are installed before the
identity conversion; the conversion preserves their environment restrictions and
adds the environment to identity uniqueness and foreign-key constraints.

Public JSON no longer includes `principal_id`. Typed profile identifiers and
`public_id` identify accounts; token introspection exposes `public_id`, and
notification recipients expose `carbon_id`. Generic actor and aggregate references
carry canonical strings when they identify accounts, and UUID strings when they
identify resources. This is a coordinated breaking contract change for consumers
that require UUID-typed account/application references.

## Existing encrypted data

`applications.encryption_context_id` preserves the old value strictly as metadata
needed to authenticate previously encrypted webhook settings, secrets, and event
projections. It is not an identity key, foreign key, authentication input, or public
field. A private `legacy_application_encryption_contexts` snapshot lets API and
worker processes load this finite metadata set before selecting a testing
environment, without bypassing identity row-level security. The map is keyed by
both the application handle and testing environment. Production imports
explicitly select production metadata even while running in a testing request.

New ciphertext always uses canonical identity handles. Decryption first tries the
canonical context, then the retained context for the same application/environment.
This keeps old ciphertext readable without making newly written ciphertext depend
on metadata from a cleaned or recreated testing application. An unrelated app,
resource row, or testing environment does not share that fallback.

## Release procedure and limits

1. Build and test the server, worker, CLI, client, frontend, and affected consumer
   adapters together. Consumers must accept canonical account/application strings
   and omit dependencies on `principal_id` before traffic returns.
2. Stop all API writers (including scoped API) and workers. Back up both production
   and testing databases and verify actual restores in isolation. Retain the
   unchanged configuration and encryption keys with the private backup. An old
   server binary cannot safely run against the converted schema.
3. Using the new image, the unchanged full API environment and an operator
   `IAM_DATABASE_URL`, run `iam-canonical-cutover prepare` separately on production
   and testing **before migration 0111**. Refresh the private identity export used
   for downstream data binding while all writers are stopped.
4. Run the normal `iam-migrate` for both planes, apply the exact image's runtime
   grants and initialize the scoped authentication helper. Then run
   `iam-canonical-cutover convert` separately for each plane with the same keys and
   operator authority. Both commands are retryable. Conversion is atomic; APIs
   and workers refuse to start while a prepared cutover remains unconverted.
5. Verify subtype/key equality, existing session relationships, environment
   isolation, ciphertext decryption and runtime grants. Start the compatible
   consumers, IAM APIs and workers, and verify existing access/refresh credentials,
   both account login paths, timezone self-edit, authorization, approval policies,
   webhook delivery and testing imports end to end.

Opaque access and refresh credentials keep their existing digests and resource
records. Identity replacement does not itself require reissuing those credentials.

The operator tool preserves pending replay records and converts encrypted cached
responses, Honeycomb snapshots and captured webhook projections. It adds canonical
membership handles to retained membership-removal projections while preserving
resource UUIDs. A bounded private replay map lets a currently authenticated
canonical actor find the old keyed request digest. It cannot authenticate a UUID
or resolve an alternative account identity. Its deadline is the latest existing
idempotency expiry; it never extends that deadline, and the worker removes the
map afterward. New reservations use canonical identities only.

A retry whose historical removed Description text cannot be reconstructed is an
idempotency conflict. It cannot silently execute a second mutation. Operators must
retain unresolved request outcomes and must not retry them with a fresh key as a
substitute for resolving the original result.

## Local regression checks

The migration regression harness `scripts/test-canonical-identity-migration.py`
checks a seeded upgrade and duplicate canonical handles in two isolated testing
environments. `scripts/test-canonical-runtime.py` exercises signup, both account
login paths, refresh, profile updates, and action approval through a local API
using the restricted runtime database role.

The existing ignored database tests also accept `IAM_TEST_DATABASE_ADMIN_URL`
pointing to a loopback PostgreSQL administrator connection. Each `TestDatabase`
instance creates a uniquely named disposable database and drops only that
instance's database when the test exits; without this setting it uses Docker.
Run these tests serially (`--test-threads=1`) because concurrent schema migrations
can exhaust PostgreSQL's default shared lock allocation. Authentication and
HTTP fixtures additionally require synthetic local test settings and keyrings.
Never supply production credentials or an external database for these checks.
