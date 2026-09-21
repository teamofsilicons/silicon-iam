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
2. Back up both production and testing databases and verify a restore in an
   isolated database. This migration changes column and stored-function types;
   rolling back only the server binary is insufficient.
3. Drain pending deliveries, then stop writes and delivery workers while applying
   the forward migration to both planes. Verify subtype/key equality, session and authorization relationships,
   same-handle testing-environment isolation, existing ciphertext decryption, and
   runtime function grants before starting the new API and workers.
4. Confirm existing access/refresh credentials still resolve their migrated
   records, then exercise Carbon/Silicon login, refresh, timezone self-edit,
   application introspection, webhook delivery, and testing imports end to end.

Opaque access and refresh credentials keep their existing digests and resource
records. Identity replacement does not itself require reissuing those credentials.

Cross-deployment idempotency replay is a separate compatibility boundary. Some
caller/request digests include the old identity UUID bytes or text, and encrypted
cached responses and captured webhook projections can contain historical identity
values. SQL cannot recompute keyed digests or rewrite encrypted responses without the runtime keys. Do not
assume a mutation retried across this cutover will find its old replay record.
Before deployment, either implement and validate a runtime rekey/re-encryption
step for outstanding replay records and replayable webhook projections, or drain
pending operations and maintain a write-free cutover covering the configured idempotency retention period. Retrying
a sensitive pre-cutover mutation with a fresh key is not an equivalent replay.

No deployment or production migration is performed by this code change.

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
