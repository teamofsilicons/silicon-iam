# Silicon IAM backend

Silicon IAM is a security-first identity and access-management backend for
Carbon accounts, organization-scoped Silicon identities, applications,
OAuth, delegated OBO access, governance, WorkOS SSO, audit, and reliable
webhook delivery.

The backend is a Rust 2024 modular monolith with two independently scalable
runtime processes and three one-shot operator binaries:

- `iam-api` serves the public and administrative HTTP contract.
- `iam-worker` processes durable notifications, subscription-aware outbox
  expansion, and ordered application and Silicon webhook deliveries.
- `iam-migrate` is a privileged one-shot forward migrator.
- `iam-bootstrap-admin` is a privileged, one-time operator command for granting
  the first platform-administrator role to an existing active Carbon.
- `iam-activate-key-version` is a narrowly privileged compare-and-swap command
  for activating a runtime key version that every pod has already preloaded.

PostgreSQL 16 or newer is the sole authoritative datastore.

## HTML surfaces

Alongside the JSON contract the API serves three server-rendered surfaces from
`src/web`. They are deliberately outside `openapi.yaml` — an interface and a
document are not contract — and `scripts/check-openapi-routes.rb` enforces that
boundary in CI.

| Path | What it is |
| --- | --- |
| `/docs` | Chooses between the two manuals |
| `/docs/api/` | The HTTP contract, eleven sections, authored in `docs/api/*.html` |
| `/docs/client/` | The official Rust SDK, seven sections, authored in `docs/client/*.html` |
| `/openapi.yaml` | The normative contract, at a stable cacheable URL |
| `/admin` | Platform-administration console: application review, consent policy, SSO entitlement |

The client manual documents [`iam-rust-library`](../iam-rust-library), the
official SDK. It is published here rather than in that repository so a reader
finds both manuals at one origin, and so the two can cross-reference each
other without a dead link when either moves.

Everything they need is embedded at compile time — markup, stylesheet, script,
marks and the IBM Plex latin subsets — so a release image makes no third-party
request and cannot serve documentation that has drifted from its binary. The
`/admin` console executes no SQL and holds no credential; it is a thin
same-origin client over `/api/v1/admin/*`, which already requires a
platform-administrator bearer, a verified-channel step-up token, an
`Idempotency-Key` and an `If-Match` on every mutation.

The HTML router is merged outside the JSON router's layer stack. Inside it,
error normalisation would rewrite the documentation's own 404 into the JSON
envelope and the `no-store` default would make every asset uncacheable.

The browser frontends — `auth.iam.teamofsilicons.com` and
`iam.teamofsilicons.com` — live in the sibling `silicon-iam-frontend`
repository.


## Local start

Prerequisites are Docker with Compose v2 and OpenSSL.

```sh
./scripts/bootstrap-local-env.sh
docker compose up --build
```

The bootstrap command creates a mode-`0600`, Git-ignored `.env` containing
independent local cryptographic keys and database passwords. It refuses to
overwrite an existing file. Compose then:

1. starts PostgreSQL on `127.0.0.1:5432`;
2. creates separate migrator, API, worker, and key-operator database principals;
3. runs every migration once;
4. applies reviewed runtime grants; and
5. starts the API on `127.0.0.1:8080` plus the asynchronous worker.

Check process and dependency health with:

```sh
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

Local provider adapters and exposed OTPs are enabled only by the generated
development configuration. Production configuration rejects those settings.

## Native development

The pinned toolchain is installed automatically by rustup from
`rust-toolchain.toml`. Start PostgreSQL first. The API and migrator may use the
development `.env`; start the worker through Compose or an explicitly
allowlisted environment, then run the applicable process:

```sh
cargo run --locked --bin iam-migrate
cargo run --locked --bin iam-api
cargo run --locked --bin iam-worker
```

The API and worker should receive different `IAM_DATABASE_URL` values in a
privileged environment. The shared variable name is intentional because each
process receives its own deployment environment. The migrator uses only
`IAM_MIGRATOR_DATABASE_URL`. Unlike the API and one-shot development commands,
`iam-worker` does not load the shared `.env` file: run it through Compose or
inject only the worker variables documented below so API authority secrets do
not enter its process environment.

After the intended first administrator has created and activated their Carbon
account, bootstrap that role exactly once with the migrator credential:

```sh
cargo run --locked --bin iam-bootstrap-admin -- --carbon-id example_admin
```

The command refuses to run once any platform-administrator grant history
exists. It commits the grant, redacted audit record, and outbox event in one
serializable transaction. `iam-bootstrap-admin` with the migrator credential is
the only first-administrator bootstrap path; the API and worker accept no
runtime bootstrap secret. Never provide the migrator credential to either
long-running process.

## Runtime-key rotation

Token HMAC, contact blind-index HMAC, and contact AEAD keys use independent,
positive integer versions. PostgreSQL stores metadata only; key material stays
in the deployment secret provider. Startup is intentionally fail closed:

- an empty purpose may be initialized from the configured current version;
- an existing database-active version must exactly equal the pod's configured
  current version;
- every database `active` or `decrypt_only` version must exist in that pod's
  local keyring; and
- startup may register a higher local version as `decrypt_only`, but can never
  change which version is active.

Rotate one purpose at a time with this two-phase rollout:

1. Add version `N+1` to every pod's keyring while keeping configured current at
   `N`, then roll the fleet. The first updated pod records `N+1` as
   `decrypt_only`; any older pod that lacks it will subsequently fail startup,
   so confirm the preload rollout has completed before activation.
2. Run the one-shot command through a dedicated login that inherits only the
   `silicon_iam_key_operator` group role:

   ```sh
   IAM_KEY_OPERATOR_DATABASE_URL='postgresql://dedicated-key-operator:…@db/iam?sslmode=verify-full' \
     iam-activate-key-version \
       --purpose token-hmac \
       --expected-current-version N \
       --new-version N+1
   ```

   The command accepts only `IAM_KEY_OPERATOR_DATABASE_URL`; do not expose the
   migrator URL to this process. The database takes a purpose-scoped advisory
   lock, verifies that the session login belongs to the dedicated operator
   role, checks the exact expected current version and preloaded target,
   rejects downgrades, changes both statuses in one transaction, and appends
   activation history. Local Compose exposes the same isolated login through
   the opt-in operator profile:

   ```sh
   docker compose --profile operator run --rm key-operator \
     --purpose token-hmac \
     --expected-current-version N \
     --new-version N+1
   ```
3. Immediately change the configured current version to `N+1` and roll every
   pod again, retaining `N` locally for verification/decryption. Between steps
   2 and 3, old processes may finish in-flight work but cannot restart with
   stale current metadata.

Repeat the command separately with `contact-lookup-hmac` or `contact-aead` as
needed. A failed or ambiguously interrupted activation must be investigated;
do not retry with a guessed expected version. This protocol deliberately does
not expose key retirement: a decrypt-only version remains required locally
until a separately reviewed retirement procedure proves no persisted value or
unexpired credential references it.

## Retention operations

The worker runs a bounded retention sweep through a fixed-search-path database
function that is callable only by a login belonging to `silicon_iam_worker`.
The worker has no direct read or delete access to retained authentication,
token, or audit tables. Each selected phase claims at most
`IAM_RETENTION_BATCH_SIZE` root records during its maintenance tick with ordered
row locking, so multiple workers cooperate without unbounded table locks. The
accepted batch range is 1–1,000. Each value in the closed 21-phase cleanup
vocabulary runs in its own statement and transaction. Exactly one phase runs per
maintenance tick, selected round-robin, so retention cannot monopolize the
delivery loop for up to 21 statement timeouts. A failed phase is logged and the
next tick advances to the following phase. The initial phase is derived from the
current wall-clock sweep slot, preventing rolling restarts from repeatedly
returning to phase zero.

Operational defaults are:

- login and authentication history: 365 days;
- expired challenges, ceremonies, and abandoned signup/contact/OAuth state:
  30 days;
- expired or revoked access, OBO, and refresh metadata: 90 days;
- compromised refresh families: 365 days;
- webhook delivery attempts: 45 days; and
- security audit events: 2,555 days.

The day values, batch size, and sweep interval are typed and bounded environment
settings listed in `.env.example`. Compromised-family retention cannot be
configured below ordinary token retention. Approval-linked step-up records and
authentication sessions still referenced by durable history are reduced to
non-secret FK skeletons rather than deleted; later sweeps remove eligible
session skeletons once every reference has aged out.

## Quality gates

Run the same core checks used by CI:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo deny --locked --all-features check
ruby scripts/check-openapi-routes.rb
ruby scripts/check-migration-security.rb
ruby scripts/check-runtime-grants.rb
```

The contract check rejects an undocumented Axum route, an OpenAPI operation
without a route, a duplicate `operationId`, or a feature router that was not
merged into the API composition root. The runtime-grant check derives direct
table verbs from production API and worker SQL and requires an exact capability
manifest. Its only non-direct API `SELECT` entries are
`ownership_transfer_requests`, read by the invoker-rights deferred approval
shape trigger, and `service_principals`, read by the invoker-rights deferred
principal-subtype trigger. Test modules, live-test fixtures, the worker, and
non-API binaries are excluded from the API derivation explicitly. CI also runs
the live PostgreSQL protocol regressions, applies migrations and exact runtime
grants to a fresh database, starts both worker and API through their non-owner
roles, checks API readiness, and enforces the locked, all-feature `cargo-deny`
policy.

## Architecture

```text
HTTP request
  -> Axum/Tower admission, limits, tracing, and redaction
  -> feature transaction and authorization policy
  -> PostgreSQL mutation + audit event + outbox event
  -> commit
  -> worker recipient expansion
  -> bounded provider/webhook delivery with lease, retry, and dead-letter state
```

Feature code lives under `src/features`; shared cryptography, PostgreSQL access,
provider clients, and browser-session handling live under `src/infrastructure`.
The worker is under `src/worker`. Migrations are append-only and support
PostgreSQL 16 and newer.

Carbon and Silicon profiles persist exact IANA TZDB identifiers and validate
them against both the Rust-bundled time-zone database and PostgreSQL's catalog.
Legacy rows receive a non-null `UTC` default. Public Carbon and Silicon handles
remain immutable while presentation fields—display name, description, time
zone, and profile photo—are independently editable through versioned profile or
directory operations.

The worker has a separate configuration and cryptographic composition root. It
receives only its restricted database URL, polling/retry/retention policy,
shutdown deadline, authentication-frontend URL for invitations, the contact
AEAD keyring, and Postmark, Twilio, and outbound-webhook delivery settings.
Its crypto type exposes authenticated encryption/decryption only. Token peppers,
contact blind-index keys, browser-cookie keys,
and WorkOS credentials are neither parsed nor held by the worker process. The
Compose worker service uses an explicit environment map so additions to the API
environment cannot silently cross this boundary. Contact-AEAD metadata startup
uses a worker-attested, fixed-purpose wrapper; the worker database role cannot
execute generic token or blind-index keyring reconciliation. Each delivery stage
claims at most the smaller of `IAM_WORKER_BATCH_SIZE` and
`IAM_WORKER_DELIVERY_CONCURRENCY` (default 16, accepted range 1–256), then awaits
that bounded wave before claiming more. Notifications and application or
subscriber-configured Silicon webhook delivery share a process-wide outbound
stage gate, so the configured delivery concurrency is an aggregate
external-I/O ceiling for the worker process rather than a per-stage allowance.

Important security boundaries include:

- product-specified 128-bit Silicon credentials and 256-bit session/application
  credentials with purpose-separated, versioned keyed digests;
- AES-256-GCM protection and HMAC blind indexes for contact identities;
- rotating refresh families with replay-family revocation;
- action- and resource-bound step-up assertions;
- immutable public handles backed by UUIDv7 internal identifiers;
- organization-qualified references, authorization epochs, and RLS defense in
  depth;
- exact idempotency binding for externally initiated mutations;
- process-scoped secret injection and an AEAD-only worker crypto capability;
- fixed-search-path, explicitly granted `SECURITY DEFINER` functions;
- no database ownership, role creation, replication, superuser, or RLS-bypass
  authority in long-running processes; and
- no raw contacts, OTPs, credentials, or provider payloads in logs, audit, or
  webhook events.

## Deployment

`Dockerfile` produces one non-root OCI image containing all five binaries. A
deployment selects the process with `iam-api`, `iam-worker`, `iam-migrate`, or
the one-shot `iam-bootstrap-admin` or `iam-activate-key-version`.
The image has no cloud-specific runtime dependency and runs with a read-only
filesystem, no Linux capabilities, and `no-new-privileges` in the local
composition.

Production provisioning should create the fixed `silicon_iam_api`,
`silicon_iam_worker`, and `silicon_iam_key_operator` NOLOGIN group roles plus
platform-managed login roles before the first migration. The key-operator
login receives no table privileges and only the reviewed activation function.
After each migration, run
`deploy/postgres/runtime-grants.sql` as the migration owner before starting the
new runtime. Do not reuse the migrator credential in an API or worker process.

Production startup also requires verified TLS for PostgreSQL, HTTPS provider
and public endpoints, complete provider credential groups, independent secret
material, and local providers disabled. The eventual cloud target may replace
the local secret and process orchestration without changing domain code.

## Contracts

- `openapi.yaml` is the normative HTTP contract.
- `API_DOCS.md` explains endpoint behavior and security semantics.
- `UNDERSTANDING.md` is the authoritative product-scope source.
