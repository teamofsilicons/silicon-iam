# Silicon IAM engineering decisions

This file is the append-only decision log for the Silicon IAM backend. Material
architecture, security, data-model, API, and operational decisions are recorded
here before or alongside their implementation. A changed decision is marked as
superseded; its original record is not silently rewritten.

## D-001 — PostgreSQL is authoritative

**Status:** Accepted

PostgreSQL is the system of record for identities, credentials, sessions,
organizations, memberships, governance, applications, SSO mappings, audit
records, idempotency records, and the event outbox. Database constraints and
transactions enforce security invariants whenever PostgreSQL can express them.

Valkey/Redis is optional acceleration for distributed rate limits, short-lived
caches, and replay markers. Losing Valkey must not lose durable state or restore
revoked authority. PostgreSQL remains a supported standalone development mode.

## D-002 — Portable deployment until a target is selected

**Status:** Accepted

The service is packaged as OCI containers and depends on PostgreSQL plus an
optional Redis-compatible endpoint. Cloud-specific key management, secret
management, and workload identity are accessed behind interfaces. No AWS-only
runtime dependency is required while the production target remains undecided.

## D-003 — Modular monolith with separate API and worker processes

**Status:** Accepted

The backend is one Rust package containing a library and two thin binaries:
`iam-api` and `iam-worker`. The library is divided into domain, application,
infrastructure, HTTP, and worker modules. This keeps transactional workflows in
one deployable system while allowing processes to scale independently. Internal
microservices are deferred until measured operational boundaries justify them.

## D-004 — Rust safety and quality baseline

**Status:** Accepted

The workspace uses a pinned stable Rust toolchain, Rust 2024 edition,
`#![forbid(unsafe_code)]`, rustfmt, strict Clippy lints, dependency license and
advisory checks, deterministic lockfiles, and tests for policy and concurrency
invariants. Production code does not use `unwrap`, `expect`, or panic for
recoverable conditions.

## D-005 — HTTP and asynchronous runtime

**Status:** Accepted

Axum, Tokio, Hyper, and Tower provide the HTTP/runtime foundation. Tower layers
enforce request IDs, tracing, timeouts, body limits, sensitive-header handling,
and concurrency controls. Outbound HTTP uses Reqwest with rustls, explicit
timeouts, bounded response bodies, and redirects disabled unless a provider flow
specifically requires a validated redirect.

## D-006 — Carbon accounts own applications

**Status:** Accepted by product

Application creators authenticate with their existing Carbon account. Silicon
IAM does not create a second email/password developer identity. Application
ownership and collaborator authorization reference Carbon identities.

Platform administrators are a privileged role, not a separate public signup
flow. The first administrator is bootstrapped from an existing active Carbon by
the one-shot `iam-bootstrap-admin` operator command using the migrator
credential; no runtime bootstrap secret or source-controlled default password
exists.

## D-007 — SSO never creates a Carbon implicitly

**Status:** Accepted by product

WorkOS SSO may only link and admit an existing Carbon. A Carbon must first
complete the normal IAM signup flow. SSO callbacks must match the authenticated
Carbon, organization, WorkOS connection, verified identity, state, and nonce.
There is no just-in-time Carbon provisioning.

## D-008 — Internal IDs and public handles are separate

**Status:** Accepted

Persistent entities use UUIDv7 identifiers. `carbon_id`, `org_id`, `app_id`, and
the local/global Silicon IDs are immutable, normalized public handles backed by
unique constraints. Handles are not foreign keys and are not reused after
deletion. Carbon IDs allow lowercase ASCII `a-z`, digits `0-9`, `_`, and `-`,
with a length of 3–30.

## D-009 — Organization role and job role are separate

**Status:** Accepted

`org_role` is an authorization tier (`owner`, `admin`, or `member`) on a Carbon
membership. `job_role` is descriptive directory text, up to 5,000 characters,
for a Carbon or Silicon and never grants authority. Admin capabilities are
explicit grants layered under `org_role=admin`. Silicons cannot be organization
owners or administrators; machine capabilities are explicit and separate.

## D-010 — Deny-by-default organization capabilities

**Status:** Accepted

The owner has every organization capability. An admin receives only explicitly
granted capabilities. Members receive none by default, though an owner/admin may
grant narrowly scoped capabilities such as invitation creation. Authorization
is evaluated centrally and never inferred from job-role text, tags, or trust
metadata.

## D-011 — Session and token classes are distinct

**Status:** Accepted

The documented 365-day value is the maximum absolute lifetime of a Carbon
refresh-session family, not an access-token lifetime. Carbon, Silicon,
application, service, authorization-code, refresh, and OBO credentials are
separate classes with distinct prefixes, audiences, expiries, and revocation
semantics.

Access tokens are opaque, uniformly random 256-bit values with a 15-minute
default lifetime. Only keyed digests are stored. Refresh tokens rotate on every
successful use; replay revokes the complete token family. Downstream services
use authenticated introspection for immediate revocation and current membership
checks.

## D-012 — Silicon and application secrets use 256 bits

**Status:** Accepted security correction

The specified 16-hex-character Silicon token is strengthened from 64 bits to
256 random bits. Silicon tokens retain the `stk-` prefix but use 64 lowercase
hexadecimal characters. Application secrets are equally strong and versioned.
Raw secrets are returned once, then only a keyed digest is retained.

`SID + STK + Salt` is not used to derive a bearer token. IAM verifies the
credential and independently issues a random access/refresh session. Per-secret
salts are implementation details; a versioned server-side pepper is supplied by
the runtime secret provider and can be rotated internally.

## D-013 — OTP security and public response behavior

**Status:** Accepted security correction

Six-digit OTPs are generated with a cryptographically secure RNG, bound to one
purpose and session, retained only as a keyed digest, expire after ten minutes,
and are consumed atomically. A newly issued code invalidates the previous code
for that channel and purpose. IAM uses no more than five verification attempts
per code, while provider limits may be stricter.

Public email/phone signup and login initiation return uniform responses to
reduce account enumeration. Carbon-ID availability remains public. Distributed
limits apply by normalized identity, IP/subnet, session, purpose, and channel.

## D-014 — OAuth/OIDC uses authorization code with PKCE

**Status:** Accepted security correction

Application login follows OAuth Authorization Code with PKCE-S256. Browser
authorization uses a secure, HttpOnly, SameSite cookie rather than requiring a
Bearer header on a navigation request. Authorization codes are hashed,
single-use, client/redirect/PKCE-bound, and expire after two minutes. Exact
redirect matching, state, nonce, requested-versus-approved scopes, consent,
refresh rotation, revocation, introspection, userinfo, metadata, and JWKS are
part of the backend contract. Implicit and password grants are not supported.

## D-015 — OBO proofs are exchanged, scoped capabilities

**Status:** Accepted security correction

The deterministic `hash(access_token + app_secret)` construction is not used.
An authenticated application exchanges an actor-bound grant for a random,
single-use OBO proof with a 60-second default lifetime. The proof is bound to
issuer application, audience application, actor, organization, action,
optional resource, and unique identifier. The audience introspects and consumes
the proof through IAM, then independently verifies resource-level permission.

## D-016 — Transactional audit and outbox

**Status:** Accepted

Every security-relevant mutation commits its domain change, redacted audit
record, monotonically incremented aggregate version, and outbox event in one
PostgreSQL transaction. Workers claim outbox rows with bounded leases and
`FOR UPDATE SKIP LOCKED`, deliver at least once, retry with capped exponential
backoff and jitter, and retain dead-letter state for operator replay.

## D-017 — Webhooks expose minimal versioned events

**Status:** Accepted security correction

IAM never sends "everything it stores." Events use explicit versioned schemas
and omit OTPs, tokens, secrets, provider credentials, raw internal records, and
unnecessary contact information. Application webhooks are HMAC signed with an
event ID and timestamp, idempotent, retryable, ordered per aggregate where
required, and protected against SSRF and DNS rebinding.

Silicon Hook provisioning and initial delivery are asynchronous, idempotent
outbox operations. IAM does not hold a database transaction open across Hook.

## D-018 — Aggregate versioning is monotonic

**Status:** Accepted clarification

Every externally visible aggregate mutation increments its version by exactly
one. "Importance" does not change the increment. Independent global event IDs
and timestamps provide cross-aggregate ordering information. Sensitive updates
support optimistic concurrency through an expected version or `If-Match`.

## D-019 — Tag, trust, and reporting invariants

**Status:** Accepted clarification

Tags are normalized organization-scoped entities. Deleting a referenced tag is
rejected unless an explicit audited cascade is requested. Effective Carbon to
Silicon visibility is the union of shared-tag access and explicit extra-Silicon
grants.

Trust remains advisory metadata. Precedence is organization default, tag rule,
then exact Silicon rule; more specific rules win and equal-specificity conflicts
resolve to the more restrictive level. Trust selectors use typed references,
not parsed free-form strings.

`reports_to` is Silicon-to-Silicon inside one organization. Self-links and
cycles are rejected. Root level is one and each child's level is its parent's
level plus one. A Silicon with direct reports cannot be removed without an
atomic reassignment.

## D-020 — Approval semantics

**Status:** Accepted clarification

A Carbon job-role change requires the affected Carbon and one currently
eligible owner/admin approver. A Silicon job-role change requires one currently
eligible owner/admin. Approval payloads are immutable, rejection is terminal,
decisions are unique per approver, and the terminal change is applied exactly
once. Silicon-token rotation requires owner approval and step-up authentication.

## D-021 — Provider boundaries

**Status:** Accepted

Postmark sends email OTP and invitation messages. The Twilio Messages API
delivers IAM-generated phone OTPs; Twilio never owns or verifies the code.
WorkOS handles enterprise SSO. Iris supplies deterministic Carbon
and Silicon profile-photo URLs. Silicon Hook provisions the default `Silicon
IAM` hook. Each provider is behind an application port with a disabled/local
implementation for deterministic tests; production startup refuses insecure
fallbacks.

## D-022 — Contract and code evolve together

**Status:** Accepted

`openapi.yaml` is the public HTTP contract and is tested for syntactic validity
and route coverage. `API_DOCS.md` explains the contract. `UNDERSTANDING.md`
remains the product-intent document. Only its obsolete separate developer
email/password paragraph has been removed at the product owner's direction.
Implementation-specific interpretation belongs in this decision log rather than
being silently added to the product brief.

## D-023 — Database migrations are explicit release steps

**Status:** Accepted

SQLx forward migrations are embedded for verification but are executed by a
dedicated migration command/release process, never implicitly by every API
replica. Production uses distinct runtime and migrator database principals.
Schema changes follow expand, backfill, observe, then contract sequencing.

## D-024 — Sensitive data is encrypted and searchable by blind index

**Status:** Accepted

Normalized email addresses and phone numbers are encrypted at the application
boundary with an authenticated encryption key from the secret provider. Exact
lookup and uniqueness use a versioned HMAC blind index. Logs, traces, errors,
audit diffs, and metrics do not contain raw credentials, OTPs, or complete
contact identities.

## D-025 — API consistency conventions

**Status:** Accepted

The API is JSON under `/api/v1`, uses the documented structured error envelope,
opaque cursor pagination, `X-Request-ID`, `X-Org-ID` for downstream-compatible
organization context, and `Idempotency-Key` for externally initiated mutations.
Health endpoints are `/healthz`, `/readyz`, and `/api/v1/version`.

## D-026 — PostgreSQL 16 is the portable minimum

**Status:** Accepted

Migrations and queries support PostgreSQL 16 and newer. Newer production
versions may be selected after compatibility verification, but application code
does not rely on a feature introduced after PostgreSQL 16 without superseding
this decision.

## D-027 — Principal supertype and tenant-qualified references

**Status:** Accepted

An internal `principals` table gives Carbons, Silicons, applications, and
services collision-free identity and a common authentication epoch. Typed
subtype tables carry domain data. Organization-owned records use composite
organization-qualified foreign keys so a UUID from another tenant cannot be
attached accidentally even if application authorization has a defect.

PostgreSQL row-level security is defense in depth. Request code uses
transaction-local principal, organization, application, and request settings;
pooled connections never retain session-level tenant state.

## D-028 — One-time secret responses have a bounded replay window

**Status:** Accepted

Successful create/rotation operations that reveal a raw Silicon token,
application secret, or webhook signing secret store only an authenticated,
encrypted response envelope in the corresponding idempotency record. The same
caller, route, request digest, and idempotency key may replay that response for
ten minutes. The envelope is then destroyed and a lost secret requires a new
rotation. Plaintext secret responses are never persisted.

## D-029 — SSO admits only existing Carbons under configured policy

**Status:** Accepted clarification

SSO never creates a Carbon. An organization using `join_method=sso` must have an
active WorkOS connection and an explicit SSO membership policy before admitting
members. A successfully authenticated existing Carbon may join without a
pending email invite only when that policy permits the verified WorkOS identity.
The policy supplies member defaults for job role, tags, first Silicon, and
trust. Otherwise IAM requires a pending invitation.

## D-030 — One active application webhook in v1

**Status:** Accepted

The schema supports versioned webhook endpoint history, but the v1 application
API exposes exactly one active webhook destination at a time, matching the
product brief. Endpoint replacement is reviewed, audited, and preserves old
delivery records.

## D-031 — Initial retention policy is configurable and conservative

**Status:** Accepted pending compliance review

Default retention is: security audit and governance history 2,555 days; login
history 365 days; expired OTP/challenge metadata 30 days; expired or revoked
token metadata 90 days, extended to 365 days for detected refresh replay;
webhook delivery attempts 45 days; completed idempotency responses 24 hours,
except one-time secret envelopes which are destroyed after ten minutes.

These defaults are configuration policy, not authorization behavior. Production
launch requires privacy/compliance review for the selected jurisdictions.

## D-032 — Membership identity survives removal and reactivation

**Status:** Accepted

One organization/principal pair retains one membership UUID for its history.
Removal disables authority and increments the authorization epoch. A deliberate
reactivation uses the same membership row, increments the epoch again, resets
directory defaults through an audited workflow, and never revives old sessions
or grants implicitly.

## D-033 — Invitations never grant admin authority directly

**Status:** Accepted

Carbon invitations always create or reactivate an `org_role=member`
membership. Admin promotion and capability delegation occur through their
separate privileged, audited workflows. Invitation `job_role` remains
descriptive metadata.

## D-034 — Sensitive protocol data is excluded from observability

**Status:** Accepted

HTTP telemetry records the method, matched route template, response status,
latency, and request ID. It does not record raw URI query strings, request or
response bodies, cookies, authorization headers, OAuth codes, SSO state, or
tokens. Provider and database errors are classified and redacted before they
cross the application boundary. Every response carries an `X-Request-ID`, and
JSON error envelopes include the same identifier.

## D-035 — Runtime and migration credentials are separate

**Status:** Accepted

The API and worker read the restricted `IAM_DATABASE_URL`. The one-shot
migration process reads only `IAM_MIGRATOR_DATABASE_URL` plus its minimal pool
and telemetry settings; it does not require application cryptographic secrets
or provider credentials. Production database connections must request TLS and
production Redis/Valkey connections must use TLS.

## D-036 — Shutdown is bounded and coordinated

**Status:** Accepted

Both API and worker processes handle `SIGINT` and `SIGTERM`, stop accepting or
claiming work, and use the configured shutdown deadline to drain in-flight
work. Expiry of the deadline terminates the drain and is logged as an
operational error so container orchestrators cannot leave replicas hanging
indefinitely.

## D-037 — Cryptography is typed, row-bound, and rotation-aware

**Status:** Accepted

Token peppers, blind-index keys, and data-encryption keys are loaded as
versioned keyrings with one explicit current write version and retained prior
read versions. Stored digests and ciphertext identify their key version; old
keys may be removed only after the corresponding data has expired or been
re-keyed.

Callers select closed cryptographic purpose enums rather than arbitrary strings.
Authenticated-encryption associated data binds the schema version, field kind,
tenant when present, entity UUID, and key version, preventing ciphertext from
being transplanted between rows. Each actor/session credential class has a
distinct prefix and digest domain. Credential, nonce, and OTP generation uses a
fallible operating-system CSPRNG and fails closed if entropy is unavailable.

## D-038 — The HTTP edge is bounded and protocol-correct

**Status:** Accepted

Browser CORS uses an explicit origin allowlist, permits credentials only for
those origins, and never reflects arbitrary origins. A bounded global
concurrency limit rejects excess admission before database work. Server-side
processing deadlines return `504 Gateway Timeout`; every externally initiated
mutation is idempotent so clients can safely resolve an uncertain outcome.

Transport rejections retain their original status and protocol headers while
using the standard JSON error envelope. Release builds retain panic unwinding
so an isolated handler panic can be converted to a redacted `500` without
terminating the entire API process; recoverable errors never use panics.

## D-039 — Principal status is the credential revocation projection

**Status:** Accepted

Every lifecycle change that enables, suspends, rejects, or deletes a Carbon,
Silicon, application, or service updates its `principals.status` and increments
`principals.auth_epoch` in the same transaction as the typed aggregate change.
Pre-authentication token lookup validates this non-tenant security projection,
the parent session, and any membership epoch without reading an RLS-protected
application or directory row before a principal context exists.

## D-040 — Runtime configuration fails closed within hard bounds

**Status:** Accepted

Startup rejects zero, excessive, or internally inconsistent timeouts, pool
sizes, body limits, concurrency, worker leases, retry counts, credential
lifetimes, and OTP attempts. Access tokens are bounded to 60–900 seconds,
authorization codes to 30–120 seconds, OTPs to 60–600 seconds with at most five
attempts, and refresh families to one hour–365 days. Keyrings contain at most 16
positive `smallint` versions and production rejects reused material across all
cryptographic purposes.

Production requires verified TLS for PostgreSQL, TLS for Redis/Valkey, HTTPS
for every public/provider base URL, exact allowed base paths, complete provider
credential groups, an exact CORS allowlist containing the auth frontend, and no
local provider or OTP-exposure mode. Non-production accepts absent providers
but rejects partially configured Twilio or WorkOS groups.

## D-041 — IAM owns OTP generation; providers only deliver

**Status:** Accepted

IAM generates, hashes, limits, and atomically consumes every OTP. Postmark sends
email through its transactional Email API, and Twilio sends the IAM-generated
code through the Messages API using a Messaging Service SID. Twilio Verify is
not used because delegating code generation and verification would split the
challenge state and contradict the central attempt/replay invariants.

Provider HTTP clients use TLS, disabled redirects, short connection/request
deadlines, bounded response bodies, and classified retryable/permanent errors.
Provider response bodies, recipient contact data, and codes are never logged.

## D-042 — Organization capabilities use one explicit vocabulary

**Status:** Accepted

The API, Rust policy layer, and database catalog use exactly:
`organization.update`, `members.invite`, `members.update_directory`,
`members.remove`, `silicons.create`, `silicons.update_directory`,
`silicons.manage_hierarchy`, `silicons.remove`, `silicons.rotate_token`,
`tags.manage`, `trust.manage`, `roles.request`, `roles.approve`,
`admins.create`, `admins.manage`, `sso.manage`, and `audit.read`.

Active organization membership already grants same-organization directory and
job-role visibility, so there is no redundant `members.read` capability.
Promotion and capability/demotion control remain separate through
`admins.create` and `admins.manage`; no ambiguous `authorization.manage` alias
is accepted.

## D-043 — OTP delivery is post-commit and never recoverably persisted

**Status:** Accepted

The API commits the new keyed OTP digest, challenge state, audit record, and
secret-free outbox event before calling Postmark or Twilio with no database
transaction open. Provider calls have a five-second deadline. A failed or
ambiguous delivery may leave a valid but undelivered challenge; a resend
atomically supersedes it with a new digest and code.

Public initiation responses remain uniform so provider success cannot become an
account-enumeration side channel. The code is never stored in plaintext or as a
decryptable notification envelope. Durable notification jobs are reserved for
invitations and security notices whose content can be safely reconstructed.

## D-044 — PostgreSQL is the authoritative abuse-control fallback

**Status:** Accepted

The portable baseline uses atomic PostgreSQL fixed-window buckets for OTP,
login, invitation, and other abuse controls; an optional Redis-compatible
accelerator may implement the same policy without changing feature code. Raw
IP addresses, contact points, and actor identifiers are never stored in a
bucket: IAM persists a purpose-separated keyed digest of a canonical scope.

Each policy has a positive request limit and whole-second window no longer
than 24 hours. The first request beyond the limit atomically blocks the
remainder of that window and returns an exact bounded `Retry-After`. A token
pepper rotation may reset these intentionally short-lived, non-authoritative
buckets; durable security outcomes and idempotency records do not rely on
rate-limit state.

## D-045 — Runtime key metadata is reconciled without storing key material

**Status:** Accepted

API and worker startup transactionally register every configured token-HMAC,
contact-lookup-HMAC, and contact-AEAD version through a narrowly scoped
`SECURITY DEFINER` database function. The function accepts only those three
purposes, serializes promotion per purpose, refuses retired versions, and moves
the previous write version to read/decrypt-only status. PostgreSQL receives
only purpose, version, and lifecycle metadata—never cryptographic material.

`PUBLIC` has no execute access. Deployment provisioning must explicitly grant
the runtime role execute access to this one function. All instances in a
deployment must use the same current versions; write-version changes are a
coordinated rollout while prior versions remain configured for reads.

## D-046 — Idempotency commits in the domain transaction

**Status:** Accepted

Every externally initiated mutation claims its idempotency record inside the
same PostgreSQL transaction as the domain mutation, audit event, and outbox
event. A process failure before commit therefore rolls back the claim and the
mutation together. Caller scope, key, and deterministic request bytes are
stored only as separate purpose-bound HMAC digests sharing an explicit key
version. A reused key with different request bytes is rejected.

Successful response status and exact JSON bytes are AEAD-encrypted with
row-bound associated data. Ordinary responses replay for up to 24 hours;
responses containing a newly issued credential replay for at most ten minutes
so retries can resolve uncertain outcomes without creating another secret.
Expired or ambiguous records fail closed instead of repeating the mutation.

## D-047 — Silicon machine capabilities are a closed projection

**Status:** Accepted clarification

“Machine capabilities” are not a second, caller-defined authorization
namespace. The Silicon-specific API field and replacement endpoint project the
same organization capability grants, restricted to catalog entries explicitly
marked as allowed for Silicons: `members.update_directory`,
`silicons.update_directory`, `silicons.manage_hierarchy`, `trust.manage`, and
`roles.request`.

Unknown strings and Carbon-only capabilities are rejected. This preserves one
auditable, deny-by-default policy engine while allowing the UI to distinguish
human administrator grants from the smaller automation-safe Silicon subset.

## D-048 — Step-up assertions are opaque, action-bound, and single-use

**Status:** Accepted security correction

A step-up result is a random `sup_` credential stored only as a
purpose-separated keyed digest with its key version. It is bound to the current
Carbon, authentication session, exact privileged action, optional resource,
assurance level, and a five-minute database expiry. Verified-channel
reauthentication has assurance level two; phishing-resistant WebAuthn has level
three.

Validation atomically consumes the assertion in the same transaction as the
privileged mutation. A transaction rollback therefore preserves the assertion,
while a committed mutation makes replay impossible. Missing assertions return
`428`; malformed, expired, consumed, resource-mismatched, or insufficient
assertions return `412` without disclosing which check failed.

## D-049 — Webhook delivery is leased, pinned, and at least once

**Status:** Accepted

The worker first expands a committed outbox event into immutable application
and Silicon Hook recipients, then completes the outbox row; delivery is a
separate leased stage. Claims use `FOR UPDATE SKIP LOCKED`, expired leases are
recoverable, earlier events with the same aggregate ordering key block later
ones, and retries use capped exponential backoff with deterministic jitter.
Consumers receive the same event UUID on every attempt and must de-duplicate.

Application payloads are explicit versioned envelopes and are signed over the
timestamp, binary event UUID, and exact body with the endpoint HMAC key. Before
each attempt IAM resolves the destination, rejects any private, loopback,
link-local, documentation, multicast, or reserved address, rejects mixed
public/private DNS answers, and pins the accepted answers into the HTTP client.
Redirects are disabled and response bodies are bounded and discarded after a
digest is recorded. This defends both initial SSRF and DNS rebinding.

## D-050 — Silicon Hook activation is an asynchronous identity transition

**Status:** Accepted

Creating a Silicon leaves its principal in `provisioning` and creates a pending
Hook row. A leased worker calls the Hook `POST /api/v1/hooks` contract with the
fixed name “Silicon IAM,” global Silicon ID, organization UUID, and the Hook row
UUID as its provider idempotency key. The returned endpoint must share the
configured Hook origin and match the expected Silicon path before IAM encrypts
it with row- and tenant-bound AEAD.

Hook activation, Silicon/principal activation, a system audit event, and the
`iam.silicon.initialized` outbox event commit atomically through a narrowly
scoped database function. Failures retain retry/dead-letter state without
holding a database transaction across provider I/O. The initialized event
contains a minimal Silicon record and organization snapshot, never credentials.

## D-051 — Durable notifications are reconstructed from allowlisted templates

**Status:** Accepted

The database notification queue stores only a template identifier, context
reference, and verified encrypted contact reference. The worker decrypts the
active contact just in time and reconstructs invitation or security-notice text
from a closed template vocabulary; caller-provided message bodies are never
accepted. Invitation links identify the logged-in Carbon workflow but contain
no OTP or bearer credential. Postmark and Twilio delivery uses bounded leases,
safe provider receipts, capped retries, and terminal failure state.

## D-052 — Membership creation authority is principal-kind specific

**Status:** Accepted security refinement

Row-level security permits a Carbon membership insert through
`members.invite` and a Silicon membership insert through `silicons.create`.
The creator/owner bootstrap remains a separate narrowly scoped Carbon case.
Creating a Silicon does not implicitly grant `tags.manage` or `admins.manage`:
requested tag assignments and machine capability grants require those
capabilities independently.

## D-053 — WorkOS lifetimes and signatures follow the provider contract

**Status:** Accepted correction to the product understanding

An Admin Portal setup URL is a secret, provider-controlled link that expires
five minutes after issuance; IAM returns `expires_in=300` and does not promise
or locally extend the earlier two-hour lifetime. IAM reconciles organization
creation by immutable external ID and never blindly retries an ambiguous create.

WorkOS webhooks use only `WorkOS-Signature`, containing an epoch-millisecond
`t` value and one or more `v1` HMAC-SHA256 values. IAM signs/verifies
`t + "." + exact_raw_utf8_body`, compares in constant time, enforces a
300-second freshness window, and persists the provider event ID for replay-safe
asynchronous processing.

## D-054 — Step-up OTP attempts are challenge-local and bounded

**Status:** Accepted security refinement

Each step-up challenge persists its delivery channel, configured attempt cap,
and monotonic failed-attempt count. OTPs use a digest purpose distinct from the
resulting `sup_` assertion. A failed verification increments the count while
holding the challenge lock and atomically cancels the challenge at exhaustion;
cancelled, expired, completed, or exhausted challenges cannot issue an
assertion.

## D-055 — Public application credential and collaborator semantics are canonical

**Status:** Accepted

Application client secrets use `ask_`, OAuth access tokens use `oat_`, and
OAuth refresh tokens use `ort_`; Carbon session refresh tokens remain `rft_`.
Distinct secret kinds and digest domains prevent one credential class from
being accepted as another. Immutable application handles allow 3–80 characters.

Application collaborators have the closed roles `owner_delegate`, `developer`,
and `viewer`. An owner delegate has full delegated management, a developer may
manage technical configuration and credentials but cannot delete the app or
manage collaborators, and a viewer is read-only. Refresh-token families bind
to the exact consent grant and snapshot their original scope ceiling; rotation
can only issue the intersection of that snapshot, still-active consent, and
currently approved scopes.

## D-056 — Invitation acceptance crosses RLS through one narrow function

**Status:** Accepted security refinement

A Carbon that has not joined an organization cannot be granted broad tenant
read or self-insert policies merely to accept an invitation. One fixed-search-
path `SECURITY DEFINER` function binds the current Carbon, organization handle,
pending unexpired unsuperseded invitation, verified contact, and exact
key-versioned invitation digest. It atomically consumes the invitation and
creates or reactivates the membership plus approved defaults. Public execute is
revoked and the deployment grants only the runtime role permission to call this
function.

## D-057 — Platform suspension is destructive to delegated authority, not tenant ownership

**Status:** Accepted

Platform administration adds explicit `carbons.status_manage` and
`deliveries.manage` capabilities instead of treating unrelated application or
audit authority as an implicit superuser permission. Every platform mutation
requires a current active Carbon, the exact capability, a phishing-resistant
action-bound step-up assertion, and request-bound idempotency.

Suspending a Carbon increments its principal authentication epoch and revokes
all active sessions, access and refresh tokens, OAuth consents, application
collaborator grants, platform-role grants, organization capability grants, and
non-owner memberships. Those delegations are not restored by reactivation. A
Carbon that is the active owner of an active organization must transfer
ownership before suspension; silently suspending that organization or leaving
an ownerless tenant is forbidden. Bootstrap platform grants and system audit
events have nullable human provenance so the API reports history truthfully.

Failed-delivery replay preserves the lifetime attempt counter and immutable
attempt history. It resets only the retry-cycle counter, increments a separate
manual-replay counter, clears the terminal lease/error state, and requeues the
same delivery and event identity. Delivery rows carry `updated_at`; platform
role grants carry an explicit aggregate version so audit and outbox ordering do
not invent versions.

## D-058 — WorkOS callback correlation does not invent nonce attestation

**Status:** Accepted provider-contract clarification

The WorkOS authorization endpoint accepts a nonce, but its documented token
exchange returns a Profile rather than an ID token and does not return a nonce
claim. IAM therefore does not claim that WorkOS attests or echoes the nonce.
The callback `state` is a bounded opaque pair of independent CSPRNG values,
stored only as purpose-separated state and nonce digests and bound to the exact
pending Carbon, organization, connection, and authentication session. Both
components must match on callback. Sending the second component in WorkOS's
nonce parameter is defense in depth and forward compatibility, not a provider-
verified claim.

SSO correlation digests and encrypted return URIs use dedicated cryptographic
domains. Successful interactive Carbon login issues a host-only Secure,
HttpOnly, SameSite=Lax `iam_session` cookie; logout and current-session
revocation clear it. Provider-controlled one-time responses use an explicit
bounded idempotency replay lifetime, with WorkOS setup links fixed to 300
seconds rather than the ordinary ten-minute secret-response default.

## D-059 — Approval creation authority follows the immutable request subtype

**Status:** Accepted security refinement

Approval-request and approval-requirement inserts are authorized from the
immutable request kind rather than through one generic governance capability.
Carbon and Silicon job-role changes require `roles.request`; Silicon credential
rotation requires `silicons.rotate_token`; and ownership transfer remains
restricted to the current active Carbon owner. The row-level policies also bind
the organization context, requester membership, current principal, subtype,
requirement shape, required capability, and quorum. This prevents a caller from
using authority for one workflow to manufacture a differently governed approval.

## D-060 — Revocation events retain their commit-time recipients

**Status:** Accepted reliability and security refinement

Application webhook recipient expansion evaluates a subject credential and
membership at the outbox event's immutable occurrence time. A suspension,
removal, or token revocation can therefore invalidate authority in the same
transaction without erasing the application that must receive the resulting
revocation event. The destination application, endpoint, and signing key must
still be active when delivery is expanded, and no historical check can restore
authorization or permit a new API request.

## D-061 — Database ownership is isolated from runtime processes

**Status:** Accepted deployment boundary

The one-shot migrator owns database objects and is never used by a long-running
process. API and worker logins inherit separate, non-login group roles that are
explicitly `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`, and
`NOBYPASSRLS`. Public schema/table/function privileges are revoked. The API
receives only the reviewed per-relation, per-verb, sequence, and function
capabilities enumerated by D-074; the worker receives only its queue tables,
RLS-scoped Silicon data, and narrowly named definer functions. Definer functions
that expose worker-only encrypted delivery material are not callable by the API
role.

Runtime grants are applied as an explicit post-migration deployment step rather
than permissive default privileges, so a newly migrated table is inaccessible
until its runtime need is reviewed. Local Compose exercises the same role split;
production login credentials remain the responsibility of the selected secret
and deployment platform.

## D-062 — WorkOS SSO policy uses exact Profile group strings

**Status:** Accepted provider-contract clarification

The documented WorkOS SSO Profile returns `groups` as strings and does not
provide stable group-ID objects in the token-exchange response used by IAM.
The admission-policy field is therefore `allowed_groups`, not
`allowed_group_ids`. Values are bounded, unique, and compared exactly and
case-sensitively with the authenticated Profile strings. IAM does not infer a
stable identifier guarantee that the provider contract does not expose.

## D-063 — Application protocols expose truthful state and closed authority

**Status:** Accepted security and contract refinement

An application webhook that has never passed review has no active destination:
its public `active_url` is null, its submitted URL is `pending_url`, and its
lifecycle is `pending_review`. Delivery, login-history, and consent projections
carry every public contract field and a complete public actor reference rather
than leaking persistence-shaped records. Every successful OAuth authorization-
code exchange creates a consent-bound rotating `ort_` refresh-token family;
`offline_access` is retained only as a compatibility scope and never controls
whether refresh capability exists. A family can issue only the intersection of
its immutable scope snapshot, the still-active consent, and still-approved app
scopes, and reuse compromises the whole family.

When platform review removes an approved scope, the same transaction revokes
each still-active application access token for that client that carries any
newly removed scope. Refresh families remain usable only through the reduced
current-scope intersection.

OBO actions are the fixed organization-capability vocabulary and unknown
strings fail before any authority lookup. Sensitive application, OAuth, and OBO
entry points use shared PostgreSQL rate-limit buckets and return protocol-safe
errors with `Retry-After` and `RateLimit-*` metadata. Application-management
routes require a direct `silicon-iam` Carbon token with `iam.self`; delegated
third-party `oat_` tokens cannot act as that Carbon. Application Basic-secret
lookup, active/retiring recheck, principal validation, and usage touch occur
under one row-locking transaction so concurrent revocation wins atomically.

The API also reconciles the configured 32-byte Ed25519 seed at fail-closed
startup. A cross-replica advisory lock serializes rotation, the previous key is
retained for a verification overlap, key-id or public-material collisions abort
startup, and PKCS#8 private material is encrypted with signing-key-specific AAD.
Discovery advertises only active stored algorithms, JWKS retains unexpired
verification keys, and OIDC `auth_time` comes from the authenticated parent
session while `nonce` and `sid` remain bound to that flow.

## D-064 — Pre-authentication protocol tables require narrow database entry points

**Status:** Accepted production-hardening boundary

Pre-authentication tables cannot use ordinary caller-context RLS because the
caller identity is discovered only after resolving a credential. They therefore
receive no schema-wide privilege. Each required relation and operation is
enumerated in the exact runtime capability manifest from D-074. Protocol
handlers use one transaction to resolve keyed digests, verify secrets in
constant time, lock the matched rows, re-check current principal, session,
consent, membership, scope, and credential state, and consume or rotate the
credential atomically.

Fixed-search-path, Public-revoked `SECURITY DEFINER` functions are used only for
transitions whose pre-authentication or cross-policy boundary cannot be
expressed safely through direct caller-context DML. New protocol tables and
verbs remain inaccessible until both the production query and its
authorization/locking analysis extend the manifest deliberately.

## D-065 — Passkeys use library-verified, server-bound WebAuthn ceremonies

**Status:** Accepted authentication hardening

Passkey enrollment and phishing-resistant step-up use `webauthn-rs`; IAM does
not implement attestation or assertion verification itself and never trusts
client-supplied public-key metadata without a successful library ceremony.
Opaque ceremony state is AEAD protected at rest and bound to one Carbon,
authentication session, RP ID, exact origin, action, optional resource, and
short expiry. Credential state and signature counters are updated in the same
transaction that consumes the ceremony and issues the five-minute assertion.
A non-increasing nonzero counter revokes the credential and fails closed.

WebAuthn credentials and ceremony rows have self-scoped row-level security.
Platform administrators cannot revoke their final active passkey, preserving a
phishing-resistant path for privileged actions.

## D-066 — IAM token management is caller-bound and revalidates current authority

**Status:** Accepted authentication hardening

Silicon SID/STK login resolves an exact active credential, principal,
organization, and membership through a fixed-search-path, Public-revoked
database function, verifies the 256-bit credential in constant time, and then
mints independent `sat_` access and `rft_` rotating refresh tokens. Access and
refresh authentication revalidate the active principal, parent session,
organization, membership, and current authorization epochs; refresh replay
revokes the complete family.

IAM introspection is authenticated with a verified application credential and
returns active metadata only when that application is the token's client or
audience. Revocation by a principal requires a direct, unbound `silicon-iam`
credential with `iam.self`; an application may revoke only tokens for which it
is the client or audience. Unknown well-formed token values retain the uniform
idempotent response.

## D-067 — Cross-policy organization teardown is one constrained transition

**Status:** Accepted security refinement

Membership removal, Silicon retirement, administrator role changes, and tag
archival cross tables whose ordinary row policies intentionally require
different capabilities. The API does not gain those unrelated capabilities.
Instead, fixed-search-path, Public-revoked `SECURITY DEFINER` functions lock the
target aggregate, re-check the exact current principal, tenant, capability,
principal subtype, and expected version, and perform the bounded cleanup as one
transactional transition. Carbon and Silicon removal use distinct authority;
Silicon removal additionally serializes reporting-graph changes and retires all
credentials, sessions, tokens, Hook state, and delegated access. Tag cascade is
opt-in and removes every membership, invitation, and SSO-policy join while
archiving active trust references.

Deployment binds portable member policies to the API role and installs separate
Silicon/Hook policies for the fixed worker role. This keeps the worker from
evaluating or receiving tenant-authorization helper functions, and runtime
function grants are limited to definer entry points plus the exact invoker
helpers required by RLS and deferred invariant triggers.

## D-068 — Organization authority requires a direct IAM credential

**Status:** Accepted security refinement

Organization management, directory, invitation, trust, and governance routes
accept only access tokens whose audience is `silicon-iam`, which have no client
application, and which carry `iam.self`. Carbon credentials remain globally
bound and therefore carry no organization or membership snapshot. Silicon
credentials must carry both snapshots, and the resolved organization and
membership must match them exactly. A delegated third-party OAuth token cannot
reuse the Carbon or Silicon subject's IAM organization capabilities.

## D-069 — The first platform administrator is bootstrapped from an existing Carbon

**Status:** Accepted security and operations refinement

IAM does not ship a default administrator, shared password, or privileged
backdoor. The first platform administrator must already be an active Carbon and
is granted through the one-shot `iam-bootstrap-admin` command using the
migrator credential. The command verifies that every embedded migration has
been applied, takes a transaction-scoped advisory lock, and refuses to run when
any platform-administrator grant history exists. The grant, redacted audit
record, and outbox event are committed atomically. Subsequent grants and all
revocations use the authenticated platform-administration API. The obsolete
default-administrator email/password line is removed from the product brief in
the same way as the separate developer-login paragraph, preserving the
product owner's existing-Carbon requirement. This decision supersedes D-022's
earlier statement that only the developer-login paragraph was removed.

## D-070 — Ephemeral security state is erased by a bounded worker stage

**Status:** Accepted operations refinement

The worker runs a separately observable maintenance stage on the configurable
maintenance interval, thirty seconds by default.
Each transaction uses bounded, ordered `SKIP LOCKED` batches so multiple workers
can cooperate without long table locks. Expired one-time idempotency response
envelopes are cryptographically erased before their ordinary record retention
ends; expired idempotency records and rate-limit buckets are then deleted.
The worker receives no direct access to idempotency or rate-limit tables. A
fixed-search-path, Public-revoked definer function exposes only bounded cleanup
counts, so the worker cannot read replayable one-time response ciphertext.
Broader business and audit retention remains governed by D-031 and the
deployment's approved compliance policy.

## D-071 — Trusted ingress is a prerequisite for network-derived security metadata

**Status:** Accepted deployment-boundary clarification

This decision supersedes D-013 only where D-013 states that the current
baseline applies IP/subnet limits. The deployment target and trusted proxy
topology are not yet selected, so IAM currently enforces keyed distributed
buckets by normalized identity, authentication/signup session, purpose,
channel, provider, and authenticated caller. Signup sends have a normalized
contact-global bucket independent of the disposable signup-session ID, plus a
per-session bucket, so creating fresh sessions cannot reset send protection.

IP/subnet buckets are enabled only after the deployment defines the direct peer
boundary, allowlisted proxy hops, and one canonical trusted-address extraction
rule. Arbitrary `Forwarded` or `X-Forwarded-For` values are never authority.
For the same reason, login/audit history reserves coarse IP-prefix and safe
user-agent-summary fields but leaves them null in the current baseline rather
than storing attacker-asserted metadata.

## D-072 — Account deletion has bounded, durable terminal finalization

**Status:** Accepted account-lifecycle clarification

`DELETE /api/v1/me` requires a strong ETag, idempotency, and a
phishing-resistant step-up assertion. It fails closed while the Carbon owns an
active organization or application, holds an active platform role, or is the
final active platform administrator. Acceptance immediately changes the
principal to `deletion_pending`, increments its authentication epoch, and
revokes active sessions and token families.

The request has a 30-day grace/retention window. A worker-only,
fixed-search-path, Public-revoked function claims at most 1,000 due requests in
ordered `SKIP LOCKED` batches, performs terminal soft deletion and authority
cleanup, and commits the completed request, redacted audit event, and outbox
event atomically. This makes the public scheduled workflow truthful; it does
not depend on an unspecified external finalizer or hard-delete authoritative
history.

Terminal finalization also erases retained contact PII: it deletes contact and
pending-contact-change blind indexes, removes pending contact-change state,
nulls contact ciphertext, nonce, and encryption-key references, retires every
contact row, and records its purge time. The Carbon profile is anonymized to a
fixed deleted display name with no description or profile-photo URI. The
immutable Carbon handle, UUID, deletion timestamp, and minimum relational and
audit skeleton remain only to prevent identifier reuse and preserve security
history. Deferred invariants are forced immediate while the definer's private
authority is still installed, so finalization never depends on the restricted
worker having trigger-helper privileges at transaction commit.

## D-073 — Runtime-key activation is a monotonic operator transition

**Status:** Accepted security and operations refinement

PostgreSQL is authoritative for the active metadata version of each
application-managed runtime keyring. API and worker startup may initialize a
completely empty purpose and may stage a locally available higher version as
`decrypt_only`; once metadata exists, startup is verification-only. It fails
closed unless the configured current version exactly matches the one database
active version and every database `active` or `decrypt_only` version is present
locally. Consequently, a stale pod can neither demote a newer active version nor
restart without every retained key required by persisted data or credentials.

Activation is a separate, explicit compare-and-swap operation. The
`iam-activate-key-version` command names a closed purpose, the exact expected
current version, and a strictly higher version already staged as decrypt-only.
A purpose-scoped transaction advisory lock serializes startup and activation;
one partial unique index enforces a single active version; the prior version
becomes decrypt-only in the same transaction; and append-only metadata records
the database login and transition. Downgrades, missing preload, ambiguous
current state, and repeated activation all fail without changing state.

Production supplies the command a dedicated login inheriting only the
NOLOGIN `silicon_iam_key_operator` role. That role receives schema usage and
execution of the activation function only, while direct API writes to key
metadata and activation history are revoked. The process accepts only the
isolated `IAM_KEY_OPERATOR_DATABASE_URL`; migration-owner credentials are not
part of its configuration surface, and the function independently verifies
the original session login's operator-role membership. Rotation therefore uses two
fleet rollouts: first preload the future key everywhere without changing
configured current, then activate it once, then immediately roll configured
current forward while retaining the prior decrypt-only key. Retirement remains
intentionally unavailable until a separate procedure can prove no stored value
or unexpired credential references the version.

## D-074 — Database runtime authority uses exact capability manifests

**Status:** Accepted least-privilege boundary

Runtime database grants are rebuilt from zero and are explicit by process,
relation, operation, function, and sequence. The API role no longer receives
schema-wide table DML. Its table manifest is derived from production API SQL,
excluding tests and the worker, migrator, bootstrap-administrator, and
key-operator binaries; the only additional reads are relations required by
invoker-rights deferred invariant triggers. Delete authority is limited to the
four relationship/snapshot tables that production API code actually replaces.
Worker table grants likewise match its claim/delivery queries, and it cannot
update immutable outbox-recipient bindings.

Every current non-partition IAM table is classified as API-readable or
explicitly denied. A new unclassified base table or sequence aborts deployment,
while child partitions receive no direct runtime privilege and are reached
only through an authorized partitioned parent. The API receives only `USAGE`
on the audit and outbox identity sequences; runtime-key activation history and
its sequence remain inaccessible. Function execution remains a separate exact
name manifest with overload detection and a closed classification of every
`SECURITY DEFINER` function. This keeps future schema additions denied until a
reviewed production query and RLS/trigger analysis deliberately extends the
appropriate capability list.

## D-075 — Worker leases and shutdown share explicit safety deadlines

**Status:** Accepted reliability refinement

A durable-worker lease is at least twenty seconds, must exceed the poll
interval, and must be strictly longer than the database-acquire timeout plus
the statement timeout plus the ten-second provider deadline plus a five-second
completion margin. A claimed Silicon Hook renews its still-owned, unexpired
lease immediately before provisioning network I/O, matching the notification
and webhook delivery stages. Partial ready/retry and expired-lease indexes keep
Hook recovery bounded as terminal history grows.

The worker runs at most one claim cycle at a time while the signal future stays
responsive. Shutdown receives biased priority, immediately stops new claims,
and drains the in-flight cycle and pool within the configured shutdown deadline.
If the deadline expires, the cycle is aborted and its durable leases make the
unfinished work recoverable. Compose grants the worker 310 seconds before
`SIGKILL`, exceeding the configuration's 300-second maximum drain deadline.

## D-076 — Untrusted webhook delivery ignores ambient proxies and preserves transient retries

**Status:** Accepted transport-hardening refinement

The DNS-pinned client used for untrusted webhook destinations disables ambient
HTTP proxy discovery. Otherwise a deployment proxy could perform a second DNS
resolution and defeat the public-address validation and connection pinning.
Provider HTTP 408, 425, 429, and all 5xx responses are transient for retry
purposes. Response bodies remain bounded; if a transient response exceeds the
bound it is normalized to a retryable unavailable result, while an oversized
non-transient response remains a terminal protocol violation.

Application webhook registration and delivery-time transport validation
independently reject DNS hostnames ending in the root-label dot before
resolution. IAM never silently strips that suffix: names such as `localhost.`
or `service.internal.` may be treated as equivalent by resolvers while bypassing
suffix classifiers. Historical stored destinations therefore receive the same
check immediately before DNS pinning.

## D-077 — Retention is a bounded worker transition with referentially safe erasure

**Status:** Accepted operations and privacy refinement

D-031's defaults are enforced by a configurable worker sweep: 365 days for
login/authentication history; 30 days for expired OTPs, challenges, ceremonies,
and abandoned signup/contact/authorization state; 90 days for expired or
revoked access, OBO, and refresh metadata; 365 days for compromised refresh
families; 45 days for webhook-attempt telemetry; and 2,555 days for security
audit events. Each duration is a whole-day value between one and 36,500, each
table claims at most 1,000 configured root records with ordered `SKIP LOCKED`,
and compromised-family retention cannot be shorter than ordinary token
retention.

The worker receives no direct visibility or delete authority over retention
tables. One fixed-search-path, Public-revoked `SECURITY DEFINER` function checks
the original session login's membership in `silicon_iam_worker`, installs a
private backend-and-transaction capability row, performs the fixed cleanup, and
removes that capability before returning. The function accepts one value from a
closed 21-phase vocabulary. Each maintenance tick invokes exactly one phase,
selected round-robin, in its own statement and transaction; this prevents a
retention sweep from monopolizing a delivery cycle for as many as 21 statement
timeouts. Failure of one phase is isolated to its tick, while the cursor advances
so later tables are not starved. The in-memory cursor is initialized from the
current Unix-epoch sweep slot modulo 21, with a zero fallback for invalid clock
input, so rolling restarts do not repeatedly reset cleanup to the first table and
replicas normally converge on the same phase for `SKIP LOCKED` cooperation.
Append-only audit/history triggers accept policy deletion only while the
per-phase capability exists. This is stronger than a caller-settable custom GUC
and remains fail closed if the worker role has not been provisioned.

Approval decisions retain their step-up assertion and source IDs as governance
evidence. After the 30-day cutoff, IAM nulls OTP/assertion digests and encrypted
WebAuthn ceremony state, including their key-version references, while keeping
only non-secret purpose, assurance, and timing skeletons. Old authentication
sessions are deleted when unreferenced; sessions still required by audit,
consent, governance, or lifecycle foreign keys have optional fingerprints and
revocation detail erased and remain skeletal until later sweeps can remove
them. Refresh-token families are the bounded cleanup aggregate so their
self-referential rotation chain and immutable scope snapshot are removed
atomically.

## D-078 — Worker configuration and cryptographic authority are process-scoped

**Status:** Accepted least-authority refinement

The durable worker has a dedicated `WorkerProcessSettings` composition root. It
loads only its restricted database connection, environment and logging policy,
poll/retry/concurrency/retention settings, shutdown deadline, authentication
frontend URL for invitation links, contact-AEAD keyring, and the Postmark,
Twilio, Silicon Hook, and Iris credentials needed for delivery. It neither
parses nor retains Redis configuration, token peppers, contact blind-index
keys, browser-cookie keys, JWT signing material, local OTP-exposure authority,
or WorkOS credentials. The worker binary does not load the shared development
`.env`, and its Compose service uses an explicit environment allowlist rather
than inheriting the API runtime map.

Worker feature code receives an AEAD-only encryption service built directly
from the contact-encryption keyring. That type has no credential generation,
digest, verification, or blind-index operation, so later worker code cannot
silently acquire authentication authority through a general crypto service.
Startup reconciles only the `contact_aead` key-metadata purpose through a
worker-role-attested, fixed-purpose database wrapper. The worker role receives
no execution authority on generic keyring reconciliation; API startup retains
that function for its three owned keyrings. Focused subprocess tests load
the worker from only its minimum intended environment, prove forbidden
authority variables are ignored even when malformed, and enforce the bounded
delivery-concurrency setting.

## D-079 — Outbound worker concurrency is process-wide and lease-safe

**Status:** Accepted reliability refinement

Hook provisioning, notification delivery, and application/Hook webhook
delivery share one process-scoped asynchronous stage gate acquired before rows
are claimed. A stage claims at most the smaller of the configured batch size
and delivery concurrency, processes that wave with bounded unordered
concurrency, and awaits every job before releasing the gate. The configured
delivery concurrency is therefore an aggregate external-I/O ceiling for the
worker process, and a durable row is never claimed merely to wait behind
another outbound stage. Database-only outbox expansion and account-deletion
finalization may continue concurrently.

The worker refuses startup until all embedded migrations are applied. An
expired Silicon Hook provisioning lease remains reclaimable even when the
crashed claim consumed the nominal final attempt; the stable provider
idempotency key makes recovery safe and prevents a terminal transition from
becoming permanently stranded.

## D-080 — Dependency and release policy fails closed

**Status:** Accepted supply-chain boundary

Runtime dependencies and enabled crate features are limited to those used by
production code. Builds, tests, and dependency-policy checks use the committed
lockfile. `cargo-deny` rejects advisories, yanked crates, wildcard requirements,
unknown registries or Git sources, unapproved licenses, and duplicate versions
except for an exact, commented allowlist of unavoidable transitive versions.
The WebAuthn user-presence-only security-key feature is explicitly forbidden.

JWT operations use the `aws_lc_rs` backend, keeping the advisory-affected
RustCrypto RSA implementation out of the dependency graph. Release builds
retain integer-overflow checks, the private package points to an explicit
proprietary license file, and CI evaluates advisories, licenses, bans, and
sources with all features against the locked graph.

## D-081 — Authorization codes revalidate authority at exchange

**Status:** Accepted protocol-hardening refinement

An authorization code is not sufficient evidence that the authority present at
approval still exists. Exchange locks the code, request, consent grant, and
current application authority and requires the subject principal to remain
active; the exact parent authentication session to remain active, unexpired,
subject-bound, and on the current authentication epoch; the optional
organization membership to remain active and tenant-bound; and the consent
grant to remain active and bound to that session and context.

The request's immutable scope set must exactly equal its current
consent-and-application-approved intersection under locks. Any revocation or
mismatch returns the uniform `invalid_grant` response without consuming the
code. Code/request consumption, refresh-family creation, token issuance, audit,
and idempotent response completion commit together, so concurrent revocation
cannot race stale authority into a new credential.

Refresh exchange applies the same current application, principal, exact parent
session and epoch, consent, optional membership, and current-scope boundary
before rotating a family. Reuse compromises the whole refresh family and also
revokes every access token issued to that authentication session for the same
client application; unrelated clients and the parent Carbon session survive.

## D-082 — SSO callbacks are preflighted before provider exchange

**Status:** Accepted provider-capacity and correlation boundary

Before spending WorkOS capacity, an SSO callback must pass bounded syntax
checks and a fixed-search-path, Public-revoked database preflight. The preflight
verifies the current authenticated Carbon and browser session, both
IAM-generated correlation digests, a pending unexpired authorization
transaction, and active organization, entitlement, SSO configuration, and
connection state. The nonce half is IAM correlation under D-058, not a claimed
WorkOS nonce attestation.

No database transaction remains open during the provider request. After WorkOS
returns, the completion transition revalidates all correlation, provider
mapping, Carbon-contact match, and admission authority and atomically consumes
the transaction. Preflight therefore protects provider capacity but never
grants membership by itself.

## D-083 — Idempotency identity survives retained pepper rotation

**Status:** Accepted rotation-safety refinement

An idempotency key is one logical caller-and-route key across every retained
token-pepper version, not a new key each time the active pepper changes. Claims
derive caller, key, and request digests for every retained version and search
historical records before inserting with the current version. A historical
record is compared with the request digest produced by its own pepper version,
preserving exact request binding and encrypted replay behavior.

Transactions acquire version-ordered advisory locks for the complete retained
candidate set before lookup or insert. During a rolling rotation, old and new
replicas therefore serialize on their shared old-version identity and cannot
create parallel claims for one request. Operators retain the previous pepper
until no process can still write with it; removing a pepper earlier would also
make credentials and replay records protected by that version unverifiable.
