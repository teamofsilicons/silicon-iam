# Silicon IAM backend API

This document explains the behavior of the public, organization, application,
provider-callback, and platform-administration endpoints in
[`openapi.yaml`](./openapi.yaml). The OpenAPI file is the normative HTTP
contract. `decisions.md` is authoritative for security and architecture
interpretation, while `UNDERSTANDING.md` remains the product-intent source.

The production origin is:

```text
https://backend.iam.teamofsilicons.com
```

JSON APIs are under `/api/v1`. Liveness and readiness remain at `/healthz`
and `/readyz`; OIDC discovery and JWKS use their standard root paths.

## Security model

### Principals and identifiers

There are four internal principal types:

- **Carbon** — a human account.
- **Silicon** — an organization-scoped machine identity.
- **Application** — a registered confidential OAuth/OIDC client and OBO actor.
- **Service** — an internal workload identity.

Persistent entities use UUIDv7 primary identifiers. Public handles
(`carbon_id`, `org_id`, `app_id`, and Silicon local/global IDs) are
immutable normalized labels, never foreign keys, and are not reused after
deletion. Carbon IDs accept lowercase `a-z`, digits `0-9`, `_`, and `-`
and are 3–30 characters long. A global Silicon ID is
`{local_silicon_id}:{org_id}`.

A typed `principal_id` prevents collisions between a Carbon and a Silicon
whose public labels happen to look alike. Organization resources use
`membership_id`, not a public actor handle, for tenant-qualified references.
Cross-tenant resources return `404 not_found` rather than disclose existence.

### Authentication transports

| Mode | Transport | Use |
| --- | --- | --- |
| Public | no credential | Signup, login initiation/verification, availability, discovery, JWKS, callbacks |
| IAM bearer | `Authorization: Bearer …` | Carbon or Silicon API access |
| Browser session | secure `iam_session` cookie | Interactive OAuth consent and SSO navigation |
| Application | HTTP Basic, app ID and app secret | OAuth token operations, introspection, OBO |
| Platform admin | IAM bearer whose Carbon is a current platform admin | `/api/v1/admin/*` |
| Step-up | `X-Step-Up-Token` in addition to bearer | Ownership, credentials, SSO, deletion, and privileged grants |
| WorkOS | verified `WorkOS-Signature` | WorkOS webhook receiver |

Silicon and application secrets contain 256 random bits. Silicon secrets use
`stk-` plus 64 lowercase hexadecimal characters. Raw Silicon, application,
and webhook secrets are returned only on creation or rotation. IAM stores only
a keyed digest. The same idempotent secret response can be replayed for ten
minutes; after that, a lost secret must be rotated.

Per-credential salts and versioned server-side peppers are internal
implementation material. Pepper/salt rotation has no public endpoint and never
uses `SID + STK + Salt` to derive a bearer token.

Normalized email and phone identities are authenticated-encrypted at the
application boundary. Exact lookup and uniqueness use a versioned HMAC blind
index. Raw contact identities, credentials, OTPs, and provider records are
excluded from logs, traces, metrics, error details, audit diffs, and webhooks.

### Credential lifetimes

| Credential/state | Default or maximum |
| --- | --- |
| Signup session | 48 hours |
| Email/phone OTP | 10 minutes, no more than 5 attempts per code |
| IAM/OAuth access token | 15 minutes |
| Carbon refresh-session family | absolute maximum 365 days |
| OAuth authorization code | 2 minutes, single use |
| Step-up token | 5 minutes, action/resource bound |
| Carbon invitation | 48 hours |
| WorkOS setup link | 5 minutes (`expires_in: 300`) |
| OBO proof | 60 seconds maximum, single use |
| One-time secret replay envelope | 10 minutes |

Access and refresh tokens are opaque 256-bit random values. Refresh tokens
rotate on every successful use. Reuse of a consumed refresh token revokes its
entire family and creates a security audit event. Applications use authenticated
introspection when they need immediate revocation and current organization
membership state. Only OIDC ID tokens are signed and exposed through JWKS.
At API startup IAM derives the Ed25519 public JWK and PKCS#8 private key from
the configured 32-byte seed, encrypts the private material with dedicated
row-bound AAD, and reconciles exactly one active key under a cross-replica
advisory lock. Changing the configured key places the previous public key into
a verification overlap. A reused key ID, duplicated public key under another
ID, retired configured key, or missing active key fails startup. Discovery
reports only algorithms backed by a currently active stored key, and an ID
token's `auth_time` is the parent session's authentication time rather than its
token issuance time. IAM emits an ID token only when the effective token scopes
contain `openid`.

### Request headers and concurrency

Every externally initiated mutation requires an `Idempotency-Key` of 16–255
characters. The key is scoped to authenticated caller, route, and request
digest. Repeating an identical request returns the stored result and may include
`Idempotency-Replayed: true`; changing any request bytes under the same key
returns `409 idempotency_conflict`.

Sensitive `PATCH`, `PUT`, and `DELETE` operations require a strong
`If-Match: "{version}"` header. Successful reads and mutations expose that
version as `ETag`. A stale value returns `412 version_mismatch`; an omitted
required precondition returns `428 precondition_required`. Every externally
visible aggregate mutation increments the version by exactly one.

`X-Request-ID` is accepted when valid and otherwise generated. On errors it is
returned as `error.request_id`. `X-Org-ID` may be sent to introspection,
userinfo, or OBO operations, but it must agree with the path, credential, and
grant; it can never expand authority.

### Pagination

List endpoints use opaque cursor pagination:

```http
GET /api/v1/organizations?limit=50&cursor=opaque-value
```

The maximum page size is 100 and the default is 50. Responses contain:

```json
{
  "items": [],
  "page": {
    "next_cursor": null,
    "has_more": false
  }
}
```

A cursor is bound to the caller, filters, sort order, and tenant context. It is
not an offset and clients must not interpret it.

### Errors and status semantics

All JSON API errors use:

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Safe human-readable explanation",
    "details": {},
    "request_id": "trace identifier"
  }
}
```

OAuth redirect errors are returned to the exact registered redirect URI using
OAuth protocol query fields and the unchanged `state`; JSON errors before a
redirect URI is trusted use the envelope above.

| HTTP | Meaning | Typical codes |
| --- | --- | --- |
| 400 | Malformed or unsupported request/protocol input | `invalid_request`, `unsupported_grant_type` |
| 401 | Missing, invalid, expired, or revoked authentication | `invalid_credentials`, `token_expired`, `token_revoked` |
| 403 | Actor type, capability, scope, consent, or step-up is insufficient | `forbidden`, `insufficient_scope`, `step_up_required` |
| 404 | Missing or tenant-hidden resource | `not_found` |
| 409 | Unique, idempotency, replay, lifecycle, or terminal-state conflict | `identifier_unavailable`, `idempotency_conflict`, `refresh_replay`, `state_conflict` |
| 410 | Expired one-time state | `challenge_expired`, `invite_expired`, `authorization_code_expired`, `proof_expired` |
| 412 | Stale ETag | `version_mismatch` |
| 413 | Body exceeds the endpoint limit | `payload_too_large` |
| 422 | Well-formed input violates field, tenant, policy, hierarchy, or quorum rules | `validation_failed`, `invalid_code`, `hierarchy_cycle` |
| 428 | Required idempotency, version, or step-up precondition is absent | `precondition_required` |
| 429 | A distributed rate-limit bucket is exhausted | `rate_limited` |
| 502 | Upstream provider returned a failed or invalid response | `provider_error` |
| 503 | A required dependency is unavailable | `service_unavailable` |
| 504 | A bounded server or provider deadline elapsed | `gateway_timeout` |

`429` includes `Retry-After`, `RateLimit-Limit`,
`RateLimit-Remaining`, and `RateLimit-Reset`. Public OTP initiation uses
uniform responses so callers cannot determine whether an email or phone number
is registered. Default initiation protection permits at most ten requests per
ten minutes in the tightest bucket, while provider policy can be stricter.
The current baseline enforces keyed buckets across normalized identity,
session, purpose, channel, and provider. Signup send protection includes a
contact-global bucket that is independent of the temporary signup-session ID,
plus a per-session bucket. IP/subnet buckets remain disabled until a deployment
defines trusted proxy extraction and allowlisted ingress hops; IAM never trusts
arbitrary forwarding headers. Issuing a new code invalidates the older code.
Application/OAuth routes additionally enforce shared one-minute buckets for
well-formed bearer credentials before token lookup, authenticated principals,
verified browser-session identifiers before session lookup, and app ID plus
route before client-secret verification. Exhaustion uses the same `429` body
and complete retry/rate-limit header set.

## System and discovery

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/healthz` | Process liveness only |
| GET | `/readyz` | Readiness of required dependencies |
| GET | `/api/v1/version` | Service, API, build, and commit versions |
| GET | `/.well-known/openid-configuration` | OIDC issuer metadata |
| GET | `/.well-known/jwks.json` | Current and rollover ID-token verification keys |

Health responses contain no dependency credentials or sensitive topology.

## Carbon signup

Signup binds both verified contact identities to one 48-hour temporary session:

```text
POST /signup/sessions
  -> POST /{session}/email
  -> POST /{session}/email/verify
  -> POST /{session}/phone
  -> POST /{session}/phone/verify
  -> POST /{session}/complete
```

All paths above are under `/api/v1/signup/sessions`.

- Creating a session returns only its random UUID and expiry.
- Email is delivered through Postmark from `auth@teamofsilicons.com`.
- Phone verification sends IAM-generated codes through the Twilio Messages API
  and requires E.164 input.
- Send operations always return the same `202 accepted` shape, including when
  an identity already exists.
- Codes are purpose-, channel-, and session-bound keyed digests.
- Completion requires both verified identities and atomically rechecks their
  uniqueness before inserting the Carbon.
- `profile_photo` defaults to
  `https://iris.teamofsilicons.com/pfp/carbon?id={carbon_id}` when omitted.
- A positive `GET /api/v1/carbon-ids/{carbon_id}/availability` never reserves
  the ID.

`GET /api/v1/carbons/search?q=…&limit=…` is bearer-authenticated, may use
fuzzy public-handle matching, and returns zero to ten public Carbon profiles.
IAM does not expose email/phone-to-Carbon reverse lookup; invitation creation
resolves an exact normalized identity inside the authorized operation.

## Carbon and Silicon authentication

### Carbon passwordless login

`POST /api/v1/login/challenges` accepts exactly one of `email`,
`phone_number`, or `carbon_id`. Email and phone targets receive their
channel-specific six-digit code. Carbon-ID login may dispatch distinct codes to
both verified channels; either code succeeds and atomically consumes every code
in the challenge. The create response does not reveal whether the identity
exists.

`POST /api/v1/login/challenges/{session_id}/verify` returns a 15-minute access
token and a rotating refresh token. Unknown identities and bad codes converge
on safe verification failures. Challenges cannot create accounts.

`POST /api/v1/auth/tokens/refresh` supports Carbon and Silicon IAM refresh
families. `POST /api/v1/auth/tokens/revoke` revokes a token or, when
authorized, its family. `POST /api/v1/auth/tokens/introspect` is available
only to authenticated applications.

`POST /api/v1/logout` defaults to the current session family and supports
`mode=all_sessions`. Revocation is immediate in IAM; logout webhooks are
queued for applications but are not the enforcement mechanism.

### Silicon login

`POST /api/v1/silicon-auth/token` verifies the global Silicon ID and current
`stk-{64 lowercase hex}` credential, then independently mints access and
refresh tokens. It never derives a bearer token from SID/STK concatenation.
Removed Silicons, rotated credentials, and stale authorization epochs fail
immediately.

### Step-up

`POST /api/v1/step-up/challenges` sends a reauthentication code to an existing
verified channel for one declared sensitive action. Verification at
`/{session_id}/verify` returns a five-minute token bound to that action and
optional resource with `assurance=verified_channel`. A token for one action or
resource cannot authorize another.

Platform administration requires phishing-resistant assurance. Carbons enroll
WebAuthn credentials through `POST /api/v1/me/passkeys/registration-options`
and `POST /api/v1/me/passkeys/registrations`; they inspect and revoke metadata
through `GET /api/v1/me/passkeys` and
`DELETE /api/v1/me/passkeys/{credential_id}`. A sensitive assertion begins at
`POST /api/v1/step-up/passkey/options` and completes at
`POST /api/v1/step-up/passkey/verify`, returning
`assurance=phishing_resistant`. Challenges are session-, origin-, RP-ID-,
action-, and resource-bound. A platform administrator cannot remove their last
active passkey.

## Current Carbon account

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/PATCH/DELETE | `/api/v1/me` | Read/update self or begin step-up-protected deletion |
| GET | `/api/v1/me/sessions` | Paginated device/session families |
| DELETE | `/api/v1/me/sessions/{session_id}` | Revoke one family |
| GET | `/api/v1/me/passkeys` | List WebAuthn credential metadata |
| POST | `/api/v1/me/passkeys/registration-options` | Begin passkey enrollment |
| POST | `/api/v1/me/passkeys/registrations` | Complete passkey enrollment |
| DELETE | `/api/v1/me/passkeys/{credential_id}` | Revoke one passkey |
| GET | `/api/v1/me/login-history` | User-wide and app-specific login events |
| POST | `/api/v1/me/email-change/sessions` | Begin verified email replacement |
| POST | `/api/v1/me/email-change/sessions/{id}/verify` | Verify and atomically replace email |
| POST | `/api/v1/me/phone-change/sessions` | Begin verified phone replacement |
| POST | `/api/v1/me/phone-change/sessions/{id}/verify` | Verify and atomically replace phone |
| GET | `/api/v1/me/application-grants` | List OAuth consent grants |
| DELETE | `/api/v1/me/application-grants/{grant_id}` | Revoke grant and app token families |

Contact changes require step-up, uniqueness revalidation, an ETag, and security
notifications to old and new channels. Other session families are revoked on a
successful contact change. Account deletion disables authority immediately and
schedules terminal soft deletion after a 30-day grace period. A bounded worker
finalizes due requests with transactional audit/outbox records. Terminal
finalization deletes every contact and pending-contact-change blind index,
removes pending contact-change state, nulls the ciphertext, nonce, and encryption
key reference on every retained contact row, and marks those rows retired and
purged. It also replaces the Carbon display name with the fixed deleted value
and clears its description and profile-photo URI. Active organization and
application ownership must be transferred or retired first; active platform
roles must be revoked, and the final active platform administrator cannot be
deleted.

## OAuth 2.0 and OpenID Connect

Silicon IAM implements only confidential-client Authorization Code with
PKCE-S256 and rotating refresh tokens. It does not implement implicit, password,
device, or client-credentials grants for end-user login.

### Authorization sequence

```text
Browser -> GET /api/v1/oauth/authorize
  response_type=code
  client_id, redirect_uri, scope, state, nonce
  code_challenge, code_challenge_method=S256
  optional org_id

IAM -> consent when required
Browser -> POST /api/v1/oauth/authorize/decisions
IAM -> exact registered redirect_uri?code=...&state=...

Application backend -> POST /api/v1/oauth/token
  HTTP Basic app credentials
  authorization_code + redirect_uri + code_verifier
IAM -> opaque access token + rotating refresh token + signed ID token
```

Browser navigation uses the secure HttpOnly `iam_session` cookie. The
authorization endpoint never expects a bearer header on a top-level navigation.
The redirect URI must match a reviewed registration byte-for-byte, including
path and query; fragments and wildcards are not accepted. `state` is returned
unchanged. `nonce` is included in the signed ID token. Authorization codes are
keyed-digest stored, two-minute, single-use, and bound to client, redirect,
actor, organization, scopes, and PKCE challenge.

Before consuming a code, the exchange locks and revalidates current authority:
the client application must still be verified on its current authentication
epoch; the subject principal must be active; the exact parent session must be
active, unexpired, subject-bound, and on the principal's current authentication
epoch; any organization membership must still be active and match the original
tenant and subject; and the exact consent grant must remain active and bound to
that session and context. The immutable requested scope set must still exactly
equal its intersection with the consent grant and the application's currently
approved scopes. A failed revalidation returns the uniform `invalid_grant`
response without consuming the code.

Every successful authorization-code exchange returns one rotating `ort_`
refresh token. Refresh issuance is not conditional on requesting
`offline_access`; each family is bound to the exact consent grant and its
original scope ceiling. Rotation can only retain the intersection of that
ceiling, the still-active consent scopes, and the application's still-approved
scopes. Reuse of any consumed family member compromises the whole family,
revokes every member, and immediately revokes access tokens for that parent
session and client application without revoking the session or another
application's tokens.

Requested scopes must be a subset of the platform-approved scopes. Consent is
recorded per actor, app, organization, and scope set. The backend-only
`notify_users=false` setting may suppress repeat consent UI but does not expand
approved scopes or bypass organization checks.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/v1/oauth/authorize` | Validate request and show consent or redirect with code |
| POST | `/api/v1/oauth/authorize/decisions` | CSRF-protected consent decision |
| POST | `/api/v1/oauth/token` | Exchange code or rotate OAuth refresh token |
| POST | `/api/v1/oauth/introspect` | Authenticated current-state introspection |
| POST | `/api/v1/oauth/revoke` | Idempotent token/family revocation |
| GET | `/api/v1/oauth/userinfo` | Scope-limited actor and organization claims |

OAuth access tokens remain linked to the parent IAM session, application,
consent grant, and organization membership. Logout, app suspension, consent
revocation, member removal, credential rotation, or authorization-epoch changes
therefore invalidate them without waiting for webhook delivery.

## Organizations

`GET /api/v1/organization-ids/{org_id}/availability` gives non-reserving
availability feedback. `POST /api/v1/organizations` creates an organization
and its sole owner membership in one transaction. The default join method is
`email`; `org_id` can never change.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/POST | `/api/v1/organizations` | List a Carbon's organizations or create one |
| GET/PATCH | `/api/v1/organizations/{org_id}` | Read or update non-secret configuration |
| POST | `/api/v1/organizations/{org_id}/ownership-transfers` | Atomically transfer the single owner |

Organization listing is Carbon-only. A Silicon already belongs to exactly one
organization and derives its tenant from its credential. Switching
`join_method` to `sso` is rejected until platform SSO entitlement, an active
connection, and an admission policy exist. Disabling SSO requires first moving
the organization to a safe join method.

Ownership transfer requires the current owner, step-up, an ETag, and an active
Carbon membership as the target. The new owner becomes the sole owner in the
same transaction. The former owner becomes an admin with no delegated
capabilities until explicitly configured. The owner cannot be removed and a
sole owner cannot delete their Carbon account.

## Memberships and authorization

Membership identity survives removal and later deliberate reactivation:
one organization/principal pair retains one `membership_id`. Removal sets the
membership to `removed`, increments its authorization epoch, revokes relevant
sessions/grants, and preserves directory/governance history. Reactivation uses
the same row, increments the epoch again, and applies fresh invitation or SSO
defaults; it never revives old sessions or capabilities.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/v1/organizations/{org_id}/members` | Filter by principal type, tag, or status |
| GET/PATCH/DELETE | `.../members/{membership_id}` | Read/update directory fields or remove |
| GET | `.../members/{membership_id}/authorization` | Read tier, explicit grants, and authorization epoch |
| POST | `.../members/{membership_id}/admin-promotions` | Promote an active Carbon member without implicit grants |
| POST | `.../members/{membership_id}/admin-demotions` | Demote an admin and revoke organization grants |
| PUT | `.../members/{membership_id}/capabilities` | Replace explicit organization capabilities without changing tier |
| PUT | `.../members/{membership_id}/machine-capabilities` | Replace Silicon-only machine capabilities |

The free-text `job_role` is directory metadata and never grants authority.
`org_role` is `owner`, `admin`, or `member`. Silicons cannot be owners
or admins. Owner authority is intrinsic. Admins and specially delegated members
receive only explicit capabilities:

- `organization.update`
- `members.invite`, `members.update_directory`, `members.remove`
- `silicons.create`, `silicons.update_directory`,
  `silicons.manage_hierarchy`, `silicons.remove`,
  `silicons.rotate_token`
- `tags.manage`, `trust.manage`
- `roles.request`, `roles.approve`
- `admins.create`, `admins.manage`
- `sso.manage`, `audit.read`

The separate `machine_capabilities` request and response field is a Silicon UX
projection, not a second authorization system. It persists in the same
organization capability-grant table and is a closed subset of catalog entries
whose `allowed_for_silicon` flag is true:

- `members.update_directory`
- `silicons.update_directory`
- `silicons.manage_hierarchy`
- `trust.manage`
- `roles.request`

Unknown strings and every catalog capability outside this subset are rejected;
the service never treats a syntactically valid arbitrary string as authority.

Same-organization directory read is baseline and therefore has no
`members.read` capability. `admins.create` permits only a member-to-admin
promotion; the new admin receives no implicit grants. `admins.manage` controls
capability replacement and admin demotion. Promotion, grant replacement, and
demotion are deliberately separate audited mutations.

Every authorization evaluation is deny-by-default and uses current principal
status, membership status, organization role, explicit grants, application
scope, organization context, and authorization epochs. It never infers
permission from job-role text, tags, reporting hierarchy, first Silicon, or
trust metadata.

Directory updates may change tags, first Silicon, explicit extra Silicons,
profile photo, or a Silicon reporting line. They cannot directly change a job
role; that requires governance approval. Effective Carbon-to-Silicon visibility
is the union of shared-tag access and explicit extra-Silicon grants.

Removing a Carbon disables only that organization's authority. Removing a
Silicon revokes every Silicon credential and session. If the Silicon has direct
reports, `reassign_reports_to` is required and the graph rewrite is atomic.

## Carbon invitations and joining

An authorized caller creates a 48-hour invitation with exactly one existing
`carbon_id` or email. The backend resolves the target privately and emails the
registered address. Invitation responses expose a public Carbon projection and
a masked delivery address, never a raw reverse lookup.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/POST | `/api/v1/organizations/{org_id}/carbon-invites` | List or create |
| GET/DELETE | `.../carbon-invites/{invite_id}` | Inspect or revoke |
| POST | `.../carbon-invites/{invite_id}/verification-code` | Send/resend join OTP |
| POST | `/api/v1/organizations/{org_id}/join` | Accept invite with bound OTP |

Invitation defaults contain a descriptive job role, tags, optional first
Silicon, explicit extra Silicons, and advisory trust. `first_silicon` may be
null when the organization has none. An invitation always creates or
reactivates `org_role=member`; it can never grant admin authority or admin
capabilities. Promotion is a separate step-up-protected audited operation.

The notification link is built only from configured frontend origin plus
`/join/{org_id}?app={redirect_app_id}`; the optional app ID is validated and
does not introduce a caller-controlled redirect URL.

Only one pending invitation per organization/Carbon is allowed. Join verifies
that the authenticated Carbon is the target, the invitation and code are
pending/unexpired, the organization matches, and every referenced tag/Silicon
is still active. Acceptance and membership creation/reactivation are atomic.

## Silicons

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/POST | `/api/v1/organizations/{org_id}/silicons` | List or create |
| GET/PATCH/DELETE | `.../silicons/{silicon_id}` | Read/update/remove |
| GET/POST | `.../silicons/{silicon_id}/iam-hook` | Inspect or retry default Hook setup |
| POST | `.../silicons/{silicon_id}/token-rotation-requests` | Request owner-approved rotation |
| POST | `.../token-rotation-requests/{request_id}/complete` | Apply approved rotation and reveal token once |

Creation accepts a local ID and appends `:{org_id}`. Both local and global IDs
are immutable and tombstoned on removal. IAM returns the raw 256-bit Silicon
token once and asynchronously provisions the default `Silicon IAM` Hook. It
does not hold a database transaction open across Silicon Hook.

When no custom photo is provided, IAM generates:

```text
https://iris.teamofsilicons.com/pfp/silicon?id={global_silicon_id}&level={level}
```

The root of a reporting tree is level 1; each child is parent level plus one.
Reporting edges are Silicon-to-Silicon inside one organization. Self-links,
cycles, removed targets, and cross-tenant references are rejected.

Token rotation creates an immutable approval request. The current owner must
approve using step-up authentication. Completion generates the new secret,
increments the credential/auth epochs, invalidates the old secret, revokes
Silicon sessions, and returns the raw secret under the ten-minute idempotent
replay rule.

## Tags, visibility, and trust

Tags are stable, normalized, organization-scoped entities rather than free-form
strings embedded in memberships.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/POST | `/api/v1/organizations/{org_id}/tags` | List or create tags |
| GET/PATCH/DELETE | `.../tags/{tag_id}` | Read, rename, or delete |
| GET | `.../tags/{tag_id}/members` | List attached Carbons and Silicons |

A referenced tag cannot be deleted normally. Explicit `cascade=true` requires
step-up and atomically removes membership assignments, visibility derivations,
and trust rules while recording a complete audit event. Renaming preserves the
tag UUID and therefore does not break references.

Trust is reliable advisory metadata, never an authorization decision. It has:

- boundary: `internal` or `external`
- level: `not_trusted`, `needs_approval`, or `trusted`

`GET/PUT /api/v1/organizations/{org_id}/trust/default` manages the initial
`internal/not_trusted` value. `GET/POST .../trust/rules` and
`GET/PATCH/DELETE .../trust/rules/{rule_id}` manage typed rules. Selectors are
`organization`, `tag`, or `membership` objects; strings such as
`tag:finance` are not parsed as foreign keys.

`POST .../trust/effective` explains the value for one subject and target
Silicon. Precedence is organization default, then tag rule, then exact
membership/Silicon rule. More specific rules win. Conflicts at the same
specificity choose the more restrictive level and return every matching rule
ID. The result always contains `advisory=true`.

Inter-Silicon department matrices use tag-subject to tag-target rules. Carbon
overrides use Carbon membership or tag subjects and Silicon membership or tag
targets.

## Job-role governance

Job-role changes never use the membership patch endpoint:

| Method | Endpoint | Behavior |
| --- | --- | --- |
| POST | `/api/v1/organizations/{org_id}/role-change-requests` | Create immutable request |
| GET | `.../approval-requests` | Filter pending/history/actionable requests |
| GET | `.../approval-requests/{request_id}` | Inspect payload and decisions |
| POST | `.../approval-requests/{request_id}/decisions` | Approve or reject |
| GET | `.../members/{membership_id}/job-role-history` | Applied role history |

A Carbon change requires the affected Carbon and one currently eligible owner
or admin with `roles.approve`. A Silicon change requires one currently
eligible owner/admin. A Silicon-token rotation requires the owner and step-up.
Eligibility is rechecked when a decision is made and when a terminal operation
is applied.

Payloads are immutable. Each approver may decide once. Rejection is terminal.
Expired requests cannot be revived. Once quorum exists, the role change, role
history record, aggregate version, redacted audit event, and outbox events
commit in one transaction and can be applied only once.

## WorkOS SSO

SSO is initially locked. A platform administrator first changes
`PUT /api/v1/admin/organizations/{org_id}/sso-entitlement`. An owner or
appropriately authorized admin may then configure it:

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/DELETE | `/api/v1/organizations/{org_id}/sso` | Inspect or safely disable |
| POST | `.../sso/setup-link` | Create five-minute WorkOS Admin Portal setup link |
| PUT | `.../sso/policy` | Configure admission policy and member defaults |
| GET | `.../sso/authorize` | Begin authenticated Carbon SSO |
| GET | `/api/v1/sso/callback` | Verify callback and admit/link |
| POST | `.../sso/test` | Read-only active-connection test |
| POST | `/api/v1/provider-webhooks/workos` | Signature/replay-verified provider events |

IAM permanently stores the IAM organization ↔ WorkOS organization/connection
mapping. Provider secrets never appear in organization reads.

SSO never creates a Carbon. The Carbon must first complete normal IAM signup,
begin SSO while authenticated, and return on the same bound browser session.
Before calling WorkOS, the callback performs a database correlation preflight
that requires the current Carbon and bound browser session, a pending unexpired
authorization transaction, both IAM-generated correlation digests, and active
organization, entitlement, SSO configuration, and connection state. The value
named `nonce` is the second IAM-generated correlation component packed into the
returned `state`; it is not a claim that WorkOS attested a provider nonce. No
database transaction remains open during the WorkOS exchange. After the
provider returns, completion revalidates the correlation, organization and
connection mapping, verified identity, existing Carbon contact match, and
admission authority before atomically consuming the transaction.

An organization using `join_method=sso` must have an active connection and an
explicit admission policy:

- `invitation_required` admits only an existing pending invitation.
- `verified_identity_policy` may admit an existing Carbon when the verified
  WorkOS email domain and/or exact, case-sensitive Profile group string matches
  configured rules. WorkOS's SSO Profile does not expose a stable group-ID
  object in this contract, so IAM does not label these values as IDs.

Policy admission supplies member defaults for job role, tags, first Silicon,
and trust and always joins as `member`. WorkOS webhook bodies are bounded,
signature checked over the raw bytes, timestamp-window checked, and deduplicated
by provider event ID. `WorkOS-Signature` is the only signature header and has
the comma-delimited form `t=<epoch_ms>,v1=<hex_hmac>`; there is no separate
trusted timestamp header. IAM verifies HMAC-SHA-256 in constant time over
`timestamp + '.' + exact raw UTF-8 body`, rejects timestamps outside a
300-second tolerance, and only then deduplicates the provider event ID.
Provider calls use rustls, explicit deadlines, bounded
responses, and validated redirect behavior. Deadline expiry is `504`; an
invalid upstream response is `502`; temporary dependency loss is `503`.

## Applications

Applications are owned by an existing Carbon. There is no separate developer
email/password identity. The owner may add existing Carbons as explicit
collaborators.

Application-management, webhook-management, grant, and platform-review routes
that act as a Carbon require a direct `silicon-iam` bearer with `iam.self`, no
client application, and no organization/membership binding. A delegated OAuth
`oat_` cannot become a confused deputy for the Carbon subject. Client-secret
authentication locks the matching secret, rechecks its active/retiring window
and active verified application principal, and records usage in one transaction
so concurrent revocation cannot authenticate after it commits.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/v1/application-ids/{app_id}/availability` | Non-reserving ID check |
| GET/POST | `/api/v1/applications` | List manageable apps or submit registration |
| GET/PATCH/DELETE | `/api/v1/applications/{app_id}` | Read/update/delete |
| GET/POST | `.../collaborators` | List or add collaborator |
| DELETE | `.../collaborators/{principal_id}` | Remove collaborator |
| POST | `.../secret-rotations` | Rotate app secret |
| GET/PUT | `.../webhook` | Inspect active endpoint or propose replacement |
| POST | `.../webhook/secret-rotations` | Rotate webhook signing secret |
| GET | `.../login-history` | App-specific authorization/login history |

Registration requires an immutable app ID, at least one exact redirect URI, one
HTTPS webhook URL, and requested scopes. It returns an `under_review`
application plus one-time application and webhook signing secrets. The app
cannot authorize users, introspect tokens, or issue OBO proofs until verified.
`notify_users` defaults to `true`.

Requested scopes and approved scopes are separate. Redirect or scope changes
remain pending and do not replace the active reviewed configuration until a
platform administrator approves them. An application webhook replacement also
keeps the previous endpoint active until review; v1 exposes exactly one active
destination. During initial registration there is truthfully no active
destination: `active_url` is `null`, `pending_url` contains the submitted URL,
and webhook status is `pending_review`. A later replacement uses
`replacement_under_review` while preserving the existing `active_url`.
`notify_users` is absent from owner mutations and is configurable
only by platform administrators.

Application secret and webhook secret rotations produce versioned credentials.
The default overlap is zero; an explicitly requested overlap may be at most one
hour to support controlled rollout. Deletion immediately disables the client,
revokes token families, OBO proofs, consents, and delivery scheduling, and
tombstones the app ID.

### Platform application review

`GET /api/v1/admin/applications` lists the inventory and pending review queue.
`POST /api/v1/admin/applications/{app_id}/decisions` supports:

- approve or reject initial registration
- suspend or reactivate
- approve or reject pending scopes, redirect URIs, or webhook replacement
- set the approved scope list
- set backend-only `notify_users`

Review requires a current platform administrator, step-up, idempotency key, and
ETag. Suspension immediately revokes active application authority. Every
decision records reviewer, reason, old/new redacted state, request ID, and
timestamp. Removing an approved scope atomically revokes every active `oat_`
token for that client that carries the removed scope; refresh rotation can
retain only the reduced current-scope intersection. A platform administrator
may also invoke the step-up-protected application `DELETE` operation when
permanent removal is required.

## OBO Access

OBO Access never hashes an access token together with an app secret.

`POST /api/v1/obo-access/exchanges` authenticates App A and accepts an
actor-bound application access token as `subject_token`, plus audience App B,
organization, action, and optional resource. IAM confirms:

1. App A is verified and its secret is current.
2. The subject token was issued to App A and is active.
3. The actor and organization membership are active.
4. App A's reviewed scopes permit this exchange.
5. The actor has no less authority than the requested delegated action.

IAM returns a random `obo_` proof with a unique ID and at most 60 seconds of
life. It is issuer-, audience-, actor-, organization-, action-, and
resource-bound.

The action is a closed organization-capability value:
`organization.update`, `members.invite`, `members.update_directory`,
`members.remove`, `silicons.create`, `silicons.update_directory`,
`silicons.manage_hierarchy`, `silicons.remove`, `silicons.rotate_token`,
`tags.manage`, `trust.manage`, `roles.request`, `roles.approve`,
`admins.create`, `admins.manage`, `sso.manage`, or `audit.read`. Unknown
strings are rejected before authority evaluation and cannot become owner-only
implicit permissions.

App B authenticates to `POST /api/v1/obo-access/verify`. The request must
repeat the exact audience/action/resource constraints. A successful transaction
atomically consumes the proof and returns the represented actor and constraints.
Replay returns a conflict. App B must still enforce resource-level permission;
proof validity alone does not authorize a file, row, operation, or business
action.

## Outbound events and webhooks

Every security-relevant mutation commits its domain change, redacted audit
record, aggregate version increment, and outbox event in one PostgreSQL
transaction. Workers claim outbox rows with bounded leases, deliver at least
once, use capped exponential backoff with jitter, and retain dead-letter state
for authorized replay.

The OpenAPI `webhooks` section defines application and Silicon IAM Hook
deliveries. Event bodies use this envelope:

```json
{
  "spec_version": "1.0",
  "event_id": "uuid",
  "event_type": "organization.membership.removed.v1",
  "occurred_at": "2026-08-31T12:00:00Z",
  "aggregate": {
    "id": "uuid",
    "type": "membership",
    "version": 7
  },
  "data": {}
}
```

Event names are stable dotted identifiers ending in their positive schema
version, such as:

- `carbon.updated.v1`
- `organization.updated.v1`
- `organization.membership.created.v1`
- `organization.membership.updated.v1`
- `organization.membership.removed.v1`
- `organization.silicon.updated.v1`
- `organization.tag_updated.v1`
- `organization.trust.rule_updated.v1`
- `session.logout.v1`
- `iam.silicon.initialized.v1`

Organization invitation, ownership, approval, SSO, tag, trust, Silicon
credential, and other directory transitions use the same versioned naming
rule. Consumers must deduplicate by `event_id`, process the event types they
understand, and safely ignore unknown event types so additive events do not
break delivery.

Events are minimal projections. They never contain OTPs, raw tokens/secrets,
provider credentials, encrypted database records, full contact identities, or
unrelated organization state. Application delivery is limited to actors and
organization grants currently relevant to that reviewed application.

### Application signature verification

Each request includes:

```text
X-Silicon-IAM-Event-ID: <uuid>
X-Silicon-IAM-Timestamp: <unix-seconds>
X-Silicon-IAM-Key-Version: <integer>
X-Silicon-IAM-Signature: v1=<lowercase-hex-hmac>
```

The signature is HMAC-SHA-256 over:

```text
{timestamp}.{exact raw request body bytes}
```

using the indicated version of the application's webhook secret. Consumers
must reject timestamps outside five minutes, verify with constant-time
comparison, and deduplicate `event_id` before applying state. A success is any
`200`, `202`, or `204` response. Redirects are not followed. Delivery is
ordered by aggregate version when order matters, but consumers must tolerate
at-least-once duplicates and gaps while retries are pending.

IAM validates outbound HTTPS endpoints against SSRF and DNS-rebinding attacks:
no userinfo, fragments, trailing-dot DNS hostnames,
private/link-local/loopback/multicast destinations, or post-resolution address
changes are allowed. Registration and delivery-time transport validation each
reject trailing-dot hosts independently, so historical encrypted destinations
cannot bypass the check. Connection, TLS, total-request, response-size, and
concurrency limits are bounded.

Silicon IAM Hook deliveries use the same event-ID, timestamp, and signature
headers and the same `{timestamp}.{body}` HMAC construction. They authenticate
with the configured Silicon Hook service credential, which is also the signing
key; the application-only key-version header is omitted.

Application owners inspect:

- `GET /api/v1/applications/{app_id}/webhook-deliveries`
- `GET .../webhook-deliveries/{delivery_id}`
- `POST .../webhook-deliveries/{delivery_id}/replays`

Only failed/dead-letter deliveries can be replayed. A replay retains the
original event ID so receivers remain idempotent.

### Silicon IAM Hook

Silicon creation queues default Hook provisioning named `Silicon IAM`.
Provisioning and the first event are separate idempotent outbox operations. Once
active, IAM sends `iam.silicon.initialized.v1` with the new Silicon's public
directory data and a minimal current organization snapshot. Later relevant
organization, Carbon, Silicon, role, tag, hierarchy, and removal changes are
sent through that Hook.

`GET .../silicons/{silicon_id}/iam-hook` exposes masked provisioning state,
not a reusable secret URL. `POST` retries only pending/failed provisioning or
initial delivery. Operator-wide failed application/Hook deliveries are visible
through the admin delivery-failure endpoints.

## Audit and history

`GET /api/v1/organizations/{org_id}/audit-events` requires owner authority or
`audit.read`. It supports action, target, and time filters. Platform
administrators use `GET /api/v1/admin/audit-events` for cross-tenant security
operations.

Audit records are append-only and include:

- initiating and effective actor
- organization/application context
- action and typed target
- request ID and authentication method
- timestamp, with reserved coarse-IP-prefix and safe-user-agent-summary fields
- redacted before/after diff

They exclude secrets, tokens, OTPs, complete contact details, and raw provider
payloads. The reserved IP and user-agent history fields remain null until a
deployment defines trusted ingress metadata and allowlisted proxy hops; IAM
never derives them from arbitrary forwarding headers. Login history is
separately available to the Carbon and relevant application owner. Job-role
history includes requester, approvers, immutable
request ID, old/new text, and application time.

The worker applies configurable retention as one independently committed
database phase per maintenance tick, selected round-robin from a closed
21-phase vocabulary. Each selected phase claims at most the configured batch
size, which is bounded at 1,000 root rows, with ordered locking; a failure is
isolated to that phase and the next tick advances to the following phase. The
initial cursor follows the global wall-clock sweep slot so rolling restarts do
not starve later phases. Defaults are 365 days for login/authentication history,
30 days for expired challenges, ceremonies, and abandoned
authorization/contact transactions, 90 days for expired or revoked
access/OBO/refresh metadata, 365 days for compromised refresh families, 45 days
for webhook-attempt telemetry, and 2,555 days for security audit events.
Approval-linked step-up records retain only a skeletal identifier, purpose,
assurance, and timing record after their digest or encrypted ceremony state is
erased. Authentication-session skeletons similarly remain only while a retained
audit, consent, governance, or lifecycle FK needs them; optional fingerprint and
revocation-detail fields are erased at the login history cutoff.

## Platform administration

There is no source-controlled default administrator password or runtime
bootstrap secret. The first platform administrator is bootstrapped only by the
one-time `iam-bootstrap-admin` operator command using the migrator database
credential. Platform administrators are existing Carbon principals with a
privileged role and strong step-up requirements.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/POST | `/api/v1/admin/platform-administrators` | List or add existing Carbon admin |
| DELETE | `.../platform-administrators/{principal_id}` | Remove admin; last admin protected |
| GET | `/api/v1/admin/applications` | App inventory and review queue |
| POST | `.../applications/{app_id}/decisions` | Review/configure/suspend app |
| PUT | `/api/v1/admin/carbons/{carbon_id}/status` | Suspend/reactivate a Carbon and revoke authority on suspension |
| PUT | `.../organizations/{org_id}/sso-entitlement` | Backend-only SSO unlock |
| GET | `/api/v1/admin/audit-events` | Cross-tenant redacted audit |
| GET | `/api/v1/admin/delivery-failures` | Failed/dead-letter deliveries |
| POST | `.../delivery-failures/{delivery_id}/replays` | Queue operator replay |

Admin authorization is checked against current Carbon, admin status, session,
and phishing-resistant step-up state on every mutation. Removal of the last active platform
administrator is rejected. Admin endpoints never return provider credentials,
encryption keys, secret digests, or raw one-time response envelopes.

## Reliability and revocation guarantees

PostgreSQL is authoritative for identities, sessions, organizations,
memberships, permissions, governance, applications, SSO mappings, idempotency,
audit, and outbox state. Redis/Valkey may accelerate rate limits, caches, and
replay markers but its loss cannot restore revoked authority or lose durable
state.

Security mutations use one database transaction. No transaction remains open
while contacting Postmark, Twilio, WorkOS, Iris, an application webhook, or
Silicon Hook. Provider work is either a bounded request whose result is required
for the response or an outbox job with visible retry state.

Membership/app/session/credential authorization epochs allow immediate central
revocation. Consumers must introspect opaque tokens at the appropriate trust
boundary; a delayed or permanently failed webhook cannot keep authority alive.

## Retention defaults

Retention is configurable policy and requires jurisdiction-specific compliance
review before production:

| Data | Default |
| --- | --- |
| Security audit and governance history | 2,555 days |
| Login history | 365 days |
| Expired OTP/challenge metadata | 30 days |
| Expired/revoked token metadata | 90 days |
| Token metadata after detected refresh replay | 365 days |
| Webhook delivery attempts | 45 days |
| Completed idempotency responses | 24 hours |
| Raw one-time secret response envelope | destroyed after 10 minutes |

Retention never makes an expired credential valid and does not permit raw
secret persistence.

## Transactional invariants

Implementations and contract tests must preserve at least these invariants:

1. Exactly one active owner exists per active organization.
2. One organization/principal pair maps to one durable membership ID.
3. Public handles remain immutable, globally unique in their namespace, and
   tombstoned after deletion.
4. Every tenant-owned reference belongs to the same organization.
5. Job-role text, tags, trust, and reporting edges never grant authority.
6. Silicon reporting graphs are acyclic and organization-local.
7. Invitation acceptance, signup completion, authorization-code exchange,
   refresh rotation, approval completion, OBO consumption, and secret rotation
   are atomic and replay-safe.
8. Domain mutation, audit, aggregate version, and outbox record commit together.
9. Owner, membership, app, session, consent, and credential revocation are
   effective centrally before webhook delivery.
10. Raw credentials and contact identities never enter logs or public events.

## Provider and non-public boundaries

Postmark, Twilio Messaging, WorkOS, Iris, and Silicon Hook are accessed behind
application ports. Their raw provider-specific payloads and outbound management
APIs are intentionally not public IAM endpoints. Production startup refuses
local/no-op provider implementations.

The public contract fixes IAM-visible behavior—timeouts, uniform OTP responses,
callback/webhook validation, asynchronous Hook state, idempotency, and error
mapping—without coupling clients to a provider SDK. Provider API version
upgrades therefore do not silently change this contract.
