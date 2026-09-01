# Silicon IAM backend API

This document explains the behavior of the public, organization, application,
provider-callback, and platform-administration endpoints in
[`openapi.yaml`](./openapi.yaml). The OpenAPI file is the normative HTTP
contract. `UNDERSTANDING.md` is the authoritative product-scope source.

The production origin is:

```text
https://backend.iam.teamofsilicons.com
```

Versioned JSON APIs are under `/api/v1`. The compatibility handshake is the
unversioned `/api/version`; liveness and readiness remain at `/healthz` and
`/readyz`.

The same origin also serves three HTML surfaces, which are deliberately outside
the JSON contract and are not described in `openapi.yaml`:

| Path | Surface |
| --- | --- |
| `/docs/api/` | Browsable API documentation, in eleven sections |
| `/openapi.yaml` | The normative contract itself |
| `/admin` | The platform-administration console |

`scripts/check-openapi-routes.rb` enforces that separation: a route declared in
`src/web/mod.rs` must sit under `/admin`, `/docs`, `/_static` or
`/openapi.yaml`, and must not appear in the specification. Contract routes
belong in a feature router and in `openapi.yaml`, as they always have.

The `/admin` console is a thin client over `/api/v1/admin/*`. It performs no
authentication of its own and executes no SQL; authority stays entirely in the
endpoints the contract already publishes.

## Security model

### Principals and identifiers

There are three public principal types:

- **Carbon** — a human account.
- **Silicon** — an organization-scoped machine identity.
- **Application** — a registered confidential OAuth client and OBO actor.

Persistent entities use UUIDv7 primary identifiers. Public handles
(`carbon_id`, `org_id`, `app_id`, and the global Silicon ID) are
immutable normalized labels, never foreign keys, and are not reused after
deletion. New Carbon IDs accept lowercase `a-z`, digits `1-9`, `_`, and `-`
and are 3–30 characters long. Immutable legacy Carbon IDs containing `0`
remain addressable for login and existing-account lookup but cannot be newly
registered. A global Silicon ID is
`{handle}:{org_id}`; the handle is only creation input and is never an
independently addressable public ID.

A typed `principal_id` prevents collisions between a Carbon and a Silicon
whose public labels happen to look alike. Organization resources use
`membership_id`, not a public actor handle, for tenant-qualified references.
Cross-tenant resources return `404 not_found` rather than disclose existence.

### Authentication transports

| Mode | Transport | Use |
| --- | --- | --- |
| Public | no credential | Signup, login initiation/verification, availability, and callbacks |
| IAM bearer | `Authorization: Bearer …` | Carbon or Silicon API access |
| Browser session | secure `iam_session` cookie | Interactive OAuth consent and SSO navigation |
| Application | HTTP Basic, app ID and app secret | OAuth token operations, introspection, and same-organization OBO |
| Platform admin | IAM bearer whose Carbon is a current platform admin | `/api/v1/admin/*` |
| Step-up | `X-Step-Up-Token` in addition to bearer | Ownership, credentials, SSO, deletion, and privileged grants |
| WorkOS | verified `WorkOS-Signature` | WorkOS webhook receiver |

Application secrets contain 256 random bits. Silicon secrets contain 128 random
bits and use `stk-` plus 32 lowercase hexadecimal characters. Raw application
secrets are returned only on creation; raw Silicon tokens are returned on
creation or an approved token rotation. Both are retained only as keyed
digests. Versioned webhook HMAC secrets are encrypted at rest. An application's
`whs_…` signing secret is returned only when the application is created;
replacing its webhook URL reuses that encrypted secret and never returns it.
Only Silicon endpoint configuration or replacement returns a new `swhs_…`
signing secret. That Silicon response can be replayed idempotently for ten
minutes.

Per-credential salts and versioned server-side peppers are internal
implementation material. Pepper/salt rotation has no public endpoint and never
uses `SID + STK + Salt` to derive a bearer token.

Normalized email and phone identities are authenticated-encrypted at the
application boundary. Exact lookup and uniqueness use a versioned HMAC blind
index. Raw contact identities, credentials, OTPs, and provider records are
excluded from logs, traces, metrics, error details, audit diffs, and webhooks.

### Credential lifetimes

| Credential/state | Exact lifetime |
| --- | --- |
| Signup session | 48 hours |
| Email/phone OTP | 10 minutes; after 10 failed attempts, a reusable challenge cools down for 1 minute before a fresh 10-attempt window |
| IAM/OAuth access token | 30 minutes |
| Carbon/Silicon/OAuth refresh-session family | 900 days absolute |
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
membership state. OAuth access and refresh tokens remain opaque and are never
published through a signing-key discovery surface.

### Request headers and concurrency

Every externally initiated mutation requires an `Idempotency-Key` of 16–255
characters. The key is scoped to authenticated caller, route, and request
digest. Repeating the same validated request returns the stored result and may
include `Idempotency-Replayed: true`; changing any canonical request field under
the same key returns `409 idempotency_conflict`. JSON whitespace and object-key
ordering are not semantically significant.

OBO proof verification is the deliberate single-use exception: it does not
accept an `Idempotency-Key`, never stores or replays a successful verification
response, and every attempt after the proof has been consumed returns `409`.
An OBO exchange remains idempotent, but its replay envelope expires no later
than the proof itself.

Versioned aggregate mutations require a strong `If-Match: "{version}"` header.
Non-versioned commands, such as deleting the authenticated session, do not.
Successful aggregate reads and mutations expose their version as `ETag`; when
a response body also contains `version`, it is the same version represented by
that ETag. A stale value returns `412 version_mismatch`; an omitted required
precondition returns `428 precondition_required`. Every externally visible
aggregate mutation increments the version by exactly one.

`X-Request-ID` is accepted when valid and otherwise generated. On errors it is
returned as `error.request_id`. `X-Org-ID` may be sent to introspection, but it
must agree with the credential and grant; it can never expand authority. OBO
does not accept `X-Org-ID`; IAM derives its organization from the authenticated
Applications and rejects cross-organization use.

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

The HTML surfaces answer with HTML rather than this envelope. They are merged
outside the JSON router's error normalisation, so an unknown documentation
section returns a readable page with a way back rather than a machine-readable
code that no reader asked for.

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
`RateLimit-Remaining`, and `RateLimit-Reset`. Carbon login initiation returns
`404` when the submitted identity is not registered. Signup contact initiation
returns the product contract's exact `already_exists` boolean and sends no OTP
when it is true. Default signup initiation protection permits ten requests and
then a ten-minute cooldown in the tightest bucket, while provider policy can be
stricter.
The current baseline enforces keyed buckets across normalized identity,
session, purpose, channel, and provider. Signup send protection includes a
contact-global bucket that is independent of the temporary signup-session ID,
plus a per-session bucket. IP/subnet buckets remain disabled until a deployment
defines trusted proxy extraction and allowlisted ingress hops; IAM never trusts
arbitrary forwarding headers. Issuing a new code invalidates the older code.
Verification-attempt cooldowns are separate from initiation limits. Signup
email/phone, Carbon login (including either Carbon-ID delivery channel), email
invitation join, and verified-channel step-up challenges allow ten failed
verifications in a window. The tenth failure starts a 60-second cooldown. The
partial failed-attempt window and any active cooldown carry into a replacement
code, so resend cannot reset either. After the cooldown, the current
still-unexpired challenge receives a fresh ten-attempt window; a cooldown never
extends that code's original ten-minute expiry.
Application/OAuth routes additionally enforce shared one-minute buckets for
well-formed bearer credentials before token lookup, authenticated principals,
verified browser-session identifiers before session lookup, and app ID plus
route before client-secret verification. Exhaustion uses the same `429` body
and complete retry/rate-limit header set.

## System

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/healthz` | Process liveness only |
| GET | `/readyz` | Readiness of required dependencies |
| GET | `/api/version` | Negotiate the highest mutually supported public API version |
| GET | `/api/v1/version` | Service, API, build, and commit versions |

Health responses contain no dependency credentials or sensitive topology.

Every official client performs the unversioned `/api/version` handshake before
making a versioned request. It sends its distinct supported versions in
descending preference order:

```http
Silicon-IAM-Supported-API-Versions: v1
```

IAM selects the highest mutually supported version and returns it in both
`selected_api_version` and `Silicon-IAM-API-Version`; `Vary` identifies the
advertisement header for intermediary caches. The response also lists the
server's supported versions in descending preference order. A client must
fail closed if the response disagrees with the advertised intersection. When
there is no common version, IAM returns `406 api_version_not_acceptable` with
the server's supported version list. `/api/v1/version` remains available as a
version-specific diagnostic endpoint; it is not the negotiation handshake.

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
- Each send operation returns `already_exists`. When it is `true`, IAM sends no
  code; when it is `false`, the response also includes `expires_in: 600` and a
  new code is sent.
- Codes are purpose-, channel-, and session-bound keyed digests.
- Each still-unexpired email or phone code follows the ten-failure,
  one-minute-cooldown verification policy described above.
- Completion requires both verified identities and atomically rechecks their
  uniqueness before inserting the Carbon.
- Completion accepts optional `time_zone` as an exact IANA TZDB identifier such
  as `UTC` or `Asia/Kolkata`; omission defaults it to `UTC`. Unknown identifiers
  and whitespace variants are rejected.
- `profile_photo` defaults to
  `https://iris.teamofsilicons.com/pfp/carbon?id={carbon_id}` when omitted.
- A positive `GET /api/v1/carbon-ids/{carbon_id}/availability` never reserves
  the ID.

`GET /api/v1/carbons/search?q=…&limit=…` is bearer-authenticated, may use
fuzzy public-handle matching, and returns zero to ten objects containing only a
`carbon_id`. Authenticated direct Carbons can resolve an exact active verified
contact through `POST /api/v1/carbons/resolve/email` or
`POST /api/v1/carbons/resolve/phone`; each returns only the matching
`carbon_id`, or `404` when none exists. These lookup endpoints are independently
rate-limited and never return contact or profile data.

## Carbon and Silicon authentication

### Carbon passwordless login

`POST /api/v1/login/challenges` accepts exactly one of `email`,
`phone_number`, or `carbon_id`. Email and phone targets receive a six-digit
code. Carbon-ID login dispatches the same code to both verified channels; a code
received through either channel succeeds and atomically consumes the challenge.
An identifier that does not belong to an active Carbon
returns `404`; login never creates an account.

`POST /api/v1/login/challenges/{session_id}/verify` returns a 30-minute access
token and a rotating refresh token. Bad codes use a safe verification failure.
Email, phone, and Carbon-ID challenges share the same ten-failure window and
one-minute cooldown policy.

`POST /api/v1/auth/tokens/refresh` supports Carbon and Silicon IAM refresh
families. IAM session revocation is exposed only through the logout and
step-up-protected session-deletion flows below. Configured applications use
`POST /api/v1/oauth/introspect` and `POST /api/v1/oauth/revoke` for their OAuth
token lifecycle.

`POST /api/v1/logout` defaults to the current session family and supports
`mode=all_sessions`. Revocation is immediate in IAM; logout webhooks are
queued for applications but are not the enforcement mechanism. Current-session
logout is always permitted. A signed `iam_session` cookie may authenticate this
operation only when `X-CSRF-Token` exactly matches the CSRF value protected by
that cookie; a first-party Carbon bearer does not require the CSRF header. If
`mode=all_sessions` would revoke another active
session, every other target and the authenticating session must be at least 12
hours old. The request must also include a verified-channel
`account.sessions_revoke_all` step-up assertion bound to the current Carbon's
`principal_id`; the transaction fails without revoking anything if any target
is too young. When there are no other active sessions, `all_sessions` safely
collapses to immediate current-session logout and does not require step-up.

The endpoint also accepts a live Carbon OAuth bearer issued to the Application
that is triggering logout, provided that Application is both the token client
and audience. This Application-triggered form always performs global logout for
the bearer token's parent IAM session: it revokes that session family and all
IAM/Application access, refresh, consent, authorization-code/request, and OBO
authority bound to it, then emits the same `session.logout.v1` event to every
Application authorized immediately before revocation. It cannot request
account-wide `all_sessions`. Authorization is rechecked under lock, and an
exact idempotent retry may replay only its already-completed response after the
triggering credential has been revoked.

`DELETE /api/v1/me/sessions/{session_id}` is the explicit single-session
revocation flow. The target must be at least 12 hours old, and when it differs
from the current session, the authenticating session must also be at least 12
hours old. Every request requires a verified-channel
`account.session_revoke` step-up assertion whose `resource_id` is exactly the
target session UUID. Assertion consumption and revocation commit atomically.

### Silicon login

`POST /api/v1/silicon-auth/token` verifies the global Silicon ID and current
`stk-{32 lowercase hex}` credential, then independently mints access and
refresh tokens. It never derives a bearer token from SID/STK concatenation.
Removed Silicons, rotated credentials, and stale authorization epochs fail
immediately.

### Step-up

`POST /api/v1/step-up/challenges` sends a reauthentication code to an existing
verified channel for one declared sensitive action. Verification at
`/{session_id}/verify` returns a five-minute token bound to that action and
required `resource_id` with `assurance=verified_channel`. A token for one action
or resource cannot authorize another. Session-revocation challenges validate
that the target belongs to the current Carbon before dispatch; all-session
challenges bind the resource to the current Carbon principal UUID.

Signup, login, and step-up initiation first commits only an unverifiable,
digest-backed pending challenge and its exact idempotency reservation. Provider
I/O then runs without an open database transaction, and IAM activates the
challenge only after every required delivery succeeds. A definitive pre-send
rejection permits an exact retry; ambiguous or partially successful delivery
remains fail-closed as `idempotency_in_progress` for the same key, while a new
key safely supersedes the unusable pending challenge. Plaintext OTPs are never
persisted. Superseding a challenge carries its partial failed-attempt count or
active 60-second cooldown into the replacement.

## Current Carbon account

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/PATCH | `/api/v1/me` | Read or update the current Carbon profile |
| GET | `/api/v1/me/sessions` | Paginated device/session families |
| DELETE | `/api/v1/me/sessions/{session_id}` | Revoke a 12-hour-old session with target-bound verified-channel step-up; cross-session revocation also requires a 12-hour-old authenticating session |
| GET | `/api/v1/me/login-history` | User-wide and app-specific login events |

`GET /api/v1/me` returns the Carbon's mutable display name, description,
effective profile-photo URL, and IANA `timezone`. `PATCH /api/v1/me` may edit
those four fields under the current strong ETag; the public `carbon_id` remains
immutable. Existing accounts migrated before time zones were captured use the
safe `UTC` default until the Carbon chooses another identifier.

## OAuth 2.0

Silicon IAM implements only confidential-client Authorization Code with
PKCE-S256 and rotating refresh tokens. It does not implement implicit, password,
device, or client-credentials grants for end-user login.

### Authorization sequence

```text
Browser -> GET /api/v1/oauth/authorize
  response_type=code
  client_id, redirect_uri, scope, state
  code_challenge, code_challenge_method=S256
  optional org_id

IAM -> consent when required
Browser -> POST /api/v1/oauth/authorize/decisions
IAM -> exact registered redirect_uri?code=...&state=...

Application backend -> POST /api/v1/oauth/token
  HTTP Basic app credentials
  authorization_code + redirect_uri + code_verifier
IAM -> opaque access token + rotating refresh token
```

Browser navigation uses the secure HttpOnly `iam_session` cookie. The
authorization endpoint never expects a bearer header on a top-level navigation.
The redirect URI must match a reviewed registration byte-for-byte, including
path and query; fragments and wildcards are not accepted. `state` is returned
unchanged. Authorization codes are keyed-digest stored, two-minute, single-use,
and bound to client, redirect,
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

The decision endpoint accepts two equivalent encodings. JSON callers send
`X-CSRF-Token` and `Idempotency-Key` as headers. The IAM-rendered consent
screen submits `application/x-www-form-urlencoded` and carries the same two
values as the `csrf_token` and `idempotency_key` fields, because a browser form
cannot set request headers and only a top-level form navigation lets the user
agent follow the `302` into a working application session. Both encodings are
validated by the same code and produce the same idempotency digest.

The consent page's Content-Security-Policy is `default-src 'none'` widened only
to `style-src 'self'`, `img-src 'self' data:`, `font-src` for the webfont, and
`form-action 'self'`. It has no `script-src` at all.
| POST | `/api/v1/oauth/token` | Exchange code or rotate OAuth refresh token |
| POST | `/api/v1/oauth/introspect` | Authenticated current-state introspection |
| POST | `/api/v1/oauth/revoke` | Idempotent token/family revocation |

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
connection, and an active SSO configuration exist. Disabling SSO requires first
moving the organization to a safe join method.

Ownership transfer requires the current owner, step-up, an ETag, and an active
Carbon membership as the target. The new owner becomes the sole owner in the
same transaction. The former owner becomes an admin with no delegated
capabilities until explicitly configured. The owner cannot be removed and a
sole owner must transfer ownership before they can be removed from the
organization.

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
- `sso.manage`

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

Directory updates may change first Silicon, explicit extra Silicons, a
Carbon's organization-wide advisory trust default, profile data, or a Silicon
reporting line. Changing the Carbon trust default requires `trust.manage` and
is rejected for Silicon memberships. They cannot directly change tags or a
job role; both use governance approval. Effective Carbon-to-Silicon visibility
is the union of shared-tag access and explicit extra-Silicon grants.

The product-facing directory endpoints are deliberately separate from the
administrative membership records:

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/v1/organizations/{org_id}/directory/self` | Current member's directory projection |
| GET | `/api/v1/organizations/{org_id}/directory/members` | Paginated active team directory |
| GET | `/api/v1/organizations/{org_id}/directory/members/{membership_id}` | One active team member |

They return `name`, public `id`, `role`, `org`, `tags`, and advisory `trust` by
default. `role` keeps authorization and description distinct as
`{org_role, job_role}`. A comma-separated `fields` query may select any subset
of `name,id,role,org,tags,trust`; unrequested properties are omitted. Trust is
evaluated from the requester's point of view for each row. The defined trust
directions are Carbon-to-Silicon and Silicon-to-Silicon. Carbon-to-Carbon and
Silicon-to-Carbon trust are undefined and therefore serialized as `null`.

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
| POST | `/api/v1/organizations/{org_id}/join/email-verification-code` | Resolve the authenticated invitee's submitted email and send/replace the join OTP |
| POST | `/api/v1/organizations/{org_id}/join` | Accept invite with bound OTP |

Invitation defaults contain a descriptive job role, tags, optional first
Silicon, explicit extra Silicons, and advisory trust. Advisory trust requires
an organization-wide default and may include one override per active tag and
one override per active Silicon. Effective trust follows organization default
→ tag override → exact-Silicon override. The complete trust configuration is
stored with the invitation as an immutable snapshot. `first_silicon` may be
null when the organization has none. An invitation always creates or
reactivates `org_role=member`; it can never grant admin authority or admin
capabilities. Promotion is a separate step-up-protected audited operation.

The notification link is built only from configured frontend origin plus
`/join/{org_id}?app={redirect_app_id}`; the optional app ID is validated and
does not introduce a caller-controlled redirect URL.

From that link, an authenticated direct Carbon submits the invited email to the
email-verification-code endpoint. The email must still be the exact active,
verified address immutably bound when that Carbon's invitation was created, and
the invitation must be pending and unexpired for the active email-join
organization. A match sends a six-digit Postmark code,
supersedes any prior live code, and returns only `accepted`, `invite_id`, and
the code's `expires_in`; it never returns contact data. A missing or mismatched
email/invitation returns the same `404 not_invited` response. The
returned invitation ID is then supplied with the code to the join endpoint.

Only one pending invitation per organization/Carbon is allowed. Join verifies
that the authenticated Carbon is the target, the invitation and code are
pending/unexpired, the organization matches, and every referenced tag/Silicon
is still active. Ten failed code verifications start a one-minute cooldown; the
same code may be tried in a fresh ten-attempt window afterward if it has not
reached its original expiry. Email-code initiation allows ten attempts per
authenticated Carbon and organization, including non-matching emails; reaching
the limit starts a full one-minute cooldown that cannot be evaded at a
wall-clock window boundary or by varying the email. A successful idempotent
replay does not consume another send attempt. Acceptance, membership
creation/reactivation, directory defaults, and trust-rule materialization are
atomic.

The email-code endpoint returns `202 Accepted` and marks the challenge
`delivered` only after Postmark confirms delivery acceptance. A definitive
provider rejection marks the pending challenge failed and returns `503`; an
ambiguous timeout or transport failure leaves it pending and unverifiable so a
false-success response can never make an undelivered OTP consumable. Provider
I/O runs outside database transactions. Exact replays return success only for a
previously confirmed delivery; an unresolved reservation remains
`409 idempotency_in_progress` until safely superseded with a new key.

## Silicons

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/POST | `/api/v1/organizations/{org_id}/silicons` | List or create |
| GET/PATCH/DELETE | `.../silicons/{silicon_id}` | Read/update/remove |
| GET/PUT/DELETE | `.../silicons/{silicon_id}/webhook` | Inspect, configure/replace, or disable the subscriber-managed endpoint |
| GET/PUT/DELETE | `.../silicons/{silicon_id}/webhook/subscription` | Inspect, replace, or remove organization-event topics |
| GET | `.../silicons/{silicon_id}/webhook/dead-letters` | List visible dead-letter deliveries |
| POST | `.../silicons/{silicon_id}/webhook/dead-letters/replays` | Replay one or an ordered batch of dead letters |
| POST | `.../silicons/{silicon_id}/token-rotation-requests` | Request owner-approved rotation |
| POST | `.../token-rotation-requests/{request_id}/complete` | Apply approved rotation and reveal token once |

Creation accepts a non-addressable handle component and constructs the only
public Silicon ID as `{handle}:{org_id}`. It requires a job role and accepts an
optional bounded display name, exact IANA `timezone`, description, and
profile-photo URL. An omitted display name defaults to the local handle and an
omitted timezone defaults to `UTC`. The resulting public ID is immutable and
tombstoned on removal. IAM returns the raw 128-bit Silicon token once. Silicon
activation does not depend on a webhook: an endpoint and subscription are
configured separately when the Silicon needs organization events.

Silicon reads return the full mutable profile. PATCH may change display name,
timezone, description, profile photo, or reporting parent with the corresponding
directory or hierarchy capability and current ETag. It never changes the public
Silicon ID or the job role; role and tag changes use their dedicated request or
direct owner/admin control routes. Profiles predating this contract are backfilled to `UTC`
and use their stored handle component as the display name.

When no custom photo is provided, IAM generates:

```text
https://iris.teamofsilicons.com/pfp/silicon?id={global_silicon_id}&level={level}
```

The root of a reporting tree is level 1; each child is parent level plus one.
Reporting edges are Silicon-to-Silicon inside one organization. Self-links,
cycles, removed targets, and cross-tenant references are rejected.

Token rotation creates an immutable approval request. The current owner must
approve using step-up authentication. Approval immediately invalidates the old
credential, advances authorization state, and revokes every Silicon access,
refresh, and IAM session authority; it does not create a replacement secret.
After approval, a separate completion request consciously generates and
reveals the new secret, again advances credential/auth epochs, and returns the
raw value under the ten-minute idempotent replay rule.

An active Silicon may manage its own webhook and subscription. A Carbon with
`silicons.update_directory` may manage any active Silicon in the organization
and must present a verified-channel step-up token for each mutation. Other
Silicons and applications are rejected. Every mutation
requires `Idempotency-Key`. Initial endpoint or subscription creation may omit
`If-Match` because no representation exists; replacing either requires its
current strong ETag. Endpoint and subscription deletion always require
`If-Match`.

Endpoint, subscription, and destination changes use the
`organization.silicon_webhook.redirect` step-up action and bind `resource_id`
to the target Silicon membership UUID.

`PUT .../webhook` accepts one SSRF-validated HTTPS URL and returns a new
`swhs_…` HMAC secret only in that no-store response. Replacing the URL also
rotates the secret. IAM retains encrypted URL and signing material; `GET` never
returns the secret.
Disabling the endpoint also removes its subscription, and a Silicon cannot
create a subscription before it has an active endpoint.

A subscription uses `mode=all`, which ignores any supplied `topics` and
canonicalizes the response to all three topic values, or `mode=selected` with
one or more of `membership_lifecycle`, `member_updates`, and `trust_updates`.
`all` receives every organization event explicitly routed to
Silicon subscribers, including organization metadata, tag-catalog,
invitation, governance-control, credential, and configuration events that do
not belong to a selected topic. For `selected`, `membership_lifecycle` is only
actual member or Silicon creation, reactivation, and removal;
`member_updates` covers applied existing-member role, tag, profile, hierarchy,
authorization, and ownership changes; and `trust_updates` is only trust state.
Optional `tag_filter` may be combined with either mode. When present, it always
contains the Silicon's own tag audience and may add up to 100 active
organization tags through `additional_tag_ids`. IAM then delivers only events
whose normalized before/after affected-tag union intersects either the
Silicon's own tags immediately before or after that mutation, or one of those
explicit extra tags. The own-tag relationship is captured in the domain
transaction: losing a shared tag does not suppress that event, and gaining a
tag later cannot expose an older event. Extra-tag authorization is rechecked
from the current subscription. Organization-wide, unattributed, and disjoint
events fail closed when filtering is enabled.

## Tags, visibility, and trust

Tags are stable, normalized, organization-scoped entities rather than free-form
strings embedded in memberships.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/POST | `/api/v1/organizations/{org_id}/tags` | List or create tags |
| GET/PATCH | `.../tags/{tag_id}` | Read or rename |
| GET | `.../tags/{tag_id}/members` | List attached Carbons and Silicons |
| PUT | `.../members/{membership_id}/tags` | Owner/admin directly replaces the complete tag set |
| POST | `.../members/{membership_id}/tag-change-requests` | Request tag additions or removals |
| GET | `.../members/{membership_id}/tag-history` | List applied tag sets with requester and approvers |

Renaming preserves the tag UUID and therefore does not break references.

Only an active Silicon may request a tag addition or removal for any active
Carbon or Silicon membership, including itself. A Carbon target requires
approval from the affected Carbon and one eligible owner/admin. A Silicon
target requires one eligible owner/admin. A Carbon owner, or an admin with
`tags.manage`, may instead directly replace any active Carbon or Silicon tag
set through the versioned PUT route. Creation and admission may still set
initial tags. Every applied or direct change preserves its initiating actor,
applicable approvers, before/after tag sets, membership version, and timestamp.

Trust is reliable advisory metadata, never an authorization decision. It has:

- boundary: `internal` or `external`
- level: `not_trusted`, `needs_approval`, or `trusted`

`GET/PUT /api/v1/organizations/{org_id}/trust/default` manages the initial
`internal/not_trusted` value. `GET/POST .../trust/rules` and
`GET/PATCH/DELETE .../trust/rules/{rule_id}` manage typed rules. Rule selectors
are `tag` or `membership` objects; strings such as `tag:finance` are not parsed
as foreign keys. Organization-wide baseline trust is represented only by the
separate `/trust/default` resource.

`POST .../trust/effective` explains the value for one subject and target
Silicon. A Carbon subject starts from its membership-wide default; a Silicon
subject starts from the organization default. Precedence then applies a tag
rule followed by an exact membership/Silicon rule. More specific rules win.
Conflicts at the same specificity choose the more restrictive level and return
every matching rule ID. The result always contains `advisory=true`.

Inter-Silicon department matrices use tag-subject to tag-target rules. Carbon
overrides use Carbon membership or tag subjects and Silicon membership or tag
targets.

## Role and tag governance

Job-role and tag changes never use the membership patch endpoint:

| Method | Endpoint | Behavior |
| --- | --- | --- |
| POST | `/api/v1/organizations/{org_id}/role-change-requests` | Create immutable request |
| GET | `.../approval-requests` | Filter pending/history/actionable requests |
| GET | `.../approval-requests/{request_id}` | Inspect payload and decisions |
| POST | `.../approval-requests/{request_id}/decisions` | Approve or reject |
| GET | `.../members/{membership_id}/job-role-history` | Applied role history |
| PUT | `.../members/{membership_id}/job-role` | Owner/admin directly replaces the descriptive job role |
| POST | `.../members/{membership_id}/tag-change-requests` | Create immutable tag request |
| PUT | `.../members/{membership_id}/tags` | Owner/admin directly replaces the complete tag set |
| GET | `.../members/{membership_id}/tag-history` | Applied tag history |

Only an active Silicon may create a role- or tag-change request; a regular
Carbon cannot request either change. A requested Carbon role change requires
the affected Carbon and one currently eligible owner/admin with
`roles.approve`; a requested Silicon role change requires one currently
eligible owner/admin. Carbon owners and admins with the corresponding
`roles.approve` or `tags.manage` capability may directly control either field
for any active Carbon or Silicon through the versioned PUT routes. A
Silicon-token rotation requires the owner and step-up. Eligibility is rechecked
when a decision is made and when a terminal operation is applied.

A Carbon tag change uses the same affected-Carbon plus owner/admin quorum. A
Silicon tag change requires owner/admin approval only. The request captures the
exact previous, added, removed, and proposed tag sets; if the target or its tag
set changes before quorum, the stale request fails instead of overwriting the
intervening change.

Payloads are immutable. Each approver may decide once. Rejection is terminal.
Once quorum exists, the role change, role history record, aggregate version,
redacted audit event, and outbox events commit in one transaction and can be
applied only once.

## WorkOS SSO

SSO is initially locked. A platform administrator first changes
`PUT /api/v1/admin/organizations/{org_id}/sso-entitlement`. An owner or
appropriately authorized admin may then configure it:

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/DELETE | `/api/v1/organizations/{org_id}/sso` | Inspect or safely disable |
| POST | `.../sso/setup-link` | Create five-minute WorkOS Admin Portal setup link |
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
current tenant authority before atomically consuming the transaction.

An organization using `join_method=sso` must have an active WorkOS organization
and connection mapping. That tenant-bound connection may admit an already
existing Carbon whose verified WorkOS email matches an active verified Carbon
email contact. Initial admission and reactivation always use `org_role=member`,
an empty job role, no tags or first Silicon, and advisory
`internal`/`not_trusted` trust. SSO does not consume an email invitation;
email-code joining remains the separate `join_method=email` flow.

Setup-link requests durably reserve their request-bound `Idempotency-Key`
before calling WorkOS. A concurrent identical request receives the retryable
`idempotency_in_progress` conflict and cannot create another provider link;
after successful completion, the encrypted response is replayable for its
five-minute lifetime. WorkOS does not offer provider-side idempotency for this
operation, so a process failure after WorkOS returns but before local completion
leaves the key in an outcome-unknown processing state and IAM does not issue a
second link automatically. The configuration test reads both the exact WorkOS
organization and connection and succeeds only when the connection is active and
belongs to the permanently mapped organization.

WorkOS webhook bodies are bounded, signature checked over the raw bytes,
timestamp-window checked, and deduplicated by provider event ID.
`WorkOS-Signature` is the only signature header and has
the comma-delimited form `t=<epoch_ms>,v1=<hex_hmac>`; there is no separate
trusted timestamp header. IAM verifies HMAC-SHA-256 in constant time over
`timestamp + '.' + exact raw UTF-8 body`, rejects timestamps outside a
300-second tolerance, and only then deduplicates the provider event ID.
Provider calls use rustls, explicit deadlines, bounded
responses, and validated redirect behavior. Deadline expiry is `504`; an
invalid upstream response is `502`; temporary dependency loss is `503`.

## Applications

Applications are owned by organizations, not individual Carbons. There is no
separate developer email/password identity. Registration requires `org_id`, and
the creating Carbon must be a current active owner or admin of that
organization. The creator is retained as immutable `created_by` provenance;
ownership and management authority remain with the organization. Any current
active owner or admin of that organization can manage its Applications.

Organization-facing Application and webhook management routes require a direct
`silicon-iam` bearer with `iam.self`, no client Application, and a current active
owner/admin membership in the target Application's organization. Promotion,
demotion, removal, or ownership transfer therefore changes Application
management authority immediately. `/api/v1/admin/applications*` review routes
instead require current platform-administrator authority and do not depend on
tenant membership. A delegated OAuth `oat_` cannot become a confused deputy for
the Carbon subject. Client-secret authentication locks the matching secret,
rechecks its active/retiring window and active verified Application principal,
and records usage in one transaction so concurrent revocation cannot
authenticate after it commits.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET/POST | `/api/v1/applications` | List apps in organizations the Carbon owns/administers, or submit registration |
| GET/PATCH | `/api/v1/applications/{app_id}` | Read/update |
| POST | `.../client-secret-rotations` | Rotate and reveal a new client secret once |
| GET/POST | `.../redirect-uris` | List complete URI history or add a new current URI |
| DELETE | `.../redirect-uris/{redirect_uri_id}` | Explicitly retire one URI |
| GET/PUT | `.../webhook` | Inspect active endpoint or propose replacement |
| GET | `.../webhook/dead-letters` | List dead-letter deliveries |
| POST | `.../webhook/dead-letters/replays` | Replay one or an ordered batch of dead letters |
| GET | `.../login-history` | App-specific authorization/login history |

Registration requires an immutable app ID and `org_id`, exactly one redirect
URI, one HTTPS webhook URL, requested scopes, and may include the Application's
callable OBO endpoint registry. IAM rechecks current organization owner/admin
authority before claiming or replaying the request. It returns an
`under_review` Application plus one-time Application and webhook signing
secrets. Application representations expose `org_id` and the Carbon
`created_by`; they never model that Carbon as the owner. The Application cannot
authorize users, introspect tokens, or issue OBO proofs until verified.
`notify_users` defaults to `true`.

Requested scopes and approved scopes are separate. Scope changes remain
pending and do not replace the active reviewed configuration until a platform
administrator approves them. Adding a redirect URI immediately retires every
previous current URI, retains those rows as versioned history, and creates the
new URI as `pending_review`; no retired URI remains usable while review is
pending. A current organization owner/admin can inspect the paginated history,
including each URI's status and lifecycle timestamps, and explicitly retire a
URI. Explicit retirement is idempotent, versioned, and audited. An Application
webhook replacement also
keeps the previous endpoint active until review; v1 exposes exactly one active
destination. During initial registration there is truthfully no active
destination: `active_url` is `null`, `pending_url` contains the submitted URL,
and webhook status is `pending_review`. A later replacement uses
`replacement_under_review` while preserving the existing `active_url`.
The webhook representation's `version` is the application aggregate version,
not an endpoint-row version; it is identical to the response `ETag` and is the
value required by `If-Match`. Replacement reuses the application's existing
encrypted webhook signing secret and does not return secret material.
`notify_users` is absent from every organization-management response and
mutation and is configurable only by platform administrators.

Initial application and webhook secrets are versioned credentials. Permanent
deletion is available only through the backend-admin decision workflow. It
immediately disables the client, compromises its credentials, revokes token
families, access tokens, OBO proofs, consents, and delivery scheduling, and
tombstones the app ID.

Client-secret rotation requires the current Application ETag, an idempotency
key, and verified-channel step-up bound to that Application. It atomically
retires every prior usable client secret, creates exactly one active successor,
increments the Application version, and returns the raw secret only in a
`no-store` response. An exact replay may recover that response for ten minutes;
the secret never appears in ordinary reads, audit diffs, or webhooks.

### Platform application review

`GET /api/v1/admin/applications` lists the inventory and pending review queue.
`POST /api/v1/admin/applications/{app_id}/decisions` supports:

- approve or reject initial registration
- suspend or reactivate
- approve or reject pending scopes, redirect URIs, or webhook replacement
- set the approved scope list
- set backend-only `notify_users`
- permanently soft-delete an application and revoke all application authority

Review requires a current platform administrator, step-up, idempotency key, and
ETag. Suspension immediately revokes active application authority. Every
decision records reviewer, reason, old/new redacted state, request ID, and
timestamp. Removing an approved scope atomically revokes every active `oat_`
token for that client that carries the removed scope; refresh rotation can
retain only the reduced current-scope intersection.

## OBO Access

OBO is available only between verified Applications owned by the same
organization. IAM derives this organization from the authenticated Application
credentials; neither the exchange nor verification API accepts caller-supplied
`org_id` or `X-Org-ID` context. Cross-organization and nonexistent target
Applications are indistinguishable as `404 not_found`.

An authenticated Application can discover another verified Application's
active callable endpoints and metadata contract with
`GET /api/v1/obo-access/applications/{app_id}/endpoints`. Discovery is limited
to the caller's organization and returns the target Application's `{app_id,
org_id}` plus at most 50 endpoint definitions in deterministic `endpoint_id`
order. Only a current organization owner/admin can configure those definitions
through Application registration or update. Endpoint identifiers and paths are
stable. Metadata definitions and exchange metadata must be JSON objects no
larger than 16 KiB, with bounded nesting and complexity. Every top-level
registered key is required, unregistered keys are rejected, and a descriptor
may enforce `string`, `number`, `integer`, `boolean`, `object`, `array`, or
`null`.

`POST /api/v1/obo-access/exchanges` authenticates App A with HTTP Basic and
requires these additional headers:

```http
Idempotency-Key: <16-255 character key>
X-OBO-Timestamp: <canonical Unix seconds>
X-OBO-Signature: <64 lowercase hexadecimal characters>
```

`X-OBO-Timestamp` must be within 60 seconds of IAM's clock. App A computes the
signature with its current Application secret and IAM verifies it in constant
time:

```text
HMAC-SHA256(
  app_secret,
  timestamp + "." + method + "." + registered_path + "." +
  body_sha256 + "." + Idempotency-Key
)
```

The method is the canonical uppercase method from `request.method`,
`registered_path` is loaded from App B's selected endpoint rather than accepted
from the exchange body, and `body_sha256` is the 64-character lowercase SHA-256
hex digest of the exact downstream body bytes. App A sends only that digest and
the endpoint's JSON metadata to IAM—never the actual downstream body or file.
The exchange request is:

```json
{
  "subject_token": "oat_...",
  "audience": "application-b-id",
  "endpoint_id": "files.upload",
  "metadata": {
    "filename": "report.pdf",
    "content_type": "application/pdf"
  },
  "request": {
    "method": "POST",
    "body_sha256": "<64 lowercase hexadecimal characters>"
  }
}
```

IAM confirms that App A and App B are verified and belong to the same
organization; the subject token was issued to App A and is active; its actor
has an active membership in that same organization; App A's reviewed scopes
permit OBO issuance; and the selected App B endpoint and metadata are current
and valid. It returns a random `obo_` proof with a unique ID and at most 60
seconds of life. The proof is bound to the source Application, audience
Application, subject token, actor, organization, registered endpoint, method,
path, exact body digest, and metadata. An exact exchange replay can recover the
same response only while the proof remains valid; its idempotency response
never outlives `expires_at`.

App A sends the proof alongside the actual downstream request to App B. Before
executing it, App B authenticates to `POST /api/v1/obo-access/verify` with HTTP
Basic and submits the proof plus details calculated from the actual request:

```json
{
  "access_proof": "obo_...",
  "request": {
    "method": "POST",
    "path": "/v1/files",
    "body_sha256": "<64 lowercase hexadecimal characters>"
  }
}
```

Audience identity comes from App B's authenticated credential. IAM verifies
the exact method, registered path, and body digest before atomically consuming
the proof and returning the represented actor, endpoint, and metadata. Exactly
one concurrent verification can succeed. Verification is intentionally not
idempotently replayable: a consumed proof always returns `409`, and an expired
proof returns `410`. App B executes the underlying operation only after a
successful verification and must still apply its own endpoint and business
authorization.

## Outbound events and webhooks

Every security-relevant mutation commits its domain change, redacted audit
record, aggregate version increment, and outbox event in one PostgreSQL
transaction. Workers claim outbox rows with bounded leases, deliver at least
once, use capped exponential backoff with jitter, and retain dead-letter state
under the configured retention policy.

Current organization owners/admins and authorized Silicon webhook managers can
list dead letters at their recipient-specific routes and replay one or a batch
of at most 100 by submitting `delivery_ids` with an idempotency key. Replay
preserves the original `event_id`, payload, `occurred_at`, aggregate version,
and complete attempt history; it resets only the cycle attempt counter and
increments the manual replay count. The transaction rechecks current Application
authorization or the current Silicon endpoint/subscription, then targets the
currently configured URL and signing-key version. `session.logout.v1` is the
narrow exception: because the event itself revokes delegated Application
authority, its secret-free revocation notification may be replayed only when
the exact persisted dead-letter recipient is bound to that Application. Other
revoked recipients fail closed. Batches are requeued and delivered in original
global event order, and each replay request records its initiating actor in the
audit trail.

The OpenAPI `webhooks` section defines application and subscriber-configured
Silicon deliveries. Event bodies use this envelope:

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
- `organization.membership.profile_updated.v1`
- `organization.membership.removed.v1`
- `organization.silicon.updated.v1`
- `organization.tag_updated.v1`
- `organization.trust.rule_updated.v1`
- `session.logout.v1`

Organization invitation, ownership, approval, SSO, tag, trust, Silicon
credential, and other directory transitions use the same versioned naming
rule. Consumers must deduplicate by `event_id`, process the event types they
understand, and safely ignore unknown event types so additive events do not
break delivery.

### Silicon Full event catalog (38)

`mode=all` is a closed set of exactly the following 38 event types.

| Membership lifecycle | Meaning |
| --- | --- |
| `organization.membership.created.v1` | A new Carbon membership was created. |
| `organization.membership.reactivated.v1` | An inactive Carbon membership was restored. |
| `organization.membership.removed.v1` | A Carbon membership was removed or deactivated. |
| `organization.silicon.created.v1` | A Silicon identity was added. |
| `organization.silicon.removed.v1` | A Silicon identity was removed. |

| Member and authorization updates | Meaning |
| --- | --- |
| `organization.membership.updated.v1` | Centrally managed membership directory, tag, role, or trust-related state changed. |
| `organization.membership.profile_updated.v1` | A Carbon profile was projected into this organization. |
| `organization.membership.authorization_updated.v1` | Explicitly delegated member capabilities changed. |
| `organization.ownership_transferred.v1` | Organization ownership moved to another Carbon. |
| `organization.admin.promoted.v1` | A Carbon member became an administrator. |
| `organization.admin.demoted.v1` | An administrator became a regular member. |
| `organization.silicon.updated.v1` | Centrally managed Silicon organization attributes changed. |
| `organization.tag_updated.v1` | A tag definition changed, including effects on assigned members. |

| Trust configuration | Meaning |
| --- | --- |
| `organization.trust.default_updated.v1` | The organization default trust value changed. |
| `organization.trust.rule_created.v1` | A trust rule was created. |
| `organization.trust.rule_updated.v1` | A trust rule was modified. |
| `organization.trust.rule_archived.v1` | A trust rule was archived. |

| Organization configuration | Meaning |
| --- | --- |
| `organization.created.v1` | The organization was created. |
| `organization.updated.v1` | Organization-level details changed. |
| `organization.tag_created.v1` | An organization tag was created. |

| Invitations and governance | Meaning |
| --- | --- |
| `organization.invitation.created.v1` | A Carbon invitation was issued. |
| `organization.invitation.accepted.v1` | Invitation admission completed. |
| `organization.invitation.revoked.v1` | A pending invitation was revoked. |
| `organization.role_change.requested.v1` | A governed job-role change was requested. |
| `organization.tag_change.requested.v1` | A governed tag-set change was requested. |
| `organization.approval.decided.v1` | A governance request was approved or rejected. |

| Silicon credential and webhook management | Meaning |
| --- | --- |
| `organization.silicon.rotation_requested.v1` | Silicon credential rotation was requested. |
| `organization.silicon.credential_rotated.v1` | A replacement Silicon credential was created. |
| `organization.silicon.webhook.configured.v1` | A Silicon webhook endpoint/signing secret was configured or replaced. |
| `organization.silicon.webhook.deleted.v1` | A Silicon webhook endpoint was disabled or deleted. |
| `organization.silicon.webhook_subscription.updated.v1` | A Silicon subscription mode, topics, or tag filter changed. |
| `organization.silicon.webhook_subscription.deleted.v1` | A Silicon subscription was removed. |

| SSO configuration | Meaning |
| --- | --- |
| `sso.setup_link.created.v1` | A provider setup link was created. |
| `sso.configuration.disabled.v1` | Organization SSO was disabled. |
| `sso.entitlement.replaced.v1` | The SSO entitlement/configuration was replaced. |
| `sso.connection.activated.v1` | An SSO connection became active. |
| `sso.connection.deactivated.v1` | An SSO connection was disabled without deletion. |
| `sso.connection.deleted.v1` | An SSO connection was permanently removed. |

Events never contain OTPs, raw tokens/secrets, provider credentials, encrypted
database records, or unrelated organization state. A Carbon profile change is
delivered to the union of Applications authorized immediately before and after
the transaction. Its `data.changed_fields` and complete `data.current` snapshot
are captured at that exact Carbon version and projected per recipient: profile
fields require the effective `profile` consent scope, while email and phone
require their respective effective scopes. Workers deliver this immutable
snapshot and never hydrate a later Carbon version.

The same capture rule applies to the closed Application organization-member
vocabulary: organization update and ownership transfer; tag update;
trust default and rule create/update/archive; membership create, reactivate,
remove, directory update, authorization update, promotion, and demotion; and
Silicon create, update, remove, and completed credential rotation. IAM resolves
the exact affected membership set, captures the union of Applications
authorized immediately before or after the mutation, and encrypts one distinct
projection per Application in the domain transaction. `profile`,
`organizations.read`, `memberships.read`, and `roles.read` disclose only their
corresponding sections; `email` and `phone` may additionally disclose the
affected Carbon's primary contact and never apply to a Silicon. A before-only
recipient receives scope-filtered `changed_fields` but only stable
resource/version authorization tombstones, never stale privileged state.

Here, an affected resource means a principal or organization projection the
Application can read through at least one effective data scope. Invitations,
SSO configuration, webhook configuration, and administrative or protocol
controls have no Application data scope and are excluded. Creating an
unassigned tag affects no member and therefore produces no Application member
projection.

Application member-event data always uses
`current: {"members":[...]}`, including a one-member event. An organization
update instead uses `current: {"organization": ...}` and is delivered only to
Applications with `organizations.read`. Tag and trust events use
`current: {"resource": ..., "members":[...]}` so the independently versioned
tag/default/rule state is not lost; trust-rule archive events carry a resource
tombstone.
All shapes and `changed_fields` are frozen at commit and cannot be hydrated from
later state. `organization.membership.profile_updated.v1` remains Silicon-only
because the same Carbon mutation is already represented to Applications by
`carbon.updated.v1`. Rotation-request/control, subscription/configuration, and
other protocol events are likewise outside this Application projection
allowlist.

For each active organization membership, a Carbon profile transaction also
captures an `organization.membership.profile_updated.v1` Silicon event under
the `member_updates` topic. That event carries the profile fields changed at
the exact Carbon version, the complete current same-organization membership
state, and the affected membership tags before and after the change. Email,
phone, credentials, and other contact or secret material are excluded.

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

Silicon webhook deliveries use the same event-ID, timestamp, key-version, and
signature headers and the same `{timestamp}.{body}` HMAC construction. The key
version identifies the subscriber-managed `swhs_…` secret returned when the
endpoint is configured or replaced. IAM never sends a provider bearer
credential to the destination.

### Silicon subscriptions

Silicon delivery begins only after both an active endpoint and a subscription
exist. `all` represents the complete closed topic vocabulary in API responses
and also receives explicitly routed Full-only organization events;
`selected` keeps the exact requested subset and never receives those unscoped
events. Multiple matching topics still produce one delivery per endpoint and
event. Subscription routing metadata—including the affected membership and
tag IDs and the event-time own-tag audience—is stored separately from the
public event payload and is never serialized to receivers.

Delivery is at least once, ordered and retried through the same durable worker
as application webhooks. Operator-wide failures use destination type
`silicon_webhook`. The old `silicon_hook` value remains readable only for
historical delivery records and cannot be selected for new deliveries.

## Audit and history

Audit records are internal, append-only security and lifecycle evidence; IAM
does not expose a generic organization-wide or global audit-browser HTTP API.
They include:

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
separately available to the Carbon and current owner/admin of the relevant
Application's organization. Job-role history includes requester, approvers,
immutable request ID, old/new text, and application time.

The worker applies configurable retention as one independently committed
database phase per maintenance tick, selected round-robin from a closed
21-phase vocabulary. Each selected phase claims at most the configured batch
size, which is bounded at 1,000 root rows, with ordered locking; a failure is
isolated to that phase and the next tick advances to the following phase. The
initial cursor follows the global wall-clock sweep slot so rolling restarts do
not starve later phases. Defaults are 365 days for login/authentication history,
30 days for expired challenges and abandoned authorization transactions,
90 days for expired or revoked
access/OBO/refresh metadata, 365 days for compromised refresh families, 45 days
for webhook-attempt telemetry, and 2,555 days for security audit events.
Approval-linked step-up records retain only a skeletal identifier, purpose,
assurance, and timing record after their digest is erased.
Authentication-session skeletons similarly remain only while a retained
audit, consent, governance, or lifecycle FK needs them; optional fingerprint and
revocation-detail fields are erased at the login history cutoff.

## Platform administration

There is no source-controlled default administrator password or runtime
bootstrap secret. The first platform administrator is bootstrapped only by the
one-time `iam-bootstrap-admin` operator command using the migrator database
credential. Platform administrators are existing Carbon principals with a
privileged role and strong step-up requirements. The administrator role is not
listed, granted, or revoked through the HTTP API.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/v1/admin/applications` | App inventory and review queue |
| POST | `.../applications/{app_id}/decisions` | Review/configure/suspend/delete app |
| PUT | `.../organizations/{org_id}/sso-entitlement` | Backend-only SSO unlock |

Admin authorization is checked against current Carbon, admin status, session,
and verified-channel step-up state on every mutation. Admin endpoints never
return provider credentials, encryption keys, secret digests, or raw one-time
response envelopes.

## Reliability and revocation guarantees

PostgreSQL is authoritative for identities, sessions, organizations,
memberships, permissions, governance, applications, SSO mappings, idempotency,
audit, rate limits, cooldowns, replay markers, and outbox state.

Security mutations use one database transaction. No transaction remains open
while contacting Postmark, Twilio, WorkOS, Iris, or an application or Silicon
webhook. Provider work is either a bounded request whose result is required
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
   refresh rotation, approval completion, OBO consumption, and Silicon token
   rotation are atomic and replay-safe.
8. Domain mutation, audit, aggregate version, and outbox record commit together.
9. Owner, membership, app, session, consent, and credential revocation are
   effective centrally before webhook delivery.
10. Raw credentials and contact identities never enter logs or public events.

## Provider and non-public boundaries

Postmark, Twilio Messaging, WorkOS, and Iris are accessed behind application
ports. Their raw provider-specific payloads and outbound management APIs are
intentionally not public IAM endpoints. Production startup refuses local/no-op
provider implementations. Subscriber-managed Silicon endpoints use IAM's
shared SSRF-hardened outbound webhook transport rather than a provisioning
provider.

The public contract fixes IAM-visible behavior—timeouts, uniform OTP responses,
callback/webhook validation, durable delivery state, idempotency, and error
mapping—without coupling clients to a provider SDK. Provider API version
upgrades therefore do not silently change this contract.
