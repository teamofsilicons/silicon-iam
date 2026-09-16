# Honeycomb membership scope and management notifications — 2026-09-16

Production main API, scoped API and worker now run
`ed9abe2241fb8962c6036624d1946ab7c7f79068`:

```text
234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:03b47f26dac6bdc34ed53634b3aa4b691b7dfe11e95f6ff28d908de4248c496d
```

## Application configuration and renewed consent

`tos>honeycomb` retains its identity, public visibility, verified status, owning
organization, credentials and original identity/profile scopes. It now has
exactly these declared and effective scopes at IAM revision 3:

- `self.identity.read`
- `self.profile.read`
- `self.membership.read`

The operator scope update revoked one prior Honeycomb consent grant and two
application access tokens, along with associated refresh authority and pending
OAuth exchanges. Parent IAM login sessions were preserved. The live login policy
returns `consent_required=true`, scope version 3 and all three scopes. Users must
sign in again and approve the expanded disclosure; this release does not grant
user consent administratively. No active old-scope consent grants remain.

The change is recorded as `application.operator_scope_update` with source
`authorized_operator`. New bootstrap identities also receive the membership
scope for Honeycomb; the IAM app's bootstrap defaults remain identity/profile.
Existing bootstrap identities continue to be preserved.

Honeycomb is a first-party application owned by `tos`, represented by an ordinary
public/verified IAM application record. There is no separate internal-app flag.
Honeycomb owns ongoing app management; IAM stores and enforces its accepted
authentication configuration. Initial setup and this explicitly requested repair
used operator authority.

## Unscoped introspection

Migration 0099 replaces the organization-role gate in
`iam_private.list_current_application_authorizations`: `self.membership.read`
now controls disclosure instead of historical `roles.read`. The effective scope
projection intersects issued token scopes, current app approvals and the exact
session's live consent scopes. Consent rows are locked while the snapshot is
read. Existing token, epoch, application and selected-membership checks remain.

Both databases received 0099. Production has 99 migration entries; testing has
108 (including overlay versions through 9009). Runtime grants and the scoped
application identity helper were reapplied from the immutable image.

## Management notifications

The worker subscription is active at:

```text
https://backend.honeycomb.teamofsilicons.com/management/webhook/
```

It uses the previously provisioned independent management signing key, copied
privately from the Honeycomb bootstrap secret into the IAM production worker
secret and protected runtime environment. App webhook keys were not reused.
The live receiver accepted a correctly signed malformed payload and rejected it
before event persistence, confirming key agreement without fabricating an event.

The real scope change then queued `application.configuration.accepted`, event
`2c4ac254-4428-42a2-b590-72df67e32e58`, for revision 3. The normal IAM worker
successfully delivered it on attempt 1 at `2026-09-16T00:15:09.196434Z`.
This confirms durable webhook receipt, not downstream Honeycomb UI behavior.

## Validation and deployment

- 500 workspace tests passed; all 37 live PostgreSQL tests passed across the
  suite and a targeted retry. The retry followed a transient Docker-port TLS
  response during the unrelated login-history connection test.
- The new restricted-role regression covers the obsolete role scope, missing
  user consent, successful membership disclosure, unchanged older token scope
  snapshots and revoked application approval. Bootstrap's live test passed.
- Strict workspace Clippy, formatting, migration-security/runtime-grant checks
  and all dependency-policy checks passed. The ARM64 image built successfully.
- The scope/consent/audit/notification transaction was rehearsed and rolled back
  before applying it. Fresh PostgreSQL 17 backups and previous unit/environment
  files are private at
  `/etc/silicon-iam/releases/honeycomb-ed9abe2241fb8962c6036624d1946ab7c7f79068`.
- SSM deployment `0524cd57-26b5-43f4-8243-f4ae1fc28067` succeeded.
  CloudFormation change set `honeycomb-membership-ed9abe2` completed, persisting
  the image while preserving all other parameter values and resolved values.
- Both public HTTPS readiness/version endpoints passed. Authenticated Honeycomb
  reads show the same app UUID and all three effective scopes. Live PostgreSQL
  verification confirms the new disclosure gate and explicit consent policy.
- API, scoped API and worker are running with zero container restarts and no
  post-deployment error-level log lines. Instance `i-011c97da3d8b7ec74` remains
  Healthy/InService. Ingress and existing frontend were preserved.

Recovery remains forward-only unless databases and a compatible runtime are
restored together. Do not start an older image against migration 0099.

## Follow-up: self.tags.read

At the user's request, `tos>honeycomb` revision 4 adds effective
`self.tags.read` while retaining identity, profile and membership scopes.
The operator transaction was rehearsed and rolled back before commit, then
retired one prior consent grant and three Honeycomb application tokens to
require renewed consent. Parent IAM sessions and app credentials were preserved.
SSM operation: `8ca58e15-dc75-4ad4-b4c0-2e75fc048bcb`.

Authenticated management reads verified all four declared/effective scopes.
Notification `3a0b4c5b-cec6-453d-b655-16cc029f2cbf` delivered on attempt 1 at
`2026-09-16T01:08:28.180641Z`. This was a configuration update; the runtime image
and migration ledger remain unchanged.

Known separate issue: the unscoped authorization-list function's tag projection
still checks historical `memberships.read`; it needs a code/migration fix before
`self.tags.read` alone discloses tags in that particular introspection projection.
The selected-organization projection already uses `self.tags.read`.
