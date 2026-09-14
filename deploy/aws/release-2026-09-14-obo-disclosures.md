# Explicit OBO disclosures and membership planning — September 14, 2026

Migration `0093` preserves explicitly authorized subject disclosures when an
application verifies an OBO proof. The delegated scope set contains the exact
OBO endpoint plus only `self.identity.read`, `self.membership.read`, and
`self.tags.read` that remain in all four authority sources: the parent access
token, its exact current session-bound consent, the issuer's current approved
scopes, and the recipient's current approved scopes.

Nested identity fields are omitted without identity permission. Role and tags
remain null without their respective permissions; disclosed empty tags are an
empty array. The verified top-level actor still identifies the represented
subject. No unrelated operation permission is forwarded and no app declaration
or user consent is changed.

The existing parent, proof, subject, membership, organization, application,
epoch, expiry, revocation, world and exact-request checks remain in place.
The exact consent row is locked after the original parent/session locks, and
its current scope rows are read under that lock before proof consumption.

Migration `0094` limits join-order planning only inside
`iam_private.application_token_allows_membership(uuid,uuid)`. The existing
eight-table query, role/consent/token checks, function owner, ACL, security mode,
volatility and fixed search path are unchanged. The caller's planner setting
and the database connection pools are unchanged.

This follows observed scoped testing checkout timeouts and slow executing
authorization queries. Read-only synthetic measurements isolated join-order
planning overhead. In a disposable regression fixture, 12 simultaneous valid
authorizations through two connections took 258.3 ms before and 16.6 ms after
the change in production, and 222.1 ms before and 18.4 ms after in testing.
These timings describe the fixture, not a production latency guarantee.

Runtime revision: `fe2a08d9a39802ce738100016d8db5fa126ac275`.

Immutable ARM image:
`234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:74852a4478ebfb7aee82fa3a0a031b643dedba7b274438e604b64e0402fa9e45`.

Test-only follow-up: `c8584f3c8e8d8beade40e797ca857cf214d41b5b`.
The existing live import/OBO fixture declares and consents to identity access
in both applications. Its old endpoint-only expectation was updated to the
exact endpoint plus identity scope, with additional assertions that role and
tags remain undisclosed. This changes no runtime behavior; the combined runtime
revision includes it.

Validation before release:

- All 497 workspace tests, all 36 real PostgreSQL cases, and all four live HTTP
  client contracts pass. One local PostgreSQL container startup failed before
  migrations and passed its isolated retry; no test assertion was relaxed.
- The new restricted-role database matrix runs in production and testing worlds.
  It independently removes each disclosure from all four authority sources,
  checks exact grant binding, null versus empty tags, unrelated-scope exclusion,
  cross-world/audience/org/member denial, revocation, epochs, endpoint version,
  proof consumption, unchanged ordinary-bearer behavior and both concurrent
  re-consent interleavings.
- The planner regression checks Carbon and Silicon bound/unbound tokens, client
  context, world separation, epochs, revoked grants, selected membership and
  expired sessions under the restricted runtime role. Its metadata assertions
  preserve the function body, owner, ACL, security mode and search path; its
  function setting does not leak into the connection. Both live HTTP database
  planes also use the restricted API runtime role.
- Workspace Clippy with warnings denied, formatting, migration privilege and
  runtime grant checks, OpenAPI, generated CLI manuals and documentation checks
  pass. Independent source review found no remaining blocker.

The updated documentation is published at
https://docs.iam.teamofsilicons.com/api/obo/ and
https://docs.iam.teamofsilicons.com/client/obo/.

GitHub CI run `34862276605` passed for the exact runtime revision, including
all PostgreSQL tests, fresh migrations, restricted worker/client contracts and
monotonic key activation.

SSM operation `9ee42f12-5a7e-45b5-a70e-18ea46809304` completed successfully
on instance `i-011c97da3d8b7ec74`, us-east-1, from 15:41:09 to 15:41:24 UTC.
The existing release helper applied base migrations `0093` and `0094` to both
database planes, retained the scoped identity helper, and updated only the
main API, scoped API and worker image references. All three services are
healthy on the runtime revision above. Runtime credentials, keyrings, provider
configuration, ingress and pool settings were preserved.

CloudFormation change set `interface-obo-fe2a08d` completed with only
`BackendImageUri` changed, including no change to resolved parameter values.
The previous live template and all other parameter values were retained; no
rolling instance replacement policy was introduced. The same instance remains
Healthy/InService and the persisted image matches the runtime digest above.

The previous service units are saved privately at
`/etc/silicon-iam/releases/testing-fe2a08d9a39802ce738100016d8db5fa126ac275-1789400472874404127`.
Migrations remain forward-only; an older image with a different embedded
migration ledger is not an automatic rollback.

Public verification after release:

- Main and scoped `/readyz` return 200; both `/api/v1/version` responses report
  `fe2a08d9a39802ce738100016d8db5fa126ac275`.
- Main OBO verification without recipient authentication returns 401.
- Main token exchange without app authentication and scoped introspection
  without a bearer each return 401.

Independent read-only SSM verification
`a5d40b03-397e-4f0c-b290-d9c3516cd09f` confirmed the function-local setting is
1 in both databases while the caller remains at 8 before and after invocation.
SECURITY DEFINER, STABLE, fixed search path and denied PUBLIC EXECUTE are intact;
JIT and connection-pool settings are unchanged. Two synthetic nil-token checks
took 7.911/3.114 ms in production and 9.847/3.714 ms in testing. These checks
used no real actor token and establish deployed configuration and synthetic
cost, not end-to-end Interface latency.

Positive authorization and proof scenarios used disposable databases and the
live HTTP client suite. Public negative checks created no user data and used
no production application secret.

Manual post-release Interface checks in the existing isolated world/session
confirmed IAM remained connected, organization/member reads still returned
the current owner and three members, and trust defaults/rules loaded. An
isolated DM message to the test Silicon was sent successfully. No new IAM
error appeared in those checks; these are specific observed flows, not a
claim that every bundled backend workflow has passed.
