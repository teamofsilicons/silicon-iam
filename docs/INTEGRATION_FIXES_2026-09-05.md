# IAM integration fixes — 1.2.0 release handoff, 2026-09-05

These changes target CLI/client **1.2.0**, developed from
`b57848ce55f0becf53e9244d2239a2dc714cecb0` (historical published CLI/client 1.1.1).
The evidence below records local verification, not proof of hosted deployment
or crate publication. Release is authorized; deploy the matching backend with
base migration `0067`, testing overlay `9003` and runtime grants, verify
readiness, then publish the packages. Confirm completion against the service
version and crates.io rather than inferring it from this report.
`UNDERSTANDING.md` edits were preserved. `iam report` remains deferred.

## Implemented contracts

### Shared testing-database isolation

The handle helpers were owned by a superuser. PostgreSQL superusers bypass
even forced row-level security, so a helper could find another environment's
handle although an ordinary query could not.

Testing overlay `9003` assigns security-definer functions to a restricted,
non-login owner, enforces environment scope, and preserves explicitly authorized
worker maintenance. Migration reconciliation handles future/replaced helpers;
readiness rejects unsafe ownership. Base migrations and existing overlays were
not rewritten. Cleanup now explicitly selects its authorized environment in
the separate testing-database transaction rather than reporting zero erased
rows under an unscoped API connection.

### First login and authorization-cache recovery

`POST /api/v1/oauth/introspect`, authenticated with the receiving Application's
Basic credential, returns `authorization` for active organization-bound access
tokens. It is a synchronous snapshot; no unrelated directory edit or webhook
delivery is required.

The snapshot binds principal/public ID, organization ID/handle, membership
ID/version, current authorization epoch, audience, testing environment and
effective scopes. `org_role` requires `roles.read`; `tags` requires
`memberships.read`. Null means undisclosed, not a default role or empty tags.

Rust: `application.oauth().authorization(access_token, Some(org_id)).await?`.
CLI (secret and access token are prompted for):

```sh
iam --test <environment-id> app token authorization 'acme>checkout' --org-context acme
```

Inactive/mismatched tokens and unscoped sessions carry no organization
authority. Refresh tokens are not resource-access credentials. An active
organization-bound access token from an older API lacking this contract causes
the convenience method to report the missing backend capability explicitly.

Apps must adopt this snapshot when bootstrapping/rebuilding their local
projection. The change does not automatically update Briefcase or another
consumer's code. Application bearer tokens intentionally remain excluded from
first-party directory management routes.

### Verified OBO authority

Successful proof verification includes the same typed authorization binding.
Disclosure is limited to the parent token's scopes intersected with the
recipient's current approved scopes. The exact persisted proof, parent token,
membership, principal, applications, epochs and endpoint are revalidated under
locks before consumption. Ordinary members do not need organization UPDATE
permissions to obtain this projection.

Use this binding only for the verified endpoint and exact request. Apply the
consumer's own resource policy; proof validity is not blanket resource access.
Never fill undisclosed fields from a broader cached token. Any cache key must
include environment, audience, organization, principal, membership, epoch and
effective scopes. Verification remains single-use and must not be retried after
an uncertain result.

### CLI/client integration issues

- Credential/config updates use cross-process locks, latest-state merges,
  owner-only temporary files, syncing and atomic replacement. Per-session locks
  cover refresh reservation, remote exchange and commit, plus login/logout
  transitions. Pending retry keys are preserved.
- Unix state handling rejects symlinks, hard links, non-regular files and unsafe
  homes. See [storage requirements](cli/storage.md), including the explicit
  `0700` home requirement and platform/filesystem limits.
- URL validation uses typed loopback IP addresses, including IPv6 `::1`, in the
  client and API. Application origins still reject trailing slashes and paths.
- Signup rejects invalid Carbon IDs before starting verification. Help states
  the 3–30-character lowercase-letter/digit-1–9/underscore/hyphen format. Rust
  integrations can call `api::signup::validate_carbon_id` before starting signup.
- `silicon-login --app-id` can reuse a stored Silicon session when both identity
  credentials are omitted, without prompting again.
- Automatic updates are driven by use, never an idle timer or daemon. The CLI
  prints the completed command's result before checking its persisted
  last-attempt time; maintenance runs only when no attempt exists or it is at
  least one hour old. Failures are also throttled, a cross-process lock prevents
  concurrent updates, and the command's exit status is preserved. Explicit
  `iam system update` bypasses opt-out and the hourly throttle. The client checks
  after a decoded IAM request using an in-memory timestamp shared with its
  clones; cancellation retains the throttle and safely releases its slot.
  Running Rust code is not hot-replaced: dependency updates take effect on the
  next build.
- The CLI bundles searchable offline integration manuals, detailed command
  help, contextual next-command suggestions and non-interactive input guidance.
  JSON remains machine-readable; help and local reference commands do not
  trigger maintenance or require a working credential store.
- Non-IAM HTTP failures have a distinct `UnstructuredResponse` diagnostic that
  preserves status/correlation without printing HTML or inventing an IAM
  permission denial.

## Manual verification performed

Behavioral verification used actual built CLI commands against a local IAM API
on port 58082, with API/client/CLI running this working tree. No automated tests
were authored or executed. Compilation, Clippy and static contract/grant checks
were also used.

The data plane was the **already-used** `silicon_iam_testing` database, not a
fresh workaround database. Two disposable environments were created for this
run. An 18 MB local control-plane copy kept the existing local runtime's schema
unchanged while testing the new migration. No hosted database was changed.

| Manual case | Observed result |
| --- | --- |
| Identical Carbon handle, email and phone in two environments | Both signups/logins succeeded independently. |
| Import `briefcase-e2e>briefcase` in both environments while the old environment still exists | Both succeeded; distinct internal Application IDs. |
| Fresh organization-bound login, no directory edit and no webhook worker | Immediate owner authorization snapshot. |
| Ordinary member with an assigned tag | Correct member role, tag, membership version and epoch. |
| Silicon login and authorization | Correct Silicon identity/member binding; cached SLT login did not reprompt. |
| Wrong environment/organization, refresh token, unscoped session | No organization snapshot. |
| Old token after membership epoch change | Inactive; a fresh SLT/session exposed current authority. |
| OBO owner, tagged member, admin and Silicon | Correct represented authority in successful verification. |
| Tampered downstream body | Rejected; the correct original body could still consume the proof. |
| Wrong environment for proof verification | Rejected; the original environment could still consume it. |
| Sequential and two concurrent proof verifications | Exactly one success; reuse returned `obo_proof_consumed` (409). |
| Proof after membership promotion | Rejected as revoked. |
| Proof past its real 60-second deadline | Rejected as expired. |
| Endpoint disabled after proof issuance | Rejected as authority revoked; fixture endpoint restored. |
| Clean disposable environment, re-signup, reimport, fresh login | 165 fixture rows erased; re-onboarding succeeded and snapshot was immediately available. Old token remained inactive. |
| Other environment after cleaning | Still usable; original pre-existing organization row also verified present. |
| 128 parallel local logouts from 3,000 synthetic sessions | Zero failures; all targeted sessions removed. |
| 96 mixed logout/config-write/config-read commands | Zero failures; all 32 config updates retained. |
| 64 concurrent first-use config writes | All retained; private home and files created safely. |
| Symlinked credential/config/lock/home, unsafe home, FIFO | Rejected; victim contents unchanged; FIFO did not hang. |
| Uncertain refresh against closed local port | Same pending idempotency key retained for retry. |
| Live refresh batches of 2, 8 and 16 concurrent CLI commands | All succeeded; read-only database counts proved exactly one remote refresh per batch. |
| Scoped local logout | Other profiles, other testing sessions and environment keys preserved. |
| Invalid Carbon ID containing `0` | Local usage error before signup/OTP traffic. |
| IPv6 loopback service URL and Application origin | Service connection attempted; local Application creation accepted `http://[::1]:18085`. Non-loopback HTTP rejected. |
| Application origin with trailing slash | Structured validation error. |
| Local server returning HTML HTTP error | Distinct unstructured diagnostic, no raw HTML, exit 5. |

An earlier local revision manually verified an idle updater daemon and its
environment filtering. That design was superseded by the updated
`UNDERSTANDING.md` requirement: 1.2.0 uses post-command/request maintenance and
contains no idle daemon or timer. Those earlier observations are not evidence
for the replacement implementation. A full real-time hour for the client's
throttle was not observed; concurrency/cancellation code was reviewed and
compiled. Manual filesystem behavior was checked on macOS, not every supported
platform.

Static gates passed: all-targets workspace compilation and Clippy, OpenAPI/Axum
agreement (102 paths / 130 operations), runtime-grant manifest agreement, and
125 fixed-search-path, PUBLIC-revoked security-definer functions. The shared
testing database had zero elevated security-definer owners after migration.

## Still external / rollout order

The reported hosted-edge rejection of loopback Application origins is **not
claimed fixed**. Its response identified an edge-generated failure, not its
specific policy. The checked-in deployment template accepts an existing HTTPS
listener and does not define that edge policy. Hosted workflow examples now use
public HTTPS Application origins; loopback examples explicitly target a local
IAM runtime. Changing/retesting the actual edge requires a separate authorized
deployment task.

Required release order:

1. Apply base migration `0067`, testing overlay `9003` and the runtime grants;
   deploy the matching backend and verify readiness.
2. Publish matching client/CLI versions and matching source/tag documentation.
3. Update consuming apps to use live bootstrap snapshots and verified OBO
   bindings; then re-run their resource-level integration scenarios.

The local verification above does not establish GitHub merge, crates.io
publication or hosted rollout. Check the selected source revision, installed
package versions and `iam system version` separately. Historical 1.1.1 packages
do not contain these fixes.
