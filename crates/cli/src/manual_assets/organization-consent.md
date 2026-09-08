# User-selected Application organization access

Applications start login with `app_id` and, optionally, `redirect_uri`. They must
not supply `org_id` or choose organizations for the user. IAM authenticates the
user, validates the Application, and then asks the user to select at least one
active organization. “Select all” means all organizations shown now, not future
memberships. The button shows loading, successful authorization, then redirects
with a two-minute, single-use SLT. Application servers still exchange only the
SLT and their own Application credentials; they never collect IAM OTPs or STKs.

```text
https://auth.iam.teamofsilicons.com/login?app_id=tos%3Ebriefcase&redirect_uri=https%3A%2F%2Fbriefcase.teamofsilicons.com%2Fauth%2Fcallback
```

## IAM client and CLI

Only a direct IAM Carbon/Silicon bearer may read choices or submit consent:

```http
GET /api/v1/app-auth/organizations?app_id=tos%3Ebriefcase
Authorization: Bearer <direct IAM access token>
```

The response contains the verified `app_id`, optional `app_name`, and `items` with
`org_id`, `name`, and `authorized`. The last field marks existing grants on this
parent IAM login. This list is never available using Application credentials.

```http
POST /api/v1/app-auth/short-lived-tokens
Authorization: Bearer <direct IAM access token>
Idempotency-Key: <unique key for this exact request>
Content-Type: application/json

{"app_id":"tos>briefcase","org_ids":["tos","my-team"]}
```

`org_ids` must contain 1–1000 active organization handles. IAM checks the entire
selection atomically; invalid/nonmember selections grant nothing. The old
singular `org_id` request field is rejected. An Application access token cannot
call this endpoint to widen its own grants or log into another Application.

```rust
let choices = signed_in.auth().login_organizations("tos>briefcase").await?;
// Present choices.items in your trusted IAM interface; obtain the user's choice.
let slt = signed_in.auth().short_lived_token_for_organizations(
    "tos>briefcase", &["tos".to_owned(), "my-team".to_owned()], &Mutation::new(),
).await?;
```

`short_lived_token` reuses only existing selected organizations, and fails when
there are none. The compatibility helper `short_lived_token_in_organization`
adds the supplied organization; it no longer creates a single-org token family.
Application integrations should initiate browser login, not hold direct IAM
credentials or offer their own organization selector.

```sh
iam login --app-id 'tos>briefcase' --grant-org tos,my-team
iam login --app-id 'tos>briefcase' --all-orgs
iam silicon-login --app-id 'tos>briefcase' --grant-org tos
# Add one later, retaining previous grants:
iam login --app-id 'tos>briefcase' --grant-org another-team
```

Without selection flags, an interactive terminal lists choices and prompts.
Noninteractive use fails with actionable help. Global `--org`, environment
variables, and stored organization defaults never imply consent.

## Enforcement and additive access

Consent is an explicit set of membership IDs, tied to the Application, subject,
and parent IAM session. Additions union with the existing set under a row lock;
they do not replace it or invalidate already-issued multi-organization tokens.
Other devices' parent sessions remain independent. Revoking or ending a parent
session still removes its authority; reactivating a revoked consent does not
resurrect its previous selection implicitly.

Active membership and organization status are rechecked on every use. Joining
another organization does not automatically expose it. Leaving or suspension
removes access. A separate new membership is not silently authorized by an old
membership grant.

Applications can read selected organization details, members, directory data,
tags, trust, Silicon details, and role/tag history. Mutations still require direct
IAM authority. Organization listing and introspection expose only selected,
currently active memberships. With `X-Org-ID`, introspection answers for that
selected organization; without it, `authorizations` lists the selected set.
An unselected organization gives inactive introspection and no directory data.

OBO remains within the calling Application's owning organization, and that
organization must be in the subject token's selection. Proof verification
rechecks it. Signed webhook projections and replay authorization use the same
organization selection, including removal notifications at the event boundary.

## Upgrade and testing

Migrations `0072_user_selected_application_organizations` and
`0073_selected_organization_obo_parent_binding` are required before the
new API, frontend, client, or CLI. The latter preserves the proof's single-org
binding while allowing a selected multi-org parent. Do not publish a client before deploying the
compatible backend. The same migration applies in the shared testing database;
its restricted security-definer ownership and environment isolation remain in
force. Use the normal testing header/CLI `--test` selection for all flows.

Apply the backend follow-up `0074_selected_consent_webhook_active_key` too.
It preserves consent filtering while retaining the existing rule that new webhook
events select exactly one active signing key per endpoint. Retiring keys remain
available only for previously bound deliveries. Client/CLI 1.4.0 needs no package
change for this backend-only correction.

Existing explicitly single-organization grants retain only that organization.
Legacy all-organization grants have no evidence of explicit user selection and
receive **no organization authority** until the user revisits IAM and selects
organizations. Do not infer “all” during migration. Existing identity tokens may
remain live with an empty `authorizations` list; downstream apps should request
reauthorization rather than fall back to cached organization rights.

Manually verify: empty/unknown/nonmember selections; one versus multiple grants;
additive access with an old token; newly joined but unselected organizations;
removal and suspension; selected/unselected directory and OBO reads; Application
credentials attempting to list or enlarge grants; and equivalent test-plane
flows with no cross-environment disclosure.

### Local manual verification — 2026-09-08

Verified with the real CLI/client and Solid browser UI against an isolated local
API, production-style database and shared testing database. No production accounts
or applications were changed.

- Browser: verified-app confirmation, organization picker, zero-selection guard,
  existing grants kept checked, loading/checkmark states, displayed SLT and callback delivery.
- CLI/API: explicit selection, duplicate/unknown/nonmember rejection, actionable
  noninteractive help, and no inherited consent from the default organization.
- Original tokens retained earlier grants after another organization was added.
  Unselected and subsequently joined organizations remained absent from listing,
  directory reads and introspection.
- Application bearers could read selected directory/tag/trust data, but could not
  mutate it, list consent choices or grant themselves more organizations.
- OBO exchange and one-time verification succeeded for a selected organization;
  an otherwise valid token excluding that organization was refused.
- Test-app import returned a fresh secret. An ordinary test member could authorize
  the app and receive the correct role and testing-environment snapshot. Removing
  the member immediately removed its authorization and retained a removal projection.

Webhook recipient/projection checks were local database checks; no external signed
webhook delivery was exercised in this run. Rust workspace/all-target compilation,
frontend production build, migration-security, runtime-grants, OpenAPI-route and
bundled-manual consistency checks passed. No automated test suite was added.
