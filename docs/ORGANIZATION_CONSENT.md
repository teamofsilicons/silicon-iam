# Application permission and organization consent

Each application login selects one account and exactly one organization. IAM
returns an app-bound short-lived token (SLT); applications never receive IAM
credentials, session tokens or verification codes. OBO approval happens
separately when an application requests a delegated action.

## Browser flow

1. Continue as Carbon or Silicon. The IAM browser can retain several configured
   accounts and list each account's active organizations. Adding an account does
   not replace the others. Account collapse preferences persist on that browser.
2. Select one account and one organization. Create or join an organization in IAM
   first if the account has no membership. Applications cannot preselect an
   organization through the login URL.
3. Show the IAM permission consent screen only when the backend reports
   `consent_required`, for critical IAM permissions requiring fresh consent.
   Display the exact current IAM permission set and critical labels. Do not
   include OBO endpoints in this screen.
4. Submit the chosen organization, exact current `approved_scopes`, and
   `scope_version` using the selected account's direct IAM session.
5. Return a two-minute, single-use SLT. Batch and bundle login return an array of
   individually app-bound SLTs.

Identity and profile are default IAM permissions. Additional permissions must be
declared. Application review and a user's critical IAM consent are separate
checks; neither replaces current membership or capabilities.

## Direct IAM clients

A Carbon or Silicon holding a direct IAM bearer reads:

```http
GET /api/v1/app-auth/organizations?app_id=billing
Authorization: Bearer <direct IAM access token>
```

The response includes application identity, `items` with available organizations,
`scopes` with descriptions and critical labels, `scope_version`, and
`consent_required`. The compatibility field `allow_empty_organization_selection`
is false. Submit current values, not the literal example version:

```json
{
  "app_id": "billing",
  "org_ids": ["customer"],
  "approved_scopes": ["self.identity.read", "self.profile.read"],
  "scope_version": 1
}
```

Use `POST /api/v1/app-auth/short-lived-tokens` with an idempotency key. `org_ids`
must contain exactly one available organization. OBO scopes, incomplete or extra
IAM scope sets, stale versions, empty selections and multiple organizations are
rejected. Reload choices after a scope change and obtain consent when required.

Application Basic credentials and application OAuth bearers cannot obtain SLTs
or approve their own access. The official IAM CLI uses the account's direct
session. For example:

```sh
iam login --app-id billing --grant-org customer --approve-scopes
```

`--approve-scopes` records explicit approval when critical IAM consent is
required. `--all-orgs` is rejected. The management `--org` default never selects
application access.

## Account onboarding and token boundaries

Direct IAM signup and account login are organization-independent. Carbon signup
signs in automatically and then asks the account to create or join its first
organization. Independent Silicon signup waits for custodian approval, then can
sign in and create an organization when its custodian allows it, or join through
an invitation. Application login begins only after an active membership exists.

Every SLT and resulting application access/refresh family binds its selected
membership. A later login for another organization issues a separate family;
it does not widen earlier tokens. Creating or joining another organization does
not expand existing application authority. Apps that support several
organizations manage those separate sessions themselves.

Current membership, scope approval and consent are rechecked during refresh,
introspection and API access. Application ownership does not determine the
user's selectable organizations. Scope removal and membership removal take
effect without waiting for a webhook. Null or absent fields mean undisclosed
information, not permissive defaults.

## Batch and bundle consent

[Batch login](BATCH_LOGIN.md) carries each application's one-element `org_ids`,
exact `approved_scopes` and `scope_version`. The direct API may select a different
organization for each app, but each issued token still represents one account
and one organization. Validation and issuance are atomic.

[Bundles](BUNDLES.md) display one bundle identity and use one browser account and
organization picker for all members. Each member retains its own exact IAM scope
set and version and receives its own SLT. A changed member list cannot silently
add another application; any failure rolls back the whole issuance.

These rules also apply in a [testing environment](api/testing-environments.html).
