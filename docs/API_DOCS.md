# Silicon IAM HTTP API

The first official contract is **v1** at `https://backend.iam.teamofsilicons.com/api/v1`. [OpenAPI](openapi.yaml) specifies the wire format. Read the hosted guide at [docs.iam.teamofsilicons.com/api](https://docs.iam.teamofsilicons.com/api/).

## Authentication and request rules

Negotiate with unversioned `GET /api/version` and `Silicon-IAM-Supported-API-Versions: v1`, then verify the selected major and response header. `GET /api/v1/contracts` lists contract status and activity. Breaking changes receive a new major. A deprecated contract becomes eligible for sunset only after at least seven days without requests, with a conservative one-minute allowance for coalesced activity timestamps. Current v1 does not sunset merely because it is idle.

Use direct IAM Carbon or Silicon bearers for IAM account and organization actions. Confidential applications use Basic credentials for token exchange, introspection, revocation, discovery, OBO, and application testing setup. Their OAuth bearers can read only resources covered by current approved scopes, user consent, and selected active memberships. They cannot approve their own additional permissions or enter first-party management flows.

Mutation endpoints require an `Idempotency-Key`; resource updates also require the documented strong `If-Match` version. Reuse the same key and payload for an uncertain retry. OBO verification is deliberately single-use and accepts no idempotency key. OAuth form endpoints use `application/x-www-form-urlencoded`; other endpoints use their declared JSON content type. See [conventions](api/conventions.html), [authentication](api/authentication.html), and [errors](api/errors.html).

## Example: external application login

Register `tos>briefcase` with declared `app_scope` permissions. Send the user to:

```text
https://auth.iam.teamofsilicons.com/login?app_id=tos%3Ebriefcase&redirect_uri=https%3A%2F%2Fbriefcase.example%2Fauth%2Fcallback%3Fstate%3DBROWSER_STATE
```

IAM authenticates the user, presents the app and current permissions, obtains consent, and asks which organizations to share. The application supplies no organization selector in the login URL. IAM returns to the callback with `slt`; the application's server exchanges it using its own Basic credentials:

```http
POST /api/v1/app-auth/tokens
Authorization: Basic <base64(tos>briefcase:app_secret)>
Idempotency-Key: <one logical exchange>
Content-Type: application/x-www-form-urlencoded

app_id=tos%3Ebriefcase&slt=<URL-encoded-SLT>
```

The SLT lasts two minutes and can be exchanged once. The response contains an application access token and a rotating refresh token. Bind the callback to the browser's initiated login and remove its credentials from the URL. Applications never receive IAM credentials, IAM session tokens, passwords, or OTPs.

A direct IAM client first gets `/app-auth/organizations?app_id=...`, then submits the exact returned `scope_version` and complete `approved_scopes` together with explicit `org_ids` to `/app-auth/short-lived-tokens`. Changed scope versions require fresh consent. Only selected organizations are accessible; future memberships are not added automatically. [Consent guide](ORGANIZATION_CONSENT.md).

## Permissions, review, and discovery

`app_scope.iam` selects named IAM permissions. `app_scope.external` selects `{app_id, endpoint_id}` from published external applications. Basic identity and profile are defaults. `webhook_scope` separately selects event categories; it never grants data access.

The scope catalog describes each permission and whether it is critical. Initial critical access waits for review; an existing application uses its prior effective permissions while additions are reviewed. Scope request threads support explanations, reviewer instructions, replies, approvals, and denial reasons with email notifications. Approval and user consent are separate requirements. [Applications guide](api/applications.html).

Verified apps can discover another verified app's `base_url` and published OBO endpoints across organizations. The subject's organization comes from its selected memberships, independently of either app's owner. An OBO exchange accepts optional body `org_id` when selecting among those memberships, binds the exact request, and returns a single-use proof for the recipient to verify. [OBO guide](api/obo.html).

## Batch and bundle login

`/login?app_ids=...` validates up to 100 apps, collects each app's permissions and organization choices, and atomically creates app-bound SLTs. A bundle groups same-organization applications behind one displayed identity and one organization picker, using `/login?bundle_id=...`. Both callbacks return individual SLTs in a URL-encoded JSON `#slts=` fragment. Every app exchanges its own SLT using its own secret. Bundles have no secret and no nested membership. [Batch login](BATCH_LOGIN.md), [bundles](BUNDLES.md).

## Current authorization and webhooks

Basic-authenticated introspection checks opaque application tokens online and returns scope-filtered authorization snapshots for selected organizations. Applications can bootstrap their cache without waiting for a directory event. Webhooks deliver authorized before/after changes at least once, filtered by effective scopes, user consent, and event subscriptions. Invitation, governance, and tag-definition events require their exact organization permissions. Own-profile access covers display name, photo, description, and timezone; own-trust access covers only effective trust from the user’s perspective. Raw SSO and Silicon credential/webhook management configuration are excluded from application deliveries. Silicon subscriptions retain their separate event vocabulary. Verify raw-body signatures, deduplicate event IDs, and apply resource versions in order. [Webhooks guide](api/webhooks.html).

## Email invitations before signup

An organization can invite an email address before its recipient has a Carbon account.
Creation stores the invitation without creating an account or granting membership. The
recipient follows `/join/{org_id}`, signs up or signs in, then verifies that exact invited
email before accepting. IAM binds the invitation only to the current active Carbon with
that verified contact. Invitations last 48 hours and may be revoked before signup.

`target_carbon` is absent until the invitation is bound; clients can display
`masked_delivery_address` while signup is pending. Carbon-ID invitations still require an
existing account. [Email invitation guide](EMAIL_INVITATIONS.md).

## Testing environments

An application can create a testing environment with its production Basic credentials or attach to an existing `iam_test_key`. IAM imports its declared external dependencies recursively, producing isolated test app credentials in one environment. Receiving applications authenticate any supplied test app secret against IAM before entering their own isolated storage. All subsequent API operations use the environment key and credentials issued there. Test OTPs are `000000`, and no real email or SMS is sent.

Imported production webhook secrets are never revealed. Test deliveries use a signed `test` envelope. Changing an imported webhook destination can generate a fresh test-only signing secret. Individual application inactivity retention defaults to 30 days and is configurable through `testing_idle_days`. [Testing guide](api/testing-environments.html).

## Endpoint guides

| Area | Guide |
| --- | --- |
| Identities and identifiers | [Overview](api/overview.html) |
| Carbon profiles, contacts, sessions | [Carbons](api/carbons.html) |
| Membership, directory, and SSO | [Organizations](api/organizations.html) |
| Machine identities | [Silicons](api/silicons.html) |
| Tags, trust, and approvals | [Governance](api/governance.html) |
| Registration, scopes, login, and credentials | [Applications](api/applications.html) |
| Client libraries and examples | [Rust client](client/README.md) |
| Commands and offline manual | [CLI](cli/README.md) |
