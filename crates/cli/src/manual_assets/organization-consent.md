# Application permission and organization consent

IAM asks users what an application may access before asking which organizations to share. Applications receive only app-bound short-lived login tokens. They never receive IAM credentials, session tokens, or verification codes.

## Browser flow

1. Authenticate the Carbon in IAM and identify the requested application or bundle.
2. Display the complete effective permission list, with descriptions, external providers, and critical labels. Obtain explicit consent. The IAM backend's `consent_required` value determines whether this step is required.
3. Show the user's active organizations. Select at least one, or explicitly select all current organizations. A Carbon may select none when `allow_empty_organization_selection` is true: the current approved permissions include `organizations.create` or `organizations.join`. Applications cannot supply organization scope through a login URL.
4. Submit the exact approved scope names and scope version with selected organization IDs.
5. Return a two-minute single-use SLT, or an array of individually bound SLTs for batch and bundle login.

Identity and profile are default application permissions. Additional self, directory, organization, and external permissions must be declared. Critical scope approval by IAM or an external provider is separate from the user's consent; both must be satisfied.

## Direct IAM clients

A Carbon or Silicon holding a direct IAM bearer reads:

```http
GET /api/v1/app-auth/organizations?app_id=acme%3Ebilling
Authorization: Bearer <direct IAM access token>
```

The response includes application identity, `items` with organization choices and existing authorization flags, `scopes` with descriptions and critical labels, `scope_version`, `consent_required`, and `allow_empty_organization_selection`. Present the returned current values to the user, then submit:

```json
{
  "app_id": "acme>billing",
  "org_ids": ["customer"],
  "approved_scopes": ["self.identity.read", "self.profile.read"],
  "scope_version": 1
}
```

Use `POST /api/v1/app-auth/short-lived-tokens` with an idempotency key. The example version is illustrative: send the value just read. External scope names flatten to `obo:{app_id}:{endpoint_id}`. IAM rejects an incomplete, extra, or outdated scope set. Reload choices and obtain fresh consent after a version change.

Application Basic credentials and application OAuth bearers cannot obtain SLTs or approve their own additional access. A trusted IAM client such as the CLI may submit choices using the user's direct session, after receiving the user's explicit choices.

## Account onboarding without an organization

A new Carbon can sign in with explicit `org_ids: []` after consenting to the current approved `organizations.create` or `organizations.join` scope. IAM rechecks eligibility during issuance; an unapproved, removed, or stale scope does not qualify. Silicons and applications without these permissions still require at least one organization. Omitting `org_ids` is never an explicit selection.

An empty selection adds no organization grants. Identity and profile remain available according to the token's scopes, refresh remains bound to the live parent IAM session, and introspection returns an active token with `authorizations: []` when it reaches no selected membership. Creating or joining an organization does not authorize the app to access it. Return to IAM and explicitly select that organization to add access. Existing grants on the same parent session are still preserved.

The CLI accepts `none` at the interactive organization prompt when eligible. A new account with no organizations can explicitly use `--all-orgs --approve-scopes`; this submits the empty current selection.

## Scope and organization boundaries

Consent is bound to the parent IAM session and target application. Additional organization choices preserve grants already approved on that session; they do not select organizations joined later. An application's owning organization does not define the user's available organizations. Tokens authorize only currently active selected memberships and currently effective consented scopes.

Introspection and application reads enforce these limits synchronously. Webhook projections obey the same field restrictions and only subscribe through `webhook_scope`. Removing a scope or membership takes effect without waiting for a webhook to arrive. Null or absent fields are undisclosed information, not permissive defaults.

## Batch and bundle consent

[Batch login](BATCH_LOGIN.md) carries each application's `approved_scopes` and `scope_version` in its selection. Validation and issuance occur in one transaction; a failure leaves no partial new consent or tokens.

[Bundles](BUNDLES.md) display one bundle identity and combine member permissions for consent, then use one organization picker. The request still records every member's exact scope version and returns individual app-bound SLTs. A changed member list cannot silently add an application to a submitted login. Every empty per-app selection must qualify independently; the shared bundle picker permits no organizations only when all members qualify. A failure rolls back the entire batch or bundle.

All routes keep these same rules inside a [testing environment](api/testing-environments.html), with test credentials and the selected environment key.
