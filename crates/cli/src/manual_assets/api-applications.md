# Applications, registration and current authorization

**Honeycomb management:** Production application editing, reviews, bundles and shared test lifecycle operations are managed by Honeycomb. See the [service integration contract](../HONEYCOMB_INTEGRATION.md). The legacy management examples below apply only before that integration is provisioned; runtime authentication and isolated test APIs remain available.

An application is an organization-owned confidential client. Its declared permissions determine which IAM information and external application endpoints it can use. Users approve that access in IAM and choose the organizations to share.

## Registration

A current Carbon owner or administrator registers an application with `POST /api/v1/applications`. IAM qualifies its local handle: `billing` in `acme` becomes `acme>billing`. Use the qualified ID in credentials, login, discovery, and OBO. A local handle starts with a lowercase letter and contains 1–80 lowercase letters, digits, underscores, or hyphens.

```
POST /api/v1/applications
Authorization: Bearer <direct IAM Carbon access token>
Idempotency-Key: <one logical creation>
Content-Type: application/json

{
  "app_id": "billing",
  "org_id": "acme",
  "app_name": "Billing",
  "base_url": "https://billing.example",
  "webhook_url": "https://billing.example/hooks/iam",
  "webhook_secret": "replace-with-at-least-32-random-characters",
  "app_scope": {
    "iam": ["self.identity.read", "self.profile.read"],
    "external": []
  },
  "webhook_scope": ["membership", "updates"],
  "testing_idle_days": 30,
  "obo_endpoints": []
}
```

`base_url` is the backend origin for discovery: HTTPS, with no trailing slash, path, credentials, query, or fragment. Literal loopback HTTP is permitted for local development. It is separate from the webhook destination and login callback. IAM generates `app_secret`; the registration supplies a webhook signing secret of 32–512 non-whitespace ASCII characters. Save secret-bearing responses securely during their ten-minute idempotent replay window.

## Declared permissions and subscriptions

`app_scope` has two parts. `iam` lists IAM permission names. `external` lists `{app_id, endpoint_id}` pairs from other applications, including applications owned by other organizations. `webhook_scope` independently subscribes to event categories: `full`, `membership`, `updates`, or `trust`. A webhook subscription never grants access to data.

Identity and profile permissions are selected by default. Request only the additional information the application uses. `GET /api/v1/application-scopes` lists IAM permissions as `items` containing `scope`, `description`, `critical`, and provider `app_id` (null for IAM). Supply `?app_id=org%3Eapp` to list one external application's published OBO endpoints. A valid, available application with no published endpoints returns an empty list; an unavailable application returns 404, and a malformed ID returns 422.

The console lists IAM permissions as checkboxes. Enter an external application's full ID to load and select its scopes; an invalid or unavailable ID displays `app_id invalid`. Every critical permission identifies its approver: “This would require approval from IAM” or the receiving application's ID. Webhook subscriptions are selected separately with checkboxes.

| Permission family | Access |
| --- | --- |
| `self.identity.read`, `self.profile.read` | The signed-in user's identifier/type and basic profile. |
| Other `self.*.read` permissions | Explicit fields about that user: contacts, selected organizations, membership, capabilities, tags, job description, Silicon relationships, and effective trust. |
| `directory.*.read` | Specific directory listings and fields for other members of selected organizations; critical review is required. |
| `organization.*.read` | Complete organization tag, trust, invitation, and governance data; critical review is required. |
| `obo:{app_id}:{endpoint_id}` | A published external endpoint; its provider determines whether it is critical. |

Application detail distinguishes desired `app_scope` from currently active `effective_app_scope`. Adding a noncritical permission or removing a permission can take effect directly. Critical additions require review. An initial application requiring critical scopes remains `under_review` and cannot be used until approval. An existing verified application continues using its previously approved scopes while an expansion is reviewed. User consent is still required before newly available permissions enter a login grant.

## Critical-scope review and discussion

Use the console's Permissions tab or `POST /api/v1/applications/{app_id}/scope-requests` with `{app_scope, message}`, the current application `If-Match`, and an idempotency key. Explain what you are building and why each critical permission is necessary. IAM creates separate threads for IAM review and each receiving application. A provider can publish its initial instructions through `obo_review_message`.

`GET /api/v1/application-scope-requests` provides the paginated review inbox, with optional `status`. Open `GET /api/v1/application-scope-requests/{request_id}` for the requested scopes, provider, status, version, participants, and timestamped messages. The response's `can_decide` identifies whether the current actor may review it.

Reply with `POST …/{request_id}/messages` and `{"message":"…"}`. Decide a pending request with `POST …/{request_id}/decisions` and `{"decision":"approve"}` or `{"decision":"deny","reason":"…"}`. A denial requires a reason. Replies and decisions use the thread's current `If-Match` and an idempotency key. Discussion history remains readable and supports follow-up replies after a decision. Replacing a request can mark the old thread `superseded`.

IAM acknowledges submissions to the requester and notifies the appropriate reviewers. Request messages, reviewer replies, decisions, and applicant replies generate email notifications for the other participants, including the application ID and a link to the thread. Review approval authorizes the requested scope; it does not replace the user's consent.

## Signing a user in

1. Send the browser to `https://auth.iam.teamofsilicons.com/login?app_id=acme%3Ebilling&redirect_uri=https%3A%2F%2Fbilling.example%2Fcallback`. Include a browser-bound login state in the callback query. Do not supply organization IDs.

2. IAM authenticates the user, identifies the application, displays its current permissions with critical labels, and obtains consent before organization selection. The user must select at least one active organization. The backend's `consent_required` controls whether the permission step is shown.

3. IAM returns `?slt=…` to the callback, or displays the token when no callback was provided. The application server exchanges it at `POST /api/v1/app-auth/tokens` using HTTP Basic with its own app ID and secret and a form-encoded body containing `app_id` and `slt`.

**Applications never receive IAM login credentials, IAM session tokens, passwords, or verification codes.** The login handoff contains only a short-lived token bound to that application, user, and parent IAM session. It expires after two minutes and permits one exchange. The exchange returns an application access token lasting 30 minutes and a rotating refresh token whose family has an absolute 900-day lifetime. Keep the app secret and returned credentials on the application server.

Only the selected memberships are authorized. The application's owning-organization prefix does not restrict which organizations the user may select. Prior organization grants on the same parent IAM session are preserved; future memberships are never shared automatically. Remove the SLT from the callback URL after establishing the application session, and do not log callback credentials.

### Example: external application login

```
Application: tos>briefcase
Callback: https://briefcase.example/auth/callback?state=<browser-login-state>

POST /api/v1/app-auth/tokens
Authorization: Basic <base64(tos>briefcase:app_secret)>
Idempotency-Key: <one logical exchange>
Content-Type: application/x-www-form-urlencoded

app_id=tos%3Ebriefcase&slt=<URL-encoded-SLT>
```

A callback may contain a path and query but must be absolute HTTPS (literal loopback HTTP is allowed), with no credentials or fragment. There is no redirect-URI registration list. The application binds and validates its callback state. `base_url` is not the callback.

### Direct Carbon and Silicon consent

A direct IAM Carbon or Silicon bearer can call `GET /api/v1/app-auth/organizations?app_id=acme%3Ebilling`. It returns the application identity, organization choices, current `scopes`, `scope_version`, and `consent_required`. Collect consent to that exact scope list, then submit:

```
POST /api/v1/app-auth/short-lived-tokens
Authorization: Bearer <direct IAM access token>
Idempotency-Key: <one logical consent>
Content-Type: application/json

{
  "app_id": "acme>billing",
  "org_ids": ["acme"],
  "approved_scopes": ["self.identity.read", "self.profile.read"],
  "scope_version": 1
}
```

Use the version and complete active scope names returned by the choices call, not the example's literal version. External names use `obo:{app_id}:{endpoint_id}`. A changed version or mismatched scope set is rejected; reload and obtain fresh consent. Application Basic credentials and application-issued bearers cannot call the consent endpoints to increase their own access.

### Batch login and bundles

`app_ids` starts one login for up to 100 unique applications and returns individual tokens in a URL-encoded JSON `#slts=` fragment. Each application's choices and submission carry its own scopes and version. See [Batch login](https://docs.iam.teamofsilicons.com/batch-login/).

A bundle gives same-organization applications one public login identity. Manage it through `/api/v1/application-bundles` and `/api/v1/application-bundles/{bundle_id}`. Create with `{org_id, app_id, app_name, app_logo, app_ids}`; `app_id` is the local bundle handle. Update metadata or members with `PATCH` and its current version, or retire with `DELETE`. Bundles have no secret and cannot contain other bundles.

Start `/login?bundle_id=acme%3Esuite`. Users see the bundle identity, approve the combined permissions, and choose organizations once. The API routes `GET /api/v1/app-auth/bundles/{bundle_id}/organizations` and `POST …/{bundle_id}/short-lived-tokens` provide that flow to direct IAM clients. Every member must remain active and verified; the submitted members must exactly match the current bundle. The callback carries individual application SLTs, and each app exchanges only its own token. See [Application bundles](https://docs.iam.teamofsilicons.com/bundles/).

## Introspection and application reads

Application tokens are opaque. Use Basic-authenticated `POST /api/v1/oauth/introspect` with form fields `token` and optional `token_type_hint` to check current validity. An active access token returns `authorization` for one selected organization, or `authorizations` when several apply. These snapshots include the principal, membership ID/version, authorization epoch, audience, and testing plane. Fetch one after first login or cache loss.

Role, tags, capabilities, and profile fields require their corresponding currently approved and consented permissions. Basic profile means display name, photo, description, and timezone. Organization profile access is limited to identifiers, name, logo, description, and resource version; it excludes SSO/security configuration. Own trust access reveals effective trust from the user’s perspective, while raw organization trust configuration needs its separate critical scope. Null means undisclosed. An application bearer can use the documented self and organization read endpoints within those same grants; list and search operations require the matching critical directory permissions. Missing permissions never default to full access. First-party management operations remain reserved for direct IAM sessions.

Introspection may use `X-Org-ID` to select an already authorized organization. A well-formed unselected organization, another app's token, or an invalid token yields `{"active":false}`. A malformed or duplicated header is a request error. Webhooks keep caches informed; they do not replace current authorization checks.

## Credentials and revocation

`POST /api/v1/oauth/revoke` uses Basic authentication, a form-encoded `token`, and an idempotency key. Revoking an access token invalidates that token. Revoking a refresh token revokes its application family. Unknown tokens return success. This operation does not revoke the parent IAM session.

Client-secret rotation uses `POST /api/v1/applications/{app_id}/client-secret-rotations`, the current application version, and a verified-channel step-up for `application.client_secret.rotate`. The previous secret stops working immediately; coordinate replacement across application instances. Webhook-secret rotation uses `…/webhook-secret-rotations`, a caller-supplied successor `webhook_secret`, and `application.webhook_secret.rotate` step-up. Retain previous webhook key versions while in-flight deliveries drain.

## Discovery and webhook destinations

A verified application can discover any other verified application's backend through Basic-authenticated `GET /api/v1/application-directory/{app_id}`. It returns only `{app_id, base_url}`. Discovery and OBO may cross application-owning organizations. In a test environment both credentials and targets resolve in that environment, without production fallback.

`PUT /api/v1/applications/{app_id}/webhook` proposes a destination. Production delivery stays on the current destination until approval. A current owning-organization Carbon owner/admin or an IAM application reviewer can read the pending endpoint and approve with `POST …/webhook/approvals`, an empty body, current application `If-Match`, idempotency key, and `application.webhook.approve` step-up bound to the application UUID. Endpoint approval is available while an application is under review or verified; scope review remains separate. Testing-environment destinations activate immediately. See Webhooks (`iam docs api/webhooks`) and Testing environments (`iam docs api/testing-environments`).

`GET /api/v1/applications/{app_id}/login-history` provides authentication history with actors, outcomes, timestamps, and request IDs. If directory access does not allow resolving an actor’s public ID, `actor.public_id` is `null`. The event stays in the history, including its principal ID and actor type; reading application history does not grant access to another organization’s directory.
