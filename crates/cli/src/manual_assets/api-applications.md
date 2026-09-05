# Applications, registration and current authorization

An application is a registered confidential OAuth client. It is owned by an organization and administered by that organization's owner and administrators — but anyone may sign in through it.

## Registration

`POST /api/v1/applications` takes a local application handle, the owning organization, a webhook URL, a caller-chosen `webhook_secret`, and the backend `base_url`. IAM qualifies the handle with the organization: creating `drive` in `google` returns the canonical ID `google>drive`. Use that canonical ID for credentials, login, discovery, path parameters, and OBO. There are no redirect URIs to register and no login scopes to request: a login names its redirect URI in the query string and carries the whole catalogue.

```
POST /api/v1/applications
Authorization: Bearer <Carbon access token>
Idempotency-Key: <one logical creation>
Content-Type: application/json

{
  "app_id": "billing",
  "org_id": "acme",
  "app_name": "Billing",
  "webhook_url": "https://billing.example/hooks/iam",
  "webhook_secret": "replace-with-at-least-32-random-characters",
  "base_url": "https://billing.example"
}
```

`base_url` identifies the application's backend origin for discovery. It must contain no trailing slash, path, user information, query, or fragment, and use HTTPS except for literal loopback HTTP during local development. For example, `https://billing.example` is valid and `https://billing.example/` is not. IAM returns it to callers; it does not navigate to it, append login tokens to it, or treat it as a redirect allowlist.

Use public HTTPS application origins with hosted IAM. The public edge has been observed rejecting loopback `base_url` payloads with an unstructured HTTP `403`; selecting a testing environment changes database isolation, not the ingress policy. The loopback exception is usable against a local IAM runtime, selected explicitly by the client service URL or CLI `--url http://127.0.0.1:8080`. The checked-in runtime's URL validator accepting a value does not prove a hosted edge will accept it.

**IAM generates only the client secret.** Your application supplies the webhook signing secret (32–512 non-whitespace ASCII characters), which IAM encrypts at rest. The v1 response echoes it for compatibility. The generated client secret is replayable for ten minutes with the same idempotency key and then unrecoverable.

A new application is usable immediately: there is no review to wait behind. In production, a change that widens authority — a new webhook destination — is still held as `has_pending_changes` until explicit webhook approval, so where an application delivers cannot quietly move. The current owning organization's owner/admin or an IAM platform reviewer can approve the endpoint of an already verified Application with verified-channel step-up. A testing environment activates its endpoint immediately because it has no platform reviewer.

| Status | Meaning |
| --- | --- |
| `verified` | Live. Where an application arrives. |
| `under_review` | Held by the platform pending a decision |
| `rejected` | Declined by the platform |
| `suspended` | Access withdrawn; reinstatable |
| `deleted` | Terminal. The ID is never reused. |

## Signing a user in

A short-lived token. Three steps, two of them yours.

1. **Send** the person to `<auth_base_url>/login?app_id=acme%3Eyour-app&redirect_uri=https://you.example/callback&org_id=acme`. IAM signs them in if they are not already. Naming an `app_id` is what makes this a login on your behalf; without one it is an ordinary Silicon IAM login and no token is minted. `org_id` is optional. When present, IAM requires the person's active membership and binds the resulting Application token family to that organization. When absent, the browser login is unscoped.

2. They arrive back at your `redirect_uri` with `?slt=…`. If you gave no `redirect_uri`, IAM shows them the token on a page instead — useful for a device or a terminal that has nowhere to be redirected to.

3. **Your server** exchanges it at `POST /api/v1/app-auth/tokens`, authenticating with HTTP Basic and sending `app_id` and `slt`. You get an access token good for 30 minutes and a refresh token that rotates on every use. Send `refresh_token` instead of `slt` to the same endpoint to renew.

**We never ask a person for their credentials on your behalf.** Signing in to an application never asks for a password, a verification code, or any other authentication secret to hand to you. The only thing an application ever receives is the short-lived token. If anything claiming to be part of this flow asks a person for a credential, it is not us.

The short-lived token lives **two minutes** and is good for exactly one exchange. It is bound to the person, to your application, and to the session it was minted from. When the login names an organization, the exchanged token family is bound to that membership as well.

### When there is nobody to redirect

A Silicon has no browser, and a Carbon that already holds a session should not have to start another one. Either can ask for the token directly:

```
POST /api/v1/app-auth/short-lived-tokens
Authorization: Bearer <access token>
Idempotency-Key: <key>

{ "app_id": "acme>your-app", "org_id": "acme" }
```

The answer carries `slt` and `expires_in`, and your server completes it at `POST /api/v1/app-auth/tokens` exactly as it would one delivered through a redirect. `org_id` is optional. Supplying it requires an active membership and binds the exchanged Application token family to that organization; omitting it preserves an unscoped login unless the IAM bearer itself already carries an organization context. OBO requires an organization-bound Application access token. This direct SLT route is the only way a Silicon can sign in to an application.

### Scope

There is none to negotiate. A login carries the whole catalogue — scope on an application is the *webhook's* scope, which decides what changes you are told about, and has nothing to do with what a session may read.

### Introspection

Tokens are opaque and there is nothing to verify locally. When an application needs to know whether a token is good **right now** — after a revocation, or a membership change — it calls `POST /api/v1/oauth/introspect` with its Basic credentials. The response reflects current revocation and membership state. An active organization-bound access token also returns `authorization`: a synchronous initial or replacement snapshot of principal/public ID, organization, membership ID/version, epoch, audience, and testing plane. Fetch this after first login or a local projection cache loss; no directory mutation or webhook arrival is required.

Send form fields `token` and optional `token_type_hint=access_token|refresh_token`. An unknown token, a token belonging to another Application, a currently invalid token, or a valid `X-Org-ID` that does not match its authority returns `{"active":false}`. A malformed or duplicated `X-Org-ID`, or an unsupported hint, is instead `400 invalid_request`.

Webhooks are a notification channel, not an authorization one. Never substitute a delivered event for an online check.

In the snapshot, `org_role` requires `roles.read` and `tags` requires `memberships.read`. Null means undisclosed, not a default role or an empty tag list. Refresh tokens and unscoped access tokens omit the snapshot. Application sessions remain excluded from first-party directory management routes; use Basic-authenticated introspection instead. After an IAM testing-environment clean, reimport/onboard and obtain fresh SLTs; the snapshot does not resurrect old tokens or erased membership state.

### Revocation

`POST /api/v1/oauth/revoke` uses the same Basic authentication and form shape, plus an `Idempotency-Key`. Revoking an access token invalidates only that token. Revoking a refresh token invalidates its complete OAuth family and access authority for the same Application session. Unknown tokens deliberately return `200`. This route never logs out the parent IAM session; an Application that needs to trigger that global session logout calls `POST /api/v1/logout` with its own OAuth bearer.

## Credentials

`POST /api/v1/applications/{app_id}/client-secret-rotations` issues a replacement and reveals it once. It requires a verified-channel step-up token bound to `application.client_secret.rotate` and an `If-Match`.

**The previous secret stops working immediately.** Deploy the replacement to every instance before rotating, not after.

`POST /api/v1/applications/{app_id}/webhook-secret-rotations` installs the successor signing secret supplied as `webhook_secret`. It requires the current Application ETag, an idempotency key, and a verified-channel step-up token for `application.webhook_secret.rotate`. IAM never generates this secret; the v1 no-store response echoes it with its version and a ten-minute idempotent replay window. New deliveries switch to it immediately; retain older key versions until already in-flight deliveries have drained.

## Base URL discovery

```
GET /api/v1/application-directory/other%3Ebilling
Authorization: Basic base64(acme>checkout:ask_…)
```

Any verified Application may discover any other verified Application, including one outside its organization. The response is deliberately small: `{"app_id":"other>billing","base_url":"https://billing.example"}`. The Basic credential identifies the requester; there is no caller ID in the query or body.

In a testing environment, also send `X-Testing-Environment-Key`. Both the requesting credential and target resolve only inside that environment, and IAM never falls through to a production target. See Testing environments (`iam docs api/testing-environments`) for the complete application proof flow.

## Redirect URIs

There is nothing to register. A login names its `redirect_uri` in the query string, and IAM appends the short-lived token to it. An application that wants to send people to different places on different days simply names a different URI.

## Webhook destination

`PUT /api/v1/applications/{app_id}/webhook` *proposes* a replacement and answers `202`: deliveries continue to the current URL until the owning organization's current Carbon owner/admin or an IAM platform administrator with `applications.review` approves the new one. The existing encrypted signing secret is normally reused, so no new secret is returned. Inside a testing environment there is no platform reviewer: the same route activates the new endpoint immediately and answers `200`. The sole key exception is an imported test Application still using an inherited production signing key: its first test URL replacement requires the caller to supply a new test-only `webhook_secret`. IAM switches to and echoes that supplied secret with `secret_replay_expires_at`; it never generates the webhook secret.

### Approve the pending destination

`POST /api/v1/applications/{app_id}/webhook/approvals` needs no request fields; omit the body or send `{}`. Send the current Application `If-Match`, an `Idempotency-Key`, and a verified-channel step-up assertion for `application.webhook.approve` bound to the internal Application UUID. The caller must currently be the owning organization's Carbon owner/admin or an IAM platform administrator with `applications.review`; the creator field is audit metadata, not an independent permission. `GET /api/v1/applications/{app_id}/webhook` permits the same reviewers and returns `application_id` for step-up and `version` for the precondition. The UUID is optional for compatibility with older idempotency responses; fresh reads include it.

The Application must already be `verified`. This includes a new verified Application's first pending webhook, where `active_url` is still null. Approval activates that endpoint and retires any former active endpoint, returning `200`, the webhook representation and its matching Application-version `ETag`, without revealing a signing secret. It changes neither Application status nor scopes; a legacy Application still `under_review` needs a separate platform application decision. No pending endpoint or a non-verified Application is `409`; a stale version is `412`.

Delivery, signature verification and dead-letter replay are covered under Webhooks (`iam docs api/webhooks`).

## Login history

`GET /api/v1/applications/{app_id}/login-history` records every authentication attempt through this application, successful or not, retained for one year. Each entry carries the actor, the event type, the outcome and a `request_id`.
