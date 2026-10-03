# Batch application login

Authenticate once in IAM, review critical IAM permissions when required, choose one organization for each application, and receive up to 100 independent app-bound short-lived tokens. For a single displayed identity and shared organization picker, use an [application bundle](BUNDLES.md).

## Start a browser login

```js
const login = new URL("/login", "https://auth.iam.teamofsilicons.com");
login.searchParams.set("app_ids", ["briefcase", "dm"].join(","));
login.searchParams.set("redirect_uri", "https://frontend.example/callback?state=YOUR_LOGIN_STATE");
location.assign(login);
```

Use 1–100 unique, bare application IDs. `app_ids` is comma-separated and mutually exclusive with single `app_id` and `bundle_id`. Do not supply organization IDs in the login URL. IAM validates every application, displays effective permission descriptions and critical labels, obtains consent as required by the backend, then collects exactly one organization per application.

Every new SLT and resulting access/refresh family binds the chosen account and one active organization. A later login for another organization does not enlarge an earlier token. The browser uses one account and one organization available to all selected applications. `GET /api/v1/login` accepts the same navigation parameters; GET requests never create consent or tokens.

## Receive individual SLTs

The callback receives a URL-encoded JSON array in `#slts=`:

```json
[
  {"app_id":"briefcase","slt":"...","expires_in":120,"expires_at":"2026-09-12T12:02:00Z","request_id":"..."},
  {"app_id":"dm","slt":"...","expires_in":120,"expires_at":"2026-09-12T12:02:00Z","request_id":"..."}
]
```

```js
const fragment = new URLSearchParams(location.hash.slice(1));
const items = JSON.parse(fragment.get("slts") || "[]");
history.replaceState(null, "", location.pathname + location.search);
// Validate the initiating browser's login state and exact expected app IDs.
// Send each SLT immediately to its own application backend over HTTPS.
```

The fragment is not sent in the callback's HTTP request; callback JavaScript reads it. Avoid third-party scripts on the callback page. Every application server exchanges only its own SLT at `POST /api/v1/app-auth/tokens` with its own Basic credentials. One app's secret cannot exchange another app's token. Completing one exchange does not consume another app's SLT.

Applications never receive IAM credentials, session tokens, passwords, or verification codes. App secrets stay on their corresponding backends. SLTs last two minutes and can be exchanged once. `expires_at` remains the original deadline on idempotent replay. Without `redirect_uri`, IAM displays individually labeled tokens.

Callbacks must be absolute HTTPS URLs (literal loopback HTTP is allowed), at most 2048 characters, and contain no credentials or fragment. Single-app login returns its token in the `slt` query parameter; batch and bundle login use the JSON fragment.

## Direct IAM API

Only a direct IAM Carbon or Silicon credential can read choices and approve consent. Application secrets and application-issued bearers cannot use these endpoints to obtain or enlarge grants.

```http
GET /api/v1/app-auth/batch/organizations?app_ids=briefcase,dm
Authorization: Bearer <direct IAM token>
```

The response is `{ "items": [...] }`. Each item includes app identity, organization choices with existing `authorized` flags, `scopes`, `scope_version`, `consent_required`, and the compatibility field `allow_empty_organization_selection` (always false). Present the current permissions before submitting each app's exact scope set and version:

```http
POST /api/v1/app-auth/batch/short-lived-tokens
Authorization: Bearer <direct IAM token>
Idempotency-Key: <one logical consent>
Content-Type: application/json

{
  "applications": [
    {
      "app_id": "briefcase",
      "org_ids": ["customer"],
      "approved_scopes": ["self.identity.read", "self.profile.read"],
      "scope_version": 1
    },
    {
      "app_id": "dm",
      "org_ids": ["personal"],
      "approved_scopes": ["self.identity.read", "self.profile.read"],
      "scope_version": 1
    }
  ]
}
```

The versions above are examples; use the returned values. Only IAM scopes are included in login consent. Each app obtains separate OBO approval when needed; batch or bundle login grants no OBO access. Changed IAM scope versions require reloading the current scope set and, for critical scopes, fresh consent. Each app requires exactly one selected organization ID. Empty and multiple selections are rejected. New accounts create or join their first organization in IAM before application login.

IAM validates and issues the complete batch in one transaction. If any application, membership, scope set, or version is invalid, no new consent or SLT is committed. Success returns `201` with `{ "items": [...] }` in requested app order. An uncertain response should be retried with the original key and identical body. Replaying never extends expiry.

## Rust client and CLI

The Rust client exposes `auth().batch_login_organizations(...)` and `auth().batch_short_lived_tokens(...)`. Populate every `BatchLoginSelection` with `app_id`, `org_ids`, `approved_scopes`, and the `scope_version` returned by the choices endpoint. The client does not decide consent for the user. See the [Rust login guide](client/login.html).

Start the CLI with a direct IAM session from `iam login` or `iam silicon-login`:

```sh
iam batch-login --app-id 'briefcase' --app-id 'dm'
iam -o json batch-login --app-id 'briefcase,dm' --grant-org customer --approve-scopes
```

Interactive use shows critical IAM permissions when consent is required and asks for one organization. Noninteractive use passes `--grant-org <org>` and requires `--approve-scopes` when critical IAM consent is outstanding. `--all-orgs` is rejected. `--org` is management context and never grants consent. See the [CLI guide](cli/README.md) for command options.

The same flow works in a [testing environment](api/testing-environments.html) with `X-Testing-Environment-Key` and credentials issued inside that environment; use the CLI's `--test` context.
