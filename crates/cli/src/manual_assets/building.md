# Build an IAM application

Start with a stateless Rust library using `silicon-iam-client`; put session
storage and background work in your application daemon, and make your CLI a
client of that library or daemon. IAM's CLI is the first-party credential issuer.
Your app's CLI authenticates using only a short-lived token (SLT).

## Register and log in

1. Sign in with the official IAM CLI and select your owning organization.
2. Register the application in Honeycomb, including a webhook receiver and its
   signing secret. A backend origin is required when publishing OBO endpoints. Store the generated application
   client secret on the backend. Declare exactly the IAM and external scopes
   needed; complete any required scope and webhook review. Follow
   [accepted IAM configuration](HONEYCOMB_INTEGRATION.md).
3. Implement `app iam --json` with the canonical `app_id`, IAM/auth URL, docs,
   source repository and package links. This command must work before login.
4. Implement `app login '<SLT>'`. The user obtains the token using
   `iam login --app-id 'org>app' --grant-org <org>` (or the IAM consent website).
   The **application backend** exchanges the SLT with its client secret via
   `client.oauth().login(...)`; follow the exact working example in
   [Rust application login](client/login.html). Never request SID/STK,
   verified-channel codes or IAM refresh tokens in an application CLI.
5. Store the resulting app session securely and expose
   `app login status --json` with `authenticated` plus nonsecret identity/context.
   Refresh expired sessions and distinguish transport failures from rejected
   credentials. Read current authorization immediately after login; don't wait
   for a webhook to initialize access.

SLTs are short-lived, single-use and bound to an application. These properties
keep a credential intended for one app from becoming a general IAM login. User
consent limits which organizations and fields the application can see. Read
[consent](ORGANIZATION_CONSENT.md) and [permissions](IAM_SCOPES.md) before using
absence of a disclosed field in an authorization decision.

## Build commands and settings

Use noun/verb command paths and put the purpose, typical workflow, arguments
and related commands in each level's `--help`. Bundle instructive usage and
integration docs so an agent can recover without an online documentation host.
Expose structured JSON on discovery, login status and normal operations. Report
specific failures, violated constraints, request IDs and a useful next command.

Use `$SILICON_HOME/.<app-name>` as the default store, with the OS home as fallback.
Keep a stateless Rust library free of implicit credential persistence. Treat
optional `ISI` as additional context where it affects application behavior;
identity and authorization must continue working when it is absent. IAM itself
has no ISI-specific domain behavior and does not attach ISI to credentials.

Offer settings with documented defaults and flag/environment overrides. Package
the CLI as a Honeycomb archive and let Honeycomb manage its installation and
updates. Rust dependencies follow the consuming project's Cargo configuration.
Do not run a second updater or modify dependency lockfiles at runtime.

Use `silicon_iam_client::support::report(message, optional_pr)` to submit an
explicitly requested IAM bug report through authenticated GitHub CLI. It also
exposes `report_body` for previewing that exact content. Applications should
route their own reports to their own repository and encourage a reproducible
fix with an optional PR. No automatic report submission belongs in error handling.

## Verify authorization and isolation

Verify raw signed webhook bytes and the event's identity before updating your
cache. Maintain revocation-aware authorization; OBO proofs bind an exact
request and are consumed once. Follow [webhooks](api/webhooks.html) and
[OBO](api/obo.html).

Create a shared testing environment in Honeycomb. Honeycomb prepares IAM,
imports the accepted app and dependency configuration, and coordinates activation.
Retain its root key privately. Use the same endpoints and the selected testing
environment, rather than a separate imitation API. When your backend receives
the test application secret in the request, select that isolated testing plane
and validate it through IAM. Never mix production and testing credentials,
storage, sessions or webhook envelopes. Follow the complete
[testing workflow](api/testing-environments.html) and
[Rust testing example](client/testing-environments.html).

Install the official CLI to discover and exercise these contracts:

```sh
honeycomb install <configured-iam-app-id>
```

For initial deployment without a catalog, see [direct bootstrap](HONEYCOMB_RELEASE.md).
