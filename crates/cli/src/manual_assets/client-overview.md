# Rust client capabilities and design

[`silicon-iam-client`](https://crates.io/crates/silicon-iam-client) is the official Rust client for Silicon IAM. It exposes the HTTP v1 resources with generated wire models, explicit credentials, idempotency keys and ETags, plus local webhook verification.

## What it covers

| Area | Client groups |
| --- | --- |
| **Identity and IAM sessions** | `signup()`, `auth()`, and `carbons()` |
| **Organizations** | `organizations()`, `members()`, `invitations()`, `tags()`, `trust()`, `governance()`, and `sso()` |
| **Silicons and Applications** | `silicons()`, `applications()`, `oauth()`, and catalog-bound OBO signing through `obo()` |
| **Operations** | `system()` and `environments()` |
| **Inbound webhooks** | `WebhookVerifier` authenticates exact bytes, timestamp, event ID and secret version before parsing. |

The crate is not restricted to an Application credential. Build an anonymous client for public routes, clone it with an IAM bearer for Carbon or Silicon administration, or clone it with an Application Basic credential for OAuth, discovery and OBO. The `cli-session` feature that starts and verifies direct Carbon login challenges is reserved for the official CLI; normal Application integrations begin login only with an SLT.

## What it deliberately does not cover

Platform-administrator routes, inbound provider webhooks and the browser-hosted login/SSO redirects are absent. Those belong to the IAM operator, provider, and browser. The client also does not store sessions, refresh credentials automatically, cache authorization, or choose a retry policy for your application.

## The design rule

Inputs with security meaning stay visible at the call site. A mutating method takes a `Mutation`; an optimistic update takes the current resource version; a privileged mutation takes a step-up assertion; and a test-plane call carries an `EnvironmentKey`. That makes accidental omission a compile-time or service error instead of hidden client state.

JSON Merge Patch has three states. For generated fields typed `Option<Option<T>>`, `None` omits the field and leaves it unchanged, `Some(None)` sends JSON `null` and clears it, and `Some(Some(value))` replaces it.

## Actual request behavior

- Every API request advertises `v1`; compatibility negotiation is available through `client.system().negotiate()` but is not run by the constructor. The explicit call validates the service, catalog, highest shared selection, selected header/body agreement, and `Vary`.

- The HTTP timeout defaults to 30 seconds and can be changed on `ClientBuilder`.

- Each method sends once. After an uncertain mutation, the caller decides whether to retry and must reuse the original `Mutation`.

- `Error::Api` retains the service envelope and request ID. `Error::RateLimited` additionally exposes the parsed delay and rate-limit counts.

- Credential wrapper types redact secrets from `Debug`. Successful response models may contain tokens or one-time secrets, so do not log those models.

## Organization SSO

`client.sso()` exposes `get`, `setup_link`, `test`, and `disable`. Setup links live five minutes. Disable takes the current SSO configuration version and a `Mutation` carrying a verified-channel `organization.sso_change` assertion bound to the organization's internal UUID. The browser authorization and callback remain hosted IAM flows, not SDK methods, and SSO never creates a Carbon account.

## Where to go next

Start with Connecting (`iam docs client/connecting`), then sign users in with an SLT (`iam docs client/login`), manage tokens (`iam docs client/tokens`), delegate between Applications (`iam docs client/obo`), and verify webhooks (`iam docs client/webhooks`). Use a testing environment (`iam docs client/testing-environments`) to prove both successful and rejected cross-plane flows before production. The crate README contains the complete group index and organization/SSO examples.
