# Configure the Rust client and credentials

Build one client for an IAM service URL and reuse it. Construction validates local configuration and creates the HTTP pool; it does not contact IAM or negotiate a version until you make a request.

## Install

The package name uses a hyphen; Rust imports it with an underscore.

```
[dependencies]
silicon-iam-client = "1.2.0"
```

View releases and dependency metadata on [the `silicon-iam-client` package page](https://crates.io/crates/silicon-iam-client). Version `1.2.0` speaks HTTP API major `v1` and requires Rust 1.98 or newer. The crate's SemVer and the HTTP API major are separate version lines: upgrading the crate does not select a different API major.

## Choose the credential for the route

A client starts anonymous. Clone it with the credential that the route requires; cloning is cheap and shares the connection pool. Secrets are redacted from `Debug`.

```
use silicon_iam_client::{Client, Credential};

let iam = Client::builder("https://backend.iam.teamofsilicons.com")?
    .user_agent("checkout/2.3.0")
    .build()?;

let signed_in = iam.with_credential(Credential::bearer(iam_access_token));
let application = iam.with_credential(Credential::application(
    "acme>checkout",
    application_secret,
));
```

| Credential | Use it for |
| --- | --- |
| `Credential::Anonymous` | Public system routes and the beginning of signup. Direct IAM login methods are available only to the CLI feature. |
| `Credential::bearer(...)` | Carbon or Silicon IAM routes after IAM authentication, and an Application-triggered logout using a Carbon Application access token. |
| `Credential::application(app_id, secret)` | Application token exchange, refresh, introspection, revocation, discovery and OBO. |

Application credentials are the canonical organization-qualified ID, such as `acme>checkout`, plus the generated client secret. The webhook signing secret is a separate, caller-chosen credential and cannot authenticate API requests.

## API compatibility

Every request advertises the single major this release implements:

```
Silicon-IAM-Supported-API-Versions: v1
```

To check compatibility at startup, call the unversioned negotiation endpoint explicitly before serving traffic:

```
let negotiated = iam.system().negotiate().await?;
assert_eq!(negotiated.selected_api_version, silicon_iam_client::API_VERSION);
```

A service with no shared version produces `Error::ApiVersionUnsupported`. `Client::new` and `ClientBuilder::build` do not perform this network check automatically. `system().negotiate()` fails closed unless the response identifies Silicon IAM, carries a valid ordered version catalog, selects the highest shared version, agrees between its selected-version header and body, and names the offered-version header in `Vary`. An inconsistent successful response produces `Error::Decode`.

## Choosing the IAM service URL

Supply the IAM service URL explicitly; the crate has no implicit default. HTTPS is required except for `localhost` and literal loopback IP addresses (including `127.0.0.1` and IPv6 `[::1]`) for a local IAM runtime. The builder rejects a missing host, embedded username or password, port zero, query, or fragment. A missing trailing slash is normalized.

```
use std::time::Duration;

let iam = Client::builder("https://iam.staging.example")?
    .timeout(Duration::from_secs(15))
    .auto_update(false)
    .build()?;
```

This is the IAM service URL, not an Application's registered `base_url`. Application base URLs follow the stricter pathless-origin rule documented in Applications (`iam docs api/applications`).

API requests never follow redirects. A redirect is a service error instead of an opportunity to forward bearer, Basic, testing-environment, or step-up authority to another location. Every response body, including an error body without a trustworthy `Content-Length`, is streamed only up to 4 MiB; crossing that fixed bound returns `Error::ResponseTooLarge`.

## Lifetime and request behavior

Keep and clone the client instead of rebuilding it per request. Requests have a 30-second timeout by default and are sent once. The crate does not automatically retry, refresh credentials, retain sessions, or cache responses. Your application owns that state and must reuse the same `Mutation` after an uncertain mutating request. A decode failure or oversized response can happen after IAM applied a mutation, so preserve its key even though neither error is automatically classified as retryable.
