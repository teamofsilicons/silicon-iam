# silicon-iam-client

A Rust client for the [Silicon IAM](https://backend.iam.teamofsilicons.com) API:
identity, organization governance, application login, and delegated access.

The public integration surfaces have typed methods here, using the contract's
own shapes. The wire types are generated from `docs/openapi.yaml`, and changes
to that contract produce a reviewable source diff. Platform administration,
provider callbacks, and browser navigations remain outside this crate.

```toml
[dependencies]
silicon-iam-client = "1.1.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Release `1.1.0` speaks HTTP API major `v1` and requires Rust 1.98 or newer.
The crate SemVer and HTTP API major are separate: upgrading the crate within
the 1.x line does not select a different wire major. `Client::new` and
`ClientBuilder::build` perform no network handshake; call
`client.system().negotiate().await?` during startup when you want an upfront
compatibility check. It validates the service identity, ordered version
catalog, highest shared selection, selected-version header/body agreement, and
the required `Vary` header. A `406` becomes `Error::ApiVersionUnsupported`;
an inconsistent success becomes `Error::Decode`. Every request advertises
`v1`.

The service URL must use HTTPS, except for literal `localhost`, `127.0.0.1`,
or `::1` during local development. The builder rejects missing hosts, embedded
credentials, port zero, queries, and fragments. Requests do not follow
redirects, so IAM authority stays on the configured endpoint, and every
response body is capped at 4 MiB. An oversized response becomes
`Error::ResponseTooLarge`.

## Runtime state stays with your application

`Client` does not store sessions, cache API responses, or refresh credentials
behind your back. An expired token produces an error; deciding what to do
about it stays with you, because only your program knows where its credentials
live.

If you want the stateful version — a token store, automatic refresh, a
configured default service — that is the `silicon-iam-cli` crate, which is
built on nothing but this one.

## Automatic crate updates

Automatic dependency maintenance is on by default. Immediately before its
first IAM request, the client compares its compiled version with the newest
stable `silicon-iam-client` release on crates.io. When it finds a newer release
and can locate a `Cargo.toml` from the process working directory, it runs the
equivalent of:

```sh
cargo update --manifest-path /path/to/Cargo.toml \
  -p silicon-iam-client --precise <latest-version>
```

That advances the consuming project's `Cargo.lock`. Rust cannot replace a
library already compiled into a running process, so the current process
finishes on its existing version and the next Cargo build uses the update.
Registry or Cargo failures are best-effort and never fail the IAM request;
inspect `client.update_status()` after the first request to see whether the
client was current, updated, skipped, or could not update.

Disable every check and Cargo invocation in code:

```rust
let client = Client::builder("https://backend.iam.teamofsilicons.com")?
    .auto_update(false)
    .build()?;
```

Or opt out for a deployed process without recompiling it:

```sh
SILICON_IAM_CLIENT_AUTO_UPDATE=false ./your-application
```

If the application starts outside its project directory, point the updater at
the correct manifest with `.update_manifest("/path/to/Cargo.toml")`. If there
is no manifest, the client reports `UpdateStatus::NoCargoProject` and leaves
the installed application alone.

## Your first Application login

```rust
use silicon_iam_client::{Client, Credential, Mutation};

#[tokio::main]
async fn main() -> silicon_iam_client::Result<()> {
    let app_id = "acme>checkout";
    let application = Client::new("https://backend.iam.teamofsilicons.com")?
        .with_credential(Credential::application(app_id, "ask_your_application_secret"));

    // Receive this only from the IAM-hosted login redirect or token screen.
    let slt = "slt_from_iam";
    let tokens = application
        .oauth()
        .login(app_id, slt, &Mutation::new())
        .await?;
    println!("Application session expires in {} seconds", tokens.expires_in);
    Ok(())
}
```

An Application never starts or verifies an OTP challenge. IAM performs that
identity ceremony on its own hosted login surface; the Rust client accepts
only the resulting single-use SLT for a new Application login.

## What the API groups look like

Every group hangs off the client and borrows it, so obtaining one is free:

| Group | Covers |
| --- | --- |
| `client.system()` | Version negotiation, liveness, readiness |
| `client.signup()` | Creating a Carbon |
| `client.auth()` | IAM refresh/logout, step-up, Silicon authentication, and SLT minting; direct Carbon login is CLI-feature-only |
| `client.carbons()` | The signed-in Carbon; sessions; Carbon lookup |
| `client.organizations()` | Organization tenancy and ownership |
| `client.members()` | Members and the directory view of them |
| `client.invitations()` | Inviting Carbons, and joining |
| `client.tags()` | Organization tags |
| `client.trust()` | Advisory trust: default, rules, evaluation |
| `client.governance()` | Approvals, direct role and tag changes, history |
| `client.silicons()` | Silicons, credentials, webhooks |
| `client.applications()` | Applications, secrets, webhooks |
| `client.oauth()` | Short-lived-token exchange, introspection, revocation |
| `client.obo()` | Catalog-bound signing and delegated access between applications |
| `client.sso()` | An organization's SSO configuration |
| `client.environments()` | Testing environments |

Platform administration, the inbound provider webhooks and the browser login
screen are deliberately absent: they belong to the operator, to the provider,
and to the browser.

## Idempotency is explicit

Every mutating route requires an idempotency key, so mutations take a
`Mutation` that carries one. The service binds the key to the caller, the route
and the exact body, then replays the original response for a repeat of the same
request — which only helps if a retry presents the *same* key:

```rust
# use silicon_iam_client::{Client, Mutation, models};
# async fn run(client: &Client, input: &models::OrganizationCreate) -> silicon_iam_client::Result<()> {
let creating = Mutation::new();

let organization = match client.organizations().create(input, &creating).await {
    Ok(organization) => organization,
    // The same `creating` replays the first outcome instead of creating a
    // second organization.
    Err(error) if error.is_retryable() => {
        client.organizations().create(input, &creating).await?
    }
    Err(error) => return Err(error),
};
# let _ = organization;
# Ok(())
# }
```

Routes that change an existing resource take its `version` as an ordinary
argument, so optimistic concurrency cannot be forgotten. Routes that change
authority or reveal a credential also need a step-up assertion, attached with
`Mutation::step_up`.

JSON Merge Patch deliberately distinguishes three states. In generated patch
models, a field typed `Option<Option<T>>` uses `None` to omit the field and
leave it unchanged, `Some(None)` to send JSON `null` and clear it, and
`Some(Some(value))` to replace it. Do not collapse the outer and inner options.

## Signing users in to an application

A login produces one short-lived token, and that token is the only thing your
application ever receives — never a password, never a verification code.

Send someone to `<auth_base_url>/login?app_id=…&redirect_uri=…`; they come back
to your callback with `?slt=…`; you trade it for a session:

```rust
# use silicon_iam_client::{Client, Credential, Mutation};
# async fn run(base: &str, app_id: &str, app_secret: &str, slt: String)
#     -> silicon_iam_client::Result<()> {
let application = Client::new(base)?
    .with_credential(Credential::application(app_id, app_secret));

let tokens = application
    .oauth()
    .login(app_id, &slt, &Mutation::new())
    .await?;
# let _ = tokens;
# Ok(())
# }
```

The token lives two minutes and is good for one exchange. `OAuth::login` has no
OTP or refresh-token input: the SLT is the only credential that can begin an
Application session. Renew an existing session separately with
`OAuth::refresh(app_id, refresh_token, mutation)`.

A Silicon has no browser, and a Carbon that already holds a session should not
have to start another one. `client.auth().short_lived_token(app_id,
&Mutation::new())` requests no new organization context: an unscoped Carbon
bearer remains unscoped, while a bearer already carrying a context retains it.
Use `short_lived_token_in_organization(app_id, Some("acme"),
&Mutation::new())` to
require the caller's active `acme` membership and bind the exchanged
Application token family to that organization. OBO requires the bound form;
an unscoped Application access token cannot issue an OBO proof.

For OBO, hash the exact downstream bytes with
`api::obo::body_sha256`, build one `OboExchangeRequest`, and pass that request,
the discovered audience catalog, and one `Mutation` to
`obo().exchange_signed(...)`. The client selects the registered path, uses the
same Application secret for Basic authentication and HMAC, and signs a fresh
timestamp. An immediate uncertain retry reuses the request and `Mutation` but
gets a new timestamp/signature; restoring an old timestamp can fall outside the
60-second signature window.

## Refresh, introspection, revocation, and logout

Refresh one Application session with the same Application Basic client. Keep
one refresh in flight per family and persist the `Mutation` key before sending:

```rust
# use silicon_iam_client::{Client, Mutation};
# async fn refresh(application: &Client, app_id: &str, old: &str) -> silicon_iam_client::Result<()> {
let refreshing = Mutation::new();
let key_to_persist = refreshing.key().as_str().to_owned();
let replacement = application.oauth().refresh(app_id, old, &refreshing).await?;
// Atomically replace `old` with `replacement`; retain `key_to_persist`
// until the operation is committed.
# let _ = (replacement, key_to_persist);
# Ok(())
# }
```

Reuse of a consumed refresh token under a new key revokes that Application
refresh family and its related access authority. It does **not** revoke the
parent IAM session, other devices, or unrelated Applications. Recover an
uncertain request with
`Mutation::with_key(IdempotencyKey::parse(saved_key)?)` and the exact same
input. The 1.1.0 client does not expose the `Idempotency-Replayed` response
header.

Tokens are opaque. Ask for their current state and optional exact organization
context with `oauth().introspect(&TokenIntrospectionRequest, Some("acme"))`.
A well-formed organization mismatch, unknown token, expiry, or revocation
returns `active: false`; malformed organization context is an API error.
Revoke with `oauth().revoke(&OAuthRevocationRequest, &Mutation)`: an access
token revokes only itself, while a refresh token revokes its family. Unknown
tokens deliberately succeed.

Application-triggered global logout is a different operation. Build a bearer
client from the Carbon Application access token and call
`auth().logout(&LogoutRequest { mode: None }, &Mutation)`. If the token's client
and audience are that Application, IAM revokes the parent IAM session and all
authority bound to it. This form cannot request account-wide `all_sessions`.

## Applications, discovery, and secret rotation

Application creation takes a local handle and an owning organization. IAM
returns the canonical public identifier `{org_id}>{handle}`; use that canonical
value for every later login, credential, path, discovery, and OBO call. The
required `base_url` is the pathless application-backend origin without a
trailing slash, such as `https://billing.example`. It is not a login redirect
and IAM does not call it automatically.

```rust
# use silicon_iam_client::{Client, Mutation, models};
# async fn create(client: &Client) -> silicon_iam_client::Result<()> {
let created = client.applications().create(
    &models::ApplicationCreate {
        app_id: "billing".to_owned(),
        org_id: "acme".to_owned(),
        app_name: Some("Billing".to_owned()),
        app_logo: None,
        webhook_url: "https://billing.example/hooks/iam".to_owned(),
        webhook_secret: "replace-with-at-least-32-random-characters".to_owned(),
        base_url: "https://billing.example".to_owned(),
        obo_endpoints: None,
    },
    &Mutation::new(),
).await?;
// Persist created.app_secret; IAM generated no webhook secret.
# Ok(())
# }
```

An Application authenticating with `Credential::application` can discover any
verified Application's base URL, even across organizations:

```rust
# use silicon_iam_client::{Client, Credential};
# async fn discover(base: &str, caller_secret: &str) -> silicon_iam_client::Result<()> {
let caller = Client::new(base)?.with_credential(Credential::application(
    "acme>checkout",
    caller_secret,
));
let billing = caller
    .applications()
    .discover_base_url("other>billing")
    .await?;
println!("{}", billing.base_url);
# Ok(())
# }
```

Client and webhook signing credentials rotate independently. Both operations
take the current Application `version`, an idempotency key, and a
verified-channel step-up assertion. The Application supplies its own webhook
successor; IAM generates only client secrets:

```rust
# use silicon_iam_client::{Client, Mutation, models};
# async fn rotate(client: &Client, step_up: &str) -> silicon_iam_client::Result<()> {
let app = client.applications().get("acme>checkout").await?;
let mutation = Mutation::new().step_up(step_up);
let rotated = client
    .applications()
    .rotate_webhook_secret(
        &app.app_id,
        app.version,
        &models::ApplicationWebhookSecretRotate {
            webhook_secret: "replace-with-32-or-more-random-characters".to_owned(),
        },
        &mutation,
    )
    .await?;
assert_eq!(rotated.webhook_secret_version, app.webhook.secret_version + 1);
# Ok(())
# }
```

The webhook rotation assertion uses action
`application.webhook_secret.rotate`; client-secret rotation uses
`application.client_secret.rotate`. A webhook URL change is a separate
operation and reuses a test-owned or production signing secret unless its
request explicitly supplies a new one.

## Organization listing and SSO

`organizations().list(&paging)` returns organizations where the caller has an
active membership. Use `list_with_status(Some("removed"), &paging)` for the
caller's removed memberships. That query value describes **membership** status;
the `status` on each returned `Organization` still describes the organization
itself (`active` or `disabled`).

SSO starts locked until a platform administrator grants the organization an
entitlement. A Carbon owner or admin with `sso.manage` can inspect it, obtain a
five-minute WorkOS setup link, and test the active connection:

```rust
# use silicon_iam_client::{Client, Mutation};
# async fn sso(client: &Client) -> silicon_iam_client::Result<()> {
let configuration = client.sso().get("acme").await?;
let setup = client.sso().setup_link("acme", &Mutation::new()).await?;
let tested = client.sso().test("acme", &Mutation::new()).await?;
# let _ = (configuration, setup, tested);
# Ok(())
# }
```

Disabling SSO additionally needs the current configuration `version` and a
verified-channel step-up assertion for `organization.sso_change` bound to the
organization's internal UUID:

```rust
# use silicon_iam_client::{Client, Mutation};
# async fn disable(client: &Client, version: i64, step_up: &str) -> silicon_iam_client::Result<()> {
client.sso().disable(
    "acme",
    version,
    &Mutation::new().step_up(step_up),
).await?;
# Ok(())
# }
```

The browser authorization and callback redirects are intentionally not client
methods. SSO never creates a Carbon: the person signs up normally first, then
begins SSO while authenticated in the same bound browser session.

## Testing environments

An environment is the same API against a separate database, starting empty.
The lifecycle is controlled from production. A successful creation returns the
public UUID and the 32-character root key:

```rust
# use silicon_iam_client::{Client, Mutation, models};
# async fn create(production: &Client) -> silicon_iam_client::Result<()> {
let created = production.environments().create(
    "acme",
    &models::TestingEnvironmentCreate {
        name: "checkout-e2e".to_owned(),
        description: Some("CI proof run".to_owned()),
    },
    &Mutation::new(),
).await?;

// Store created.id as the safe selector and created.key in a secret store.
# let _ = created;
# Ok(())
# }
```

Move a client onto that environment and every ordinary method uses the same
route against isolated test data:

```rust
# use silicon_iam_client::{Client, EnvironmentKey};
# async fn run(client: &Client, key: &str) -> silicon_iam_client::Result<()> {
let sandbox = client.with_environment(EnvironmentKey::new(key)?);
let organizations = sandbox.organizations().list(&Default::default()).await?;
# let _ = organizations;
# Ok(())
# }
```

The root key selects the database plane; it does not replace endpoint
authentication. A protected call still needs the bearer or Application Basic
credential issued inside that environment. Email and SMS delivery are
suppressed, and signup, login, invitation and step-up verification accept the
fixed code `000000`.

Credentials do not cross the boundary in either direction: production access
and refresh tokens, short-lived tokens, STKs, Application secrets, sessions,
and OBO proofs are refused in a test environment, and test credentials are
refused in production. IAM does not currently expose a caller API-key
credential; a future API-key surface must retain this same plane binding. Keep
one credential store per environment or key it by the environment UUID.

### Create or import a test Application

Creating a new test Application uses the ordinary method on the plane-selected client:

```rust
# use silicon_iam_client::{Client, Mutation, models};
# async fn create_app(sandbox: &Client) -> silicon_iam_client::Result<()> {
let created = sandbox.applications().create(
    &models::ApplicationCreate {
        app_id: "checkout".to_owned(),
        org_id: "acme".to_owned(),
        app_name: Some("Checkout".to_owned()),
        app_logo: None,
        webhook_url: "https://hooks.example.test/iam".to_owned(),
        webhook_secret: "test-webhook-secret-with-32-characters".to_owned(),
        base_url: "http://127.0.0.1:4100".to_owned(),
        obo_endpoints: None,
    },
    &Mutation::new(),
).await?;
assert_eq!(created.application.app_id, "acme>checkout");
# Ok(())
# }
```

The local handle is qualified with the owning organization. A newly created
test application cannot claim a canonical ID that already exists in
production.

Import copies a production Application into the selected environment. It can
also create the corresponding test organization and make the authenticated
test Carbon its owner. The response returns a fresh test-only Application
secret, but only confirms that the production webhook secret was inherited;
it never reveals that secret:

```rust
# use silicon_iam_client::{Client, Mutation};
# async fn import(sandbox: &Client) -> silicon_iam_client::Result<()> {
let imported = sandbox
    .applications()
    .import_from_production("google>drive", &Mutation::new())
    .await?;
assert!(imported.webhook_secret_inherited);
// Persist imported.app_secret now. The replay window is ten minutes.
# Ok(())
# }
```

`import_from_production` refuses locally when the client has no environment
key, before any request is sent.

### Discover a base URL in the correct plane

Any authenticated Application may discover any other verified Application,
including one outside its organization. Build the caller with its own Basic
credential. For a test lookup, keep the environment key on the same client so
both caller and target resolve in that environment:

```rust
# use silicon_iam_client::{Client, Credential, EnvironmentKey};
# async fn discover(base: &str, key: &str, secret: &str) -> silicon_iam_client::Result<()> {
let caller = Client::new(base)?
    .with_environment(EnvironmentKey::new(key)?)
    .with_credential(Credential::application("acme>checkout", secret));
let target = caller
    .applications()
    .discover_base_url("google>drive")
    .await?;
println!("{}", target.base_url);
# Ok(())
# }
```

Test webhook delivery is real. Its signed JSON body is wrapped as
`{"test": {"testing_key": "…", "metadata": {…}, "data": {…}}}` rather
than using the production top-level `metadata` and `data`. Treat
`testing_key` as the root credential it is: never log it, persist it with an
event record, or forward it beyond the dedicated test receiver. Verify the
signature over the exact body bytes before reading the envelope.

## Errors

`Error::Api` carries the service's envelope, whose `code` is the stable thing to
match on. `Error::RateLimited` is separate because it is the one failure with a
mechanical remedy — wait the stated interval and repeat. `Error::Transport`
means the request never reached a response, so the outcome is genuinely unknown;
retry it with the original `Mutation` rather than a new one.

```rust
# use silicon_iam_client::Error;
# fn handle(error: Error) {
if let Some(api) = error.api() {
    if api.is_version_conflict() {
        // Someone changed it first: re-read, then decide.
    } else if api.requires_step_up() {
        // Obtain an assertion and attach it to the mutation.
    }
}
# }
```

## Testing against a real service

The authoritative integration proof is the manual CLI walkthrough in the
[CLI guide](https://github.com/teamofsilicons/silicon-iam/tree/main/docs/cli#end-to-end-application-proof-in-a-test-environment).
Run it against an isolated testing environment and inspect each result. At a
minimum, prove:

- Carbon signup and login use the fixed test-plane code, while an Application
  receives only the resulting SLT; prove both an ordinary unscoped SLT and an
  organization-bound SLT minted with `short_lived_token_in_organization`;
- token exchange, refresh, current introspection, refresh-family revocation,
  and post-revocation `active: false` all agree;
- an OBO proof made from the organization-bound access token verifies exactly
  once for the registered method, path and exact body, fails for every
  mismatched binding, and cannot be issued from the unscoped token;
- valid webhook bytes verify, while a changed byte, stale timestamp, wrong
  secret version, duplicate security header, or wrong environment key fails;
- production credentials fail in the test plane and test credentials fail in
  production;
- SSO entitlement, setup-link, connection test and step-up-protected disable
  behave as documented when SSO is in scope.

Keep the environment UUID as metadata and its root key in secret storage. Do
not substitute mock-only routes: the test plane intentionally uses the same API
paths and authorization rules as production.

For crate-development coverage, the repository also contains ignored live
integration tests. Point them at a disposable running instance:

```sh
SILICON_IAM_LIVE_URL=http://127.0.0.1:8080 \
  cargo test -p silicon-iam-client --test live -- --ignored --test-threads=1
```

## Regenerating the wire types

After changing `docs/openapi.yaml`:

```sh
ruby scripts/generate-client-models.rb
```

The output is committed as ordinary source, so a contract change shows up as a
reviewable diff.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.

Copyright 2026 Team of Silicons.
