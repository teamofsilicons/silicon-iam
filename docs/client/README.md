# silicon-iam-client

A Rust client for the [Silicon IAM](https://backend.iam.teamofsilicons.com) API:
identity, organization governance, application login, and delegated access.

Everything a caller can do over HTTP has a method here, typed with the
contract's own shapes. The wire types are generated from `docs/openapi.yaml`,
so they cannot drift from the service.

```toml
[dependencies]
silicon-iam-client = "1.0.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Stateless by construction

`Client` holds configuration and nothing else. It does not write to disk, does
not cache responses, and does not refresh credentials behind your back. An
expired token produces an error; deciding what to do about it stays with you,
because only your program knows where its credentials live.

If you want the stateful version — a token store, automatic refresh, a
configured default service — that is the `silicon-iam-cli` crate, which is
built on nothing but this one.

## A first call

```rust
use silicon_iam_client::{Client, Credential, Mutation, models};

#[tokio::main]
async fn main() -> silicon_iam_client::Result<()> {
    let anonymous = Client::new("https://backend.iam.teamofsilicons.com")?;

    let challenge = anonymous
        .auth()
        .start_login(
            &models::LoginChallengeCreate {
                email: Some("founder@example.com".to_owned()),
                phone_number: None,
                carbon_id: None,
            },
            &Mutation::new(),
        )
        .await?;

    // The code arrives by email or SMS.
    let tokens = anonymous
        .auth()
        .verify_login(challenge.session_id, "123456", &Mutation::new())
        .await?;

    let client = anonymous.with_credential(Credential::bearer(tokens.access_token));
    println!("signed in as {}", client.carbons().me().await?.carbon_id);
    Ok(())
}
```

## What the API groups look like

Every group hangs off the client and borrows it, so obtaining one is free:

| Group | Covers |
| --- | --- |
| `client.system()` | Version negotiation, liveness, readiness |
| `client.signup()` | Creating a Carbon |
| `client.auth()` | Login, refresh, logout, step-up, Silicon tokens |
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
| `client.obo()` | Delegated access between applications |
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

## Signing users in to an application

A login produces one short-lived token, and that token is the only thing your
application ever receives — never a password, never a verification code.

Send someone to `<auth_base_url>/login?app_id=…&redirect_uri=…`; they come back
to your callback with `?slt=…`; you trade it for a session:

```rust
# use silicon_iam_client::{Client, Credential, Mutation, models};
# async fn run(base: &str, app_id: &str, app_secret: &str, slt: String)
#     -> silicon_iam_client::Result<()> {
let application = Client::new(base)?
    .with_credential(Credential::application(app_id, app_secret));

let tokens = application
    .oauth()
    .token(
        &models::ApplicationTokenRequest {
            app_id: app_id.to_owned(),
            slt: Some(slt),
            refresh_token: None,
        },
        &Mutation::new(),
    )
    .await?;
# let _ = tokens;
# Ok(())
# }
```

The token lives two minutes and is good for one exchange. Renewing later is the
same call with `refresh_token` set instead of `slt`.

A Silicon has no browser, and a Carbon that already holds a session should not
have to start another one — either asks for the token directly with
`client.auth().short_lived_token(app_id, &Mutation::new())`.

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

Creating a new test Application uses the ordinary method on the planed client:

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

The integration tests are ignored by default. Point them at a running instance:

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
