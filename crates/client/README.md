# silicon-iam-client

A Rust client for the [Silicon IAM](https://backend.iam.teamofsilicons.com) API:
identity, organization governance, application login, and delegated access.

Everything a caller can do over HTTP has a method here, typed with the
contract's own shapes. The wire types are generated from `docs/openapi.yaml`,
so they cannot drift from the service.

```toml
[dependencies]
silicon-iam-client = "0.1"
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
| `client.applications()` | Applications, secrets, redirect URIs, webhooks |
| `client.oauth()` | Token exchange, introspection, revocation |
| `client.obo()` | Delegated access between applications |
| `client.sso()` | An organization's SSO configuration |
| `client.environments()` | Testing environments |

Platform administration, the inbound provider webhooks and the browser consent
screens are deliberately absent: they belong to the operator, to the provider,
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

## Testing environments

An environment is the same API against a separate database, starting empty.
Move a client onto one and every other method works unchanged:

```rust
# use silicon_iam_client::{Client, EnvironmentKey};
# async fn run(client: &Client, key: &str) -> silicon_iam_client::Result<()> {
let sandbox = client.with_environment(EnvironmentKey::new(key)?);
let organizations = sandbox.organizations().list(&Default::default()).await?;
# let _ = organizations;
# Ok(())
# }
```

Environments deliver no email, SMS or webhooks, and their verification steps
accept the fixed code `000000`. Credentials do not cross the boundary in either
direction: a production token is refused inside an environment, and an
environment's token is refused outside it.

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
