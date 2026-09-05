# Rust client testing environment workflow

The Rust client uses one switch for an entire isolated IAM world: `Client::with_environment`. Every ordinary API group then keeps the same methods and paths while the client adds the environment root key to each request.

## Create on production, execute in the test plane

```
use silicon_iam_client::{Client, EnvironmentKey, Mutation, models};

// `production` carries the creator's production bearer.
let created = production.environments().create(
    "acme",
    &models::TestingEnvironmentCreate {
        name: "checkout-e2e".to_owned(),
        description: Some("CI application proof".to_owned()),
    },
    &Mutation::new(),
).await?;

// Store created.id as normal metadata. Put created.key in a secret store.
let sandbox = Client::new("https://backend.iam.teamofsilicons.com")?
    .with_environment(EnvironmentKey::new(created.key)?);
```

`EnvironmentKey` accepts only the exact 32-character alphanumeric wire form and redacts itself from `Debug`. The SDK stores no IAM credentials, so retaining the public UUID-to-key mapping is your program's responsibility. Do not use the UUID as a credential and do not expose the key as a selector.

**Plane selection and actor authentication are independent.** `sandbox` above is anonymous. Bootstrap test identities with the CLI or raw IAM control-plane API, then attach the resulting test bearer with `with_credential`. An Application client never runs that OTP ceremony. Give it only the environment's Application Basic credential and the SLT returned by IAM.

## Bootstrap the empty environment

Use the CLI or raw control-plane API to run the normal signup and IAM-session login sequence. Email and SMS are not sent; pass `000000` to each verification call. Keep the returned control-plane tokens under the environment UUID, never in your production token slot. When testing the Application itself, complete the IAM-hosted Application login and pass only its SLT to `OAuth::login`.

From there, attach the access token and create organizations, tags, Silicons, invitations, and governance state with the same client methods used in production. Expiry, failed-attempt cooldowns, idempotency, ETags, step-up, and authorization are still real; only delivery and the fixed verification code differ.

## Create a test-only Application

```
use silicon_iam_client::{Credential, Mutation, models};

let carbon = sandbox.with_credential(Credential::bearer(test_access_token));
let created_app = carbon.applications().create(
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

assert_eq!(created_app.application.app_id, "acme>checkout");
// Store created_app.app_secret now; the webhook secret was caller-supplied.
```

The create input uses a local handle; every returned and later Application ID is canonical `{org_id}>{handle}`. A test-only creation cannot claim a canonical ID that already exists in production.

## Import a production Application

```
let imported = carbon.applications()
    .import_from_production("google>drive", &Mutation::new())
    .await?;

assert!(imported.webhook_secret_inherited);
store_test_secret(imported.app_secret);
// No production signing secret exists anywhere in this response.
```

The import method fails locally when the client has no environment key. On success IAM copies the production canonical ID, base URL, webhook URL, and OBO registry. It creates the test organization with the requesting test Carbon as owner when necessary and returns a fresh test-only client secret. Its no-store response can be recovered for ten minutes only by repeating the exact request with the same `Mutation`.

The production webhook secret is inherited but not revealed. To point the import at a dedicated test receiver, call `replace_webhook` with a caller-chosen `webhook_secret`. It is required for that first replacement. The v1 response echoes it as `webhook_signing_secret`; ordinary replacements may omit the secret and reuse the current key. Use `rotate_webhook_secret` with another caller-chosen secret for a later rotation.

## Discover a base URL

```
let app = sandbox.with_credential(Credential::application(
    "acme>checkout",
    test_app_secret,
));

let drive = app.applications()
    .discover_base_url("google>drive")
    .await?;
assert_eq!(drive.app_id, "google>drive");
```

Any Application may discover any verified target, even across organizations. With an environment key on the client, requester and target both resolve only there. IAM will not use a production credential or fall through to a production target. OBO discovery remains a separate, same-organization operation.

## Receive a test webhook

```
{
  "test": {
    "testing_key": "…",
    "metadata": {
      "spec_version": "1.0",
      "event_id": "…",
      "event_type": "organization.membership.created.v1",
      "occurred_at": "…",
      "organization_id": "…",
      "aggregate": { "type": "membership", "id": "…", "version": 1 }
    },
    "data": {}
  }
}
```

Verify the signature over the exact raw outer bytes first. Then detect `test`, compare `testing_key` to the expected secret without timing leakage, route to that isolated run, deduplicate on `metadata.event_id`, and order on `metadata.aggregate.version`. Redact the key before logging and do not persist it in the event table.

```
let verified = webhook_verifier.verify(&headers, &body)?;
verified.verify_testing_environment(&environment_key)?;

// The SDK removes the root key and normalizes metadata/data after verification.
let event_id = verified.event_id();
let event = verified.event();
```

## Proof checklist

1. Assert the environment begins empty.

2. Use control-plane tooling to complete both-contact signup and IAM login with `000000`.

3. Create or import the Application and persist every one-time test secret.

4. Mint the SLT with `short_lived_token_in_organization`, give the Application client only that SLT, complete `OAuth::login`, and introspect it with the matching organization in the same plane. Use an unscoped Carbon bearer and `short_lived_token` separately when proving an ordinary non-OBO login.

5. Prove production credentials fail inside the environment and test credentials fail without it.

6. Verify and deduplicate a wrapped webhook; run OBO exchange/verification with the organization-bound access token, and prove an unscoped access token is refused.

7. Call `clean_current` with the key when the run finishes, or retire it from production.

Never construct a second set of test endpoint paths. If a test can pass only through a mock-only route, it is not proving the production integration. The [manual CLI walkthrough](https://github.com/teamofsilicons/silicon-iam/tree/main/docs/cli#end-to-end-application-proof-in-a-test-environment) exercises this sequence and lists the negative cases to verify before production.
