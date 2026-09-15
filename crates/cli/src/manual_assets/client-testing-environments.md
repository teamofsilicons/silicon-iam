# Rust client testing environment workflow

**Honeycomb management:** Production application editing, reviews, bundles and shared test lifecycle operations are managed by Honeycomb. See the [service integration contract](../HONEYCOMB_INTEGRATION.md). The legacy management examples below apply only before that integration is provisioned; runtime authentication and isolated test APIs remain available.

The Rust client uses one switch for an entire isolated IAM world: `Client::with_environment`. Every ordinary API group then keeps the same methods and paths while the client adds the environment root key to each request.

## Connect an Application with its test secret alone

After IAM imports or creates the test Application, a service such as Briefcase can select its environment without retaining the IAM root key or registering a pairing.

```
let application = Client::new("https://backend.iam.teamofsilicons.com")?
    .with_testing_application(&app_id, &app_secret)?
    .with_credential(Credential::application(&app_id, &app_secret));
let context = application.applications().testing_context().await?;
let tokens = application.oauth().login(&app_id, "test-user", &Mutation::new()).await?;
let actor = application.with_credential(Credential::bearer(tokens.access_token));
let me = actor.application_reads().me().await?;
```

The SDK sends `X-Testing-Application: Basic …` separately from actor Authorization. IAM verifies the full application credential and returns current metadata in `context.environment`. Scoped OAuth reads retain their normal audience and scope checks. This selector cannot bootstrap identities, issue direct IAM sessions, or manage the environment. Use IAM's root selection and authorized control-plane identity for those operations. Production secrets, inactive environments, mixed selectors, and mismatched application tokens fail closed.

Application secret rotation needs no service pairing update. Environment root rotation leaves application selection usable. IAM clean removes the old applications and selectors; reimport them and use the new secret. Services should track `cleaned_at` to clear their old data before accepting a reinitialized world. The context also contains a SHA-256 `webhook_key_digest` for matching an already signature-verified IAM webhook without retaining root authority.

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

Use the CLI or raw control-plane API to run the normal signup and IAM-session login sequence. Email and SMS are not sent; pass `000000` to each verification call. Keep the returned control-plane tokens under the environment UUID, never in your production token slot. When testing the Application itself, pass an IAM-issued test SLT or an existing Carbon/Silicon ID (such as `alice` or `worker:tos`) to `OAuth::login` using the paired environment key and test Application secret. Actor-ID login selects current active organizations and approved Application scopes. Production requires an issued SLT.

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
        app_scope: None,
        webhook_scope: None,
        obo_review_message: None,
        testing_idle_days: Some(30),
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

The production webhook secret is inherited but not revealed. A testing `replace_webhook` call installs a supplied test-only `webhook_secret`, or generates one when omitted. Store `webhook_signing_secret` from the response. Use `rotate_webhook_secret` with an explicit successor for a later rotation.

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

Any Application may discover any verified target, even across organizations. With an environment key on the client, requester and target both resolve only there. IAM will not use a production credential or fall through to a production target. OBO discovery remains a separate, scope-authorized operation across application-owning organizations.

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

4. Mint the SLT with explicit `scope_version`, `approved_scopes`, and `org_ids`, give the Application client only that SLT, complete `OAuth::login`, and introspect it with the matching organization in the same plane. Use `short_lived_token_for_organizations` with explicit selections; test selected and unselected organizations separately.

5. Prove production credentials fail inside the environment and test credentials fail without it.

6. Verify and deduplicate a wrapped webhook; run OBO exchange/verification with the organization-bound access token, and prove a token without the calling app's organization in its selection is refused.

7. Call `clean_current` with the key when the run finishes, or retire it from production.

Never construct a second set of test endpoint paths. If a test can pass only through a mock-only route, it is not proving the production integration. The [manual CLI walkthrough](https://docs.iam.teamofsilicons.com/cli#end-to-end-application-proof-in-a-test-environment) exercises this sequence and lists the negative cases to verify before production.

## Provision testing from your application

Applications support test mode by default. Call `applications().create_testing_environment(&ApplicationTestingEnvironmentCreate, &mutation)` using the production application's credential. Supply a name and optional description. An optional valid `iam_test_key` attaches to that environment; an invalid provided key fails instead of creating another environment. Without a key, IAM creates a new environment.

IAM imports the caller plus every transitive external dependency into the same test layer. The result includes the environment ID, IAM key, caller's new test app secret, and dependency IDs. Only IAM handles dependency credentials. Use `applications().testing_environments` to list active environments for the application and its organization.

**A received app_secret indicates test mode.** If a request to your application includes `app_secret` in the request itself, it is using the application testing protocol. Validate the secret with IAM, resolve its IAM test environment, and use only that environment's isolated application data. Every downstream dependency shares that same IAM environment. Never route data from an unauthenticated test flag.

Use the ordinary SDK methods with `with_environment(EnvironmentKey::new(key)?)` and the test application credential. Exercise login consent, token exchange, cross-app OBO, webhooks, invalid keys, and production/test credential rejection. An inactive application test environment expires after 30 days by default; configure `testing_idle_days` on the app.

## Manage from your application server

A client authenticated with the production app credential can use every `environments()` lifecycle method for environments that application created. Dependency membership alone does not grant this authority.

```
let production_app = Client::new("https://backend.iam.teamofsilicons.com")?
    .with_credential(Credential::application(app_id, production_app_secret));
let environments = production_app.applications()
    .testing_environments(Some("all"), &silicon_iam_client::Paging::new()).await?;
// Check can_manage before showing lifecycle controls.
let environment = production_app.environments().get(&org_id, environment_id).await?;
let key = production_app.environments().key(&org_id, environment_id).await?;
// update(org_id, environment_id, version, patch, mutation)
// rotate_key(org_id, environment_id, mutation)
// clean(org_id, environment_id, mutation)
// delete(org_id, environment_id, mutation)
// restore(org_id, environment_id, mutation)
```

## Validate a test-view session

```
let test_app = Client::new("https://backend.iam.teamofsilicons.com")?
    .with_environment(EnvironmentKey::new(iam_test_key)?)
    .with_credential(Credential::application(expected_app_id, test_app_secret));
let context = test_app.applications().testing_context().await?;
// Only after successful authentication, select your own isolated storage
// using context.environment_id. Keep test credentials on your server.
// Use test_app for later IAM calls; never fall back to a production client.
```

IAM’s context endpoint returns only the authenticated application’s test configuration. User data still requires a test user’s login and authorization. Cleaning removes test apps and their credentials; rotation invalidates the old environment key; deletion makes the environment unavailable until recovery.
