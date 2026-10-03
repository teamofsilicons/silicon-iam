# Rust client app-to-app verification

Use `client.ata()` when one application acts with another application's authority. ATA proof identifies the originating application and permits only the reviewed recipient endpoints. It carries no Carbon or Silicon identity and never becomes OBO authority later in a chain.

## Configure endpoints and a verification

Each receiving app configures its `ata_endpoints` in Honeycomb. Give every action a stable local ID, a registered path, name, description, critical classification, metadata, warnings and explicit ATA dependencies. The public identifier is namespaced, for example `[briefcase:ata:files.write]`. Importing an OBO endpoint copies its definition; it does not transfer user consent or convert its dependencies into ATA permissions.

Create and manage verification records on Honeycomb's central **App to App** page. Select an originating application you are authorized to manage, the allowed recipient applications and ATA endpoints. Review the expanded dependencies: adding a required downstream endpoint also adds its recipient to the reviewed application list. The immutable signing Carbon or Silicon identifies who created the record; it does not turn the proof into authority to act for that person.

Verification expiry defaults to never, or can be set to at least one hour. Access-token validity defaults to 30 minutes and can be set from one minute to 24 hours. Honeycomb reveals the refresh credential once. Store it in the originating application's protected server configuration. The CLI can list your records with `honeycomb apps ata list`, or retain an explicit app argument for the app-scoped list.

## Obtain and rotate access proof

```
use silicon_iam_client::{Client, Credential, Mutation};

let origin = Client::new("https://backend.iam.teamofsilicons.com")?
    .with_credential(Credential::application("ting", "<Ting app secret>"));
let exchange = Mutation::new(); // Persist this identity for an uncertain retry.
let tokens = origin.ata().refresh(&stored_refresh_token, &exchange).await?;
// Atomically save tokens.refresh_token before discarding the prior credential.
// Send tokens.access_token only to recipients in this verification's approved graph.
```

The response includes `verification_id`, `token_id`, the reusable `access_token`, replacement `refresh_token`, `expires_at`, `expires_in` and optional `refresh_expires_at`. A verification with no expiry still issues expiring access tokens. Serialize refreshes per verification and retain the exact request and mutation key until its outcome is known. Never distribute the refresh token to receiving apps.

## Verify at the receiving application

```
let receiver = Client::new("https://backend.iam.teamofsilicons.com")?
    .with_credential(Credential::application("waveform", "<Waveform app secret>"));
let proof = receiver.ata().verify(
    "ting", // Originating app, not the immediate forwarding app.
    &incoming_access_token,
    "/v1/application-speech", // This handler's exact registered ATA endpoint path.
).await?;
if proof.verified {
    // Enforce this handler's method, payload, resource policy and operation idempotency.
} else {
    // Reject the operation. Do not fall back to ordinary login or OBO.
}
```

The receiving app authenticates with its own credentials. Select the endpoint path from the matched server handler, never from a caller's claimed authorization fields. `app_id` is the originating app throughout a declared chain. Success returns `{verified: true, valid_till: ...}`; `valid_till` is the UTC expiry as a `YYYYMMDDHHMMSS` integer. An invalid proof, unauthorized recipient or unapproved endpoint returns `{verified: false}`. Authentication, transport or server failures are errors, not permission to continue.

Verification is reusable while authority remains valid. It does not authorize arbitrary resources or make an application's writes idempotent. Keep resource policy, request validation and duplicate-write protection in the receiver. Check proof before each protected operation; do not cache a successful result beyond the operation.

## Keep the declared chain and testing context

For Ting → Waveform → Briefcase, the verification must explicitly include both receiving applications and the needed ATA dependency. Waveform may forward the same access proof only for that approved downstream action; Briefcase verifies it using Briefcase's own credentials and Ting as the origin. Neither receiver obtains the refresh credential, and no step may reinterpret ATA proof as a user's OBO token.

Use `origin.ata().endpoints("waveform").await?` to discover endpoint definitions. Discovery alone grants no permission. Keep testing credentials, endpoint catalogs, verification records and requests in the same testing environment and cleaning generation. Never retry a failed testing lookup against production.

Revocation, expiry or a change to required authority can stop a previously valid verification. Preserve the pending operation and surface a clear configuration error; require an authorized manager to review the verification instead of silently adding recipients or endpoints. See the HTTP contract (`iam docs api/applications`) and OBO guide (`iam docs client/obo`) when the action must instead represent a selected user account and organization.
