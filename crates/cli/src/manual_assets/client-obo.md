# Rust client OBO signing and verification

On-behalf-of (OBO) lets one Application call a registered endpoint on another Application in the same organization. IAM mints a proof for one exact downstream request; the audience authenticates and consumes it before doing the work.

**Start with an organization-bound Application login.** Mint the SLT with `auth().short_lived_token_in_organization(app_id, Some("acme"), mutation)`, then exchange it through `oauth().login`. IAM requires the actor's membership to be active. An access token produced by an unscoped login cannot issue an OBO proof.

## Discover, hash, sign, then exchange

```
use silicon_iam_client::{Mutation, api::obo::body_sha256, models};

let catalog = caller.obo().endpoints("acme>billing").await?;

// Compute this over the exact downstream bytes, not re-serialized JSON.
let body_digest = body_sha256(body);
let exchanging = Mutation::new();

let request = models::OboExchangeRequest {
    subject_token: subject_access_token.to_owned(),
    audience: "acme>billing".to_owned(),
    endpoint_id: "invoices.create".to_owned(),
    metadata: serde_json::json!({ "reason": "checkout" }),
    request: models::OboExchangeRequestBinding {
        method: "POST".to_owned(),
        body_sha256: body_digest,
    },
};

let proof = caller.obo()
    .exchange_signed(&request, &catalog, &exchanging)
    .await?;
```

`body_sha256` hashes exact bytes and returns the required lowercase digest. `exchange_signed` generates a fresh Unix-seconds timestamp, selects the endpoint's exact registered path from the supplied catalog, and uses the same `Credential::Application` secret for Basic authentication and HMAC. It rejects a catalog/audience/endpoint mismatch or a non-canonical method, path, digest, timestamp, or idempotency key before sending. The signature is lowercase HMAC-SHA256 hex over this exact UTF-8 string:

```
{timestamp}.{UPPERCASE_METHOD}.{registered_path}.{lowercase_body_sha256}.{idempotency_key}
```

The request body itself never goes to IAM; it travels directly to the audience Application. For a specialized transport, `sign_exchange(request, catalog, timestamp, mutation)` exposes the same canonical signer and the low-level `exchange` method remains available. Normal callers should keep signing and sending coupled through `exchange_signed`.

## What the proof is bound to

IAM binds the proof to the source and audience Applications, subject token, actor, organization, endpoint, metadata, method, registered path and exact body digest. It is valid for one verification or at most 60 seconds, whichever comes first. Exchange immediately before the downstream request.

## Consume it against the actual request

```
let verified = audience.obo().verify(
    &models::OboVerifyRequest {
        access_proof: proof.access_proof,
        request: models::OboVerifyRequestBinding {
            method: "POST".to_owned(),
            path: "/v1/invoices".to_owned(),
            body_sha256: body_sha256(actual_body),
        },
    },
).await?;

// Only now execute the operation. `verified` identifies the actor,
// issuer Application, endpoint and authenticated metadata.
// `verified.authorization` is the current delegated membership binding.
```

`verified.authorization` binds the represented actor to the current membership ID/version, authorization epoch, organization, audience and testing environment. Its role/tag disclosure is limited to the intersection of the parent token's scopes and the recipient's currently approved scopes: `roles.read` reveals `org_role` and `memberships.read` reveals `tags`. Null means undisclosed, not baseline member or empty tags. Apply your application's authorization policy to this binding for this exact verified endpoint/request only. Never fill undisclosed fields from a broader cached scope set, promote the actor from an unbound cached role, or reuse a consumed proof's binding on another request.

**Verification is single-use and must never be retried.** It accepts no idempotency key. If the call returns a transport or decode error, the proof may already have been consumed; fail the downstream request and mint a fresh proof for a new attempt. A second verification returns `409`.

## Recovering an uncertain exchange

Exchange, unlike verification, is idempotent. Recreate a `Mutation` with the saved `IdempotencyKey` and repeat the exact subject token, audience, endpoint, metadata, method and body digest while the proof is still valid. Call `exchange_signed` again so the retry receives a fresh timestamp and signature; those two headers are not idempotency material and an old timestamp can fall outside the 60-second window. Any changed request input returns `409 idempotency_conflict`. The client does not store those inputs or retry the exchange automatically.

## How the proof reaches the audience

IAM does not prescribe a downstream proof header or body field. The two Applications must agree how to carry `access_proof`. Regardless of that transport, the audience calculates the verification method, path and digest from the request it actually received.

## Failure modes

| Condition | Meaning | Do |
| --- | --- | --- |
| `401` | The Application Basic credential or exchange HMAC is invalid. | Correct the credential, canonical string, clock, or signature. Do not retry unchanged. |
| `403` | The subject token is unscoped, belongs to a different organization, or no longer has the required current authority. | Start a new organization-bound login and re-check the actor's active membership and the caller's OBO scope. |
| `404 not_found` | The target is nonexistent, invisible, or outside the caller's organization; those cases are intentionally indistinguishable. | Correct the audience or organization. Do not retry unchanged. |
| `409` | The proof was consumed, or an idempotency key was reused with different exchange input. | Do not retry verification. For an exchange conflict, recover the original input or use a new key for a genuinely new operation. |
| `410 proof_expired` | The proof's 60-second life elapsed. | Exchange a new proof for a new downstream attempt. |
| `422` | The metadata or presented request binding does not satisfy the registered contract. | Re-read the catalog and compare the actual request. |

See the HTTP OBO contract (`iam docs api/obo`) for the complete signature and authorization checks.
