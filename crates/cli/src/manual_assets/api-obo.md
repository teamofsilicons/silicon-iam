# On-behalf-of proofs and delegated authority

On-behalf-of lets one application call another on a user's behalf, without either holding the other's credentials. It is strictly same-organization, and every proof is bound to one exact request.

**OBO never crosses an organization.** IAM derives the organization from the two authenticated applications and refuses anything else. `X-Org-ID` is not accepted on these endpoints at all.

**The subject token must already be organization-bound.** Include `org_id` when minting its SLT (or start the browser login with that query parameter), then exchange the SLT normally. IAM requires a current active membership and rejects an unscoped Application access token with `403 obo_organization_required`.

## The shape of it

Application A wants to call Application B. Instead of sending B a token that would work for any request, A asks IAM for a proof that works for *exactly one* request — and B validates it with IAM before doing anything.

1. **Discover.** `GET /api/v1/obo-access/applications/{app_id}/endpoints` lists what B exposes and what metadata each endpoint requires.

2. **Exchange.** A calls `POST /api/v1/obo-access/exchanges` with the subject token, the audience, the endpoint, the metadata, and a description of the request it intends to make. IAM returns a proof token.

3. **Call.** A sends B the real request — including any file bytes — with the proof attached.

4. **Verify.** B calls `POST /api/v1/obo-access/verify`. IAM consumes the proof and returns the bound actor, endpoint and metadata. Only then does B execute.

## The exchange request

```
{
  "subject_token": "oat_...",
  "audience": "application-b-id",
  "endpoint_id": "files.upload",
  "metadata": {
    "filename": "report.pdf",
    "content_type": "application/pdf"
  },
  "request": {
    "method": "POST",
    "body_sha256": "hash of the exact body bytes"
  }
}
```

Note what the exchange does *not* carry: the file. Only its digest. The bytes travel directly from A to B, and the proof commits to what they will be.

The request is additionally signed:

```
X-OBO-Timestamp: <unix seconds>
X-OBO-Signature: HMAC-SHA256(
  app_secret,
  timestamp + "." + method + "." + path + "." + body_sha256 + "." + idempotency_key
)
```

## Why the proof is bound to the request

Because the proof commits to the method, the path, the body digest and the idempotency key, it cannot be lifted and replayed against a different call. A proof minted to upload `report.pdf` cannot be used to upload anything else, or to hit a different endpoint, even by the application that legitimately obtained it.

It is valid for **one request or sixty seconds, whichever comes first**.

## Verification is single-use, deliberately

`POST /api/v1/obo-access/verify` accepts **no** `Idempotency-Key`, never stores or replays a successful response, and returns `409` on every attempt after the proof is consumed.

This is the one endpoint in the contract that is deliberately not idempotent, and it must not be retried. If your HTTP layer retries automatically, exempt this path — a retry after a successful verification looks exactly like a replay attack and will be refused as one.

The exchange itself *is* idempotent, but its replay envelope expires no later than the proof does.

## Current delegated authorization

Successful verification returns `authorization` alongside the actor. It is a live binding to principal, membership ID/version, authorization epoch, organization, audience and testing environment, read before consuming the proof. Role and tag disclosure requires `roles.read` and `memberships.read`, respectively, in both the parent token and the recipient's currently approved scopes. Null means undisclosed; never infer administrator authority from a missing field or an unbound cached role. This binding applies only to the verified endpoint and exact request. The audience still applies its own resource policy; proof validity alone does not grant blanket access to every resource.

## Exposing endpoints

An application declares its OBO surface through `obo_endpoints` on registration or update. Each entry has a stable `endpoint_id`, an absolute `path`, and a `metadata` schema whose top-level keys are all required at exchange time.

An existing `endpoint_id` cannot be repointed at a different path. That would silently redirect callers who believe they are still talking to the endpoint they discovered.

Only an organization owner or administrator can configure this, and the resulting catalogue is visible to every application in the same organization.

## Failure modes worth handling

| Status | Means | Do |
| --- | --- | --- |
| `403` | The subject token is unscoped, belongs to a different organization, or lacks current OBO authority | Start a new organization-bound Application login and re-check membership and reviewed scope. |
| `404` `not_found` | The target does not exist or is outside the caller's organization; those cases are intentionally indistinguishable | Do not retry without correcting the target or caller context. |
| `409` | The proof was already consumed | Do not retry. Mint a new proof for a new request. |
| `410` `proof_expired` | More than 60 seconds elapsed | Exchange again. Consider why the gap was that long. |
| `422` | Metadata does not satisfy the declared schema | Re-read the catalogue; the audience may have changed it. |
