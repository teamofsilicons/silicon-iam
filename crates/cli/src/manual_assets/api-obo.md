# On-behalf-of proofs and delegated authority

On-behalf-of access lets application A call a registered endpoint on application B for an authenticated user. Applications may belong to different organizations. IAM issues a short-lived, single-use proof bound to the precise downstream request.

## Authority before exchange

B publishes an `obo_endpoints` catalog. A declares each required endpoint in `app_scope.external`. Critical endpoints require B's review approval, and the user must consent to A's effective permissions and selected organizations. The subject token must be an active application access token issued to A. An IAM session token or a token issued to another application is rejected.

The selected user's organization is independent of either application's owning organization. Send optional body `org_id` to choose one of the token's active, user-selected memberships. It may be omitted only when exactly one such membership is available. Selection cannot widen the grant. OBO routes reject `X-Org-ID`; use the exchange body's field instead.

## Discover, exchange, call, verify

1. A discovers B's base URL through `GET /api/v1/application-directory/{app_id}` and endpoints through `GET /api/v1/obo-access/applications/{app_id}/endpoints`, using A's Basic credentials.

2. A hashes the exact downstream body bytes and calls `POST /api/v1/obo-access/exchanges` with its Basic credentials, a signed request binding, and an idempotency key.

3. A sends the actual body directly to B with the returned `access_proof`. IAM receives metadata and a digest, not the uploaded file or downstream body.

4. B calls `POST /api/v1/obo-access/verify` using B's own Basic credentials and the actual request's method, path, and body hash. IAM consumes the proof. B then applies its resource policy and executes the request.

## The exchange request

```
{
  "subject_token": "oat_…",
  "audience": "storage>drive",
  "endpoint_id": "files.upload",
  "org_id": "customer",
  "metadata": {"filename":"report.pdf", "content_type":"application/pdf"},
  "request": {"method":"POST", "body_sha256":"<64 lowercase hexadecimal characters>"}
}
```

The method is canonical uppercase. `body_sha256` is SHA-256 of the exact bytes A will send. The path comes from B's registered endpoint; it is not supplied as an exchange override. Metadata must match the registered schema's required keys and types.

```
X-OBO-Timestamp: <Unix seconds>
X-OBO-Signature: <64 lowercase hexadecimal characters>

signature = lowercase_hex(HMAC_SHA256(
  app_secret,
  timestamp + "." + method + "." + registered_path + "." + body_sha256 + "." + idempotency_key
))
```

The OBO signature is raw lowercase hexadecimal; it does not use the webhook signature's `v1=` prefix. Use the exact `Idempotency-Key` header in the signed input. Timestamp checks reject stale signatures. A proof expires after at most 60 seconds and cannot authorize another method, path, body, subject, or audience.

## Single-use verification

```
POST /api/v1/obo-access/verify
Authorization: Basic <recipient application credentials>
Content-Type: application/json

{
  "access_proof": "<proof from IAM>",
  "request": {
    "method": "POST",
    "path": "/v1/files",
    "body_sha256": "<hash of actual received bytes>"
  }
}
```

Verification accepts no idempotency key and must not be automatically retried. A consumed proof returns `409`; an expired proof returns `410 proof_expired`. An uncertain result is not permission to execute. Obtain a new proof for a new attempt and use the recipient's own operation-level deduplication where necessary.

The exchange is idempotent: retry its exact payload with the original key after an uncertain response. Its stored response expires no later than the proof, and replay never extends the original deadline. If a retry needs a fresh timestamp, sign the same method, path, digest, and idempotency key again.

## Current delegated authorization

Verification rechecks the user, active membership, parent session, calling and receiving applications, endpoint configuration, current scope approvals, consent, and authorization epochs. Its response includes actor, selected `org_id`, endpoint, metadata, expiry, consumption time, and `authorization`. Optional role and tag information remains scope-filtered; an undisclosed value grants no default authority. The proof authorizes only its registered endpoint and exact request. The recipient still decides whether that user may act on the requested resource.

## Publishing endpoints

```
{
  "endpoint_id": "files.upload",
  "path": "/v1/files",
  "metadata": {"filename":{"type":"string"}, "content_type":{"type":"string"}},
  "critical": true
}
```

Every endpoint requires an explicit boolean `critical`. Its stable `endpoint_id` cannot be moved to another path. Metadata keys are required at exchange time. Current owning-organization owners/admins configure the catalog. Published endpoints are discoverable by verified applications across organizations. B can set `obo_review_message` to describe what applicants should explain in critical-scope review threads.

## OBO in application testing

All participating apps, tokens, and proofs must belong to the same testing environment. Recursive dependency import prepares the external apps A declared. An exchange may include `testing_context` with the recipient's test `app_id`, `app_secret`, and `iam_test_key`. Forward this only to that recipient over its secure application transport so it can authenticate against IAM and select its isolated test storage.

The presence of `app_secret` signals a test request; it is not proof of authenticity. The recipient verifies it against IAM with the environment key before accepting test authority. Production app secrets are never shared this way. Redact test credentials and root keys from logs. See Testing environments (`iam docs api/testing-environments`).

## Failures

| Status | Recovery |
| --- | --- |
| `403` | Check current subject authority, explicit selected membership, endpoint permission, review status, and both app states. |
| `404` | Check the qualified target and endpoint in the selected data plane. |
| `409` | A proof may already be consumed; do not replay verification. |
| `410` | Obtain a new proof for the intended request. |
| `422` | Refresh endpoint discovery and correct the metadata schema. |
