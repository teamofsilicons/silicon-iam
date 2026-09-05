# API error codes and recovery

Common statuses, representative codes, and the stable conflicts integrations need to handle. Branch on the code; the message is prose and may change.

## By status

| Status | Meaning | Typical codes |
| --- | --- | --- |
| `400` | Malformed or unsupported protocol input | `invalid_request`, `unsupported_grant_type` |
| `401` | Missing, invalid, expired or revoked authentication | `invalid_credentials`, `token_expired`, `token_revoked` |
| `403` | Actor type, capability, scope, consent or step-up is insufficient | `forbidden`, `insufficient_scope`, `step_up_required` |
| `404` | Missing or tenant-hidden resource | `not_found` |
| `409` | Unique, idempotency, replay or lifecycle conflict | `identifier_unavailable`, `idempotency_conflict`, `state_conflict` |
| `410` | Expired one-time state | `challenge_expired`, `invite_expired`, `authorization_code_expired`, `proof_expired` |
| `412` | Stale `ETag` | `version_mismatch` |
| `413` | Body exceeds the endpoint limit | `payload_too_large` |
| `422` | Well-formed input violates a field, tenant, policy or quorum rule | `validation_failed`, `invalid_code`, `hierarchy_cycle` |
| `428` | A required precondition is absent | `precondition_required` |
| `429` | A rate-limit bucket is exhausted | `rate_limited` |
| `502` | An upstream provider failed | `provider_error` |
| `503` | A required dependency is unavailable | `service_unavailable` |
| `504` | A bounded deadline elapsed | `gateway_timeout` |

## What to do about each

### 401 — re-authenticate, once

Refresh the access token and replay the request exactly once. If the refresh is also rejected, the family is gone: sign the user out and start a fresh login. Do not loop.

### 403 `step_up_required` — mint a token

Start a step-up challenge for the action and resource named in the request, verify it, and retry with `X-Step-Up-Token`. See Authentication (`iam docs api/authentication`).

### 404 on a resource you believe exists

Cross-tenant reads are hidden rather than forbidden. A `404` here usually means the caller is not a member of that organization, not that the record is missing.

### 409 `idempotency_conflict` — you changed the body

The same key was reused with different content. Mint a new key for the new intent; do not strip the key and retry, which would risk a duplicate.

### 409 no-op and duplicate-intent conflicts

A mutation that would leave state unchanged returns a resource-specific stable code and does not increment the version or emit audit/outbox work:

| Area | Codes |
| --- | --- |
| Profiles and directory | `carbon_profile_unchanged`, `member_directory_unchanged`, `silicon_profile_unchanged` |
| Organization and governance | `organization_unchanged`, `job_role_unchanged`, `tag_set_unchanged`, `tag_name_unchanged`, `trust_default_unchanged`, `trust_rule_unchanged` |
| Webhook configuration | `silicon_webhook_subscription_unchanged`, `application_webhook_unchanged` |
| Applications and testing | `application_unchanged`, `testing_environment_unchanged` |

`approval_request_exists` separately means an equivalent pending governance request already exists. Treat these responses as no-op or duplicate intent, not as transient failures to retry under a new idempotency key.

### Refresh-token reuse — the affected family is terminal

IAM refresh rejects reuse with `401 unauthenticated` after invalidating that one IAM session family and authority descended from it. OAuth refresh rejects it with `400 invalid_grant` after invalidating only that OAuth family and access tokens for the same Application session. Neither case automatically revokes another device session; OAuth reuse also does not revoke the parent IAM session or another Application's tokens. Refresh must be single-flight per family. An exact retry with the original idempotency key replays the first result and is not treated as token reuse.

### 410 — the state expired

A code, invitation, short-lived login token or proof passed its lifetime. Nothing is retryable; start the flow again. Tell the user the exact lifetime — "codes are valid for 10 minutes", not "please try again".

### 412 `version_mismatch` — refetch, do not retry

The record changed since you read it. Reload, show the current state, and let the human decide whether their edit still applies. An automatic retry silently overwrites somebody else's work.

### 422 `invalid_code` — count the attempts

Ten failures start a sixty-second cooldown. The count and the cooldown carry into a resent code, so offering "send a new code" as the remedy is actively misleading.

### 428 — a precondition is missing

Usually a missing `Idempotency-Key` or `If-Match`. The `details` object names which.

### 429 — wait exactly as long as you are told

Honour `Retry-After`. Adding your own backoff on top produces long, confusing waits; ignoring it produces a longer ban.

### 502, 503, 504 — retry with jitter

These are transient. Retry a `GET` freely, and a mutation only while reusing the original idempotency key. Use full jitter so a fleet of clients does not resynchronise onto one retry instant.

## Reading `details`

`details` is a free-form object whose shape depends on the code. Validation failures populate `fields` with an array of objects, each carrying `field` and `message`:

```
{
  "error": {
    "code": "validation_failed",
    "message": "The request was well-formed but could not be accepted.",
    "details": {
      "fields": [
        { "field": "job_role", "message": "at most 5000 characters" }
      ]
    },
    "request_id": "018f2c1e-…"
  }
}
```

Never surface `details` raw to an end user. Map the codes you handle to your own copy, and fall back to `message` for the rest.
