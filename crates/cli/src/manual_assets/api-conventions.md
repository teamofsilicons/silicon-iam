# HTTP conventions, versions and pagination

A small set of rules applies to nearly every call in the contract. Getting them right once, in your HTTP layer, removes most of the failure modes you would otherwise meet one endpoint at a time.

## The version handshake

Before its first versioned call, a client negotiates an API major against the unversioned `GET /api/version`. It advertises every major it implements, in descending preference order:

```
GET /api/version
Silicon-IAM-Supported-API-Versions: v1
```

```
{
  "service": "silicon-iam",
  "selected_api_version": "v1",
  "supported_api_versions": ["v1"],
  "build": "0.1.0",
  "commit": "…"
}
```

IAM selects the highest mutually supported version and returns it in both `selected_api_version` and the `Silicon-IAM-API-Version` header. When there is no common version it answers `406 api_version_not_acceptable` with its own catalog in `details`.

**Fail closed on a disagreement.** Verify the catalog, the header, and that the selection really is the highest common version before making a versioned request. The Rust SDK exposes this explicit call as `client.system().negotiate()`. A client that guesses at the wire contract will eventually send a well-formed request that means something other than its author intended.

`/api/v1/version` remains available as a version-specific diagnostic. It is not the handshake, and calling it instead skips every check above.

## Idempotency

IAM's own failures use a JSON error envelope with a stable `code` and an optional request correlation ID. A public edge or reverse proxy can answer before that contract is reached. An HTML `403` without an IAM envelope is not an IAM membership denial; record the HTTP status and any request ID, then inspect deployment logs. Do not invent a request ID or infer a particular firewall rule from that response alone. If a mutation's outcome is uncertain, retain its original idempotency key.

Every externally initiated mutation requires an `Idempotency-Key` of 16–255 characters. The server scopes it to the authenticated caller, the route, and a digest of the request body.

- Repeating an identical validated request returns the stored result, and may carry `Idempotency-Replayed: true`.

- Changing any canonical field under the same key returns `409 idempotency_conflict`.

- JSON whitespace and object-key ordering are not significant.

**A key belongs to an intent, not to a request.** Mint it when the user submits, and reuse it for every transport retry of that submission. A fresh key per attempt lets the server execute the mutation twice — which is the exact thing idempotency exists to prevent.

Two deliberate exceptions. **OBO proof verification** accepts no idempotency key, never stores a successful response, and answers `409` on every attempt after the proof is consumed — it is single-use by design. And a response containing a **newly generated secret** stays replayable for only ten minutes, rather than the usual twenty-four hours.

## JSON Merge Patch

Every `PATCH` endpoint consumes `application/merge-patch+json`. For a nullable property, three wire states have three different meanings:

| JSON state | Meaning |
| --- | --- |
| Property omitted | Leave the stored value unchanged |
| `"property": null` | Clear a nullable stored value |
| `"property": value` | Replace the stored value |

Use `null` only where the OpenAPI property is nullable. Do not serialize an absent nullable optional as `null`: that turns “leave unchanged” into “clear this field.” A patch that produces no state change returns its resource-specific stable `409 …_unchanged` code rather than incrementing the version or emitting audit and outbox work.

## Optimistic concurrency

Versioned aggregate mutations require a strong `If-Match: "{version}"` header. Reads and successful mutations return the version as an `ETag`; when a body also contains `version`, it is the same number.

| Situation | Response |
| --- | --- |
| Version matches | The mutation applies and the version increments by exactly one |
| Version is stale | `412 version_mismatch` |
| Precondition omitted | `428 precondition_required` |

Do not retry a `412` automatically. It means the record changed underneath you, and a blind retry silently overwrites whatever the other party did. Re-read, show the current state, and let the human decide whether their change still applies.

## Pagination

List endpoints use opaque cursors. The maximum page size is 100 and the default is 50.

```
GET /api/v1/organizations?limit=50&cursor=opaque-value
```

```
{
  "items": [],
  "page": { "next_cursor": null, "has_more": false }
}
```

A cursor is bound to the caller, the filters, the sort order and the tenant context. It is **not** an offset, and clients must not interpret, construct or reuse one across a different filter set. There is no total count, and no way to jump to page seven — an interface that promises either is promising something the API cannot deliver.

## Errors

Every JSON error uses one envelope:

```
{
  "error": {
    "code": "machine_readable_code",
    "message": "Safe human-readable explanation",
    "details": {},
    "request_id": "trace identifier"
  }
}
```

Branch on `code`, never on `message` — the message is prose for a human and may be reworded without a contract change. Log `request_id`; it is the fastest way to have a specific failure investigated.

A login that fails answers with this envelope too. It does not redirect: there is no token to deliver, and the redirect URI came from the caller rather than from a registration, so it is not a trusted place to report an error to.

Status guidance and stable no-op conflict codes are in the error index (`iam docs api/errors`).

## Rate limits

A `429` carries `Retry-After`, `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`. Honour `Retry-After`; do not invent your own backoff on top of it.

Buckets are keyed across normalised identity, session, purpose, channel and provider. Signup send protection includes a contact-global bucket independent of the temporary signup session, so cycling sessions does not buy extra attempts. Verification-attempt cooldowns are separate from initiation limits, and issuing a new code invalidates the older one.

IP and subnet buckets are deliberately disabled until a deployment defines trusted proxy extraction. Silicon IAM never trusts an arbitrary forwarding header.

## Headers worth knowing

| Header | Direction | Meaning |
| --- | --- | --- |
| `Idempotency-Key` | request | Required on every external mutation |
| `If-Match` | request | Strong version precondition, quoted |
| `X-Step-Up-Token` | request | Action-bound reauthentication |
| `X-Org-ID` | request | Introspection only; can never widen authority |
| `X-Request-ID` | both | Accepted when a valid UUID, otherwise generated |
| `ETag` | response | Current aggregate version |
| `Idempotency-Replayed` | response | A stored result was returned |

`X-Org-ID` must agree with the credential and the grant. OBO does not accept it at all: IAM derives the organization from the authenticated applications and refuses cross-organization use.
