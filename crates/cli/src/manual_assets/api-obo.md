# On-behalf-of consent, tokens and delegated authority

OBO lets application A call an approved endpoint on application B for a user. Ordinary application login grants no OBO authority. A requests separate approval when it needs an action, then receives reusable access and refresh tokens bound to that root's approved dependency graph and each provider's selected account and organization.

## Declare endpoints and dependencies

B publishes `obo_endpoints`; A declares the roots it uses in `app_scope.external`. Critical scopes require the provider approval applicable to the requesting app. A private-app exemption never replaces user consent or its owning-organization restriction. Applications may belong to different organizations; the represented user's selected organization is separate.

```
{
  "endpoint_id": "speech.generate",
  "name": "Generate speech",
  "description": "Generate audio from the supplied text.",
  "path": "/v1/speech",
  "note_to_user": "Audio will be saved to your selected storage account.",
  "additional_warnings": ["uses_credits"],
  "metadata": {},
  "critical": false,
  "ttl_seconds": 300,
  "downstream": [{"audience": "storage", "endpoint_id": "files.create"}]
}
```

IAM exposes a globally unique `obo_id`, such as `[waveform:obo:speech.generate]`, alongside the local `endpoint_id`. Names, descriptions, notes, metadata and predefined warning codes are preserved in discovery and consent. Every endpoint explicitly declares `critical`. Its ID cannot move to another path; an app exposing endpoints needs a `base_url`. Omitted `ttl_seconds` defaults to 300 seconds. The provider controls the positive TTL. An omitted or empty `downstream` grants no delegation. Each receiving app must also hold the next endpoint in its own effective external scopes. IAM resolves the complete graph, rejects cycles or a revisited app, and limits a chain to ten hops.

Discover the accepted catalog with `GET /api/v1/obo-access/applications/{app_id}/endpoints`, authenticated as the requesting app. Discover an available backend origin through `GET /api/v1/application-directory/{app_id}`. Discovery grants no endpoint authority.

## Request separate consent

A authenticates to IAM with its own Basic credentials and sends an idempotent authorization request. `subject_token` is the user's current ordinary application access token issued to A; `org_id` must be a selected active membership in that login grant.

```
POST /api/v1/obo-access/authorizations
Authorization: Basic <A's credentials>
Idempotency-Key: <stable key for this request>

{
  "subject_token": "<user's application login access token>",
  "org_id": "customer",
  "endpoints": [{"audience": "waveform", "endpoint_id": "speech.generate"}]
}
```

The response contains the request `id`, `authorization_url`, version, expiry and full endpoint graph. It creates a pending request, not a grant. A opens the IAM URL. Only the represented user, authenticated directly to IAM, may view `GET /api/v1/obo-access/consents/{id}` or decide. A may read status through `GET /api/v1/obo-access/authorizations/{id}`; that response never reveals the authorization code.

IAM shows who calls whom, endpoint names and descriptions, critical classifications, notes, warnings and every branch. The returned `providers` list enables one account and organization selection for each receiving app. By default each uses the originating account and organization. For example:

```
Assistant
  -> Waveform: generate speech
      -> Storage: save the generated audio
```

Approval allows repeated use while the grant remains valid. One screen may show several requested roots, with a separate grant and token pair for each root endpoint and organization. Required dependencies are approved together with their root. Ordinary login, bundle membership and trusted-organization login consent bypass never create OBO grants.

```
POST /api/v1/obo-access/consents/{id}/decision
Authorization: Bearer <direct IAM user session>
Idempotency-Key: <stable decision key>

{"decision":"approve","version":1,"contexts":[],"iam_disclosures_reviewed":true}
```

Each endpoint also displays `iam_disclosures`: identity (`self.identity.read`), organization membership and role (`self.membership.read`), and organization tags (`self.tags.read`). Only scopes both declared and currently approved for every app on that endpoint’s path are offered. These are separate OBO disclosures for the account and organization selected for that provider; an originating login cannot consent for another account. Show them before approval and send `iam_disclosures_reviewed:true` when any endpoint requests them. An older client that omits this acknowledgement receives `obo_disclosure_review_required` and must update and review the request.

Use the version just displayed. Approval pins the graph reviewed by the user; a changed graph returns `412` and must be reviewed again. Use `decline` to refuse OBO without ending ordinary login. Approval displays a short-lived, single-use authorization code for the user to copy to A. A valid existing grant can be reused during approval without broadening its authority.

Optional `contexts` entries are `{app_id, account_token, org_id}`, with at most one entry per provider in the graph. Each `account_token` is a current direct IAM Carbon or Silicon token, used only to authenticate the chosen account and membership. Do not persist it with the grant or expose it to applications. The browser gateway replaces opaque configured-account handles with protected server-side credentials. Omitted providers retain the root account and organization. All required dependencies are approved together; users manage grants at `/console/obo?app=<requesting_app_id>`.

## Optional bound callback

The app may include `redirect_uri` and `state` when creating the authorization request. Supply both or neither. State must be 32–512 bytes. The callback must be an absolute HTTPS URI (literal loopback HTTP is allowed), at most 2048 characters, without credentials or a fragment. The authenticated app binds this exact URI/state to the request; the decision cannot replace them. IAM has no global callback registration list.

After a confirmed decision, IAM returns `redirect_uri` with `authorization_id`, `state` and `code` for approval, or `error=access_denied` for decline. Follow only this confirmed server response. The app validates the state and request ID against its initiating session, removes the code from browser history/logs, and redeems it server-side with its own Basic credentials. The code expires after two minutes and is single-use. Status polling never reveals it. Without a callback, IAM displays the code for manual handoff.

Browser integrations can use compact popup approval with `display=popup` on the returned consent URL. The callback and state remain bound to the authorization request. Complete the server-side exchange before notifying an exact app-origin opener, and keep a full-page fallback. See the popup approval guide (`iam docs client/obo`) for return destinations, cancellation and uncertain retries.

## Exchange and refresh tokens

```
POST /api/v1/obo-access/tokens
Authorization: Basic <A's credentials>
Idempotency-Key: <stable exchange key>

{"authorization_id":"<request UUID>","authorization_code":"<approved code>"}
```

The `items` response contains one pair per approved root: `grant_id`, `access_token`, `refresh_token`, `token_type`, expiry, audience, endpoint, organization and exact OBO scope. Keep the pair in the requesting app's protected storage. Each access token authorizes every endpoint in that root's approved graph, using the context selected for the verifying provider. It cannot authorize endpoints outside that graph.

Refresh by sending only `{"refresh_token":"..."}` to the same route with A's Basic credentials and an idempotency key. Refresh rotates the token and preserves the exact grant; reuse of an already rotated token compromises its family. Keep one refresh in flight per family. Persist the mutation key and replay the same request after an uncertain transport outcome. Idempotent replay returns the original credentials and expiry; it never extends their lifetime.

Access-token validity uses the shortest endpoint TTL in the approved graph. The grant and its rotating refresh family have no ordinary time expiry. Ordinary logout, approving-session expiry and application login expiry do not remove that consent. Explicit revocation, security resets and current authority changes still invalidate affected credentials. Use returned expiry fields; never assume an access token is permanently valid.

## Verify every incoming request

Each OBO action has a unique, stable registered path within its application. Verification uses that exact canonical path; for a parameterized route, use the router’s matched template (for example `/api/v1/obo/todos/{todo_id}/read`), not an expanded resource path. Select the endpoint ID and path from the matched server handler, never caller-supplied authorization fields. Distinct HTTP methods on one REST path do not create distinct OBO paths; use separate action routes when needed. The handler still checks the actual method, resource ID, payload and resource permissions.

A sends the access token and actual payload directly to B. Before every operation B authenticates to IAM using B's own credentials:

```
POST /api/v1/obo-access/token-verifications
Authorization: Basic <B's credentials>

{
  "access_token":"<incoming OBO access token>",
  "endpoint_id":"speech.generate",
  "request":{"method":"POST","path":"/v1/speech"}
}
```

IAM checks the recipient, endpoint, current user and organization membership, effective app scopes and provider approvals, the durable grant and provider context, credential security epochs, expiry and revocation. The successful result identifies the user, organization, immediate caller, originating app, endpoint and full lineage, with current `authorization`. B must then enforce resource permissions and validate payload and required metadata. Undisclosed role or tags grant no authority.

**Verification does not consume the token.** The same token may authorize different bodies for its endpoint until expiry or revocation. The body and uploaded files never pass through this IAM check. Optional self disclosures come from the explicit per-provider OBO consent snapshot, bounded by current declarations and approvals for every app on that path. They never inherit another account’s login consent. Changing those declarations or replacing an approval requires fresh review; previously issued grants are not widened. Verification accepts no idempotency key and can be repeated after an uncertain result; execute only after successful current verification. B handles operation-level deduplication.

## Use the same token throughout the approved chain

For A → B → C, B forwards the same incoming access token to C's approved endpoint. C authenticates with its own app credentials and verifies its own endpoint, method and path. IAM returns C's selected account and organization, and the chain's immediate caller and originating app. The root token also works when A calls an approved deeper endpoint. It never grants another endpoint outside the approved graph.

`POST /api/v1/obo-access/delegations` remains a compatibility check for an approved edge, accepting `{access_token, audience, endpoint_id}` with the caller's Basic credentials and an idempotency key. It returns the same access token; no child token or refresh credential is created. Only the originating app stores and rotates the refresh token. Providers receive the access token only.

## Review, revoke and change authority

A directly authenticated user lists grants most recent first at `GET /api/v1/obo-access/grants` (optional `app_id` filters by requesting app before pagination; `limit` defaults to 10 and is bounded to 1–10; pass the opaque `page.next_cursor` as `cursor` while `page.has_more` is true) and revokes one with idempotent `POST /api/v1/obo-access/grants/{id}/revoke`. Revocation ends root and descendant tokens. Ordinary logout/session expiry preserves consent. Explicit grant revocation, app disablement, applicable account/membership/organization removal, graph changes and required-scope revocation stop affected authority. Account/application security-epoch changes invalidate issued credentials.

Grant snapshots cannot silently acquire new roots or dependencies: additions require fresh consent. Current removals and revocations apply immediately. Every verification, refresh and compatibility delegation rechecks current graph and authorization. The originating app can recover credentials for an unchanged live grant by sending `{grant_id, subject_token}` to the token route with a fresh login for the original account and organization. A reset of a different selected account requires that account to authenticate and approve again; recovery never silently changes provider contexts.

## Testing and cutover

All apps, requests, grants, codes and token families must belong to the same production or testing environment and current cleaning generation. A lookup never falls back to production. Where token responses provide `testing_context`, forward those test recipient credentials only to that recipient over secure transport. Authenticate them against IAM before accepting test authority; redact all credentials from logs.

Earlier login consent and proofs are not converted to OBO grants. Legacy `POST /api/v1/obo-access/exchanges`, `chained-exchanges` and `verify` return `410 obo_proof_flow_retired`. Integrations must adopt separate consent, token refresh and token verification before cutover. See the Rust client guide (`iam docs client/obo`).
