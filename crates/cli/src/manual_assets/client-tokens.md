# Application tokens and authorization snapshots

Application access tokens are opaque. Refresh rotates one Application refresh family; introspection answers what a token authorizes now; revocation removes either one access token or one refresh family; logout can revoke the parent IAM session.

**Serialize refresh and retain its idempotency key.** Reusing a consumed Application refresh token under a new key is treated as compromise and revokes that Application refresh family and its related access authority. It does not revoke the parent IAM session, unrelated devices, or other Applications.

## Refresh

```
use silicon_iam_client::Mutation;

let refreshing = Mutation::new();
let key_to_persist = refreshing.key().as_str().to_owned();

// Persist `key_to_persist` with `stored_refresh_token` before this call.
let replacement = application
    .oauth()
    .refresh(app_id, &stored_refresh_token, &refreshing)
    .await?;

// Atomically replace the stored token pair with `replacement`.
```

Two rules are load-bearing:

- **One refresh at a time per family.** Serialize workers and browser tabs that share a refresh token.

- **Store the replacement atomically.** A crash after the server rotates but before the new token is committed otherwise leaves only a consumed token.

## Recovering an uncertain refresh

Reconstruct the same `Mutation`, and send the exact same Application ID and old refresh token. A changed body with the same key returns `409 idempotency_conflict`; the same body with a new key is refresh-token reuse.

```
use silicon_iam_client::{IdempotencyKey, Mutation};

let key = IdempotencyKey::parse(saved_key)?;
let refreshing = Mutation::with_key(key);
let replacement = application
    .oauth()
    .refresh(app_id, &stored_refresh_token, &refreshing)
    .await?;
```

The service may return its stored result with `Idempotency-Replayed: true`. Version 1.2.1 returns the typed response body but does not expose that response header, so recovery must be keyed by the `Mutation` your application persisted rather than by an SDK replay flag.

## Introspection

```
use silicon_iam_client::models::{
    TokenIntrospectionRequest,
    TokenIntrospectionRequestTokenTypeHint,
};

let current = application.oauth().introspect(
    &TokenIntrospectionRequest {
        token: access_token.to_owned(),
        token_type_hint: Some(TokenIntrospectionRequestTokenTypeHint::AccessToken),
    },
    Some("acme"),
).await?;

if current.active {
    let actor = current.principal_id;
}
```

The optional organization context must be one canonical organization handle. A valid handle that does not match the token returns `active: false`, including when the token came from an unscoped login. A malformed or duplicate `X-Org-ID` is a request error. Unknown, expired and revoked tokens also return an inactive response rather than revealing which condition applied. Use introspection for current authorization; a webhook is a notification, not an authorization cache. Mint the SLT with `short_lived_token_in_organization` when the token must be active in an organization or used for OBO.

## First login and rebuilding a missing authorization projection

An active organization-bound access token now includes a typed `authorization` snapshot in introspection. Fetch it immediately after login and whenever your application has no local membership projection:

```
let authority = application.oauth()
    .authorization(&access_token, Some("acme"))
    .await?;
// None means no current organization authority; fail closed.
// Do not replace missing role/tag disclosure with extra permissions.
```

The snapshot binds principal ID, public ID, organization ID and handle, membership ID/version, current authorization epoch, audience and testing environment. `org_role` requires `roles.read`; `tags` requires `memberships.read`. Null means undisclosed; an empty tag array means the disclosed membership has no active tags. No unrelated directory edit or webhook delivery is required. Refresh tokens and unscoped access tokens do not carry organization authorization.

Keep webhook updates for asynchronous projection maintenance, but introspect current access tokens before authorizing. Bind any cache to the full environment/audience/organization/principal/membership/epoch/effective-scopes tuple. Never fill undisclosed fields from a broader cached token. After an IAM environment clean, reimport, onboard and log in again; old tokens cannot reconstruct erased authority. Application bearer tokens do not gain access to IAM's first-party member/directory management routes through this contract.

## Revocation

```
use silicon_iam_client::{Mutation, models};

application.oauth().revoke(
    &models::OAuthRevocationRequest {
        token: refresh_token.to_owned(),
        token_type_hint: Some(
            models::OAuthRevocationRequestTokenTypeHint::RefreshToken,
        ),
    },
    &Mutation::new(),
).await?;
```

Revoking an access token removes only that token. Revoking a refresh token removes its complete Application refresh family and related access authority. Revoking an unknown token deliberately succeeds, so callers cannot use the route as a token-existence oracle.

## Application-triggered global logout

To honor “sign out everywhere” for a Carbon, authenticate `auth().logout` with the Carbon Application access token itself, not with the Application's Basic credential:

```
use silicon_iam_client::{Credential, Mutation, models};

let actor = iam.with_credential(Credential::bearer(application_access_token));
actor.auth().logout(
    &models::LogoutRequest { mode: None },
    &Mutation::new(),
).await?;
```

The token must have been issued to the calling Application as both client and audience. This form revokes the token's parent IAM session and every IAM/Application authority tied to that session. It cannot request account-wide `all_sessions`; that is a separate, step-up-protected first-party Carbon operation.

## The mutation pattern

1. Create one `Mutation` per logical operation.

2. Persist `mutation.key().as_str()` with the exact input before sending.

3. On success, commit the result and retire the saved key together.

4. After an uncertain transport outcome, rebuild with `Mutation::with_key(IdempotencyKey::parse(saved_key)?)` and resend unchanged.

5. On an authoritative terminal API error, fix the request or stop; do not blindly retry it.

The crate sends each call once and does not persist mutations for you. OBO proof verification is intentionally different: it consumes a single-use proof and accepts no idempotency key, so an ambiguous verification must not be retried.
