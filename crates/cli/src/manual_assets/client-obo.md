# Rust client OBO consent, tokens and verification

Use `client.obo()` for separate endpoint approval, reusable access/refresh tokens, verification, downstream delegation and user grant management. The SDK never stores or refreshes these tokens automatically. Ordinary application login grants no OBO authority.

## Start consent when the app needs the action

```
use silicon_iam_client::{Client, Credential, Mutation, models};

let application = Client::new("https://backend.iam.teamofsilicons.com")?
    .with_credential(Credential::application("assistant", "<app secret>"));
let request = application.obo().authorize(&models::OboAuthorizationRequest {
    redirect_uri: None, // Or Some(exact_callback) together with a 32–512-byte state.
    state: None,
    subject_token: "<user's ordinary application token>".to_owned(),
    org_id: "customer".to_owned(),
    endpoints: vec![models::OboAuthorizationEndpoint {
        audience: "waveform".to_owned(),
        endpoint_id: "speech.generate".to_owned(),
    }],
}, &Mutation::new()).await?;
// Open request.authorization_url in IAM for the represented user.
// Save request.id; application.obo().authorization(request.id) reads status.
```

IAM shows the requesting app, user, organization and every requested root's full dependency tree. Approval creates a separate grant per root endpoint. Only a direct IAM user session may call `obo().consent(id)` and `obo().decide(id, decision, mutation)`; application credentials or app bearers cannot approve their own access. Send the displayed version with `OboConsentDecision`. A stale graph must be reviewed again. Optional `contexts` select a direct IAM account token and organization per provider; omitted providers use the root context. Direct account credentials stay inside IAM clients, never the requesting app. With a bound callback, validate returned state/request ID, clear the code from the URL and redeem it on the application server; status polling never returns it.

## Redeem the approved code

```
let exchange = Mutation::new();
let issued = application.obo().exchange_code(
    request.id, "<code copied after IAM approval>", &exchange,
).await?;
for token in issued.items {
    // Store token.access_token and token.refresh_token with their grant/endpoint binding.
}
```

Code exchange returns `OboTokenResponse` with one `OboTokenPair` per root endpoint and organization. Refresh through `obo().refresh(refresh_token, mutation)`; this returns a single replacement pair and rotates the refresh token. Keep one refresh in flight per family, and retain one mutation key for an uncertain identical retry. Neither refresh nor replay can expand endpoints or extend an already issued token's original expiry.

## The receiver verifies each request

```
let receiver = Client::new("https://backend.iam.teamofsilicons.com")?
    .with_credential(Credential::application("waveform", "<receiver secret>"));
let verified = receiver.obo().verify(&models::OboTokenVerificationRequest {
    access_token: incoming_access_token,
    endpoint_id: "speech.generate".to_owned(),
    request: models::OboTokenRequestBinding {
        method: "POST".to_owned(),
        path: "/v1/speech".to_owned(),
    },
}).await?;
// Validate payload, metadata, and the represented user's resource permissions.
// verified.authorization carries only current, permitted self disclosures.
```

Verification is reusable and accepts no mutation key. It may be repeated after a transport failure, but execute only after receiving current success. Tokens do not bind body hashes; the receiver enforces resource permissions, metadata validation and operation deduplication. The result includes the immediate `issuer_app_id`, `originating_app_id`, user, organization, endpoint and chain.

## Call any approved graph endpoint

The same access token works at every approved endpoint in the root graph. Forward it to the next declared provider; that provider calls `obo().verify(...)` with its own credentials and exact endpoint/method/path. The result returns the provider's selected account and organization. Only the originating app holds the refresh token.

`obo().delegate(...)` is a compatibility edge check and returns the same access token, without a child credential. It does not broaden the graph. Newly requested dependencies require fresh consent.

## Direct IAM consent clients

Render each recursive endpoint’s optional `iam_disclosures` list beside its selected account and organization. The supported values are `self.identity.read`, `self.membership.read` and `self.tags.read`. Reject unknown or malformed values rather than hiding requested information. After the user reviews and approves these disclosures, set `OboConsentDecision.iam_disclosures_reviewed` to `Some(true)`. Missing acknowledgement fails closed when any endpoint has disclosures. Graph or approval changes require a fresh displayed version. These additive consent fields do not change application authorization, token exchange or receiving-provider verification requests.

## User control and migration

With a direct IAM user client, use `obo().grants()` to review the first page of up to 10 grants, `obo().grants_page(&Paging::new().after(cursor).limit(10))` to continue with `page.next_cursor` while `page.has_more` is true and `obo().revoke(grant_id, mutation)` to end the root and all descendant authority. Ordinary logout and session expiry preserve durable consent. Grant revocation and current membership, app, organization or graph changes stop access; account/app security resets invalidate issued credentials. Access uses the shortest graph endpoint TTL, while the rotating refresh family follows the durable grant lifetime. Recover unchanged grants with `obo().recover(grant_id, subject_token, mutation)` using a fresh originating account/app login. Another selected account's security reset requires renewed approval from that account. Requests and tokens remain isolated to their testing environment and generation.

The old proof-signing/exchange SDK methods are retired. Earlier login consent is not converted into a new grant. Migrate callers and receivers together to `authorize`, `exchange_code`, `refresh`, `verify` and, when declared, `delegate`. See the HTTP OBO contract (`iam docs api/obo`) for the complete lifecycle.
