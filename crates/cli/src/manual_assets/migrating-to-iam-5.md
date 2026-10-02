# Updating an application for IAM 5

This guide describes the IAM 5.0.0 and Honeycomb 0.6.0 integration contracts. The documentation is being published before the coordinated runtime rollout. Until the documentation's release notice says otherwise, production still serves the previous APIs. Prepare and test your changes now; switch production callers and receivers together when the new runtime is available.

For a broader product guide, read [Building a Team of Silicons-ready application](https://docs.honeycomb.teamofsilicons.com/guides/team-of-silicons-ready-applications/). This page focuses on changes an existing application needs to make.

## Start from the versioned contract

Use the [OpenAPI document](/openapi.yaml) for exact bodies and response types, and the [Rust client guide](/client/guide/) for the SDK. While the crates.io release is pending, the reviewed SDK candidate can be pinned directly:

```toml
silicon-iam-client = { git = "https://github.com/teamofsilicons/silicon-iam", rev = "52dd5ea7d48571e29e3b79371dfc27405644fbd9", version = "5.0.0" }
```

After 5.0.0 is published, use the registry dependency with the same version. Installing the current public CLI does not opt a production backend into the new protocol. Check [the running backend version](https://backend.iam.teamofsilicons.com/api/v1/version) when coordinating your deployment.

## Keep login bound to one account and organization

Continue sending the user to IAM and exchanging the returned short-lived token on your application's server. Keep your application secret on that server and bind the callback to the login attempt. Your application receives an application session, not the user's IAM password, Silicon STK, OTP, or direct IAM account token.

Every application login selects exactly one Carbon or Silicon account and one organization. An application that supports several organizations should retain separate sessions for those contexts and show an explicit context switcher. Keep caches, data queries, permission checks, background tasks and outgoing requests bound to their originating session. Do not combine several organizations into one IAM token.

Read the [login integration](/client/login/) and [organization consent contract](/organization-consent/). Older unscoped application credentials are revoked during the rollout; handle reauthentication as a normal user flow and ask the user to choose an organization again. Do not infer OBO authority from an ordinary login or an old consent record.

## Move OBO consent into the feature that needs it

An application asks for OBO when the user starts a feature that requires another app. For example, opening a speech-generation feature may require Waveform and its declared storage dependency. Ordinary login remains usable if the user declines that feature's OBO request.

The caller implements this lifecycle:

1. Register the root provider endpoints it uses in Honeycomb. Providers declare their complete downstream endpoint graph, notes, metadata and warnings. Required provider approvals must be effective before user consent.
2. Authenticate to `POST /api/v1/obo-access/authorizations` with the caller's application credentials. Send the current application `subject_token`, its `org_id`, and the requested `{audience, endpoint_id}` roots. Use an idempotency key.
3. Open the returned `authorization_url` in IAM. Only the represented user can approve. IAM shows the complete graph and lets the user select a provider account and organization. The application never collects those providers' direct account tokens.
4. Complete either a bound callback or a manual code flow. For a callback, supply `redirect_uri` and a 32–512-byte `state` together, then validate the returned state and authorization request ID. Redeem the one-use code on your server at `POST /api/v1/obo-access/tokens`.
5. Store each returned root's OBO access/refresh pair separately from ordinary login credentials. Persist its grant, endpoint, account, organization, testing environment and generation binding.
6. Serialize refreshes per token family. Refresh at the same token endpoint and save the replacement pair atomically. After an uncertain response, retry the identical request with the same persisted idempotency key.

The response can contain several root token pairs. Each root's access token covers that root's approved dependency graph. It does not grant every unrelated root or endpoint. The root application alone retains the refresh credential.

The [HTTP OBO reference](/api/obo/) includes complete request examples, expiry semantics and errors. The [SDK OBO reference](/client/obo/) shows `authorize`, `authorization`, `exchange_code`, `refresh`, `verify`, `recover` and grant management.

## Update every OBO receiver

Replace consumed, request-bound proofs with reusable access-token verification. On every incoming operation, authenticate to IAM as the receiving application and call `POST /api/v1/obo-access/token-verifications` with the incoming `access_token`, the handler's registered `endpoint_id`, and its actual request method/path.

Check the returned recipient, endpoint, originating app, selected account and organization before enforcing your own resource ACLs and payload rules. A successful token check does not permit access to every resource in an organization. Undisclosed roles or tags grant no authority; do not substitute the originating account's permissions for another selected provider account.

Verification does not consume the token or bind a payload hash. It is safe to verify again, but an application must still deduplicate its own writes with operation idempotency. On a declared downstream call, forward the same access token. The downstream receiver verifies its own endpoint using its own app credentials. Never forward the refresh token.

The retired `POST /api/v1/obo-access/exchanges`, `/chained-exchanges` and `/verify` routes return `410 obo_proof_flow_retired` after cutover. Earlier login consent and old proofs are not converted to new grants. Coordinate both sides of each integration before using the new production protocol.

## Make decline, revocation and retries usable

Keep the user's draft or pending action while they review permissions. A decline should return them to that action with a clear explanation. A changed consent graph returns `412`; load the new graph and let the user review it again. Rejected or revoked OBO should prompt a new permission flow without silently signing the user out of your application.

Ordinary logout and session expiry preserve durable OBO consent. Explicit grant revocation, security resets and current membership, app or graph changes can invalidate credentials. Check current authority for every provider operation. Keep the original resource destination and operation key through retries; a refresh or account switch must not silently move an upload to another organization.

## Use ATA for application authority

Configure `ata_endpoints` within each application in Honeycomb. Create and manage verification records from the central **App to App** page, or list your records with `honeycomb apps ata list`. The source application, reviewed recipient list, endpoint dependency graph, immutable signing account, verification expiry and access-token lifetime are part of the record.

The originating app stores the once-revealed refresh credential. It obtains and rotates proof through Basic-authenticated `POST /api/v1/ata-access/tokens` with `{refresh_token}` and an idempotency key. Each receiving app verifies with its own credentials at `POST /api/v1/ata-access/verify`, sending `{app_id, app_proof_token, endpoint}`. Here `app_id` is the originating app and `endpoint` is the exact registered recipient path.

Success returns `{verified: true, valid_till: ...}`; `valid_till` is a UTC `YYYYMMDDHHMMSS` integer. Invalid proof, unapproved recipient or unauthorized endpoint returns `{verified: false}`. ATA never represents a user and cannot become OBO anywhere in its chain. See [the ATA contract](/api/applications/#app-to-app-verification-ata) and [Honeycomb's endpoint configuration](https://docs.honeycomb.teamofsilicons.com/scopes-and-obo/).

## Test and publish the integration

Use an isolated testing environment with all required apps and dependencies. Carry the environment and cleaning generation through authorization, token storage, provider verification, webhooks and resource access; never fall back to production when a testing lookup fails. Exercise both Carbons and Silicons, and keep the CLI capable of completing the same authorization flows as the website.

- [ ] Login supports Carbon and Silicon accounts and selects exactly one organization.
- [ ] Multiple contexts have separate sessions and isolated caches, requests and jobs.
- [ ] OBO is requested by the feature, and decline preserves the pending action.
- [ ] Endpoint dependencies, warnings and provider approvals match the actual calls.
- [ ] Callback state, request ID and single-use code redemption are validated.
- [ ] Refresh is serialized, encrypted at rest, and retries preserve their original key.
- [ ] Receivers verify every call and enforce selected-context resource permissions.
- [ ] Repeated calls, wrong endpoint/app/org, graph changes and revocation are tested.
- [ ] Ordinary logout does not silently erase durable consent.
- [ ] ATA remains application authority and cannot enter a user OBO path.
- [ ] Production and testing credentials cannot cross, including after environment cleanup.
- [ ] Webhook signatures and retry deduplication are verified.
- [ ] CLI, SDK, website, metadata and versioned documentation describe the same contract.
- [ ] Callers and receivers are deployed together, then the real integrated flow is verified.

Publish the version through [Honeycomb's release and review workflow](https://docs.honeycomb.teamofsilicons.com/publication/). A permission-expanding release stays private until its required approvals complete; an upload alone does not make it the public update.
