# OBO token cutover checklist

Status: **coordinated production cutover pending**. As of 2026-10-02, IAM,
Honeycomb caller/receiver integration, and the Briefcase JSON receiver adapter are
implemented locally. This is not evidence of a deployed consumer release.
Waveform, DM, Ting and Commit are also implemented locally as of 2026-10-03.
Extend, Hook and Browser are implemented locally with their protocol and frontend
checks complete. Verify release revisions and deployed configuration before scheduling
a cutover; the coordinated production deployment remains pending.

## IAM release boundary

- [ ] Apply the complete ordered IAM migration set, including
  `0122_chained_obo.sql` (dependency graphs) and `0124_obo_token_grants.sql`
  (separate consent), `0128_durable_obo_graph_permissions.sql` (durable graph
  grants and shared tokens), `0129_ata_catalog.sql`, `0130_ata_verification_credentials.sql`,
  and `0134_single_organization_application_login.sql` plus
  `0138_obo_bound_callbacks.sql`. Apply every matching testing overlay,
  including `9020`–`9023`, `9029`, `9031` and `9032`. Selected provider identity
  and organization metadata require `0140_obo_selected_provider_metadata.sql`; explicit per-provider IAM disclosure consent requires `0141_obo_provider_disclosure_consent.sql`. The latter revokes older OBO grants for fresh review. These do not replace
  intervening migrations. Deploy matching runtime grants, API, frontend and SDK.
- [ ] Verify ordinary app and bundle login discloses only IAM scopes. A previous
  login consent, old proof or trusted-organization exemption **cannot be converted
  into an OBO grant**. Users must explicitly approve the separate full graph.
- [ ] Treat legacy `POST /api/v1/obo-access/exchanges`, `/chained-exchanges` and
  `/verify` returning `410 obo_proof_flow_retired` as a breaking cutover. Existing
  application login tokens are not reusable OBO credentials.
- [ ] Verify new consent review at `/obo/consent?request=<id>`, user grant review
  and revocation, and browser gateway restrictions. Approval returns a single-use
  code. An authenticated app can bind an exact `redirect_uri` and opaque `state`
  when it creates the request; approval/decline then returns that callback. HTTPS
  is required except loopback HTTP, and credentials/fragments are rejected.
  Only that same app can redeem the code. IAM currently follows the SLT model
  of app-authenticated callback binding; it has no global redirect-URI allowlist.
  Honeycomb separately validates its configured web origins and fixed callback
  path, and checks state on completion.

## Provider disclosure review

Each OBO endpoint displays `iam_disclosures`, bounded to `self.identity.read`,
`self.membership.read` and `self.tags.read` and intersected with every app's
current declarations and approvals along its path. Consent binds this set to the
selected provider account and organization; the originating login does not supply
another account's disclosure consent. The direct IAM browser/CLI must review this
information and send `iam_disclosures_reviewed:true` (CLI:
`--approve-iam-disclosures`) when any node requests disclosures. Older clients fail
closed. Changed scope declarations or approval records require another review;
legacy grant snapshots are never silently upgraded. Receiver verification wire
contracts remain compatible, including the minimum actor and organization context
needed to identify the delegated action. These optional self disclosures govern the
additional IAM authorization projection, not an anonymous OBO mode.

## Receiver migration status

Receiver adapters can migrate without adding their own consent UI or refresh
storage. On every delegated request, use app authentication to call
`POST /api/v1/obo-access/token-verifications` with
`{access_token, endpoint_id, request:{method,path}}`. Check the returned active
authority against the handler's endpoint, recipient app, subject, organization
and testing environment; retain application resource ACLs and idempotency.
Verification is repeatable and no longer consumes a body-bound proof. Do not
retain old proof-prefix, metadata or `consumed_at` assumptions. Update public
client credential types and transport documentation together with each receiver.

| Repository / code path | Current runtime and required work | Status |
| --- | --- | --- |
| Briefcase: `src/infrastructure/iam/official.rs::verify_obo`; `src/api/auth.rs::obo_credentials`; `src/api/handlers/{obo,delegated,delegated_upload,invitations}.rs` | Uses repeatable `/token-verifications` with `oba_` credentials in `X-IAM-OBO-Access-Token` for registered JSON endpoints. Normalizes verified authority into existing resource ACL checks. The legacy metadata-only `/api/v1/obo/files` stream is rejected; use reservation, separate byte-transfer capability, then commit. | Implemented locally; focused receiver tests pass, deployed integration pending |
| Honeycomb: `crates/server/src/auth.rs::verify_obo`; `crates/server/src/obo.rs`; `crates/client/src/lib.rs::organization_apps_obo` | Uses repeatable `/token-verifications` for `honeycomb.apps.list`, `POST /api/v1/obo/apps/list`, with `X-IAM-OBO-Access-Token`. A token can serve multiple pages while every request rechecks current authority. SDK helper uses the same header. | Implemented locally; nine receiver regressions pass |
| Waveform: `src/infrastructure/auth.rs::authorize_obo`; `src/api/headers.rs` | Repeated app-authenticated verification checks the exact TTS/STT endpoint, origin app, selected actor/org and testing world. Accepts `X-IAM-OBO-Access-Token`; retired proofs and mixed bearer credentials are rejected. SDK and CLI support incoming OBO. | Implemented locally; repeated verification and denial regressions pass, deployed integration pending |
| Ting: `crates/ting-server/src/auth.rs::proof` | Verifies reusable `oba_` tokens for the exact registered receiver endpoint and path; retains origin-app, actor, organization, recipient and testing checks. Retired proofs are denied. | Implemented locally; receiver and full server regressions pass |
| Commit: `src/api/auth.rs` and existing route/action authorization | Verifies `X-IAM-OBO-Access-Token` with the originating `X-App-ID`, exact endpoint and route template. Retains resource ACLs, member roles/tags and testing checks; no legacy-proof fallback. | Implemented locally; 154 library tests and strict Clippy pass. IAM0141 now binds explicitly reviewed disclosures to each selected provider account/org. Restricted-role production/testing regressions prove selected-account role/identity and fail-closed scope changes; receiver resource ACLs stay in place. Coordinated live verification remains pending |
| DM: `src/api/extract.rs::realtime_bearer` | Rejects inbound OBO. Its required migration is the outgoing Ting integration below. | No incoming OBO migration identified |

## Caller migration status

Each root caller needs an explicit user-facing authorization entry point, code
redemption and storage/rotation of dedicated OBO credentials bound to the exact
approved account and organization context per provider, and testing environment.
Consent survives ordinary logout; credentials still honor explicit revocation and
principal/application security epochs. Access tokens retain their endpoint-bounded
TTL; refresh families follow the durable grant lifetime, with no ordinary
180-day expiry. Recover an unchanged durable grant using
`{grant_id, subject_token}` with a current login as its original account and org.
A security reset on a separately selected account requires that account to approve again. The IAM APIs
are `POST /obo-access/authorizations` and `POST /obo-access/tokens` under
`/api/v1`. A new ordinary login is not a substitute for OBO approval. Handle
decline, expiry and revocation without silently authorizing work. Do not migrate
cached ordinary tokens into dedicated grant records.

| Repository / code path | Affected runtime workflows | Status |
| --- | --- | --- |
| Honeycomb: `crates/server/src/storage.rs::Briefcase::control` | Requests separate consent for `briefcase.uploads.reserve`, `briefcase.uploads.commit`, `briefcase.files.read` and `briefcase.link_access.update`. Server-side encrypted grant storage rotates credentials with persistent retry identity; rejected grants produce `storage_authorization_required`. Website popup and CLI manual-code flow preserve action retry keys. Calls use the selected Briefcase account/org, including byte transfer. Existing public-path downloads remain independent. | Implemented locally; seven broker/storage protocol regressions pass; live deployment pending |
| Waveform: `src/infrastructure/auth.rs::delegate_storage`; `src/infrastructure/briefcase_reader.rs`; `src/infrastructure/briefcase_sdk.rs` | Separate manual-code feature consent covers `briefcase.uploads.reserve`, `briefcase.uploads.commit`, `briefcase.entries.list` and `briefcase.files.read`. Encrypted plane/account/org-bound grant storage serializes refresh with persistent retry identity. Website, CLI and SDK expose start/status/complete; explicit speech retry preserves request IDs. Selected Briefcase actor/org is honored; reserve/capability byte-transfer/commit replaces the retired stream. Incoming chains reuse the verified access token. | Implemented locally; 197 backend/DB tests, 16 SDK tests, 24 CLI tests and 41 frontend tests pass; live integration pending |
| DM: `src/infrastructure/{ting_authorization,ting_enrollment,ting_publisher}.rs`; `src/api/ting.rs` | Explicit approval for `subscriptions.register` and `tings.send` replaces automatic enrollment and ordinary login-token authority. Website, CLI and SDK expose manual approval, status and local disconnect. Dedicated encrypted credentials preserve actor/org/test-generation binding, serialized refresh and revocation. Uncertain starts persist and replay the original encrypted body/key after current-login rotation. | Implemented locally; 146 Rust tests, 90 frontend tests, production/testing PostgreSQL broker tests, four native regression suites and strict Clippy pass; live integration pending |
| Ting: `crates/ting-server/src/auth/catalog.rs`; `web/src/CatalogConsent.tsx`; `ting apps authorize` | Separate `honeycomb.apps.list` consent; encrypted account/org/test-generation-bound credentials, manual code and state, repeatable catalog pagination, serialized refresh with stable retry keys, explicit invalidation. The selected Honeycomb context must match the Ting management workspace. Ordinary logout preserves consent; test cleanup clears it. | Implemented locally; full server suite and two broker protocol regressions pass; live integration pending |
| Hook: `src/infrastructure/iam/ting_grants.rs`; `src/delivery/publisher.rs`; `src/api/delivery.rs` | Separate actual-account approval covers `subscriptions.register`, `tings.send`, `sent.query` and testing-only `receivers.bootstrap`. Publisher and observer use their own typed actor/org/plane context. Website, CLI and SDK expose manual approval, status and disconnect; durable encrypted start/refresh requests preserve retry identity across login rotation and process restart. Reusable `oba_` transport retains receiver ACLs and operation idempotency. | Implemented locally; 328 workspace tests plus three doctests, 37 frontend tests/build, production/testing restricted-role grant lifecycle and strict Clippy pass. One existing external telemetry case remains opt-in; live integration pending |
| Extend: `crates/extend-service/src/obo.rs`; `/api/v1/permissions` | Encrypted server-side Briefcase/Ting permissions with website, SDK and CLI approval entry points. Storage uses selected provider context; notification approval preserves the original recipient. | Implemented locally; 45 service tests, 12 provider cases, 15 contract replays, real PostgreSQL grant lifecycle, four migration rehearsals, 174 frontend tests/build and synthetic browser recovery checks pass; live integration pending |
| Browser: `crates/backend/src/delivery_auth/obo.rs`; recording worker and Briefcase adapter | Separate manual-code approval binds encrypted dedicated tokens to the origin account/org/member and testing world. Website, SDK and CLI expose approval and recovery. Paid starts revalidate authority; reserve/capability transfer/commit uses the chosen provider actor/org and a pinned artifact destination. Legacy login-derived authority becomes revoke-only. | Implemented locally; 214 backend tests plus legacy-upgrade regression, 91 SDK/CLI tests, 39 frontend tests/build, strict Clippy and desktop/mobile recovery checks pass; live integration pending |

Honeycomb browser callbacks use `/storage-authorization` on an origin in
`HONEYCOMB_WEB_ORIGINS`; deployments must include each console/library origin.
The popup sends only completion identity/state to its opener. Access and refresh
tokens remain encrypted on the server. Manual CLI authorization omits the
callback, prints the consent URL, and completes with a code file and state.
Storage credentials are isolated by authenticated account, origin organization,
testing environment and generation; cleanup removes the corresponding rows.

For a downstream call made while serving incoming OBO, retain the verified
incoming access token and forward that same token to the approved downstream
receiver. Each receiver must authenticate its own application to IAM and verify
its exact endpoint; the verifier returns that provider's approved account/org.
`POST /api/v1/obo-access/delegations` remains a compatibility check and returns
the same token without a child credential. Declare every downstream endpoint in
the approved graph. Waveform retains incoming OBO only for the current request,
validates each downstream edge, and uses the selected provider metadata returned
by migration `0140_obo_selected_provider_metadata.sql`. Deploy that migration and
matching SDK models before enabling these chains.

ATA uses separate `ata_` access and `atr_` refresh credentials. The originating
application alone rotates its refresh token at `/api/v1/ata-access/tokens`; each
allowed recipient authenticates itself and verifies the shared access token with
`{app_id, app_proof_token, endpoint}` at `/api/v1/ata-access/verify`. ATA never
produces a user identity or authorizes OBO. Honeycomb manages the endpoint graph,
recipient allowlist, expiry, access TTL and immutable signer audit. Root or provider
app security changes, endpoint changes, and explicit revocation invalidate proof.

Application SLT login now requires exactly one organization and binds both access
and refresh credentials to it. Migration `0134` revokes older unscoped application
credentials and their consent; users choose an organization on their next login.
Direct IAM account login remains available before first-organization setup.

## Local verification and coordinated release gate

Local tests cover production/testing IAM grants, refresh races, cross-account
context proofs, graph changes, callback redemption, security epochs and directory
transport. Honeycomb tests exercise storage authorization, encrypted credentials,
uncertain refresh retry, selected provider org, and recipient revalidation.
Briefcase focused receiver tests exercise repeatable verification, recipient
authentication and denial paths. These protocol tests do not prove a real
IAM → Honeycomb → Briefcase deployment, external storage, or the remaining coordinated consumer deployments. Waveform real-DB tests cover
feature consent, encrypted refresh/revocation, plane isolation, and source-resource
revalidation; mocked upstreams do not prove live IAM/Briefcase or paid speech providers.
Browser's SQLite/protocol regressions cover immutable consent origin binding,
encrypted refresh uncertainty/concurrency, test-world isolation, delayed rejected
credentials after reapproval, paid-start revocation, selected storage context and
lost commit responses without another upload/version. Its `0009` upgrade keeps
existing receipt/job ownership while retiring old delivery families. Deploy the
matching Browser API, website, SDK/CLI and Briefcase receiver together; preserve
the encryption key and verify real Carbon/Silicon recordings after deployment.

DM's `0038_ting_separate_authorization.sql` removes the legacy ordinary-token
cache and adds dedicated encrypted grants and pending starts; existing message and
receipt data stay intact. Hook's `0018_ting_separate_authorization.sql` adds private
grant/start tables, runtime grants, generation fences and testing cleanup. Both
brokers now prove uncertain-start recovery after login rotation, stable refresh
retry, explicit revocation and account/organization isolation in production and
testing fixtures. Ting receiver tests verify the same access token repeatedly and
reject revoked or retired proof authority. Hook's standalone `scripts/ting_e2e`
helpers use the new consent protocol, but their historical published artifact pins
must be replaced by the coordinated releases before running them as live evidence.

- [ ] Update each consumer's pinned/vendored IAM SDK and any Briefcase client
  credential types; compile and test against the same IAM contract revision.
- [ ] Register and approve actual endpoint dependencies, including all branches,
  before testing user consent. Reject cycles and stale or broadened graphs.
- [ ] Run real IAM-to-consumer tests for separate approval/decline, code exchange,
  repeated endpoint calls, refresh rotation/reuse, wrong app/endpoint/org denial,
  ordinary logout preserving OBO consent, security resets invalidating credentials,
  and explicit grant/member/app revocation stopping the full graph.
- [ ] Exercise `412` on a changed pending graph, reload the fresh graph/version,
  review it and explicitly approve again. Browser fixture tests alone do not
  establish the database refresh behavior.
- [ ] Test production and isolated testing-plane credentials, including propagated
  testing context and environment reset. Retain each app's resource authorization
  and transfer-capability boundaries.
- [ ] Coordinate API/consumer deployment and user reauthorization. An IAM-only
  production deployment breaks the old integrations; do not declare cutover
  complete until deployed consumer workflows pass these checks.
