# Cross-application session refresh audit — 22 September 2026

## Release state

The preceding IAM App Verification change is deployed and live-verified. See
[its deployment receipt](deployment-verification-2026-09-22.md).

The session repairs are now deployed to the affected backends and browser
gateways, and updated CLI packages are published. The final versions and receipts
are listed below. Local activation and final retained-session checks remain
partially blocked by a macOS Documents privacy prompt; these limits do not imply
that the production rollout or package publication is pending.

IAM backend 3.0.1 also fixes a sibling-family revocation defect discovered during
live verification. A production probe with automatic refresh disabled confirmed
that logging out one app family leaves a sibling family under the same IAM
parent session authenticated. See the [backend receipt](oauth-family-revocation-2026-09-22.md)
and [IAM CLI/web receipt](cli-web-session-release-2026-09-22.md).

## Final deployment and publication matrix

Source revisions below identify the deployed runtime separately from later
CLI-only patches. GitHub assets, Honeycomb production packages and crates.io
artifacts were verified unless a limitation is explicitly listed.

| Application | Deployed runtime / browser source | Published CLI | Retained-session evidence and receipt |
| --- | --- | --- | --- |
| IAM | Backend **3.0.1**, `ae6ceb3`; web `9b64a49`, Vercel Ready on both domains | **3.1.1**, `9b64a49`; SDK remains 3.1.0 | Maharaj identity retained; existing Carbon browser retained across frontend deployment; production same-parent family logout isolation passed. [CLI/web](cli-web-session-release-2026-09-22.md), [backend](oauth-family-revocation-2026-09-22.md) |
| Honeycomb | Web `fe028a8`, image `510f221b1592adedc92806dffcb2558c832c23dcb9765374f0c9ea1725cded29` | **0.3.2**, `3be8bb3`; all six native targets and full CI passed | Same web cookie and 13 app reads survived restart; installed global CLI and daemon 0.3.2 retained the original login. Fresh anonymous install passed. [Receipt](https://github.com/teamofsilicons/silicon-honeycomb/blob/0c18cea/deploy/aws/release-2026-09-22-session-retention.md) |
| Briefcase | BFF **1.1.1**, `e33e20a`, image `7a672f0a89cf946d122d884e1db904a27b179e1417cc47208605eca9c1ca5299`; API/worker unchanged | CLI/client **1.1.2**, `2e3a542`; all six native builds, package validation and general CI passed | Durable private store, restart/logout and three real entries passed; final Maharaj 1.1.2 activation pending. [Receipt](https://github.com/teamofsilicons/silicon-briefcase/blob/51f3d28729d983eedab85cc26b596b35bada73f7/deploy/base-tier/release-2026-09-22-sessions.md) |
| Browser | Existing frontend unchanged; audited session behavior verified | **0.2.5**, `0680f1d`, tag `managed-v0.2.5`; all six native builds passed | Maharaj 0.2.5 authenticated status and profile listing passed; GitHub/Honeycomb and fresh anonymous install verified. crates.io publication blocked by owner-permission 403. [Receipt](https://github.com/unlikefraction/silicon-browser/blob/d21551a/docs/SESSION_RETENTION_RELEASE_2026_09_22.md) |
| Commit | Frontend **0.2.4**, `91ef108`, Vercel `dpl_GRu72n9P1zU2mTqnWvxnBZadQyy1`; backend unchanged | CLI/client **0.2.5**, `85cd0a0`; all six native builds, package validation and general CI passed | Browser renewed after 1,211 seconds and read four todos; Maharaj original family recovered without login and read four todos/zero projects before the final IAM rollout. Carbon live family-isolation probe subsequently passed. [Receipt](https://github.com/teamofsilicons/silicon-commit/blob/5981f3d24b5dac3e6ba88368c9f169040c836742/deploy/aws/verification-2026-09-22-sessions.md) |
| DM | Backend/web `7fffb88`, API/worker task definitions 18; backend **0.9.5** | CLI/client **0.9.6**, `1e275d3`; protocol remains 0.9.5 | Initial deployed CLI/daemon 0.9.5 retained identity and conversation/queue reads; final Maharaj 0.9.6 activation pending. [Receipt](https://github.com/teamofsilicons/silicon-dm/blob/9f66fa3157b5adcf83aec64902f43ab407823590/deploy/verification/session-release-2026-09-22.md) |
| Hook | Native API/worker and gateway `dc9c2e3`; native backend package remains 0.7.0 | CLI **0.7.3**, `cd91afc`; SDK 0.7.2 | Initial 0.7.2 retained identity and resource reads through daemon restart; final Maharaj 0.7.3 activation pending, existing daemon left running. [Receipt](https://github.com/teamofsilicons/silicon-hook/blob/be1473c3839621ce7bb4a1df7e7d45ae152c7a25/deploy/verification/session-release-2026-09-22.md) |
| Remind | Backend/frontend `a37ddc6`; existing session volume/key retained | CLI **0.3.2**, `90c32a3`; SDK 0.3.1 | Initial deployed version passed retained resource reads; latest Maharaj package installed, final authentication check blocked locally. [Receipt](https://github.com/teamofsilicons/silicon-remind/blob/c72a1e51ecf6b3e5baa4f712c4e888798856c98f/deploy/verification/session-release-2026-09-22.md) |
| Waveform | Native backend **0.3.1** and frontend **0.3.2**, source `0435ac6`; frontend image `9ed21c3d4e8e75038fc091963d0545f936884679bdf873a260a04de6cc6d94bf` | CLI **0.3.3**, `c475f0e`; all six native builds and full CI passed | Normal web login, refresh, same-cookie restart and jobs reads passed; latest Maharaj package installed, final authentication check blocked locally. Fresh anonymous install passed. [Runtime receipt](https://github.com/teamofsilicons/silicon-waveform/blob/0333051/docs/session-retention-deployment-2026-09-22.md) |
| Interface | Gateway/frontend `bc47691`; gateway image `7bc107971c144f3409a8a9dceed148acb8dc904e78bd020c04730ef3b1ae3618` | Not applicable | Normal Carbon login and workspace reads survived gateway restart with the same cookie; disposable test family logged out. [Receipt](https://github.com/teamofsilicons/interface-web/blob/e4ad33f/deploy/session-retention-2026-09-22.md) |
| Stemcell | Delegates authentication to the installed app CLIs | No independent auth release needed | Delegated-auth tests passed; no independently stored refresh token |

DM, Hook and Remind final releases passed all six native builds, full CI,
checksum verification and fresh anonymous installation. Briefcase and Commit
also passed fresh anonymous installs. Detailed release receipts record immutable
artifact hashes, Honeycomb release IDs, host/container changes and recovery
assets.

## Remaining local verification limits

- A pending macOS `SystemPolicyDocumentsFolder` privacy request from the
  standalone Honeycomb helper blocked Documents file opens. Briefcase 1.1.2,
  DM 0.9.6 and Hook 0.7.3 remain published but not activated in Maharaj. Remind
  0.3.2 and Waveform 0.3.3 were installed; their final retained-authentication
  checks remain pending. No TCC reset, permission bypass or replacement login
  was used. Existing running daemons were preserved when safe verification was
  unavailable.
- IAM, Browser and Commit retained-session checks passed before the final IAM
  backend rollout. The final original-Maharaj-token probe was excluded because
  the same filesystem block prevented reading its saved session. The deployed
  IAM isolation probe used two disposable Carbon app families through ordinary
  Commit APIs, with automatic refresh disabled: both began at 200; logout of
  the first changed only that token to 401 while the sibling stayed 200; logout
  of the sibling then changed it to 401. Both test families were cleaned up.
- The existing Carbon browser login survived the IAM frontend deployment. A
  further browser reload after the final backend rollout was blocked by an
  unavailable browser policy check, which was not bypassed.
- Browser 0.2.5 is available through verified GitHub and Honeycomb native/source
  distributions. Publishing its crate requires crates.io owner authorization;
  the attempted publish returned 403.

## Diagnosis

Production IAM evidence showed a 1,800-second access-token lifetime and a
77,760,000-second (900-day) refresh-family lifetime. These are different from
short-lived login handoff codes and App Verification keys. No evidence showed
that the new verification feature shortened user sessions.

The audit reproduced several independent client defects:

- Honeycomb CLI status skipped refresh; CLI and daemon could rotate the same
  saved token with different mutation keys. A consumed token reused under a
  different key can legitimately trigger IAM family-reuse protection.
- Interface and Briefcase browser sessions existed only in process memory and
  had an eight-hour cutoff. Waveform also used a process-only session map.
- Several clients treated a replayed `expires_in` as a fresh lifetime. The
  response describes the original token, so retries must retain the original
  request time or conservatively account for the maximum replay window.
- Some browser gateways treated temporary refresh/identity lookup failures as
  sign-out. Several backend IAM adapters also collapsed app configuration
  errors such as `invalid_client` into user-session rejection.

Live release verification also found an IAM server defect: app-family logout
and refresh-reuse handling revoked every access token for the same parent
session/application, even when other refresh families remained active. Migration
0116 links application access tokens to their exact refresh family; backend
3.0.1 scopes revocation to that family. The migration backfilled uniquely
identifiable valid tokens, rejected ambiguous live data, and preserved existing
credential values across both databases. All old runtime writers were paused
before migration and all three containers were replaced before writes resumed.

Final CLI patches also add bounded recovery for unexpectedly rejected access
credentials where needed. An active saved refresh family can renew access without
a new login; a genuinely revoked refresh family is not resurrected. Hook's
daemon performs normal expiry renewal; an ambiguous early subscription rejection
can require an authenticated CLI command or `hook login status`, after which it
reloads the saved successor within five seconds.

These are reproduced failure paths, not proof that every one occurred during
this user's reported incident. IAM's refresh-reuse protection remains enabled.

## Coverage

| Application | CLI/session owner | Browser/session owner |
| --- | --- | --- |
| IAM | Persist original refresh time with retry key; save successor before bounded recovery; keep actor and testing context | Deterministic single-flight refresh; conservative 600-second replay bound; one exact request retry on stale access; preserve session on generic request errors |
| Honeycomb | Refresh status, coordinate CLI/daemon/login/logout under process locks, persist retry key/time and credentials | Existing encrypted SQLite retained; durable refresh receipt, transient failure retention, stale-access recovery |
| Briefcase | Persist retry start, bounded successor recovery, existing context isolation retained | Durable private session storage, restart recovery and regular-session lifetime repair |
| Browser | Status refreshes instead of reporting outages as signed out; adopt concurrent renewal only for same login | Existing absolute-expiry, single-flight, tab-session persistence and testing isolation verified; no frontend change needed |
| Commit | Persist original retry timing and rotated credential recovery | Preserve transient failures, evict failed refresh promise, retry stale access with unchanged mutation, correct test-login deadline |
| DM | Persist retry timing in local client/CLI runtime | Persist original retry time across restart and organization siblings; existing HTTP/WebSocket recovery and durable storage verified |
| Hook | Persist retry timing in CLI owner | Recover delayed replay through successor; retry stale access once with unchanged mutation key/body; existing encrypted storage retained |
| Remind | Persist retry timing and bounded recovery | Save retry timing before exchange; preserve identity on outage; renew browser cookie on activity; retry stale access; atomic synced writes |
| Waveform | Persist retry timing and bounded recovery | Durable encrypted session store and original refresh receipt; restart, expiry and concurrency repair |
| Interface | No independent CLI | Encrypted durable store; regular-session lifetime aligned with IAM; rolling browser cookie; testing/demo limits retained; persisted retry receipt and successor credentials |
| Stemcell | Delegates auth to installed app CLIs; no independent refresh token | Not applicable |

DM, Hook, Remind and Waveform backend adapters now keep explicit invalid-grant
or token-reuse rejection separate from configuration, provider and unknown
errors. CLI SDKs remain stateless where designed; application session owners
perform renewal and persistence.

## Validation

The counts below record the original repair phase. Subsequent release CI and
additional early-access-rejection regressions passed as documented in the final
release receipts. IAM backend 3.0.1 passed 403 library tests, actual database
issuance/logout/reuse containment and historical-backfill regressions in both
runtime planes, workspace Clippy/format/grant checks, and the complete CI
PostgreSQL/restricted-runtime suite. Its dual-database restore rehearsal and
paused-writer live migration passed; public version/readiness/auth-denial checks
passed on both APIs. CloudFormation and launch template version 49 pin the new
image. Temporary rollout permissions and ASG protections were restored.

- IAM CLI: 52 unit tests plus 11 integration tests; CLI Clippy with warnings
  denied; frontend 47 tests, typecheck and production build; embedded manuals
  regenerated and checked.
- Honeycomb: 13 CLI tests, 12 web tests, Clippy, typecheck/build and two browser
  auth/concurrency/sign-out journeys.
- App CLI suites: Briefcase 56, Browser 56, Commit 18, DM runtime 12, Hook 10
  CLI plus 3 client, Remind 15 and Waveform 22; scoped Clippy checks passed.
  Stemcell's two delegated-auth tests passed.
- Browser frontend: all 33 existing tests and production build passed.
- Commit frontend: 19 tests, typecheck and production build passed.
- DM web: 41 tests, including HTTP, realtime, test isolation and persistent
  rotation across restart; typecheck/build passed.
- Hook web: eight tests, including exact mutation replay and expired cached
  response recovery; typecheck/build passed.
- Remind web: four tests, including outage/restart/retry-key recovery;
  typecheck/build passed. The recovery test also preserves the selected
  organization through a failed renewal and gateway restart.
- Backend classifier regressions: Remind IAM five tests, Hook IAM ten, DM and
  Waveform table-driven mapping tests; each library Clippy check passed.

Briefcase web: all 14 tests and Clippy passed. An isolated `git archive` of
commit `b7530e7` also passed all 14 tests with its committed Cargo.lock and
`--locked`, independently of the user's preexisting working-tree changes.

- Interface: all 340 tests, production build/typecheck and full formatting check
  passed. Storage/deployment received independent review. Tests include abrupt
  process death, disk-write failure, uncertain response replay, logout races,
  test isolation, legacy receipts, and recovery after two-day grant outages.
- Waveform frontend: all 40 tests, production build/typecheck, Node syntax and
  Python installer compilation checks passed. Tests cover encrypted restart
  persistence, production/test isolation, delayed concurrent access rejection,
  logout races, malformed responses and disk-write failure.
- Interface and Waveform commit a validated refresh response before secondary
  identity/grant lookups. A lookup outage can therefore outlast IAM's response
  replay window without losing an already received successor. If verification
  rejects its access token, one bounded successor renewal is attempted;
  repeated rejection preserves the receipt and returns a retryable error.

## Rollout constraints

- Interface, Briefcase and Waveform cannot reconstruct credentials from the
  previous version's process-only session maps. Their first upgrade may need
  one fresh sign-in; subsequent restarts retain the new durable sessions.
- Keep session directories, keys and database/files together across releases.
  Updated deployment configuration mounts stable private storage. Do not run
  concurrent owners against stores designed for one gateway process.
- Production and testing credentials remain isolated. Interface demo/testing
  sessions retain their bounded lifetime and are not recovered as regular
  production sessions after restart.
- Browser's existing static frontend persists its interactive session per tab
  in sessionStorage, surviving reloads but not a closed browser session.
- A refresh reply lost beyond IAM's bounded secret replay window cannot be
  recovered by inventing a new key for the consumed token. Such ambiguous
  failures preserve the receipt and report an error; reauthentication may be
  required. Revocation, lost local storage and browser cookie deletion can
  also require sign-in.
- Human-owned UNDERSTANDING files and preexisting unrelated changes were
  preserved. This work adds no telemetry or Space Station features.

## Source commits

| Repository | Original repair commits |
| --- | --- |
| IAM | `be96276` |
| Honeycomb | `ee0fd81` |
| Briefcase | `1f78bc4`, `88bff43`, `b7530e7` |
| Browser | `5d0c539` |
| Commit | `f25ab87`, `d238828` |
| DM | `ab035b6`, `1998096`, `e4b7eba` |
| Hook | `a0b5ca6`, `8ca2332`, `e1ee0e3` |
| Remind | `02a6c3c`, `8ae68b9`, `ac53374`, `9832029` |
| Waveform | `00836c9`, `bb2dd78`, `153f266` |
| Interface | `846ea8e`, `45a87fe` |
| Stemcell | Audited without source changes |
