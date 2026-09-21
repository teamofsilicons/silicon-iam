# Cross-application session refresh audit — 22 September 2026

## Release state

The preceding IAM App Verification change is deployed and live-verified. See
[its deployment receipt](deployment-verification-2026-09-22.md).

The session repairs described here are local source commits with regression
checks. They have not yet been published as updated CLI packages or deployed to
production. Existing installed binaries and deployed gateways do not acquire
these changes merely because the repositories have been fixed.

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

| Repository | Local repair commits |
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
