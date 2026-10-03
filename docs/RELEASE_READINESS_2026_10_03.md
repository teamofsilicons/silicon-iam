# Release readiness — 3 October 2026

This is an implementation and operator evidence record, not a change to the
human-owned requirements. Cloud observations were read-only, using the
`silicon-production` AWS profile and the existing Vercel login. No release was
published, production process restarted, production database changed, or active
preview replaced during this inspection. Secret values were not printed.

## Current production and rollback references

All service images below are ARM64. Keep these immutable references alongside
the configuration and database backups for the eventual release.

| Service | Running source revision | Current image digest |
| --- | --- | --- |
| IAM API, scoped API, worker | `433665db296d4cdb26b846e2db97ede81066bf09` (build `4.0.0`) | `sha256:2d42eae89fd2b0cd9f1eda8d8f3d38643ffcc9c604c846537bda2ba97a6bb2c8` |
| Honeycomb backend | `7403c6d76083d0ad89c1ae64d97f6f7583bfd826` | `sha256:009de491ec6530a49edb8207883630edcdb09407c2931b64c82d4074bcd10ee6` |
| Honeycomb library and console gateways | `0043b11b6e0d511433c339281bfeefdf96b58d6a` | `sha256:e5f345335d0df175d1bcc1138d5066f7e2a27d1d92329c28c5c116d6435ef561` |
| Briefcase API and worker | `2e6ffefec98daca6e10f199faff0ad3f294dcd50` (`2.1.0`) | `sha256:ff6c5395b6ac8c8dbf46bb90eba3484c0cad0a57bc042fdede92936b4300a17f` |
| Briefcase browser | `2e6ffefec98daca6e10f199faff0ad3f294dcd50` | `sha256:e36573451d34baade59f200c78fd32013d2693190bb4f2223afa163b98cac478` |

Image repository prefixes:

- IAM: `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production`.
- Honeycomb backend: `234951665042.dkr.ecr.us-east-2.amazonaws.com/silicon-honeycomb-backend`.
- Honeycomb gateways: `234951665042.dkr.ecr.us-east-2.amazonaws.com/silicon-honeycomb-web`.
- Briefcase API, worker and browser: `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-briefcase-production`.

Host and frontend targets:

| Target | Existing deployment |
| --- | --- |
| IAM host | `us-east-1`, `i-011c97da3d8b7ec74` |
| Briefcase host | `us-east-1`, `i-00c2b0c4968b57186` |
| Honeycomb host | `us-east-2`, `i-06986627793021fb2`; persistent volume `vol-0315a7a9cd5c2a357` |
| IAM console and auth domains | Vercel project `silicon-iam-frontend`, deployment `dpl_CgLmi64FjrBssikdh7CBgLuZ4U8t` |
| Honeycomb library | Vercel project `silicon-honeycomb-library`, deployment `dpl_24Ct7MjJtSn9sAPanhRtsiP3Qtdw` |
| Honeycomb console | Vercel project `silicon-honeycomb-console`, deployment `dpl_32BdKqHZ46J5fb4i3gobtmj7qaF1` |

Both `iam.teamofsilicons.com` and `auth.iam.teamofsilicons.com` resolve to the
same ready IAM deployment. Honeycomb's Vercel sites are static and proxy
`/api` and `/auth` to the persistent host gateways under `/web/library` and
`/web/console`. Updating only the Vercel sites would leave the old gateway
behavior running. Briefcase's browser is a container on its existing host.
Vercel inspection did not disclose a source commit for these frontend deployments;
their deployment IDs, rather than an inferred Git revision, are recorded here.

Read-only SSM inventory receipts: IAM
`cb4e344f-a109-44ec-bd4c-87c1e694e5d3`, Briefcase
`9924ae20-8de2-4278-90f2-fbbea2d1941f`, Honeycomb
`c5994f08-36ca-46c3-94f1-cb9deaea368f`.

## Source and migration reconciliation

At inspection, IAM was on `feat/chained-obo` at `85921c2`, Honeycomb on
`feat/install-script` at `89fcca9`, and Briefcase on `main` at `183c10a`.
All three had uncommitted work, including pre-existing human requirements.
Briefcase's committed tree at `183c10a` matches remote main `0c2e260` after
the interface revert; its uncommitted browser redesign is separate work and must
not be swept into a backend consumer release accidentally. No applicable
`AGENTS.md` was found in these repositories or their parent directories.

The IAM branch predates production migrations 0119–0121. Its new migrations had
reused those numbers. The following production files were restored **byte for
byte** from the running source revision `433665db`:

- `0119_honeycomb_single_validator_gate.sql`
- `0120_honeycomb_scoped_validator_gate.sql`
- `0121_approvals_persist_until_revoked.sql`

All 134 migration files in that deployed Git revision (120 main and 14 testing)
now match the working tree byte for byte. This compares committed source with
the observed running image revision; the actual production SQLx ledger still
requires its normal release-time checksum read.

Unshipped main migrations were renumbered without changing their SQL:

| Previous | Reconciled | Feature |
| --- | --- | --- |
| 0119 | 0122 | Chained OBO |
| 0120 | 0123 | Organization logos |
| 0121 | 0124 | Separate OBO token grants |
| 0122 | 0125 | Optional signup phone |
| 0123 | 0126 | Profile photos |
| 0124 | 0127 | Independent Silicon signup |
| 0125 | 0128 | Durable OBO graph permissions |
| 0126 | 0129 | ATA catalog |
| 0127 | 0130 | ATA verification credentials |
| 0128 | 0131 | Silicon organization authority |
| 0129 | 0132 | Directional directory visibility |
| 0130 | 0133 | Social signup |
| 0131 | 0134 | Single-organization application login |
| 0132 | 0135 | Existing Silicon invitations |
| 0134 | 0137 | Silicon action reauthentication |
| 0135 | 0138 | Bound OBO callbacks |
| 0136 | 0139 | Organization Silicon custody |
| 0137 | 0140 | Selected OBO provider metadata |

Testing migrations 9015–9031 keep their numbers. Gaps in migration numbering are
intentional; use exact manifests, not the highest number as a count. The reconciliation
inventory was 138 main and 29 testing overlays, or 167 combined for a testing DB.
The final provider-disclosure consent additions `0141` and `9032` bring the candidate
to 139 main and 30 testing overlays, or 169 combined. They require fresh consent for
older OBO grants; no existing grant inherits another account’s IAM disclosure authority.
`docs/OBO_CUTOVER.md` and its bundled CLI manual references were updated.

Validation after reconciliation:

- `scripts/check-migration-security.rb`: 448 fixed-search-path,
  PUBLIC-revoked SECURITY DEFINER definitions validated.
- `scripts/test-migration-security.rb`: 4 tests, 24 assertions passed.
- Fresh production and testing schema rehearsals passed, as did upgrades from
  the exact committed `433665db` schema in both planes. Each used a separate
  disposable local PostgreSQL 16 database owned by a NOSUPERUSER, NOBYPASSRLS
  role, exact SQLx SHA384 ledger values, current runtime grants, and testing
  security reconciliation. The four durable publication-approval function
  bodies remained unchanged across both upgrade rehearsals.
- Local invocation: `python3 /tmp/iam-reconcile-migrations.py`, using the
  existing disposable server at `127.0.0.1:55483`. Every random rehearsal
  database and owner was removed afterward. The active `iam_identity_preview`
  database and its running API were untouched.

These were **schema rehearsals with synthetic, empty databases**, not restored
production data. Rebuilt SQLx-embedded code passed 62 of 63 database behavior tests
in the complete run; the remaining publication test was corrected to reflect
the deployed durable-approval policy and passed on rerun. A former Honeycomb
validator cannot record a fresh Honeycomb decision, while their existing approval
survives role removal until explicit revocation. These local checks do not replace
a production-data rehearsal before release. A production-data restore rehearsal and final ledger verification
remain release gates.

## Configuration and rollback gates

IAM's running containers contain mail, cryptographic, cookie and existing SSO
configuration, but no Google or Apple social-provider configuration. Its live
`IAM_HONEYCOMB_SCHEDULED_TESTING` is `true`; legacy-writer retirement is `false`.
Honeycomb has no Postmark server token in its running backend. Its configured
web origins already include both library and console HTTPS domains. The new
Honeycomb `deploy/aws/start.sh` refuses missing mail configuration before
replacing containers. Inspect the existing mail queue before enabling delivery;
this inspection did not send or release historical mail. A read-only Postmark
server check confirmed the existing shared `silicon` server (ID 19312876). Its
token was copied into the protected local Honeycomb runtime configuration as a
prepared shared-server option; no live Honeycomb secret or service was changed.
Honeycomb sender-domain verification and the historical queue rollout remain
unverified. Google and Apple sign-in registration details are still required.

IAM's Vercel production variable names include `SESSION_COOKIE_KEY`,
`API_UPSTREAM`, `AUTH_ORIGIN`, `CONSOLE_ORIGIN`, `COOKIE_DOMAIN`,
`DISPLAY_ENVIRONMENT` and telemetry configuration. Preserve the established
cookie key and origins. Preserve Honeycomb's backend encryption key and each
gateway session key and volume. Briefcase's browser sessions and staging are
mounted from `/var/lib/silicon-briefcase/web-sessions` and `web-staging`.

IAM and Briefcase each use separate production and testing RDS PostgreSQL 17.9
instances, encrypted and available. Production backup retention is seven days;
testing retention is one day. Available automated snapshots were observed for
2 October. Latest restorable timestamps were approximately 19:03–19:05 UTC on
2 October. No fresh release snapshot was taken by this task.

Before a coordinated cutover:

1. Finish and test the consumer changes, choose new package versions, and commit
   the precise release contents. IAM server/CLI still say `4.0.0`, SDK `4.1.0`;
   Honeycomb packages still say `0.5.0`; Briefcase still says `2.1.0`. Existing
   published version numbers cannot be reused for changed artifacts.
2. Create paired manual RDS snapshots and quiesced custom-format dumps of both
   IAM databases. Validate archive readability, checksums and restore; retain
   private units, environment files and the exact migration manifest. Use a
   PostgreSQL client at least as new as the PostgreSQL 17 server. Apply the same
   backup discipline to Briefcase if its release includes schema changes.
3. Back up Honeycomb's SQLite database consistently with its WAL and persistent
   backend/gateway state; take an EBS snapshot after quiescing writers. Preserve
   keys with the backup. Its current startup script does not perform backups.
4. IAM's `release-honeycomb-contracts.py` now records each running service's
   Honeycomb feature flags, preserves environment files, and checks the same
   values after replacement. Three read-only regression tests cover enabled,
   disabled/default and unknown values; no release execution was performed.
   Do not use the 0118-specific public-identifier release helper for this release. `install-release.py` is image-only and does not apply this migration
   series. After schema mutation, an old image alone is not a valid IAM rollback;
   restore the coordinated databases/configuration and old images together.
5. Use Briefcase's current `deploy/base-tier/README.md` procedure, not its older
   autoscaling/CloudFormation deployment script. The effective browser image is
   in `/etc/systemd/system/silicon-briefcase-web.service.d/upload.conf`; retain
   that drop-in and all mounted session/staging data. Keep its docs release
   directory and previous `current` symlink target for an independent docs rollback.
6. Release Honeycomb backend and both gateway containers together with the two
   Vercel static sites. Keep the previous Vercel deployment IDs for alias rollback.
   Release IAM's auth/console gateway with the compatible backend and preserved
   session configuration. Prove real login, review, storage consent and upload
   after deployment; health checks alone do not establish these flows.

## Consumer audit and local follow-up

The initial audit found these active legacy code paths, not merely SDK
definitions or comments. The local follow-up below records their migration;
their deployed versions still need a coordinated release before retiring the
legacy proof endpoint across production.

| Consumer | Active path | Required work |
| --- | --- | --- |
| Hook | `src/infrastructure/iam/ting.rs::ting_proof`, called from `infrastructure/ting.rs` send, subscription registration and sent-query operations; testing receiver bootstrap in `infrastructure/ting/receiver.rs` | Separate Ting consent, durable refresh storage and reusable access-token forwarding; keep testing receiver credentials isolated. |
| Browser | `crates/backend/src/server/delivery.rs` recording worker → `delivery_auth.rs` → `auth.rs::issue_recording_proof` → `providers/briefcase.rs::upload_file` | Separate recording/storage grant lifecycle, retained initiator binding, refresh and reusable Briefcase tokens; update delivery recovery UX. |
| Extend | `crates/extend-service/src/iam.rs::obo_proof`, called by `files.rs` and `ting.rs` | Consent and retained grant per account/organization/plane; reusable token forwarding for Briefcase upload, share, trash, read and Ting operations. |
| Commit | `src/api/auth.rs` accepts legacy proof headers; `src/infrastructure/clients/iam.rs::authenticate_obo` calls legacy verification | Receiver-only verification migration while preserving recipient, subject, organization, testing and resource ACL checks. Its separate `exchange_child_proof` method is retired and returns Forbidden; it is not an active downstream caller. |

This table records the audit before follow-up consumer implementation. It is not
evidence those consumers have already shipped the new protocol.

Follow-up local implementation: Commit's receiver now uses the vendored official
IAM 4.1 client and `X-IAM-OBO-Access-Token`, rejects the old proof header, and
verifies the handler-owned action ID and server-matched route through
`/obo-access/token-verifications`. It retains recipient, actor, organization,
testing-plane and resource ACL checks. Its library suite passed 154 tests;
`cargo clippy --offline --locked --all-targets -- -D warnings`, formatting and
diff whitespace checks passed. The focused tests cover reuse followed by
revocation, expiry, mismatched authority, legacy-header rejection, parameterized
routes and both testing selectors. This is local mock/unit evidence, not a live
Commit/IAM integration or deployment. Register the existing action IDs and exact
route templates in the application catalog before exercising real grants; absent
identity or role disclosure still fails closed. The final upstream SDK release
revision must replace the development snapshot provenance before publication.

## Active preview limitations

IAM is available at local port 4310; Honeycomb library and console at 4312 and
4313. The Honeycomb preview uses current Vite source with explicit synthetic
fixtures and never contacts IAM, storage, email or production. It supports
navigation, published/private release surfaces, request badges and read markers,
and a disposable logo-consent retry demonstration. ATA only has an empty-list
fixture; review replies/decisions and app creation are not implemented in that
fixture. A completed received-request detail currently gets a fixture-only
`can_decide: true` override. These limitations prevent using the preview as
operational acceptance evidence. No running preview was replaced by this audit.

## Local integration completion notes

Hook's separate publisher/observer permissions and DM's Ting permissions now
persist encrypted authorization requests before contacting IAM. After an uncertain
response, a current login for the same account may retry the unchanged original
request and idempotency key across process restart; this creates no grant without
approval. Production/testing lifecycle regressions pass. Hook's full workspace
passed 328 tests and three doctests, plus 37 frontend checks/build; DM passed 146
Rust tests, 90 frontend checks and the native/database regression suites. Both
passed strict Clippy. Hook's grant-table trigger no longer causes parallel grant
refreshes to deadlock on the testing-environment guard; environment reset remains
fenced. Historical live fixture artifacts still need coordinated release updates.

Browser recording delivery now stores separate encrypted Briefcase grants and
uses reservation, transfer capability and commit. The immutable recording pins
its approved destination before transfer, so uncertain retries cannot move it to
another account or organization. A rejected old credential cannot disable a newer
approval. IAM authorization responses must match the initiating application,
account, organization, request and expiry before binding the pending request.
Backend tests passed 214 cases and a separate legacy-upgrade regression with
strict Clippy; SDK/CLI passed 91 cases with
strict Clippy; frontend passed 39 tests and a production build. Synthetic
desktop/mobile checks covered invalid-code recovery, account/org switching and
completion without automatic paid-session replay. These checks did not create
paid sessions or call real IAM/Briefcase providers.

Extend now includes separate feature consent in API, website, SDK and CLI. Its real
PostgreSQL lifecycle, provider request fixtures, consumer/provider contract replay
and fresh/upgrade/rollback schema rehearsals pass. The synthetic browser flow
retains login on a bad code and clears pending authorization on an organization
switch. Ting catalog approval also passes malformed-code recovery, stable refresh
retry and test-clean fencing. These are local results, not live provider evidence.

Commit requires its existing identity and membership disclosures before mapping an
OBO result into resource roles. IAM deliberately omits login-derived disclosures
when the selected provider account differs from the originating account; those
Commit requests therefore fail closed. Do not remove the role guard to make a
test pass. A reviewed, explicitly approved disclosure contract and regression
coverage are still needed before claiming cross-account Commit actions work.

### Proposed cross-account disclosure contract — awaiting review

The smallest extension is visible consent inside the existing OBO screen:

- Endpoint definitions declare an allowlisted `subject_disclosures` set:
  `self.identity.read`, `self.membership.read`, and, only where needed for
  resource policies, `self.tags.read`.
- Each provider section shows the requested disclosures beside the selected
  account and organization. The same explicit decision approves the displayed
  delegated actions and disclosures; no additional login page is required.
- Persist the disclosure decision per graph node, bound to selected principal,
  membership, receiving app, endpoint, graph version and approval receipt. Never
  inherit another account's login scopes or backfill existing OBO grants.
- Verification returns current identity, role or tags only within this consent
  and current participating application approval ceilings. Keep membership,
  security-epoch, revocation and testing-generation checks unchanged.
- Commit retains every resource and role check. Access to other members'
  directory details requires its existing separate authorization.

Implementation spans IAM endpoint validation/catalog persistence, graph decision
and verification functions in a new additive migration, the OBO consent UI,
OpenAPI/SDK models, and Honeycomb's endpoint configuration. Required tests cover
explicit cross-account success, absent disclosure denial, stale graph/context,
app approval removal, live role/tag changes, Carbon/Silicon identities and both
data planes. Commit regression tests must retain private-resource, role, tag and
other-assignee denials. This proposal has not changed authorization behavior.
