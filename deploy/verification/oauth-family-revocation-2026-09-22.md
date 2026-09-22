# IAM OAuth family revocation deployment — 2026-09-22

IAM backend **3.0.1** is deployed from `ae6ceb3b8b05134bf16232151d68d380b01eeabe`. An independent app login gets its own refresh family even when it shares an IAM parent session. App logout and refresh reuse now revoke access tokens only in that family, preserving sibling app logins and the parent IAM session.

## Exact release

- Image: `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:1b8874a0c7aa51af920b3db2249e19a03d6c71996676e01b1b7d090d42941b88` (Linux ARM64).
- [Image build](https://github.com/teamofsilicons/silicon-iam/actions/runs/35666633629) and [complete CI](https://github.com/teamofsilicons/silicon-iam/actions/runs/35666586482) passed.
- Exported image archive: SHA256 `51c2fc5b78d5459e452011159ab67d8cb0c5c404b846a8eee2568844b6c9062c`, 73,489,386 bytes. Its OCI config digest, manifest digest, all filesystem layers, revision and version were checked before ECR publication. Classic Docker reports the config digest as image ID; containerd reports the manifest digest.
- Previous image: `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:9ef897f45332cd004697261a964d59b2e6faffa41aab5027ea9183a8496fd64b`; source `21e63ffb073ac436d3ddb9f26adc689847f11ad1`.
- SDK remains 3.1.0; CLI remains 3.1.1. No public protocol change.

## Migration and verification

Migration `0116_oauth_access_refresh_family.sql` adds an identity-bound access-to-refresh-family foreign key. Existing valid tokens are linked only when their access and refresh issuance timestamps identify exactly one family. Ambiguous live data aborts the migration. Expired/revoked tokens are not revived. New issuance stores the explicit link; no permanent compatibility trigger is needed because all old writers were paused for cutover.

Both production and testing restores successfully rehearsed the exact image and migrations before cutover. Local regression tests covered real issuance, logout and reuse containment in both runtime modes; historical backfill rejection/success; wrong-client FK rejection; and worker retention. All 403 regular library tests, the existing protocol test, the canonical membership upgrade test, workspace Clippy, formatting and privilege/grant checks passed. Complete CI also passed the broader PostgreSQL and restricted-runtime suite.

- Restore-only rehearsal SSM: `67b7fda7-961d-4eb7-a095-dd3a2b630364`.
- Live rollout SSM: `2b41c627-8e9a-45ac-af7a-c2190c89bfda`, 2026-09-22T00:50:07.318Z to 2026-09-22T00:51:06.318Z.
- Postflight SSM: `39981c98-a2d7-48f1-8454-a919ba0b76e0`.
- Production ledger: 115 migrations; testing ledger: 129. Both match migration116 checksum `b9a026bf1b27534fc98dc0b6c0babe4f32ce54d3773a52a6740707fe160067e08b356855d86511eeb18d4c69a3d01a96`.
- Postflight found zero valid unlinked application-access tokens in either database. All three containers (API, scoped API, worker) use the pinned image with zero restarts. Credential fingerprints and all four runtime environment-file hashes stayed unchanged.
- Both public APIs returned version3.0.1/source ae6ceb3, readiness200 and anonymous account401.

## Durable deployment and recovery

CloudFormation `silicon-iam-production` is `UPDATE_COMPLETE`. Launch template `lt-07bbd8600954025aa`, version49, embeds the immutable image digest. Existing host `i-011c97da3d8b7ec74` remains healthy. Temporary ASG process suspensions and scale-in protection were restored to their prior values; the single-object backup upload policy was removed.

The operator verified paused-writer backups of both databases and saved service/configuration files before migration. The encrypted recovery archive remains in private S3:

- Bucket: `silicon-iam-recovery-234951665042-us-east-1`.
- Key: `oauth-family-ae6ceb3/quiesced-databases-and-config.tar.gz`.
- Version: `bEa3_XDW5R03gTgMhL.hl6fZr6c3Lz0e`.
- SHA256: `332175be0c5122c61c260bbd443fc984033ae046a5b8654f71ffb78699aea83b`; 7,788,222 bytes; AES256.
- Protected host release directory: `/etc/silicon-iam/releases/canonical-ae6ceb3b8b05134bf16232151d68d380b01eeabe-1790038207453932070`.

Do not roll back only the image after this migration. Forward-repair the deployment or restore both verified database snapshots and saved configuration with the previous image.

## Live session isolation

A normal Carbon IAM login created two disposable Commit app families under the same parent session. With automatic refresh disabled, both raw access tokens initially returned 200. Logging out the first returned 204; its access token then returned 401 while the untouched sibling still returned 200. Logging out the remaining family returned 204 and its access token then returned 401. Both verification families were cleaned up. This directly verifies family isolation against the deployed IAM backend through ordinary application APIs.

The check completed at 2026-09-22T01:05:10Z. Its nonsecret local evidence is `commit-carbon-sibling-isolation.json` in the session release verification directory.

The final check of the original Maharaj access token was excluded because macOS Documents access was blocked by a pending privacy permission request. No Maharaj credentials were read, reauthenticated or replaced for this probe. The final backend-era Carbon browser reload was also unverified because the browser policy check was unavailable; that check was not bypassed. The earlier [frontend retention proof](cli-web-session-release-2026-09-22.md), successful live sibling isolation and complete dual-plane database regressions remain valid.
