# IAM 1.9.0 telemetry deployment — 2026-09-13

The API, scoped API, worker, authenticated frontend, documentation site and
published Rust client/CLI were released after explicit deployment authorization.

## Artifacts

- Backend source: `a169881998e939749e10bd6c1a3ad3f3d9ade771`.
- ARM64 image: `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:3bef6e16b526f3bb7b8fc2de1cbe462a1dffdc56d27c435d1e162bdaffc4aaef`.
- Runtime instance: `i-011c97da3d8b7ec74`; all three IAM services use this image.
- Frontend: `dpl_233t2Mdupvg1T2f48HhxYwMSarZW`, serving both
  `iam.teamofsilicons.com` and `auth.iam.teamofsilicons.com`.
- Docs: `dpl_7Ybga2noTRjPpWL3yncEVdAYh9C8`, serving `docs.iam.teamofsilicons.com`.
- `silicon-iam-client` and `silicon-iam-cli` **1.9.0** published to crates.io.
- Source pushed to the IAM repository. The frontend follow-up normalizes
  whitespace in server-side telemetry keys and tests the environment kill switch.

## Configuration

The dedicated write key for `tos.siliconiam` was added to the existing IAM
application secret in Secrets Manager and as a Sensitive production environment
variable in Vercel. Other application secret values were preserved. The key is
not included in source, release artifacts or this record.

Each backend container has its own persistent host spool under
`/var/lib/silicon-iam/telemetry/{api,scoped-api,worker}`, owned by UID/GID 10001,
mode 0700. It is mounted at `/var/lib/silicon-iam/telemetry` inside the container.
The release installer preserves existing runtime settings, receiver keys,
service options and rollback files. No database migration was necessary.

CloudFormation change set `iam-telemetry-a169881` completed successfully. It
updated only the launch template and the ASG's launch-template reference,
preserving the existing infrastructure parameters and databases. New instances
inherit the image and API/worker telemetry configuration. The scoped-service
installer now provisions its own persistent spool as well.

## Verification

- All three systemd services and containers healthy after rollout; public API
  reports the release revision and public API/scoped readiness return 200.
- Both frontend origins report `telemetryEnabled: true`; signed-out HTTP session
  checks succeed, and the existing signed-in session renders the production
  console correctly in a real browser.
- Space Station SQL confirms production records from `iam-api`, `iam-scoped-api`,
  `iam-worker`, and `iam-web`.
- Distinct enabled API/scoped readiness probes each produced one correlated
  event; a disabled probe produced zero. A disabled web batch returned 204 and
  produced zero matching events.
- The public installer bytes match `scripts/install.sh`; the telemetry guide
  is reachable at `/telemetry/`.
- Rust verification: 493 tests passed, 36 service/database-dependent tests
  skipped locally; workspace Clippy and formatting passed. Frontend final tests:
  34 passed, production Vercel bundle built. Documentation links/assets checked.
- Both published crates passed Cargo's packaged-source verification.
- The dependency-policy check identified the two additional transitive versions
  required by Space Station: `base64@0.23.1` and `webpki-roots@0.26.11`.
  They now have narrow, documented duplicate-version exceptions, matching the
  existing policy. `cargo deny --locked check` passes advisories, bans, licenses
  and sources with the released lockfile.

The ASG reports the instance InService/Healthy. Its pre-existing target-group
reference could not be resolved by ELB during verification; public DNS resolves
to `44.209.29.33`, and external readiness checks succeed. This release preserved
that routing configuration; it did not modify or recreate an edge resource.

## Rollback

The previous unit and environment files are retained privately on the instance:
`/etc/silicon-iam/releases/a169881998e939749e10bd6c1a3ad3f3d9ade771-1789300452611191092`.
Restore those files and restart the relevant systemd services, then verify
readiness. Previous API/worker and scoped image digests remain locally available.
The previous backend CloudFormation image parameter was
`sha256:f906c226b83a7342309c346c4e6904a2a1d9ce1471e9e07c08f55d0ecae1aec7`;
reconcile the template/image parameter if rolling back replacement configuration.

Previous frontend deployment: `dpl_5Jc7C5CJDdJuvS8hH7eeMVWnsHL1`
(`silicon-iam-frontend-fbcmsa38e-saketdev12-5675s-projects.vercel.app`).
Previous docs deployment:
`silicon-iam-docs-4qfwst3zs-saketdev12-5675s-projects.vercel.app`.
Promote a previous deployment through Vercel to restore it. Published crate
versions are immutable; corrective client changes need a new version.
