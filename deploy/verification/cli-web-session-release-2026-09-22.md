# IAM CLI and web session release — 2026-09-22

IAM CLI **3.1.1** and the matching web gateway are published and deployed from `9b64a49dbc25225c60cf78c56251056e59f15a8c`. Refresh retries retain their original request timing, successor credentials are saved before recovery, and temporary request failures preserve the saved login. The IAM SDK remains **3.1.0**.

## Publication

All six native targets built successfully, including the Linux glibc 2.28 runtime check. The [public GitHub release](https://github.com/teamofsilicons/silicon-iam/releases/tag/v3.1.1) contains the six binaries in the Honeycomb archive plus provenance and checksum manifests. All four release assets were downloaded anonymously and matched their published checksums.

- Package: `iam-3.1.1-honeycomb.tar.gz`, 28,239,603 bytes.
- Archive SHA256: `42cf43f375b7018f67ff3d89311c2f50d7fd6b354c1d17a15e85cfb080a7460f`.
- Honeycomb production release: `1c012e2f-b579-4328-aafb-86379628fa7c`.
- crates.io publication was verified against the exact release source and artifact hash.

The CLI regression run passed 52 unit tests, 11 integration tests and Clippy with warnings denied. Embedded manuals were regenerated and checked. The frontend passed all 47 tests, typecheck and production build.

## Web deployment

Vercel deployment `dpl_BQXSEUkpVCckk2ktHKbejWc2j4VJ` reached Ready and serves both `iam.teamofsilicons.com` and `auth.iam.teamofsilicons.com`. Public entry points and anonymous session checks passed. The gateway retains a deterministic refresh mutation, accounts conservatively for replayed token expiry, retries stale access once, and keeps the session on generic request errors.

An existing Carbon browser login at `https://iam.teamofsilicons.com` survived the frontend deployment. Profile and organization-directory reads succeeded without a fresh login. This proof preceded the final backend family-revocation rollout. A browser recheck after that rollout was unavailable because the browser policy check failed; no policy bypass was attempted.

## Installed session verification

The supported Maharaj package upgrade installed IAM 3.1.1. `whoami` retained the original identity without signing in again. No saved production credentials were copied or replaced to obtain this result.

The subsequent backend **3.0.1** release fixes an additional, independent sibling-family revocation bug. Its dual-database migration, exact image, live isolation proof and recovery assets are recorded in the [backend deployment receipt](oauth-family-revocation-2026-09-22.md). The [cross-application audit](session-refresh-audit-2026-09-22.md) distinguishes all deployed versions from remaining local activation checks.
