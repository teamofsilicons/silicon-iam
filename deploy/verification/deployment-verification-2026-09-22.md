# Application verification deployment — September 22, 2026

Application identity verification is deployed on the main IAM backend. These
keys are separate from user access/refresh tokens and do not grant user or OBO
authority. The scoped backend intentionally does not expose these endpoints.

## Deployed artifacts

- Backend source: `21e63ffb073ac436d3ddb9f26adc689847f11ad1`.
- ARM64 image: `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:9ef897f45332cd004697261a964d59b2e6faffa41aab5027ea9183a8496fd64b`.
- Rust client and CLI: **3.1.0**, source `01fc43d0dfed786b466c931231b4f6059a075c24`, [GitHub release](https://github.com/teamofsilicons/silicon-iam/releases/tag/v3.1.0).
- All six native builds passed [release workflow 35652429659](https://github.com/teamofsilicons/silicon-iam/actions/runs/35652429659).
- Honeycomb `tos>iam` production release: `b2f4b55e-52cb-4385-aa8e-624726d77a97`.
- Combined archive SHA-256: `a42a661a5582b2191bda5006a149effb453a903409403535e6821cddffa517b2`.
- Documentation deployment: `dpl_8L2sb4P5YhdNAPckKpFJ5JpyQW37`, serving the [application verification guide](https://docs.iam.teamofsilicons.com/api/applications/#app-verification).

Both crates, GitHub assets, and Honeycomb installation were verified through
anonymous downloads. A fresh anonymous install executed version 3.1.0, both
verification command help pages, and the offline manual. Its temporary updater
and PATH integration were removed while preserving the existing updater.

## Migration and continuity

The exact image passed an isolated restore rehearsal of both existing RDS
databases before the live upgrade. Production now has 114 migration entries;
testing has 128, including migrations 0115 and 9014. Runtime grants and the
scoped helper were applied from the immutable image.

The main API, scoped API, and worker run the same image with zero container
restarts at acceptance. The operator verified unchanged credential fingerprints
and all runtime environment file hashes. Retained IAM, Waveform, and Remind CLI
sessions remained authenticated with the same identities after rollout.

Live rollout SSM command: `e86a1742-d384-48fe-94ae-c1d052eed4f8` (success).
CloudFormation `silicon-iam-production` reached `UPDATE_COMPLETE`; launch template
48 pins the image. Instance `i-011c97da3d8b7ec74` was retained. Temporary
replacement guards and backup-upload permission were removed after verification.
The temporary ARM64 build instance and its resources were cleaned up.

## Acceptance

[Backend CI 35651383091](https://github.com/teamofsilicons/silicon-iam/actions/runs/35651383091)
passed all formatting, lint, unit, PostgreSQL protocol, generated-documentation,
privilege, packaging, restricted-runtime, live-client, and dependency checks.

Production HTTP checks verified independent random keys, the 300-second default
and 60-second custom lifetime, TTL bounds, repeated verification by a different
application, expiry rejection, and rejection of invalid receiving credentials.
Wrong-app, malformed, and unknown keys return only `valid_key: false`. Both
successful responses prohibit caching; an app key is rejected as a user bearer.
Anonymous calls to the main endpoints return 401, while the scoped backend
preserves its narrower route surface and returns 404 for them.

## Recovery evidence

Encrypted RDS snapshots:

- `silicon-iam-production-before-app-verification-21e63ff`
- `silicon-iam-testing-production-before-app-verification-21e63ff`

Verified quiesced databases/configuration archive:

- Bucket: `silicon-iam-recovery-234951665042-us-east-1`
- Key: `app-verification-21e63ff/quiesced-databases-and-config.tar.gz`
- Version: `clmC7sCkuTcaLknx4KqctExMA.kqwMhs`
- SHA-256: `cbfabe44253e905f654eb1392bffbdee42e5471694a99fc91540d0e6b4d51b78`
- Encryption: AES256; size: 7,472,500 bytes.

Private host evidence remains under
`/etc/silicon-iam/releases/canonical-21e63ffb073ac436d3ddb9f26adc689847f11ad1-1790024134587791450`.
Recovery requires forward repair or a coordinated restore of both databases and
configuration; an old-image-only rollback is incompatible with the new ledger.
