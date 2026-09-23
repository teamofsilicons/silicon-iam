# Testing credential rotation release — September 23, 2026

IAM backend **3.0.3** is committed, published and deployed. Both public APIs report
the exact source below and pass readiness; the worker is active on the same image.
The original Honeycomb rotation has been recovered through the supported protocol,
and a fresh rotation returns a usable official-SDK audience credential.

## Fixes and source

Backend 3.0.2 source: `2f24d2203bbab8ee1cc740848a1516d36fb17816`.
Honeycomb's authorized test rotation runs without a Carbon principal in the
testing database. The former owner-only snapshot updater silently changed zero
rows, leaving OBO and recovery with a retired credential after an authentication
secret rotation. Migration `0117` updates the active digest and encrypted import
snapshot atomically; a missing snapshot aborts the transaction. An explicitly
supplied configuration revision zero is valid for an unchanged import.

Backend 3.0.3 source: `9fd370c5589e099399a377e5667b9408cc2d13fd`.
The original saved request also had a stale environment revision. The environment
fence hid its definitive configuration rejection. IAM now checks an exactly bound
target-plane receipt before rejecting that revision. An existing receipt recovers
the original result; without a receipt, a rotation's configuration revision is
validated first. A valid configuration with a stale environment revision still
cannot mutate anything.

Current authorization, environment generation/key checks, operation claims and
exact service/actor/resource/request binding remain required. Unknown outcomes
remain recoverable. No saved request is rewritten. Version 3.0.3 adds no migration
or wire field. IAM CLI remains **3.1.2** and the Rust client remains **3.1.0**.

## Verification and published artifact

The new ordering failure was reproduced before the fix. Final-source tests use
real PostgreSQL with restricted runtime roles and cover definitive configuration
rejection, a stale environment with valid configuration, target receipt recovery
after a lost control result, no second rotation, unchanged credentials, and
actor/body/lifecycle/context isolation. The local workspace suite passed 538 tests;
Clippy, formatting, migration security, runtime grants, OpenAPI and generated
documentation checks passed.

- [Complete source CI](https://github.com/teamofsilicons/silicon-iam/actions/runs/35832825030)
  passed, including the live PostgreSQL protocols, fresh dual-plane migrations,
  restricted grants, worker smoke tests and live SDK contract.
- [ARM64 image build](https://github.com/teamofsilicons/silicon-iam/actions/runs/35832847994)
  passed for source `9fd370c5589e099399a377e5667b9408cc2d13fd`.
- Archive: 73,508,904 bytes, SHA-256
  `43574b458a2f12439ac67e41a8587806f98e03e02b7c952e316aab069aac113e`.
- Image configuration digest:
  `sha256:de9e436bd18e26b725808efe436c5b68f7e34426975eb1810594a654addb84b8`.
- Immutable deployed image:
  `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:664aae796c59ef0b6c92cc2b2ed43ca847d18dcf42a453c9eb3233a1f5dd53b3`.
- Archive checksum, image configuration, rootfs layers, Linux ARM64 platform,
  source/version labels and remote ECR manifest were verified independently.
- [Backend release](https://github.com/teamofsilicons/silicon-iam/releases/tag/backend-v3.0.3)
  publishes the exact archive, checksum and two metadata files. All four uploaded
  asset sizes/digests match local files. The separate latest CLI release remains
  `v3.1.2`.

## Deployment and retained recovery state

Backend 3.0.2 first applied migration `0117` to both planes after restored-backup
rehearsal and a coordinated writer stop. The complete migration ledgers now contain
116 production and 130 testing entries. Runtime API execute permission is present
for the rotation function on both planes; public execute permission is absent.
Environment files and credential fingerprints were preserved.

The 3.0.2 coordinated backup remains versioned in
`silicon-iam-recovery-234951665042-us-east-1`, object
`ting-rotation-2f24d22/quiesced-databases-and-config.tar.gz`, version
`AwRClCwNv9aFtc3chdNKTR8MmwAj2uP6`, SHA-256
`c8cb485975381c521990ccd18aca9e5bc25c2bcb91f5696b664f3b87530d0819`.

The 3.0.3 upgrade changed only the immutable image in the three existing systemd
units. It saved all units and all four environment files, stopped all writers and
took fresh private dumps of both planes. It verified unchanged environment hashes,
complete ledgers, credential fingerprints before restart, container environment
values and mount settings. No migrations or database restore ran during this
image-only upgrade.

Private 3.0.3 backup directory:
`/etc/silicon-iam/releases/image-3.0.3-1790151130930601749`.

- Production dump: 3,811,155 bytes, SHA-256
  `00b5fbcd2e27b832f9a47da60b9da40b56a98aa7d3f50bdb4bed75c43b0c7080`.
- Testing dump: 7,300,254 bytes, SHA-256
  `cabfc20343870d361895aaa3d93082254c0f0ee5e8f8998420f76969f9413488`.

An initial 3.0.3 cutover automatically rolled back to healthy 3.0.2 because the
operator compared Docker mount arrays in their unstable order. A stopped-container
probe confirmed every mount value and environment value matched. The operator was
corrected to compare complete mount records sorted by destination; the retry
succeeded. Neither attempt rewound the database or changed credentials.

Both `backend.iam.teamofsilicons.com` and
`scoped.backend.iam.teamofsilicons.com` return build `3.0.3`, source `9fd370c…`,
and readiness HTTP 200. API, scoped API and worker use the verified image.
CloudFormation stack `silicon-iam-production` is `UPDATE_COMPLETE`, with launch
template `lt-07bbd8600954025aa` version **51** pinned to the same image. The retained
instance `i-011c97da3d8b7ec74` and AMI `ami-0eb45f74aa8a20238` are unchanged.
Only the image changed in launch-template data. Prior autoscaling processes and
scale-in protection have been restored.

[Documentation](https://docs.iam.teamofsilicons.com/honeycomb-integration/) is live
through the existing `silicon-iam-docs` Vercel project, deployment
`silicon-iam-docs-1vpidq6vb-saketdev12-5675s-projects.vercel.app`. The build checked
47 pages. Live integration documentation, OpenAPI and installer match the built
bytes; all four configured security headers and legacy `/docs/` redirects remain.

## Live Honeycomb recovery

In environment `d70c8674-6d2e-41d4-bf8d-96ddd882edbd`, the original immutable
operation `a2b700ff-90dd-4795-b6c1-27e98871ba9c` now reaches its definitive
`testing_configuration_revision_conflict` rejection. Supported reconciliation was
accepted, followed by a new rotation `344d03bc-1d3d-45f7-a363-42b1464088ce`,
accepted at credential version 2. The original body and idempotency key were not
edited.

A fresh signed exchange through official `silicon-iam-client` 3.1.0 returned the
new audience credential and matching IAM key. That credential authenticated with
the exact testing context for this environment and `tos>ting`. The diagnostic
proof was neither consumed nor persisted. Fresh Carbon and Silicon preparation
also passed in environment `1d32b4c6-dc84-4c44-b7b7-a16be7a31d06`.

DM delivery, explicit receipts and native client publication are tracked by the
coordinating DM release; this record establishes the IAM deployment and supported
credential-recovery gates. Private evidence is retained under
`/tmp/ting-rotation-release-20260923/`, including sanitized recovery verification.
