# Honeycomb management API production rollout — 2026-09-16

IAM's main API, scoped API and worker run revision
`c57b3a385fc6b0749f1cd9ae1e91e40169db531f` from the immutable ARM64 image:

```text
234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:dee342fa02b0f01583ef6842d8c0bd31576582714e09fa9aef0aaecbfdc84adc
```

The release merges the deployed scoped-authentication and OBO/planner fixes.
The existing main IAM application identity and credentials are preserved.
`UNDERSTANDING.md` was committed separately, unchanged, in `0467ef0`.

## Enabled behavior and Honeycomb handoff

The production management base URL is
`https://backend.iam.teamofsilicons.com/api/v1/honeycomb`.
The new verified authentication application is `tos>honeycomb`, owned by `tos`.
Its identity UUID is `01a0a751-69c0-70b2-8456-96806349f999`.

Credentials are held in AWS Secrets Manager at
`silicon-honeycomb/production/iam-management`. The operator's protected local
handoff file is `/Users/codanium/.config/silicon/honeycomb/iam-production.env`
(mode 0600). It contains the application ID/secret, IAM base URL, dedicated
management service credential and independent notification signing key.
Never commit its contents. The protected bootstrap JSON beside it is retained
for idempotent operator retries.

- IAM stores only the SHA-256 digest of the management service credential.
- `IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS=false`: existing management writers stay
  available while Honeycomb completes adoption.
- `IAM_HONEYCOMB_SCHEDULED_TESTING=false`: service-authored scheduled lifecycle
  work remains disabled. IAM's former autonomous idle retirement is removed.
- Management notifications remain durably queued. Delivery awaits Honeycomb's
  live HTTPS management receiver; configure its URL and the independent signing
  key together on the IAM worker when that receiver is ready.
- The existing frontend remains deployed. Honeycomb itself and Rust package
  publication are outside this backend rollout.
- User-triggered management writes still require a live Honeycomb Carbon actor
  token and applicable step-up proof; service credentials do not replace them.

## Database and runtime changes

Both databases received base migrations 0095–0098. The testing database also
received testing migrations 9008–9009. Production now has 98 migrations;
testing has 107, with maximum version 9009. Every deployed migration checksum
matches the release. The deployed 0092–0094 and testing 9007 histories were
preserved by renumbering the previously unreleased Honeycomb migrations.

The image's runtime grant manifest was applied to both databases, and the
IAM-owned scoped application identity helper was reinstalled. The
`application_token_allows_membership` function retains `join_collapse_limit=1`.
Existing testing environments remain one active and 34 deleted.

PostgreSQL 17 custom-format backups, prior environment files and service units
are private on the host at:

```text
/etc/silicon-iam/releases/honeycomb-c57b3a385fc6b0749f1cd9ae1e91e40169db531f
```

The bootstrap's temporary instance-role permission to read Honeycomb's secret
was removed after provisioning. The temporary plaintext bootstrap copy on the
host was deleted. Runtime providers, keyrings and scoped webhook configuration
were preserved.

## Deployment and infrastructure

SSM operation `eb265306-4540-4237-9d9c-0f38b15c5a2f` completed the coordinated
migration and runtime upgrade on `i-011c97da3d8b7ec74`. CloudFormation change set
`honeycomb-c57b3a385fc6` completed successfully for `silicon-iam-production`,
persisting the image and optional Honeycomb secret-to-environment wiring.
The existing instance remains InService/Healthy; no instance refresh occurred.

All supplied parameter values except `BackendImageUri` were preserved. AWS
re-resolved the existing latest-AL2023 SSM parameter from
`ami-0a157bd98d97a9589` to `ami-02c13950b5ec1f04e` in launch-template version 41.
Both are available Amazon-owned ARM64 AL2023 images. This affects future
instances; the running instance was not replaced.

Live ingress is nginx. The pre-existing unresolved ASG target-group reference
and historical edge/replacement-host drift remain outside this release; this
rollout does not validate automatic host reconstruction. The legacy edge
CloudFormation source now redacts `x-honeycomb-actor-token` if used later,
but no edge stack was created or deployed. The live nginx configuration has
no reference that logs this credential header.

## Verification

- Workspace tests: 500 passed; strict workspace/all-target/all-feature Clippy
  and dependency advisory, license, source and duplicate-version checks passed.
- All 37 live PostgreSQL library tests passed, including restricted runtime
  grants and production/testing isolation. The protected bootstrap was also
  exercised successfully against production during this rollout.
- Migration security, runtime grant, OpenAPI and generated documentation checks
  passed; the ARM64 release image built successfully.
- Main and scoped HTTPS readiness return 200 and both version endpoints report
  the exact release revision.
- Authenticated management scope-catalog and `tos>honeycomb` reads return 200.
  An unauthenticated management request returns 401; the management route is
  absent from the scoped API (404).
- Unauthenticated legacy application creation returns 401, confirming the
  route is not retired (410); no production mutation was used for this probe.
- Main API, scoped API and worker containers are running with zero restarts;
  post-deployment log inspection found no error-level lines.

Authenticated actor mutations and notification delivery through a deployed
Honeycomb service remain integration work for Honeycomb. This release verifies
IAM's authenticated service API, not those end-to-end flows.

## Recovery

Migrations are forward-only. Do not restart the previous image against the new
schema: its embedded migration ledger is incompatible. Use a reviewed forward
repair, or coordinate a database restore and matching runtime together using
the protected backups. A restore would discard writes after the backup and
requires a separate recovery decision.
