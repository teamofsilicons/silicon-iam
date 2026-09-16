# Honeycomb contracts release — September 16, 2026

## Prepared release

Backend source: `11e49a079c6bd2ae2cddb43d8d479af2c599db83`.
The clean ARM64 image built and was pushed to ECR:
`234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:7d2de04e5701f2a007ec8b2d3fbce276ce39ad0fe7f9d4c3cdb3614b121a9b8c`.
Its revision label matches the backend source above.

This includes publication and shared testing contracts plus migration0105,
which removes the obsolete60-second OBO proof ceiling in favor of the existing
positive i32 endpoint-lifetime bound. Parent token, consent and revocation
checks remain enforced.

Production rollout succeeded. SSM command
`cac0c19c-f423-4426-9837-63d26acda45e` backed up both databases, applied all107base
migrations plus13testing overlays, reapplied runtime grants and restarted the
main API, scoped API and worker. Public readiness and exact commit checks passed.
Honeycomb and Briefcase retained their UUIDs and Honeycomb's four self scopes.
The organization-recipient route passed a service-authenticated live read.

CloudFormation change set `honeycomb-contracts-11e49a0` reached UPDATE_COMPLETE,
persisting only the backend image and launch-template version reference.
Private rollback artifacts are at
`/etc/silicon-iam/releases/contracts-11e49a079c6bd2ae2cddb43d8d479af2c599db83-1789544756578418577`.
The previous image alone is incompatible with the migrated database ledgers.

SDK and CLI1.11.0 are published to crates.io. Native artifacts were built from
`da0b59527f6d7d74d6c5d9dc1d2561057283e39d`; all six operating-system/architecture
builds passed executable-header and native version checks. CI run:
https://github.com/teamofsilicons/silicon-iam/actions/runs/35056460251

Combined Honeycomb archive SHA256:
`0e662f15d9b0d1b18346a15f65f349d12dc959e3115031bcae6ce9777cee374f`.
Honeycomb received the archive, checksums and provenance for normal registration
and publication. IAM does not duplicate its app registration.

## Verification

- 506 workspace tests passed; SDK45unit+18wire+3documentation tests passed.
- 39 disposable database contracts passed across the full run and one focused
  rerun after a transient Docker PostgreSQL authentication failure.
- Explicit root-key import/rotation/replay, private-source rejection, generation
  bounds and suspended runtime activation regression passed.
- Populated0099/9009 upgrade preserves app/source identities, encrypted secrets,
  environment root keys and links; restricted runtime checks enforce isolation.
- OBO proof lifetime300/3600/i32-bound regression and consent revocation passed.
- Separate bootstrap replay regression passed. Strict workspace Clippy,
  formatting, migration security, runtime grants, route/schema and dependency
  checks passed; frontend40tests and production build passed.
- SDK/CLI package verification passed. Native packaging tests and actionlint passed.
- Docs were built and deployed with Vercel prebuilt output; live shared-testing
  documentation includes environment-only keys and credential recovery.

## Deployment fence

The deployed ledgers contain107production and120testing entries with exact
source checksums. Both backups were verified before migration. An old-image-only
rollback after migration is unsafe.

After Honeycomb0.1.1 deployed healthy, enabled scheduled-testing authority in
SecretsManager and all three runtime environments. SSM command
`40a80be2-b294-47fc-a72e-b8ddb1febaec` verified readiness and the effective flags.
Legacy writer cutover remains false. Scheduled authority lets the authenticated
coordinator finalize only after participant acknowledgements; it is not an
end-user testing-enable key.
Public publication requires an explicitly designated validator; no administrator
is automatically granted that separate capability and no consent is fabricated.
