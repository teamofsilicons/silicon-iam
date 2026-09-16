# Honeycomb contracts release — September 16, 2026

## Prepared release

Backend source: `44019d162cf9504164bf1b2e50362fb00389fa4c`.
This includes publication and shared testing contracts plus migration0105,
which removes the obsolete60-second OBO proof ceiling in favor of the existing
positive i32 endpoint-lifetime bound. Parent token, consent and revocation
checks remain enforced.

Production rollout is pending renewed AWS SSO authentication. The previously
deployed missing-webhook hotfix remains `72767708d9ac2e7bf11873aee9bc8800da3c4835`.
No new migration, environment-key change, validator grant or cutover has been
performed by this release preparation.

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

Apply105base migrations and13testing overlays using the reviewed dual-database
release script, with both databases backed up while writers are stopped.
Require exact ledger checksums and matching main/scoped/worker image revisions.
Persist the accepted image in CloudFormation afterward. An old-image-only
rollback after migration is unsafe.

Keep scheduled-testing and legacy-writer-cutover flags false until Honeycomb's
real adapter and participant acknowledgements are ready. These flags grant
service maintenance authority; neither is an end-user testing-enable key.
Public publication requires an explicitly designated validator; no administrator
is automatically granted that separate capability and no consent is fabricated.
