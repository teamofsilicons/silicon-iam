# Testing credential rotation release — September 23, 2026

IAM backend **3.0.2** is committed, pushed and published. Production deployment is pending
renewal of the operator's `silicon-production` AWS SSO session. No production
credential or database has been changed by this release yet.

## Fix and source

Source: `2f24d2203bbab8ee1cc740848a1516d36fb17816`.

Honeycomb's authorized test rotation runs without a Carbon principal in the
testing database. The former owner-only snapshot updater silently changed zero
rows, leaving OBO and recovery with a retired credential despite a successful
authentication-secret rotation. Migration `0117` updates the active digest and
encrypted import snapshot atomically; a missing snapshot aborts the transaction.

An explicitly supplied configuration revision zero is valid for rotating an
unchanged import. Missing, negative and stale revisions are rejected;
configuration writes still require a positive increasing revision. IAM CLI
remains 3.1.2 and the Rust client remains 3.1.0.

## Verification and artifact

The original failure was reproduced before the fix. Final-source restricted-role
PostgreSQL tests verify a usable OBO audience credential, exact replay and
recovery, imported revision handling, environment isolation and complete rollback
when the snapshot update cannot succeed. The local workspace suite passed 538
tests; final-source Clippy, migration security, runtime grants, OpenAPI and
generated-documentation checks passed.

- [Complete source CI](https://github.com/teamofsilicons/silicon-iam/actions/runs/35791739076)
  passed, including all live PostgreSQL protocol tests, fresh dual-plane
  migrations and the restricted-role live client contract.
- [ARM64 image build](https://github.com/teamofsilicons/silicon-iam/actions/runs/35791795399)
  succeeded for the exact source above.
- Image archive: 73,501,535 bytes, SHA-256
  `57bbfd2902c75fd1e12478436d192d5b1d7861d68aba3d85688e24da5f3d800a`.
- Image config digest:
  `sha256:632e0e79ca0739d3879c0c4d87e9829ee149d2812c3e03cf2fca20a16009d9eb`.
- Archive checksum, OCI configuration digest, Linux ARM64 platform, version and
  source labels were verified independently after download.
- [Backend release](https://github.com/teamofsilicons/silicon-iam/releases/tag/backend-v3.0.2)
  publishes the exact source, image archive, checksum and image metadata. GitHub's
  uploaded-asset digest matches the locally verified archive. The CLI's separate
  latest release remains `v3.1.2`.
- [Documentation](https://docs.iam.teamofsilicons.com/honeycomb-integration/)
  was deployed through the existing `silicon-iam-docs` Vercel project, deployment
  `silicon-iam-docs-kaov7h413-saketdev12-5675s-projects.vercel.app`.
  The build checked 47 pages; live integration documentation, OpenAPI and
  installer match the built bytes. Security headers and old `/docs/` redirects
  remain present.

The private release workspace is `/tmp/ting-rotation-release-20260923/`.
Its migration manifest expects 116 production and 130 testing ledger entries.
ECR publication has not completed: the retained registry credential returned 403,
and AWS SSO refresh reports an expired session. No deployment was attempted.

## Remaining rollout and recovery

Renew AWS SSO, publish the verified image to the existing IAM ECR repository,
then run the existing coordinated dual-database release operator. Rehearse the
exact image against restored backups before stopping writers and applying
migration `0117` to both planes. Preserve credentials and runtime configuration;
verify the running API, scoped API and worker against the pinned digest and
source revision before updating the durable infrastructure configuration.

Deploy Honeycomb 0.3.3 after IAM. Recover the original test rotation
`a2b700ff-90dd-4795-b6c1-27e98871ba9c` in environment
`d70c8674-6d2e-41d4-bf8d-96ddd882edbd` through its existing account and operation.
Its specific pre-mutation revision rejection must become terminal without
rewriting the saved request. Reconcile the application, then perform a new
authorized rotation with a new idempotency key.

The already-accepted Ting rotation in environment
`1d32b4c6-dc84-4c44-b7b7-a16be7a31d06` also needs a new authorized rotation to
repair its stale encrypted snapshot. Replaying the old accepted operation
returns historical results and cannot perform this repair. Keep new secrets in
private files and reauthenticate the task's affected test receivers. Confirm that
fresh official-SDK OBO responses authenticate with IAM and that real DM delivery
and receipts succeed before marking the integration issues resolved live.
