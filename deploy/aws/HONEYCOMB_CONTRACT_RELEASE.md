# Honeycomb contract backend release

`release-honeycomb-contracts.py` prepares and executes an upgrade of the existing
IAM API, scoped API and worker. The `manifest` and `plan` commands do not access
AWS or change the production host. Only `execute` performs the rollout.

The October 2026 IAM redesign requires the coordinated consumer gates in
[`docs/OBO_CUTOVER.md`](../../docs/OBO_CUTOVER.md) and the backup and restore
requirements in [`docs/RELEASE_READINESS_2026_10_03.md`](../../docs/RELEASE_READINESS_2026_10_03.md).
This helper does not deploy consumers or establish application-flow acceptance.
Its Honeycomb flags do not preserve the retired OBO proof routes. Do not deploy
the complete redesign to IAM alone while consumers still use those routes.

## Prepare the immutable inputs

1. Finish release checks, commit the complete source, and build the ARM64 image
   from a clean checkout with its full commit in `BUILD_REVISION`. Push the image
   and record its immutable ECR digest. Record the currently deployed image and
   revision separately.
2. Select an immutable ARM64 PostgreSQL client image. Its client major version
   must be at least the server version; the script checks both databases before
   stopping services. The current RDS databases use PostgreSQL 17.
3. Generate the migration manifest from the exact committed source:

   ```sh
   python3 deploy/aws/release-honeycomb-contracts.py manifest \
     --source /path/to/clean/silicon-iam \
     --revision "$RELEASE_REVISION" \
     --output /private/release/migration-manifest.json
   ```

   This uses committed Git objects, including SQLx SHA-384 checksums. It never
   captures uncommitted SQL. The 3 October 2026 redesign inventory contains
   139 main migrations through `0141_obo_provider_disclosure_consent.sql` and
   30 testing overlays through `9032_obo_provider_disclosure_consent.sql`:
   139 production ledger entries and 169 testing ledger entries. Numbering has
   intentional gaps. Recalculate this inventory from the final release commit
   if it changes; do not infer counts from the highest migration number. Every
   already-applied checksum must match the corresponding committed migration.
4. Transfer the script and manifest to a private directory on the existing IAM
   host. Keep database credentials in Secrets Manager. Supply only secret ARNs
   and RDS endpoints as arguments; the script obtains credentials in memory.

## Isolated production-data rehearsal

Before any writer shutdown, use `rehearse-contract-release.py restore` with the
exact migration manifest, pinned PostgreSQL image and a private JSON file mapping
`production` and `testing` to their `host` and Secrets Manager `secret` ARN. Use a
fresh `/etc/silicon-iam/releases/rehearsal5-<timestamp>` directory. This reads live
data into verified dumps and restores both databases with their original roles
and ACLs in a network-none container limited to 512 MiB and one CPU. It preserves
the restricted migrator role, modeling only the actual RDS role-administration
capability in the isolated copy. It never runs canonical-ID prepare/convert.

When the pinned ARM64 release image is locally available, run the helper’s
`migrate` command against the same directory with its manifest and `--image`.
It runs that image’s dual-database migrator, runtime grants and scoped helper in
the isolated network namespace; verifies every checksum and preserved identity
and credential rows; then removes only its own successful restore container and
volume. Failed copies remain for private diagnosis. Online dumps do not replace
the final paired quiesced backup.

## Review and execute

First run `plan` with these arguments. After reviewing the output, run the same
arguments using `execute` as root on the existing IAM host:

```sh
python3 release-honeycomb-contracts.py plan \
  --migration-manifest /private/release/migration-manifest.json \
  --revision "$RELEASE_REVISION" --image "$RELEASE_IMAGE_DIGEST" \
  --previous-revision "$CURRENT_REVISION" --previous-image "$CURRENT_IMAGE_DIGEST" \
  --postgres-image "$POSTGRES_CLIENT_IMAGE_DIGEST" \
  --production-host "$PRODUCTION_RDS_HOST" --production-secret-arn "$PRODUCTION_DB_SECRET_ARN" \
  --testing-host "$TESTING_RDS_HOST" --testing-secret-arn "$TESTING_DB_SECRET_ARN" \
  --backup-bucket "$PRIVATE_RECOVERY_BUCKET" --backup-prefix "$UNIQUE_RELEASE_PREFIX" \
  --region "$AWS_REGION"
```

The host's instance role supplies AWS access. The script serializes execution
with a host lock and reports only safe checkpoint metadata. Full command output,
configuration backups, migration receipts and database dumps remain under a
mode-0700 `/etc/silicon-iam/releases/contracts-<revision>-<timestamp>` directory.
These files can contain credentials and must remain private. The host role needs
`s3:GetBucketPublicAccessBlock` on the recovery bucket and `s3:PutObject`,
`s3:GetObject` and `s3:GetObjectVersion` only on the chosen release prefix. The
operator does not change bucket policy, ACLs, encryption or existing versions.

## Checkpoints

1. **Preflight:** pull both pinned images; validate backend architecture and
   revision; check existing readiness, all units, and every existing database
   migration checksum. Prepare replacements and copy runtime configuration.
   Before shutdown, verify all four bucket public-access blocks and probe exact
   versioned encrypted object upload/read permissions under the release prefix.
2. **Quiesce and back up:** stop all three units; create custom-format dumps of
   both databases; validate each archive with `pg_restore --list`; record sizes
   and SHA-256 checksums. Bundle both dumps with saved environment, units, ledgers
   and release metadata; upload using AES256 encryption into the private versioned
   recovery bucket. Verify the exact object version, SHA-256 checksum and length
   via `HeadObject`. Persist `offhost-backup.json`. Migrations cannot begin until
   both local dumps and the off-host paired recovery receipt pass.
3. **Migrate:** durably mark migration start; run the release's dual-database
   migrator; apply its runtime grant manifest to both databases; install the
   scoped authentication SQL helper. Verify both complete ledgers exactly.
4. **Start:** install the release image in all three units and retain environment
   files byte for byte. Preserve each service's current
   `IAM_HONEYCOMB_SCHEDULED_TESTING` and `IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS`
   values, recorded during preflight. Missing values retain the `false` default;
   unrecognized values or inline unit overrides stop preflight for review. Check
   both API revisions, readiness, running images, and unchanged effective flags.
5. **Acceptance:** the script reports `healthy-acceptance-gates-pending`. Run the
   authenticated IAM/Honeycomb and coordinated consumer end-to-end checks.
   Changing either Honeycomb flag is a separate reviewed configuration action;
   this helper neither enables nor disables it.
   Persist the verified image in the existing infrastructure configuration using
   the separately reviewed deployment process. This script does not update
   CloudFormation or replace the instance.

The scoped helper initialization installs a SQL function; it does not register
an application. This script performs no app creation, scope or consent changes,
credential provisioning, or secret-store mutations.

## Failure recovery

After writer shutdown, any failure leaves all three units stopped and records
the stage in `state.json`. The script never automatically starts an older image
against migrated databases. A partial production/testing migration is possible;
consult both ledger receipts and the private log.

Prefer a forward repair that preserves every applied migration checksum. If
database restoration is required, verify both dump checksums and restore **both
databases** together with the saved environment and service units while all
writers remain stopped. Review external effects and any writes since backup
before selecting restoration. Start the previous image only after both restored
ledgers are compatible with it and the original configuration has been restored.
Restoration is a separate, explicit operator operation; rerunning this release
script is not a restore procedure.
