# Honeycomb contract backend release

`release-honeycomb-contracts.py` prepares and executes an upgrade of the existing
IAM API, scoped API and worker. The `manifest` and `plan` commands do not access
AWS or change the production host. Only `execute` performs the rollout.

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
   captures uncommitted SQL. For this contract release, verify that production
   ends at 0106 and testing ends at 9013 (106 and 119 entries respectively).
4. Transfer the script and manifest to a private directory on the existing IAM
   host. Keep database credentials in Secrets Manager. Supply only secret ARNs
   and RDS endpoints as arguments; the script obtains credentials in memory.

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
  --region "$AWS_REGION"
```

The host's instance role supplies AWS access. The script serializes execution
with a host lock and reports only safe checkpoint metadata. Full command output,
configuration backups, migration receipts and database dumps remain under a
mode-0700 `/etc/silicon-iam/releases/contracts-<revision>-<timestamp>` directory.
These files can contain credentials and must remain private.

## Checkpoints

1. **Preflight:** pull both pinned images; validate backend architecture and
   revision; check existing readiness, all units, and every existing database
   migration checksum. Prepare replacements and copy runtime configuration.
2. **Quiesce and back up:** stop all three units; create custom-format dumps of
   both databases; validate each archive with `pg_restore --list`; record sizes
   and SHA-256 checksums. Migrations cannot begin until both backups pass.
3. **Migrate:** durably mark migration start; run the release's dual-database
   migrator; apply its runtime grant manifest to both databases; install the
   scoped authentication SQL helper. Verify both complete ledgers exactly.
4. **Start:** install the release image in all three units, preserve other runtime
   settings, and explicitly set both `IAM_HONEYCOMB_SCHEDULED_TESTING` and
   `IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS` to `false`. Check both API revisions,
   readiness, running container images, and effective disabled flags.
5. **Acceptance:** the script reports `healthy-acceptance-gates-pending`. Run the
   authenticated IAM/Honeycomb end-to-end checks before enabling either flag.
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
