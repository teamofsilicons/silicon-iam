# Canonical identity release operator

`release-canonical-identities.py` performs the coordinated, in-place upgrade of
the existing production and testing PostgreSQL databases and all three IAM
services. It does not replace credentials, encryption keyrings, infrastructure,
application registrations, or runtime environment files.

Generate a private migration manifest from the exact immutable image revision:

```sh
python3 deploy/aws/release-canonical-identities.py \
  --write-manifest /private/release/manifest.json \
  --revision FULL_GIT_REVISION --source /path/to/silicon-iam
```

The nonsecret settings JSON must supply `revision`, `image`, `previous_revision`,
`previous_image`, `postgres_image`, `region`, `production_host`,
`production_secret_arn`, `testing_host`, `testing_secret_arn`, and
`migration_manifest`. Image references require SHA-256 digests, source revisions
require full commit SHAs, and the PostgreSQL client must support the live server
version. Protect the settings, manifest, operator, and release directory on the
existing IAM host. Database owner passwords are fetched there and never printed.

Run an initial rehearsal on that host:

```sh
sudo python3 /private/release/operator.py \
  --settings /private/release/settings.json --rehearse-only
```

It verifies current service revisions and historical migration checksums, takes
online backups of both databases, restores both into an isolated PostgreSQL
container with no network or published ports, and runs the exact preparation,
migrations, runtime grants, encrypted-data conversion, and scoped helper setup.
The restore preserves ownership, privileges and role memberships. Migration
commands use the live migrator role attributes rather than PostgreSQL superuser
authority. Credential fingerprints verify unchanged token digests, expiry state,
session resource identifiers and other fields apart from canonical identity links.
For RDS, `rehearsal_rds_role_admin: true` can model the managed service's existing
ability to re-grant the testing-definer role. Enable it only after verifying that
exact operation with the real migrator inside a rolled-back transaction. The
isolated model adds that role's ADMIN capability only; it preserves the migrator's
NOSUPERUSER/NOBYPASSRLS restrictions and records the exception in the private
rehearsal evidence. It changes no production role or schema privilege.
The successful rehearsal removes its container. Failed rehearsals preserve a
private diagnostic container and leave the live services unchanged.

Before actual execution, finish consumer compatibility migrations and retained
session/resource checks. Retain encrypted native RDS snapshots of both planes.
Protect the serving singleton from automatic replacement if its launch template
has not yet been verified against the new release. Never replace it merely to
test deployment configuration.

Execute by omitting `--rehearse-only`. A fresh isolated rehearsal runs again before
any live pause. The operator then stops API, scoped API, and worker together;
saves and verifies final quiesced backups and the private identity mapping;
prepares and migrates both planes; applies grants and encrypted-data conversion;
and pins all three existing systemd units to the new image. It checks readiness,
source revisions, containers, complete migration ledgers, canonical invariants,
and unchanged environment file hashes. The final checkpoint still requires
authenticated consumer and feature acceptance before declaring the release done.

Recovery instructions are written to the protected release `state.json`. After
migration starts, an image-only rollback is unsafe. Keep writers stopped and
repair forward, or restore both databases and the saved configuration together
before starting the previous image. Backups, private logs, and identity exports
contain sensitive account material and must not be published.
