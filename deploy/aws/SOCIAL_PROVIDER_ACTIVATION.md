# IAM 5.1 provider activation

These are internal operations for the reviewed 2026-10-03 production release.
The activation scripts deliberately bind Apple's confirmed Team ID, Services ID
and Key ID, and the workstation promotion guard binds backend source `45a3fdf`.
They are not a general-purpose secret editor. Never pass credentials as command
arguments, print secret bodies, or upload the Apple signing key to the runtime.

The backend's full CI, exact-image restored-database rehearsal, paired recovery
backups, migration, runtime grants and health acceptance must pass first. Publish
the matching frontend before enabling provider discovery. Real OAuth and Apple
relay delivery still need separate acceptance after configuration succeeds.

1. Validate the two protected provider candidates with the Apple helper and the
   reviewed activation checks. Save their nonsecret expiry/claims receipts.
2. Read the current application secret version from Secrets Manager. On the IAM
   host, run `activate-social-providers.py plan` with the exact source, complete
   migration manifest, immutable PostgreSQL image, secret ARN and prior version.
   Use a fresh `/etc/silicon-iam/provider-activations/<operation-id>` directory.
   Save its JSON output locally as the host plan. It verifies both runtime API
   sources and complete schema ledgers, records environment/unit/image hashes,
   and privately backs up the environment files. It changes no running service.
3. On the workstation, run `stage-social-provider-secret.py stage` with
   `--google`, `--apple`, `--previous-version`, `--secret-arn` and a `--receipt`
   inside an existing 0700 directory. This merges only the four provider fields
   into a fresh read of the secret and saves an idempotent operation ID before
   writing a candidate version. It does not move `AWSCURRENT`.
4. Run `stage-social-provider-secret.py promote` with that receipt, secret ARN
   and `--host-plan`. The label move uses both expected prior and candidate
   version IDs; a concurrent third version is rejected. A lost success response
   can be retried using the same receipt without moving the label again.
5. Run the host script's `apply` action with the same directory and arguments,
   adding `--candidate-version`. It rechecks source, schema, secret version and
   all recorded hashes. It briefly stops only the two authentication APIs,
   updates only their provider fields, restarts them, and verifies their actual
   running environments, source, readiness and login-provider discovery. The
   worker receives no Google or Apple credential and is not restarted.
6. If activation fails, inspect its private failure receipt. The host attempts
   to restore only its own changes to the same reviewed backend, without
   overwriting concurrent configuration changes. Run the workstation helper's
   `rollback` against the same receipt to restore the prior secret label using
   the reverse compare-and-swap. Verify both services before any fresh attempt;
   the host rejects blind repetition of an already-attempted activation.
7. Persist the updated optional API provider rendering and exact backend image
   in the production CloudFormation launch template. Review the change set
   first: preserve unrelated parameters/resources, do not replace the current
   instance or trigger an instance refresh, and verify the existing instance
   remains healthy afterward. The scoped API inherits the API environment on
   a future host; the worker remains excluded.

The scripts never migrate the database, alter IAM grants, publish a CLI or
perform user authorization. An `activated: true` receipt proves configuration
and service health, not successful Google/Apple login. Apple JWT renewal is an
explicit operator task described in `SOCIAL_PROVIDERS.md`, with a saved due date;
this release does not install an unattended renewal scheduler.
