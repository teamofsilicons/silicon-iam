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

## Disable a failing Apple registration while preserving Google

This is a reviewed alternative to supplying an Apple candidate, not a general
provider removal or credential rotation mode. Use a **fresh** host plan directory
and workstation receipt, bound to the current secret version. Never reuse an
already-applied activation plan.

- Pass `--disable-apple` to both host `plan` and `apply` actions.
- Stage with the protected existing `--google <candidate.json>` and
  `--disable-apple`; `--apple` and `--disable-apple` are mutually exclusive.
- Promotion uses the saved receipt and fresh host plan. It rejects an
  enable/disable mode mismatch before changing `AWSCURRENT`.

The staging helper removes only `IAM_APPLE_CLIENT_ID` and
`IAM_APPLE_CLIENT_SECRET`. It requires Google values to equal the current secret,
retains all unrelated fields, and preserves the same version CAS and rollback
rules. The host additionally checks that both authentication environment files'
Google values match the preserved candidate before stopping any service. It
removes only Apple environment lines, preserving every remaining byte, including
Google lines. Partial or empty provider pairs are rejected. When Apple is
present, the existing exact Services ID, Team ID, Key ID and JWT checks remain.

Successful apply must show Google signup/login enabled and Apple signup/login
disabled; the scoped API must still return 404 for discovery. Source, schema,
image, unit and worker checks remain unchanged. The receipt records the two
removed Apple fields and the disabled provider. No CloudFormation change is
needed when its optional-provider rendering is already deployed.
