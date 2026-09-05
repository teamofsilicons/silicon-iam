# Keep application consent bound to its parent login

A Carbon signs into the same application from a second IAM session. Previously,
`approve_request` reused the unique application/subject/organization consent row
and replaced its parent session. Existing refresh families still referenced that
row and their original parent. Current-authority checks then rejected them even
though their own parent login remained active.

Silicon Browser exposed this when its independently owned recording family was
created through a CLI login and the same person subsequently signed into the web
dashboard. The recording was captured, but renewal for delivery was rejected.
The deployed IAM build observed during investigation was `1db1cc1e39867fb03e5021fa3a15c5e77885008b`.

The fix includes the parent session in the consent uniqueness constraint and
upsert conflict target. Repeated authorization within one parent still reuses its
grant. A second parent receives a separate grant. A database trigger prevents an
existing grant from moving to another parent. Scope ceilings, subject/session
liveness checks, membership checks and revocation checks remain enforced.

Migration 0070 preserves existing rows and credentials. It does not reactivate
previously invalidated families; affected applications need one fresh
authorization after rollout.

## Verification

An isolated native PostgreSQL 16 database used the real migrations and protocol
fixture. Executing the production upsert before the fix changed the original
grant's current-authority count from one to zero while its parent stayed active.
After migration 0070 and the new upsert, two separate grants existed and the
original grant remained authorized.

The full ignored PostgreSQL protocol test passed, including scoped and unscoped
consents, same-parent reuse, independent parent authority, mismatched-parent
rejection, independent revocation and rejection of parent mutation. The existing
single-use credential and revocation checks also passed. The standard server
suite passed 339 tests, with 21 environment-dependent tests ignored. Formatting,
the migration security audit and warning-denied all-target Clippy passed.

To run the protocol suite without Docker, supply `IAM_TEST_DATABASE_URL` pointing
to an empty disposable PostgreSQL database and run:

```sh
cargo test -p silicon-iam --lib protocol_credentials_are_single_use_and_revocation_is_atomic -- --ignored
```

## Rollout requirement

This changes the constraint used by login approval. Old API binaries use the old
three-column conflict target and must not serve login approvals after migration
0070. Prepare the new release, coordinate migration of production and testing
databases with replacement of all API instances, and resume traffic only on the
new binary. Do not treat a binary-only rollback as compatible with the new
schema. Existing authentication sessions are not forcibly ended by the fix.
