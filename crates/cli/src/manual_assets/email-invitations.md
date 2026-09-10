# Email invitations before signup

Email invitations no longer require a pre-existing Carbon. An invite stores a
row-bound encrypted email and versioned HMAC indexes. Creation does not create a
Carbon or grant organization membership. Existing Carbon-ID invitations retain
their lookup requirement.

Recipients follow `/join/{org_id}`, sign up or sign in, and submit the invited
email. A privileged database helper binds an unassigned invitation only to the
current active Carbon with that exact active, verified contact. The existing
OTP and acceptance checks then apply. The invitation expires after 48 hours and
can be revoked before registration. Creation and binding share a tenant lock;
normalized email duplicates are rejected and idempotent retries replay safely.

`target_carbon` is absent from invitation responses until binding. The frontend
and Rust client/CLI support that optional field; the console shows the masked
email before signup. The frontend retains the organization through signup.

## Rollout

Apply migration `0076` and the updated runtime grant manifest to production and
testing databases before deploying the API and notification worker, then deploy
the frontend. The migration preserves existing invitations. Do not roll back to
an old API or worker while unbound invitations exist: old binaries require a
non-null Carbon/contact. Prefer a forward fix or pause creation before rollback.

## Validation

- Workspace unit tests, Clippy, frontend compilation, and invitation URL tests.
- All 22 Docker-backed database tests, including creation before registration,
  restricted-role listing, worker lease checks, verified binding, and acceptance.
- Disposable local API/worker smoke: signup, unknown-email creation, delivery,
  idempotency, normalized duplicates, wrong email/code rejection, acceptance,
  revocation, and expiry. Acceptance uses a deterministic test OTP digest seeded
  only in the disposable local database; no production contacts are used.
- OpenAPI routing, generated client/manual consistency, migration security, and
  runtime grant checks.
