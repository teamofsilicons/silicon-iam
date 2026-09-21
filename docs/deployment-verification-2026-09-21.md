# Canonical identity release verification — 21 September 2026

This records post-deployment acceptance of the canonical identity and sensitive-action
release. Infrastructure, database backup, and final release completion evidence can
be appended separately. No production profile, organization policy, message, or paid
browser session was changed by these acceptance checks.

## Released surfaces

- IAM API reports version `3.0.0`, source
  `deea75e3d8f9b331bf9ef25e5d39c6546ed5a9fd`, image digest
  `sha256:f799c1172e16be44c1959159f599bc312e5cfcbbf9e45e9ced75132117b2fd7a`.
- Rust client and CLI `3.0.2` are published. Native CLI publication includes all
  six supported targets, checksum verification, Linux compatibility checks, and
  a fresh anonymous install.
- The frontend was promoted only after the canonical backend became healthy:
  Vercel deployment `dpl_Fkc82BAZQTF3JaLrd7QCwpHqn7U9`, serving
  [IAM](https://iam.teamofsilicons.com/) and
  [IAM authentication](https://auth.iam.teamofsilicons.com/).
- Documentation deployment `dpl_9YcGWDpv7RLZWG2qMJ2uFC2du5kt` serves
  [IAM documentation](https://docs.iam.teamofsilicons.com/), including the
  [sensitive-action policy guide](https://docs.iam.teamofsilicons.com/api/governance/).

## Existing credentials and visible application behavior

The retained Browser authentication family was refreshed normally before the IAM
pause. Its new access token was recorded privately, and the exact same token was
used after the switch before any further refresh. `/me`, `/orgs`, `/profiles`,
`/sessions`, and `/recordings` all returned HTTP 200. IAM introspection reported
the same session resource UUID and the canonical account handle without a
`principal_id` field. Normal refresh then succeeded in the same family, and an
exact retry of the previous refresh request returned the identical credentials.

The existing browser session in the IAM frontend remained signed in after the
deployment. The organization view showed its canonical owner membership handle
and all 14 policy rows. The Silicon detail view showed the permanent Silicon ID,
canonical membership ID, existing timezone, and one **Job Description** field
containing the existing job text. It exposed no independent principal ID.

The existing Interface account was reloaded after the cutover. Messages loaded
the retained conversation history. Browser's **Live now** and **All sessions**
views loaded their authorized results without a reconnect or provider-response
error. No new login was needed for these post-cutover Interface checks.

## Isolated feature acceptance

Every mutation below included the root key for an agent-created testing
environment. The complete flow passed against the public production deployment
while all resulting account and organization data remained in that testing world.

1. Carbon signup, login, canonical identity output, profile timezone update to
   `Asia/Kolkata`, and token refresh.
2. Organization and Silicon creation, Silicon token login, Silicon self-timezone
   update to `America/New_York`, and organization directory readback.
3. Public responses omit `principal_id` and configurable trust `advisory` fields.
   Silicon creation and readback use one `job_description` field, with no separate
   `job_role` or profile `description` field.
4. The complete catalog matches the [14 defaults](SENSITIVE_ACTIONS.md). In
   particular, Job Description permits **Any member / None** and applies directly
   without producing an approval request.
5. After the owner explicitly configured admin approval, a Silicon's mutation
   returned HTTP 428. The owner reviewed the exact body and path, approved it,
   and the Silicon retried the same mutation, version, and idempotency key.
   Application and subsequent identical replay both succeeded.
6. A configured permanent Silicon ID satisfied automatic approval without a
   manual request.
7. A delegated administrator with the required action and approval capabilities
   applied the action directly. The owner also applied it directly. An
   administrator holding `action_policies.manage` successfully changed the rule;
   an owner-only rule denied the Silicon with HTTP 403 while allowing the owner.
8. A matching membership tag, with both identity selector lists empty, satisfied
   otherwise-required admin approval. Retaining the matching tag while changing
   the requester tier to **Only admins** denied the ordinary Silicon with HTTP
   403 and left its member version and body unchanged. Tag matching therefore
   satisfies approval without granting action eligibility.

The tag-assignment check also confirmed existing authorization invalidation:
assignment increments the membership authorization epoch, and an access token
issued before that change is rejected. The automatic-approval test used current
credentials after the assignment.

## Test cleanup and evidence handling

Private test tokens, root keys, response bodies, and exact access-token hashes are
kept outside the repository. The owned testing world is
`1d8ccde9-4b13-4a4d-a88b-49ed402eab2a` ("Browser canonical authentication proof").
After Browser, Briefcase, and IAM acceptance completed, its deletion was requested
through Honeycomb's normal environment-management API. A readback confirmed
`state=deleted`, revision `2`, and no pending operation; its normal retention
period remains in effect. Unrelated environments,
including the separate Commit acceptance world, were left untouched.

The test scripts and redacted deployment/UI proof are retained privately for the
release operator. This document records observed live acceptance; it does not
substitute for the CI result, database restore proof, or final infrastructure
rollout record.
