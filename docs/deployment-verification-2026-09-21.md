# Canonical identity release verification — 21 September 2026

This records the canonical identity and sensitive-action release, its database
restore rehearsal, production deployment, and post-deployment acceptance. No production profile, organization policy, message, or paid
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


## Database backup, rehearsal, and cutover

Both encrypted native RDS snapshots became available before the cutover:
`silicon-iam-before-canonical-20260921` and
`silicon-iam-testing-before-canonical-20260921`.

The operator restored both databases with their real owners, ACLs, role
memberships, and restrictive RLS settings. The exact final image passed this
rehearsal before all three IAM writers were stopped. Final quiesced dumps,
runtime configuration, migration ledgers, private identity mappings, and
credential fingerprints were archived off host before migration. The private,
versioned, encrypted recovery object is:

- Bucket: `silicon-iam-recovery-234951665042-us-east-1`
- Key: `canonical-20260921/quiesced-databases-and-config.tar.gz`
- Version: `mZnw6DHSwP4sRlZXj3V53Xi5Sj.yWL.S`
- SHA-256: `4441dcc42b5b809ea843f96b3029b13619772fa5aae94d6b6fb16230350a4e91`

SSM command `d3aee19c-578d-4382-9372-3c0223c7cb17` completed successfully.
Both migration ledgers reached 0114, canonical identity relationships passed,
and six credential-table fingerprints remained unchanged except for the intended
identity reference representation. Runtime environment hashes were unchanged.
The main API, scoped API, and worker run the same immutable final image; both
public readiness endpoints returned 200.

The migration changes IAM identity keys and their references, while preserving
independent organization, membership, session, and application resource UUIDs.
Existing encrypted data retains its original private cryptographic context.
Private bounded replay metadata allows existing identical retries without
reintroducing legacy UUID authentication. A rollback requires both database and
configuration restoration; an image-only rollback is incompatible with the new
schema.

## Durable replacement configuration

CloudFormation `silicon-iam-production` reached `UPDATE_COMPLETE` with launch
template version 47, pinned to the deployed image and verified TLS archive.
The update preserved the current instance and capacity. Replacement bootstrap
now provisions the main API, scoped API, worker, and direct Nginx ingress in the
retained network interface's availability zone. It preserves secret values and
refuses to take an interface attached to another instance. No reboot or instance
refresh was used as a production test.

## Retained consumer data and sessions

DM's installed Maharaj CLI returned the same three conversations, and Interface
loaded the complete existing history. Hook's existing `chef:bricks` registration
remained online. Browser's retained access token and refresh family passed the
checks above. Briefcase retained file ownership and entries, including exact
refresh replay. Remind preserved all 14 retained reminders; Waveform preserved
its two jobs, preferences, and provider-key list through normal same-family
refresh.

Commit preserved its retained projects, todos, notes, diary, history, ownership,
and three existing idempotent replays. Its installed CLI renewed an intentionally
expired access token through the existing refresh family. Its separate browser
cookie had expired, so browser acceptance used normal same-Carbon reauthentication
and verified the retained data plus an isolated create/edit/delete flow.

IAM access tokens still last 30 minutes. The session fixes add automatic renewal
to Commit and Waveform resource requests, with locking, atomic persistence, and
safe refresh retries; they do not lengthen access-token lifetimes. Authorization
changes such as tag assignment still invalidate older access tokens intentionally.


## Honeycomb application management follow-up

The final retained-environment check found an outer Honeycomb verifier still
requiring an application UUID. It now requires the canonical application ID,
while preserving organization UUID and organization-handle checks. A verified
private pre-cutover map migrated only the matching historical owner and link
bindings. Exact original create retries retain their resource and operation IDs;
unreconstructable historical hashes have an operation-bound private context,
which is never accepted as an authentication identity.

Honeycomb source `3a6351dad128366491854df73e90f4b28d29111b` and migration 23
were deployed successfully by SSM `2397ab21-beb5-4985-a56b-3324330f667f`.
A quiesced, encrypted, versioned off-host backup preceded all 16 reference/digest
conversions. Business fingerprints, encrypted data, resources, and runtime
configuration were preserved. Normal saved-session application reads succeeded.
The consumer repository records the image, backup checksum, and detailed proof.

One agent-created partial Browser testing world,
`2639e06a-bd6a-4656-8709-26e38c9ebec7`, remains tracked separately. Its original
pending import requires Browser's unsupported protected lifecycle integration,
and the normal API rejects deletion while an import is pending. One retry
confirmed the limitation; no manual database deletion was used. This does not
affect the verified production Browser authentication or UI. All feature accounts
and organizations belonged to the successfully deleted acceptance world.

Browser navigation to both IAM frontend domains returned 200 with the normal
`Accept: text/html` header. Requests accepting only generic content return the
existing 404 behavior because the gateway's SPA fallback is HTML-specific.

The separate Commit acceptance world was subsequently deleted through its
retained production application's normal owner credentials. The original create
replay first returned the identical environment and operation, while changed
input returned 409. Deletion operation `ac0ea930-ba96-4bdb-b315-3c84893eda7c`
completed with matching Commit, IAM, and Honeycomb participant receipts. Seven
old test-credential probes returned 401, verifying revocation.
