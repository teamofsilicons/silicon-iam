# IAM redesign implementation contract — 2 October 2026

Source: the user's implementation brief in the current chat. This document records
the work and decisions; it does not modify the human-owned `UNDERSTANDING.md` and
does not establish that a feature is deployed. Existing uncommitted separate-OBO
work is the starting point, with the changes below superseding conflicting parts
of that earlier design.

## Boundaries

IAM owns global Carbon/Silicon identity, credentials, memberships, organization
authority, directory visibility, login, consent, runtime verification, revocation,
audit and identity notifications. Honeycomb owns application configuration and
the management UI/CLI for endpoint definitions and ATA verifications. Its service
integration submits authenticated, actor-bound changes to IAM. Apps continue to
enforce their own resource permissions after verification.

CLI coverage is a release requirement for every user action. Browser workflows
use the same backend contracts. Production deployment requires a coordinated
consumer migration; this task's local edits alone are not deployment evidence.

## Identity and onboarding

- Carbon signup requires verified email. Phone is optional; a supplied phone
  must be verified before it becomes an account contact.
- Google/Apple provider assertions must be validated server-side (issuer,
  signature, audience, nonce, expiry, verified email). Provider identity binds
  to the provider's immutable subject. Email matching an existing account
  offers login and never silently merges independent accounts.
- Suggest an available canonical `c:handle`, display name, Iris portrait and
  request timezone; allow profile photo upload and overrides. Authenticate at
  successful completion, then require an active organization membership.
- Silicon identity/profile/credential is independent of organization membership.
  Independent signup has a verified Carbon custodian; organization-created
  Silicons have an organization custodian. Existing Silicons retain identity,
  credentials and organization membership during migration.
- A user-selected STK is a case-sensitive 12–24 character password, requiring a
  password hash. Legacy high-entropy STKs keep their compatible verifier.
  Generated signup credentials are returned once through a protected response.
- Custodian requests have explicit pending/approved/rejected/expired outcomes.
  A resumed CLI wait uses the same pending request. Webhooks report the durable
  transition with bounded retries and event IDs, without returning credentials.
- Custodian authority covers approval and the configured organization-creation
  setting. It does not grant credential-reset, profile-control or impersonation
  rights. A Silicon denied organization creation can finish onboarding by
  accepting an existing organization invitation.
- Organization managers can configure this setting for Silicons actually owned
  by their organization. An invited Silicon retains its original custodian and
  cannot have custody settings changed by the inviting organization.

## Login and organizations

- IAM supports identity-only authentication for onboarding/custodian actions;
  application SLTs bind one selected account and one organization membership.
- Browsers may retain multiple authenticated Carbon and Silicon accounts.
  Credentials remain in protected gateway sessions. Expansion preferences may
  persist client-side without storing tokens. Account refresh/logout is isolated.
- Show ordinary login consent only for critical IAM endpoints; disclose no OBO
  endpoints there. App callers handle separate logins for additional orgs.
- Silicons may be organization owners/admins. Every database constraint,
  capability check, governance path and step-up mechanism must support this.
- Creating a Silicon and inviting an existing Silicon are different operations.
  Invite discovery is restricted to Silicons in the inviter's organizations.
  The invited Silicon accepts or declines using its own authenticated session;
  acceptance adds an ordinary membership and does not change custody.
- Directory visibility is directional per membership, with organization defaults
  and explicit per-member overrides for both principal types. Enforcement must
  cover lists, search, details, application projections and relevant notifications.
  A visible identity does not acquire resource permissions from visibility.

## OBO

- Globally unique display/discovery identity: `[app_id:obo:local_id]`. Preserve
  internal IDs and unambiguous local endpoint keys during migration.
- Definitions carry name, path, criticality, description, metadata, note, warnings
  and explicit downstream OBO dependencies. Dependencies describe delegated
  actions, not ordinary package dependencies. Reject cycles and excessive graphs.
- Apps request authorization after login at the point a feature needs it.
  Consent displays the requesting app, all providers/endpoints, notes and warnings,
  plus a grant-management link. Each provider can use an authenticated account
  and an active membership selected by the user; default to the initial context.
- Cross-account selection requires proof of each configured session, not a
  client-supplied account ID. Store selected principal/membership authority,
  never the supplied session token in the grant.
- Approval returns a one-use code exchanged for dedicated access/refresh tokens.
  One access token represents the approved chain. Each recipient authenticates
  itself and verifies only its own permitted endpoint and selected context.
- Consent survives ordinary logout/session expiry until revoked; credential
  expiry, principal/membership suspension/removal, app disablement and endpoint
  removal still deny execution. Refresh cannot expand the approved graph.
  Added dependencies or changes to selected authority require fresh approval.
- Never convert legacy login consent into OBO approval automatically.

## ATA

- ATA is separate application authority throughout a chain. It cannot become OBO.
  Global endpoint identity is `[app_id:ata:local_id]`. An explicit import copies
  an OBO definition as a new ATA definition and must not copy user authority.
- Honeycomb manages verification records, displays their immutable signing
  Carbon/Silicon, recipients, endpoint graph, expiry and access-token validity.
- Verification lifetime is one hour through never, default never. Access-token
  validity is 1 minute through 24 hours, default 30 minutes, capped by the
  remaining verification lifetime. Refresh tokens are secrets, revealed only in
  protected creation/replay windows and omitted from reads/config archives.
- Dependency review adds both required recipient applications and endpoints,
  presents the expansion before creation, and verifies the reviewed graph has
  not changed when the record is committed.
- Receiver verification authenticates the receiving app and checks requesting
  app, proof class, configured endpoint, graph, expiry, revocation and environment.
  Invalid proof, unauthorized recipient and unauthorized endpoint share the
  same negative response. No user/organization authority is inferred.
- The configured app list names recipients. Only the originating application
  can exchange or rotate the refresh credential; a recipient cannot expand its
  verification authority into token issuance.

## Presentation and verification

Use the free Arc UI source/patterns at <https://uiarc.dev/> as the reference,
adapted to the existing SolidJS implementation. Keep consistent blue accents,
clear hierarchy, quiet borders, concise copy, visible focus, reduced motion and
responsive layouts. Social options share an equal-width block. Inputs/actions
have deliberate pending/success/retry/expired states; avoid silent failures.

Email includes both HTML and text alternatives. OTP subjects include the actual
code. Invitation buttons and fallback URLs use the exact configured link, escape
untrusted content, and do not use click tracking to rewrite authentication links.

Required verification covers real database invariants and authorization denial,
CLI/API parity, session isolation, repeatable graph verification, refresh replay,
revocation, dependency changes, production/testing isolation, and browser flows
at desktop/mobile sizes. Provider sandbox/mocked tests do not prove live Google,
Apple, email or SMS delivery.

## Operational activation

Google and Apple sign-up require their configured client credentials and exact
provider callback URLs. The local signature, issuer, audience, nonce and database
tests do not establish that these external provider registrations are active.
Live mail/SMS delivery also requires valid provider configuration and a separately
authorized delivery check. No production deployment is recorded here.

## Migration gates

Preserve existing internal authorization references, canonical public IDs, encrypted
contacts, valid credentials and audit. Backfill custody/membership mappings with
collision reports. Never pick the first organization of an existing multi-org
grant silently. Require a new selected-context application login at the cutover
or explicitly maintain a bounded, documented compatibility path.

The existing `OBO_CUTOVER.md` consumer inventory remains relevant. Its instructions
for audience-specific child tokens and session-bound grant lifetime are superseded
by this brief and must be updated with the final tested contract. Coordinate
Briefcase, Waveform, Ting, DM, Honeycomb and other affected caller/receiver releases
before replacing production behavior.

## Local verification evidence

- Rust workspace, all targets and features: 568 tests passed; 68 tests requiring
  external services or database fixtures are ignored in that ordinary run.
- The dedicated PostgreSQL suite exercised 63 tests. The eight initial failures
  were resolved through test-environment correction, updates to obsolete
  multi-/zero-organization login expectations, and targeted fixture repairs;
  every failed test subsequently passed. These checks use restricted runtime
  roles and disposable production/testing schemas.
- Identity regression covers Carbon email-only signup and replay, Silicon
  custodian approval and denials, profile upload, organization onboarding,
  ownership, Carbon and organization custody settings, step-up, sessions,
  legacy STK membership independence, and logout/replay in both data planes.
- Browser checks exercised Carbon onboarding and Silicon signup, custodian
  approval, automatic login, first-organization creation and profile changes.
- OBO/ATA tests cover repeated receiver verification, exact endpoints and
  recipients, selected provider contexts, revocation, graph changes, concurrent
  refresh/replay, credential secrecy and environment isolation.
- These are local checks. They do not establish live OAuth provider activation,
  live notification delivery, coordinated consumer rollout or deployment.
