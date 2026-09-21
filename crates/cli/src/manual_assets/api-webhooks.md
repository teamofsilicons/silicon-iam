# Signed webhook delivery and verification

Silicon IAM delivers scope-filtered changes to authorized applications and separately routes organization events to subscribed Silicons. Events are written in the same transaction as the change and delivered at least once.

## The delivery guarantee, precisely

Within its `webhook_scope` event subscription and effective consented `app_scope`, a change is delivered to an application for which the user was authorized **immediately before or immediately after** it. The "before" half is what makes removal and revocation events arrive at all — an application that only heard about people it currently sees would never learn that somebody left.

Application events carry changed fields and the affected resource state captured at that version, limited to the recipient’s approved and consented scopes. Production event data excludes tokens, OTPs, credentials, signing secrets, and other secret material. Test envelopes additionally carry the environment root key as described below.

**Deduplicate on `event_id`; order by the resource version.** Delivery is at least once, so a duplicate is normal rather than exceptional. Arrival order is not guaranteed, and the aggregate version is the only reliable sequencing signal.

Webhooks are a notification channel, never an authorization one. When an application needs a current answer it calls introspection (`iam docs api/applications`).

## Application event and field boundaries

`webhook_scope` chooses event categories within an application's existing authority. Even `full` does not grant access to the complete IAM event catalog. Every application delivery needs effective `app_scope`, user consent, and an authorized selected organization. Event recipients and their per-application payloads are captured in the domain transaction; workers do not reconstruct historical data from later records.

| Information | Required permission and permitted content |
| --- | --- |
| Own profile | `self.profile.read` exposes display name, photo, and timezone. It does not expose contact details, account status, or creation/update timestamps. Identity, contacts, and membership fields have separate permissions. |
| Organization profile | `self.organizations.read` exposes identifiers, name, logo, description, and the resource version. It does not disclose SSO, security, or administrative configuration. |
| Other members | Matching `directory.*.read` permissions separately authorize listings, profile fields, membership, capabilities, tags, job descriptions, and Silicon relationships. Directory access never includes credential or webhook management configuration. |
| Own effective trust | `self.trust.read` exposes `membership.effective_trust` from that user's perspective: target Silicon membership ID and effective trust. It does not expose defaults, rules, overrides, or rule identifiers. |
| Organization trust configuration | `organization.trust.read` is required for raw trust configuration and its aggregate events, including `membership.trust` where disclosed. |
| Invitations | `organization.invitations.read` authorizes immutable invitation lifecycle snapshots captured at the mutation. |
| Governance | `organization.governance.read` authorizes captured role/tag requests and approval decisions. It does not grant access to SSO or Silicon credential/webhook administration. |
| Organization tag definitions | `organization.tags.read` authorizes captured tag creation, update, and archive aggregates. A tag need not already be assigned to a member to have a definition event. |

Member snapshots use `current.members`; organization updates use `current.organization`. Invitation, governance, and tag-creation snapshots use `current.resource`; tag/trust changes may include both their independently versioned resource and affected members. A recipient authorized only before a removal receives a stable identity/version tombstone rather than the removed private fields. Missing fields are undisclosed and must never be filled from a broader cached credential.

Each captured application projection has a 1 MiB plaintext limit. A mutation whose complete authorized projection exceeds that limit fails atomically. Directory and effective-trust snapshots can grow with organization size, so deployments must account for this limit when sizing large organization changes.

Applications do not receive raw SSO events, Silicon webhook destination/subscription configuration, or credential-management requests. A completed Silicon credential rotation may produce only its permitted authorization-epoch/access projection, never the credential or management configuration. The larger event vocabulary below remains available to Silicon subscriptions according to their own routing and subscription rules.

## Verifying a delivery

Every request carries four headers:

| Header | Contents |
| --- | --- |
| `X-Silicon-IAM-Event-ID` | The deduplication key |
| `X-Silicon-IAM-Timestamp` | Unix seconds at signing |
| `X-Silicon-IAM-Key-Version` | Which signing-secret version was used |
| `X-Silicon-IAM-Signature` | Exactly `v1=<64 lowercase hexadecimal characters>` |

To verify:

1. Reject the request if the timestamp is outside your tolerance — five minutes is a reasonable default. This is what stops a replay.

2. Recompute HMAC-SHA256 over `{timestamp}.{exact raw request body bytes}`, using the signing secret for the named key version. Lowercase-hex encode the 32-byte result and prefix it with `v1=`.

3. Compare the complete header value in **constant time**. A byte-by-byte comparison that returns early leaks the signature one character at a time.

**Sign over the raw bytes, before any parsing.** Re-serialising the JSON changes whitespace and key order and the signature will never match. Capture the body as bytes in your framework's earliest hook.

`X-Silicon-IAM-Key-Version` exists so rotation is not an outage: keep the previous secret accepted for a window and select by version rather than trying each in turn.

Organization administrators rotate an Application signing key independently with `POST /api/v1/applications/{app_id}/webhook-secret-rotations`, supplying the successor as `webhook_secret`. Normal key rotation uses that supplied secret. New deliveries switch immediately; already persisted in-flight deliveries retain their original bytes and key version, so consumers keep old versions until that retry window closes.

## Testing-environment deliveries

A test environment delivers a visibly different signed JSON shape. Instead of production's top-level event metadata and data, it sends one top-level `test` object containing `testing_key`, `metadata`, and `data`. Signature verification still covers the exact complete body. After verification, deduplicate on `test.metadata.event_id` and order on `test.metadata.aggregate.version`.

**The test key in that envelope remains root authority.** Compare it to the expected environment key without timing leakage, use it only to route the event to its isolated run, then redact it. Never write it to request logs, traces, analytics, dead-letter payload views, or your event table.

Imported Applications initially inherit their production signing key without exposing it. The webhook URL replacement in a test environment creates and returns a fresh test-only `webhook_signing_secret` when no `webhook_secret` was supplied. An explicit supplied replacement is also accepted. The endpoint activates immediately, and the secret response can be replayed for ten minutes. Every test destination replacement installs a supplied or newly generated test-only key. Production URL changes reuse the current key. The complete flow is in Testing environments (`iam docs api/testing-environments`).

Respond `2xx` quickly and do the work asynchronously. A slow endpoint becomes a retrying endpoint, and a retrying endpoint becomes a dead-lettered one.

## Retries and dead letters

Failed deliveries retry on a bounded schedule. A delivery that exhausts its cycle is dead-lettered and stays readable:

| Recipient | List | Replay |
| --- | --- | --- |
| Application | `GET /api/v1/applications/{app_id}/webhook/dead-letters` | `POST …/webhook/dead-letters/replays` |
| Silicon | `GET …/silicons/{silicon_id}/webhook/dead-letters` | `POST …/webhook/dead-letters/replays` |

Attempt history is retained for 45 days.

## What a replay does, and does not, change

A replay preserves:

- the original `event_id` — so your existing deduplication still works;

- the original payload, occurrence time and aggregate version;

- all previous attempt history.

It resets `cycle_attempt_count` and increments `manual_replay_count`.

Delivery goes to the **currently configured** URL, signed with the **current** signing secret — not the ones in force when the event first fired.

**Authorization is re-checked before each replay.** Current authorization and, for a Silicon, current subscription. Historical data is never replayed to a recipient that no longer has permission, which is exactly the property that makes a manual replay safe to expose at all.

Batches are capped at 100, replayed in their original order, require an `Idempotency-Key`, and record who requested them.

## Event catalogue by recipient

This is the broader IAM event vocabulary used by Silicon subscriptions. Application consumers receive only the approved projections described above; entries marked Silicon-only are not application events. In every case, subscription and routing rules still apply.

### Carbon profile changes

Applications receive `carbon.updated.v1` with independently filtered profile, identity, and contact fields. `organization.membership.profile_updated.v1` is the organization-bound Silicon notification; applications do not receive that second form.

### Membership lifecycle

| Event | Meaning |
| --- | --- |
| `organization.membership.created.v1` | A new Carbon membership |
| `organization.membership.reactivated.v1` | An inactive membership restored |
| `organization.membership.removed.v1` | A membership removed or deactivated |
| `organization.silicon.created.v1` | A new Silicon |
| `organization.silicon.removed.v1` | A Silicon removed |

### Member and authorization updates

| Event | Meaning |
| --- | --- |
| `organization.membership.updated.v1` | Directory, tag, role or trust-related state changed |
| `organization.membership.profile_updated.v1` | A Carbon profile change projected here |
| `organization.membership.authorization_updated.v1` | Delegated capabilities changed |
| `organization.ownership_transferred.v1` | Ownership moved |
| `organization.admin.promoted.v1` | A member became an administrator |
| `organization.admin.demoted.v1` | An administrator became a member |
| `organization.silicon.updated.v1` | Silicon attributes changed |
| `organization.tag_updated.v1` | A tag definition changed |

### Trust configuration

Application aggregate disclosure requires `organization.trust.read`. `self.trust.read` permits only the user’s effective perspective, not these raw configuration records.

| Event | Meaning |
| --- | --- |
| `organization.trust.default_updated.v1` | Default trust changed |
| `organization.trust.rule_created.v1` | A rule was created |
| `organization.trust.rule_updated.v1` | A rule was modified |
| `organization.trust.rule_archived.v1` | A rule was disabled or archived |

### Organization, invitations and governance

Application delivery uses the specific organization-profile, invitation, tag, or governance permission listed above and a captured resource snapshot. One category does not imply authority over another.

| Event | Meaning |
| --- | --- |
| `organization.created.v1` · `organization.updated.v1` · `organization.tag_created.v1` | Organization-level changes |
| `organization.invitation.created.v1` · `…accepted.v1` · `…revoked.v1` | Invitation lifecycle |
| `organization.role_change.requested.v1` · `organization.tag_change.requested.v1` · `organization.approval.decided.v1` | Governance |

### Silicon credentials and webhooks

Management request, configuration, and subscription events in this group are Silicon-only. The completed `credential_rotated` event has a separate scope-filtered application authorization projection with no credential or configuration data.

| Event | Meaning |
| --- | --- |
| `organization.silicon.rotation_requested.v1` · `organization.silicon.credential_rotated.v1` | Credential rotation |
| `organization.silicon.webhook.configured.v1` · `…webhook.deleted.v1` | Endpoint configuration |
| `organization.silicon.webhook_subscription.updated.v1` · `…deleted.v1` | Subscription changes |

### SSO — Silicon subscriptions only

Application scopes do not expose this SSO event payload or its provider and security configuration.

| Event | Meaning |
| --- | --- |
| `sso.setup_link.created.v1` | A provider setup link was generated |
| `sso.configuration.disabled.v1` | SSO was disabled |
| `sso.entitlement.replaced.v1` | The entitlement changed |
| `sso.connection.activated.v1` · `…deactivated.v1` · `…deleted.v1` | Connection lifecycle |
