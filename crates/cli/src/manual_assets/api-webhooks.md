# Signed webhook delivery and verification

Silicon IAM pushes directory changes to every application that was authorized for the affected resource, and to every Silicon subscribed to them. Events are written in the same transaction as the change and delivered at least once.

## The delivery guarantee, precisely

A change is delivered to every application for which the user was authorized **immediately before or immediately after** it. The "before" half is what makes removal and revocation events arrive at all — an application that only heard about people it currently sees would never learn that somebody left.

Each event carries the changed fields and the complete current authorized state of the affected resource, excluding tokens, OTPs, credentials, signing secrets and any other secret material.

**Deduplicate on `event_id`; order by the resource version.** Delivery is at least once, so a duplicate is normal rather than exceptional. Arrival order is not guaranteed, and the aggregate version is the only reliable sequencing signal.

Webhooks are a notification channel, never an authorization one. When an application needs a current answer it calls introspection (`iam docs api/applications`).

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

Organization administrators rotate an Application signing key independently with `POST /api/v1/applications/{app_id}/webhook-secret-rotations`, supplying the successor as `webhook_secret`. IAM never generates it. New deliveries switch immediately; already persisted in-flight deliveries retain their original bytes and key version, so consumers keep old versions until that retry window closes.

## Testing-environment deliveries

A test environment delivers a visibly different signed JSON shape. Instead of production's top-level event metadata and data, it sends one top-level `test` object containing `testing_key`, `metadata`, and `data`. Signature verification still covers the exact complete body. After verification, deduplicate on `test.metadata.event_id` and order on `test.metadata.aggregate.version`.

**The test key in that envelope remains root authority.** Compare it to the expected environment key without timing leakage, use it only to route the event to its isolated run, then redact it. Never write it to request logs, traces, analytics, dead-letter payload views, or your event table.

Imported Applications initially inherit their production signing key without exposing it. The first webhook URL replacement in the test environment requires the caller to supply a test-only `webhook_secret`; IAM switches to and echoes that value but never generates it. Ordinary URL changes reuse the current key. The complete flow is in Testing environments (`iam docs api/testing-environments`).

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

## Event catalogue

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

| Event | Meaning |
| --- | --- |
| `organization.trust.default_updated.v1` | Default trust changed |
| `organization.trust.rule_created.v1` | A rule was created |
| `organization.trust.rule_updated.v1` | A rule was modified |
| `organization.trust.rule_archived.v1` | A rule was disabled or archived |

### Organization, invitations and governance

| Event | Meaning |
| --- | --- |
| `organization.created.v1` · `organization.updated.v1` · `organization.tag_created.v1` | Organization-level changes |
| `organization.invitation.created.v1` · `…accepted.v1` · `…revoked.v1` | Invitation lifecycle |
| `organization.role_change.requested.v1` · `organization.tag_change.requested.v1` · `organization.approval.decided.v1` | Governance |

### Silicon credentials and webhooks

| Event | Meaning |
| --- | --- |
| `organization.silicon.rotation_requested.v1` · `organization.silicon.credential_rotated.v1` | Credential rotation |
| `organization.silicon.webhook.configured.v1` · `…webhook.deleted.v1` | Endpoint configuration |
| `organization.silicon.webhook_subscription.updated.v1` · `…deleted.v1` | Subscription changes |

### SSO

| Event | Meaning |
| --- | --- |
| `sso.setup_link.created.v1` | A provider setup link was generated |
| `sso.configuration.disabled.v1` | SSO was disabled |
| `sso.entitlement.replaced.v1` | The entitlement changed |
| `sso.connection.activated.v1` · `…deactivated.v1` · `…deleted.v1` | Connection lifecycle |
