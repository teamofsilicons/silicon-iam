# Silicon identities and credentials

A Silicon is a machine identity that exists only inside one organization. It authenticates with a credential pair, carries tags and a job role like any member, and can subscribe to directory changes over its own webhook.

## Identity

`POST /api/v1/organizations/{org_id}/silicons` takes a handle and returns the Silicon plus its token. The handle is creation input only; the public ID is always `{handle}:{org_id}`.

**The response carries the only copy of the token.** Silicon IAM stores a keyed digest. The value is replayable for ten minutes with the same idempotency key and is then unrecoverable — a lost token can only be rotated, never read.

`reports_to_membership_id` sets the reporting line, which determines `hierarchy_level` and hence the default profile image. A cycle is refused with `422 hierarchy_cycle`.

## Credential rotation is two steps, on purpose

1. `POST …/silicons/{silicon_id}/token-rotation-requests` opens an approval request. Requires `silicons.rotate_token` and a step-up token.

2. An organization owner approves it via the governance endpoints. **Approval does not mint a replacement.** It invalidates the current credential.

3. `POST …/token-rotation-requests/{request_id}/complete` generates and reveals the new token, once.

The split is the point: it guarantees a human is present when the replacement appears, rather than a token being generated into an empty room and lost. The Silicon cannot authenticate between step two and step three, so schedule accordingly.

## Webhooks

`PUT …/silicons/{silicon_id}/webhook` configures the delivery endpoint. It must be `https`, and the response returns a fresh `swhs_…` signing secret — replayable for ten minutes, then gone. `If-Match` is required only when replacing an existing endpoint.

A configured endpoint is a **precondition for subscribing**. There is nowhere to deliver to otherwise.

### Subscriptions

`PUT …/silicons/{silicon_id}/webhook/subscription` takes a mode and, when the mode is `selected`, a set of topics.

| Value | Covers |
| --- | --- |
| `mode: "all"` | Every category, including ones added later |
| `membership_lifecycle` | People and Silicons joining, being reactivated, or being removed |
| `member_updates` | Role, tag, profile and hierarchy changes. **Excludes trust.** |
| `trust_updates` | Default trust, trust rules, and rule archival |

The three topics combine freely. Trust deliberately sits outside `member_updates`: a Silicon that wants org-chart changes rarely wants every trust adjustment, and conflating them makes both noisier.

### The tag filter

`tag_filter` narrows whichever topics are selected; it is **not** a category of its own. Set it to `null` to disable filtering, or to an object with `additional_tag_ids` to widen beyond the Silicon's own tags.

Matching uses the state **before and after** each change, so joining, leaving, updating and removal all arrive. Without that, a Silicon filtering on `tech` would never learn that somebody left `tech` — the very event it most needs.

With a filter active, organization-wide and unattributed events are suppressed. That is the intended trade: a filtered subscription is a per-tag feed, not a filtered firehose.

## Dead letters

Deliveries that exhaust their retry cycle land in a dead-letter queue, readable at `GET …/silicons/{silicon_id}/webhook/dead-letters` and replayable at `POST …/webhook/dead-letters/replays` with up to 100 delivery IDs.

Replay is covered in full under Webhooks (`iam docs api/webhooks`). The property worth knowing here: authorization and subscription are re-checked before *each* replay, so a Silicon whose tags changed never receives history it would not be entitled to today.

## Removal

`DELETE /api/v1/organizations/{org_id}/silicons/{silicon_id}` revokes access everywhere immediately and deletes the credential. `reassign_reports_to` re-parents anything beneath it. The global ID is never reused.
