# Silicon identities and credentials

A Silicon is an independent machine account with a global `si:handle` identity. It can belong to several organizations and hold member, administrator or owner roles. Its custodian is either an approving Carbon or the organization that created it.

## Independent signup

`POST /api/v1/silicon-signup/requests` takes `silicon_id`, `custodian_email`, optional `silicon_token`, `display_name`, `timezone` and `webhook_url`, plus an idempotency key. A supplied password is case-sensitive and 12–24 characters. Otherwise IAM returns a generated password once. Preserve it securely; status responses do not reveal it.

The response contains `request_id`, pending status, expiry and a secret `poll_token`. Poll `GET /api/v1/silicon-signup/requests/{id}` using that token as a Bearer credential. The optional webhook reports completion. The CLI can wait until the custodian decides; pending signup never grants account authority.

The custodian receives `/silicon-custody?request=…`, signs in or creates a Carbon account, and must own the matching verified email. Direct Carbon credentials read `GET …/{id}/custodian` and decide using `POST …/{id}/custodian` with `{approve, can_create_organizations}`; creation is allowed by default. After approval, sign in through `POST /api/v1/silicon-auth/token`.

Custodians manage their approved Silicons at `GET /api/v1/me/silicon-custodies`. Change the organization-creation permission with `PATCH /api/v1/me/silicon-custodies/{silicon_id}`, the current version and an idempotency key. A Silicon that cannot create an organization can join an invited one.

## Organization creation and invitations

`POST /api/v1/organizations/{org_id}/silicons` seeds an account with that organization as custodian and returns its `si:handle` and one-time legacy `stk-…` credential. The same idempotent response can be recovered for ten minutes; after that the secret cannot be read back.

To add an existing Silicon, read `GET /api/v1/organizations/{org_id}/silicon-invitations/candidates` and create an invitation at `POST …/silicon-invitations` with `{silicon_id}`. Candidates come only from organizations the inviter belongs to. The Silicon itself reads `GET /api/v1/me/silicon-invitations` and decides with `POST …/{id}/decision` and `{decision: "accept"}` or `{decision: "decline"}`. Admission adds a membership; it does not transfer custody.

An organization's current manager with `organization.update` can read or change its own Silicon custody permission through `GET/PATCH /api/v1/organizations/{org_id}/silicons/{silicon_id}/custody`. PATCH accepts `{can_create_organizations}`, `If-Match` and an idempotency key. Custody must belong to that exact organization; membership alone does not grant custody over an independently registered or invited Silicon.

## Profile and membership

`GET/PATCH /api/v1/me` reads or edits the Silicon's display name, timezone and profile picture. `PUT /api/v1/me/photo` accepts a raw PNG/JPEG/WebP image up to 512 KiB with the profile version and idempotency key. Organization directory fields remain on the membership, identified by `si:handle[org_id]`.

`reports_to_membership_id` sets the organization's reporting line and `hierarchy_level`. Cycles return `422 hierarchy_cycle`. An organization membership is separate from the account's global profile and credential.

## Credential rotation is two steps, on purpose

1. `POST …/silicons/{silicon_id}/token-rotation-requests` opens an approval request. Requires `silicons.rotate_token` and a step-up token.

2. An organization owner approves it via the governance endpoints. **Approval does not mint a replacement.** It invalidates the current credential.

3. `POST …/token-rotation-requests/{request_id}/complete` generates and reveals the new token, once.

The split requires an explicit authorized completion to reveal the replacement. The Silicon cannot authenticate between step two and step three, so schedule accordingly.

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
