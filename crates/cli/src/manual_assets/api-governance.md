# Tags, trust and approvals

Three mechanisms decide who can reach what inside an organization: tags, which grant access; trust, which describes it; and governance, which controls who may change either.

## Tags are access grants

**Assigning a tag to a Carbon grants them every Silicon carrying the same tag.** A tag is not a label. Renaming one is harmless; reassigning one changes who can reach what.

Tags also scope trust rules and Silicon webhook subscriptions, which makes them the single highest-leverage object in the model. `GET …/tags/{tag_id}/members` returns both sides of the grant — every Carbon and every Silicon carrying it — and is the right screen to read before changing anything.

A member's tag set is replaced wholesale by `PUT …/members/{membership_id}/tags`. There is no partial add or remove on that endpoint; send the complete intended set.

## Trust has two dimensions

| Dimension | Values | Means |
| --- | --- | --- |
| `boundary` | `internal`, `external` | Whether the principal is inside the organization's circle. A contractor or freelancer is typically `external`. |
| `level` | `not_trusted`, `needs_approval`, `trusted` | How far that relationship extends. |

The default is `internal` and `not_trusted`. Resolution is strictly:

```
organization default  →  tag rule  →  exact Silicon rule
```

Later entries win. `POST …/trust/effective` resolves a specific subject and target pair and reports which rule matched, which is the only reliable way to answer "why does this read as it does".

**Trust is advisory.** Silicon IAM records it faithfully and enforces nothing. Applications read it and decide. Treating a stored trust value as an access-control decision is a misreading of the model.

### Trust is directional

Tag-to-tag rules form a matrix, and the matrix is not symmetric. "Tech trusts legal" says nothing whatsoever about "legal trusts tech" — they are two independent rules, and an interface that renders them as one is lying about the model.

## Sensitive-action policies

The owner, or an admin delegated `action_policies.manage`, configures an action's requester tier (any member, only admins, or only owner) and required approval (none, admin, or owner). The owner always acts directly. A permitted requester who can approve the action also acts directly.

Automatic approval can match a requester's permanent Carbon ID, full Silicon ID, or membership tag. It satisfies approval without granting action permission. When approval is required, empty selector lists require manual approval.

Submit the direct job-description, tag, profile, hierarchy, or trust mutation. Job Description changes apply directly by default, without approval. When a rule requires review, HTTP 428 `approval_required` returns the pending request and its request key. Review exact changes at `GET …/action-approvals` and decide at `POST …/action-approvals/{request_id}/decisions`. After approval, retry the identical mutation and request key.

Approvals expire after twelve hours. Changed rules, resource versions, sessions, or request contents require fresh validation. The approval and action commit atomically. The old role-change and tag-change request routes return HTTP 410; token rotation continues to use its dedicated ownership and credential-verification flow.

`GET …/action-policies` lists every action with its current rule and defaults. Use `PUT …/action-policies/{action}` and If-Match to configure it.

## History

`GET …/members/{membership_id}/job-role-history` and `…/tag-history` record the applied change and actor. Sensitive-action approvals retain the exact reviewed request and consumption status in the action-approvals list.

Audit records are retained for seven years.
