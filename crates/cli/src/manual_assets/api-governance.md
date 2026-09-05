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

## Governance: who may change a role or a tag

| Actor | Job roles and tags |
| --- | --- |
| Owner or administrator | Changes them directly |
| Silicon | May only *request* a change |
| Ordinary member | Neither |

The quorum then depends on *who the change is about*:

| Target | Approvals required |
| --- | --- |
| A Carbon | That Carbon **and** an owner or administrator |
| A Silicon | An owner or administrator only |
| A Silicon token rotation | The organization owner |

Show the quorum per party, not as a single total. "1 of 2" hides which of the two is still missing, and that is precisely the thing a reader needs.

### The request lifecycle

1. A Silicon opens a request via `POST …/role-change-requests` or `POST …/members/{membership_id}/tag-change-requests`.

2. Each required party records a decision at `POST …/approval-requests/{request_id}/decisions`, with `If-Match` on the request version.

3. Once the quorum is met the change applies atomically and the request completes.

`immutable_payload` is fixed when the request opens, so nobody can approve one change and have another take effect. A token-rotation decision additionally requires a verified-channel step-up token.

`actionable_by_me=true` narrows the list to requests the caller can act on now, which is the only filter most people want.

## History

`GET …/members/{membership_id}/job-role-history` and `…/tag-history` record who requested each change, who approved it, when it applied, and the linked approval request. A direct owner or administrator change has no `approval_request_id` and no approvers, which is how you tell the two apart.

Audit records are retained for seven years.
