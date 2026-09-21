# Sensitive actions

The organization owner configures these rules under **Organization settings → Sensitive actions**. An admin can configure them when the owner delegates `action_policies.manage`.

Each action has an allowed requester tier (`any_member`, `only_admins`, or `only_owner`) and an approval requirement (`none`, `admin`, or `owner`). The owner can always perform every action. An eligible approver who is allowed to perform an action performs it directly; they never need to approve their own request in another tab. Other permitted requesters can receive manual approval or match an automatic approval rule.

Automatic approval accepts Carbon IDs, full Silicon IDs, and organization tag IDs. Any matching **requester** ID or requester membership tag satisfies approval. It does not override the allowed requester tier, application consent, application scopes, or tenant isolation. All automatic approval lists start empty.

| Action | Default requester | Default approval |
| --- | --- | --- |
| `membership.job_description.update` | Any member | None |
| `membership.tags.update` | Any member | Admin |
| `membership.directory.update` | Only admins | None |
| `silicon.self_profile.update` | Any member, own Silicon profile | None |
| `silicon.profile.update` | Only admins | None |
| `silicon.hierarchy.update` | Only admins | Admin |
| `organization.profile.update` | Only admins | None |
| `tag.create` | Only admins | None |
| `tag.update` | Only admins | None |
| `tag.delete` | Only admins | None |
| `trust.default.update` | Only admins | None |
| `trust.rule.create` | Only admins | None |
| `trust.rule.update` | Only admins | None |
| `trust.rule.delete` | Only admins | None |

Job Description changes apply directly by default, without an approval request.

`membership.directory.update` controls a Carbon member's preferred first Silicon (`first_silicon_membership_id`) and extra Silicon access grants (`extra_silicon_membership_ids`). Job Description, tags, trust, and reporting hierarchy use their own action rules.

An admin permitted by an “Only admins / Admin approval” rule acts immediately, since that admin can approve the action. Select Owner approval to require owner review of admin requests; matching automatic approval exceptions can still apply. Only the owner bypasses an “Only owner” requester tier.

## Manual approval and retries

Submit the direct mutation. IAM returns HTTP 428 `approval_required` with `details.approval_request_id` and `details.idempotency_key` when approval is needed. An eligible reviewer inspects the exact change in the Approvals page. After approval, the requester retries the original mutation with the same body, method, path, If-Match version and request key. The console retains the pending form and stores a hashed request signature plus its retry key in tab-local session storage for up to twelve hours. Repeating the exact inputs in the same tab also works after navigating away or refreshing; raw request contents are never stored. The CLI accepts `--request-key` for the retry.

A change touching several sensitive actions creates one request per action that needs approval. All must be approved before the exact change can execute; the Approvals page lists each request.

Approvals expire after twelve hours. They bind the requester session and application permissions. Rule edits invalidate approvals from the old policy version, and the approver must still hold authority when the change is applied. Approval consumption and the mutation commit together. Editing a proposed change requires a new approval. A resource changed in the meantime still fails its normal version check.

Legacy job-role/tag request creation and decision routes return HTTP 410; use direct mutations and the generic action approvals. Historical decisions remain readable. Existing unfinished legacy job-role/tag requests are cancelled during migration because they do not bind the new policy.

## API and CLI

- `GET /api/v1/organizations/{org_id}/action-policies`
- `PUT /api/v1/organizations/{org_id}/action-policies/{action}` with If-Match (zero for an unmodified default)
- `GET /api/v1/organizations/{org_id}/action-approvals`
- `POST /api/v1/organizations/{org_id}/action-approvals/{request_id}/decisions` with If-Match

```sh
iam --org bricks approval policies
iam --org bricks approval configure-policy membership.tags.update --expected-version 0 --file rule.json
iam --org bricks approval actions
iam --org bricks approval decide-action <request-uuid> --expected-version 1 --decision approve
```

Example `rule.json`:

```json
{
  "allowed_actors": "any_member",
  "approval": "admin",
  "auto_approve": {
    "carbon_ids": ["saket"],
    "silicon_ids": ["chef:bricks"],
    "tag_ids": []
  }
}
```

Only active organization identities and tags can be selected. Initial assignments on Silicon creation and Carbon invitations follow the same rules; the existing create/invite permission is also required.
