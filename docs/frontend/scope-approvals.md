# Application scope approvals

Open Applications → select the target application → Approvals. Incoming requests
are matched by `target_app_id`; sent requests are matched by the caller's
`app_id`. The app view includes every status by default so completed reviews
remain visible. The shared Scope reviews page retains its Pending default and
adds a Needs your review filter. Organization governance approvals remain in the
separate Approvals section.

A review's critical scope list is its immutable decision boundary. Requests are
split by the provider that owns the scopes. Non-critical scopes need no review;
previously approved critical scopes need no repeat approval. The thread also
shows the caller's current declared scopes for this provider, clearly labeled
as current context rather than the original submission. It never exposes scopes
owned by unrelated providers to the target app's reviewer.

Messages identify the current Carbon's messages as You · Sent, other participants
as Received with their public Carbon ID, and system-authored text as Review
instructions. Existing request ownership and decision authorization are unchanged.

Filtered inbox reads advance across nonmatching API pages; an empty first shared
page cannot hide an older incoming request. The backend continues authorizing
all reads and decisions. A decision still requires a pending request, its current
version, and target organization owner/admin (or IAM platform review authority
for IAM scopes).

Validation: frontend tests cover sender/target matching, cross-page discovery,
and cursor failures; the PostgreSQL lifecycle test checks current non-critical
scope context, exclusion of other providers, message authorship, and unchanged
critical approval enforcement.
