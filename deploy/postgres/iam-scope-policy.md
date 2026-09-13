# Internal IAM permission policy

`organizations.allowed_restricted_iam_scopes` is an internal database setting.
It defaults to the restricted permission set in migration 0087. A restricted
permission is available only when the application's **owning organization** is
active, has `trusted_org = true`, and retains that permission in the array.
The user's selected customer organization cannot authorize the application owner.
Ordinary organization APIs cannot modify either setting.

Operators may remove individual entries with `array_remove`; an empty array denies
all restricted permissions. Nonrestricted critical permissions still require their
ordinary review and user consent. Trust does not auto-approve critical scopes.

Policy changes revoke affected application scope approvals and active tokens.
System revocations are recorded as `revoked_by_policy = true`, without attributing
them to an unrelated Carbon. Restoring availability does not restore old tokens or
approvals; the application must request approval again and obtain current consent.
Application scope versions change with the policy, making stale consent fail.

The restriction applies at declaration, request and approval boundaries and again
when authenticating an application token. The full shared permission catalog stays
stable; public responses disclose only that a permission is unavailable, not these
internal organization settings.

Deploy migration 0087 plus the current runtime grants to both production and the
isolated testing plane. Run the catalog policy regression in both planes before
publishing changes. No runtime API receives permission to invoke policy triggers.
