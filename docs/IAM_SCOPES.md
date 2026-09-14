# Scoped IAM API

Applications declare permissions in `app_scope.iam`; discover their exact names,
descriptions and critical labels with `GET /api/v1/application-scopes`. Every new
mutation permission is critical and requires review. Some permissions may be
unavailable to an application; user consent cannot make an unavailable permission
available.

Call the API with the application's ordinary, self-audience access token. IAM
checks its current approved and consented scopes, the user's selected organizations,
and the represented Carbon or Silicon's current authority. An external OBO token
cannot perform these mutations. A scope never promotes a member or replaces an
organization capability. The IAM console's direct sessions retain their existing
behavior.

| Permission | API operation |
| --- | --- |
| `organizations.create` | Check an organization handle and create an organization; the represented Carbon owns it |
| `organizations.join` | Send an invitation verification code, accept the verified invitation, or start SSO admission |
| `organization.profile.update` | Update organization name, logo and description |
| `organization.invitations.create` / `.revoke` | Issue or revoke Carbon invitations |
| `organization.testing_environments.create` | Non-critical: create an isolated test world for the selected organization and receive its root for test bootstrap/import/data management; active Carbon members only |
| `organization.silicons.create` / `.update` / `.remove` | Create Silicons, edit their profile/reporting relationships, or remove them |
| `organization.carbons.remove` | Remove a Carbon membership |
| `organization.tags.create` / `.update` / `.delete` | Manage tag definitions |
| `organization.member_tags.update` | Replace member tag assignments through the existing governance endpoint |
| `organization.job_roles.update` | Replace a member's descriptive job role |
| `organization.silicon_access.update` | Change a Carbon's first or extra Silicon assignments |
| `organization.trust.update` | Change trust defaults, rules or a Carbon's configured trust |
| `organization.admins.promote` / `.demote` | Change a Carbon member's admin status |
| `organization.capabilities.update` | Replace an admin's capability set |
| `organization.change_requests.read` | Read role/tag change requests and decisions |
| `organization.job_role_changes.request` / `organization.tag_changes.request` | Submit requests subject to the existing actor and governance rules |
| `organization.change_requests.decide` | Decide requests for which the represented user is an eligible approver |
| `organization.job_role_history.read` / `organization.tag_history.read` | Read the respective histories |
| `organization.sso.read` / `.manage` | View SSO configuration or manage setup, testing, disabling and organization join method |
| `organization.silicons.credentials.rotate` | Request/complete credential rotation and access the rotation workflow |

`organization.governance.read` remains the compatible umbrella read permission.
The granular change-request permission does not independently expose Silicon
credential-rotation requests; reading those also requires the credential permission
(or the existing umbrella). Deciding a rotation requires both the decision and
credential permissions.

A PATCH with several types of changes requires every corresponding permission.
Changing an organization's join method requires `organization.sso.manage`; editing
profile fields in the same request also requires `organization.profile.update`.
The existing organization capability checks still apply.

Creating or joining an organization is Carbon-only and does not require existing
membership. Eligible Carbons can explicitly approve `org_ids: []` during login;
see [organization consent](ORGANIZATION_CONSENT.md). Creating or joining does not
automatically grant the application access to that organization. Continue through
IAM organization consent to add it.

Privileged operations still require their existing `X-Step-Up-Token`, `If-Match`,
and idempotency key. Obtain step-up verification in IAM. The assertion must match
the represented Carbon, parent authentication session, action and resource; an
application permission does not replace it. Idempotency responses are isolated by
application, parent session and effective scopes.

Write access does not grant unrelated read access. Mutation results retain usable
resource IDs and versions, while existing member/profile/trust/invitation/governance
data follows the application's read permissions. Request the corresponding read
permissions when the UI needs a complete resource. Creating or rotating a Silicon
credential returns the explicitly requested one-time credential; preserve the
existing limited replay lifetime and secret handling.

The separate scoped backend exposes these APIs for application callers. Login,
application registration, scope review and first-party step-up remain in the main
IAM service. The scoped backend publishes no OBO endpoints and does not expose
platform administration, ownership transfer or webhook administration.
