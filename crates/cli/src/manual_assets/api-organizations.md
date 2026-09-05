# Organizations, membership and SSO

An organization is the boundary for people, machine identities, tags, trust and applications. It has exactly one owner, any number of administrators, and everyone else is a member.

## Roles

| Role | Authority |
| --- | --- |
| **Owner** | Exactly one. Holds every capability implicitly. Only the owner can transfer ownership, and doing so demotes them to administrator. |
| **Administrator** | Holds explicitly delegated capabilities, granted by the owner or by an administrator with `admins.manage`. |
| **Member** | No organization-level authority. Invitations always join as members. |

A Silicon can never be an owner or an administrator. Its authority is a separate question, covered in Tags, trust and governance (`iam docs api/governance`).

## Capabilities

Administrator authority is a set, replaced wholesale via `PUT /api/v1/organizations/{org_id}/members/{membership_id}/capabilities`. Anything not in the submitted list is removed.

| Capability | Permits |
| --- | --- |
| `organization.update` | Name, logo, description, join method |
| `members.invite` | Issuing and revoking invitations |
| `members.update_directory` | Job role, tags, trust, reporting line |
| `members.remove` | Removing a member |
| `silicons.create` · `silicons.update_directory` · `silicons.manage_hierarchy` · `silicons.remove` · `silicons.rotate_token` | The Silicon lifecycle |
| `tags.manage` | Creating and editing tags |
| `trust.manage` | Default trust and trust rules |
| `roles.request` · `roles.approve` | Governance |
| `admins.create` · `admins.manage` | Promotion and delegation |
| `sso.manage` | SSO configuration, once entitled |

Promotion, demotion and capability replacement all require a verified-channel step-up token and an `If-Match` on the authorization aggregate, whose version is separate from the membership's.

## Creating an organization

`GET /api/v1/organization-ids/{org_id}/availability` then `POST /api/v1/organizations`. The creator becomes the sole member and owner.

**`org_id` is permanent.** It cannot be changed and is never reused after deletion. It also becomes the suffix of every Silicon ID in the organization — a Silicon created as `head_of_growth` in `tos` is `head_of_growth:tos` forever.

## Listing your organizations

`GET /api/v1/organizations` is Carbon-only and defaults to `status=active`. Its `status=active|removed` query filters the authenticated Carbon's *membership* in each organization, not the organization's own lifecycle state. The `status` property in every returned Organization still describes the organization itself and remains `active` or `disabled`; a result reached through a removed membership may therefore describe an active organization.

## The directory

Three read-optimised endpoints answer "who is here, and what is my relationship to them" in one call each:

|  | Endpoint | Returns |
| --- | --- | --- |
| GET | `/api/v1/organizations/{org_id}/directory/self` | The caller's own entry |
| GET | `/api/v1/organizations/{org_id}/directory/members` | Every teammate, paginated |
| GET | `/api/v1/organizations/{org_id}/directory/members/{membership_id}` | One teammate |

Each returns name, ID, job role, tags and trust. **Trust is always resolved from the caller's point of view** — the same pair reads differently depending on who is asking — so label the column accordingly rather than presenting it as an absolute property.

All three accept `fields` to narrow the projection. On a large directory this is the difference between a 12 KB and a 400 KB page, and it is worth using.

The directory deliberately exposes public handles rather than `membership_id`. To act on somebody you need the membership endpoints, which are authority-checked.

## Invitations

`POST /api/v1/organizations/{org_id}/carbon-invites` identifies the invitee by **either** `carbon_id` **or** `email`, never both, and carries the job role, tags, default trust and any trust overrides they should start with.

You cannot invite a Carbon who does not yet have an account. Resolve or search first.

The invitation email links to `{auth_url}/join/{org_id}?app={app_id}`. When `app_id` is present, the person is returned to that application after joining. Invitations last 48 hours and can be revoked at any point before acceptance.

### Joining by email

1. `POST /api/v1/organizations/{org_id}/join/email-verification-code` with the invited address. Returns `invite_id` and `expires_in`.

2. `POST /api/v1/organizations/{org_id}/join` with that `invite_id` and the six-digit `verification_code`.

Both calls need an IAM bearer: joining attaches an organization to an existing Carbon account, so the visitor must already be signed in. Say so before they start.

### Joining by SSO

`GET /api/v1/organizations/{org_id}/sso/authorize` is a *navigation*, not a fetch. It authenticates with the browser-session cookie and answers `302` to the identity provider. `return_to` is honoured only for the configured auth origin; anything else is refused outright.

**SSO never creates a Carbon.** It admits an existing one to an organization. A visitor without an account must sign up first.

## SSO configuration

SSO is locked by default. A platform administrator grants the entitlement via `PUT /api/v1/admin/organizations/{org_id}/sso-entitlement`; the organization cannot grant it to itself. Once entitled:

1. `POST /api/v1/organizations/{org_id}/sso/setup-link` mints a WorkOS admin-portal link valid for **five minutes**. Open it immediately; do not store it.

2. WorkOS calls back; IAM sets `sso_status: "active"` with the connection ID.

3. `POST /api/v1/organizations/{org_id}/sso/test` verifies the live connection without admitting anybody.

`join_method` is `email` or `sso`, and the two are mutually exclusive.

## Removing a member

`DELETE /api/v1/organizations/{org_id}/members/{membership_id}` revokes access across every configured application immediately. `reassign_reports_to` re-parents any Silicons that reported to them; without it the removal may fail rather than orphan a hierarchy.

Removal affects this organization only. The Carbon's own account is untouched and they can be invited back later.
