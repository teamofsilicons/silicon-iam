# Silicon IAM API documentation

This document explains the behavior and intent of every endpoint in the Silicon IAM OpenAPI contract. The machine-readable contract is in [`openapi.yaml`](./openapi.yaml).

## API conventions

### Base URL

```text
https://backend.iam.teamofsilicons.com/api/v1
```

### Actors

- **Carbon:** A human account in the Silicon platform.
- **Silicon:** An AI-agent account created inside one organization.
- **Application:** A registered service that uses IAM for authentication or OBO Access.
- **Organization:** The security and directory boundary containing Carbons and Silicons.

### Authentication modes

The API uses three authentication modes:

1. **Public:** Signup, login, token-establishment, and identifier-availability endpoints.
2. **Bearer authentication:** Carbon and Silicon requests with an IAM access token.
3. **Application credentials:** Service-to-service authentication used when verifying OBO Access.

Public means that an IAM session is not required. Public endpoints must still enforce rate limits, verification-attempt limits, expiry, and abuse protection.

### Errors

Errors use a common envelope:

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Human-readable explanation",
    "details": {},
    "request_id": "request trace identifier"
  }
}
```

Clients should branch on `error.code`, not on the human-readable message.

## Carbon signup

Signup uses a temporary session. This binds email verification, phone verification, and final account creation to one flow.

### `POST /signup/sessions`

Starts a Carbon signup.

- **Authentication:** None.
- **Input:** None.
- **Returns:** `session_id` and `expires_at`.
- **Intended lifetime:** 48 hours.

The client must retain `session_id` and include it in all subsequent signup requests. Expired sessions cannot be completed.

### `POST /signup/sessions/{session_id}/email`

Sends a six-digit email verification code.

- **Authentication:** None.
- **Input:** `email`.
- **Returns:** The code expiry time.
- **Conflict:** Returns `already_exists: true` when the email belongs to an existing Carbon.

This request sends the code but does not mark the email as verified. Codes are intended to expire after ten minutes.

### `POST /signup/sessions/{session_id}/email/verify`

Verifies the email code.

- **Authentication:** None.
- **Input:** Six-digit `verification_code`.
- **Returns:** `verified: true`.

On success, IAM stores the verified email in the signup session. After ten failed attempts, verification enters the configured cooldown.

### `POST /signup/sessions/{session_id}/phone`

Sends a six-digit phone verification code.

- **Authentication:** None.
- **Input:** An E.164 phone number such as `+919876543210`.
- **Returns:** The code expiry time.
- **Conflict:** Returns `already_exists: true` when the number belongs to an existing Carbon.

The number must contain its country code and begin with `+`.

### `POST /signup/sessions/{session_id}/phone/verify`

Verifies the phone code.

- **Authentication:** None.
- **Input:** Six-digit `verification_code`.
- **Returns:** `verified: true`.

On success, IAM stores the verified phone number in the signup session.

### `POST /signup/sessions/{session_id}/complete`

Creates the Carbon account.

- **Authentication:** None.
- **Required input:** `carbon_id` and `display_name`.
- **Optional input:** `description` and `profile_photo`.
- **Returns:** The newly created Carbon.

IAM must reject completion unless the session contains both a verified email and verified phone number. It must recheck that neither identity was claimed by another signup after verification.

A Carbon ID is case-insensitive, 3–30 characters long, and limited to lowercase letters, numbers, hyphens, and underscores.

## Carbon discovery

### `GET /carbon-ids/{carbon_id}/availability`

Checks whether a Carbon ID can currently be registered.

- **Authentication:** None.
- **Returns:** `available: true` or `available: false`.

This supports live feedback in the signup interface. A positive response does not reserve the identifier; account creation must check availability again.

### `GET /carbons/search?q={query}&limit={limit}`

Searches registered Carbons by Carbon ID.

- **Authentication:** Bearer token.
- **Input:** `q` and an optional limit from 1 to 10.
- **Returns:** Carbon ID, display name, and profile picture for each match.

Search may be fuzzy so a query such as `sak` can suggest `saket`. Results must contain public profile information only. Email addresses and phone numbers must not be exposed.

## Carbon login

### `POST /login/challenges`

Starts passwordless Carbon login.

- **Authentication:** None.
- **Input:** Exactly one of `email`, `phone_number`, or `carbon_id`.
- **Returns:** A login `session_id` and expiry.

Email login sends a code to the registered email. Phone login sends a code to the registered number. Carbon-ID login may send codes to both registered channels, and either valid code can complete the login. This endpoint must not silently create an account for an unknown identity.

### `POST /login/challenges/{session_id}/verify`

Completes a login challenge.

- **Authentication:** None.
- **Input:** Six-digit verification code.
- **Returns:** Bearer `access_token`, token type, expiry, and the authenticated actor.

The code must belong to the challenge, remain unexpired, and stay within the failed-attempt limit. A successful verification consumes the challenge.

## Silicon authentication

### `POST /silicon-auth/token`

Authenticates a Silicon using its global ID and Silicon token.

- **Authentication:** None.
- **Input:** `silicon_id` and `silicon_token`.
- **Returns:** Bearer access token, expiry, and Silicon actor information.

The Silicon ID contains its organization suffix, for example `head_of_growth:tos`. The supplied token follows `stk-{16 hexadecimal characters}`.

IAM must store only a secure derived value of the Silicon token. A raw token is displayed only when a Silicon is created or its token is rotated.

## Application login

These endpoints let registered applications use IAM as their identity provider.

### `GET /oauth/authorize`

Authorizes an application for the currently authenticated actor.

- **Authentication:** Bearer token.
- **Query:** `app_id`, `redirect_uri`, `state`, and optional `org_id`.
- **Returns:** HTTP `302` redirect with a short-lived authorization code.

IAM must verify that the application is approved, the redirect URI exactly matches its registration, and the actor can access the selected organization. If the application's `notify_users` setting requires consent, IAM shows consent before redirecting.

The `state` value must be returned unchanged. Applications use it to bind the callback to the login request and prevent request forgery.

### `POST /oauth/token`

Exchanges an authorization code for an application access token.

- **Authentication:** Application identity is supplied in the request body.
- **Input:** `app_id`, `app_secret`, `code`, and `redirect_uri`.
- **Returns:** Bearer access token, expiry, and represented actor.

The authorization code is intended to expire after two minutes and be single-use. Its application and redirect URI must match the authorization request.

### `POST /logout`

Logs a Carbon out of IAM-integrated applications.

- **Authentication:** Bearer token.
- **Returns:** `204 No Content`.

IAM revokes the session and queues logout events for affected applications. Webhooks tell applications to remove local state, but central authorization must stop accepting the revoked session even when webhook delivery is delayed.

## Organizations

### `GET /organizations`

Lists organizations available to the authenticated Carbon.

- **Authentication:** Bearer token.
- **Returns:** Organization records.

Each organization includes its immutable ID, name, owner, join method, SSO status, and creation time. Whether Silicons may call this endpoint remains a product decision.

### `POST /organizations`

Creates an organization.

- **Authentication:** Bearer token.
- **Required input:** `org_id` and `name`.
- **Optional input:** `logo` and `description`.
- **Returns:** The created organization.

The authenticated Carbon becomes the sole organization owner. The organization ID must be globally unique and cannot be changed after creation.

### `GET /organizations/{org_id}`

Returns an organization visible to the caller.

- **Authentication:** Bearer token.
- **Authorization:** Organization membership.
- **Returns:** Organization metadata and non-secret configuration.

Provider secrets, SSO credentials, and backend-only configuration must not be returned by this general endpoint.

### `PATCH /organizations/{org_id}`

Updates organization configuration.

- **Authentication:** Bearer token.
- **Input:** Any of `name`, `logo`, `description`, or `join_method`.
- **Returns:** The updated organization.

The join method can be either `email` or `sso`; they are mutually exclusive. The endpoint intentionally cannot change `org_id`. Only the owner or an admin with the relevant permission may make these changes.

## Organization membership

### `GET /organizations/{org_id}/members`

Lists Carbons and Silicons in an organization.

- **Authentication:** Bearer token.
- **Optional filters:** `actor_type=carbon|silicon` and `tag`.
- **Returns:** Member records.

Member records contain the actor, organization role, job role, tags, reporting relationship, first Silicon, and explicitly granted extra Silicons where applicable.

### `POST /organizations/{org_id}/carbon-invites`

Invites an existing Carbon into an organization.

- **Authentication:** Bearer token.
- **Caller:** Owner or authorized admin.
- **Identity:** Either `carbon_id` or `email`.
- **Required configuration:** Role, first Silicon, and default trust.
- **Optional configuration:** Tags and extra Silicons.
- **Returns:** The invitation.

The invitation records its creator, status, and expiry. The intended lifetime is 48 hours. Creating it also sends the invitation email.

### `POST /organizations/{org_id}/silicons`

Creates a Silicon inside an organization.

- **Authentication:** Bearer token.
- **Caller:** Owner or authorized admin.
- **Required input:** Local `silicon_id`, profile photo, and role.
- **Optional input:** `reports_to` and tags.
- **Returns:** The global Silicon identity and a one-time Silicon token.

IAM appends the organization suffix to the requested local ID. For example, `head_of_growth` in `tos` becomes `head_of_growth:tos`.

The raw Silicon token is shown only once. Silicon creation should also initiate its default `Silicon IAM` Hook and then send the initial organization snapshot.

### `DELETE /organizations/{org_id}/members/{actor_id}`

Removes a Carbon or Silicon from an organization.

- **Authentication:** Bearer token.
- **Caller:** Owner or authorized admin.
- **Returns:** `204 No Content`.

Removal revokes organization access across all applications and emits membership-revocation events. Removing a Carbon from one organization does not delete their global account.

The owner cannot be removed without an ownership transfer. Removing a Silicon with direct reports may require reassignment.

### `POST /organizations/{org_id}/join`

Accepts an email-based organization invitation.

- **Authentication:** Bearer token.
- **Input:** `invite_id` and six-digit `verification_code`.
- **Returns:** The created membership.

IAM verifies that the invitation belongs to the organization, belongs to the authenticated Carbon, is still pending, and has not expired. After success, the organization appears in the Carbon's organization list.

The API still needs a separate operation for sending or resending this join verification code.

## Tags

### `GET /organizations/{org_id}/tags`

Lists organization-defined tags.

- **Authentication:** Bearer token.
- **Returns:** An array of tag names.

Tags categorize members and determine which tagged Silicons a Carbon can access.

### `PUT /organizations/{org_id}/tags`

Replaces the organization's complete tag list.

- **Authentication:** Bearer token.
- **Caller:** Owner or authorized admin.
- **Input:** A unique array of tag names.
- **Returns:** Successful replacement.

Because this is a `PUT`, the submitted list represents the complete desired state. Omitting an existing tag removes it. IAM must define how tag removal affects member assignments, derived Silicon access, trust rules, and Briefcase tag folders.

## Role governance

### `POST /organizations/{org_id}/role-change-requests`

Requests a job-role change for a Carbon or Silicon.

- **Authentication:** Bearer token.
- **Input:** Target `actor_id` and proposed `role` of up to 5,000 characters.
- **Returns:** An approval request.

Carbon role changes require approval from the affected Carbon and an owner or admin. Silicon role changes require owner or admin approval. The request records its initiator, required approvers, collected approvals, and status.

### `POST /organizations/{org_id}/role-change-requests/{request_id}/decisions`

Approves or rejects a role-change request.

- **Authentication:** Bearer token.
- **Input:** `approve` or `reject`.
- **Returns:** The updated approval request.

IAM verifies that the caller is an eligible approver. Once all required approvals are present, IAM applies the role, records its history, and emits organization-change events.

The current contract does not expose pending-request listing or role-history retrieval.

## Trust

### `PUT /organizations/{org_id}/trust`

Creates or replaces a trust rule.

- **Authentication:** Bearer token.
- **Input:** `subject`, `target`, and a two-dimensional trust value.
- **Returns:** The stored trust rule.

The subject is an actor or tag selector. The target is a Silicon or tag selector. Trust contains:

- `boundary`: `internal` or `external`.
- `level`: `not_trusted`, `needs_approval`, or `trusted`.

Example:

```json
{
  "subject": "tag:finance",
  "target": "tag:tech",
  "trust": {
    "boundary": "internal",
    "level": "needs_approval"
  }
}
```

Trust is currently advisory metadata. It does not grant or deny actions until a product explicitly connects an action to trust evaluation. The API still needs rule identifiers, listing, and deletion.

## Silicon-token rotation

### `POST /organizations/{org_id}/silicons/{silicon_id}/token-rotation-requests`

Requests rotation of a Silicon token.

- **Authentication:** Bearer token.
- **Returns:** An approval request requiring the organization owner.

This operation does not immediately rotate the token. After owner approval, IAM should generate a new one-time token, invalidate the old token, revoke affected sessions, and record the rotation.

The current contract still needs the completion operation that securely returns the new raw token.

## SSO

### `POST /organizations/{org_id}/sso/setup-link`

Creates a WorkOS configuration link.

- **Authentication:** Bearer token.
- **Caller:** Owner or authorized admin.
- **Returns:** Setup URL and expiry.

The setup link is intended to remain valid for two hours. IAM permanently stores the relationship between the IAM organization and its WorkOS organization. This endpoint should work only after SSO has been enabled for the organization by the platform backend.

### `POST /organizations/{org_id}/sso/test`

Tests an active SSO configuration.

- **Authentication:** Bearer token.
- **Returns:** `ok` and a human-readable result message.

Testing should validate the configured connection without changing organization membership.

The API still needs WorkOS webhook, SSO callback, SSO login initiation, disable, and reconfiguration operations.

## IAM applications

IAM applications use IAM for login, organizational context, and OBO Access.

### `GET /applications`

Lists applications owned or manageable by the authenticated account.

- **Authentication:** Bearer token.
- **Returns:** Application records.

An application contains its ID, name, logo, webhook URL, redirect URI, scopes, review status, `notify_users` setting, and creation time. Application secrets are never returned.

### `POST /applications`

Registers an application.

- **Authentication:** Bearer token.
- **Required input:** `app_id`, `webhook_url`, `redirect_uri`, and scopes.
- **Optional input:** Name and logo.
- **Returns:** An `under_review` application and one-time `app_secret`.

The raw secret is displayed only once and IAM stores a secure derived value. The application cannot initiate production authentication until it has been manually approved.

### `DELETE /applications/{app_id}`

Deletes an IAM application.

- **Authentication:** Bearer token.
- **Caller:** Application owner or platform administrator.
- **Returns:** `204 No Content`.

Deletion should revoke active application tokens, OBO Access proofs, redirect authorization, and webhook delivery. Recovery and soft-deletion behavior are not currently specified.

## OBO Access

OBO means **On-Behalf-Of**. It allows one application to perform a narrowly defined action on another service as a particular Carbon or Silicon.

### `POST /obo-access/verify`

Verifies an OBO Access proof.

- **Authentication:** Application credentials through HTTP Basic authentication.
- **Input:** `access_proof`, `audience`, `action`, and optional `resource`.
- **Returns:** Verified actor, organization, audience, allowed actions, and expiry.

Example flow:

```text
DM needs a temporary URL for Carbon A's Briefcase file.

DM -> Briefcase
  X-App-ID: silicon-dm
  X-IAM-OBO-Access-Proof: ...

Briefcase -> IAM /obo-access/verify
  audience: silicon-briefcase
  action: briefcase.file.temporary_url
  resource: file-id

IAM -> Briefcase
  valid: true
  actor: carbon A
  org_id: tos
  actions:
    - briefcase.file.temporary_url
```

The target service must apply two checks:

1. The OBO proof is valid for the audience, action, resource, actor, organization, and current time.
2. The represented actor has permission to perform that action on the resource.

OBO Access cannot give an application more authority than the represented actor possesses. Proofs must be short-lived, audience-bound, action-bound, replay-resistant, and auditable.

The current API verifies OBO proofs but does not define the operation that creates or exchanges one. That operation is required before the OBO flow is implementation-complete.

## Complete platform flows

### Carbon signup

```text
Create signup session
  -> send email code
  -> verify email
  -> send phone code
  -> verify phone
  -> check Carbon ID
  -> complete signup
```

### Carbon login into an application

```text
Create login challenge
  -> verify code
  -> receive IAM session
  -> authorize application
  -> application receives authorization code
  -> application exchanges code for access token
```

### Silicon creation and authentication

```text
Owner/admin creates Silicon
  -> IAM appends organization suffix
  -> IAM returns one-time Silicon token
  -> IAM creates default Silicon IAM Hook
  -> IAM sends initial organization snapshot
  -> Silicon exchanges ID + token for an access token
```

### Organization revocation

```text
Owner/admin removes member
  -> IAM revokes organization authority
  -> IAM emits revocation events
  -> applications close sessions and connections
  -> future authorization attempts fail centrally
```

## Contract gaps

The documented endpoints represent the current OpenAPI contract, but the following operations are still needed:

- Send or resend an organization-join verification code.
- List, inspect, and revoke pending Carbon invitations.
- Read and update individual memberships, tags, reporting lines, and extra-Silicon access.
- Transfer organization ownership.
- Configure granular organization-admin permissions.
- Create or exchange an OBO Access proof.
- List and inspect pending approval requests.
- Complete Silicon-token rotation and return the new token securely.
- Read role-change history and login history.
- Receive WorkOS webhooks and support SSO initiation and callback.
- Approve, reject, suspend, and configure applications from the backend administrator interface.
- Rotate application secrets.
- Refresh, inspect, and revoke individual access tokens.
- Define delivery retries, signatures, ordering, and replay handling for IAM application webhooks.

These gaps should be addressed before the IAM contract is treated as implementation-complete.
