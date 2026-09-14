# Scoped IAM backend

`iam-scoped-api` serves the noncritical and critical IAM permission APIs at
`https://scoped.backend.iam.teamofsilicons.com`. It is a separate process with
an explicit route list, sharing IAM's database, user identities, authorization,
keyrings, audit events, and durable worker. It does not create another identity
store or issue unrestricted IAM credentials.

## Application and bundle integration

The hosted scoped service's registered application is **`tos>iam`**. Register
and manage it through main IAM; the scoped host does not create or administer
applications. Include `tos>iam` in Interface's `tos>interface` bundle.

Set the application's `base_url` to
`https://scoped.backend.iam.teamofsilicons.com`, declare the IAM permissions that
Interface needs under `app_scope.iam`, and leave `app_scope.external` and
`obo_endpoints` empty. Registration requires a signature-verifying webhook receiver and its secret.
For this application, configure the scoped service's `POST /webhooks/iam`
receiver as described below and register
`https://scoped.backend.iam.teamofsilicons.com/webhooks/iam` as its webhook URL.

The bundle issues a separate, single-use SLT for `tos>iam`. Interface sends it
to the scoped host's `POST /api/v1/auth/login` as JSON `{ "slt": "oac_..." }`.
The scoped process resolves its own fixed application identity through IAM's
trusted database connection and reuses IAM's existing token machinery. **Neither
Interface nor scoped IAM requires an application client secret for this flow.**
There is no caller-selected application ID, destination, or secret parameter.

Main IAM remains responsible for the initial Carbon/Silicon login, consent, and
SLT issuance. Its public `/api/v1/app-auth/tokens`, `/api/v1/oauth/introspect`, and
`/api/v1/oauth/revoke` contracts still require application Basic authentication.
The scoped adapter does not weaken those endpoints or mint first-party tokens.
Other applications keep their existing authentication contracts.

### Scoped application session endpoints

The machine-readable adapter contract is [scoped-auth-openapi.yaml](scoped-auth-openapi.yaml).

| Scoped-only endpoint | Input | Success |
| --- | --- | --- |
| `POST /api/v1/auth/login` | JSON `{ "slt": "oac_..." }` | IAM token response with access token, refresh token, expiry, scopes, and actor |
| `POST /api/v1/auth/refresh` | JSON `{ "refresh_token": "ort_..." }` | Rotated IAM token response |
| `POST /api/v1/auth/logout` | JSON `{ "refresh_token": "ort_..." }` | `200`, empty body; repeat/unknown/other-app tokens are safe no-ops |
| `POST /api/v1/auth/introspect` | `Authorization: Bearer oat_...`, optional `X-Org-ID`; no body | Current IAM introspection and authorization snapshot |

Login, refresh, and logout require `Idempotency-Key`. Preserve the same key and
body after a transport failure; exchange and rotation preserve IAM's encrypted
replay receipts and refresh-reuse protection. A fresh key cannot redeem a spent
SLT again. Unknown JSON fields, repeated security headers, query parameters,
incorrect credential types, and bodies over 4 KiB are rejected. Auth throttling
is keyed to an HMAC digest of each credential and route, so garbage credentials
cannot consume one shared login allowance for every user. Production login accepts
only a real issued SLT. In a verified testing plane, the same adapter accepts an
existing test Carbon/Silicon public ID through IAM’s existing testing login core.

Introspection accepts only an active, ordinary `tos>iam` application token for
a Carbon or Silicon. Other applications, OBO tokens, first-party sessions, and
cookies cannot authorize it. It returns only that token's current grants;
`X-Org-ID` selects an authorized organization and never expands its reach.
Unavailable or suspended `tos>iam` registration fails closed. Approved scopes,
consent, current actor/session epochs, selected memberships, and role/capability
checks remain enforced by IAM's existing revocation-aware machinery.

Keep application access and refresh credentials in the consuming application's
server session storage. The SolidJS frontend needs only its Interface session.
The signed webhook receiver below retains its separate webhook keyring.

The application needs critical-scope approval through the usual IAM review
workflow. Application permission availability still applies;
being included in a bundle does not override them. Every request is also limited
by the user's current membership, role, capabilities, and selected organization
grants. Removing a permission or revoking a session takes effect through IAM's
normal revocation-aware token checks.

## Authentication boundary

Every business route requires `Authorization: Bearer <application access token>`.
The token must have a nonempty client-application binding and the same audience
application. Direct IAM sessions, platform-administrator sessions, browser
cookies, and OBO tokens for another application are rejected. A valid ordinary
application session may represent either a Carbon or a Silicon; each handler
still enforces its own actor restrictions. An invalid bearer never falls back
to a browser cookie.

There is no OBO exchange, verification, proxy, or endpoint-discovery route.
`GET /api/v1/application-scopes` returns only the IAM permission catalog and
rejects query parameters, including `app_id`. It does not advertise another
application's OBO endpoints.

Public operational routes are `/healthz`, `/readyz`, `/api/version`,
`/api/v1/version`, and `/api/v1/contracts`. They disclose no user or organization
data. The backend retains normal version negotiation, CORS, size limits,
timeouts, admission control, structured errors, sensitive-header redaction,
request IDs, and no-store responses. Testing-environment credentials select the
same isolated testing data plane before authentication. The explicit delegated
creation operation below runs only on the production control plane; other
testing-environment administration remains available through main IAM.

## Delegated testing-environment creation

`POST /api/v1/organizations/{org_id}/testing-environments` accepts JSON
`{ "name": "Interface testing", "description": "Optional description" }` and
requires an ordinary application **Carbon** bearer with the exact non-critical
`organization.testing_environments.create` scope. Declare this permission in the
application's `app_scope.iam` and obtain fresh user consent. The migration defines
its availability and classification; it does not grant it to any application.

The represented Carbon must remain an active member of the selected organization.
`X-Org-ID`, when supplied, must match the path. App approval, live consent, session,
actor epochs and selected membership are rechecked under transaction locks before
creation or idempotent receipt recovery. Another organization, app or login session
cannot recover that receipt. `Idempotency-Key` is required; identical retries return
the same encrypted receipt, while a changed payload conflicts. Concurrent creation
observes the organization's existing testing quota.

The `201` response is the existing flat `EnvironmentWithKey` object: environment
fields including `id`, `org_id`, `name`, `created_by_membership_id`, `version`,
`key_generation`, timestamps and **`key`**, the 32-character environment root.
This permission explicitly delegates creation and possession of the new test-world
root, including its existing bootstrap/import/test-data authority. It confers no
production identity or access management. Keep the root and test credentials in
the application gateway's server session. Responses are never cacheable. A root or
application testing selector on this production mutation is rejected.

### Bootstrap and use the isolated world

Use the returned root as `X-Testing-Environment-Key` on main IAM's existing testing
signup, organization creation and application import routes. These create test
identities and import application configuration; they do not copy production users
or production app secrets. Import `tos>iam` before using scoped application login.
Then call scoped `POST /api/v1/auth/login` with `{ "slt": "<test Carbon public ID>" }`
and the same root header. IAM creates an ordinary revocable test application
session for that existing actor. Real issued test SLTs are also supported.

Keep the root header on **every** scoped test login, refresh, logout, introspection
and business request. Resolution is fixed to the verified, active imported
`tos>iam` record in that selected world and its current import policy. A missing
import, another world or a production credential cannot trigger a production
fallback. Production calls without a root continue to require real SLTs and
production application sessions. No production app client secret is needed.

Deploy the matching main and scoped images plus base migration `0092` and testing
overlay `9007` together so registration, consent and readiness use the same native
catalog and migration ledger. Preserve the existing database credentials/keyrings.

## Signed application webhook receiver

The scoped service can receive its registered application's production IAM
notifications at `POST /webhooks/iam`. Set `IAM_SCOPED_WEBHOOK_KEYRING` to a JSON
object mapping positive signing-key versions to their secrets, for example
`{"1":"<the same random secret supplied at registration>"}`. This secret is
separate from the generated application client secret. The route is absent
when this setting is missing, and invalid or empty keyrings prevent startup.

The production installer loads the setting from the private host file
`/etc/silicon-iam/scoped-webhook.env` and preserves that file on reinstall.
Store it with mode `0600`; never commit keys or print them in logs. Restart only
the scoped service after updating it. Retain both old and new versions during
webhook-secret rotation until the previous delivery retry window has elapsed.

The receiver uses the official SDK verifier: HMAC-SHA256 over the timestamp,
a dot and exact body bytes; a five-minute timestamp window; a 1 MiB body limit;
exactly one of each security header; and matching header/body event IDs. Valid
production events receive `204`; missing, invalid, stale or unknown-version
signatures and testing envelopes receive `401`. Imported testing applications
must configure their own receiver with their own environment-bound keys.

This receiver keeps no user/session cache. The scoped API reads IAM's
revocation-aware database on every authorized request, so webhook processing
requires no domain mutation, forwarding or payload storage. Duplicate valid
deliveries are safe to acknowledge. The receiver is authenticated by its
signature, outside the application's bearer gate; business APIs still require
application bearer tokens. It is not exposed on the main IAM host and adds no
OBO or webhook-administration endpoints.

## Available route groups

The paths and request/response schemas match the corresponding main IAM APIs
in [the OpenAPI contract](openapi.yaml).

| Route group | Available actions |
| --- | --- |
| `/api/v1/me` | Read the current subject's permitted identity/profile/contact fields |
| `/api/v1/application-scopes` | Discover IAM permissions only |
| `/api/v1/organization-ids/{org_id}/availability` | Check an organization ID for onboarding |
| `/api/v1/organizations` and `/{org_id}` | List, read, create, and update organizations according to scopes |
| `/{org_id}/members` and `/{membership_id}` | Read directory members, update assignments, remove members |
| Member authorization, tags, job roles, histories, promotions, demotions, and capabilities | Read or mutate only with the relevant published scope and the represented user's authority |
| `/{org_id}/directory/*` | Read self/member projections filtered by granted fields |
| `/{org_id}/carbon-invites/*` and `/join/*` | Manage invitations and complete verified invitation admission |
| `/{org_id}/silicons/*` | Read, create, update, remove, and request/complete credential rotation |
| `/{org_id}/tags/*` and `/trust/*` | Read and manage tag catalogs, member assignments, and trust configuration |
| `/{org_id}/role-change-requests` and `/approval-requests/*` | Submit, read, and decide eligible governance requests |
| `/{org_id}/sso`, `/sso/setup-link`, `/sso/test`, `/sso/authorize` | Read/manage entitled SSO and initiate validated SSO admission |

All abbreviated organization paths above begin with
`/api/v1/organizations`. Methods without a published IAM scope are absent: there
is no `PATCH /api/v1/me`, ownership transfer, Silicon webhook administration,
application administration, provider webhook, platform admin, or HTML surface.

Initial identity login, consent, SLT issuance, first-party step-up challenges,
and the WorkOS callback stay on main IAM. The scoped session endpoints above
complete and maintain only the `tos>iam` application login. A critical operation that requires step-up consumes
`X-Step-Up-Token` from IAM's existing verified-channel flow, bound to the same
underlying authentication session, action, and resource. IAM's provider callback
remains `https://backend.iam.teamofsilicons.com/api/v1/sso/callback`; the scoped
process therefore retains the **canonical main IAM** `IAM_PUBLIC_BASE_URL`.

For example, after exchanging the application's SLT:

```sh
curl --fail-with-body \
  --header "Authorization: Bearer $SCOPED_ACCESS_TOKEN" \
  https://scoped.backend.iam.teamofsilicons.com/api/v1/me
```

Organization mutations use the same `Idempotency-Key`, version preconditions,
and optional step-up headers documented in the main contract. Scopes grant the
application permission to request an action; they do not increase the user's
organization authority.

## Rust SDK and mutation receipts

Use `client.application_reads()` for projected reads and
`client.application_mutations()` for organization, member, invitation, Silicon,
tag, trust, and governance mutations. The mutation methods return
`models::ApplicationMutationObject` (a JSON value), preserving absent fields and
any independently disclosed nested data. The existing strongly typed methods
remain available for direct IAM sessions. Deletes, verification-code delivery,
completed credential rotation, and SSO retain their existing typed SDK methods.

A successful write with no matching read permission can return only identifiers,
version/status metadata, or an empty object. Do not decode that response as a
full organization, membership, invitation, or trust model, and do not interpret
omitted fields as empty/default data. For example, a Carbon with only
`organizations.create` can receive `{ "id": "...", "org_id": "acme", "version": 1,
"status": "active" }`, without an organization name or timestamps. Silicon
creation still includes its generated identifiers and requested one-time
credential; store that credential immediately and never log the response.

```rust
use silicon_iam_client::{Client, Credential, Mutation, models};

async fn example(access_token: String) -> silicon_iam_client::Result<()> {
let client = Client::new("https://scoped.backend.iam.teamofsilicons.com")?
    .with_credential(Credential::bearer(access_token));
let input = models::OrganizationCreate {
    org_id: "acme".into(), name: "Acme".into(), logo: None, description: None,
};
let creating = Mutation::new();
let receipt = client.application_mutations()
    .create_organization(&input, &creating).await?;
let organization_id = receipt.get("id").and_then(serde_json::Value::as_str);
let _ = organization_id;
Ok(())
}
```

OpenAPI documents both the direct IAM full response and the application mutation
object for these operations. Reuse the same `Mutation` on retries so an omitted
field does not cause an accidental second write with a new idempotency key.

## Local operation

`docker compose up scoped-api` runs the separate process at
`http://localhost:8081`, using the normal migrations and API runtime role. Set
`IAM_SCOPED_CORS_ALLOWED_ORIGINS` to the local Interface origin when it differs
from `http://localhost:3000`. The scoped process defaults to four production DB
connections; its pool is separate from the main API pool.

For a native process, use the same IAM environment and override `IAM_BIND_ADDR`
to an unused address before `cargo run --bin iam-scoped-api`. Keep the canonical
main IAM backend and authentication URLs for provider callbacks and invitations.

## Scoped authentication bootstrap

Run the one-shot `iam-scoped-auth-init` binary with the existing private
`IAM_MIGRATOR_DATABASE_URL` before starting the updated scoped service. It applies
`deploy/scoped/application-identity.sql` to the production database only. The
scoped process checks that the helper is installed and executable at startup. The idempotent SQL installs one argument-free, fixed-search-path
resolver for active, verified `tos>iam` in the active `tos` organization. Only
the existing trusted `silicon_iam_api` database role can execute it; PUBLIC
execution is revoked. The resolver never returns secret material and cannot
select another application. The shared OAuth core rechecks current authority
inside each credential transaction.

This scoped-owned bootstrap deliberately leaves `_sqlx_migrations` unchanged:
main IAM and worker readiness validate their exact embedded migration ledger.
No main IAM restart or deployment is required. The runtime grant manifest
preserves the optional resolver grant when it is installed. Include the bootstrap
in scoped provisioning after ordinary IAM runtime grants. Rollback the scoped
binary independently; leaving this narrow helper installed is safe.

## Production installation

The current production ingress is nginx and Certbot on the IAM EC2 instance;
the older ALB migration templates in `deploy/aws` are not the live ingress.
Do not replay those templates to install this service.

1. Build and verify one immutable image containing the updated main IAM binary,
   migrations, and `iam-scoped-api`. Apply migrations to production and the
   isolated testing database, then upgrade the main IAM API so scope registration
   and login use the same catalog. Preserve existing credentials and keyrings.
2. On the existing IAM instance, pull that image and extract
   `/opt/silicon-iam/scoped` from it into the release directory. The image includes
   both `install.sh` and `nginx.conf`.
3. Run `bash install.sh --image '<registry/repository@sha256:digest>'`. It copies
   the existing private API environment inside the host, limits the new pools,
   installs a dedicated systemd service on `127.0.0.1:8081`, and checks readiness
   plus absence of privileged routes. It does not change the main API service.
4. Add only `scoped.backend.iam.teamofsilicons.com` in DNS, pointing to the current
   IAM public IP. Preserve the complete existing zone and verify authoritative
   resolution. Re-run the installer with the same image and `--tls` to obtain the
   host-specific Let's Encrypt certificate and activate the separate nginx
   virtual host. The existing `*.iam.teamofsilicons.com` certificate does not
   cover this deeper hostname.
5. Verify public TLS, readiness, version, an ordinary scoped application request,
   missing-scope denial, direct-IAM/OBO rejection, and that excluded paths return
   404. Confirm the main IAM endpoint and worker remain healthy.

Production CORS includes `https://interface.teamofsilicons.com` and the canonical
IAM authentication origin, `https://auth.iam.teamofsilicons.com`. IAM's shared
production configuration requires the authentication origin even on the scoped
service. When replacing the list through `--cors-origins`, retain that origin and
add any other required exact HTTPS origins. Application bearer authentication
remains mandatory for every business route. The container port is loopback-only; public clients
reach it through TLS. API logs use the existing IAM CloudWatch log group with
the `scoped-api` tag, while the new nginx host disables access logging.

Rollback the scoped process by rerunning its installer with the previous
compatible immutable image. For an initial-install rollback, disable the scoped
systemd service and remove only its nginx virtual host and DNS record. Do not
remove shared IAM database migrations, keyrings, main API service, or worker.
