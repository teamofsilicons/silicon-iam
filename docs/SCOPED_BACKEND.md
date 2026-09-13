# Scoped IAM backend

`iam-scoped-api` serves the noncritical and critical IAM permission APIs at
`https://scoped.backend.iam.teamofsilicons.com`. It is a separate process with
an explicit route list, sharing IAM's database, user identities, authorization,
keyrings, audit events, and durable worker. It does not create another identity
store or issue unrestricted IAM credentials.

## Application and bundle integration

Register the application through the **main IAM** application-management API or
frontend. The scoped host itself does not expose application creation or
administration. The owning organization and application ID are chosen at
registration; the hosted service does not reserve or automatically register one.

Set the application's `base_url` to
`https://scoped.backend.iam.teamofsilicons.com`, declare the IAM permissions that
Interface needs under `app_scope.iam`, and leave `app_scope.external` and
`obo_endpoints` empty. Registration still requires the application's actual,
signature-verifying webhook receiver and its secret. The stateless scoped IAM
service is not a webhook receiver and must not be entered as a placeholder
webhook destination.

An organization with bundle configuration available can include that application in its existing bundle.
The bundle issues the usual separate, single-use SLT for that application.
Interface's backend exchanges the SLT with the application's client secret at
**main IAM** `/api/v1/app-auth/tokens`. The resulting ordinary application access
token authorizes calls to the scoped backend. The app secret and refresh token
belong in the application's backend session storage.

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
same isolated testing data plane before authentication, but testing-environment
administration is available only through main IAM.

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

Login, refresh, SLT exchange, first-party step-up challenges, and the WorkOS
callback stay on main IAM. A critical operation that requires step-up consumes
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
