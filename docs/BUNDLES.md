# Application bundles

A bundle gives users one application identity during login while connecting
several applications in the same organization. Every member remains an ordinary,
independent application with its own permissions, secret, short-lived token,
access tokens, refresh tokens, and webhook configuration.

Create and manage bundles in the IAM console’s **App bundles** section, or use
`POST /api/v1/application-bundles` with a direct IAM Carbon bearer token. The
current organization owner or administrator can manage a bundle when bundle
creation is available for that organization.

```json
{
  "org_id": "tos",
  "app_id": "workspace",
  "app_name": "Workspace",
  "app_ids": ["tos>notes", "tos>files"]
}
```

The response contains `bundle_id: "tos>workspace"`, the member app IDs, a
version, and timestamps. The local handle becomes an immutable qualified bundle
ID. Members must be distinct, active, approved applications in the same
organization. There are 1–100 members, and bundles cannot contain other bundles.
A bundle has no secret of its own.

Use `GET /api/v1/application-bundles` to list managed bundles and
`GET /api/v1/application-bundles/{bundle_id}` for one bundle. `PATCH` on that
resource changes its name, logo, or the full `app_ids` list; `DELETE` retires it.
Mutations require an idempotency key. Updates and deletion also require the
current version in `If-Match`. Deleting the bundle leaves its member
applications intact.

## Browser login

Send the user to IAM with only a bundle target and optional callback:

```text
https://auth.iam.teamofsilicons.com/login?bundle_id=tos%3Eworkspace&redirect_uri=https%3A%2F%2Fworkspace.example%2Fcallback%3Fstate%3Dopaque
```

`bundle_id`, `app_id`, and `app_ids` are mutually exclusive. Applications do not
choose the user’s organizations. IAM validates the bundle, presents its public
identity, asks for the applicable permissions, and lets the user select
organizations. Only permissions that the backend marks as requiring consent
are displayed. Every member receives its own declared, user-approved scope set.

IAM returns the same per-application SLT array as batch login, encoded in the
callback fragment:

```text
https://workspace.example/callback?state=opaque#slts=<URL-encoded JSON array>
```

Each array item contains `app_id`, `slt`, and expiry metadata. Parse the fragment,
validate your callback state, promptly remove the fragment from browser history,
and deliver each SLT only to its matching application server. That server
exchanges it at `/api/v1/app-auth/tokens` using its own application ID and secret.
The SLT expires after at most two minutes and is single-use. One member’s secret
cannot exchange another member’s token. Applications never ask for IAM
credentials or verification codes.

## Direct IAM client flow

Read `GET /api/v1/app-auth/bundles/{bundle_id}/organizations` using the current
Carbon or Silicon IAM session. It returns the bundle identity and one login
choice object per member. Each object includes organizations, `scope_version`,
`consent_required`, and the complete active permission descriptors.

Submit explicit choices to
`POST /api/v1/app-auth/bundles/{bundle_id}/short-lived-tokens`:

```json
{
  "applications": [
    {
      "app_id": "tos>notes",
      "org_ids": ["work"],
      "scope_version": 3,
      "approved_scopes": ["self.identity.read", "self.profile.read"]
    },
    {
      "app_id": "tos>files",
      "org_ids": ["work"],
      "scope_version": 8,
      "approved_scopes": ["self.identity.read", "self.profile.read"]
    }
  ]
}
```

Use the actual scope versions and exact permission identifiers returned by the
choices endpoint. All current bundle members must be present exactly once.
Membership, application status, and scope changes are revalidated atomically
before issuing any token. If validation fails, no partial bundle login is
created. Reload choices after a stale scope or changed-member response.

An idempotent retry is bound to the same IAM session and bundle, preserving the
original tokens and expiry times. Retry the exact same body and key after an
ambiguous response; do not extend or assume a fresh token lifetime.

See [application login](https://docs.iam.teamofsilicons.com/client/login/),
[batch login](BATCH_LOGIN.md), and the
[OpenAPI contract](https://docs.iam.teamofsilicons.com/openapi.yaml).
