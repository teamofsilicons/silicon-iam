# Testing environments and isolation

Testing environments run the IAM contract against isolated data. An application can create an environment for its own tests or attach to an existing IAM environment, recursively preparing the external applications it depends on.

## One API, isolated data

Requests without a testing header use production. Select an environment with `X-Testing-Environment-Key`, a 32-character alphanumeric root key. Protected endpoints still require the ordinary credentials issued inside that environment. Production and testing sessions, application secrets, SLTs, refresh tokens, Silicon credentials, and OBO proofs cannot be used interchangeably. A lookup never falls back to production.

```
X-Testing-Environment-Key: <environment root key>
Authorization: Bearer <direct IAM token issued in this environment>
```

The key is root authority, not an identifier. A holder can use the testing authentication flows to administer the environment. Keep the public environment UUID in run metadata and store the key separately as a secret. Exclude keys and credential-bearing bodies from source, URLs, logs, traces, screenshots, and persisted webhook records.

## Create an application testing environment

An application uses its production Basic credentials to call `POST /api/v1/application/testing-environments`. Without `iam_test_key`, IAM creates a new environment for the application's owning organization. With a valid existing key, IAM attaches the application and its dependencies to that environment. Reuse the same key for all parts of one integrated test.

```
POST /api/v1/application/testing-environments
Authorization: Basic <production app ID and app secret>
Idempotency-Key: <one logical setup>
Content-Type: application/json

{
  "name": "Checkout integration",
  "description": "Payment and storage delegation",
  "iam_test_key": "<optional existing environment key>"
}
```

The response includes `environment_id`, `org_id`, name and description, `iam_test_key`, the root application's `app_id` and fresh test `app_secret`, a list of imported `dependencies`, and `secret_replay_expires_at`. Save it securely during the ten-minute replay window. Repeating the same logical operation uses the original idempotency key.

IAM follows declared external scopes recursively, including dependencies of dependencies. It deduplicates applications and handles cycles so a dependency is prepared once per environment. Every dependency shares the same environment key. Application-owned organizations may differ; each is represented within the isolated environment.

`GET /api/v1/application/testing-environments` lists linked environments in the calling application's owning-organization context, with `cursor`, `limit`, and `status=active|deleted|all` (default active). Each item exposes the environment UUID, organization, name, description, status, version, purge deadline, last activity, retention days, and `can_manage`. Credentials are not included in the list.

## Recognize and authenticate test requests

When a test request carries an `app_secret`, the receiving application treats that as a signal to enter its test flow. It must authenticate the supplied test app credentials against IAM with the corresponding environment key before trusting the request. Presence of a secret-shaped string is insufficient. Store test data separately from production, keyed to the environment, and carry the authenticated testing context through subsequent work.

For an OBO request, IAM may return a `testing_context` containing the recipient's test app ID, test secret, and `iam_test_key`. The caller passes it to that recipient over secure transport. The recipient uses it to verify the proof against IAM inside the correct environment. Production application secrets are never disclosed to another application.

## IAM environment lifecycle

A direct production Carbon or Silicon member can create an environment through the organization lifecycle API. The creator and current owning-organization owners/admins can administer it. A production application can also perform every lifecycle operation on environments it created, using HTTP Basic with its production app ID and secret. Use the organization and environment IDs returned by creation. App clients list through `/application/testing-environments` and create through that same application route; the individual environment routes below accept either authorized IAM bearers or the creating application’s Basic credential. These routes operate on the environment's production control record; they do not enter its test data plane.

| Method | Route under /api/v1 | Purpose |
| --- | --- | --- |
| `GET/POST` | `/organizations/{org_id}/testing-environments` | List or create environments. |
| `GET/PATCH/DELETE` | `…/testing-environments/{environment_id}` | Read, edit, or soft-delete an environment. |
| `GET` | `…/{environment_id}/key` | Retrieve the current key with audit. |
| `POST` | `…/{environment_id}/key-rotations` | Replace the key immediately. |
| `POST` | `…/{environment_id}/cleanings` | Erase test data while retaining the environment. |
| `POST` | `…/{environment_id}/restorations` | Restore before the purge deadline. |

A newly created IAM environment starts empty. `GET /api/v1/testing-environment` and `POST /api/v1/testing-environment/cleanings` are key-authorized self routes. A clean invalidates the erased identities, imports, sessions, and proofs; reimport and obtain new credentials before another run. Deletion disables the key and allows recovery for 30 days before purge.

## Application import and webhook keys

Create a test-only application with the ordinary application registration route using a test Carbon owner/admin token and the environment key. It cannot claim an ID occupied by a production application. To import a production application into the selected environment, use:

```
POST /api/v1/testing-environment/applications/imports
Authorization: Bearer <test Carbon access token>
X-Testing-Environment-Key: <environment key>
Idempotency-Key: <one logical import>
Content-Type: application/json

{"app_id":"storage>drive"}
```

Import preserves the qualified ID, backend URL, webhook URL, OBO catalog, and declared dependency permissions. IAM creates a missing owning organization in the environment and makes the importing test Carbon its owner. It returns a fresh test-only client secret. The same production app may be imported into several environments without sharing their data or credentials.

The production webhook signing secret is inherited internally so the existing receiver can validate test deliveries, but IAM never reveals that production secret. When an app replaces its webhook destination in a testing environment, IAM creates and returns a fresh test-only `webhook_signing_secret` when no replacement was supplied. A caller may instead supply a test-only `webhook_secret`. The new endpoint activates immediately, and the secret-bearing response has a ten-minute replay window. Every testing destination replacement uses a supplied or newly generated test-only secret. Production destination changes reuse the current key.

## Fixed verification codes

Testing sends no real email or SMS. Use `000000` for signup contact verification, Carbon login, invitation acceptance, and verified-channel step-up. Challenge creation, attempts, cooldowns, expiry, session binding, and idempotency still run through the normal lifecycle. The root key therefore enables onboarding and authenticating administrative test identities without a real inbox or phone.

## Test webhooks

Production events carry top-level `metadata` and `data`. Test deliveries wrap them with the environment key:

```
{
  "test": {
    "testing_key": "<environment root key>",
    "metadata": {
      "spec_version": "1.0",
      "event_id": "<uuid>",
      "event_type": "organization.membership.updated.v1",
      "occurred_at": "2026-09-12T08:00:00Z",
      "organization_id": "<uuid>",
      "aggregate": {"type":"membership", "id":"<uuid>", "version":2}
    },
    "data": {}
  }
}
```

Verify the signature over the complete raw outer body before interpreting it. Validate and match the testing key to the expected environment, route to isolated storage, then redact the key. Deduplicate on `test.metadata.event_id` and order updates by `test.metadata.aggregate.version`. An otherwise valid test event must never update production data.

## Inactivity and cleanup

The default application testing retention is 30 idle days. An application's owner/admin can configure `testing_idle_days` on its registration or update. IAM tracks activity for individual application-environment links and retires idle test instances according to that application's setting. Retiring one instance does not authorize deleting another application's active test data.

IAM environments also default to soft deletion after 30 idle days, followed by a 30-day recovery window. Active application links with longer configured retention keep their environment available while they are still within that retention period. List responses expose activity and retention so applications can clean their own isolated storage on the same lifecycle.

## Exercise the complete flow

1. Create or attach an application environment and securely retain its key and test secret.

2. Onboard a test Carbon with fixed OTPs, or authenticate a test Silicon, and establish the required memberships.

3. Read current login choices, approve the exact scope version, choose organizations, exchange each SLT with its matching test application secret, and introspect the resulting token.

4. Discover and call an external dependency through OBO. Verify the proof inside the same environment and ensure an unselected organization or production credential fails.

5. Trigger a scoped directory change; verify and apply its signed test webhook only to that environment's data.

6. Clean for another run or retire the environment. Discard erased credentials and imported app secrets.

See the Rust testing guide (`iam docs client/testing-environments`) and [CLI guide](https://docs.iam.teamofsilicons.com/cli/) for typed and command-line workflows.

## Application lifecycle authority

`can_manage=true` means the authenticated production application created that environment. It can read, edit, clean, delete, restore, reveal the key, and rotate the key. Importing a dependency or attaching another application does not transfer lifecycle ownership. Linked applications with `can_manage=false` cannot retrieve the root key or manage the control record using their production app secret. Authorized organization administrators retain their existing controls.

Edits require the current `If-Match` ETag. All mutations require `Idempotency-Key`. Clean permanently erases the entire selected IAM environment, including every imported application and test identity, while retaining its key. Recreate/import the application before using its test secret again. Delete disables the environment and key until restored; recovery is available only until `purge_after`. Rotation invalidates the previous key immediately. These actions do not delete your application’s own database: apply your own environment cleanup policy there.

## Build a test-view switch in your application

1. Ask for the test `app_secret` and `iam_test_key` over your own HTTPS form. Fix the app ID on your server to your application’s configured ID.

2. From your server, call `GET /api/v1/application/testing-context` with HTTP Basic `app_id:app_secret` and `X-Testing-Environment-Key: iam_test_key`.

3. On success, IAM returns `environment_id` and the authenticated application’s test configuration. Match the app ID, select storage by that environment UUID, and visibly identify test mode. This endpoint returns no credentials.

4. Keep credentials server-side in a short-lived session or secret store. Revalidate them before privileged work and clear the session when IAM rejects a deleted environment, rotated key, or retired test app. Never fall back to production after a failed test request.

5. Use the same environment key and test app secret for subsequent IAM calls. Apply ordinary user login, consent, and authorization inside the test environment when accessing user data. An app secret does not identify an end user.

The IAM console’s application Testing tab offers a read-only configuration view using this same endpoint. It clears submitted credentials after every request. It does not open an external application’s UI or convert a production console session into a test administrator.
