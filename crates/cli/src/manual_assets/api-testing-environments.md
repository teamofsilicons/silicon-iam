# Testing environments and isolation

A testing environment is the complete Silicon IAM contract on isolated data. It begins with no organizations, Carbons, Silicons, Applications, sessions, or logs, and uses the same endpoints and authorization rules as production.

## Two planes, one API

A normal request without an environment header operates on production. Add the root key to a plane-selectable request to execute that same route inside one environment:

```
X-Testing-Environment-Key: <32 alphanumeric characters>
```

**The key is root authority, not an environment label.** Anyone holding it can perform any action inside that environment. Keep the public environment UUID in build metadata and keep the key in a secret store. Never put the key in a URL, source, test name, log, trace, screenshot, or persisted webhook record.

The header selects the data plane; it does not replace normal authentication. A protected Carbon route still needs a bearer issued inside that environment. An Application route still needs an Application secret issued there. Production and test access tokens, refresh tokens, short-lived tokens, STKs, Application secrets, sessions, and OBO proofs are mutually rejected. IAM does not currently expose a caller API-key credential; any such credential added later must preserve this same fail-closed plane binding.

## Lifecycle API

Lifecycle routes use a production Carbon or Silicon bearer and never enter the selected test plane. Any active organization member may create an environment and becomes its creator. The creator and current organization owners/admins can administer it.

| Method | Route | Result |
| --- | --- | --- |
| `GET` | `/organizations/{org_id}/testing-environments` | List active or deleted environments |
| `POST` | `/organizations/{org_id}/testing-environments` | Create and return the key |
| `GET/PATCH/DELETE` | `…/testing-environments/{id}` | Read, edit, or retire |
| `GET` | `…/{id}/key` | Audited retrieval of the current key |
| `POST` | `…/{id}/key-rotations` | Replace the key immediately |
| `POST` | `…/{id}/cleanings` | Erase test data but retain the environment |
| `POST` | `…/{id}/restorations` | Restore before `purge_after` |

`GET /api/v1/testing-environment` and `POST /api/v1/testing-environment/cleanings` are the key-authorized self routes. They are test-only: omitting the environment key is an authentication error. Cleaning retains the environment and key. Deletion disables the key and starts a 30-day recoverable window. Thirty days without accepted activity causes the same soft deletion automatically.

## Fixed OTPs without email or SMS delivery

Test data never triggers real email or SMS. Use `000000` for signup email and phone verification, Carbon login, invitation acceptance, and verified-channel step-up. Attempts, cooldowns, expiry, idempotency, and all resulting session behavior still follow the production paths, so a proof exercises more than a mocked response.

## Applications: create or import

To create a test-only Application, call ordinary `POST /api/v1/applications` with a test Carbon owner/admin bearer and the environment key. The request supplies a local handle, `org_id`, `base_url`, webhook URL, a caller-chosen `webhook_secret`, and an optional OBO catalog. IAM returns the canonical `{org_id}>{handle}` ID and a generated test-only client secret, and echoes the supplied webhook secret for v1 compatibility. IAM never generates a webhook secret. A test creation may not claim an ID already registered in production.

To mirror an existing production Application, use the test-only import route:

```
POST /api/v1/testing-environment/applications/imports
Authorization: Bearer <test Carbon access token>
X-Testing-Environment-Key: <environment key>
Idempotency-Key: <one logical operation>
Content-Type: application/json

{ "app_id": "google>drive" }
```

Import keeps the production canonical ID, base URL, webhook URL, and OBO catalog. When the organization does not exist in the environment, IAM creates it and makes the requesting test Carbon its owner. It returns a fresh test-only Application secret. The production webhook key is inherited so an existing receiver can verify deliveries, but is never exposed; the response says only `webhook_secret_inherited: true`.

The same production Application can be imported into several environments in the same testing database. Organization and Application handle lookups are environment-local, including privileged lookup helpers. An organization with the same public handle in another environment does not block import or grant access to its data. A `testing_import_organization_not_managed` conflict refers only to an organization in the selected environment whose owner/admin authority the requesting test Carbon does not hold.

Replacing the webhook URL of an imported Application that still uses that inherited key requires a caller-supplied `webhook_secret`. That exceptional `PUT …/webhook` response echoes it as `webhook_signing_secret` for v1 compatibility and includes `secret_replay_expires_at`. Later URL changes reuse it. Explicit rotation remains available through `POST …/webhook-secret-rotations`.

## Application discovery in a test

Call `GET /api/v1/application-directory/{app_id}` with the requesting test Application's Basic credential and the environment key. Both requester and target are resolved exclusively inside that environment. The response is `{app_id, base_url}`; there is no fallback to production. Discovery may cross organizations, while OBO remains same-organization.

## Test webhook envelope

A production event has top-level metadata and data. A test event is instead:

```
{
  "test": {
    "testing_key": "<environment key>",
    "metadata": {
      "spec_version": "1.0",
      "event_id": "<uuid>",
      "event_type": "organization.membership.created.v1",
      "occurred_at": "2026-09-04T08:00:00Z",
      "organization_id": "<uuid>",
      "aggregate": { "type": "membership", "id": "<uuid>", "version": 1 }
    },
    "data": {}
  }
}
```

Verify the signature over the exact outer bytes before parsing. Deduplicate on `test.metadata.event_id` and order on `test.metadata.aggregate.version`. Compare the key without timing leakage, use it to route the event to the isolated run, then redact it; it remains a live root credential.

## An application test proof

1. Create an environment from production and store UUID and key separately.

2. Run ordinary signup under the key, verify both contacts with `000000`, then log in and retain the test bearer under the environment UUID.

3. Create a test organization/Application or import the production Application; persist the returned test-only client secret during its ten-minute replay window.

4. Complete an organization-bound short-lived-token login and matching-organization introspection entirely in the test plane. Also prove an unscoped login remains valid for ordinary Application use. Assert that production credentials fail there and test credentials fail without the header.

5. Trigger a directory change; verify, route, deduplicate, and apply the wrapped webhook. Exercise OBO with the organization-bound token, and prove the unscoped token is refused.

6. Clean the environment for another run or retire it from the production control plane.

The Rust client guide (`iam docs client/testing-environments`) and the [`silicon-iam-cli` guide](https://github.com/teamofsilicons/silicon-iam/tree/main/docs/cli#end-to-end-application-proof-in-a-test-environment) show the same proof without constructing headers by hand.
