# API overview

Silicon IAM is the identity and access layer for every Silicon application. It authenticates people and machines, holds the authoritative directory for each organization, and tells registered applications about changes they are permitted and subscribed to receive.

IAM is authoritative for membership. Removing someone invalidates their organization authority in subsequent IAM checks. Applications may cache scope-filtered projections, but must enforce revocations and verify current access for protected actions.

## Three kinds of principal

| Principal | What it is | Public identifier |
| --- | --- | --- |
| **Carbon** | A human account. | `carbon_id` — 3–30 characters of `a–z`, `1–9`, `_` and `-`. |
| **Silicon** | A machine identity, always scoped to one organization. | `{handle}:{org_id}` — always contains a colon. |
| **Application** | A registered confidential OAuth client and delegation actor. | `app_id`. |

A Silicon has no organization-local form. The handle you submit at creation is input only; `head_of_growth` registered in `tos` is addressable forever as `head_of_growth:tos` and never as anything else. That single colon is also how a client tells the two principal kinds apart, since a Carbon ID cannot contain one.

## Identifiers, and what they are not

Carbon, Silicon, and Application IDs are immutable canonical identity keys, including in storage and foreign keys. They are never reused after deletion. Other resources retain UUID keys.

A public `membership_id` is `carbon_id[org_id]` or `silicon_id[org_id]`, using the full Silicon ID: for example `saket[tos]` and `helper:tos[tos]`. URL-encode the brackets in path segments. These stable identifiers also appear in relationship fields, trust selectors and webhook membership references. UUID membership keys remain private to storage. Identifier resolution never grants access; tenant, consent and resource authorization still apply.

Use the permanent `carbon_id`, full `silicon_id`, or `app_id` as the identity key. Generic actor objects expose the same identifier as `public_id`. There is no separate principal UUID.

## How to read this documentation

[openapi.yaml](/openapi.yaml) is normative. Where these pages and the specification disagree, the specification wins and the discrepancy is a bug worth reporting. What you get here is the reasoning: why an endpoint behaves the way it does, which failure modes matter, and what to do about each of them.

Read Authentication (`iam docs api/authentication`) and Request conventions (`iam docs api/conventions`) first. Between them they cover the rules that apply to every call in the contract, and almost every integration problem traces back to one of the two.

If you are integrating an Application in Rust, the official client (`iam docs client`) provides typed API calls and models, explicit version negotiation, credential transports, and webhook verification. Your application still owns credential persistence, refresh coordination, OBO request signing, and retry decisions. These pages explain the contract behind those calls.

## Environments

| Surface | URL |
| --- | --- |
| Documentation | `https://docs.iam.teamofsilicons.com` |
| API | `https://backend.iam.teamofsilicons.com` |
| Sign-in and signup | `https://auth.iam.teamofsilicons.com` |
| Management console | `https://iam.teamofsilicons.com` |
| Platform administration | `https://backend.iam.teamofsilicons.com/admin` |

Timestamps are UTC RFC 3339. Request and response bodies are JSON unless an endpoint says otherwise; the OAuth token, introspection and revocation endpoints take `application/x-www-form-urlencoded`, as the OAuth specifications require.

## Application authority in v1

Applications declare `app_scope` separately from their `webhook_scope` subscriptions. Critical permissions go through IAM or external-provider review. Users approve effective permissions and choose organizations before IAM hands the application a short-lived token. Apps never receive IAM credentials or verification codes.

External OBO can connect applications owned by different organizations while preserving the user's selected membership context. Bundles offer one displayed login identity for same-organization applications; tokens remain individually bound. Application testing environments reproduce the same contract with isolated credentials, recursively imported dependencies, fixed test OTPs, and configurable inactivity retention.

`GET /api/v1/contracts` describes the first official `v1` contract and the current/deprecated/sunset lifecycle. Read Request conventions (`iam docs api/conventions`) for negotiation and retirement rules.
