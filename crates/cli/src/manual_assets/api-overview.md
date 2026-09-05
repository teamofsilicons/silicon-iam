# API overview

Silicon IAM is the identity and access layer for every Silicon application. It authenticates people and machines, holds the authoritative directory for each organization, and tells registered applications the moment anything about that directory changes.

Membership here is the real thing. Remove somebody from an organization in Silicon IAM and they lose access in every application at once — no application keeps its own copy of who belongs where.

## Three kinds of principal

| Principal | What it is | Public identifier |
| --- | --- | --- |
| **Carbon** | A human account. | `carbon_id` — 3–30 characters of `a–z`, `1–9`, `_` and `-`. |
| **Silicon** | A machine identity, always scoped to one organization. | `{handle}:{org_id}` — always contains a colon. |
| **Application** | A registered confidential OAuth client and delegation actor. | `app_id`. |

A Silicon has no organization-local form. The handle you submit at creation is input only; `head_of_growth` registered in `tos` is addressable forever as `head_of_growth:tos` and never as anything else. That single colon is also how a client tells the two principal kinds apart, since a Carbon ID cannot contain one.

## Identifiers, and what they are not

Persistent records use UUIDv7 primary keys. Public handles are immutable normalised labels — they are never foreign keys, and they are never reused after deletion.

Organization-scoped resources are addressed by `membership_id` rather than by a public handle. This is deliberate: it keeps tenant-internal references out of URLs that a member of another organization might see, and cross-tenant reads answer `404 not_found` rather than disclosing that a resource exists.

A typed `principal_id` prevents collisions between a Carbon and a Silicon whose public labels happen to look alike. Never key your own storage on the public handle alone.

## How to read this documentation

[openapi.yaml](/openapi.yaml) is normative. Where these pages and the specification disagree, the specification wins and the discrepancy is a bug worth reporting. What you get here is the reasoning: why an endpoint behaves the way it does, which failure modes matter, and what to do about each of them.

Read Authentication (`iam docs api/authentication`) and Request conventions (`iam docs api/conventions`) first. Between them they cover the rules that apply to every call in the contract, and almost every integration problem traces back to one of the two.

If you are integrating an Application in Rust, the official client (`iam docs client/`) provides typed API calls and models, explicit version negotiation, credential transports, and webhook verification. Your application still owns credential persistence, refresh coordination, OBO request signing, and retry decisions. These pages explain the contract behind those calls.

## Environments

| Surface | URL |
| --- | --- |
| API | `https://backend.iam.teamofsilicons.com` |
| Sign-in and signup | `https://auth.iam.teamofsilicons.com` |
| Management console | `https://iam.teamofsilicons.com` |
| Platform administration | `https://backend.iam.teamofsilicons.com/admin` |

Timestamps are UTC RFC 3339. Request and response bodies are JSON unless an endpoint says otherwise; the OAuth token, introspection and revocation endpoints take `application/x-www-form-urlencoded`, as the OAuth specifications require.
