# Carbon accounts and sessions

A Carbon is a human account. Creating one requires a verified email address and a verified phone number, both bound to a single 48-hour signup session.

## Signup

Six calls, in order. Every one takes an `Idempotency-Key`.

|  | Call | Returns |
| --- | --- | --- |
| POST | `/api/v1/signup/sessions` | A 48-hour session |
| POST | `/api/v1/signup/sessions/{session_id}/email` | `already_exists`, and a code if false |
| POST | `/api/v1/signup/sessions/{session_id}/email/verify` | `verified: true` |
| POST | `/api/v1/signup/sessions/{session_id}/phone` | `already_exists`, and a code if false |
| POST | `/api/v1/signup/sessions/{session_id}/phone/verify` | `verified: true` |
| POST | `/api/v1/signup/sessions/{session_id}/complete` | The new `CarbonSelf` |

**The `already_exists` short-circuit.** When a contact already belongs to an account, the server returns `already_exists: true` and deliberately sends nothing. Rendering "check your inbox" here strands the user forever — route them to sign-in instead.

Completion requires both channels verified *in that session*, and neither may belong to another account. Availability of a candidate handle is a separate public probe: `GET /api/v1/carbon-ids/{carbon_id}/availability`.

New Carbon IDs accept lowercase `a–z`, the digits `1–9`, `_` and `-`, and are 3–30 characters. Note the absence of `0`: immutable legacy IDs containing it remain addressable for login and lookup, but cannot be newly registered. Rejecting it client-side is far kinder than a `422` after somebody has settled on a name.

Completion does not sign the new Carbon in. It returns the profile; the client then runs the ordinary login flow.

## Login

Two calls, covered in Authentication (`iam docs api/authentication`). The verification response is the credential pair plus the actor and session ID, and it also sets the `iam_session` cookie.

## The account surface

|  | Endpoint | Notes |
| --- | --- | --- |
| GET | `/api/v1/me` | The authenticated Carbon. The `ETag` is the precondition for the patch. |
| PATCH | `/api/v1/me` | `application/merge-patch+json`. Requires `If-Match`. |
| GET | `/api/v1/me/sessions` | Active refresh families |
| DELETE | `/api/v1/me/sessions/{session_id}` | Requires step-up bound to that session |
| GET | `/api/v1/me/login-history` | Retained one year |

The profile patch is a **JSON Merge Patch**. Omitting a key leaves it alone; sending `null` clears it. That distinction is load-bearing — a client that serialises an absent optional as `null` will delete the field.

## Session revocation and the twelve-hour rule

**Both the target and the calling session must be at least 12 hours old.** The operation fails atomically if any target is younger.

This exists to stop somebody who has just taken over an account from immediately locking out the real owner. It has a real consequence for interfaces: a freshly signed-in user *cannot* revoke anything, and the screen should say so up front rather than letting them discover it through a `403`.

Revocation also needs a verified-channel step-up token carrying an `account.session_revoke` assertion bound to the specific session — one prompt per session, by design.

## Logout

`POST /api/v1/logout` revokes the current session by default and propagates to every configured application. `mode: "all_sessions"` extends that to every device, and then the twelve-hour rule and a `account.sessions_revoke_all` step-up assertion both apply.

Cookie-authenticated logout additionally requires `X-CSRF-Token` matching the token bound into the signed session cookie. Bearer-authenticated logout does not.

## Finding other Carbons

|  | Endpoint | Notes |
| --- | --- | --- |
| GET | `/api/v1/carbons/search` | Fuzzy Carbon-ID suggestions, 0–10 results |
| POST | `/api/v1/carbons/resolve/email` | Exact match on a verified address |
| POST | `/api/v1/carbons/resolve/phone` | Exact match on a verified number |

These exist for invitation pickers: you cannot invite a Carbon that does not exist, so resolving first turns a guaranteed `404` into a working autocomplete. Search returns handles only — never contact details.

## How contact identities are stored

Normalised email addresses and phone numbers are authenticated-encrypted at the application boundary. Exact lookup and uniqueness use a versioned HMAC blind index, so the server can answer "is this address taken?" without holding a searchable plaintext column.

Raw contact identities, credentials, OTPs and provider records never appear in logs, traces, metrics, error details, audit diffs or webhooks.
