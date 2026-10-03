# Carbon accounts and sessions

A Carbon is a human account with a required verified email. Phone is optional; if supplied it must also be verified. Signup works through the official IAM CLI and website.

## Signup

Email signup uses a 48-hour session. Each mutation takes an `Idempotency-Key`:

1. `POST /api/v1/signup/sessions` creates the session.

2. `POST …/{session_id}/email` starts verification, then `POST …/{session_id}/email/verify` checks the code.

3. Optionally call `POST …/{session_id}/phone` and `POST …/{session_id}/phone/verify`. A supplied but unverified number blocks completion. `DELETE …/{session_id}/phone` explicitly skips and clears it.

4. `POST …/{session_id}/complete` creates the profile and signs the Carbon in.

If a contact is already registered, IAM returns `already_exists: true` without sending a signup code. Offer to sign in to that account instead of asking the user to wait.

Completion accepts optional `carbon_id`, `display_name` and `timezone`. Omitted ID/name derive available defaults from the verified email; clients should supply the detected IANA timezone (otherwise UTC). Use `GET /api/v1/carbon-ids/{carbon_id}/availability` for an edited ID. Public Carbon IDs have the form `c:handle`; use the current schema's handle restrictions.

The completion response includes the profile, access/refresh tokens, actor, session ID and `onboarding.requires_organization`; it also sets `iam_session`. No second login OTP is required. Complete profile setup, then create or join the first organization before an application login. An absent phone is returned as null.

## Google and Apple

`GET /api/v1/signup/social/providers` reports which providers are enabled. Start an enabled provider with `POST /api/v1/signup/social/{provider}/start` and an idempotency key. Open its `authorization_url`; keep the returned `request_id` and secret `poll_token` in memory. Poll `POST …/{provider}/status` with those two values.

Status is `pending`, `verified`, `already_registered`, `failed` or `expired`. Verified results include a signup session and provider-verified email; continue with optional phone and profile setup without another email OTP. Already-registered accounts are offered login. Provider callbacks and token validation run on IAM's server; the CLI uses the same browser-and-poll protocol.

## Profile pictures

New profiles receive an IAM-style generated image. Upload a replacement using `PUT /api/v1/me/photo` with raw PNG, JPEG or WebP bytes, at most 512 KiB, matching `Content-Type`, `If-Match` and `Idempotency-Key`. It returns the updated profile and its immutable public `profile_photo` URL. The same self-profile upload route supports Silicon accounts.

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

These support account invitation pickers. Email invitations may also be sent before signup; they bind only after the recipient verifies the matching email. Search returns handles only — never contact details.

## How contact identities are stored

Normalised email addresses and phone numbers are authenticated-encrypted at the application boundary. Exact lookup and uniqueness use a versioned HMAC blind index, so the server can answer "is this address taken?" without holding a searchable plaintext column.

Raw contact identities, credentials, OTPs and provider records never appear in logs, traces, metrics, error details, audit diffs or webhooks.
