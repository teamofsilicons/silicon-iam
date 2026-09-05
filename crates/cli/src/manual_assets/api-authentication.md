# Authentication, SLTs and credentials

Seven transports, each with one job. Picking the wrong one is the most common integration mistake, so this page starts with the table and then explains when each applies.

| Mode | Transport | Used for |
| --- | --- | --- |
| Public | no credential | Signup, login initiation and verification, availability probes, provider callbacks |
| IAM bearer | `Authorization: Bearer …` | Carbon or Silicon API access |
| Browser session | secure `iam_session` cookie | Interactive application login and SSO navigation |
| Application | HTTP Basic, app ID and app secret | Token exchange, introspection, revocation, and OBO |
| Platform admin | IAM bearer whose Carbon holds a current grant | `/api/v1/admin/*` |
| Step-up | `X-Step-Up-Token`, *in addition to* a bearer | Ownership, credentials, SSO, deletion, privileged grants |
| WorkOS | verified `WorkOS-Signature` | The WorkOS webhook receiver |

## Credential lifetimes

These are exact. Startup rejects a deployment that overrides any of them.

| Credential or state | Lifetime |
| --- | --- |
| Signup session | 48 hours |
| Email or phone OTP | 10 minutes |
| IAM and application access token | 30 minutes |
| IAM session refresh family (Carbon or Silicon) | 900 days, absolute |
| Application OAuth refresh family | 900 days, absolute |
| Short-lived login token | 2 minutes, single use |
| Step-up token | 5 minutes, bound to one action on one resource |
| Carbon invitation | 48 hours |
| WorkOS setup link | 5 minutes |
| OBO proof | 60 seconds maximum, single use |
| One-time secret replay envelope | 10 minutes |

## Refresh tokens rotate, and reuse is fatal

**The single most important rule on this page.** Every successful refresh returns a new refresh token and consumes the old one. Presenting a consumed refresh token in a different logical operation compromises that token's *own family* and raises a security audit event.

The family boundary matters. An IAM refresh family belongs to one Carbon device session or one Silicon session; compromise invalidates that session and authority descended from it, not the principal's other device sessions. An OAuth refresh family belongs to one parent IAM session and one client Application; compromise revokes that Application family and its access tokens without revoking the parent IAM session or another Application's tokens.

This is deliberate: it is what makes a stolen refresh token detectable. It also means a client must serialise refresh per family. Two browser tabs or worker replicas starting separate refresh operations with the same token will compromise that family. An uncertain transport retry is safe only when it repeats the identical request with the original `Idempotency-Key`.

Concretely, a correct client:

- refreshes at most once at a time for each family, across every concurrent caller;

- waits for an in-flight refresh rather than starting a second;

- persists the replacement token before allowing another refresh;

- reuses the original idempotency key for an exact transport retry; and

- treats a reuse rejection — `unauthenticated` for IAM or `invalid_grant` for OAuth — as terminal for the affected family and re-authenticates.

Access and refresh tokens are opaque 256-bit random values. There is no signing-key discovery surface and nothing to parse: when an application needs to know whether a token is still good *right now*, it calls introspection (`iam docs api/applications`).

## Carbon login

Passwordless, in two calls. `POST /api/v1/login/challenges` takes exactly one of `email`, `phone_number` or `carbon_id`; `POST /api/v1/login/challenges/{session_id}/verify` exchanges the six-digit code for a credential pair.

A `carbon_id` challenge dispatches a code to **both** verified channels, and either one satisfies the verification. Say so in your interface — a user who checks only their inbox will otherwise sit waiting for an SMS that already arrived.

Email codes are generated and digest-verified by IAM. Phone codes are generated, routed and validated by Twilio Verify; IAM stores only the provider attempt identifier and its own challenge lifecycle state. Phone numbers must be supplied in E.164 form.

Login initiation answers `404` when no active Carbon owns the submitted identity. That is a documented, deliberate disclosure: an identity provider that pretends to send a code to a non-existent account teaches people to ignore a missing message.

## Silicon login

`POST /api/v1/silicon-auth/token` takes the global Silicon ID as the username and the `stk-…` token as the password, and returns the same credential pair a Carbon gets. Silicon tokens are 128 bits, formatted as `stk-` plus 32 lowercase hexadecimal characters, and are stored only as a keyed digest — a lost token can be replaced, never recovered.

## Step-up

Some actions need proof that the person at the keyboard is still the account holder. Step-up is a second factor over an already-authenticated session, and the resulting token is bound to **one action on one resource**: a token minted for `application.client_secret.rotate` or `application.webhook_secret.rotate` on application A is rejected for application B.

1. `POST /api/v1/step-up/challenges` with the action, the resource ID and a channel.

2. `POST /api/v1/step-up/challenges/{session_id}/verify` with the code.

3. Send the resulting `sup_…` value as `X-Step-Up-Token` alongside your bearer, within five minutes.

Actions that require it:

- `account.session_revoke`, `account.sessions_revoke_all`

- `organization.transfer_ownership`, `organization.authorization_change`

- `organization.sso_change`, `organization.silicon_webhook.redirect`

- `application.client_secret.rotate`, `application.webhook_secret.rotate`, `silicon.rotate_token`

- `platform_admin.application_review`, `platform_admin.sso_entitlement`

Do not cache a step-up token. It buys at most one prompt and leaves a live credential in memory between unrelated operations.

## Verification-code protection

Every IAM-managed OTP is six digits and lives ten minutes. Signup, Carbon login, invitation-join and verified-channel step-up challenges each allow **ten failed verifications**; the tenth failure starts a **sixty-second cooldown**, after which the still-unexpired code gets a fresh ten-attempt window.

The partial failure count and any active cooldown **carry into a replacement code**. Resending cannot reset either, and a cooldown never extends the original ten-minute expiry. Interfaces should say so, or users will resend repeatedly in the belief that it helps.

## The browser session

A successful Carbon login also sets `iam_session`: host-only, `Secure`, `HttpOnly`, `SameSite=Lax`, and signed. It exists for the two flows that are navigations rather than API calls — application login and SSO — and it is bound to the same refresh family, so revoking the session revokes the cookie.

It is what lets `GET /api/v1/login` recognise somebody who is already signed in and go straight to minting their short-lived token instead of asking them to log in again. Application login may supply `org_id` to require an active membership and bind the resulting token family to that organization. Omitting it keeps a Carbon login unscoped; OBO issuance requires the organization-bound form.

**An application never sees a credential.** Signing in to an application never asks anyone for a password, a verification code, or any other authentication secret on that application's behalf. The only thing an application receives is a short-lived token.
