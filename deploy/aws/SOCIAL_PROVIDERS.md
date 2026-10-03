# Social provider operations

This is internal IAM deployment guidance. Applications continue using the same typed IAM popup and SLT protocol; they do not configure Google or Apple credentials.

## Configuration

Enable a provider only after the matching backend, schema, grants and frontend are deployed and their release gates pass. Provider discovery is server-controlled. The new login UI requires `login_enabled: true`; an older backend advertising signup alone cannot accidentally enable existing-account login.

| Provider | Runtime secret fields | Production callback |
| --- | --- | --- |
| Google | `IAM_GOOGLE_CLIENT_ID`, `IAM_GOOGLE_CLIENT_SECRET` | `https://backend.iam.teamofsilicons.com/api/v1/signup/social/google/callback` |
| Apple | `IAM_APPLE_CLIENT_ID`, `IAM_APPLE_CLIENT_SECRET` | `https://backend.iam.teamofsilicons.com/api/v1/signup/social/apple/callback` |

Each pair must be configured together. An absent pair keeps that provider unavailable. A partially configured pair fails configuration validation. Store values only in the protected runtime secret; never commit downloads, secret JSON, client secrets, Apple signing keys, provider authorization codes or poll proofs. Preserve all unrelated runtime fields when updating credentials.

The Google client is a Web application. Its authorized redirect URI must exactly match the callback, including scheme and path. IAM uses authorization code flow with S256 PKCE and requests email/profile. Apple uses the Services ID as client ID and a valid Apple client-secret JWT; register the exact HTTPS return URL and relevant verified domain. Apple posts the callback with `form_post`. Rotate its expiring client-secret JWT before expiry. Neither provider requires consumer applications to register callbacks.

The callback path intentionally retains `signup/social` for both signup and login. IAM stores the initiating intent and opaque state before redirecting; a browser must not change the callback or choose an account at callback time. `IAM_PUBLIC_BASE_URL` is the backend origin and `IAM_AUTH_BASE_URL` is the public IAM authentication origin. Verify these exact active values before changing provider console registration.

Apple private-relay delivery must allow IAM's actual verified mail sender. Current production sender is `iam@teamofsilicons.com`; register the appropriate sender/domain in Apple's relay configuration and preserve the verified Postmark sender configuration. Do not infer delivery success from provider login: verify relay email delivery separately.

## Email authentication and recovery

The approved email-authentication contract is in `docs/PROVIDER_EMAIL_AUTHENTICATION.md`. Google and Apple verify the email used for Carbon authentication; users do not link a provider account. IAM verifies the provider signature, issuer, audience, nonce and verified-email claim before resolving that email to its active Carbon. An existing email signs in without an additional IAM OTP. Historical provider-subject associations grant no login authority.

A new provider-verified email uses the ordinary signup session, optional phone verification and profile steps, with no email OTP. Signup persists a normal verified email contact, so email-code login remains available later. A provider login never silently creates an account. Completion must revalidate that the email still belongs to the same active Carbon and its security epoch is unchanged. Request proofs expire after ten minutes, remain private to the initiating client, and are consumed once with stable idempotent retries after uncertain responses. Social providers remain unavailable in isolated testing environments; use testing identities for app integration tests.

This product policy accepts the provider's verified-email assertion. It does not claim a fresh mailbox challenge occurred: Google documents that a verified third-party email may reflect an earlier verification. Apple's Hide My Email supplies a private-relay address; IAM authenticates that address and does not infer the undisclosed real email. See Google's [ID-token verification guidance](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token).

## Release verification

1. Pass full CI, restricted-role PostgreSQL tests, frontend checks and the exact candidate image migration rehearsal on isolated copies of both live databases.
2. Preserve encrypted, versioned, checksum-verified paired quiesced backups and runtime configuration before applying migrations and runtime grants.
3. Deploy the tested backend before the frontend and preserve the existing provider configuration. If provider configuration also needs an update, merge only the intended fields through the separate reviewed operator. Verify exact source, health and provider discovery.
4. Verify an email-created Carbon can use provider login without an extra IAM OTP, a provider-created Carbon can use ordinary email-code login, and a new provider email can continue verified signup. Synthetic callback fixtures prove UI/retry behavior, not real Google/Apple authorization.
5. Check user cancellation, expired proof, popup blocked/closed fallback, wrong OTP, idempotent retry and mail delivery. Keep an unconfigured provider visibly unavailable.

Do not create provider-subject bindings manually, substitute client-supplied email for a verified provider claim, or bypass current contact ownership checks. Keep provider availability tied to its configured backend capability and record live authorization acceptance separately from synthetic tests.
