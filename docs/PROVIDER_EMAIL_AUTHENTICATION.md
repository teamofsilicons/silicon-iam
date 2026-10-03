# Provider email authentication

Status: approved product contract, 2026-10-03. Implementation and release verification are pending. This supersedes the provider-subject account-linking behavior shipped in IAM 5.1.0.

Google and Apple are alternate ways to verify the email used to authenticate a Carbon. An IAM account has no required Google or Apple link. The Carbon can switch between a provider and an email one-time code without account conversion or a separate linking step.

## User flows

| Starting point | Verified result | Outcome |
| --- | --- | --- |
| Continue with Google or Apple | The verified email belongs to an active Carbon | Sign in as that Carbon, without sending an IAM email code or asking to link accounts. |
| Continue with Google or Apple | No Carbon owns the verified email | Continue explicit Carbon signup with email already verified. Keep optional phone verification, profile setup, and organization onboarding. |
| Email sign-in | The email belongs to a Carbon originally created through a provider | Send an ordinary IAM email code. A valid code signs into the same Carbon. |
| Provider signup or login | The provider does not supply an accepted verified email | Fail without creating an account or authenticating a Carbon. |

Both new website and CLI flows use the same behavior. They must not display account-linking language or require a fresh direct IAM OTP after accepting a provider's verified email. Signup remains explicit: a new verified email does not silently create an account.

## Identity and authorization rules

- Verify the provider signature, issuer, audience, expiry, nonce, authorization state, applicable PKCE proof, and verified-email claim before accepting the email. A client-supplied email or display name is never authentication evidence.
- Resolve the accepted email with IAM's normal email canonicalization and current contact ownership. Do not invent aliases, collapse distinct emails, or derive identity from provider display names.
- Provider subject identifiers may validate the provider response, but no saved provider-subject association grants login authority, reserves a Carbon identity, or prevents signup under a different verified email. Historical association rows must not remain an alternate authentication path.
- Resolve the verified email again at completion. Require the same active Carbon, verified contact record, and unchanged security epoch captured at verification. Email removal, reassignment, removal and re-addition, suspension, deletion, or security reset invalidates a pending login proof rather than redirecting it to another Carbon.
- Keep proof confidentiality, expiry, one-time consumption, idempotent retry, direct Carbon session boundaries, and testing-environment isolation. The provider method does not bypass organization membership checks, application SLT completion, critical IAM consent, or OBO consent.
- A provider-created Carbon stores the email as an ordinary verified IAM contact, so ordinary email OTP login works immediately.
- Apple's private-relay address is the email Apple verifies when the user chooses Hide My Email. It matches only that address in IAM; it does not prove the undisclosed underlying email.
- Existing published clients and contracts must remain usable. Legacy link surfaces, if retained for compatibility, cannot create or rely on subject bindings or turn a different authenticated Carbon into the provider-email owner. New flows never emit a linking requirement. Expired or invalidated in-flight requests can restart clearly.

## Release acceptance

Prove email-created account to Google/Apple login without a second OTP; provider-created account to ordinary email-code login; new provider email to verified signup; same email across providers to the same Carbon; changed provider email to the current email owner; and Apple relay-email separation.

Reject unverified provider claims, wrong issuer/audience/nonce/state, wrong poll capabilities, stale proofs, completed proofs replayed with another operation key, suspended or deleted accounts, changed security epochs, and email ownership changes between verification and completion. Preserve stable retries with the original operation key. Cover concurrent signup and contact changes so authentication cannot select an ambiguous owner.

Record backend/database protocol tests, frontend and CLI flow tests, immutable release artifacts, and production source/configuration checks. Real provider account authorization and Apple relay-mail delivery remain separate acceptance evidence from mocked provider tests or an accepted authorization page.

Provider setup and these internal authentication rules stay in IAM documentation. Consuming applications continue integrating the typed IAM popup and SLT contract; they do not configure Google or Apple.
