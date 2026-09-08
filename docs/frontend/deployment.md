# Frontend deployment history

## Organization-consent release — 2026-09-08

The frontend source is now tracked in the IAM repository's `frontend/` directory;
its documentation is in `docs/frontend/`. The Vercel project and domains below
remain unchanged. Deploy the matching API and migrations 0072/0073 first, then
build and promote this frontend. GET login now opens verified-app confirmation
and an explicit organization picker; it no longer automatically mints an SLT.
The [consent guide](../ORGANIZATION_CONSENT.md) records the new manual checks.

The record below describes the earlier deployment; it is not a claim that the
current source revision has been promoted. Check the Vercel deployment and live
backend version when auditing a release.

## Deployment status — 2026-09-05

## Live

- Vercel project: `silicon-iam-frontend`, scope `saketdev12-5675s-projects`.
- Deployment: `dpl_F4vEj2yjHJY1J23uQFtGaEcBjURs`, status **Ready**, promoted after the backend app-handle update.
- Node 24 function in `iad1`, including the SolidJS production assets and same-origin session gateway.
- Production upstream/origins/cookie domain configured. A fresh 32-byte cookie key is stored as a Sensitive Vercel variable, not in source or a local file.
- Public console: https://iam.teamofsilicons.com
- Public authentication: https://auth.iam.teamofsilicons.com
- Both custom domains are attached and verified, with valid HTTPS and the prepared deployment promoted. Existing DNS required no changes. Public activation was explicitly approved by the user.
- Vercel deployment protection remains enabled for generated deployment URLs. Those hostnames also deliberately fail the gateway's exact-host check; the custom domains are public, with IAM authentication protecting private data.
- No frontend GitHub repository was created or pushed. Backend release `1db1cc1e39867fb03e5021fa3a15c5e77885008b` and forward migration `0069_short_application_handles.sql` relax local app handles to 1–80 characters in both production and testing databases. Organization handles and character restrictions remain unchanged. API and worker use the new image; SSO environment settings were not changed.

The backend source was committed locally; this deployment did not push GitHub source or publish crates. Existing clients send string app IDs and do not require a new crate release for the relaxed backend rule. The OpenAPI, generated client documentation, CLI bundled contracts, and frontend snapshot were updated together. Further functional tests were cancelled at the user's request; deployment checks verified migration checksums, unchanged data counts, healthy services and the released version.

## Remaining SSO action

Resolve the WorkOS prerequisite below before claiming organization SSO works. The public frontend launch does not resolve or change that pre-existing provider configuration.

## WorkOS prerequisite

The existing backend uses `IAM_PUBLIC_BASE_URL=https://backend.iam.teamofsilicons.com`; its auth origin already correctly names `auth.iam.teamofsilicons.com`.

Read-only WorkOS checks found an empty redirect-URI allowlist. A selector-free authorization check rejected `https://auth.iam.teamofsilicons.com/api/v1/sso/callback` and redirected to a staging AuthKit `redirect-uri-invalid` page. No identity provider or login was invoked. The configured client is therefore not production-verified.

Choose the intended WorkOS environment/client and allowlist that exact callback there. Then update the backend's `IAM_PUBLIC_BASE_URL` in both `deploy/aws/production.yaml` and the running instance's `/etc/silicon-iam/api.env`. Preserve all other settings and file mode `0600`. A reviewed CloudFormation update persists replacement-instance configuration but does not modify the current instance. Restart `silicon-iam-api.service` (not just the Docker container), then check readiness and ALB health. This single-instance service may have a brief interruption. Worker restart is unnecessary.

## Verification performed

- `npm run build:vercel` passed, including TypeScript checking.
- The exact packaged function served local HTML, public config, and signed-out session state with security headers.
- An actual browser login from `/join?org_id=frontend-qa` retained the join destination and prefilled organization handle against the isolated local IAM instance.
- Vercel reports the uploaded deployment Ready. Both custom domains return valid HTTPS, correct Production configuration, and HTML with security headers when requested with browser `Accept: text/html`.
- Both domains return `403 frontend_csrf` for session requests missing the frontend header, signed-out session state with the header, `401` for protected profile reads, and `404` for server-only app-token exchange routes. Responses are no-store with nosniff, no-referrer, frame denial, and HTTPS transport protection.
- Application handoff preserves the supplied app/organization context while redirecting signed-out visitors to the auth page. The public version endpoint successfully reaches the existing production backend through the gateway.
- No real production login, account mutation, or actual WorkOS provider-login test was performed. The full signed-in browser flows were tested only against the isolated local instance.

Build/runtime references: [Vercel primitives](https://vercel.com/docs/build-output-api/primitives), [WorkOS redirect URIs](https://workos.com/docs/reference/authkit/redirect-uri).
