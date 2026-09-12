# Manual QA

## Batch login — 2026-09-09

Verified against a disposable PostgreSQL 16 container on loopback port 65130,
restricted API runtime role on port 58141, and the built frontend on port 58142.
Both ordinary and testing databases received the existing migrations and grants.
Only synthetic identities, organizations and apps were used.

- One browser OTP login preserved two app IDs and the callback state.
- Consent offered separate organization checkboxes per app and required a
  selection for every app before enabling approval.
- Selecting Work for one app and Personal for the other returned two independent
  SLTs in the agreed JSON `#slts=` fragment; `state` remained in the query.
- Reloading consent showed the separate previous grants as already authorized.
- Without a callback, IAM displayed individually labelled SLTs and status links.
- Visual inspection at the in-app browser panel width confirmed horizontal
  checkbox/label alignment after correcting the inherited column layout.
- A real 100-app atomic issuance returned 100 distinct SLTs in approximately
  1.25 seconds on this local fixture; this is not a production performance guarantee.
- The live client regression passed in ordinary and isolated testing planes:
  failed batches rolled back all new grants, same-key retries returned identical
  tokens/deadlines, cross-app exchange failed without consuming the token, each
  own-app exchange succeeded once, and app bearers could not enlarge consent.
- Existing single-app live client protocol passed after the shared-code refactor.
- CLI `batch-login` with two app IDs and explicit organization consent returned
  two independent SLTs in JSON; offline batch help passed.
- Five frontend regression tests covered bounds, invalid URLs, callback encoding,
  redirect preservation and CSRF rejection; TypeScript and production build passed.


## Organization consent — 2026-09-08

See the [organization-consent verification record](../ORGANIZATION_CONSENT.md#local-manual-verification--2026-09-08)
for the current local browser, CLI and testing-plane results. The older flow below
predates explicit organization selection and is retained as historical evidence.

## Manual QA — 2026-09-05

No automated test suite was written. These checks used the actual frontend in the browser and a real, isolated IAM API. The browser was exercised at its normal narrow panel width and a 1280×850 desktop viewport. Final small-screen checks use 390×844.

## Isolation

- Frontend: `http://127.0.0.1:4310`
- API: `http://127.0.0.1:4320`
- Dedicated PostgreSQL container: `silicon-iam-frontend-qa-db-20260905`, loopback port `55440`, database `silicon_iam_frontend_qa`.
- Official IAM migrations and runtime grants applied; API uses the restricted runtime role, not the migration owner.
- Disposable identity `frontend-qa`, organization `frontend-qa`, application `frontend-qa>station`, Silicon `qa-agent:frontend-qa`.
- No production identity, application, database, DNS, provider setting, deployment or Git remote was changed. No webhook worker was started, so the placeholder receiver was never sent live deliveries.

## Browser checks completed

| Flow | Observed result |
|---|---|
| Signup email dispatch | Local provider returned a random code and the verification form appeared. |
| Incorrect signup OTP | Inline error included the field reason and IAM request ID; the form remained usable. |
| Email + phone verification | Both contacts verified separately; profile creation was available only afterward. |
| Carbon creation | Account created; a separate, fresh sign-in challenge was required. |
| Email/Carbon-ID login | Both entry points established the gateway session and opened the console. |
| Session bootstrap/navigation | Console reads succeeded after navigation; credentials were not exposed in normal API responses. |
| Organization creation | New organization appeared in the selector and overview immediately. |
| Application creation | Organization, local handle, base URL, webhook URL and user-managed secret were explicit. |
| Trailing-slash base URL | Rejected locally before submission, with specific corrective guidance. |
| Created application | Canonical `frontend-qa>station` loaded with version 1; one-time credentials appeared masked in a dismissible dialog. |
| OBO endpoint editing | Character-by-character input retained focus; an endpoint with typed metadata saved and app version advanced to 2. |
| Webhook approval | Confirmation → local step-up code → approval succeeded; pending URL became active and version advanced to 3. |
| SLT, no callback | IAM's official single-use token page rendered through the gateway with its static assets. |
| SLT with callback | A disposable loopback receiver displayed “SLT callback received”; token contents were neither stored nor displayed by that receiver. |
| Unknown application | Failed navigation returned to the branded auth screen with an error and preserved context; the IAM session stayed usable. |
| Tag create/edit | New tag appeared without a full navigation; rename advanced version from 1 to 2 and refreshed the detail dialog. |
| Silicon creation | Local handle and required job role created a Silicon; generated STK appeared only in the masked credential dialog. |
| Profile patch | Description updated and was visible on the account page. |
| Current-session logout | Returned to sign-in and removed console access. |
| Sessions | Correct current-session label and real timestamps; fresh sessions are ineligible for remote/all-session revocation. |
| Testing service unavailable | Local API lacks a separate testing database; its 503 and Retry-After were surfaced inline without breaking the console. |
| WebMCP | `iam_current_view` returned only section, organization and environment; navigation/staging tool schemas were present. |
| Responsive layout | Desktop and 390×844 mobile views rendered; mobile navigation worked and document width matched the 390-pixel viewport. |
| Built Node frontend | Auth page rendered under the production CSP with no new console errors; login and session bootstrap succeeded on port 4312. |

## Build and gateway checks

`npm run check` and `npm run build` passed. Production bundle includes browser assets and both Worker-style and Node gateway entries. `npm audit --omit=dev` reported no vulnerabilities at the time of this check.

The built Node server was run separately on port 4312. Manual HTTP checks observed:

- SPA deep link and official SLT stylesheet: 200.
- JSON API without frontend header: 403.
- Protected API with frontend header but no session: 401.
- Cross-origin mutation: 403.
- Browser request to application-server token exchange: 404.
- Untrusted Host: 403.
- HTML response carries no-store, CSP, no-referrer, nosniff and frame denial.

## Not claimed as end-to-end verified

This is **not** exhaustive command/API parity or production certification. WorkOS SSO completion requires actual WorkOS entitlement, connection, callback allowlisting and hosted auth-origin configuration. Real email invitation delivery, the entire delegated-capability/quorum matrix, 12-hour session aging, secret-rotation recovery under packet loss, very large cursor collections, and testing-environment lifecycle operations were not fully exercised in this local run. They are implemented against backend contracts and need the corresponding configured fixtures before release.

OBO proof exchange/verification and application SLT exchange belong to application servers and the IAM client, not this human browser console. The browser run verifies endpoint registration and handoff, not an external application’s authorization implementation.

The local QA API/database and built preview (`http://127.0.0.1:4312`) are left available for continued preview work. The temporary callback receiver on 4321 was stopped after verification. The database container is separate from existing Briefcase containers. Do not use broad Docker cleanup commands; stopping this named container is recoverable, while deleting its storage is not.

## Declared scopes and bundles — 2026-09-12

The production frontend build and seven Node regression tests passed. The
OpenAPI form snapshot was regenerated after the scope, bundle, and application
testing contracts changed.

A loopback, read-only UI fixture verified the browser presentation independently
of backend authorization: app confirmation led to a permission screen displaying
non-critical IAM identity, critical IAM directory access, and a critical external
endpoint with its provider. Organization selection appeared only after that
screen, and authorization stayed disabled without a selection. A bundle showed
one public bundle identity, a deduplicated permission list, and one organization
picker. A backend `consent_required: false` response led directly from app
confirmation to organization selection. No production identity or grant was used.

The standalone documentation site built 36 content pages plus a 404 page. Its
link/asset checker passed, and the generated home page was visually inspected
in the in-app browser. Canonical hosting uses `docs.iam.teamofsilicons.com`.
These checks do not claim a deployment, DNS change, live email delivery, or an
end-to-end external application integration.
