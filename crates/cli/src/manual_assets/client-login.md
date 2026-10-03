# Application login using short-lived tokens

A login produces one short-lived token. The application sends somebody to IAM, gets that token back, and trades it — together with its own secret — for a session. The IAM SLT exchange has no PKCE verifier; IAM asks the user to choose an organization and reviews critical IAM permissions when needed. Your application must still bind the callback to the browser's initiated login attempt; this protocol is not a substitute for callback CSRF protection.

Use the globally unique bare Application ID everywhere, for example `checkout`. Its owning organization is a separate property.

**You never receive anyone's credentials.** Nothing in this flow hands your application a password, a verification code, or any other authentication secret. The only thing you ever receive is the short-lived token.

## Step one — send them to IAM

For an external-app walkthrough using example ID `briefcase` and callback `https://briefcase.teamofsilicons.com/auth/callback`, see the Briefcase login example (`iam docs api/applications`). Use your actual registered ID and implemented callback route; keep the app secret server-side.

```
let mut login = url::Url::parse(auth_base_url)?.join("/login")?;
login.query_pairs_mut()
    .append_pair("app_id", app_id)
    .append_pair("redirect_uri", callback_with_state)
    .append_pair("identity_kind", "carbon") // or silicon, from the chosen app button
    .append_pair("display", "popup"); // optional compact presentation
// Redirect the user agent to `login`; query values are percent-encoded.
```

Naming `app_id` is what makes this a login on your behalf; without one it is an ordinary Silicon IAM login and no token is minted. `redirect_uri` is optional and decides delivery only — give one and the token comes back on it, omit it and IAM shows the token to the person instead. Applications must not supply `org_id`. IAM validates the app and the selected account/organization. It shows the IAM consent screen only when critical IAM permissions require it. OBO endpoints require separate on-demand consent. Only the selected active memberships are disclosed, never future memberships automatically.

The URI does not have to be registered anywhere, so an application may send people to different callbacks on different days without changing its configuration.

## Carbon and Silicon buttons, with popup sign-in

Offer **Continue as Carbon** and **Continue as Silicon** in your application. Pass `identity_kind=carbon` or `identity_kind=silicon` on the IAM login URL. IAM shows only that kind of configured account and preserves it while adding another account. The user clicks an organization to continue; critical IAM permissions still receive their own review. Each session is bound to exactly one account and organization.

Open the popup directly from the button click so the browser can permit it. Use `display=popup` for IAM's compact layout. Keep a full-page fallback when popups are blocked. Popup presentation does not change the SLT or its callback format.

1. Your backend creates a short-lived, unpredictable, single-use login state and stores the chosen identity kind with it. Put the state in your own callback URL's query, then percent-encode that complete URL as `redirect_uri`. IAM preserves callback query parameters.

2. The callback backend validates state, exchanges the SLT with the app secret, and verifies the authenticated principal has the stored kind. If the exchange omits `actor`, use authenticated token introspection and its `actor_type`. Reject mismatches and missing or inactive identity proof before creating an app session. Complete the attempt once; retain the original mutation key and protected callback state while an exchange outcome is uncertain, so an identical retry cannot exchange the SLT twice.

3. Set the application's secure session before serving an app-origin completion page. That page can notify its opener using `postMessage` with the exact app origin, a one-use attempt identifier and a completion status, then close itself. This server-callback pattern keeps the SLT out of window messages. Never post an access token, refresh token, direct IAM account credential or app secret.

4. The opener must check `event.origin`, `event.source === popup`, the expected message shape and attempt identifier, then reload authenticated app state. Treat a popup close or timeout as cancellation, not successful login.

A single-page application may instead receive the one-use SLT in its own callback page and hand it, the bound state and attempt identifier to the exact app-origin opener. The opener must verify the origin, popup window, message schema, state and attempt identifier, clear the callback URL, then submit the SLT to its authenticated same-origin backend for exchange. The message itself is not successful login: wait for the backend to verify the requested principal kind and establish the application session. Never send long-lived credentials or access/refresh tokens through this channel, and do not exchange with an app secret in JavaScript.

Store an optional post-login return URL with the same backend login attempt. After the app session is established, navigate to that approved URL; if absent, render an app completion page with a return link. Accept an allowlisted destination or a validated same-origin application path; reject protocol-relative URLs, credentials and unapproved origins. Keep callback destinations and return paths under application control. A browser-selected kind or a popup message alone is not identity proof.

Direct IAM clients can additionally send `X-IAM-Identity-Kind: carbon` or `silicon` when listing organizations and issuing single, batch or bundle SLTs. The production backend enforces the selected kind against the authenticated principal before issuance or replay, and includes it in the mutation fingerprint. Invalid or duplicate values return `400`; a mismatched kind returns `403 identity_kind_mismatch`. Requests without this optional header retain their established behavior. Applications must still verify the exchanged principal against their server-stored login attempt.

## Step two — take the token off the callback

The user agent arrives at your callback with `?slt=…`. That string is the whole hand-off. It lives two minutes and is good for exactly one exchange.

## Step three — exchange it

```
use silicon_iam_client::{Client, Credential, Mutation};

let application = Client::new(base_url)?
    .with_credential(Credential::application(app_id, app_secret));

let tokens = application
    .oauth()
    .login(app_id, &slt, &Mutation::new())
    .await?;
```

You get an access token good for 30 minutes and a refresh token that rotates on every use. Renewing an existing session is a separate operation:

```
let renewed = application
    .oauth()
    .refresh(app_id, &previous.refresh_token, &Mutation::new())
    .await?;
```

`OAuth::login` accepts only an SLT. It has no OTP, email, phone, Carbon ID, or refresh-token argument, so an Application cannot accidentally collect IAM authentication credentials or treat a continuing session as a new login.

## When there is nobody to redirect

A Silicon has no browser, and a Carbon that already holds a session should not have to start another one. Either can ask for the token directly on the session it already has:

```
let choices = signed_in.auth().login_organizations("your-app").await?;
// Display choices.scopes, obtain permission consent, then select exactly one organization.
let approved = choices.scopes.iter().map(|scope| scope.scope.clone()).collect::<Vec<_>>();
let slt = signed_in.auth().short_lived_token_for_organizations(
    "your-app", &["acme".to_owned()], choices.scope_version,
    &approved, &Mutation::new(),
).await?;
```

Only direct IAM credentials can submit this choice. Submit exactly one organization. Each new token family remains bound to that membership; later logins never expand an earlier token. Apps get no list of unselected organizations. OBO separately selects an account and organization per provider in its approved graph.

## Scope

`app_scope` declares IAM permissions and exact external OBO endpoint permissions. An ordinary login token carries only the application's effective, user-approved IAM scopes within the user's selected organization. External endpoints require separate on-demand OBO consent and dedicated tokens. `webhook_scope` independently chooses event categories. The defaults are `self.identity.read` and `self.profile.read`; email, phone, directory data, and external endpoints require explicit declarations. New critical scopes require review before they become usable. An upgrade awaiting review keeps the prior approved version working. Every direct login submission supplies the reviewed `scope_version` and complete `approved_scopes` list. Stale views fail; reload and show the new permissions before retrying.

## Batch login

Use `/login?app_ids=briefcase,dm` to authenticate once for 1–100 distinct applications. IAM collects exactly one organization for each app, checks critical IAM consent, and creates all SLTs atomically. A callback receives `#slts=` with a URL-encoded JSON array of objects containing `app_id`, `slt`, `expires_in`, `expires_at` and `request_id`. Read it in browser JavaScript, verify your login state and expected app IDs, clear the fragment, then send each SLT to its own app backend for the existing secret-authenticated exchange.

The direct-IAM endpoints are `GET /api/v1/app-auth/batch/organizations?app_ids=...` and `POST /api/v1/app-auth/batch/short-lived-tokens`. The POST takes `{"applications":[{"app_id":"briefcase","org_ids":["tos"],"scope_version":1,"approved_scopes":["self.identity.read","self.profile.read"]}]}` and an idempotency key, returning `{"items":[...]}`. The Rust client exposes `auth().batch_login_organizations(...)` and `auth().batch_short_lived_tokens(...)`. The CLI exposes `iam batch-login --app-id` with repeatable app IDs. See `iam docs batch-login` for the complete guide. Use the matching API, CLI, and frontend contract together.

## Bundle login

A configured bundle presents one application identity while preserving a separate credential and token exchange for every member. Start with `/login?bundle_id=acme%3Eworkspace`. The callback uses the same `#slts=` result shape as batch login. Each member app receives only its own SLT and exchanges it with its own secret. Bundle membership is confined to one organization; existing member apps remain independently usable.

For direct IAM clients, call `auth().bundle_login_organizations(bundle_id)`, review the bundle and current member scope versions, then call `auth().bundle_short_lived_tokens(bundle_id, &request, &mutation)`. The submitted member list must match the current complete bundle. A stale or invalid member prevents all token issuance.
