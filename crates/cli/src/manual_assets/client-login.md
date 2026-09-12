# Application login using short-lived tokens

A login produces one short-lived token. The application sends somebody to IAM, gets that token back, and trades it — together with its own secret — for a session. The IAM SLT exchange has no PKCE verifier; IAM collects explicit permission and organization consent. Your application must still bind the callback to the browser's initiated login attempt; this protocol is not a substitute for callback CSRF protection.

Use the canonical organization-qualified Application ID everywhere in this flow, for example `acme>checkout`. The local handle supplied during registration is not independently addressable.

**You never receive anyone's credentials.** Nothing in this flow hands your application a password, a verification code, or any other authentication secret. The only thing you ever receive is the short-lived token.

## Step one — send them to IAM

For an external-app walkthrough using example ID `tos>briefcase` and callback `https://briefcase.teamofsilicons.com/auth/callback`, see the Briefcase login example (`iam docs api/applications`). Use your actual registered ID and implemented callback route; keep the app secret server-side.

```
let mut login = url::Url::parse(auth_base_url)?.join("/login")?;
login.query_pairs_mut()
    .append_pair("app_id", app_id)
    .append_pair("redirect_uri", callback); // IAM asks the user to choose organizations.
// Redirect the user agent to `login`; query values are percent-encoded.
```

Naming `app_id` is what makes this a login on your behalf; without one it is an ordinary Silicon IAM login and no token is minted. `redirect_uri` is optional and decides delivery only — give one and the token comes back on it, omit it and IAM shows the token to the person instead. Applications must not supply `org_id`. IAM validates the app, displays its critical and noncritical IAM and external permissions, then asks the user to select at least one organization. Only the selected active memberships are disclosed, never future memberships automatically.

The URI does not have to be registered anywhere, so an application may send people to different callbacks on different days without changing its configuration.

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
let choices = signed_in.auth().login_organizations("acme>your-app").await?;
// Display choices.scopes, obtain permission consent, then select organizations.
let approved = choices.scopes.iter().map(|scope| scope.scope.clone()).collect::<Vec<_>>();
let slt = signed_in.auth().short_lived_token_for_organizations(
    "acme>your-app", &["acme".to_owned()], choices.scope_version,
    &approved, &Mutation::new(),
).await?;
```

Only direct IAM credentials can submit this choice. Existing grants on the same parent IAM login are preserved when adding organizations; other sessions remain independent. Apps get no list of unselected organizations. OBO uses an explicitly selected organization of the user; the calling and audience apps may belong to other organizations.

## Scope

`app_scope` declares IAM permissions and exact external OBO endpoint permissions. A token carries only the application's effective, user-approved scope set within the user's selected organizations. `webhook_scope` independently chooses event categories. The defaults are `self.identity.read` and `self.profile.read`; email, phone, directory data, and external endpoints require explicit declarations. New critical scopes require review before they become usable. An upgrade awaiting review keeps the prior approved version working. Every direct login submission supplies the reviewed `scope_version` and complete `approved_scopes` list. Stale views fail; reload and show the new permissions before retrying.

## Batch login

Use `/login?app_ids=tos%3Ebriefcase,tos%3Edm` to authenticate once for 1–100 distinct applications. IAM collects organization consent separately for each app, reviews its permissions, and creates all SLTs atomically. A callback receives `#slts=` with a URL-encoded JSON array of objects containing `app_id`, `slt`, `expires_in`, `expires_at` and `request_id`. Read it in browser JavaScript, verify your login state and expected app IDs, clear the fragment, then send each SLT to its own app backend for the existing secret-authenticated exchange.

The direct-IAM endpoints are `GET /api/v1/app-auth/batch/organizations?app_ids=...` and `POST /api/v1/app-auth/batch/short-lived-tokens`. The POST takes `{"applications":[{"app_id":"tos>briefcase","org_ids":["tos"],"scope_version":1,"approved_scopes":["self.identity.read","self.profile.read"]}]}` and an idempotency key, returning `{"items":[...]}`. The Rust client exposes `auth().batch_login_organizations(...)` and `auth().batch_short_lived_tokens(...)`. The CLI exposes `iam batch-login --app-id` with repeatable app IDs. See `iam docs batch-login` for the complete guide. Use the matching API, CLI, and frontend contract together.

## Bundle login

A configured bundle presents one application identity while preserving a separate credential and token exchange for every member. Start with `/login?bundle_id=acme%3Eworkspace`. The callback uses the same `#slts=` result shape as batch login. Each member app receives only its own SLT and exchanges it with its own secret. Bundle membership is confined to one organization; existing member apps remain independently usable.

For direct IAM clients, call `auth().bundle_login_organizations(bundle_id)`, review the bundle and current member scope versions, then call `auth().bundle_short_lived_tokens(bundle_id, &request, &mutation)`. The submitted member list must match the current complete bundle. A stale or invalid member prevents all token issuance.
