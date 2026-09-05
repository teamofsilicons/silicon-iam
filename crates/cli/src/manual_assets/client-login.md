# Application login using short-lived tokens

A login produces one short-lived token. The application sends somebody to IAM, gets that token back, and trades it — together with its own secret — for a session. The IAM SLT exchange has no PKCE verifier or consent screen. Your application must still bind the callback to the browser's initiated login attempt; this protocol is not a substitute for callback CSRF protection.

Use the canonical organization-qualified Application ID everywhere in this flow, for example `acme>checkout`. The local handle supplied during registration is not independently addressable.

**You never receive anyone's credentials.** Nothing in this flow hands your application a password, a verification code, or any other authentication secret. The only thing you ever receive is the short-lived token.

## Step one — send them to IAM

For an external-app walkthrough using example ID `tos>briefcase` and callback `https://briefcase.teamofsilicons.com/auth/callback`, see the Briefcase login example (`iam docs api/applications`). Use your actual registered ID and implemented callback route; keep the app secret server-side.

```
let mut login = url::Url::parse(auth_base_url)?.join("/login")?;
login.query_pairs_mut()
    .append_pair("app_id", app_id)
    .append_pair("redirect_uri", callback)
    .append_pair("org_id", "acme"); // Omit for an unscoped login.
// Redirect the user agent to `login`; query values are percent-encoded.
```

Naming `app_id` is what makes this a login on your behalf; without one it is an ordinary Silicon IAM login and no token is minted. `redirect_uri` is optional and decides delivery only — give one and the token comes back on it, omit it and IAM shows the token to the person instead. `org_id` is also optional: when present, IAM requires an active membership in that organization and binds the resulting Application token family to it; when absent, the login is unscoped.

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
// Request no new organization context. An unscoped Carbon bearer stays unscoped;
// a bearer that already carries organization context retains it.
let inherited_or_unscoped = signed_in
    .auth()
    .short_lived_token("acme>your-app", &Mutation::new())
    .await?;

// Bind the Application tokens to the caller's active `acme` membership.
let organization_bound = signed_in
    .auth()
    .short_lived_token_in_organization(
        "acme>your-app",
        Some("acme"),
        &Mutation::new(),
    )
    .await?;
```

Your server then completes it at the same exchange as any other token. This is the only way a Silicon can sign in to an application. Use the organization-bound form when the resulting access token will issue OBO proofs; an unscoped Application token is deliberately rejected for OBO.

## Scope

There is none to request. A login carries the whole catalogue. An application's `scope` is the *webhook's* scope — which changes you are told about — and has nothing to do with what a session may read.
