//! The platform-administration console at `/admin`.
//!
//! This handler renders a shell and nothing else. It performs no
//! authentication, executes no SQL, and reads no credential — every byte it
//! emits is a compile-time constant.
//!
//! Authority lives entirely in `/api/v1/admin/*`, which the accompanying
//! script calls same-origin. Those endpoints already require a bearer whose
//! Carbon holds a current platform-administrator grant, a verified-channel
//! step-up token, an `Idempotency-Key`, and an `If-Match` precondition on
//! every mutation. Re-implementing that here would create a second place for
//! the authorization to be wrong, which is the last thing a platform-admin
//! surface needs.
//!
//! Serving the shell unauthenticated is therefore safe and deliberate: it is
//! an empty page until a real platform administrator signs in through it.

use super::{
    assets,
    shell::{Document, Page, Surface, render},
};

/// Renders the console shell.
pub(crate) async fn page() -> Document {
    let body = format!(
        r#"    <header class="header">
      <a class="logo" href="/admin">
        <img src="/_static/{mark}" alt="" width="24" height="24">
        <span>Silicon <em>IAM</em></span>
      </a>
      <span class="label">Platform administration</span>
      <span class="spacer"></span>
      <span class="micro mono" id="signed-in" hidden></span>
      <button class="btn btn-sm" id="sign-out" type="button" hidden><span>Sign out</span></button>
    </header>
    <div class="rail" aria-hidden="true"></div>

    <main id="main" tabindex="-1">
      <div class="wrap stack">
        <noscript>
          <div class="banner banner-danger">
            <div>
              <strong>This console needs JavaScript.</strong>
              It is a thin client over the <code>/api/v1/admin</code> endpoints, which require a
              bearer token and a step-up assertion that a plain HTML form cannot carry. Every
              action here is also available directly from the API.
            </div>
          </div>
        </noscript>

        <!--
          Three views, one document. The script reveals exactly one.
          A single page keeps the whole console inside one CSP and one
          cache entry, and the review queue is the only thing most
          sessions ever open.
        -->
        <section id="view-signin" hidden>{signin}</section>
        <section id="view-denied" hidden>{denied}</section>
        <section id="view-console" hidden>{console}</section>

        <div id="view-loading" class="row">
          <span class="ticker" aria-hidden="true"></span>
          <span class="small muted" role="status">Checking your session…</span>
        </div>
      </div>
    </main>

    <div id="toast-region" role="status" aria-live="polite" class="visually-hidden"></div>
"#,
        mark = assets::MARK.path,
        signin = SIGN_IN_VIEW,
        denied = DENIED_VIEW,
        console = CONSOLE_VIEW,
    );

    Document::private(
        Surface::Admin,
        render(&Page {
            title: "Platform administration",
            description: "",
            head: HEAD,
            body: &body,
        }),
    )
}

const HEAD: &str = concat!(
    "    <meta name=\"robots\" content=\"noindex, nofollow\">\n",
    "    <script type=\"module\" src=\"/_static/admin.js\" defer></script>\n",
);

/// Sign-in.
///
/// Same-origin, so the login endpoints set `iam_session` natively and the
/// bearer never crosses an origin. The flow is the ordinary Carbon login the
/// contract already publishes; being a platform administrator is a property of
/// the account, not a separate credential.
const SIGN_IN_VIEW: &str = r#"
        <div class="section-head">
          <span class="ordinal" aria-hidden="true">01</span>
          <h1 class="label">Sign in</h1>
        </div>

        <div class="panel panel-narrow">
          <div class="panel-body stack">
            <p class="small muted">
              Platform administration requires a Silicon IAM account holding a current
              platform-administrator grant.
            </p>

            <form id="form-identity" class="stack" novalidate>
              <div class="field">
                <label for="identity">Email or Carbon ID</label>
                <input id="identity" class="mono" type="text" autocomplete="username"
                       autocapitalize="none" spellcheck="false" required>
                <p class="micro">A Carbon ID sends a code to both verified channels.</p>
              </div>
              <button class="btn btn-primary" type="submit"><span>Send code</span></button>
            </form>

            <form id="form-code" class="stack" novalidate hidden>
              <div class="field">
                <label for="code">Verification code</label>
                <input id="code" class="mono otp-input" type="text" inputmode="numeric"
                       pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required>
                <p class="micro">
                  Six digits, valid for 10 minutes. After 10 incorrect attempts there is a
                  60-second pause; requesting a new code does not clear it.
                </p>
              </div>
              <button class="btn btn-primary" type="submit"><span>Verify</span></button>
              <button class="btn btn-sm" type="button" id="code-back"><span>Start over</span></button>
            </form>

            <p id="signin-error" class="small form-error" role="alert" hidden></p>
          </div>
        </div>
"#;

/// Shown when the account signs in successfully but holds no grant.
///
/// A distinct view rather than an error toast: the reader needs to understand
/// that their credentials were fine and their authority was not, which is a
/// different problem with a different remedy.
const DENIED_VIEW: &str = r#"
        <div class="empty">
          <h1>You are signed in, but not a platform administrator.</h1>
          <p class="lede">
            This console is restricted to accounts holding a current platform-administrator
            grant. Organization administration lives at
            <a href="https://iam.teamofsilicons.com">iam.teamofsilicons.com</a>.
          </p>
          <p class="micro">
            Grants are issued with <code>iam-bootstrap-admin</code> and are audited. If you
            believe you should have one, ask an existing platform administrator.
          </p>
        </div>
"#;

/// The console proper: review queue, application detail, SSO entitlement.
const CONSOLE_VIEW: &str = r#"
        <div class="section-head">
          <span class="ordinal" aria-hidden="true">01</span>
          <h1 class="label">Application review</h1>
          <span class="spacer"></span>
          <span class="micro mono" id="queue-count"></span>
        </div>

        <div class="row" role="group" aria-label="Filter by status">
          <button class="btn btn-sm" type="button" data-status="under_review"
                  aria-pressed="true"><span>Under review</span></button>
          <button class="btn btn-sm" type="button" data-status="verified"
                  aria-pressed="false"><span>Verified</span></button>
          <button class="btn btn-sm" type="button" data-status="suspended"
                  aria-pressed="false"><span>Suspended</span></button>
          <button class="btn btn-sm" type="button" data-status="rejected"
                  aria-pressed="false"><span>Rejected</span></button>
          <button class="btn btn-sm" type="button" data-status=""
                  aria-pressed="false"><span>All</span></button>
          <span class="spacer"></span>
          <button class="btn btn-sm" type="button" id="refresh"><span>Refresh</span></button>
        </div>

        <div class="table-wrap">
          <table class="data">
            <caption class="visually-hidden">Registered applications</caption>
            <thead>
              <tr>
                <th scope="col">Application</th>
                <th scope="col">Organization</th>
                <th scope="col">Status</th>
                <th scope="col">Consent</th>
                <th scope="col">Scopes</th>
                <th scope="col">Changes</th>
                <th scope="col">Registered</th>
                <th scope="col"><span class="visually-hidden">Actions</span></th>
              </tr>
            </thead>
            <tbody id="applications"></tbody>
          </table>
        </div>

        <div id="detail" hidden></div>

        <div class="section-head">
          <span class="ordinal" aria-hidden="true">02</span>
          <h1 class="label">SSO entitlement</h1>
        </div>

        <div class="panel panel-medium">
          <div class="panel-body stack">
            <p class="small muted">
              Single sign-on is locked by default and can only be unlocked here. An entitled
              organization can then configure its own WorkOS connection; it cannot grant itself
              the entitlement.
            </p>
            <form id="form-entitlement" class="stack" novalidate>
              <div class="field">
                <label for="entitlement-org">Organization ID</label>
                <input id="entitlement-org" class="mono" type="text" autocapitalize="none"
                       spellcheck="false" placeholder="teamofsilicons" required>
              </div>
              <div class="field">
                <label for="entitlement-state">Entitlement</label>
                <select id="entitlement-state">
                  <option value="true">Entitled — the organization may configure SSO</option>
                  <option value="false">Not entitled — SSO is locked</option>
                </select>
              </div>
              <div class="field">
                <label for="entitlement-version">Current version</label>
                <input id="entitlement-version" class="mono" type="text" inputmode="numeric"
                       placeholder="0" required>
                <p class="micro">
                  The <code>If-Match</code> precondition. Read it from
                  <code>GET /api/v1/organizations/{org_id}/sso</code>; a stale value is refused
                  with <code>412</code> rather than overwriting a concurrent change.
                </p>
              </div>
              <button class="btn btn-primary" type="submit"><span>Replace entitlement</span></button>
            </form>
          </div>
        </div>
"#;

#[cfg(test)]
mod tests {
    use super::{CONSOLE_VIEW, DENIED_VIEW, HEAD, SIGN_IN_VIEW};

    #[test]
    fn the_shell_is_excluded_from_search_indexes() {
        assert!(HEAD.contains("noindex"));
    }

    #[test]
    fn the_script_is_a_deferred_module_from_the_same_origin() {
        assert!(HEAD.contains("type=\"module\""));
        assert!(HEAD.contains("src=\"/_static/admin.js\""));
        assert!(!HEAD.contains("http://"));
        assert!(!HEAD.contains("https://"));
    }

    #[test]
    fn no_view_carries_an_inline_event_handler() {
        // The CSP has no `unsafe-inline`, so any of these would silently fail.
        for view in [SIGN_IN_VIEW, DENIED_VIEW, CONSOLE_VIEW] {
            for attribute in [
                "onclick=",
                "onsubmit=",
                "onload=",
                "onerror=",
                "javascript:",
            ] {
                assert!(!view.contains(attribute), "view contains {attribute}");
            }
        }
    }

    #[test]
    fn every_view_starts_hidden_so_nothing_flashes_before_the_session_is_known() {
        // The markup for all three ships in one document; the script reveals
        // one. Without `hidden` the reader would see the sign-in form flash
        // before an established session resolves.
        assert!(!SIGN_IN_VIEW.contains("<section"));
        assert!(!CONSOLE_VIEW.contains("<section"));
    }

    #[test]
    fn the_sign_in_form_states_the_exact_otp_contract() {
        // The product's copy rule: any message about a TTL, a cooldown or an
        // attempt counter states the figure and the remedy.
        assert!(SIGN_IN_VIEW.contains("10 minutes"));
        assert!(SIGN_IN_VIEW.contains("10 incorrect attempts"));
        assert!(SIGN_IN_VIEW.contains("60-second"));
        assert!(SIGN_IN_VIEW.contains("does not clear it"));
    }

    #[test]
    fn the_entitlement_form_explains_the_version_precondition() {
        assert!(CONSOLE_VIEW.contains("If-Match"));
        assert!(CONSOLE_VIEW.contains("412"));
    }
}
