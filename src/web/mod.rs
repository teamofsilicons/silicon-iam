//! Server-rendered HTML surfaces.
//!
//! Two things live here, and nothing else:
//!
//! - `/admin` — the platform-administration console. Application review,
//!   suspension, consent policy, and SSO entitlement.
//! - `/docs/api/` — the public API documentation.
//!
//! Both are deliberately outside `/api/v1`. They are documents and interfaces,
//! not contract surface, and `scripts/check-openapi-routes.rb` enforces that
//! separation in CI: every route declared here must sit under `/admin`,
//! `/docs` or `/_static`, and none of them may appear in `openapi.yaml`.
//!
//! # Why the admin console is a thin client rather than a server-rendered app
//!
//! The platform-admin API already exists and is well guarded: it requires a
//! bearer whose Carbon holds a current platform-administrator grant, a
//! verified-channel step-up token, an `Idempotency-Key`, and an `If-Match`
//! precondition on every mutation. Re-implementing that authorization in a
//! second, HTML-shaped path would mean a second place for it to be wrong.
//!
//! So this module serves a static shell plus one small script, and the script
//! drives the same `/api/v1/admin/*` endpoints the contract already publishes,
//! same-origin. The Rust here executes no SQL and reads no credential.

pub(crate) mod admin;
pub(crate) mod assets;
pub(crate) mod docs;
pub(crate) mod shell;

use axum::{Router, routing::get};

/// Routes for the HTML surfaces.
///
/// Merged at the composition root *after* the JSON router's layer stack, so
/// these responses keep their own `Content-Type`, caching and CSP rather than
/// inheriting the API's `no-store` default and JSON error normalisation.
///
/// Generic over the state type because **no handler here touches it**. These
/// surfaces read no database and no credential, and saying so in the signature
/// keeps that true: adding a stateful handler would stop compiling rather than
/// quietly widening what the documentation site can reach.
pub(crate) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/admin", get(admin::page))
        .route("/docs", get(docs::redirect_to_api))
        .route("/docs/api/", get(docs::index))
        .route("/docs/api/{section}", get(docs::section))
        .route("/openapi.yaml", get(docs::openapi))
        .route("/_static/{file}", get(assets::serve))
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt as _;

    /// The HTML surfaces need no application state, so a test can drive the
    /// real router directly — no database, no credentials, no fixtures.
    fn surfaces() -> Router {
        super::router::<()>()
    }

    async fn send(request: Request<Body>) -> axum::response::Response {
        match surfaces().oneshot(request).await {
            Ok(response) => response,
            Err(error) => panic!("the router failed to respond: {error}"),
        }
    }

    async fn get(path: &str) -> axum::response::Response {
        let Ok(request) = Request::builder().uri(path).body(Body::empty()) else {
            panic!("could not build a request for {path}");
        };
        send(request).await
    }

    async fn body_of(response: axum::response::Response) -> String {
        let Ok(bytes) = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024).await else {
            panic!("the response body could not be read");
        };
        match String::from_utf8(bytes.to_vec()) {
            Ok(body) => body,
            Err(error) => panic!("the response body is not valid UTF-8: {error}"),
        }
    }

    fn header_of(response: &axum::response::Response, name: &str) -> String {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }

    #[tokio::test]
    async fn the_admin_console_serves_its_shell() {
        let response = get("/admin").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(header_of(&response, "content-type").starts_with("text/html"));

        // Authenticated surface: never cached, never indexed.
        assert_eq!(header_of(&response, "cache-control"), "no-store");

        let body = body_of(response).await;
        assert!(body.contains("Platform administration"));
        assert!(body.contains("noindex"));
    }

    #[tokio::test]
    async fn the_admin_console_locks_down_script_and_forms() {
        let policy = header_of(&get("/admin").await, "content-security-policy");
        assert!(policy.starts_with("default-src 'none'"));
        assert!(policy.contains("script-src 'self'"));
        assert!(policy.contains("form-action 'none'"));
        assert!(!policy.contains("unsafe-inline"));
        assert!(!policy.contains("unsafe-eval"));
    }

    #[tokio::test]
    async fn documentation_is_cacheable_and_scriptless() {
        let response = get("/docs/api/").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(header_of(&response, "cache-control").starts_with("public"));

        let policy = header_of(&response, "content-security-policy");
        // No `script-src` at all: an injection on a docs page must not be able
        // to reach the admin console that shares this origin.
        assert!(!policy.contains("script-src"));

        let body = body_of(response).await;
        assert!(body.contains("Silicon IAM API"));
        assert!(body.contains("/docs/api/authentication"));
    }

    #[tokio::test]
    async fn every_declared_section_renders() {
        for slug in [
            "overview",
            "authentication",
            "conventions",
            "carbons",
            "organizations",
            "silicons",
            "governance",
            "applications",
            "webhooks",
            "obo",
            "errors",
        ] {
            let response = get(&format!("/docs/api/{slug}")).await;
            assert_eq!(response.status(), StatusCode::OK, "{slug} did not render");
            let body = body_of(response).await;
            assert!(
                body.contains("<article class=\"prose\">"),
                "{slug} has no body"
            );
            assert!(body.contains("Contents"), "{slug} has no navigation");
        }
    }

    /// The reason `src/web` is merged outside the API's layer stack.
    ///
    /// Inside it, `normalize_errors` would rewrite this HTML page into the JSON
    /// error envelope, and a reader who mistyped a slug would get a
    /// machine-readable blob instead of a way back.
    #[tokio::test]
    async fn an_unknown_section_answers_with_html_not_the_json_envelope() {
        let response = get("/docs/api/does-not-exist").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(header_of(&response, "content-type").starts_with("text/html"));

        let body = body_of(response).await;
        assert!(body.contains("No such section"));
        assert!(body.contains("/docs/api/"));
        assert!(!body.contains("\"error\""));
    }

    #[tokio::test]
    async fn docs_redirects_to_the_api_documentation() {
        let response = get("/docs").await;
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(header_of(&response, "location"), "/docs/api/");
    }

    #[tokio::test]
    async fn the_contract_is_served_as_yaml() {
        let response = get("/openapi.yaml").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(header_of(&response, "content-type").starts_with("application/yaml"));
        assert!(body_of(response).await.starts_with("openapi: 3.1"));
    }

    #[tokio::test]
    async fn assets_are_served_with_a_strong_entity_tag() {
        for path in ["console.css", "admin.js", "favicon.svg", "mark.svg"] {
            let response = get(&format!("/_static/{path}")).await;
            assert_eq!(response.status(), StatusCode::OK, "{path} did not serve");
            assert!(
                !header_of(&response, "etag").is_empty(),
                "{path} has no ETag"
            );
            assert!(header_of(&response, "cache-control").contains("max-age"));
        }
    }

    #[tokio::test]
    async fn a_matching_entity_tag_answers_not_modified() {
        let first = get("/_static/console.css").await;
        let etag = header_of(&first, "etag");

        let Ok(request) = Request::builder()
            .uri("/_static/console.css")
            .header(header::IF_NONE_MATCH, etag)
            .body(Body::empty())
        else {
            panic!("could not build a conditional request");
        };
        assert_eq!(send(request).await.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn an_unknown_asset_is_a_bare_404() {
        // Single-segment matching means there is nothing to traverse to, but
        // the negative case is worth pinning down anyway.
        for path in ["nope.css", "..%2F..%2Fetc%2Fpasswd", "console.css.map"] {
            let response = get(&format!("/_static/{path}")).await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} was served"
            );
        }
    }

    /// The CSP is `style-src 'self'` with no `unsafe-inline`, so a `style=""`
    /// attribute is silently dropped by the browser. An earlier draft used them
    /// and the documentation index rendered as an unstyled bulleted list — the
    /// kind of break that no status code reports.
    #[tokio::test]
    async fn no_surface_relies_on_an_inline_style() {
        for path in [
            "/admin",
            "/docs/api/",
            "/docs/api/overview",
            "/docs/api/errors",
            "/docs/api/nope",
        ] {
            let body = body_of(get(path).await).await;
            assert!(!body.contains("style=\""), "{path} carries an inline style");
            assert!(
                !body.contains("<style"),
                "{path} carries an inline style block"
            );
        }
    }

    /// Everything the surfaces reference must actually be served.
    ///
    /// A fabricated font URL 404s silently and the page falls back without
    /// complaint, which is exactly how the first draft shipped three dead
    /// requests.
    #[tokio::test]
    async fn every_referenced_asset_exists() {
        let mut referenced = std::collections::BTreeSet::new();
        for path in ["/admin", "/docs/api/", "/docs/api/overview"] {
            let body = body_of(get(path).await).await;
            let mut rest = body.as_str();
            while let Some(start) = rest.find("/_static/") {
                let tail = &rest[start + "/_static/".len()..];
                let end = tail.find(['"', '\'']).unwrap_or(tail.len());
                referenced.insert(tail[..end].to_owned());
                rest = &tail[end..];
            }
        }
        assert!(!referenced.is_empty(), "no assets were referenced at all");

        for asset in referenced {
            let response = get(&format!("/_static/{asset}")).await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{asset} is referenced but not served"
            );
        }
    }

    /// The stylesheet's own `url()` references, which no page links directly.
    #[tokio::test]
    async fn every_font_the_stylesheet_declares_is_served() {
        let css = body_of(get("/_static/console.css").await).await;
        let mut rest = css.as_str();
        let mut fonts = 0_usize;
        while let Some(start) = rest.find("url('/_static/") {
            let tail = &rest[start + "url('/_static/".len()..];
            let end = tail.find('\'').unwrap_or(tail.len());
            let asset = &tail[..end];
            let response = get(&format!("/_static/{asset}")).await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{asset} is declared but not served"
            );
            fonts += 1;
            rest = &tail[end..];
        }
        assert_eq!(fonts, 3, "expected three self-hosted font faces");
    }

    /// `hidden` must beat this stylesheet's own `display` declarations.
    ///
    /// The attribute's UA rule is `display: none`, which a later `display` on
    /// `.btn`, `.stack` or `.row` silently wins against. Without the override
    /// the admin console paints its sign-out button, its verification-code
    /// form and its loading row all at once.
    #[tokio::test]
    async fn the_stylesheet_forces_hidden_to_win() {
        let css = body_of(get("/_static/console.css").await).await;
        assert!(
            css.contains("[hidden]") && css.contains("display: none !important"),
            "the hidden override is missing",
        );
    }

    /// A second `class` on one element is dropped by the parser, so the styling
    /// it carried disappears without any error anywhere.
    #[tokio::test]
    async fn no_element_declares_class_twice() {
        for path in ["/admin", "/docs/api/", "/docs/api/overview"] {
            let body = body_of(get(path).await).await;
            for tag in body.split('<').skip(1) {
                let Some(end) = tag.find('>') else { continue };
                let attributes = &tag[..end];
                assert!(
                    attributes.matches("class=\"").count() <= 1,
                    "{path} has an element with two class attributes: <{attributes}>",
                );
            }
        }
    }

    #[tokio::test]
    async fn html_surfaces_refuse_to_be_framed() {
        for path in ["/admin", "/docs/api/", "/docs/api/overview"] {
            let response = get(path).await;
            assert_eq!(header_of(&response, "x-frame-options"), "DENY", "{path}");
            assert!(
                header_of(&response, "content-security-policy").contains("frame-ancestors 'none'"),
                "{path} can be framed",
            );
        }
    }
}
