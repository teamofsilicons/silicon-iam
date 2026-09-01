//! HTML document shell and escaping.
//!
//! Every byte these surfaces emit is either a compile-time constant or passes
//! through [`escape`]. There is no template engine and no runtime
//! interpolation of anything a request controls, which is the cheapest way to
//! be confident about injection on a security product's own console.

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

/// The design tokens, inlined.
///
/// Kept in step with `@silicon-iam/tokens` by hand rather than by a build
/// step: these surfaces need three colours, one type scale and a handful of
/// components, and adding a Node toolchain to a Rust service's release build
/// to avoid duplicating forty lines is a bad trade.
pub(crate) const PALETTE_PAPER: &str = "#EDE8E0";

/// Which surface a document belongs to. Drives the header and the CSP.
#[derive(Clone, Copy)]
pub(crate) enum Surface {
    /// The platform-administration console. Needs script and connect.
    Admin,
    /// The API documentation. Static prose; no script at all.
    Docs,
}

impl Surface {
    /// Content-Security-Policy for this surface.
    ///
    /// Both are `default-src 'none'` and widen only where the surface
    /// genuinely needs it. The docs need no script, so they do not get
    /// `script-src` — an XSS on a documentation page that shares an origin
    /// with the admin console would be a real problem.
    fn content_security_policy(self) -> &'static str {
        match self {
            Self::Admin => concat!(
                "default-src 'none'; ",
                "style-src 'self'; ",
                "script-src 'self'; ",
                "connect-src 'self'; ",
                "img-src 'self' data:; ",
                "font-src 'self'; ",
                "form-action 'none'; ",
                "frame-ancestors 'none'; ",
                "base-uri 'none'",
            ),
            Self::Docs => concat!(
                "default-src 'none'; ",
                "style-src 'self'; ",
                "img-src 'self' data:; ",
                "font-src 'self'; ",
                "form-action 'none'; ",
                "frame-ancestors 'none'; ",
                "base-uri 'none'",
            ),
        }
    }
}

/// One rendered HTML document, with its security headers already decided.
pub(crate) struct Document {
    status: StatusCode,
    surface: Surface,
    body: String,
    cache_control: &'static str,
}

impl Document {
    /// A private document: authenticated, never cached anywhere.
    pub(crate) fn private(surface: Surface, body: String) -> Self {
        Self {
            status: StatusCode::OK,
            surface,
            body,
            cache_control: "no-store",
        }
    }

    /// A public document: safe to cache briefly, revalidated after that.
    pub(crate) fn public(surface: Surface, body: String) -> Self {
        Self {
            status: StatusCode::OK,
            surface,
            body,
            cache_control: "public, max-age=300, must-revalidate",
        }
    }

    /// Overrides the status. Used for the documentation's own 404 page.
    pub(crate) fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }
}

impl IntoResponse for Document {
    fn into_response(self) -> Response {
        let mut response = (self.status, self.body).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(self.cache_control),
        );
        headers.insert(
            http::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(self.surface.content_security_policy()),
        );
        headers.insert(
            http::HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            http::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        );
        headers.insert(
            http::HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
        response
    }
}

/// What goes into the document shell.
pub(crate) struct Page<'a> {
    /// Prepended to " · Silicon IAM" in the `<title>`.
    pub(crate) title: &'a str,
    /// Meta description. Omitted when empty.
    pub(crate) description: &'a str,
    /// Extra `<head>` markup. Must be a compile-time constant.
    pub(crate) head: &'a str,
    /// The `<body>` contents. Must already be escaped.
    pub(crate) body: &'a str,
}

/// Wraps `page` in the standard document.
///
/// The stylesheet is served from `/_static/` under a content-hashed name, so
/// it can be cached immutably while still updating the instant the binary
/// does.
pub(crate) fn render(page: &Page<'_>) -> String {
    let description = if page.description.is_empty() {
        String::new()
    } else {
        format!(
            "\n    <meta name=\"description\" content=\"{}\">",
            escape(page.description)
        )
    };

    format!(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <meta name="theme-color" content="{paper}">{description}
    <title>{title} · Silicon IAM</title>
    <link rel="icon" href="/_static/{favicon}" type="image/svg+xml">
    <link rel="stylesheet" href="/_static/{stylesheet}">
    <link rel="preload" href="/_static/plex-sans.woff2" as="font" type="font/woff2" crossorigin>
{head}  </head>
  <body>
    <a class="si-skip-link" href="#main">Skip to content</a>
{body}
  </body>
</html>
"##,
        paper = PALETTE_PAPER,
        description = description,
        title = escape(page.title),
        favicon = super::assets::FAVICON.path,
        stylesheet = super::assets::STYLESHEET.path,
        head = page.head,
        body = page.body,
    )
}

/// Escapes text for an HTML text node or a double-quoted attribute.
///
/// Deliberately escapes the full five rather than the minimal set: the same
/// function is used in both contexts, and a helper that is only correct in one
/// of them is a helper somebody will eventually misuse.
pub(crate) fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 16);
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Surface, escape};

    #[test]
    fn escaping_covers_both_text_and_attribute_contexts() {
        assert_eq!(
            escape(r#"<script>alert("x" & 'y')</script>"#),
            "&lt;script&gt;alert(&quot;x&quot; &amp; &#39;y&#39;)&lt;/script&gt;",
        );
    }

    #[test]
    fn escaping_leaves_ordinary_text_untouched() {
        assert_eq!(escape("head_of_growth:tos"), "head_of_growth:tos");
        assert_eq!(escape(""), "");
    }

    #[test]
    fn documentation_pages_are_denied_script_entirely() {
        let docs = Surface::Docs.content_security_policy();
        assert!(!docs.contains("script-src"));
        assert!(docs.starts_with("default-src 'none'"));
        assert!(docs.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn the_admin_console_gets_only_same_origin_script_and_connect() {
        let admin = Surface::Admin.content_security_policy();
        assert!(admin.contains("script-src 'self'"));
        assert!(admin.contains("connect-src 'self'"));
        assert!(admin.contains("form-action 'none'"));
        assert!(!admin.contains("unsafe-inline"));
        assert!(!admin.contains("unsafe-eval"));
    }
}
