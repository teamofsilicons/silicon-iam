//! The API documentation at `/docs/api/`.
//!
//! Content is authored as HTML fragments under `docs/api/` and embedded at
//! compile time, so a release image serves documentation that is guaranteed to
//! match the binary it ships with — a docs site that drifts from its API is
//! worse than no docs site.
//!
//! There is no Markdown renderer. That would mean a new dependency in a
//! service whose supply chain is deliberately minimal, and it would give the
//! author less control over the markup than the tables and endpoint listings
//! here actually need.
//!
//! The pages carry no script at all: their CSP has no `script-src`, so an
//! injection on a documentation page cannot reach the admin console that
//! shares this origin.

use core::fmt::Write as _;

use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};

use super::{
    assets,
    shell::{Document, Page, Surface, escape, render},
};

/// One documentation page.
struct Section {
    /// URL slug under `/docs/api/`.
    slug: &'static str,
    title: &'static str,
    /// One line, shown in the navigation and as the meta description.
    summary: &'static str,
    body: &'static str,
}

/// The documentation, in reading order.
///
/// Order is meaningful: it is the order a developer integrating with Silicon
/// IAM for the first time should read them, not alphabetical.
const SECTIONS: &[Section] = &[
    Section {
        slug: "overview",
        title: "Overview",
        summary: "What Silicon IAM is, the three principal types, and how to read this contract.",
        body: include_str!("../../docs/api/overview.html"),
    },
    Section {
        slug: "authentication",
        title: "Authentication",
        summary: "Transports, credential lifetimes, and how each principal proves who it is.",
        body: include_str!("../../docs/api/authentication.html"),
    },
    Section {
        slug: "conventions",
        title: "Request conventions",
        summary: "Idempotency, versioning, pagination, rate limits, and the error envelope.",
        body: include_str!("../../docs/api/conventions.html"),
    },
    Section {
        slug: "carbons",
        title: "Carbons",
        summary: "Signup, passwordless login, step-up, sessions, and the account surface.",
        body: include_str!("../../docs/api/carbons.html"),
    },
    Section {
        slug: "organizations",
        title: "Organizations",
        summary: "Organizations, memberships, the directory, invitations, and joining.",
        body: include_str!("../../docs/api/organizations.html"),
    },
    Section {
        slug: "silicons",
        title: "Silicons",
        summary: "Machine identities, credential rotation, and per-Silicon webhooks.",
        body: include_str!("../../docs/api/silicons.html"),
    },
    Section {
        slug: "governance",
        title: "Tags, trust and governance",
        summary: "Tags as access grants, two-dimensional trust, and approval quorums.",
        body: include_str!("../../docs/api/governance.html"),
    },
    Section {
        slug: "applications",
        title: "Applications",
        summary: "Registering an application, OAuth login, credentials, and redirect URIs.",
        body: include_str!("../../docs/api/applications.html"),
    },
    Section {
        slug: "webhooks",
        title: "Webhooks",
        summary: "Delivery guarantees, signature verification, and dead-letter replay.",
        body: include_str!("../../docs/api/webhooks.html"),
    },
    Section {
        slug: "obo",
        title: "On-behalf-of",
        summary: "Request-bound delegation between applications in one organization.",
        body: include_str!("../../docs/api/obo.html"),
    },
    Section {
        slug: "errors",
        title: "Error index",
        summary: "Every status and machine-readable code the API emits, and what to do about it.",
        body: include_str!("../../docs/api/errors.html"),
    },
];

/// `/docs` sends readers to the API documentation, which is all there is today.
pub(crate) async fn redirect_to_api() -> Redirect {
    Redirect::permanent("/docs/api/")
}

/// `/docs/api/` — the contents page.
pub(crate) async fn index() -> Document {
    let mut cards = String::new();
    for (position, section) in SECTIONS.iter().enumerate() {
        // Writing into the buffer cannot fail for a `String`; the result is
        // discarded rather than unwrapped so this stays panic-free.
        let _ = write!(
            cards,
            r#"          <li>
            <a class="panel" href="/docs/api/{slug}"
               style="display:block; padding:16px; text-decoration:none; color:inherit">
              <span class="label">{ordinal}</span>
              <h2 style="font-size:1.1875rem; margin-block:4px">{title}</h2>
              <p class="small muted">{summary}</p>
            </a>
          </li>
"#,
            slug = section.slug,
            ordinal = format_args!("{:02}", position + 1),
            title = escape(section.title),
            summary = escape(section.summary),
        );
    }

    let body = format!(
        r#"{header}
    <main id="main" tabindex="-1">
      <div class="wrap stack">
        <div>
          <h1>Silicon IAM API.</h1>
          <p class="lede">
            Identity, organization governance, application login, and delegated access. The
            normative contract is <a href="/openapi.yaml">openapi.yaml</a>; these pages explain
            the behaviour behind it.
          </p>
        </div>

        <div class="banner banner-info">
          <div>
            <strong>Base URL</strong>
            All JSON endpoints live under <code>https://backend.iam.teamofsilicons.com/api/v1</code>.
            Liveness and readiness stay at <code>/healthz</code> and <code>/readyz</code>.
          </div>
        </div>

        <ul style="list-style:none; display:grid; gap:16px;
                   grid-template-columns:repeat(auto-fill, minmax(320px, 1fr))">
{cards}        </ul>
      </div>
    </main>
"#,
        header = page_header(None),
        cards = cards,
    );

    Document::public(
        Surface::Docs,
        render(&Page {
            title: "API documentation",
            description: "Silicon IAM — identity, organization governance, application login, and delegated access.",
            head: "",
            body: &body,
        }),
    )
}

/// `/docs/api/{section}`.
pub(crate) async fn section(axum::extract::Path(slug): axum::extract::Path<String>) -> Response {
    let Some(section) = SECTIONS.iter().find(|entry| entry.slug == slug) else {
        return not_found().into_response();
    };

    let position = SECTIONS
        .iter()
        .position(|entry| entry.slug == slug)
        .unwrap_or(0);
    let previous = position
        .checked_sub(1)
        .and_then(|index| SECTIONS.get(index));
    let next = SECTIONS.get(position + 1);

    let mut pager = String::new();
    if previous.is_some() || next.is_some() {
        pager.push_str(r#"          <nav class="row-between" style="margin-block-start:48px; padding-block-start:16px; border-block-start:1px solid var(--rule)" aria-label="Section">
"#);
        match previous {
            Some(entry) => {
                let _ = writeln!(
                    pager,
                    "            <a class=\"small\" href=\"/docs/api/{slug}\">← {title}</a>",
                    slug = entry.slug,
                    title = escape(entry.title),
                );
            }
            None => pager.push_str("            <span></span>\n"),
        }
        match next {
            Some(entry) => {
                let _ = writeln!(
                    pager,
                    "            <a class=\"small\" href=\"/docs/api/{slug}\">{title} →</a>",
                    slug = entry.slug,
                    title = escape(entry.title),
                );
            }
            None => pager.push_str("            <span></span>\n"),
        }
        pager.push_str("          </nav>\n");
    }

    let body = format!(
        r#"{header}
    <main id="main" tabindex="-1">
      <div class="docs">
{nav}
        <article class="prose">
          <div class="section-head" style="margin-block-start:0">
            <span class="ordinal" aria-hidden="true">{ordinal}</span>
            <h1 class="label">{title}</h1>
          </div>
{body}
{pager}        </article>
      </div>
    </main>
"#,
        header = page_header(Some(section.slug)),
        nav = navigation(Some(section.slug)),
        ordinal = format_args!("{:02}", position + 1),
        title = escape(section.title),
        body = section.body,
        pager = pager,
    );

    Document::public(
        Surface::Docs,
        render(&Page {
            title: section.title,
            description: section.summary,
            head: "",
            body: &body,
        }),
    )
    .into_response()
}

/// The documentation's own 404.
///
/// A real HTML page rather than a JSON envelope, because this router is merged
/// outside the API's error normalisation and a reader who mistypes a slug
/// should get a way back rather than a machine-readable code.
fn not_found() -> Document {
    let body = format!(
        r#"{header}
    <main id="main" tabindex="-1">
      <div class="wrap">
        <div class="empty">
          <h1>No such section.</h1>
          <p class="lede">
            That documentation page does not exist. The contents page lists everything.
          </p>
          <a class="btn btn-primary" href="/docs/api/"><span>Back to the contents</span></a>
        </div>
      </div>
    </main>
"#,
        header = page_header(None),
    );

    Document::public(
        Surface::Docs,
        render(&Page {
            title: "Not found",
            description: "",
            head: "",
            body: &body,
        }),
    )
    .with_status(StatusCode::NOT_FOUND)
}

fn page_header(current: Option<&str>) -> String {
    let _ = current;
    format!(
        r#"    <header class="header">
      <a class="logo" href="/docs/api/">
        <img src="/_static/{mark}" alt="" width="24" height="24">
        <span>Silicon <em>IAM</em></span>
      </a>
      <span class="label">API documentation</span>
      <span class="spacer"></span>
      <a class="small" href="/openapi.yaml">openapi.yaml</a>
    </header>
    <div class="rail" aria-hidden="true"></div>
"#,
        mark = assets::MARK.path,
    )
}

fn navigation(current: Option<&str>) -> String {
    let mut items = String::new();
    for section in SECTIONS {
        let is_current = current == Some(section.slug);
        let _ = writeln!(
            items,
            "            <li><a href=\"/docs/api/{slug}\"{aria}>{title}</a></li>",
            slug = section.slug,
            aria = if is_current {
                " aria-current=\"page\""
            } else {
                ""
            },
            title = escape(section.title),
        );
    }

    format!(
        r#"        <nav class="docs-nav" aria-label="Documentation">
          <span class="label">Contents</span>
          <ol>
{items}          </ol>
        </nav>
"#
    )
}

/// Serves the normative contract itself.
///
/// Documentation is prose; this is the thing prose describes, and a client
/// generator needs it at a stable URL.
pub(crate) async fn openapi() -> Response {
    let mut response = (StatusCode::OK, OPENAPI).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/yaml; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("public, max-age=300, must-revalidate"),
    );
    headers.insert(
        http::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    response
}

const OPENAPI: &str = include_str!("../../openapi.yaml");

#[cfg(test)]
mod tests {
    use super::{OPENAPI, SECTIONS};

    #[test]
    fn every_section_is_populated() {
        for section in SECTIONS {
            assert!(!section.slug.is_empty(), "a section has no slug");
            assert!(!section.title.is_empty(), "{} has no title", section.slug);
            assert!(
                !section.summary.is_empty(),
                "{} has no summary",
                section.slug
            );
            assert!(
                section.body.len() > 400,
                "{} is too thin to be useful ({} bytes)",
                section.slug,
                section.body.len(),
            );
        }
    }

    #[test]
    fn slugs_are_unique_and_url_safe() {
        for (index, section) in SECTIONS.iter().enumerate() {
            assert!(
                section
                    .slug
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
                "{} is not a clean slug",
                section.slug,
            );
            for other in SECTIONS.iter().skip(index + 1) {
                assert_ne!(section.slug, other.slug, "duplicate slug");
            }
        }
    }

    #[test]
    fn section_bodies_carry_no_script() {
        // The docs CSP omits `script-src` entirely, so anything here would be
        // dead markup that a future CSP relaxation would silently activate.
        for section in SECTIONS {
            assert!(
                !section.body.contains("<script"),
                "{} embeds a script",
                section.slug,
            );
            assert!(
                !section.body.contains("javascript:"),
                "{} contains a javascript: URL",
                section.slug,
            );
        }
    }

    #[test]
    fn every_internal_documentation_link_resolves() {
        // A dead cross-reference in an API doc costs a reader real time, and
        // is exactly the kind of rot a compile-time check can prevent.
        for section in SECTIONS {
            let mut rest = section.body;
            while let Some(start) = rest.find("href=\"/docs/api/") {
                let tail = &rest[start + "href=\"/docs/api/".len()..];
                let Some(end) = tail.find('"') else { break };
                let target = &tail[..end];
                rest = &tail[end..];

                let slug = target.split('#').next().unwrap_or(target);
                if slug.is_empty() {
                    continue; // the contents page
                }
                assert!(
                    SECTIONS.iter().any(|entry| entry.slug == slug),
                    "{} links to a missing section: {slug}",
                    section.slug,
                );
            }
        }
    }

    #[test]
    fn the_embedded_contract_is_the_real_one() {
        assert!(OPENAPI.starts_with("openapi: 3.1"));
        assert!(OPENAPI.contains("title: Silicon IAM API"));
    }
}
