//! The documentation at `/docs/`.
//!
//! Two manuals share one renderer:
//!
//! - `/docs/api/` — the HTTP contract. What every endpoint does, and why.
//! - `/docs/client/` — the official Rust SDK. How to integrate an Application
//!   without reimplementing PKCE, proof signing, or signature verification.
//!
//! Content is authored as HTML fragments under `docs/` and embedded at compile
//! time, so a release image serves documentation that is guaranteed to match
//! the binary it ships with — a docs site that drifts from its API is worse
//! than no docs site.
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
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};

use super::{
    assets,
    shell::{Document, Page, Surface, escape, render},
};

/// One documentation page.
struct Section {
    /// URL slug under the manual's prefix.
    slug: &'static str,
    title: &'static str,
    /// One line, shown in the navigation and as the meta description.
    summary: &'static str,
    body: &'static str,
}

/// A set of sections published under one prefix.
struct Manual {
    /// URL prefix, without slashes, e.g. `api`.
    prefix: &'static str,
    /// Shown beside the logo in the header.
    label: &'static str,
    title: &'static str,
    lede: &'static str,
    sections: &'static [Section],
}

impl Manual {
    fn find(&self, slug: &str) -> Option<(usize, &Section)> {
        self.sections
            .iter()
            .enumerate()
            .find(|(_, section)| section.slug == slug)
    }
}

/// The HTTP contract, in reading order.
///
/// Order is meaningful: it is the order a developer integrating with Silicon
/// IAM for the first time should read them, not alphabetical.
const API_SECTIONS: &[Section] = &[
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
        summary: "The version handshake, idempotency, versioning, pagination, and errors.",
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

/// The Rust SDK, in the order an integration is actually built.
const CLIENT_SECTIONS: &[Section] = &[
    Section {
        slug: "overview",
        title: "Overview",
        summary: "What the SDK covers, what it deliberately does not, and why.",
        body: include_str!("../../docs/client/overview.html"),
    },
    Section {
        slug: "connecting",
        title: "Connecting",
        summary: "Installation, credentials, and the fail-closed compatibility handshake.",
        body: include_str!("../../docs/client/connecting.html"),
    },
    Section {
        slug: "oauth",
        title: "Signing users in",
        summary: "PKCE authorization, the sealed continuation, and callback handling.",
        body: include_str!("../../docs/client/oauth.html"),
    },
    Section {
        slug: "tokens",
        title: "Managing tokens",
        summary: "Refresh, introspection, revocation, logout, and idempotency discipline.",
        body: include_str!("../../docs/client/tokens.html"),
    },
    Section {
        slug: "obo",
        title: "Delegated access",
        summary: "Discovering endpoints, exchanging a request-bound proof, and consuming it.",
        body: include_str!("../../docs/client/obo.html"),
    },
    Section {
        slug: "webhooks",
        title: "Receiving webhooks",
        summary: "Signature verification, secret keyrings, and deduplication.",
        body: include_str!("../../docs/client/webhooks.html"),
    },
    Section {
        slug: "errors",
        title: "Errors and recovery",
        summary: "The error taxonomy, what is retryable, and how to recover a lost response.",
        body: include_str!("../../docs/client/errors.html"),
    },
];

const API: Manual = Manual {
    prefix: "api",
    label: "API documentation",
    title: "Silicon IAM API.",
    lede: "Identity, organization governance, application login, and delegated access. The \
           normative contract is <a href=\"/openapi.yaml\">openapi.yaml</a>; these pages explain \
           the behaviour behind it.",
    sections: API_SECTIONS,
};

const CLIENT: Manual = Manual {
    prefix: "client",
    label: "Client documentation",
    title: "Silicon IAM for Rust.",
    lede: "The official SDK for integrating an Application. It keeps wire paths, PKCE material, \
           proof signatures, and retry policy inside the crate, and exposes only the inputs an \
           Application actually owns.",
    sections: CLIENT_SECTIONS,
};

const MANUALS: &[&Manual] = &[&API, &CLIENT];

/// `/docs` — chooses between the two manuals.
pub(crate) async fn landing() -> Document {
    let body = format!(
        r#"{header}
    <main id="main" tabindex="-1">
      <div class="wrap stack">
        <div>
          <h1>Documentation.</h1>
          <p class="lede">
            Two manuals. Read the contract if you are calling the API directly; read the client
            if you are integrating an Application in Rust and would rather not reimplement PKCE,
            proof signing, and signature verification yourself.
          </p>
        </div>

        <ul class="docs-cards">
          <li>
            <a class="panel docs-card" href="/docs/api/">
              <span class="label">01</span>
              <h2>API</h2>
              <p class="small muted">
                The HTTP contract: transports, credential lifetimes, idempotency, the directory
                model, webhooks, and delegated access. Language-independent.
              </p>
            </a>
          </li>
          <li>
            <a class="panel docs-card" href="/docs/client/">
              <span class="label">02</span>
              <h2>Client</h2>
              <p class="small muted">
                The official Rust SDK. Connect, sign users in, manage tokens, delegate between
                applications, and verify webhook deliveries.
              </p>
            </a>
          </li>
          <li>
            <a class="panel docs-card" href="/openapi.yaml">
              <span class="label">03</span>
              <h2>openapi.yaml</h2>
              <p class="small muted">
                The normative machine-readable contract. Everything else describes this.
              </p>
            </a>
          </li>
        </ul>
      </div>
    </main>
"#,
        header = page_header(None),
    );

    Document::public(
        Surface::Docs,
        render(&Page {
            title: "Documentation",
            description: "Silicon IAM — the HTTP contract and the official Rust client.",
            head: "",
            body: &body,
        }),
    )
}

/// `/docs/api/` and `/docs/client/` — a manual's contents page.
pub(crate) async fn index(Path(manual): Path<String>) -> Response {
    let Some(manual) = MANUALS.iter().find(|entry| entry.prefix == manual) else {
        return not_found().into_response();
    };

    let mut cards = String::new();
    for (position, section) in manual.sections.iter().enumerate() {
        let _ = write!(
            cards,
            r#"          <li>
            <a class="panel docs-card" href="/docs/{prefix}/{slug}">
              <span class="label">{ordinal}</span>
              <h2>{title}</h2>
              <p class="small muted">{summary}</p>
            </a>
          </li>
"#,
            prefix = manual.prefix,
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
          <h1>{title}</h1>
          <p class="lede">{lede}</p>
        </div>

{banner}
        <ul class="docs-cards">
{cards}        </ul>
      </div>
    </main>
"#,
        header = page_header(Some(manual)),
        title = escape(manual.title),
        lede = manual.lede,
        banner = index_banner(manual),
        cards = cards,
    );

    Document::public(
        Surface::Docs,
        render(&Page {
            title: manual.label,
            description: manual.lede,
            head: "",
            body: &body,
        }),
    )
    .into_response()
}

/// `/docs/{manual}/{section}`.
pub(crate) async fn section(Path((manual, slug)): Path<(String, String)>) -> Response {
    let Some(manual) = MANUALS.iter().find(|entry| entry.prefix == manual) else {
        return not_found().into_response();
    };
    let Some((position, section)) = manual.find(&slug) else {
        return not_found().into_response();
    };

    let previous = position
        .checked_sub(1)
        .and_then(|index| manual.sections.get(index));
    let next = manual.sections.get(position + 1);

    let mut pager = String::new();
    if previous.is_some() || next.is_some() {
        pager.push_str("          <nav class=\"row-between docs-pager\" aria-label=\"Section\">\n");
        match previous {
            Some(entry) => {
                let _ = writeln!(
                    pager,
                    "            <a class=\"small\" href=\"/docs/{prefix}/{slug}\">← {title}</a>",
                    prefix = manual.prefix,
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
                    "            <a class=\"small\" href=\"/docs/{prefix}/{slug}\">{title} →</a>",
                    prefix = manual.prefix,
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
          <div class="section-head section-head-flush">
            <span class="ordinal" aria-hidden="true">{ordinal}</span>
            <h1 class="label">{title}</h1>
          </div>
{body}
{pager}        </article>
      </div>
    </main>
"#,
        header = page_header(Some(manual)),
        nav = navigation(manual, Some(section.slug)),
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

/// A manual's own 404.
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
          <a class="btn btn-primary" href="/docs"><span>Back to the contents</span></a>
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

/// A cross-reference from each manual to the other.
///
/// The two are complementary, not alternatives, and a reader who lands on the
/// wrong one should discover that immediately rather than three sections in.
fn index_banner(manual: &Manual) -> &'static str {
    if manual.prefix == "api" {
        r#"        <div class="banner banner-info">
          <div>
            <strong>Integrating in Rust?</strong>
            The <a href="/docs/client/">official client</a> already implements everything on these
            pages — PKCE, the version handshake, proof signing, signature verification, and the
            retry policy. Read the contract when you need to know why it behaves as it does.
          </div>
        </div>

"#
    } else {
        r#"        <div class="banner banner-info">
          <div>
            <strong>The contract behind this client.</strong>
            Every behaviour here is described language-independently in the
            <a href="/docs/api/">API documentation</a>. Read it when you need to know what the
            SDK is protecting you from.
          </div>
        </div>

"#
    }
}

fn page_header(manual: Option<&Manual>) -> String {
    let (home, label) = match manual {
        Some(entry) => (format!("/docs/{}/", entry.prefix), escape(entry.label)),
        None => ("/docs".to_owned(), "Documentation".to_owned()),
    };

    format!(
        r#"    <header class="header">
      <a class="logo" href="{home}">
        <img src="/_static/{mark}" alt="" width="24" height="24">
        <span>Silicon <em>IAM</em></span>
      </a>
      <span class="label">{label}</span>
      <span class="spacer"></span>
      <a class="small" href="/docs/api/">API</a>
      <a class="small" href="/docs/client/">Client</a>
      <a class="small" href="/openapi.yaml">openapi.yaml</a>
    </header>
    <div class="rail" aria-hidden="true"></div>
"#,
        home = home,
        mark = assets::MARK.path,
        label = label,
    )
}

fn navigation(manual: &Manual, current: Option<&str>) -> String {
    let mut items = String::new();
    for section in manual.sections {
        let is_current = current == Some(section.slug);
        let _ = writeln!(
            items,
            "            <li><a href=\"/docs/{prefix}/{slug}\"{aria}>{title}</a></li>",
            prefix = manual.prefix,
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

/// Keeps a `/docs/api` link without its trailing slash working.
pub(crate) async fn redirect_to_index(Path(manual): Path<String>) -> Response {
    if MANUALS.iter().any(|entry| entry.prefix == manual) {
        return Redirect::permanent(&format!("/docs/{manual}/")).into_response();
    }
    not_found().into_response()
}

const OPENAPI: &str = include_str!("../../openapi.yaml");

#[cfg(test)]
mod tests {
    use super::{MANUALS, OPENAPI};

    #[test]
    fn every_section_is_populated() {
        for manual in MANUALS {
            assert!(
                !manual.sections.is_empty(),
                "{} has no sections",
                manual.prefix
            );
            for section in manual.sections {
                assert!(!section.slug.is_empty(), "a section has no slug");
                assert!(!section.title.is_empty(), "{} has no title", section.slug);
                assert!(
                    !section.summary.is_empty(),
                    "{} has no summary",
                    section.slug
                );
                assert!(
                    section.body.len() > 400,
                    "{}/{} is too thin to be useful ({} bytes)",
                    manual.prefix,
                    section.slug,
                    section.body.len(),
                );
            }
        }
    }

    #[test]
    fn slugs_are_unique_within_a_manual_and_url_safe() {
        for manual in MANUALS {
            for (index, section) in manual.sections.iter().enumerate() {
                assert!(
                    section
                        .slug
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
                    "{} is not a clean slug",
                    section.slug,
                );
                for other in manual.sections.iter().skip(index + 1) {
                    assert_ne!(section.slug, other.slug, "duplicate slug");
                }
            }
        }
    }

    #[test]
    fn manual_prefixes_are_unique() {
        for (index, manual) in MANUALS.iter().enumerate() {
            for other in MANUALS.iter().skip(index + 1) {
                assert_ne!(manual.prefix, other.prefix, "duplicate manual prefix");
            }
        }
    }

    #[test]
    fn section_bodies_carry_no_script() {
        // The docs CSP omits `script-src` entirely, so anything here would be
        // dead markup that a future CSP relaxation would silently activate.
        for manual in MANUALS {
            for section in manual.sections {
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
    }

    #[test]
    fn every_internal_documentation_link_resolves() {
        // A dead cross-reference in an API doc costs a reader real time, and
        // is exactly the kind of rot a compile-time check can prevent.
        for manual in MANUALS {
            for section in manual.sections {
                let mut rest = section.body;
                while let Some(start) = rest.find("href=\"/docs/") {
                    let tail = &rest[start + "href=\"/docs/".len()..];
                    let Some(end) = tail.find('"') else { break };
                    let target = &tail[..end];
                    rest = &tail[end..];

                    let path = target.split('#').next().unwrap_or(target);
                    let mut parts = path.split('/');
                    let prefix = parts.next().unwrap_or("");
                    if prefix.is_empty() {
                        continue; // the landing page
                    }
                    let Some(other) = MANUALS.iter().find(|entry| entry.prefix == prefix) else {
                        panic!(
                            "{}/{} links to an unknown manual: {prefix}",
                            manual.prefix, section.slug,
                        );
                    };
                    let slug = parts.next().unwrap_or("");
                    if slug.is_empty() {
                        continue; // that manual's contents page
                    }
                    assert!(
                        other.find(slug).is_some(),
                        "{}/{} links to a missing section: {prefix}/{slug}",
                        manual.prefix,
                        section.slug,
                    );
                }
            }
        }
    }

    #[test]
    fn the_embedded_contract_is_the_real_one() {
        assert!(OPENAPI.starts_with("openapi: 3.1"));
        assert!(OPENAPI.contains("title: Silicon IAM API"));
    }
}
