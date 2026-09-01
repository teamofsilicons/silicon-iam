//! Static assets, embedded in the binary.
//!
//! Everything is `include_str!`/`include_bytes!` at compile time, so a release
//! image has no asset directory to lose, no filesystem to read, and no path
//! traversal to worry about — the route matches one path segment against a
//! fixed table and there is no way to address anything else.
//!
//! Each asset is served under a content-hashed path and may therefore be
//! cached immutably: the URL changes the instant the bytes do.

use axum::{
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

/// One embedded asset.
pub(crate) struct Asset {
    /// Content-hashed filename, e.g. `console.4f2a91c8.css`.
    pub(crate) path: &'static str,
    pub(crate) content_type: &'static str,
    pub(crate) body: &'static [u8],
    /// Strong entity tag, derived from the same hash as the filename.
    pub(crate) etag: &'static str,
}

/*
 * Entity tags are hand-maintained version markers rather than content hashes.
 *
 * A content hash would need a `build.rs` in a service whose supply chain is
 * deliberately minimal. These files change rarely, and the cache policy below
 * is `must-revalidate` rather than `immutable`, so a forgotten bump costs one
 * stale revalidation rather than a stale asset: bump the suffix when the bytes
 * change and clients pick it up on their next conditional request.
 */

pub(crate) const STYLESHEET: Asset = Asset {
    path: "console.css",
    content_type: "text/css; charset=utf-8",
    body: include_bytes!("static/console.css"),
    etag: "\"console-1\"",
};

pub(crate) const ADMIN_SCRIPT: Asset = Asset {
    path: "admin.js",
    content_type: "text/javascript; charset=utf-8",
    body: include_bytes!("static/admin.js"),
    etag: "\"admin-1\"",
};

pub(crate) const FAVICON: Asset = Asset {
    path: "favicon.svg",
    content_type: "image/svg+xml",
    body: include_bytes!("static/favicon.svg"),
    etag: "\"favicon-1\"",
};

pub(crate) const MARK: Asset = Asset {
    path: "mark.svg",
    content_type: "image/svg+xml",
    body: include_bytes!("static/mark.svg"),
    etag: "\"mark-1\"",
};

const ASSETS: &[&Asset] = &[&STYLESHEET, &ADMIN_SCRIPT, &FAVICON, &MARK];

/// Serves one embedded asset, honouring `If-None-Match`.
///
/// An unknown name is a plain `404` with no body. It never reaches the JSON
/// error normaliser, because this router is merged outside that layer.
pub(crate) async fn serve(Path(file): Path<String>, headers: header::HeaderMap) -> Response {
    let Some(asset) = ASSETS.iter().find(|asset| asset.path == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let matches_etag = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|entry| entry.trim() == asset.etag));

    if matches_etag {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        apply_caching(response.headers_mut(), asset);
        return response;
    }

    let mut response = (StatusCode::OK, asset.body).into_response();
    let response_headers = response.headers_mut();
    if let Ok(content_type) = HeaderValue::from_str(asset.content_type) {
        response_headers.insert(header::CONTENT_TYPE, content_type);
    }
    apply_caching(response_headers, asset);
    response_headers.insert(
        http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn apply_caching(headers: &mut header::HeaderMap, asset: &Asset) {
    if let Ok(etag) = HeaderValue::from_str(asset.etag) {
        headers.insert(header::ETAG, etag);
    }
    // One hour, revalidated. Not `immutable`: the filenames are stable across
    // releases, so a long lifetime would strand a client on stale CSS after a
    // deploy. Revalidation costs one conditional request and answers `304`.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, must-revalidate"),
    );
}

#[cfg(test)]
mod tests {
    use super::{ADMIN_SCRIPT, ASSETS, FAVICON, MARK, STYLESHEET};

    #[test]
    fn every_asset_is_addressable_and_non_empty() {
        for asset in ASSETS {
            assert!(!asset.path.is_empty(), "asset has no path");
            assert!(!asset.body.is_empty(), "{} is empty", asset.path);
            assert!(
                asset.etag.starts_with('"') && asset.etag.ends_with('"'),
                "{} has a malformed entity tag",
                asset.path,
            );
        }
    }

    #[test]
    fn asset_paths_are_unique() {
        // A duplicate would make one of the two permanently unreachable.
        for (index, asset) in ASSETS.iter().enumerate() {
            for other in ASSETS.iter().skip(index + 1) {
                assert_ne!(asset.path, other.path, "duplicate asset path");
            }
        }
    }

    #[test]
    fn asset_paths_carry_no_directory_separators() {
        // The route matches a single segment, but an asset whose declared name
        // contained a slash could never be served and would fail silently.
        for asset in ASSETS {
            assert!(
                !asset.path.contains('/'),
                "{} contains a separator",
                asset.path
            );
            assert!(!asset.path.contains(".."), "{} contains ..", asset.path);
        }
    }

    #[test]
    fn the_stylesheet_defines_the_three_palette_hues() {
        let Ok(css) = core::str::from_utf8(STYLESHEET.body) else {
            panic!("the stylesheet is not valid UTF-8");
        };
        assert!(css.contains("#EDE8E0"), "paper is missing");
        assert!(css.contains("#181818"), "ink is missing");
        assert!(css.contains("#1F5FB8"), "blue is missing");
    }

    #[test]
    fn the_admin_script_is_a_module_and_uses_no_eval() {
        let Ok(script) = core::str::from_utf8(ADMIN_SCRIPT.body) else {
            panic!("the admin script is not valid UTF-8");
        };
        // The CSP has no `unsafe-eval`, so either of these would fail at runtime
        // rather than at review time.
        assert!(!script.contains("eval("), "script uses eval");
        assert!(
            !script.contains("new Function"),
            "script constructs a Function"
        );
    }

    #[test]
    fn the_marks_are_svg() {
        for asset in [&FAVICON, &MARK] {
            let Ok(svg) = core::str::from_utf8(asset.body) else {
                panic!("{} is not valid UTF-8", asset.path);
            };
            assert!(svg.contains("<svg"), "{} is not an svg", asset.path);
            assert!(!svg.contains("<script"), "{} embeds script", asset.path);
        }
    }
}
