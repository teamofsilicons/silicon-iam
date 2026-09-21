import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import MarkdownIt from "markdown-it";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const docs = join(root, "docs");
const output = join(here, "dist");
export const origin = "https://docs.iam.teamofsilicons.com";
const markdown = new MarkdownIt({ html: true });
const escape = (text) => String(text).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
const plain = (html) => markdown.utils.unescapeAll(html.replace(/<[^>]*>/g, "")).replace(/&amp;/g, "&").replace(/&gt;/g, ">").replace(/&lt;/g, "<").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
const slug = (text) => plain(text).toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, "").trim().replace(/\s+/g, "-");
const api = ["overview", "authentication", "conventions", "carbons", "organizations", "silicons", "governance", "applications", "webhooks", "obo", "testing-environments", "errors"];
const client = ["overview", "connecting", "updates", "login", "tokens", "obo", "webhooks", "testing-environments", "errors"];
const label = (text) => text.replaceAll("-", " ").replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
const titles = { obo: "On-behalf-of access", "testing-environments": "Testing environments", authentication: "Authentication", login: "Application login", conventions: "Request conventions" };
const pages = [];
const historical = new Set(["INTEGRATION_FIXES_2026-09-05.md", "SESSION_BOUND_CONSENT_FIX.md", "frontend/deployment.md", "frontend/manual-qa.md"]);
async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await collect(path);
    else if ([".md", ".html"].includes(extname(path))) {
      const source = relative(docs, path);
      if (historical.has(source)) continue;
      const file = entry.name.replace(/\.(md|html)$/, "");
      let route = `/docs/${source.replace(/\.(md|html)$/, "").toLowerCase().replaceAll("_", "-")}/`;
      if (source === "README.md") route = "/docs/source-guide/";
      else if (source === "client/README.md") route = "/docs/client/guide/";
      else if (file === "README") route = `/docs/${relative(docs, directory)}/`;
      const raw = await readFile(path, "utf8");
      const title = extname(path) === ".md" ? (raw.match(/^#\s+(.+)$/m)?.[1] || label(file)) : (titles[file] || label(file));
      pages.push({ source, route, title, body: extname(path) === ".md" ? markdown.render(raw) : raw });
    }
  }
}
await collect(docs);
for (const page of pages) page.route = page.route.replace(/^\/docs\//, "/");
const bySource = new Map(pages.map((page) => [page.source, page.route]));
const groups = [
  { title: "HTTP API", route: "/api/", items: [...api.map((item) => pages.find((page) => page.source === `api/${item}.html`)), ...["IAM_SCOPES.md", "SCOPED_BACKEND.md"].map((source) => pages.find((page) => page.source === source))].filter(Boolean) },
  { title: "Rust client", route: "/client/", items: client.map((item) => pages.find((page) => page.source === `client/${item}.html`)).filter(Boolean) },
  { title: "CLI", route: "/cli/", items: pages.filter((page) => page.source.startsWith("cli/")) },
  { title: "Frontend", route: "/frontend/", items: pages.filter((page) => page.source.startsWith("frontend/")) },
];
for (const group of groups.slice(0, 2)) pages.push({ route: group.route, title: group.title, body: `<p class="lede">${group.title === "HTTP API" ? "The IAM contract, from authentication to delegated access." : "Build an application integration with the official stateless Rust client."}</p><div class="cards">${group.items.map((page) => `<a href="${page.route}"><h2>${escape(page.title)}</h2><span>Read guide →</span></a>`).join("")}</div>` });
pages.push({ route: "/", title: "Silicon IAM documentation", body: `<p class="eyebrow">SILICON IAM · DEVELOPER DOCUMENTATION</p><h1>Use and build with Silicon IAM.</h1><h2>Install and use IAM</h2><pre><code>curl -fsSL https://docs.iam.teamofsilicons.com/install.sh | sh
iam iam --json
iam login --carbon-id &lt;your-carbon-id&gt;
iam login status --json</code></pre><p>The installer sets up the CLI without logging in. Honeycomb manages CLI updates. Current client and CLI release: 3.1.0. <a href="/cli/">Usage guide</a> · <a href="/building/">Step-by-step builder guide</a></p><p class="lede">Authenticate Carbons and Silicons, share only approved information, and connect applications through scoped delegation.</p><div class="notice"><strong>Your application receives a short-lived token.</strong> IAM credentials and verification codes stay in IAM. Exchange each token on your application server using that application’s secret.</div><div class="cards">${groups.map((group) => `<a href="${group.route}"><h2>${group.title}</h2><span>Explore documentation →</span></a>`).join("")}</div><h2>Start an integration</h2><ol><li><a href="/docs/api/applications/">Register your application</a> and declare IAM and external application permissions.</li><li><a href="/docs/client/login/">Send users through IAM login</a>, permission consent, and organization selection.</li><li><a href="/docs/api/webhooks/">Verify webhooks</a> to keep authorization current.</li><li><a href="/docs/api/testing-environments/">Test the complete flow</a> in an isolated environment.</li></ol><p><a href="/openapi.yaml">Download the OpenAPI contract</a> · <a href="https://backend.iam.teamofsilicons.com/api/v1/version">Check the running backend version</a></p>` });

function links(body, source) {
  return body.replace(/href="([^"]*)"/g, (whole, raw) => {
    const href = raw.replaceAll("&amp;", "&");
    if (!href || href.startsWith("#") || /^(mailto:|tel:)/.test(href)) return whole;
    let target = href.replace(/^https:\/\/backend\.iam\.teamofsilicons\.com(?=\/(docs|openapi\.yaml))/, "");
    target = target.replace(/^https:\/\/docs\.iam\.teamofsilicons\.com(?=\/)/, "");
    if (/^https?:/.test(target)) return `href="${escape(target)}"`;
    const parsed = new URL(target, `${origin}/docs/${source || "README.md"}`);
    if (!target.startsWith("/")) {
      const key = decodeURIComponent(parsed.pathname.replace(/^\/docs\//, ""));
      if (bySource.has(key)) parsed.pathname = bySource.get(key);
      else if (["openapi.yaml", "scoped-auth-openapi.yaml"].includes(key)) parsed.pathname = `/${key}`;
      else if (!parsed.pathname.startsWith("/docs/")) return `href="${escape(`https://github.com/teamofsilicons/silicon-iam/blob/main${parsed.pathname}${parsed.hash}`)}"`;
    }
    if (parsed.pathname === "/docs" || parsed.pathname === "/docs/") parsed.pathname = "/";
    parsed.pathname = parsed.pathname.replace(/^\/docs\//, "/");
    if (!extname(parsed.pathname) && !parsed.pathname.endsWith("/")) parsed.pathname += "/";
    return `href="${escape(parsed.pathname + parsed.search + parsed.hash)}"`;
  });
}
function document(page) {
  const headingCounts = new Map();
  const toc = [];
  let body = links(page.body, page.source).replace(/<h([1-6])([^>]*)>([\s\S]*?)<\/h\1>/g, (whole, level, attributes, content) => {
    let id = attributes.match(/\bid="([^"]+)"/)?.[1];
    if (!id) {
      const base = slug(content); const count = headingCounts.get(base) || 0;
      headingCounts.set(base, count + 1); id = `${base}${count ? `-${count}` : ""}`;
      attributes += ` id="${escape(id)}"`;
    }
    if (level === "2") toc.push({ id, title: plain(content) });
    return `<h${level}${attributes}>${content}</h${level}>`;
  });
  if (!body.includes("<h1")) body = `<h1>${escape(page.title)}</h1>${body}`;
  const nav = groups.map((group) => `<details ${page.route.startsWith(group.route) ? "open" : ""}><summary><a href="${group.route}">${group.title}</a></summary>${group.items.map((item) => `<a ${page.route === item.route ? 'aria-current="page"' : ""} href="${item.route}">${escape(item.title)}</a>`).join("")}</details>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(page.title)} · Silicon IAM</title><meta name="description" content="${escape(`${page.title} — Silicon IAM API, client, CLI and application integration documentation.`)}"><link rel="canonical" href="${origin}${page.route}"><link rel="icon" href="/assets/mark.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/site.css"></head><body><a class="skip" href="#content">Skip to content</a><header class="top"><a class="brand" href="/"><img src="/assets/mark.svg" width="28" height="28" alt="">Silicon <strong>IAM</strong><span>Docs</span></a><nav aria-label="Product navigation"><a href="/openapi.yaml">OpenAPI</a><a href="https://iam.teamofsilicons.com">Console ↗</a></nav></header><div class="layout"><aside class="sidebar"><nav aria-label="Documentation"><a href="/">Documentation home</a>${nav}</nav></aside><main id="content">${body}<h2>Install the CLI</h2><pre><code>curl -fsSL https://docs.iam.teamofsilicons.com/install.sh | sh</code></pre><footer>Silicon IAM · <a href="https://github.com/teamofsilicons/silicon-iam">Source repository</a></footer></main><aside class="on-this-page" aria-label="On this page"><strong>On this page</strong>${toc.map((item) => `<a href="#${escape(item.id)}">${escape(item.title)}</a>`).join("")}</aside></div></body></html>`;
}
await rm(output, { recursive: true, force: true });
await mkdir(join(output, "assets"), { recursive: true });
await cp(join(root, "scripts/install.sh"), join(output, "install.sh"));
await cp(join(here, "site.css"), join(output, "assets/site.css"));
for (const asset of ["mark.svg", "plex-sans.woff2", "plex-mono.woff2"]) await cp(join(root, "frontend/public/brand", asset), join(output, "assets", asset));
for (const page of pages) {
  const directory = join(output, page.route);
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "index.html"), document(page));
}
await cp(join(docs, "openapi.yaml"), join(output, "openapi.yaml"));
await cp(join(docs, "scoped-auth-openapi.yaml"), join(output, "scoped-auth-openapi.yaml"));
await writeFile(join(output, "robots.txt"), `User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`);
await writeFile(join(output, "sitemap.xml"), `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${pages.map((page) => `<url><loc>${origin}${page.route}</loc></url>`).join("")}</urlset>`);
await writeFile(join(output, "404.html"), document({ route: "/404.html", title: "Page not found", body: '<p>This documentation page does not exist.</p><p><a href="/">Return to documentation home</a></p>' }));
console.log(`Built ${pages.length} pages for ${origin} in docs-site/dist.`);
