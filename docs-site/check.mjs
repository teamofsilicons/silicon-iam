import { access, readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const output = join(dirname(fileURLToPath(import.meta.url)), "dist");
const origin = "https://docs.iam.teamofsilicons.com";
const pages = new Map();
async function collect(directory) {
  for (const item of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, item.name);
    if (item.isDirectory()) await collect(path);
    else if (path.endsWith(".html")) pages.set(path, await readFile(path, "utf8"));
  }
}
await collect(output);
const failures = new Set();
// Check the emitted routes independently of the collector so a future export
// regression cannot publish an operator record while still passing link checks.
const evidenceRoute = /(?:^|\/)(?:release-readiness-[^/]+|iam-redesign-[^/]+|deployment-verification-[^/]+|integration-fixes-[^/]+|session-bound-consent-fix|private-application-login-errors|honeycomb-implementation|provider-email-authentication|frontend\/(?:deployment|manual-qa|scope-approvals))\//;
const sitemap = await readFile(join(output, "sitemap.xml"), "utf8");
for (const [, route] of sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)) {
  if (evidenceRoute.test(new URL(route).pathname)) failures.add(`sitemap: internal evidence route ${route}`);
}
for (const route of ["api/obo/index.html", "client/obo/index.html", "obo-cutover/index.html"]) {
  if (!pages.has(join(output, route))) failures.add(`${route}: required public OBO integration guide is missing`);
}
for (const [file, body] of pages) {
  if (evidenceRoute.test(file.slice(output.length))) failures.add(`${file}: internal evidence in public documentation`);
  if (/\btrusted_org\b|\bskip_consent\b|\bskip_application_consent\b|\ballow_bundled_applications\b|\bbundles_enabled\b/.test(body)) failures.add(`${file}: internal organization policy in public documentation`);
  if (!body.includes(`rel="canonical" href="${origin}/`)) failures.add(`${file}: missing canonical documentation origin`);
  if (/<script\b/i.test(body)) failures.add(`${file}: documentation must not execute scripts`);
  for (const [, raw] of body.matchAll(/(?:href|src)="([^"]*)"/g)) {
    const href = raw.replaceAll("&amp;", "&");
    if (!href || (!href.startsWith("/") && !href.startsWith("#"))) continue;
    const currentPath = file.slice(output.length).replace(/index\.html$/, "");
    const url = new URL(href, origin + currentPath);
    const path = decodeURIComponent(url.pathname);
    const target = resolve(output, `.${path.endsWith("/") ? `${path}index.html` : path}`);
    if (!target.startsWith(`${output}/`)) { failures.add(`${file}: path escapes site: ${href}`); continue; }
    try {
      await access(target);
      if (url.hash && pages.has(target)) {
        const id = decodeURIComponent(url.hash.slice(1));
        const ids = [...pages.get(target).matchAll(/\b(?:id|name)="([^"]*)"/g)].map((match) => match[1]);
        if (!ids.includes(id)) failures.add(`${file}: missing section ${href}`);
      }
    } catch { failures.add(`${file}: missing local target ${href}`); }
  }
}
if (failures.size) {
  console.error([...failures].join("\n"));
  process.exitCode = 1;
} else console.log(`Checked ${pages.size} documentation pages: links, sections, assets, canonical origin, and public content boundaries pass.`);
