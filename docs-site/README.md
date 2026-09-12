# Silicon IAM documentation site

This static site publishes the repository’s API, Rust client, CLI, and frontend
manuals at **https://docs.iam.teamofsilicons.com**. The API and client HTML
fragments remain shared with the backend’s embedded manuals. Markdown guides
are rendered at build time; the deployed site runs no JavaScript or API server.

From `docs-site/`, using Node 24:

```sh
npm ci
npm run build
npm run check
python3 -m http.server 4320 --directory dist --bind 127.0.0.1
```

Open http://127.0.0.1:4320. The generated `dist/` directory contains the entire
site, local fonts, OpenAPI contract, sitemap, robots policy, and 404 page.
Canonical URLs always use `docs.iam.teamofsilicons.com`.

For Vercel, create a project whose root directory is `docs-site`, enable access
to source files outside the root directory, and use the checked-in
`vercel.json`. Set the project’s Node version to 24.x and attach
`docs.iam.teamofsilicons.com`; follow the DNS target shown by the hosting
provider. This site needs no IAM secrets or environment variables. Build
and deploy it from the same release revision as the API and client. The
configuration is prepared; building locally does not deploy or change DNS.

Other static hosts can publish `dist/` directly with directory index serving.
Apply the response headers from `vercel.json` and redirect `/docs` to `/` and `/docs/:path` to `/:path`.

The checker verifies generated local page links, section anchors, assets, and canonical URLs, and rejects public
documentation that exposes internal organization-policy configuration.
