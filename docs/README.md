# Silicon IAM integration documentation

This is the first official Silicon IAM v1 contract. The public documentation is hosted at [docs.iam.teamofsilicons.com](https://docs.iam.teamofsilicons.com/).

Applications declare the IAM information and external endpoints they need. Critical permissions go through review. Users authenticate in IAM, approve the application's current permissions, and choose which organizations to share. The application receives an app-bound short-lived token, never IAM credentials or verification codes.

## Start here

| Task | Guide |
| --- | --- |
| Understand the HTTP contract | [API reference](API_DOCS.md) and [OpenAPI](openapi.yaml) |
| Register an application and request permissions | [Applications](api/applications.html) |
| Implement permission and organization consent | [Consent](ORGANIZATION_CONSENT.md) |
| Sign in to several applications | [Batch login](BATCH_LOGIN.md) or [bundles](BUNDLES.md) |
| Call an external application for a user | [OBO](api/obo.html) |
| Keep authorization caches current | [Webhooks](api/webhooks.html) |
| Test without production data | [Testing environments](api/testing-environments.html) |
| Use the official Rust integration client | [Rust client](client/README.md) |
| Use the command-line client | [CLI](cli/README.md) and [credential storage](cli/storage.md) |
| Run the IAM console and authentication UI | [Frontend](frontend/README.md) |

## Service addresses

| Surface | Address |
| --- | --- |
| HTTP API | `https://backend.iam.teamofsilicons.com` |
| IAM login and signup | `https://auth.iam.teamofsilicons.com` |
| Organization console | `https://iam.teamofsilicons.com` |
| Documentation | `https://docs.iam.teamofsilicons.com` |

Negotiate an API major with `GET /api/version` before versioned calls. Inspect `GET /api/v1/contracts` for the current contract catalog and lifecycle policy. The API major and published SDK/CLI package versions are separate version numbers.

## Documentation sources and build

[openapi.yaml](openapi.yaml) specifies request and response shapes. The API and client guides are controlled HTML fragments; Markdown guides provide longer workflows. The static site publishes root `/api/`, `/client/`, `/cli/`, and `/frontend/` paths. It contains no application credentials and is deployed independently from the authenticated IAM frontend.

From the repository root:

```sh
npm --prefix docs-site ci
npm --prefix docs-site run build
npm --prefix docs-site run check
ruby scripts/generate-cli-docs.rb
ruby scripts/generate-cli-docs.rb --check
ruby scripts/check-openapi-routes.rb
```

The static host's deployment configuration is in `docs-site/`. The CLI packages generated offline manuals so `iam docs` works without the documentation host. Historical fix reports and deployment/QA logs remain repository evidence and are excluded from the public site and packaged manuals.
