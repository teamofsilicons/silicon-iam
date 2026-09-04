# Silicon IAM integration documentation

Everything an application developer or operator needs to integrate with
Silicon IAM lives in this directory. The product authority remains
[`UNDERSTANDING.md`](../UNDERSTANDING.md); this directory turns that authority
into public contracts, runnable examples, and client guidance.

## Start here

| Need | Document |
| --- | --- |
| Understand HTTP behavior and security semantics | [`API_DOCS.md`](./API_DOCS.md) |
| Generate a client or inspect the normative wire contract | [`openapi.yaml`](./openapi.yaml) |
| Use the `iam` command-line client | [`cli/README.md`](./cli/README.md) |
| Integrate through the official Rust client | [`client/README.md`](./client/README.md) |
| Browse the rendered API manual sources | [`api/`](./api/) |
| Browse the rendered Rust-client manual sources | [`client/`](./client/) |

## Feature guides

| Topic | Raw API guide | Client or CLI guide |
| --- | --- | --- |
| Carbon accounts and session lifecycle | [`api/carbons.html`](./api/carbons.html) | [`client/README.md`](./client/README.md#what-the-api-groups-look-like) |
| Organizations, membership directory, and SSO | [`api/organizations.html`](./api/organizations.html) | [`client/README.md`](./client/README.md#what-the-api-groups-look-like) |
| Silicon identity lifecycle | [`api/silicons.html`](./api/silicons.html) | [`client/README.md`](./client/README.md#what-the-api-groups-look-like) |
| Tags, trust, and governance | [`api/governance.html`](./api/governance.html) | [`client/README.md`](./client/README.md#what-the-api-groups-look-like) |
| Applications and qualified Application IDs | [`api/applications.html`](./api/applications.html) | [`client/overview.html`](./client/overview.html) |
| Authentication and tokens | [`api/authentication.html`](./api/authentication.html) | [`client/login.html`](./client/login.html), [`client/tokens.html`](./client/tokens.html) |
| On-behalf-of access | [`api/obo.html`](./api/obo.html) | [`client/obo.html`](./client/obo.html) |
| Webhook delivery and verification | [`api/webhooks.html`](./api/webhooks.html) | [`client/webhooks.html`](./client/webhooks.html) |
| Testing environments | [`api/testing-environments.html`](./api/testing-environments.html) | [`client/testing-environments.html`](./client/testing-environments.html) |
| Manual end-to-end Application proof | [`api/testing-environments.html`](./api/testing-environments.html) | [`cli/README.md`](./cli/README.md#end-to-end-application-proof-in-a-test-environment) |
| Errors and recovery | [`api/errors.html`](./api/errors.html) | [`client/errors.html`](./client/errors.html) |
| Automatic crate updates | — | [`client/updates.html`](./client/updates.html) |

## Published documentation

The release image embeds the HTML manuals and OpenAPI document from this
directory, so production documentation always matches the running binary:

- [Documentation home](https://backend.iam.teamofsilicons.com/docs)
- [API manual](https://backend.iam.teamofsilicons.com/docs/api/)
- [Rust client manual](https://backend.iam.teamofsilicons.com/docs/client/)
- [OpenAPI contract](https://backend.iam.teamofsilicons.com/openapi.yaml)

The Markdown package guides are the source used for crate metadata. Keep CLI,
client, and raw-HTTP examples aligned whenever an operation changes.
