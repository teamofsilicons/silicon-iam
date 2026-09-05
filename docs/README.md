# Silicon IAM integration documentation

Everything an application developer or operator needs to integrate with
Silicon IAM lives in this directory. The product authority remains
[`UNDERSTANDING.md`](../UNDERSTANDING.md); this directory turns that authority
into public contracts, runnable examples, and client guidance.

## Start here

| Need | Document |
| --- | --- |
| Understand HTTP behavior and security semantics | [`API_DOCS.md`](./API_DOCS.md) |
| Add IAM login to an external app: Briefcase example | [`API_DOCS.md#example-external-application-login`](./API_DOCS.md#example-external-application-login) |
| Generate a client or inspect the normative wire contract | [`openapi.yaml`](./openapi.yaml) |
| Use the `iam` command-line client | [`cli/README.md`](./cli/README.md) |
| Upgrade an existing CLI home or diagnose local logout | [`cli/storage.md`](./cli/storage.md) |
| Integrate through the official Rust client | [`client/README.md`](./client/README.md) |
| Browse the rendered API manual sources | [`api/`](./api/) |
| Browse the rendered Rust-client manual sources | [`client/`](./client/) |

## Feature guides

The [2026-09-05 integration-fix report](INTEGRATION_FIXES_2026-09-05.md)
records the 1.2.0 contracts, local manual verification and required rollout order.
The matching backend, migration `0067`, testing overlay `9003` and runtime grants
must be deployed and verified before publishing/adopting the client/CLI packages.

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

### CLI 1.2.2; client remains 1.2.1

CLI **1.2.2** adds bounded recovery when opening a Unix lock file transiently
returns `ENOENT` or `EINTR`. It makes at most six open attempts with 31
milliseconds of scheduled backoff, retains the pinned-directory/no-follow
safety checks, and rejects removed or replaced lock identities. Persistent
errors still fail; no command proceeds without acquiring its lock.

The [storage guide](cli/storage.md#version-122-bounded-unix-lock-open-recovery)
records the reproduced 1.2.1 failures, 480 successful concurrent logouts with
the fix, controlled-fault checks, and the remaining uncertainty about the
underlying platform cause. CLI 1.2.2 retains the commands and contracts of
1.2.1. The Rust client remains **1.2.1**; this patch changes no API/client
contract and needs no new database migration.

- [CLI release source tagged `v1.2.2`](https://github.com/teamofsilicons/silicon-iam/tree/v1.2.2)
- [CLI 1.2.2 source](https://github.com/teamofsilicons/silicon-iam/tree/v1.2.2/crates/cli) and [manual](https://github.com/teamofsilicons/silicon-iam/blob/v1.2.2/docs/cli/README.md)
- [Version-pinned 1.2.2 integration documentation](https://github.com/teamofsilicons/silicon-iam/tree/v1.2.2/docs)
- [Unchanged client 1.2.1 source](https://github.com/teamofsilicons/silicon-iam/tree/v1.2.1/crates/client) and [manual](https://github.com/teamofsilicons/silicon-iam/blob/v1.2.1/docs/client/README.md)

### CLI/client 1.2.1

Release **1.2.1** includes these CLI fixes:

- Clearing all membership tags reports `Tags cleared.` instead of an empty list.
- A local configuration or state-access failure no longer produces the same
  error again during post-command automatic maintenance.
- Logout diagnostics distinguish an unconfirmed local removal from a remote
  logout that succeeded before local persistence failed.
- `iam login` requires an identity or `--app-id` at argument parsing, with the
  exact command help surfacing the missing input before accessing local state.
- `iam app approve-webhook <app-id>` activates a verified Application's pending
  endpoint with current owning-org owner/admin or platform review authority,
  and verified-channel step-up bound to that Application.

Client 1.2.1 adds `applications().approve_webhook(...)` and the
`application.webhook.approve` step-up action, alongside updated packaged
documentation and release provenance. Deploy the matching webhook-approval
backend before using this new method or CLI command. HTTP API major remains
`v1`, and the authorization/OBO contracts introduced in 1.2.0 still require the
matching backend, migration `0067`, testing overlay `9003` and runtime grants.
The isolated unsuccessful logout reported in the 1.2.0 audit remains
unexplained; improved diagnostics are not a claim that its cause was fixed.

- [Release source tagged `v1.2.1`](https://github.com/teamofsilicons/silicon-iam/tree/v1.2.1)
- [Version-pinned integration documentation](https://github.com/teamofsilicons/silicon-iam/tree/v1.2.1/docs)
- [CLI 1.2.1 source](https://github.com/teamofsilicons/silicon-iam/tree/v1.2.1/crates/cli) and [manual](https://github.com/teamofsilicons/silicon-iam/blob/v1.2.1/docs/cli/README.md)
- [Client 1.2.1 source](https://github.com/teamofsilicons/silicon-iam/tree/v1.2.1/crates/client) and [manual](https://github.com/teamofsilicons/silicon-iam/blob/v1.2.1/docs/client/README.md)

The tag identifies the packaged source revision; each crate's
`.cargo_vcs_info.json` records its exact commit. Updating `main` does not modify
an installed or published crate.

### Original CLI/client 1.2.0 provenance

The published `silicon-iam-cli` and `silicon-iam-client` **1.2.0** packages both
record source commit `ec04ec92444e02c88a39c83a286dbf47b5ded458` in their packaged
`.cargo_vcs_info.json`. These permanent links identify that release independently
of changes to GitHub's default branch:

- [Complete release source](https://github.com/teamofsilicons/silicon-iam/tree/ec04ec92444e02c88a39c83a286dbf47b5ded458)
- [Release tag `v1.2.0`](https://github.com/teamofsilicons/silicon-iam/tree/v1.2.0), pointing to that same published-source commit
- [Version-pinned integration documentation](https://github.com/teamofsilicons/silicon-iam/tree/ec04ec92444e02c88a39c83a286dbf47b5ded458/docs)
- [CLI 1.2.0 source](https://github.com/teamofsilicons/silicon-iam/tree/ec04ec92444e02c88a39c83a286dbf47b5ded458/crates/cli) and [CLI 1.2.0 manual](https://github.com/teamofsilicons/silicon-iam/blob/ec04ec92444e02c88a39c83a286dbf47b5ded458/docs/cli/README.md)
- [Client 1.2.0 source](https://github.com/teamofsilicons/silicon-iam/tree/ec04ec92444e02c88a39c83a286dbf47b5ded458/crates/client) and [client 1.2.0 manual](https://github.com/teamofsilicons/silicon-iam/blob/ec04ec92444e02c88a39c83a286dbf47b5ded458/docs/client/README.md)

The CLI fixes listed for 1.2.1 and 1.2.2 are not included in these original
1.2.0 packages.

Existing Unix homes created with mode `0755` require a one-time permission repair
when upgrading. Verify the directory and its ownership before applying the
[documented `0700` repair](cli/storage.md#upgrading-an-existing-iam-home); do not
replace the home, erase credentials, or bypass the safety checks.

### Running service

The release image embeds the HTML manuals and OpenAPI document from this
directory, so production documentation always matches the running binary:

- [Documentation home](https://backend.iam.teamofsilicons.com/docs)
- [API manual](https://backend.iam.teamofsilicons.com/docs/api/)
- [Rust client manual](https://backend.iam.teamofsilicons.com/docs/client/)
- [OpenAPI contract](https://backend.iam.teamofsilicons.com/openapi.yaml)

The Markdown package guides are the source used for crate metadata. Keep CLI,
client, and raw-HTTP examples aligned whenever an operation changes.

Source changes are not automatically deployed or published. Check `iam --version`
for the installed CLI, `iam system version` for the configured backend's build
and commit, and the resolved `silicon-iam-client` entry in your app's `Cargo.lock`
for the library actually used. GitHub's default-branch docs, another branch's
source, crates.io releases, and the deployed embedded manuals can refer to
different revisions; validate against the revision you are running. Unreleased
local fixes are not available to installed clients until a release is explicitly
published and adopted.
