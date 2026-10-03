# silicon-iam-cli

Silicon IAM from the command line. Installs a single binary, `iam`, built only on the
stateless `silicon-iam-client` Rust package. This guide describes the current official contract.
The hosted manual is [docs.iam.teamofsilicons.com/cli](https://docs.iam.teamofsilicons.com/cli).

For local session safety and storage precedence, see [credential storage](storage.md).
Use `iam --help` for a concise overview, `iam app scopes --help` for scope reviews,
and `iam -o json commands` for machine-readable command discovery. Help and bundled docs work offline.

## Start using IAM

```sh
honeycomb install <configured-iam-app-id>
iam iam --json
iam login --carbon-id <your-carbon-id>       # Carbon: enter the IAM verification code
# Or, for a Silicon: iam silicon-login --sid <si:handle>
iam login status --json
iam --org <org> member self
```

Before Honeycomb is available, use the [direct bootstrap path](../HONEYCOMB_RELEASE.md).
The direct installer sets up Rust and IAM without starting an updater or logging in.
See `iam --help`, then a noun such as `iam app --help`,
then a verb such as `iam app create --help`. Every level includes purpose,
arguments and related documentation. `iam commands --json` exposes the tree to agents.

### Google and Apple login

The next CLI release adds `iam login --provider google` and `iam login --provider apple`.
These commands print the provider's authorization URL and wait for browser verification.
They require a configured production provider; IAM testing environments reject external
provider authentication. Already published CLI 5.0.0 artifacts do not include these flags.

A previously linked provider signs in directly. If its verified email belongs to an
existing account without that provider link, IAM sends a new email code. Enter that code
to prove the existing account before linking; an old saved session cannot authorize
this operation. The CLI stores only the independently verified IAM session and can then
issue the usual application SLT with `--app-id` and one `--grant-org`.

For a new verified email, login returns `signup_required` and a `signup_session_id`
without creating an account. Continue with `iam signup --session-id <id>`, optionally
adding `--phone`, `--carbon-id`, `--display-name`, `--timezone`, or `--photo`.
Provider verification replaces email OTP; any supplied phone still requires verification.
Polling secrets and access/refresh tokens are never printed in the normal login result.

IAM is the credential issuer: Carbon verification and Silicon SID/STK login
happen here. An application CLI must instead accept `app login '<SLT>'`, using a
token minted by `iam login --app-id 'app'` or the IAM consent website. An
app-bound SLT cannot create an unrestricted IAM session. `iam iam --json`
therefore reports `app_id: null` and `credential_issuer: true`; IAM does not
invent an application registration for itself.

`iam login status --json` validates the selected profile/environment with IAM,
refreshing when needed. It returns `authenticated: false` for an absent or
rejected session. Transport, configuration and authorization errors remain
errors so agents can distinguish a service outage from needing to log in.
No tokens are printed. `--json` is equivalent to `--output json` everywhere.

For an application integration, follow [the builder guide](../BUILDING.md).
For reasons behind the contract, see [permission and organization consent](../ORGANIZATION_CONSENT.md).

## Current authorization without waiting for a webhook

After an Application login with an explicit organization selection, use its secret and access token
to fetch current membership authority. Omit secrets from the command line to
use hidden prompts:

```sh
iam --org acme app token authorization 'checkout' --org-context acme
```

Add `--test <environment-id>` for a testing environment. `-o json` returns the
typed snapshot; text output explains membership, epoch, audience, environment,
role and tags. `app token introspect` also includes it. No directory edit or
webhook arrival is required, including after losing an application's local
projection. First select the organization with
`iam login --app-id 'checkout' --grant-org acme --approve-scopes`, then exchange the SLT.

Role disclosure requires `self.membership.read`; tag disclosure requires
`self.tags.read`. Missing scope means **undisclosed**, not a default role or
empty tags. Inactive, wrong-application and wrong-organization tokens have no
current organization authorization. A new token reaches only its selected organization
where its subject has an active membership: `iam app token authorizations` lists that scope and
`iam app token authorization --org-context` answers for one. After an IAM environment clean,
reimport/onboard and log in again; old tokens cannot restore erased authority.

Successful `app obo verify` identifies the user, organization, immediate caller,
originating app and approved endpoint. Optional identity, membership and tag disclosures
come from explicit OBO review for each selected provider account and organization,
bounded by the declared and approved scopes of every app on that path. Verification does not consume the OBO
access token; the recipient enforces payload and resource permissions on every call.

## Organization consent

Application login selects exactly one account and organization and asks for explicit
consent only when critical IAM permissions require it. OBO endpoints require separate
on-demand approval and dedicated access/refresh tokens. OBO consent selects an account
and organization per provider; one access token covers the approved dependency graph.
Only selected active memberships are returned. See [the consent guide](../ORGANIZATION_CONSENT.md).

## CLI updates

Honeycomb manages installed IAM CLI releases:

```sh
honeycomb update <configured-iam-app-id>
```

IAM never updates itself. Remove a legacy updater service with `iam daemon
uninstall`; old `iam daemon check` invocations perform no update work.
`iam system update` and enabling `auto-update` return actionable Honeycomb
instructions. Rust dependency versions follow the consuming Cargo project.
See [release packaging and direct bootstrap](../HONEYCOMB_RELEASE.md).

## Report and contribute a fix

Install [GitHub CLI](https://cli.github.com/) and run `gh auth login` once, then:

```sh
iam report 'Login fails: reproduction steps, expected and actual behavior'
iam report 'Login fails after refresh; regression test included' --pr https://github.com/teamofsilicons/silicon-iam/pull/123
```

This submits an issue to [the repository](https://github.com/teamofsilicons/silicon-iam).
The supplied report text, optional project PR link and package version are the
only submitted content. It never uploads logs, credentials or environment data,
and it never retries an uncertain submission. A report without `--pr` includes
an invitation to contribute a fix. `iam iam --json` includes repository, online
docs and package links without requiring configuration or network access.

Everything the CLI can do, the [`silicon-iam-client`](https://crates.io/crates/silicon-iam-client) crate can do —
the CLI is a shell over it and has no capability of its own. What it adds is
memory: which service, which profile, whose session, and a terminal to read a
verification code from.

## First run

```sh
iam config set url https://backend.iam.teamofsilicons.com
iam login --email you@example.com
iam config set org acme          # most commands act on an organization
iam whoami
```

The session is stored under `~/.silicon-iam/` and renewed automatically when it
is close to expiring. `iam logout` ends the current Carbon or Silicon session on IAM
and then forgets it locally. `iam logout --all` ends every session for that account;
when another active session is affected, every affected session must satisfy the
12-hour rule and the request needs account-bound `account.sessions_revoke_all`
step-up. Carbons verify an OTP; Silicons confirm their current STK.
`iam logout --local-only` only clears this device. The CLI persists a pending
remote-logout idempotency key so an identical retry can reconcile a lost response.

## Finding your way around

The installed CLI is its own interface and reference, for both people and
agents. You do not need a browser, a login, a configured profile, or network
access to discover commands or read the bundled documentation. Local help,
`iam commands` and `iam docs` do not run the automatic updater.

Commands read as noun then verb:

```sh
iam --help             # concise command and global-option overview
iam -h                 # the same concise overview
iam commands           # every command, at every depth
iam commands --json    # full help and argument metadata for every command
iam tag --help         # one group
iam tag delete --help  # one command's options
iam app create         # missing required inputs: exact create help, exit 2
iam docs               # all offline documentation topics
iam docs cli           # this complete CLI guide
iam docs applications  # registration, secrets, URLs and authorization
iam docs testing       # isolation, fixed OTPs, import and lifecycle
iam docs authorization # initial/current organization authority contract
iam docs obo           # endpoint consent and delegated access tokens
iam docs storage       # private credential files and concurrent sessions
iam docs --search 'webhook secret'
iam docs client/tokens # Rust client token lifecycle and snapshots
iam docs cli --search 'app create'
```

An incomplete command shows the help for that exact command, including required
arguments, constraints and examples. For example, `iam app create` surfaces
`--webhook-secret` alongside the other required fields; it does not attempt a
request. Required input errors exit with status `2`. Runtime errors retain
their distinct exit codes and show recovery guidance when available.

Successful commands in text mode offer relevant next commands where useful.
For example, application creation explains the returned credentials and points
to inspecting the application, minting an SLT and exchanging it. Suggestions
retain the selected service URL, profile, organization, testing environment
and custom `SILICON_HOME` / `SILICON_IAM_HOME`, so a copied follow-up stays in the same context.
They use POSIX shell quoting; production
suggestions explicitly unset `SILICON_IAM_TEST` to avoid inheriting a different
environment. They are suggestions only: the CLI does not execute them. Secret
values are not inserted into suggested commands; use the referenced help for
credential flags or supply them at an interactive terminal prompt.

### Agent and script usage

```sh
iam -o json commands                        # parser-derived command discovery
iam -o json docs                            # topic metadata and source hashes
iam -o json docs client/tokens               # full content plus provenance
iam -o json docs --search 'webhook secret'    # topics and matching excerpts
iam docs openapi > iam-openapi.yaml          # exact bundled YAML, no preamble
```

`-o json` keeps successful command output machine-readable: contextual
next-step suggestions do not contaminate the JSON result. Command discovery
comes from the installed parser, so it reflects its actual commands and
options. Documentation search is case-insensitive, treats whitespace-separated
words as terms that must occur on the same line, and returns at most three
matching excerpts per document plus the total matching-line count. Add a topic
before `--search` to limit the search. An empty query is a usage error; no matches
is a successful empty result.

Hidden prompts require both standard input and standard error to be terminals.
They write prompts to standard error, including when JSON is redirected from
standard output. In a non-interactive invocation, supply the command's
credential/code flags explicitly: a missing value fails with the exact missing
flag instead of waiting indefinitely for a hidden terminal prompt. The CLI does
not read secrets from piped standard input or open a hidden terminal to bypass
that check. Empty credentials are rejected. A stored session can still be
reused without a prompt, and local/testing responses that supply development
verification codes still work without a prompt. Carbon signup verifies an email and any optional phone. Use `iam signup --provider
google` or `--provider apple` to open provider verification in a browser while the
CLI waits. The provider's verified email skips the email OTP step. Without a
provider, use `--email`; noninteractive verification returns a `session_id` that
can be resumed with `--session-id` and `--email-code` or `--phone-code`. Omit
`--phone` to skip the optional number, or use `--skip-phone` when resuming.
Keep secret-bearing command lines and JSON credential responses out of shell
traces, CI logs and agent transcripts.

The offline manuals include the complete public HTTP reference and OpenAPI
contract, the Rust client guide, all API/client feature guides and this CLI
guide. HTML guides are bundled as terminal-readable Markdown with code blocks
and tables preserved. `iam docs` lists aliases and exact topic names. JSON
metadata includes each canonical source path and its SHA-256 so an integrator
can identify the documentation that was packaged. The content belongs to the
installed binary's source revision; it is not fetched from GitHub or the running
service. Compare `iam --version` and `iam system version` when investigating a
service contract mismatch.

For maintainers, edit the canonical files under `docs/`, then run
`ruby scripts/generate-cli-docs.rb`. Verify with
`ruby scripts/generate-cli-docs.rb --check` before a release. Generated assets
live inside the CLI crate, so installed/package builds need neither the
repository's `docs/` directory nor a documentation generator.

## Complete command reference

This guide covers the current command tree; `iam commands` reports the installed version's exact capabilities. Angle
brackets mark required values; square brackets mark optional values. A row for
a noun such as `iam member` is a help namespace and requires one of the listed
subcommands. Run `iam <command> --help` for every flag, accepted value, default,
and generated usage line.

Global `--org` wins over `SILICON_IAM_ORG` and the profile default. `--no-org`
ignores both environment and stored organization defaults; it conflicts only
with an explicitly supplied `--org`. `--test <environment-uuid>` selects an
isolated plane by its public, hyphenated UUID—never put its root key on the
command line. Options may appear before or after positional identifiers. Application IDs are bare handles such as `billing`; bundle IDs retain
`org>bundle` and must be quoted in a shell.

### Authentication and top-level commands

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam login` | Exactly one of `--email`, `--phone`, or `--carbon-id`, or `--app-id` to reuse a stored session; the code is prompted unless `--code` is given | Carbon login. `--app-id` without an identity reuses the existing session to mint an SLT; with an identity it first signs in. A bare `iam login` is incomplete even when signed in. It never logs the Application in directly. |
| `iam silicon-login` | Silicon ID and STK at flags/prompts, or only `--app-id` with a stored Silicon session | `--app-id` mints an SLT; omit both credentials to reuse the current Silicon session. The global `si:handle` does not select an organization; use `--grant-org` for app login. |
| `iam logout` | None | Ends the current Carbon or Silicon session remotely. `--local-only` and `--all` conflict. `--all` uses step-up action `account.sessions_revoke_all` on the account principal ID, and affected sessions must satisfy the 12-hour rule. |
| `iam whoami` | None | Requires an IAM session in the selected production or test plane. |
| `iam step-up` | `<action> <resource-id>` | Carbon: OTP prompt or `--code`; Silicon: hidden current-password prompt or `--stk`. The action and exact resource must match the later protected mutation. |
| `iam signup` | `--email <email>` or `--provider google\|apple`; optional `--phone`, `--carbon-id`, `--display-name`, `--timezone`, `--photo` | Creates and signs in a Carbon. Omitted ID and name receive available defaults. Provider signup requires configured production provider credentials; testing email signup uses the explicitly returned test code. Create or join your first organization afterward. |
| `iam commands` | None | Prints this same complete command tree from the installed binary. |
| `iam docs` | Optional `<topic>` and/or `--search <words>` | Offline API/client/CLI manuals. `-o json` returns structured metadata, content or search results. No session or configuration is required. |

### Carbon profile and lookup

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam carbon` | `<subcommand>` | Carbon profile and public-lookup namespace. |
| `iam carbon show` | None | Signed-in Carbon; returns the complete private profile. |
| `iam carbon update` | At least one update or `--clear-*` flag | Signed-in Carbon. Set and clear forms for the same field conflict. |
| `iam carbon available` | `<carbon-id>` | Checks availability only; it does not reserve the ID. |
| `iam carbon search` | `<partial-id>` | Signed-in Carbon. Query must be non-empty and at most 100 characters; `--limit` is 1–10. |
| `iam carbon resolve-email` | `<verified-email>` | Signed-in Carbon; exact, privacy-preserving lookup. |
| `iam carbon resolve-phone` | `<verified-e164-phone>` | Signed-in Carbon; exact, privacy-preserving lookup. |

### Organizations and SSO

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam org` | `<subcommand>` | Organization namespace. |
| `iam org list` | None | Requires an IAM session; `--status` accepts `active` or `removed` membership state. |
| `iam org create` | `<handle> --name <name>` | Carbon session; the handle is global and unique. |
| `iam org show` | `[handle]` | Defaults to the selected `--org`. |
| `iam org update` | `[handle]` plus at least one update or `--clear-*` flag | Defaults to the selected `--org`; requires organization update authority. |
| `iam org available` | `<handle>` | Checks availability only. |
| `iam org transfer` | `<new-owner-membership-id>` | Selected organization plus step-up action `organization.transfer_ownership` on the organization UUID. |
| `iam sso` | `<subcommand>` | Selected-organization SSO namespace. |
| `iam sso show` | None | Requires `sso.manage`. |
| `iam sso setup-link` | None | Requires an SSO entitlement and `sso.manage`; the returned WorkOS setup link lasts five minutes. |
| `iam sso test` | None | Requires `sso.manage` and an active WorkOS connection. |
| `iam sso disable` | None | Requires `sso.manage` and step-up action `organization.sso_change` on the organization UUID. |

### Members and invitations

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam member` | `<subcommand>` | Selected-organization member namespace. |
| `iam member list` | None | Optional principal type, tag UUID from `iam tag list`, status, and paging filters. |
| `iam member show` | `<membership-id>` | Reads the full member record allowed to the caller. |
| `iam member authorization` | `<membership-id>` | Reads organization role and capabilities. |
| `iam member update` | `<membership-id>` plus at least one update or `--clear-*` flag | `--first-silicon` is Carbon-only; reporting-line and profile-photo fields are Silicon-only. |
| `iam member remove` | `<membership-id>` | Step-up action `organization.authorization_change` on that membership ID; use `--reassign-reports-to` when required by the hierarchy. |
| `iam member promote` | `<membership-id>` | Step-up action `organization.authorization_change` on that membership ID. |
| `iam member demote` | `<membership-id>` | Step-up action `organization.authorization_change` on that membership ID. |
| `iam member capabilities` | `<membership-id>` | Step-up action `organization.authorization_change` on that membership ID. Repeat `--capability`; omitting every capability intentionally clears the complete set. |
| `iam member details` | No arguments | Complete JSON dictionary keyed by Carbon/Silicon ID, including all permitted details and trust from your perspective. |
| `iam member directory` | None | Sparse directory; `--fields` accepts `name,id,role,org,tags,trust`. |
| `iam member self` | None | The caller's own sparse directory entry; accepts the same field selector. |
| `iam member directory-member` | `<membership-id>` | One sparse entry; accepts the same field selector. |
| `iam invite` | `<subcommand>` | Selected-organization invitation namespace. |
| `iam invite list` | None | Issued invitations; optional status and paging filters. |
| `iam invite create` | `--job-description <role>` and exactly one of `--carbon-id` or `--email` | Requires invitation authority; optional starting trust boundary and level default to `internal/not_trusted`. |
| `iam invite show` | `<invite-uuid>` | Issuer-side invitation read. |
| `iam invite revoke` | `<invite-uuid>` | Revokes a pending invitation. |
| `iam invite code` | `<invited-email>` | Sends the accepting Carbon its email verification code. |
| `iam invite accept` | `<invite-uuid> --code <code>` | Signed-in invited Carbon; joins the organization once. |

### Tags and advisory trust

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam tag` | `<subcommand>` | Selected-organization tag namespace. |
| `iam tag list` | None | Optional paging. |
| `iam tag create` | `<name>` | Requires tag-management authority. |
| `iam tag show` | `<tag-uuid>` | Reads one tag. |
| `iam tag rename` | `<tag-uuid> <new-name>` | Requires tag-management authority. |
| `iam tag delete` | `<tag-uuid>` | Requires tag-management authority; assignments are removed and tag-scoped trust rules are archived. |
| `iam tag members` | `<tag-uuid>` | Lists memberships carrying the tag. |
| `iam trust` | `<subcommand>` | Selected-organization advisory-trust namespace. Trust values are stored policy data; IAM does not enforce them as authorization. |
| `iam trust default` | None | Reads the organization-wide default. |
| `iam trust set-default` | `--boundary <boundary> --level <level>` | Boundaries are `internal` or `external`; levels are `not_trusted`, `needs_approval`, or `trusted`. Requires `trust.manage`. |
| `iam trust list` | None | Lists explicit rules; optional paging. |
| `iam trust create` | Exactly one subject selector, one target selector, `--boundary`, and `--level` | Choose `--subject-tag` or `--subject-membership`, then `--target-tag` or `--target-membership`; requires `trust.manage`. |
| `iam trust show` | `<rule-uuid>` | Reads one rule. |
| `iam trust update` | `<rule-uuid> --boundary <value> --level <value>` | Replaces the rule's trust value; requires `trust.manage`. |
| `iam trust delete` | `<rule-uuid>` | Archives the rule; requires `trust.manage`. |
| `iam trust evaluate` | `--subject <membership-id> --target <silicon-membership-uuid>` | Subject may be any visible membership; target must be an active Silicon membership. Explains the winning default/rules and returns advisory trust. |

### Governance approvals

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam approval` | `<subcommand>` | Selected-organization governance namespace. |
| `iam approval list` | None | Optional status/kind filters; `--mine` limits to requests the caller can decide now. |
| `iam approval show` | `<request-uuid>` | Reads one request and its decision state. |
| `iam approval decide` | `<request-uuid> --decision <decision>` | Decision is `approve` or `reject`. Requires applicable approval authority. A Silicon-token rotation additionally needs step-up action `silicon.rotate_token` on the Silicon principal UUID. |
| `iam approval request-role` | `--membership-id <membership-id> --job-description <role>` | Uses the configured sensitive-action policy. |
| `iam approval request-tags` | `--membership-id <membership-id>` and at least one `--add` or `--remove` tag UUID | Uses the configured sensitive-action policy. |
| `iam approval set-role` | `<membership-id> <job-role>` | Direct Carbon owner/admin operation requiring `roles.approve`. |
| `iam approval set-tags` | `<membership-id>` | Direct Carbon owner/admin operation requiring `tags.manage`. Repeat `--tag`; no tags means clear the complete set. |
| `iam approval role-history` | `<membership-id>` | Paginated immutable role-change history. |
| `iam approval tag-history` | `<membership-id>` | Paginated immutable tag-change history. |

### Silicons

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam silicon` | `<subcommand>` | Selected-organization Silicon namespace. Local IDs use `--org`; canonical IDs use `si:handle`. |
| `iam silicon list` | None | Optional tag and paging filters. |
| `iam silicon create` | `<handle> --job-description <role>` | Requires `silicons.create`; returns the STK exactly once. A canonical ID supplies its org when none is selected and must match a selected org. |
| `iam silicon show` | `<silicon-id>` | Accepts a local or canonical ID. |
| `iam silicon update` | `<silicon-id>` plus at least one update or `--clear-*` flag | Requires the corresponding directory/hierarchy authority. |
| `iam silicon remove` | `<silicon-id>` | Step-up action `organization.authorization_change` on its membership ID; hierarchy reassignment may be required. |
| `iam silicon rotate-request` | `<silicon-id>` | Step-up action `silicon.rotate_token` on its principal UUID; creates an approval request and invalidates the old credential only after approval. |
| `iam silicon organization-custody` | `<si:id>`; optional `--can-create-organizations true\|false` | Read or update the selected organization's custody permission; requires exact organization custody and `organization.update`. |
| `iam silicon rotate-complete` | `<silicon-id> <approved-request-uuid>` | Same step-up action/resource; returns the replacement STK exactly once. |
| `iam silicon webhook` | `<silicon-id>` | Reads the current endpoint. |
| `iam silicon set-webhook` | `<silicon-id> --webhook-url <https-url>` | Step-up action `organization.silicon_webhook.redirect` on its membership ID; returns the generated signing secret once. |
| `iam silicon delete-webhook` | `<silicon-id>` | Same step-up action/resource. |
| `iam silicon subscription` | `<silicon-id>` | Reads the current webhook subscription. |
| `iam silicon set-subscription` | `<silicon-id>` | Same redirect step-up. Mode defaults to `all`; `selected` requires one or more repeated `--topic`. `--own-tags-only` conflicts with additional `--tag` filters. |
| `iam silicon delete-subscription` | `<silicon-id>` | Same redirect step-up action/resource. |
| `iam silicon dead-letters` | `<silicon-id>` | Lists exhausted deliveries; optional paging. |
| `iam silicon replay` | `<silicon-id>` and one or more `--delivery <uuid>` | Re-queues only the named dead letters. |

### Application identity keys

```sh
iam app verification issue 'checkout' --ttl-seconds 300 --json
iam app verification verify 'checkout' --as-app-id 'billing' --json
```

The first command prompts for the issuing application's secret and prints a new
identity key with its expiry. The second prompts for the receiving application's
secret and the caller's key. In noninteractive use, supply `--app-secret` and
`--app-access-key` explicitly. Keep the key out of logs and archives. A valid key
identifies the caller; the receiver still authorizes the action. Verification
is repeatable until expiry, revocation, rotation, disablement or environment
invalidation; it grants no user permissions and does not replace OBO.

### Applications, tokens, OBO, and webhooks

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam app` | `<subcommand>` | Application namespace. IDs are globally unique bare handles. Creation requires an owning `--org`; IDs do not imply it. |
| `iam app list` | None | Carbon session; intentionally lists Applications across every organization the Carbon can administer. `--org` does not filter this view; `--status` does. |
| `iam app create` | `<app-id> --name <name> --webhook-url <https-url> --webhook-secret <secret> --base-url <origin>` | Current Carbon owner/admin of the owning org. The webhook secret is caller-chosen (32–512 visible ASCII); the generated client secret is returned once. Base URL is a pathless origin with no trailing slash. |
| `iam app show` | `<app-id>` | Carbon or Silicon Application administrator. |
| `iam app update` | `<app-id>` plus at least one update or `--clear-*` flag | Carbon Application administrator; `--obo-endpoints` replaces the complete catalog. |
| `iam app rotate-secret` | `<app-id>` | Step-up action `application.client_secret.rotate` on the canonical Application ID; returns the replacement client secret once. |
| `iam app rotate-webhook-secret` | `<app-id> --webhook-secret <secret>` | Step-up action `application.webhook_secret.rotate` on the canonical Application ID. IAM stores the caller-chosen 32–512 visible-ASCII secret. |
| `iam app discover` | `<target-app-id> --as-app-id <requester-app-id>` plus requester secret at flag or prompt | Application-authenticated base-URL discovery; may cross organizations and respects production/test credential separation. |
| `iam app verification issue` | `<app-id>` plus issuing app secret at `--app-secret` or prompt | Returns a fresh `app_access_key`, expiry and app ID. `--ttl-seconds` accepts 60–3600; omitted means 300 seconds. Each call issues independently with no request-key replay. |
| `iam app verification verify` | `<calling-app-id> --as-app-id <receiving-app-id>` plus caller's `--app-access-key` and receiver's `--app-secret` at flags or prompts | Proves calling app identity only. Invalid keys return `{valid_key:false}`; invalid receiving credentials are authentication errors. Use the same `--test` for both apps when testing. |
| `iam app token` | `<subcommand>` | Application SLT exchange, refresh, introspection, and revocation namespace. |
| `iam app token exchange` | `<app-id>` plus SLT and Application secret at flags or prompts | SLT is single-use. Optional idempotency key is 16–255 visible ASCII; reuse the same key and input after an uncertain result. |
| `iam app token refresh` | `<app-id>` plus refresh token and Application secret at flags or prompts | Rotates the refresh and access tokens. Persist/reuse the same idempotency key after uncertainty; a new key with an already-used refresh token is a replay. |
| `iam app token introspect` | `<app-id>` plus token and Application secret at flags or prompts | `--token-type` is a hint. Optional `--org-context` must exactly match an org-bound token, or name an explicitly selected organization where the subject is active; otherwise the result is inactive. |
| `iam app token authorization` | `<app-id>` plus access token and Application secret at flags or prompts | Current scope-filtered membership/epoch/role/tag snapshot for one organization; `--org-context` must match a bound token and selects one for an unscoped token. No directory mutation or webhook is required. |
| `iam app token authorizations` | `<app-id>` plus access token and Application secret at flags or prompts | One snapshot per organization the token currently reaches: exactly one for a bound token, one per selected active membership for a multi-organization token, none when the subject holds no membership. |
| `iam app token revoke` | `<app-id>` plus token and Application secret at flags or prompts | Access revocation affects one access token; refresh revocation affects the family. Optional 16–255 visible-ASCII idempotency key should be reused after uncertainty. |
| `iam app obo` | `<subcommand>` | Separate endpoint consent, reusable access/refresh tokens and grant management. |
| `iam app obo endpoints` | `<audience-app-id> --as-app-id <requester-app-id>` | Discover available endpoint definitions and dependencies with requester credentials. |
| `iam app obo authorize` | `<app-id> --endpoints '[{"audience":"target","endpoint_id":"action"}]' --org-context <org>` | Requires the user's ordinary `--subject-token` and app secret. Returns the IAM approval URL and complete graph. |
| `iam app obo status` | `<app-id> <request-id>` | Read a request as its creating application; never reveals the approval code. |
| `iam app obo consent` | `<request-id>` | Direct IAM user session: review the requested actions, branches, classifications and displayed version. |
| `iam app obo decide` | `<request-id> approve\|decline --consent-version <displayed-version> [--approve-iam-disclosures]` | Direct IAM user decision on the graph just reviewed; acknowledge displayed identity, membership and tag disclosures for each selected provider account with `--approve-iam-disclosures`. Approval returns a single-use code. |
| `iam app obo token` | `<app-id> <request-id>` | Redeem `--authorization-code` with the app secret for a dedicated pair per root endpoint. |
| `iam app obo refresh` | `<app-id>` | Rotate `--refresh-token` using the owning app secret; retain the exact grant. |
| `iam app obo verify` | `<audience-app-id> <endpoint-id> --method <method> --path <path>` | Use receiver credentials and `--access-token`. Verification is repeatable and does not consume the token. |
| `iam app obo delegate` | `<app-id> <downstream-audience> <endpoint-id>` | Use the incoming `--access-token` and current receiver secret to obtain a downstream access token with no refresh token. |
| `iam app obo grants` | `--cursor`, `--limit` (1–10; default 10) | Review one page of the direct IAM user's grants and dependency chains; continue with the returned cursor. |
| `iam app obo revoke` | `<grant-id>` | Revoke the user-owned grant and every descendant token. |
| `iam app verify-webhook` | `<body-file> --event-id <id> --timestamp <value> --key-version <version> --signature <v1=hex> --webhook-secret <secret>` | Fully local verification over exact raw bytes. Use `-` for stdin. A test-wrapped event requires the matching `--test`; production/test mismatches fail. |
| `iam app import` | `<canonical-production-app-id>` and `--test <environment-uuid>` | Signed-in test Carbon. If the target org already exists there, the Carbon must be its owner/admin; otherwise import creates the org and ownership. Returns a fresh test-only client secret once. |
| `iam app webhook` | `<app-id>` | Current owning-org Carbon or Silicon owner/admin or IAM platform administrator with `applications.review`; reads the endpoint and canonical Application ID for step-up. |
| `iam app set-webhook` | `<app-id> --webhook-url <https-url>` | Carbon or Silicon Application administrator. Test endpoints activate immediately and install the supplied `--webhook-secret` or generate a test-only secret. |
| `iam app approve-webhook` | `<app-id> --step-up <assertion>` | Current owning-org Carbon or Silicon owner/admin or IAM platform administrator with `applications.review`. Step-up action `application.webhook.approve` on the canonical Application ID. Activates only a pending endpoint of an already verified app; no Application status or scope change. |
| `iam app dead-letters` | `<app-id>` | Carbon Application administrator; optional paging. |
| `iam app replay` | `<app-id>` and one or more `--delivery <uuid>` | Re-queues only the named dead letters. |
| `iam app history` | `<app-id>` | Carbon Application administrator; paginated Application-login history. |

### Testing environments

Lifecycle commands below use a production IAM session and selected production
organization; omit `--test`. `env current` and `env clean` without an explicit
ID are key-authorized test-plane commands. `app import` is also test-only, but
requires both the environment selection and a signed-in test Carbon.

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam env` | `<subcommand>` | Testing-environment namespace. |
| `iam env list` | None | Production IAM session and org; optional `active`, `deleted`, or `all` status and paging. |
| `iam env create` | `<name>` | Production IAM session and org; returns and stores the root key. |
| `iam env show` | `<environment-uuid>` | Production control plane. |
| `iam env update` | `<environment-uuid>` plus at least one update or `--clear-description` | Environment creator or active organization owner/admin. |
| `iam env delete` | `<environment-uuid>` | Same environment-admin authority; retires it with a recovery deadline. |
| `iam env restore` | `<environment-uuid>` | Same environment-admin authority and only before purge. |
| `iam env key` | `<environment-uuid>` | Same environment-admin authority; audited, and stores the current key on this device. |
| `iam env rotate-key` | `<environment-uuid>` | Same environment-admin authority; returns/stores the new key and immediately invalidates the old one. |
| `iam env clean` | Either `<environment-uuid>` outside `--test`, or no positional ID with `--test <environment-uuid>` | Erases all test-plane rows but retains the environment. Do not combine an explicit ID with `--test`. |
| `iam env current` | `--test <environment-uuid>` | Key-authorized; no IAM session required. Describes only the selected active environment. |

### Sessions, configuration, and service

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam session` | `<subcommand>` | Current Carbon's session/history namespace. |
| `iam session list` | None | Lists active and recently revoked sessions; optional paging. |
| `iam session revoke` | `<session-uuid>` | Step-up action `account.session_revoke` on that session UUID. The target, and the current session when different, must satisfy the 12-hour rule. |
| `iam session history` | None | Paginated Carbon login history. |
| `iam config` | `<subcommand>` | Local profile/configuration namespace. |
| `iam config show` | None | Local only; shows resolved profile, URL, org, test selection, sign-in state, and store path. |
| `iam config profiles` | None | Local only; lists stored profiles and whether each has credentials. |
| `iam config set` | `<key> <value>` | Key is `url`, `org`, or `auto-update`. Local only. Service URLs require HTTPS except literal loopback; auto-update accepts off; enabling it returns Honeycomb instructions. With `--test`, org is stored only for that environment. |
| `iam config unset` | `<key>` | Key is `org` or `auto-update`. Local only. With `--test`, clears only that environment's org; unsetting auto-update retains disabled IAM self-updates. |
| `iam config use` | `<profile>` | Local only; creates the profile with defaults when missing and makes it current. |
| `iam system` | `<subcommand>` | Service/CLI maintenance namespace. |
| `iam system version` | None | No session required; validates service identity and negotiates API major `v1`. |
| `iam system update` | None | Checks crates.io immediately and installs the newest stable CLI with Cargo. |
| `iam system health` | None | No session required; checks liveness/readiness. |

## Everyday use

```sh
# Your Carbon profile and privacy-preserving lookup
iam carbon show
iam carbon update --display-name "Ada" --timezone Europe/London
iam carbon available ada
iam carbon search ad --limit 5
iam carbon resolve-email ada@example.com
iam carbon resolve-phone +12025550123

# Organizations
iam org list
iam org list --status removed
iam org create acme --name "Acme"
iam org show

# Organization SSO
iam sso show
iam sso setup-link
iam sso test
iam sso disable --step-up "$TOKEN"

# Members
iam member list
iam member list --principal-type silicon
iam member show <membership-id>
iam member directory-member <membership-id> --fields name,id,role,tags
iam member promote <membership-id> --step-up "$TOKEN"

# Tags
iam tag create Engineering
iam tag members <tag-id>
iam tag delete <tag-id>          # takes its assignments and trust rules with it

# Governance
iam approval list --mine
iam approval decide <request-id> --decision approve
iam approval set-tags <membership-id> --tag <tag-id> --tag <tag-id>

# Silicons
iam silicon create builder --job-description "Build agent"
iam silicon set-webhook builder --webhook-url https://example.com/hooks
iam silicon set-subscription builder --mode selected \
    --topic member_updates --own-tags-only

# Applications
iam app create billing --name Billing \
    --base-url https://billing.example.com \
    --webhook-url https://billing.example.com/hooks \
    --webhook-secret "$WEBHOOK_SECRET"
iam app rotate-secret billing --step-up "$TOKEN"
iam app rotate-webhook-secret billing \
    --webhook-secret "$NEW_WEBHOOK_SECRET" --step-up "$TOKEN"
```

`app create` and `app rotate-webhook-secret` require the caller-chosen
`--webhook-secret`; it appears in each command's generated usage and help.
IAM encrypts that value. Testing webhook URL replacements can generate a fresh test-only secret when none is supplied.

An Application belongs to exactly one organization. `app create billing --org acme`
sends the globally unique bare ID `billing` and its owning organization separately.
The same `billing` ID is used for login, credentials, discovery and OBO. No
organization can be inferred from an application or account ID.
CLI options may appear before or after the positional Application ID, although
the examples keep the ID first for readability.

The local app handle accepts **1–80 characters**: a lowercase ASCII letter first,
then lowercase letters, digits, underscores, or hyphens. For example, `a`, `ab`,
and `billing` are valid. Organization handles are separate and require 3–50 characters.

`--base-url` is the Application backend **origin**, for example
`https://billing.example.com`. It must contain no slash after the authority —
not even a trailing `/` — and no path, credentials, query, or fragment. HTTPS
is required except for literal `localhost`, `127.0.0.1`, or `::1` development.
`--webhook-url` is different: it is a complete HTTPS delivery endpoint, so it
may contain a path and may end in `/`.

### Approving a production webhook

An application without pending critical approvals is usable; its first production webhook
starts pending; later URL replacements leave the old URL active until approval.
The current owning-org Carbon or Silicon owner/admin or an IAM platform administrator
with `applications.review` can approve that pending endpoint. Being the
Application's creator alone does not grant authority.

```sh
APP_ID='billing'
APP_UUID=$(iam -o json app webhook "$APP_ID" | jq -r .application_id)
TOKEN=$(iam -o json step-up application.webhook.approve "$APP_UUID" \
    | jq -r .step_up_token)
iam app approve-webhook "$APP_ID" --step-up "$TOKEN"
```

The assertion uses the internal UUID from `app webhook`, not the public
bare application ID. The CLI reads the current Application version and sends an
idempotent approval with no request fields. Approval changes only the endpoint, not
Application status or scopes. An Application itself still `under_review`
must complete platform review separately. A missing pending endpoint or a
non-verified Application returns a conflict; test endpoints normally activate
immediately and need no approval.

### Other organization and membership commands

`iam org list --status active|removed` filters the signed-in Carbon's
membership state. The `status` shown on each returned organization is still
the organization's own `active|disabled` state.

SSO is unavailable until a platform administrator grants the organization an
entitlement. `sso setup-link` prints a five-minute WorkOS setup URL; `sso test`
checks the mapped connection; `sso disable` requires the current configuration
version plus step-up action `organization.sso_change` bound to the
organization UUID. SSO does not create a Carbon account.

`iam approval request-role` and `iam approval request-tags` are Silicon-only
self-service commands. Carbon callers are forbidden; Carbons with the required
organization capability use the direct `set-role` and `set-tags` commands.

### Updating and clearing optional fields

Patch commands preserve omitted fields. To remove a nullable value, use its
explicit `--clear-*` flag; sending no related flag means “leave it unchanged.”
The set and clear forms for one field conflict, so the CLI cannot send both:

```sh
iam carbon update --clear-profile-photo
iam org update --clear-logo --clear-description
iam member update <membership-id> --clear-first-silicon \
    --clear-reports-to --clear-profile-photo
iam silicon update builder \
    --clear-profile-photo --clear-reports-to
iam app update billing --clear-name --clear-logo
iam env update <environment-id> --clear-description
```

The corresponding set flags are `--description`, `--profile-photo`,
`--first-silicon`, `--reports-to`, `--name`, and `--logo`. Full-replacement
arguments remain full replacements: for example, an empty Application OBO
endpoint array retires the complete catalog.

## Output

Text is the default, aligned for reading. `-o json` always emits one valid JSON
document, which is what to reach for in a script. Most remote reads and writes
serialize the service's typed response. A successful bodyless operation emits
`null`; local/configuration operations and logout may emit a small CLI-owned
summary instead of a service body:

```sh
iam -o json org show | jq -r .owner_membership_id
```

Exit codes distinguish the cases worth branching on: `2` a usage mistake, `3`
not signed in, `4` a recognized service refusal, `5` a transport failure or an
HTTP error without a recognizable IAM envelope. An HTML `403` is reported as
an unstructured response with its actual status and any valid request ID; it
is not presented as an IAM permission denial, and its raw body is never printed.

## Testing environments

An environment is the whole service against a separate database, starting
empty. Its UUID is safe to use in commands; its 32-character root key is not.
The CLI keeps that key in the owner-only credentials file and resolves it when
you pass `--test`:

```sh
CREATED=$(iam -o json env create Sandbox)
TEST_ID=$(printf '%s' "$CREATED" | jq -r .id)

iam --test "$TEST_ID" env current
iam --test "$TEST_ID" signup --email dev@example.test \
     --phone +14155550123 --carbon-id dev
iam --test "$TEST_ID" login --email dev@example.test --code 000000
iam --test "$TEST_ID" org list             # empty: it is a fresh world
```

Email and SMS delivery are suppressed and every OTP flow accepts `000000`.
Webhook delivery is real, but test payloads are wrapped under `test` and carry
the environment key so a receiver can isolate the run. Never log that field.

Production and test credentials do not cross the boundary in either direction.
The CLI therefore keeps the production session and every environment session
in separate slots. Leaving off `--test` returns to production; it never reuses
the test session there.

Creation, key retrieval and key rotation automatically register the current
key on this device. On a new device, authorize the mapping from a production
session first:

```sh
iam env key "$TEST_ID"       # audited, and stores the key in credentials.json
iam --test "$TEST_ID" whoami
```

The CLI never accepts a raw key in `--test`. An unknown UUID fails locally and
points to `iam env key`. Test-only commands likewise fail locally when
`--test <environment-id>` is missing.

Organization defaults are isolated too. A production default such as `acme`
is never silently reused in a test database where it may not exist. Set the
default once for that exact environment, or keep passing `--org`:

```sh
iam --test "$TEST_ID" config set org sandbox-org
```

When a scoped request really cannot find something, the CLI points to the
active `--org`/`--test` scope instead of leaving a bare “resource not found”.

### Applications in a test environment

Create a brand-new application through the ordinary command. Its local handle
must not collide with a production application in the same organization:

```sh
iam --test "$TEST_ID" app create checkout --org acme --name Checkout \
    --base-url https://checkout.example \
    --webhook-url https://hooks.example.test/iam \
    --webhook-secret "$TEST_WEBHOOK_SECRET"
```

Use your public HTTPS application origin with hosted IAM, including hosted
testing environments: `--test` does not bypass the public edge. Loopback
application origins are for a local IAM runtime. Use that runtime explicitly,
with an environment and credentials created on the same local service:

```sh
iam --url http://127.0.0.1:8080 --profile local-iam --test "$LOCAL_TEST_ID" \
    app create checkout --org acme --name Checkout \
    --base-url 'http://[::1]:4100' \
    --webhook-url https://hooks.example.test/iam \
    --webhook-secret "$TEST_WEBHOOK_SECRET"
```

The hosted edge has been observed returning HTML `403` for loopback app
origins without an IAM request ID. That requires deployment-side investigation,
not a new login or a membership change. Keep the original idempotency key if
the create operation's outcome is uncertain.

Or import an existing production application by canonical ID. Import creates
its organization in the environment when needed, copies the base URL, webhook
URL and OBO catalog, inherits the production webhook signing secret without
revealing it, and returns a fresh test-only application secret:

```sh
iam --test "$TEST_ID" -o json app import 'google>drive'
```

To use a different test webhook URL, run `app set-webhook` inside the test
environment. Test endpoints activate immediately because an isolated plane has
no platform reviewer. IAM installs the supplied `--webhook-secret`, or generates a fresh
test-only secret when omitted. Store `webhook_signing_secret` from the response.
Use `app rotate-webhook-secret` with an explicit successor for later rotation.

Any test application can discover another application's base URL with its own
test-only credential:

```sh
iam --test "$TEST_ID" app discover 'google>drive' \
    --as-app-id 'checkout'
```

The secret is prompted for when `--app-secret` is omitted, keeping it out of
shell history.

Application IDs are bare handles such as `billing`; Silicon account IDs are
`si:builder`. `--org` selects management context, never part of either account ID.
Public membership references include the organization, such as `si:builder[acme]`.
Bundle IDs keep the separate `acme>workspace` namespace.

Retiring one keeps it recoverable:

```sh
iam env delete <environment-id>    # prints the deadline
iam env restore <environment-id>
```

## Signing in to an application

An Application can start a session only by exchanging an IAM-issued,
single-use short-lived token (SLT). It cannot submit an OTP, email, phone,
Carbon ID, Silicon token, or IAM refresh token.

With a direct IAM session, select exactly one organization:

```sh
iam login --app-id billing --grant-org acme
iam silicon-login --sid si:builder --app-id billing --grant-org acme
# A separate login issues a separate token family for another organization:
iam login --app-id billing --grant-org another-team
```

Without `--grant-org`, an interactive terminal lists choices and prompts;
noninteractive use must supply one. `--all-orgs`, empty selection and multiple
organization values are rejected. Create or join your first organization before
application login. `--org`, `SILICON_IAM_ORG` and stored defaults select management
context only; `--no-org` clears that context. They never grant app access.

IAM validates the Application and the entire selection. Applications cannot
use their own bearer or secret to choose or enlarge grants. The printed SLT is
the only credential handed to the app. See
[organization consent](../ORGANIZATION_CONSENT.md) (`iam docs consent`).

### End-to-end Application proof in a test environment

Use a disposable testing environment containing a configured caller and audience.
The caller must declare the audience endpoint in its effective external scopes;
critical scopes need the applicable provider approval. Sign in directly to IAM
as the represented user, select an organization during ordinary app login, and
exchange its SLT for the caller's ordinary access token. That login grants no OBO
authority. The following assumes `TEST_ID`, `ACCESS`, `CALLER_SECRET` and
`AUDIENCE_SECRET` are set for that environment:

```sh
REQUEST=$(iam --test "$TEST_ID" -o json app obo authorize caller \
  --org-context customer --subject-token "$ACCESS" --app-secret "$CALLER_SECRET" \
  --endpoints '[{"audience":"audience","endpoint_id":"orders.create"}]')
REQUEST_ID=$(printf '%s' "$REQUEST" | jq -r .id)

# Review every dependency and the displayed version before deciding.
iam --test "$TEST_ID" app obo consent "$REQUEST_ID"
VERSION=$(printf '%s' "$REQUEST" | jq -r .version)
DECISION=$(iam --test "$TEST_ID" -o json app obo decide "$REQUEST_ID" approve \
  --consent-version "$VERSION" --approve-iam-disclosures)
CODE=$(printf '%s' "$DECISION" | jq -r .authorization_code)
TOKENS=$(iam --test "$TEST_ID" -o json app obo token caller "$REQUEST_ID" \
  --authorization-code "$CODE" --app-secret "$CALLER_SECRET")
OBO_ACCESS=$(printf '%s' "$TOKENS" | jq -r '.items[0].access_token')
OBO_REFRESH=$(printf '%s' "$TOKENS" | jq -r '.items[0].refresh_token')
GRANT_ID=$(printf '%s' "$TOKENS" | jq -r '.items[0].grant_id')

# This verification can be repeated while the endpoint token remains valid.
iam --test "$TEST_ID" app obo verify audience orders.create \
  --access-token "$OBO_ACCESS" --app-secret "$AUDIENCE_SECRET" \
  --method POST --path /v1/orders

iam --test "$TEST_ID" app obo refresh caller \
  --refresh-token "$OBO_REFRESH" --app-secret "$CALLER_SECRET"
iam --test "$TEST_ID" app obo grants
iam --test "$TEST_ID" app obo revoke "$GRANT_ID"
```

The consent and decision steps require the represented user's direct IAM session;
the app cannot approve its own endpoint access. Use the IAM URL instead for a
browser flow. Keep the exact reviewed version; if the graph changes, reread and
review the new graph before approval. Secrets are explicit here to make the test
reproducible; omit secret flags interactively to use hidden prompts.

Authorization, decisions, code exchange, refresh, delegation and revocation
accept `--idempotency-key`. Persist one key per operation and reuse it with identical
input after an uncertain transport result. A new key with a used refresh token is
reuse and compromises its family. Verification has no idempotency key and does not
consume the token; receivers still deduplicate their own actual operations.

Before shipping, verify that ordinary login alone grants no OBO access; declining
leaves login valid; wrong users cannot approve; an added dependency requires new
consent; a stale consent version fails; repeated verification succeeds; wrong
audiences/endpoints and revoked grants fail; derived tokens cannot refresh or
outlive their parents; and production/testing credentials never cross environments.
Test current membership removal, app/scope revocation and global logout as well.

### Offline webhook verification

Save the exact body bytes and the four `X-Silicon-IAM-*` headers before a web
framework parses them. The CLI verifies the signature, timestamp, key version,
event ID, and event schema locally:

```sh
iam app verify-webhook delivery.json \
    --event-id "$EVENT_ID" --timestamp "$TIMESTAMP" \
    --key-version "$KEY_VERSION" --signature "$SIGNATURE" \
    --webhook-secret "$WEBHOOK_SECRET"
```

The signing secret is required explicitly. For a test delivery, add
`--test "$TEST_ID"`; the CLI then also compares the wrapped
`testing_key` in constant time with that environment's locally stored key. A
wrapped test event without `--test`, a production event with `--test`, or a key
for a different environment is rejected. Successful output is the normalized
event and never includes the testing root key.

The signature value must have the canonical `v1=<64 lowercase hex>` form. Also
test a changed body byte, stale timestamp, duplicate security header in the
actual receiver, unknown key version, wrong secret, mismatched event ID, and
wrong test-environment key. Verification must happen over the captured raw
body before JSON parsing.

## Profiles

One profile per service, or per identity on the same service:

```sh
iam --profile staging config set url https://staging.example.com
iam --profile staging login --email you@example.com
iam config profiles
iam config use staging
```

Every setting can also come from the environment: `SILICON_IAM_URL`,
`SILICON_IAM_PROFILE`, `SILICON_IAM_ORG`, `SILICON_IAM_TEST`, and
`SILICON_IAM_AUTO_UPDATE`. Flags win over environment variables, which win
over stored settings.

`SILICON_HOME` selects the home base: IAM stores state in its `.silicon-iam`
subdirectory, falling back to `~/.silicon-iam` when unset. `SILICON_IAM_HOME`
overrides the exact storage directory, which is useful for isolated CI runs.
`iam config home <existing-directory>` persists a selection for the current
base. See [credential storage](storage.md) for the complete precedence rules.

## Step-up

Privileged commands need a short-lived assertion bound to one exact action and
one resource identifier (a canonical membership ID for a membership, otherwise the resource UUID). Every affected command names both values in its
`--help`. The complete CLI mapping is:

| Command | Step-up action | Resource UUID |
| --- | --- | --- |
| `org transfer` | `organization.transfer_ownership` | organization `id` |
| `member remove`, `promote`, `demote`, `capabilities` | `organization.authorization_change` | target membership ID |
| `silicon remove` | `organization.authorization_change` | target Silicon `membership_id` |
| `silicon rotate-request`, `rotate-complete` | `silicon.rotate_token` | target full `silicon_id` |
| `silicon set-webhook`, `delete-webhook`, `set-subscription`, `delete-subscription` | `organization.silicon_webhook.redirect` | target Silicon `membership_id` |
| `app rotate-secret` | `application.client_secret.rotate` | Application `id` |
| `app rotate-webhook-secret` | `application.webhook_secret.rotate` | Application `id` |
| `app approve-webhook` | `application.webhook.approve` | Application `id` |
| `sso disable` | `organization.sso_change` | organization `id` |
| `session revoke` | `account.session_revoke` | session ID |
| `logout --all` when other sessions are active | `account.sessions_revoke_all` | signed-in `carbon_id` or `silicon_id` |
| `approval decide` for a `silicon_token_rotation` request | `silicon.rotate_token` | target full `silicon_id` |

Use the exact action/resource binding returned by the protected resource.
Some resources use UUIDs; principals and memberships use their canonical IDs.
Mint the assertion for that value and pass it to the matching mutation. For example:

```sh
SILICON=$(iam -o json silicon show builder)
SILICON_MEMBERSHIP=$(printf '%s' "$SILICON" | jq -r .membership_id)

TOKEN=$(iam -o json step-up organization.silicon_webhook.redirect \
    "$SILICON_MEMBERSHIP" | jq -r .step_up_token)
iam silicon set-webhook builder \
    --webhook-url https://example.com/hooks --step-up "$TOKEN"
```

Useful resource-ID sources are `iam -o json org show | jq -r .id`,
`iam -o json member list`, `iam -o json silicon show <silicon>` (both
`membership_id` and `silicon_id`), `iam -o json app show <app> | jq -r .id`,
`iam -o json app webhook <app> | jq -r .application_id` (also available to
platform webhook reviewers),
`iam -o json session list`, and `iam -o json carbon show | jq -r .carbon_id`.

If the code is not supplied, `iam step-up` prompts after sending it to the
selected verified channel (`--channel email` by default, or `phone`). For a Silicon,
the CLI instead requests its current password, or accepts `--stk`; no email OTP is sent. The
service also rejects a missing or mismatched assertion explicitly:

```
error: A step-up assertion is required. (step_up_required)
hint: This action needs step-up verification; re-run with --step-up.
```

## Permission consent and scoped login

Applications declare `app_scope` separately from `webhook_scope`. IAM scope names start with
`self.`, `directory.`, or `organization.`. An external permission names one exact audience app
and endpoint. Create defaults to `self.identity.read` and `self.profile.read`; other data
requires explicit declaration, review where critical, and user consent.

```sh
iam app scopes catalog
iam app scopes catalog --app-id 'drive'
iam app create checkout --org acme --name Checkout \
  --base-url https://checkout.example --webhook-url https://checkout.example/hooks \
  --webhook-secret "$WEBHOOK_SECRET" \
  --webhook-scope membership,updates \
  --app-scope '{"iam":["self.identity.read","self.profile.read"],"external":[]}'
iam login --app-id 'checkout' --grant-org customer --approve-scopes
iam silicon-login --app-id 'checkout' --grant-org customer --approve-scopes
```

Interactive login displays the current IAM permission set when critical consent is
required. Without a terminal, `--approve-scopes` records that explicit approval.
`--grant-org <org>` selects exactly one organization; `--all-orgs` is rejected; a default `--org` never grants access. If consent becomes stale,
reload the application view and review again. IAM tokens, OTPs, SID/STK, and refresh credentials
stay inside IAM: an external application asks only for its short-lived token.

## Critical scope review forum

```sh
iam app scopes request 'checkout' \
  --app-scope '{"iam":["self.identity.read","directory.carbons.read"],"external":[]}' \
  --message 'Checkout needs to list organization Carbons to assign invoice recipients.'
iam app scopes requests --status pending
iam app scopes show <request-uuid>
iam app scopes reply <request-uuid> --message 'Only the selected organization is queried.'
iam app scopes approve <request-uuid>
iam app scopes deny <request-uuid> --reason 'Explain why individual lookup is insufficient.'
```

Requester and target organization owners/admins can read and reply to their shared discussion;
only authorized reviewers can decide. A denial always includes a reason. IAM scope reviews
are handled by IAM reviewers. Initial instructions appear as the first forum message, and
requests, replies, acknowledgments, and decisions trigger the appropriate notifications.
The CLI fetches the current version and sends it with each mutation. Pending critical scopes
block a new app's first use; an upgrade keeps the prior approved scope set working. Remove
permissions through `iam app update --app-scope ...` without requesting approval.

When exposing OBO endpoints, every object needs `critical: true` or `false`:

```sh
iam app update 'drive' \
  --obo-endpoints '[{"endpoint_id":"files.read","path":"/v1/files","critical":false,"metadata":{}}]' \
  --obo-review-message 'Explain the information you need and how users control its use.'
```

OBO accepts apps from different owning organizations. The calling app must declare the exact
endpoint, obtain critical approval if required, and hold the user's consent. Use
`iam app obo authorize ... --org-context customer` for the originating login organization;
consent can select a different configured account and organization for each provider.
The subject token must belong to the calling app and still be active when requesting consent.

## Application bundles

```sh
iam app bundle availability --org acme
iam app bundle create workspace --org acme --name Workspace \
  --logo https://example.com/workspace.svg --app-id 'checkout,billing'
iam app bundle list --org acme --limit 25
iam app bundle show 'acme>workspace'
iam app bundle update 'acme>workspace' --name 'Acme Workspace'
iam app bundle update 'acme>workspace' --clear-logo
iam app bundle login 'acme>workspace' --grant-org customer --approve-scopes
iam app bundle delete 'acme>workspace'
```

`iam app bundle availability` reports whether the signed-in Carbon can configure bundles in
the selected organization. It returns a derived yes/no result, without exposing organization
policy settings. Use `--org` or the configured organization; a direct Carbon IAM session and
active membership are required.

`iam app bundle list` and `iam app list` filter by the selected organization before applying
`--cursor` and `--limit`. Use `--no-org` to list across administered organizations. Both show
a continuation cursor when another page is available.

Bundle creation accepts an optional HTTPS `--logo` URL. During an update, omit `--logo` to
keep the existing image, pass a new URL to replace it, or use `--clear-logo` to remove it.
`--logo` and `--clear-logo` cannot be combined.

All members belong to the bundle's organization and remain independently usable. Login shows the bundle and issues a distinct
SLT for every member atomically; exchange each with that app's own secret. Deleting a bundle
keeps every member application. `iam batch-login` remains available for an explicitly
selected ad hoc list; it also supports `--approve-scopes` and per-app permission review.

## One-step application test environments

```sh
iam app testing create 'checkout' 'Invoice integration' --description 'Cross-app invoice flow'
iam app testing create 'checkout' 'Shared scenario' --iam-test-key "$IAM_TEST_KEY"
iam app testing list 'checkout'
iam app update 'checkout' --testing-idle-days 14
```

These commands use the production app secret, prompted securely when `--app-secret` is
omitted. Omit `--test` on testing-management commands. A valid `--iam-test-key` attaches to
that exact IAM environment; an invalid supplied key fails; omitting it creates a new one.
IAM imports the caller and all transitive external dependencies into the same isolated layer.
The response includes the environment UUID, IAM key, caller's test secret, and dependency IDs.
Dependency secrets remain managed by IAM. The CLI securely remembers the returned IAM key,
so subsequent ordinary commands can use `iam --test <environment-uuid> ...`.

Applications receiving **`app_secret` inside a request** must treat it as the testing protocol,
validate the secret through IAM, and resolve isolated data using its IAM test environment.
Every dependency stays in that environment. The default inactivity retention is 30 days.
Test IAM verification accepts `000000`; production and testing credentials reject each other.
Test webhooks include `testing_key` and nest data/metadata under a `test` object. Verify the
signed outer bytes and the selected environment key before applying the event.

## Scoped IAM reads and API contracts

An application's user access token carries only approved scopes. Organization lists include
only explicitly selected active memberships. Directory lists require the corresponding
`directory.carbons.read` or `directory.silicons.read`; field scopes independently control
profiles, roles, job descriptions, tags, hierarchy, capabilities, and accessible Silicons.
Self permissions never reveal those fields for other members. Email and phone are self-only.
Absent fields mean undisclosed and must not be replaced with cached wider permissions.

Rust integrations use `client.application_reads().me/organizations/organization/members/member/member_authorization/silicon/tags`
with `Credential::bearer(application_access_token)`. These methods preserve scope-dependent
JSON field omission. Direct IAM management methods retain their full typed response shapes.
Use `system().contracts()` or `iam system contracts` (alias `iam api contracts`) to inspect
contract versions and compatibility. Breaking changes receive a new major API version;
a deprecated version can sunset after seven days without requests.

## Reading disclosed application data

Use an application user access token with `iam app read`. These commands print the server's
JSON projection, preserving absent fields instead of filling in undisclosed data. Tokens are
prompted when `--token` is omitted; they are not stored as your IAM login session.

```sh
iam app read me --token "$APP_ACCESS_TOKEN"
iam app read organizations --token "$APP_ACCESS_TOKEN"
iam --org customer app read member <membership-id> --token "$APP_ACCESS_TOKEN"
iam --org customer app read self-directory --token "$APP_ACCESS_TOKEN"
iam --org customer app read directory --limit 25 --token "$APP_ACCESS_TOKEN"
iam --org customer app read authorization <membership-id> --token "$APP_ACCESS_TOKEN"
iam --org customer app read silicons --token "$APP_ACCESS_TOKEN"
iam --org customer app read tags --token "$APP_ACCESS_TOKEN"
```

`self.*` permissions disclose the represented user's fields. Directory actor scopes select
which other actor types can be listed or looked up; directory profile, membership, capability,
job, tag, access, and hierarchy fields each require their own scope. Every organization must
be included in the login's active consent. The server rechecks active application approval and
consent on every request, including when an old token is presented after scope revocation.

## What is not here

Platform administration, the inbound provider webhooks, and the browser login
screen. Those belong to the operator, to the provider, and to the browser —
not to a command-line caller.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.

Copyright 2026 Team of Silicons.

## Manage application-owned testing environments

Production application secrets are securely prompted when omitted. Lifecycle management runs outside `--test` and is restricted to environments created by that application.

```sh
iam app testing list 'checkout' --status all
iam app testing manage 'checkout' show ENVIRONMENT_UUID
iam app testing manage 'checkout' update ENVIRONMENT_UUID --name 'Checkout test'
iam app testing manage 'checkout' key ENVIRONMENT_UUID
iam app testing manage 'checkout' rotate-key ENVIRONMENT_UUID
iam app testing manage 'checkout' clean ENVIRONMENT_UUID
iam app testing manage 'checkout' delete ENVIRONMENT_UUID
iam app testing manage 'checkout' restore ENVIRONMENT_UUID
```

Clean permanently erases every IAM row in the selected environment, including imported dependencies, and retains its key. Delete disables the environment; restore is available until the returned purge deadline. Key rotation invalidates the previous key immediately. These commands do not clean external application databases.

To authenticate and inspect a test application, securely enter its test secret and IAM test key at the prompts:

```sh
iam app testing view 'checkout'
```

This returns the environment UUID and test configuration without returning credentials. The `view` command does not grant a production IAM session or user-data authority.

Telemetry defaults on when configured. Use `iam config set telemetry off` to disable collection, or `iam docs telemetry` for [setup and delivery details](../TELEMETRY.md).

## Management ownership

Use Honeycomb for production app configuration, scope reviews, bundles and shared
testing lifecycles. Legacy IAM management commands remain for migration-era
servers; after `IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS=true` is enabled they receive
`410 management_moved_to_honeycomb`. IAM continues to provide identity, login,
consent and test-plane authentication. See [the service contract](../HONEYCOMB_INTEGRATION.md).

### Membership identifiers

Membership IDs are `carbon_id[org_id]` or the full `silicon_id[org_id]`, for example
`c:saket[tos]` and `si:helper[tos]`. Quote IDs in shell commands:

```sh
iam --org tos --json member show 'c:saket[tos]'
iam --org tos --json member details
```

The details command returns every visible active member in one dictionary. Each
entry includes `display_name`, profile, roles, tags, hierarchy, capabilities and
Silicon access where permitted. Trust is evaluated for the requesting user;
Carbon-to-Carbon trust is null. Unapproved fields and credentials are omitted.

## Sensitive action policies

Use `iam approval policies` to see rules and defaults, `iam approval configure-policy` to configure them, and `iam approval actions` / `decide-action` for manual review. Job updates use the single `job_description` field (`--job-description` on creation/invitations). A pending change returns a request key; repeat the identical command with `--request-key` after approval. See [Sensitive actions](../SENSITIVE_ACTIONS.md) for defaults and selector semantics.
