# silicon-iam-cli

Silicon IAM from the command line. Installs a single binary, `iam`.

```sh
cargo install silicon-iam-cli --version 1.1.1 --locked
```

Release `1.1.1` requires Rust 1.98 or newer, bundles
`silicon-iam-client` 1.1.1, and speaks HTTP API major `v1`. The crate/CLI
SemVer and HTTP API major are separate version lines. Check the installed
binary with `iam --version`, and inspect/negotiate with the configured service
using `iam system version`.

The installed binary checks crates.io at most once every 24 hours and updates
itself with `cargo install` when a newer stable release exists. Automatic
updates are on by default. An offline registry or unavailable Cargo executable
only prints a warning and never prevents the requested IAM command from
running.

```sh
iam config set auto-update off   # opt out persistently
iam config unset auto-update     # restore the default-on policy
iam system update                # force a check now, even while opted out
```

`SILICON_IAM_AUTO_UPDATE=false` is the process-level opt-out; set it to `true`
to override a stored opt-out. After an update, the command already in progress
finishes with the old binary and the next `iam` invocation uses the new one.

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
is close to expiring. `iam logout` ends the current Carbon session on IAM and
then forgets it locally. `iam logout --all` ends every Carbon session; when
another active session would be affected, the service requires every affected
session to be at least 12 hours old and a verified-channel
`account.sessions_revoke_all` step-up assertion bound to the signed-in
Carbon's principal UUID. `iam logout --local-only` only clears this device.

A Silicon logout is local because the public logout route accepts Carbon
authority; rotate or remove the Silicon to revoke its server-side credential.
The CLI persists a pending remote-logout idempotency key before sending, so an
exact retry can confirm a logout whose response was lost.

## Finding your way around

Commands read as noun then verb:

```sh
iam -h                 # the top-level commands and global options
iam commands           # every command, at every depth
iam tag --help         # one group
iam tag delete --help  # one command's options
```

## Complete command reference

This is the complete `1.1.1` command tree emitted by `iam commands`. Angle
brackets mark required values; square brackets mark optional values. A row for
a noun such as `iam member` is a help namespace and requires one of the listed
subcommands. Run `iam <command> --help` for every flag, accepted value, default,
and generated usage line.

Global `--org` wins over `SILICON_IAM_ORG` and the profile default. `--no-org`
ignores both environment and stored organization defaults; it conflicts only
with an explicitly supplied `--org`. `--test <environment-uuid>` selects an
isolated plane by its public, hyphenated UUID—never put its root key on the
command line. Options may appear before or after positional identifiers. Quote
canonical Application IDs such as `'acme>billing'` so the shell does not treat
`>` as redirection.

### Authentication and top-level commands

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam login` | For a new session, exactly one of `--email`, `--phone`, or `--carbon-id`; the code is prompted unless `--code` is given | Carbon login. With an existing session, no identity is needed. `--app-id` additionally mints an SLT; it never logs the Application in directly. |
| `iam silicon-login` | Silicon ID and STK; either may be entered at the prompt instead of a flag | Silicon login. `--app-id` additionally mints an SLT. A canonical `handle:org` supplies the organization when none is selected. |
| `iam logout` | None | Ends the current Carbon session remotely; Silicon logout is local. `--local-only` and `--all` conflict. `--all` uses step-up action `account.sessions_revoke_all` on the Carbon principal UUID, and affected sessions must satisfy the 12-hour rule. |
| `iam whoami` | None | Requires an IAM session in the selected production or test plane. |
| `iam step-up` | `<action> <resource-uuid>` | Carbon only. The code is prompted unless `--code` is given. The action and exact resource must match the later protected mutation. |
| `iam signup` | `--email <email> --phone <e164> --carbon-id <id>` | Creates and verifies a Carbon; the testing plane suppresses delivery and accepts `000000`. |
| `iam commands` | None | Prints this same complete command tree from the installed binary. |

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
| `iam org transfer` | `<new-owner-membership-uuid>` | Selected organization plus step-up action `organization.transfer_ownership` on the organization UUID. |
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
| `iam member show` | `<membership-uuid>` | Reads the full member record allowed to the caller. |
| `iam member authorization` | `<membership-uuid>` | Reads organization role and capabilities. |
| `iam member update` | `<membership-uuid>` plus at least one update or `--clear-*` flag | `--first-silicon` is Carbon-only; reporting-line and profile-photo fields are Silicon-only. |
| `iam member remove` | `<membership-uuid>` | Step-up action `organization.authorization_change` on that membership UUID; use `--reassign-reports-to` when required by the hierarchy. |
| `iam member promote` | `<membership-uuid>` | Step-up action `organization.authorization_change` on that membership UUID. |
| `iam member demote` | `<membership-uuid>` | Step-up action `organization.authorization_change` on that membership UUID. |
| `iam member capabilities` | `<membership-uuid>` | Step-up action `organization.authorization_change` on that membership UUID. Repeat `--capability`; omitting every capability intentionally clears the complete set. |
| `iam member directory` | None | Sparse directory; `--fields` accepts `name,id,role,org,tags,trust`. |
| `iam member self` | None | The caller's own sparse directory entry; accepts the same field selector. |
| `iam member directory-member` | `<membership-uuid>` | One sparse entry; accepts the same field selector. |
| `iam invite` | `<subcommand>` | Selected-organization invitation namespace. |
| `iam invite list` | None | Issued invitations; optional status and paging filters. |
| `iam invite create` | `--job-role <role>` and exactly one of `--carbon-id` or `--email` | Requires invitation authority; optional starting trust boundary and level default to `internal/not_trusted`. |
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
| `iam trust evaluate` | `--subject <membership-uuid> --target <silicon-membership-uuid>` | Subject may be any visible membership; target must be an active Silicon membership. Explains the winning default/rules and returns advisory trust. |

### Governance approvals

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam approval` | `<subcommand>` | Selected-organization governance namespace. |
| `iam approval list` | None | Optional status/kind filters; `--mine` limits to requests the caller can decide now. |
| `iam approval show` | `<request-uuid>` | Reads one request and its decision state. |
| `iam approval decide` | `<request-uuid> --decision <decision>` | Decision is `approve` or `reject`. Requires applicable approval authority. A Silicon-token rotation additionally needs step-up action `silicon.rotate_token` on the Silicon principal UUID. |
| `iam approval request-role` | `--membership-id <uuid> --job-role <role>` | Silicon-only; Carbon callers are forbidden. |
| `iam approval request-tags` | `--membership-id <uuid>` and at least one `--add` or `--remove` tag UUID | Silicon-only; Carbon callers are forbidden. |
| `iam approval set-role` | `<membership-uuid> <job-role>` | Direct Carbon owner/admin operation requiring `roles.approve`. |
| `iam approval set-tags` | `<membership-uuid>` | Direct Carbon owner/admin operation requiring `tags.manage`. Repeat `--tag`; no tags means clear the complete set. |
| `iam approval role-history` | `<membership-uuid>` | Paginated immutable role-change history. |
| `iam approval tag-history` | `<membership-uuid>` | Paginated immutable tag-change history. |

### Silicons

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam silicon` | `<subcommand>` | Selected-organization Silicon namespace. Local IDs use `--org`; canonical IDs use `handle:org`. |
| `iam silicon list` | None | Optional tag and paging filters. |
| `iam silicon create` | `<handle> --job-role <role>` | Requires `silicons.create`; returns the STK exactly once. A canonical ID supplies its org when none is selected and must match a selected org. |
| `iam silicon show` | `<silicon-id>` | Accepts a local or canonical ID. |
| `iam silicon update` | `<silicon-id>` plus at least one update or `--clear-*` flag | Requires the corresponding directory/hierarchy authority. |
| `iam silicon remove` | `<silicon-id>` | Step-up action `organization.authorization_change` on its membership UUID; hierarchy reassignment may be required. |
| `iam silicon rotate-request` | `<silicon-id>` | Step-up action `silicon.rotate_token` on its principal UUID; creates an approval request and invalidates the old credential only after approval. |
| `iam silicon rotate-complete` | `<silicon-id> <approved-request-uuid>` | Same step-up action/resource; returns the replacement STK exactly once. |
| `iam silicon webhook` | `<silicon-id>` | Reads the current endpoint. |
| `iam silicon set-webhook` | `<silicon-id> --webhook-url <https-url>` | Step-up action `organization.silicon_webhook.redirect` on its membership UUID; returns the generated signing secret once. |
| `iam silicon delete-webhook` | `<silicon-id>` | Same step-up action/resource. |
| `iam silicon subscription` | `<silicon-id>` | Reads the current webhook subscription. |
| `iam silicon set-subscription` | `<silicon-id>` | Same redirect step-up. Mode defaults to `all`; `selected` requires one or more repeated `--topic`. `--own-tags-only` conflicts with additional `--tag` filters. |
| `iam silicon delete-subscription` | `<silicon-id>` | Same redirect step-up action/resource. |
| `iam silicon dead-letters` | `<silicon-id>` | Lists exhausted deliveries; optional paging. |
| `iam silicon replay` | `<silicon-id>` and one or more `--delivery <uuid>` | Re-queues only the named dead letters. |

### Applications, tokens, OBO, and webhooks

| Command | Required input | Authority and important constraints |
| --- | --- | --- |
| `iam app` | `<subcommand>` | Application namespace. Local IDs use `--org`; canonical IDs use `org>handle`. |
| `iam app list` | None | Carbon session; intentionally lists Applications across every organization the Carbon can administer. `--org` does not filter this view; `--status` does. |
| `iam app create` | `<app-id> --name <name> --webhook-url <https-url> --webhook-secret <secret> --base-url <origin>` | Active Carbon member of the owning org. The webhook secret is caller-chosen (32–512 visible ASCII); the generated client secret is returned once. Base URL is a pathless origin with no trailing slash. |
| `iam app show` | `<app-id>` | Carbon Application administrator. |
| `iam app update` | `<app-id>` plus at least one update or `--clear-*` flag | Carbon Application administrator; `--obo-endpoints` replaces the complete catalog. |
| `iam app rotate-secret` | `<app-id>` | Step-up action `application.client_secret.rotate` on the Application UUID; returns the replacement client secret once. |
| `iam app rotate-webhook-secret` | `<app-id> --webhook-secret <secret>` | Step-up action `application.webhook_secret.rotate` on the Application UUID. IAM stores the caller-chosen 32–512 visible-ASCII secret. |
| `iam app discover` | `<target-app-id> --as-app-id <requester-app-id>` plus requester secret at flag or prompt | Application-authenticated base-URL discovery; may cross organizations and respects production/test credential separation. |
| `iam app token` | `<subcommand>` | Application SLT exchange, refresh, introspection, and revocation namespace. |
| `iam app token exchange` | `<app-id>` plus SLT and Application secret at flags or prompts | SLT is single-use. Optional idempotency key is 16–255 visible ASCII; reuse the same key and input after an uncertain result. |
| `iam app token refresh` | `<app-id>` plus refresh token and Application secret at flags or prompts | Rotates the refresh and access tokens. Persist/reuse the same idempotency key after uncertainty; a new key with an already-used refresh token is a replay. |
| `iam app token introspect` | `<app-id>` plus token and Application secret at flags or prompts | `--token-type` is a hint. Optional `--org-context` must exactly match an org-bound token or the result is inactive. |
| `iam app token revoke` | `<app-id>` plus token and Application secret at flags or prompts | Access revocation affects one access token; refresh revocation affects the family. Optional 16–255 visible-ASCII idempotency key should be reused after uncertainty. |
| `iam app obo` | `<subcommand>` | Same-organization, organization-bound on-behalf-of namespace. |
| `iam app obo endpoints` | `<audience-app-id> --as-app-id <requester-app-id>` plus requester secret at flag or prompt | Application-authenticated catalog discovery; a cross-org target is deliberately indistinguishable from missing. |
| `iam app obo exchange` | `<audience-app-id> <endpoint-id> --as-app-id <requester-app-id> --method <method>` plus subject access token and requester secret at flags or prompts | Fetches the catalog, validates metadata, and signs the exact method/path/body binding. `--body` conflicts with `--body-file`; optional idempotency key must be reused for an uncertain identical request. |
| `iam app obo verify` | `<audience-app-id> --method <method> --path <path>` plus proof and audience secret at flags or prompts | Audience Application consumes the proof once and verifies the exact method, registered path, and body bytes. `--body` conflicts with `--body-file`. |
| `iam app verify-webhook` | `<body-file> --event-id <id> --timestamp <value> --key-version <version> --signature <v1=hex> --webhook-secret <secret>` | Fully local verification over exact raw bytes. Use `-` for stdin. A test-wrapped event requires the matching `--test`; production/test mismatches fail. |
| `iam app import` | `<canonical-production-app-id>` and `--test <environment-uuid>` | Signed-in test Carbon. If the target org already exists there, the Carbon must be its owner/admin; otherwise import creates the org and ownership. Returns a fresh test-only client secret once. |
| `iam app webhook` | `<app-id>` | Carbon Application administrator; reads the current endpoint. |
| `iam app set-webhook` | `<app-id> --webhook-url <https-url>` | Carbon Application administrator. The first replacement of an imported test webhook also requires a caller-chosen `--webhook-secret`; test endpoints activate immediately. |
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
| `iam config set` | `<key> <value>` | Key is `url`, `org`, or `auto-update`. Local only. Service URLs require HTTPS except literal loopback; auto-update accepts on/off forms. With `--test`, org is stored only for that environment. |
| `iam config unset` | `<key>` | Key is `org` or `auto-update`. Local only. With `--test`, clears only that environment's org; unsetting auto-update restores default-on. |
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
iam silicon create builder --job-role "Build agent"
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
IAM encrypts that value and never generates an Application webhook secret.

An Application belongs to exactly one organization. With an active `--org`
(or stored default), `app create billing` sends local handle `billing` and the
selected organization separately; IAM returns the canonical ID
`acme>billing`. Alternatively, `app create 'acme>billing'` infers `acme` when
no organization is selected. If both are present, they must match. Always
quote a canonical ID in a shell because an unquoted `>` is output redirection.
CLI options may appear before or after the positional Application ID, although
the examples keep the ID first for readability.

`--base-url` is the Application backend **origin**, for example
`https://billing.example.com`. It must contain no slash after the authority —
not even a trailing `/` — and no path, credentials, query, or fragment. HTTPS
is required except for literal `localhost`, `127.0.0.1`, or `::1` development.
`--webhook-url` is different: it is a complete HTTPS delivery endpoint, so it
may contain a path and may end in `/`.

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
iam carbon update --clear-description --clear-profile-photo
iam org update --clear-logo --clear-description
iam member update <membership-id> --clear-first-silicon \
    --clear-reports-to --clear-profile-photo
iam silicon update builder --clear-description \
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
not signed in, `4` the service refused, `5` the service could not be reached.

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
    --base-url http://127.0.0.1:4100 \
    --webhook-url https://hooks.example.test/iam \
    --webhook-secret "$TEST_WEBHOOK_SECRET"
```

Or import an existing production application by canonical ID. Import creates
its organization in the environment when needed, copies the base URL, webhook
URL and OBO catalog, inherits the production webhook signing secret without
revealing it, and returns a fresh test-only application secret:

```sh
iam --test "$TEST_ID" -o json app import 'google>drive'
```

To use a different test webhook URL, run `app set-webhook` inside the test
environment. Test endpoints activate immediately because an isolated plane has
no platform reviewer. For the first replacement of an imported app, pass
`--webhook-secret` with the caller-chosen test secret.
Rotate it explicitly with `app rotate-webhook-secret`; IAM never generates an
Application webhook secret.

Any test application can discover another application's base URL with its own
test-only credential:

```sh
iam --test "$TEST_ID" app discover 'google>drive' \
    --as-app-id 'acme>checkout'
```

The secret is prompted for when `--app-secret` is omitted, keeping it out of
shell history.

For ordinary same-organization commands, Application and Silicon local handles
are enough. The CLI expands `billing` to `acme>billing` and `builder` to
`builder:acme` from the active organization. Canonical IDs remain accepted for
cross-organization Application calls. On creation, a canonical ID supplies the
organization when none is active; when `--org` or a default is active, its
organization component must match.

Retiring one keeps it recoverable:

```sh
iam env delete <environment-id>    # prints the deadline
iam env restore <environment-id>
```

## Signing in to an application

An Application can start a session only by exchanging an IAM-issued,
single-use short-lived token (SLT). It cannot submit an OTP, email, phone,
Carbon ID, Silicon token, or IAM refresh token.

If this profile already holds a Carbon or Silicon IAM session, mint the SLT
without another login ceremony:

```sh
# Override any stored/environment organization for an unscoped login.
iam --no-org login --app-id 'acme>billing'

# Bound to the caller's active membership in acme; required for OBO.
iam --org acme login --app-id billing
```

To establish a new IAM session and then mint the SLT in one command:

```sh
iam --org acme login --email you@example.com --app-id billing
iam --org acme silicon-login --sid builder --app-id billing
```

`iam silicon-login` prompts for the Silicon token rather than taking it as a
flag by default, so it stays out of shell history. Without `--app-id` both
commands simply sign in to IAM. In every case, the Application receives only
the printed SLT and exchanges it through `iam app token exchange` (or
`OAuth::login` in the Rust client). This is the only Application-login path for
both Carbons and Silicons. A selected organization — from `--org`,
`SILICON_IAM_ORG`, or the current profile — requires the actor's active
membership and binds the resulting Application token family to it. Use the
global flag `--no-org` to override every stored/environment selection for this
invocation; it conflicts with `--org`. An unscoped login then needs the
canonical Application ID because no organization is available to qualify a
local handle.
An organization-bound access token is required for OBO.

### End-to-end Application proof in a test environment

The complete Application protocol can be exercised without `curl` or SDK code.
This creates an isolated plane and two Applications, exchanges and refreshes a
login, checks it authoritatively, mints and consumes an OBO proof, then revokes
the token family. `jq` is used only to carry JSON fields between `iam`
commands:

```sh
ENVIRONMENT=$(iam -o json env create cli-application-proof)
TEST_ID=$(printf '%s' "$ENVIRONMENT" | jq -r .id)

iam --test "$TEST_ID" signup --email proof@example.test \
    --phone +14155550123 --carbon-id proof
iam --test "$TEST_ID" login --email proof@example.test --code 000000
iam --test "$TEST_ID" org create acme --name Acme

CALLER=$(iam --test "$TEST_ID" -o json app create caller --org acme \
    --name Caller --base-url http://127.0.0.1:4101 \
    --webhook-url https://hooks.example.test/caller \
    --webhook-secret caller-demo-webhook-secret-000001)
CALLER_SECRET=$(printf '%s' "$CALLER" | jq -r .app_secret)

AUDIENCE=$(iam --test "$TEST_ID" -o json app create audience --org acme \
    --name Audience --base-url http://127.0.0.1:4102 \
    --webhook-url https://hooks.example.test/audience \
    --webhook-secret audience-demo-webhook-secret-0001 \
    --obo-endpoints \
    '[{"endpoint_id":"orders.create","path":"/v1/orders","metadata":{"reason":{"type":"string"}}}]')
AUDIENCE_SECRET=$(printf '%s' "$AUDIENCE" | jq -r .app_secret)

# An Application credential can discover another Application in this plane.
iam --test "$TEST_ID" app discover 'acme>audience' \
    --as-app-id 'acme>caller' --app-secret "$CALLER_SECRET"

SLT=$(iam --test "$TEST_ID" --org acme -o json login \
    --app-id 'acme>caller' | jq -r .slt)
TOKENS=$(iam --test "$TEST_ID" -o json app token exchange 'acme>caller' \
    --slt "$SLT" --app-secret "$CALLER_SECRET")
ACCESS=$(printf '%s' "$TOKENS" | jq -r .access_token)
REFRESH=$(printf '%s' "$TOKENS" | jq -r .refresh_token)

iam --test "$TEST_ID" -o json app token introspect 'acme>caller' \
    --token "$ACCESS" --token-type access-token \
    --org-context acme --app-secret "$CALLER_SECRET" | jq -e '.active == true'

TOKENS=$(iam --test "$TEST_ID" -o json app token refresh 'acme>caller' \
    --refresh-token "$REFRESH" --app-secret "$CALLER_SECRET")
ACCESS=$(printf '%s' "$TOKENS" | jq -r .access_token)
REFRESH=$(printf '%s' "$TOKENS" | jq -r .refresh_token)

iam --test "$TEST_ID" app obo endpoints 'acme>audience' \
    --as-app-id 'acme>caller' --app-secret "$CALLER_SECRET"
PROOF=$(iam --test "$TEST_ID" -o json app obo exchange \
    'acme>audience' orders.create --as-app-id 'acme>caller' \
    --subject-token "$ACCESS" --app-secret "$CALLER_SECRET" \
    --method POST --body '{"order_id":"demo-1"}' \
    --metadata '{"reason":"CLI proof"}' | jq -r .access_proof)
iam --test "$TEST_ID" app obo verify 'acme>audience' \
    --access-proof "$PROOF" --app-secret "$AUDIENCE_SECRET" \
    --method POST --path /v1/orders --body '{"order_id":"demo-1"}'

iam --test "$TEST_ID" app token revoke 'acme>caller' \
    --token "$REFRESH" --token-type refresh-token \
    --app-secret "$CALLER_SECRET"
iam --test "$TEST_ID" -o json app token introspect 'acme>caller' \
    --token "$ACCESS" --token-type access-token \
    --org-context acme --app-secret "$CALLER_SECRET" | jq -e '.active == false'
```

The second `login` above intentionally supplies no identity or OTP: it proves
that an existing IAM session can mint an organization-bound SLT and that the
Application still sees only that SLT. The two `jq -e` checks prove the exact
organization authority before revocation and inactive state afterward.

The OBO exchange reads the audience's current catalog, hashes the exact body
bytes, and delegates canonical path/signature construction to the Rust client
using the same caller credential and idempotency key that go on the request.
Verification hashes the actual body again and consumes the proof once. To
recover an uncertain exchange, reuse `--idempotency-key` and every JSON request
input but omit `--timestamp` so the retry is signed with a fresh value. The
timestamp and signature are not idempotency material; an old timestamp falls
outside the 60-second signature window. `--timestamp` exists for controlled
protocol checks and must itself be current.

Token exchange, refresh, and revocation accept `--idempotency-key`. Persist
that key before a refresh or revocation and reuse it after an uncertain
outcome; retrying the same refresh token under a new key is treated as a replay
and compromises that Application refresh family. It does not revoke the parent
IAM session, other devices, or unrelated Applications. Revoking a refresh token
invalidates its whole Application family and related access authority; revoking
an access token invalidates only that access token. Either operation deliberately
succeeds when the token is already unknown.

`--org-context` on introspection is an optional exact organization handle. A
well-formed handle that does not match the token — including any unscoped
token — returns `active: false`; a
malformed or duplicated `X-Org-ID` is rejected as an invalid request.

For normal interactive use, omit `--app-secret`, `--slt`, `--refresh-token`,
`--token`, `--subject-token`, or `--access-proof`; the CLI prompts for each so
the value does not enter shell history. They are explicit above only to make
the isolated proof reproducible.

Before shipping an integration, manually exercise the rejected paths in the
same disposable environment, not only the happy path:

- repeat token exchange, refresh, revocation, and OBO exchange with the same
  explicit idempotency key and exact input; then change one input under that
  key and confirm `409 idempotency_conflict`;
- verify one OBO proof twice and confirm only the first succeeds; change its
  method, registered path, or one body byte and confirm verification fails;
- mint another Application token with `--no-org` and confirm OBO exchange is
  refused, then repeat with `--org acme` and confirm it succeeds;
- create an Application in a second organization and confirm ordinary base-URL
  discovery can find it but OBO discovery returns the same `404 not_found` as a
  nonexistent target;
- introspect with the matching organization, a different valid organization,
  and a malformed organization; expect active, inactive, and request error
  respectively;
- try production credentials with `--test`, and test credentials without it;
  both directions must fail;
- confirm `app create` rejects a missing/short webhook secret and rejects
  `--base-url https://example.test/`, while a webhook URL with a path remains
  valid;
- run each relevant `--clear-*` form and re-read the resource to distinguish
  cleared from unchanged.

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

`SILICON_IAM_HOME` moves the store somewhere else, which is what to use in CI so
a build never touches a developer's real credentials.

## Step-up

Privileged commands need a short-lived assertion bound to one exact action and
one internal resource UUID. Every affected command names both values in its
`--help`. The complete CLI mapping is:

| Command | Step-up action | Resource UUID |
| --- | --- | --- |
| `org transfer` | `organization.transfer_ownership` | organization `id` |
| `member remove`, `promote`, `demote`, `capabilities` | `organization.authorization_change` | target membership ID |
| `silicon remove` | `organization.authorization_change` | target Silicon `membership_id` |
| `silicon rotate-request`, `rotate-complete` | `silicon.rotate_token` | target Silicon `principal_id` |
| `silicon set-webhook`, `delete-webhook`, `set-subscription`, `delete-subscription` | `organization.silicon_webhook.redirect` | target Silicon `membership_id` |
| `app rotate-secret` | `application.client_secret.rotate` | Application `id` |
| `app rotate-webhook-secret` | `application.webhook_secret.rotate` | Application `id` |
| `sso disable` | `organization.sso_change` | organization `id` |
| `session revoke` | `account.session_revoke` | session ID |
| `logout --all` when other sessions are active | `account.sessions_revoke_all` | signed-in Carbon `principal_id` |
| `approval decide` for a `silicon_token_rotation` request | `silicon.rotate_token` | target Silicon `principal_id` |

The public handles accepted by most commands are not the step-up resource.
Read the internal UUID first, mint the assertion, then pass it to the matching
mutation. For example:

```sh
SILICON=$(iam -o json silicon show builder)
SILICON_MEMBERSHIP=$(printf '%s' "$SILICON" | jq -r .membership_id)

TOKEN=$(iam -o json step-up organization.silicon_webhook.redirect \
    "$SILICON_MEMBERSHIP" | jq -r .step_up_token)
iam silicon set-webhook builder \
    --webhook-url https://example.com/hooks --step-up "$TOKEN"
```

Useful UUID sources are `iam -o json org show | jq -r .id`,
`iam -o json member list`, `iam -o json silicon show <silicon>` (both
`membership_id` and `principal_id`), `iam -o json app show <app> | jq -r .id`,
`iam -o json session list`, and `iam -o json carbon show | jq -r .principal_id`.

If the code is not supplied, `iam step-up` prompts after sending it to the
selected verified channel (`--channel email` by default, or `phone`). The
service also rejects a missing or mismatched assertion explicitly:

```
error: A step-up assertion is required. (step_up_required)
hint: This action needs step-up verification; re-run with --step-up.
```

## What is not here

Platform administration, the inbound provider webhooks, and the browser login
screen. Those belong to the operator, to the provider, and to the browser —
not to a command-line caller.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.

Copyright 2026 Team of Silicons.
