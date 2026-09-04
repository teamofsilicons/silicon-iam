# silicon-iam-cli

Silicon IAM from the command line. Installs a single binary, `iam`.

```sh
cargo install silicon-iam-cli
```

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
is close to expiring. `iam logout` forgets it locally; it does not end the
session on the service, so clearing one laptop does not sign you out
everywhere. Use `iam session revoke` for that.

## Finding your way around

Commands read as noun then verb:

```sh
iam -h                 # the top-level commands and global options
iam commands           # every command, at every depth
iam tag --help         # one group
iam tag delete --help  # one command's options
```

## Everyday use

```sh
# Organizations
iam org list
iam org create acme --name "Acme"
iam org show

# Members
iam member list
iam member list --principal-type silicon
iam member show <membership-id>
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
iam silicon set-webhook builder:acme --url https://example.com/hooks

# Applications
iam app create billing --name Billing \
    --base-url https://billing.example.com \
    --webhook-url https://billing.example.com/hooks
iam app rotate-secret 'acme>billing' --step-up "$TOKEN"
iam app rotate-webhook-secret 'acme>billing' --step-up "$TOKEN"
```

## Output

Text by default, aligned for reading. `-o json` gives the service's own JSON,
unmodified, which is what to reach for in a script:

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

### Applications in a test environment

Create a brand-new application through the ordinary command. Its local handle
must not collide with a production application in the same organization:

```sh
iam --test "$TEST_ID" app create checkout --org acme --name Checkout \
    --base-url http://127.0.0.1:4100 \
    --webhook-url https://hooks.example.test/iam
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
no platform reviewer. That environment then owns a newly generated signing
secret, ready for the new URL; rotate it explicitly with
`app rotate-webhook-secret` when needed.

Any test application can discover another application's base URL with its own
test-only credential:

```sh
iam --test "$TEST_ID" app discover 'google>drive' \
    --as-app-id 'acme>checkout'
```

The secret is prompted for when `--app-secret` is omitted, keeping it out of
shell history.

Retiring one keeps it recoverable:

```sh
iam env delete <environment-id>    # prints the deadline
iam env restore <environment-id>
```

## Signing in to an application

Naming an application prints a short-lived token it can exchange for a session:

```sh
iam login --email you@example.com --app-id 'acme>billing'
iam silicon-login --sid builder:acme --app-id 'acme>billing'
```

`iam silicon-login` prompts for the Silicon token rather than taking it as a
flag by default, so it stays out of shell history. Without `--app-id` both
commands simply sign in.

### End-to-end Application proof in a test environment

The complete Application protocol can be exercised without `curl` or SDK code.
This creates an isolated plane and two Applications, exchanges and refreshes a
login, checks it authoritatively, then mints and consumes an OBO proof. `jq` is
used only to carry JSON fields between `iam` commands:

```sh
ENVIRONMENT=$(iam -o json env create cli-application-proof)
TEST_ID=$(printf '%s' "$ENVIRONMENT" | jq -r .id)

iam --test "$TEST_ID" signup --email proof@example.test \
    --phone +14155550123 --carbon-id proof
iam --test "$TEST_ID" login --email proof@example.test --code 000000
iam --test "$TEST_ID" org create acme --name Acme

CALLER=$(iam --test "$TEST_ID" -o json app create caller --org acme \
    --name Caller --base-url http://127.0.0.1:4101 \
    --webhook-url https://hooks.example.test/caller)
CALLER_SECRET=$(printf '%s' "$CALLER" | jq -r .app_secret)

AUDIENCE=$(iam --test "$TEST_ID" -o json app create audience --org acme \
    --name Audience --base-url http://127.0.0.1:4102 \
    --webhook-url https://hooks.example.test/audience \
    --obo-endpoints \
    '[{"endpoint_id":"orders.create","path":"/v1/orders","metadata":{"reason":{"type":"string"}}}]')
AUDIENCE_SECRET=$(printf '%s' "$AUDIENCE" | jq -r .app_secret)

# An Application credential can discover another Application in this plane.
iam --test "$TEST_ID" app discover 'acme>audience' \
    --as-app-id 'acme>caller' --app-secret "$CALLER_SECRET"

SLT=$(iam --test "$TEST_ID" -o json login --carbon-id proof --code 000000 \
    --app-id 'acme>caller' | jq -r .slt)
TOKENS=$(iam --test "$TEST_ID" -o json app token exchange 'acme>caller' \
    --slt "$SLT" --app-secret "$CALLER_SECRET")
ACCESS=$(printf '%s' "$TOKENS" | jq -r .access_token)
REFRESH=$(printf '%s' "$TOKENS" | jq -r .refresh_token)

iam --test "$TEST_ID" app token introspect 'acme>caller' \
    --token "$ACCESS" --token-type access-token \
    --org-context acme --app-secret "$CALLER_SECRET"

TOKENS=$(iam --test "$TEST_ID" -o json app token refresh 'acme>caller' \
    --refresh-token "$REFRESH" --app-secret "$CALLER_SECRET")
ACCESS=$(printf '%s' "$TOKENS" | jq -r .access_token)

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
```

The OBO exchange reads the audience's current catalog, hashes the exact body
bytes, and signs the registered path with the caller secret. Verification
hashes the actual body again and consumes the proof once. Add
`--idempotency-key` and `--timestamp` together only when recovering the exact
same uncertain exchange.

Token exchange and refresh also accept `--idempotency-key`. Persist that key
before a refresh and reuse it after an uncertain outcome; retrying the same
refresh token under a new key is treated as a replay and compromises its token
family.

For normal interactive use, omit `--app-secret`, `--slt`, `--refresh-token`,
`--token`, `--subject-token`, or `--access-proof`; the CLI prompts for each so
the value does not enter shell history. They are explicit above only to make
the isolated proof reproducible.

### Offline webhook verification

Save the exact body bytes and the four `X-Silicon-IAM-*` headers before a web
framework parses them. The CLI verifies the signature, timestamp, key version,
event ID, and event schema locally:

```sh
iam app verify-webhook delivery.json \
    --event-id "$EVENT_ID" --timestamp "$TIMESTAMP" \
    --key-version "$KEY_VERSION" --signature "$SIGNATURE"
```

The signing secret is prompted for when `--webhook-secret` is omitted. For a
test delivery, add `--test "$TEST_ID"`; the CLI then also compares the wrapped
`testing_key` in constant time with that environment's locally stored key. A
wrapped test event without `--test`, a production event with `--test`, or a key
for a different environment is rejected. Successful output is the normalized
event and never includes the testing root key.

## Profiles

One profile per service, or per identity on the same service:

```sh
iam --profile staging config set url https://staging.example.com
iam --profile staging login --email you@example.com
iam config profiles
iam config use staging
```

Every setting can also come from the environment: `SILICON_IAM_URL`,
`SILICON_IAM_PROFILE`, `SILICON_IAM_ORG`, `SILICON_IAM_TEST`. Flags win
over environment variables, which win over stored settings.

`SILICON_IAM_HOME` moves the store somewhere else, which is what to use in CI so
a build never touches a developer's real credentials.

## Step-up

Some actions — promoting an admin, rotating a secret, transferring ownership —
need a second factor beyond the session. The service says so, and the CLI
repeats it:

```
error: A step-up assertion is required. (step_up_required)
hint: This action needs step-up verification; re-run with --step-up.
```

Obtain the assertion through the step-up flow, then pass it with `--step-up`.

## What is not here

Platform administration, the inbound provider webhooks, and the browser login
screen. Those belong to the operator, to the provider, and to the browser —
not to a command-line caller.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.

Copyright 2026 Team of Silicons.
