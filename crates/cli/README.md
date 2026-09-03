# silicon-iam-cli

Silicon IAM from the command line. Installs a single binary, `siam`.

```sh
cargo install silicon-iam-cli
```

Everything the CLI can do, the [`silicon-iam-client`](https://crates.io/crates/silicon-iam-client) crate can do —
the CLI is a shell over it and has no capability of its own. What it adds is
memory: which service, which profile, whose session, and a terminal to read a
verification code from.

## First run

```sh
siam config set url https://backend.iam.teamofsilicons.com
siam login --email you@example.com
siam config set org acme          # most commands act on an organization
siam whoami
```

The session is stored under `~/.silicon-iam/` and renewed automatically when it
is close to expiring. `siam logout` forgets it locally; it does not end the
session on the service, so clearing one laptop does not sign you out
everywhere. Use `siam session revoke` for that.

## Finding your way around

Commands read as noun then verb:

```sh
siam -h                 # the top-level commands and global options
siam commands           # every command, at every depth
siam tag --help         # one group
siam tag delete --help  # one command's options
```

## Everyday use

```sh
# Organizations
siam org list
siam org create acme --name "Acme"
siam org show

# Members
siam member list
siam member list --principal-type silicon
siam member show <membership-id>
siam member promote <membership-id> --step-up "$TOKEN"

# Tags
siam tag create Engineering
siam tag members <tag-id>
siam tag delete <tag-id>          # takes its assignments and trust rules with it

# Governance
siam approval list --mine
siam approval decide <request-id> --decision approve
siam approval set-tags <membership-id> --tag <tag-id> --tag <tag-id>

# Silicons
siam silicon create builder --job-role "Build agent"
siam silicon set-webhook builder:acme --url https://example.com/hooks

# Applications
siam app create billing --name Billing --webhook-url https://example.com/hooks
siam app rotate-secret billing --step-up "$TOKEN"
```

## Output

Text by default, aligned for reading. `-o json` gives the service's own JSON,
unmodified, which is what to reach for in a script:

```sh
siam -o json org show | jq -r .owner_membership_id
```

Exit codes distinguish the cases worth branching on: `2` a usage mistake, `3`
not signed in, `4` the service refused, `5` the service could not be reached.

## Testing environments

An environment is the whole service against a separate database, starting
empty. Create one, then point any command at it:

```sh
KEY=$(siam -o json env create Sandbox | jq -r .key)

siam --environment "$KEY" env current      # the key alone describes it
siam --environment "$KEY" signup --email dev@example.test \
     --phone +14155550123 --carbon-id dev
siam --environment "$KEY" org list         # empty: it is a fresh world
```

Environments send no email, SMS or webhooks, and accept the fixed verification
code `000000`. Credentials do not cross the boundary in either direction, so a
production session is refused inside an environment and vice versa. Store the
key with `siam config set environment "$KEY"` to stop repeating the flag, and
`siam config unset environment` to come back out.

Retiring one keeps it recoverable:

```sh
siam env delete <environment-id>    # prints the deadline
siam env restore <environment-id>
```

## Profiles

One profile per service, or per identity on the same service:

```sh
siam --profile staging config set url https://staging.example.com
siam --profile staging login --email you@example.com
siam config profiles
siam config use staging
```

Every setting can also come from the environment: `SILICON_IAM_URL`,
`SILICON_IAM_PROFILE`, `SILICON_IAM_ORG`, `SILICON_IAM_ENVIRONMENT`. Flags win
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

Platform administration, the inbound provider webhooks, and the browser consent
screens. Those belong to the operator, to the provider, and to the browser —
not to a command-line caller.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.

Copyright 2026 Team of Silicons.
