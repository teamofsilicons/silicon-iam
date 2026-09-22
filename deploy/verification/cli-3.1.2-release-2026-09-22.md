# IAM CLI 3.1.2 publication — September 22, 2026

## Result

CLI 3.1.2 is published from `7b28a76149b4351f034963113df7fef40a7e988f` as
[GitHub v3.1.2](https://github.com/teamofsilicons/silicon-iam/releases/tag/v3.1.2),
Honeycomb production release `99cdeeb9-5e65-43bb-b03e-a39d35ff4daa`, and the
`silicon-iam-cli 3.1.2` crate. Root help is now a 65-line overview instead of
16,457 lines. Detailed command help remains scoped, the offline JSON catalog
contains all 199 public commands, and the complete bundled CLI guide remains
available through `iam docs cli`.

## Verification

All 63 CLI tests, Clippy with warnings denied, formatting and generated-manual
checks passed. Tests and native smoke checks cover both help flags, `iam help`,
scoped help, machine-readable discovery, unavailable credential storage and
absence of state writes or update checks during help.

[Native release CI](https://github.com/teamofsilicons/silicon-iam/actions/runs/35702231127)
passed all six platform builds, source/package validation, native executable
version checks and Linux glibc 2.28 compatibility checks. Each downloaded binary
was checked against its source receipt, format, CPU architecture and checksum.
The native macOS ARM executable independently passed root/scoped help and command
catalog checks.

[Exact-source repository CI](https://github.com/teamofsilicons/silicon-iam/actions/runs/35702151423)
passed formatting, workspace lint/tests, live PostgreSQL protocols, migration
security/grants, fresh migrations, worker/client smoke tests under restricted
roles, and monotonic key activation. Dependency policy also passed.

The crate was published with ordinary Cargo package compilation/verification.
Anonymous crate bytes matched the verified local publication artifact and its
embedded Git revision. Crate SHA-256: `1f5453486ee85e8b36e389f9f7189445ec10e7f6e1a5f65c0fac0a26bb01bda4` (328,208 bytes).

## Native archive and license correction

Published archive: `iam-3.1.2-honeycomb.tar.gz`, 28,254,327 bytes,
SHA-256 `c28dc2405c0a97ca102bb80afa030161e2feb321293269f307ba587c043fbb8b`.
Honeycomb accepted the production release and retained publication
`82c4c695-af1b-4843-afb5-dba9097d9876` in the published state.

The pinned workflow originally packaged the repository-root backend license.
The release operator was corrected to copy the CLI's existing Apache-2.0 license
from `crates/cli/LICENSE`; its existing deterministic archive test now verifies
all six license copies. The operator snapshot used for the final archive is
`5938f9b24b87625604d2b2f1e4ae55665aae9696`. The original CI archive hash was
`261dcf4d2a679431e110d299676a4c258f069e6c01d95ed10eb14b8ba253598b`. Comparison proved that the manifest and every binary
payload remained byte-identical; only the six license files changed. The binary
provenance JSON and binary checksum list therefore retain the exact CI source
revision above. The final archive/checksum metadata were regenerated together.

All four GitHub release assets were independently downloaded anonymously and
matched the checked local bytes, checksum file and GitHub digests. Binary
provenance, archive member integrity and all six CLI license copies were verified.

## Installed CLI and saved session

A fresh anonymous Honeycomb installation downloaded the exact published archive,
ran `iam 3.1.2`, printed 65-line root help and correctly remained signed out.
Its native macOS ARM binary hash is `e37851ef1bb4e258ae547dee30f6fb7dcb9496306d7dab8e594dc8011aaa88e4`.
Maharaj's managed installation then updated through `honeycomb update 'tos>iam'`.
Its installed binary matches that anonymous install, detailed help and all 199
catalog entries remain available, and live `whoami` retained the same Silicon,
organization and membership without another login. Credentials were not manually
copied, edited or deleted.

## Documentation

The public documentation was built with Node 24; all 47 HTML page checks passed.
Vercel deployment `dpl_2dSBfbFsvwFxwd6J59mwZTkj2kBG` is Ready and serves
[the CLI guide](https://docs.iam.teamofsilicons.com/cli/). Anonymous homepage and
CLI guide responses match the built output exactly. The guide describes concise
help and complete JSON discovery; the homepage identifies CLI 3.1.2 and Rust
client 3.1.0 separately.

Nonsecret machine-readable receipts are retained under
`/tmp/iam-cli-3.1.2-proof/`, including `crate-proof.json`, `native-proof.json`,
`github-public-proof.json`, `honeycomb-upload.json`,
`anonymous-install-proof.json`, `maharaj-retained-session-proof.json`, and
`docs-public-verification.json`. The prior identity comparison snapshot is private
and is not included in release artifacts or this receipt.
