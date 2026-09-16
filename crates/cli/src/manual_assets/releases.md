# Install and release the IAM CLI

Once the IAM release is registered in Honeycomb:

```sh
honeycomb install <configured-iam-app-id>
iam login --help
honeycomb update <configured-iam-app-id>
```

Use the application ID configured for your deployment. IAM's Rust library follows
the consuming project's Cargo dependency configuration and never updates itself.
IAM does not run an independent CLI updater. Old `iam daemon check` invocations
are harmless no-ops; `iam system update` explains the Honeycomb command. Remove
an old updater service with `iam daemon uninstall`. An IAM telemetry daemon can
still be explicitly supervised when needed.

## Direct bootstrap

The initial IAM backend, signup and login do not require Honeycomb. At a reviewed,
pinned source revision, follow the repository's PostgreSQL deployment and key
configuration instructions, then build the backend and CLI:

```sh
cargo build --release --locked --bins
cargo install --path crates/cli --locked
iam --help
```

The direct `scripts/install.sh` installer is also available before the catalog
exists. It does not install an updater. Backend migrations and deployment remain
separate operator actions; installing a CLI archive never runs them.

## Combined CLI archive

Build the CLI from the same revision for the six Honeycomb targets and stage only
the resulting executables:

| Honeycomb target | Rust target | Staged executable |
| --- | --- | --- |
| linux-x86_64 | x86_64-unknown-linux-gnu | linux-x86_64/iam |
| linux-aarch64 | aarch64-unknown-linux-gnu | linux-aarch64/iam |
| windows-x86_64 | x86_64-pc-windows-msvc | windows-x86_64/iam.exe |
| windows-aarch64 | aarch64-pc-windows-msvc | windows-aarch64/iam.exe |
| macos-x86_64 | x86_64-apple-darwin | macos-x86_64/iam |
| macos-aarch64 | aarch64-apple-darwin | macos-aarch64/iam |

```sh
python3 scripts/package-honeycomb.py --staging /path/to/staged-binaries \
  --output /path/to/iam-release.tar.gz --app-id '<configured-iam-app-id>' \
  --version <release-version>
```

The deterministic archive contains a Honeycomb v1 `honeycomb.yaml`, six executable
payloads and one license copy inside each platform root. Missing targets, links, empty binaries and overwriting
an existing archive are rejected. The script never includes local credentials,
environment files or backend configuration. Validate the archive with Honeycomb
before submitting the release; publication requires Honeycomb integration.

## Native CI build

The `CLI release assets` workflow builds and verifies each target on its
native operating system and architecture. Dispatch it from a pushed source revision
with `source_revision` set to that exact full commit SHA and `app_id` set to the
registered IAM application ID. The workflow checks the executable header and native
`iam --version`, then uploads six artifacts and a combined archive with checksums
and source provenance. It does not publish the application or approve a release.
