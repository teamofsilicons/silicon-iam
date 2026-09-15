# Dependency and CLI release management

IAM dependencies follow the consuming project's Cargo configuration. The Rust client never updates itself or changes a lockfile at runtime.

## Rust dependencies

Choose a compatible client version in Cargo.toml, review dependency updates and rebuild your application. The old auto_update and update_manifest builder settings remain accepted for source compatibility but have no effect. update_status always reports Disabled.

## CLI releases

Install and update the CLI through Honeycomb using the configured IAM application ID:

```
honeycomb install <configured-iam-app-id>
honeycomb update <configured-iam-app-id>
```

IAM does not run a second updater. Existing daemon check commands do no update work; system update returns instructions for Honeycomb. Remove a legacy updater service with iam daemon uninstall.

## Before Honeycomb is available

Build and install the CLI from a pinned source checkout using cargo install --path crates/cli --locked. The direct installer remains available without starting an updater. Backend deployment and migration are separate from CLI installation.
