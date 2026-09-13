# Changelog

## 1.9.0

Add issuer discovery, --json, verified login status and GitHub reports with optional PR links. Replace command-triggered updates with a supervised hourly worker, user service controls and an installer. Reorganize online and bundled docs around usage and building applications. Add default-on, configurable Space Station telemetry for commands, SDK requests and daemon activity, with a dedicated table and private recording key.

## 1.8.0

- Update the IAM client and embedded testing-environment documentation to 1.8.0.

## 1.7.0

- Added `app testing manage` for reading, editing, cleaning, deleting, restoring, revealing, and rotating keys for application-owned environments.
- Added `app testing view` with secure prompts for test credentials.
- Added active/deleted/all filters and lifecycle ownership to application environment listings.
- Updated the SDK and embedded documentation to 1.7.0.

## 1.6.0

- Added `iam app bundle availability` for the selected organization.
- Application and bundle lists now apply the selected organization before pagination; `--no-org` lists across administered organizations.
- Bundle lists support `--cursor` and `--limit` and display continuation cursors.
- Added `iam app bundle update --clear-logo`; omitted logo flags preserve the current image.
- Updated the SDK dependency to 1.6.0 and refreshed the bundled manuals.
- Login history supports events whose actor identifier is hidden by directory permissions.
