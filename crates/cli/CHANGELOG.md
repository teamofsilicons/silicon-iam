# Changelog

## 1.6.0

- Added `iam app bundle availability` for the selected organization.
- Application and bundle lists now apply the selected organization before pagination; `--no-org` lists across administered organizations.
- Bundle lists support `--cursor` and `--limit` and display continuation cursors.
- Added `iam app bundle update --clear-logo`; omitted logo flags preserve the current image.
- Updated the SDK dependency to 1.6.0 and refreshed the bundled manuals.
- Login history supports events whose actor identifier is hidden by directory permissions.
