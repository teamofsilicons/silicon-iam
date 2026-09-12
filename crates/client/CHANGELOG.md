# Changelog

## 1.6.0

- Added `bundles().availability(org_id)` for derived bundle configuration availability.
- Added organization filtering before pagination through `applications().list_for_organization` and `bundles().list_for_organization`.
- Added `bundles().list_page` and exposed the existing bundle response's `page` metadata.
- Documented bundle logo URLs and the distinct preserve, replace, and clear patch values.
- Login history preserves authorized events when directory permissions hide an actor's public identifier.
