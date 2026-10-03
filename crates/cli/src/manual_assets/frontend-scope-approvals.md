# Application permission approvals

Manage application permission requests and publication reviews in [Honeycomb](https://console.honeycomb.teamofsilicons.com/requests/received). Received requests show reviews you are currently authorized to handle; sent requests show approval progress for applications you manage. Each provider has its own discussion page, requested permissions, message history, and decision.

Honeycomb owns the review inbox, discussion, notification emails, and publication workflow. IAM checks reviewer authority and enforces accepted permissions. User login consent, personal OBO consent, and organization governance approvals remain in IAM.

Create and configure production applications through Honeycomb. Direct IAM app registration and legacy scope-request submissions return `410 management_moved_to_honeycomb`. An internal IAM application record is required for runtime authentication, but does not itself register an application or create a review in Honeycomb.

Existing approval emails may contain an IAM `/applications?scope_request=...` or `/scope-reviews?request=...` link. IAM forwards only the validated request ID to Honeycomb. For migrated requests, Honeycomb resolves that ID to the original provider's discussion after checking the signed-in account's current access. Signing in preserves the destination. Unavailable requests show a clear message without exposing another application's details.

Migrating a request preserves its original messages and author attribution. It does not approve permissions, rotate app credentials, or publish the app. Reviewers make their decisions through Honeycomb's normal IAM-validated review flow.
