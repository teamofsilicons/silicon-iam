# Scoped directory fix for Hook — September 13, 2026

Released backend revision `15e98aec5d261e27908650fa2ede2bf5cc428634` to the existing IAM API, scoped API and worker on `i-011c97da3d8b7ec74` while completing the authorized Hook production rollout.

The directory actor filter now casts its bound string to `iam.principal_kind`. Previously a Silicon-only application grant caused PostgreSQL enum/text comparison to fail and the scoped directory returned HTTP 500. A live request with Hook’s application token now returns HTTP 200 and an empty authorized directory, as expected for its current organization data.

Image: `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:df9126376272e62d687c0e17ad1f938c3818b31951d8082c8d34b20b7a450b4b`.

Five focused directory tests, library Clippy and formatting passed. All three services are healthy and the public version endpoint matches the release revision. No schema or credential changes were needed. The release installer retained previous unit/environment files for rollback. CloudFormation change set `hook-directory-15e98ae` completed and updated only the launch template and ASG reference so replacements inherit the fix.
