# Scope approval inbox release — September 14, 2026

Released `d279512220e9c6001c3968bbdf1b0b9d03efe0d1` to the IAM API, scoped API,
worker, and production frontend. Applications now have an Approvals tab with
incoming/sent filters and visible completed history. Review threads show the
critical decision boundary, all current scopes for the reviewing provider,
and sent/received/system message labels.

Image: `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:7aa140fea4b930377205971b77bd4a9f3a73125188660e3f59a583fe944d5c0e`.
Frontend: `silicon-iam-frontend-3icnjquub-saketdev12-5675s-projects.vercel.app`,
promoted to the existing production domains.

Migration 0091 applied successfully to production and testing. It replaces only
the authorized scope-review JSON projection; it does not change grants, decisions,
or caller scope declarations. Request and approval counts were checked before
and after migration and were unchanged. All three services are healthy, and the
public version endpoint reports the release revision.

CloudFormation change set `scope-reviews-d279512` completed. It changed only
BackendImageUri, the launch-template data, and the ASG launch-template version
reference so replacement instances inherit the release. No instance refresh was
requested. Previous service units and the previous SQL view definition are
retained privately on the runtime host under
`/etc/silicon-iam/releases/scope-reviews-d279512220e9c6001c3968bbdf1b0b9d03efe0d1`.
Because readiness checks the embedded migration ledger, restoring an older image
requires a compatible forward-schema rollback build; do not downgrade the ledger.

Verification: 37 frontend tests and the real PostgreSQL critical-scope review
lifecycle test passed, including non-critical context, provider isolation,
authorship flags, and unchanged approval enforcement. Production build,
OpenAPI route check, runtime-grant check, and migration-security check passed.
Browser verification shows Starter's approved incoming Briefcase request, all
five currently declared Briefcase scopes, and Received/System message labels.
The pre-existing approval was not made or changed as part of this release.
