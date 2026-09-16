# Private application login error release — September 16, 2026

Production source: `caf45a021c8b06e5b7695cd2550ffe5c30879a35`.
Immutable image: `234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:7a9d77ac00b9e4e776cfd7381ad19505f6557034eec70f74028912c4667d72fd`.

Single, batch, and bundle SLT issuance now maps the known private cross-organization SQL guard to HTTP 403 `private_application_organization_required`, preserving the owning-organization restriction. Unexpected database failures remain internal errors. No migration or runtime configuration change is needed.

SSM command `a674d29e-79a5-40fa-a867-c826119c35db` rolled out the scoped API, main API, and worker with readiness gates and rollback units. All three services are healthy; runtime environment files are unchanged. Public `/api/v1/version` returns the exact source commit above. CloudFormation change set `external-bugs-caf45a0` reached `UPDATE_COMPLETE`, persisting the backend image and dependent launch-template version.

Rollback units are retained privately at `/etc/silicon-iam/releases/external-bugs-caf45a021c8b06e5b7695cd2550ffe5c30879a35-1789583279473932899`. The preceding image was `sha256:7d2de04e5701f2a007ec8b2d3fbce276ce39ad0fe7f9d4c3cdb3614b121a9b8c`.

Validation: all-target/all-feature workspace tests, strict Clippy, formatting, OpenAPI, migration-security and runtime-grant checks passed locally. The disposable PostgreSQL regression verifies public second-organization success, private owning-organization success, and precise private second-organization rejection. GitHub's initial run passed format, lint, tests, live PostgreSQL and OpenAPI checks, then identified the new fix report missing from the documentation catalog exclusions. That catalog-only correction is committed separately; it does not change the deployed backend artifact.

Public readiness checks after rollout passed for IAM and the seven dependent services in this task. Production principals and application grants were not changed for regression testing.
