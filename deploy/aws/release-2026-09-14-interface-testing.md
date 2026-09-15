# Delegated Interface test-world release — September 14, 2026

The native non-critical permission `organization.testing_environments.create`
now authorizes scoped creation of an isolated IAM world for an active Carbon's
selected organization. Its actual root uses the existing encrypted idempotent
receipt. Test-root-selected scoped authentication resolves only imported `tos>iam`
and reuses the existing test actor-login protocol. Production main-IAM SLT and
application Basic authentication contracts are unchanged.

Runtime revision: `d0a8d58f60aa2e1be499d61615d2877efa7ca59e` (implementation
`6bec13521682114b51a9d82a68c2a7488598a361`, followed by a build concurrency cap).

Immutable ARM image:
`234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:4ffcd80e3985604c91d49a7b129dc747ee9b98cc33d722850c00922dba4e318f`.

SSM operation `f9a581d7-df14-4b7e-8dd5-9afc818b9c96` completed successfully
on instance `i-011c97da3d8b7ec74`, us-east-1, from 11:22:20 to 11:22:33 UTC.
The release applied base migration `0092` and testing overlay `9007`, retained the
fixed production scoped identity helper, and changed only the image references
for main API, scoped API and worker. The worker also requires the matching
embedded migration ledger at startup. Existing runtime environment files,
provider configuration, credentials, keyrings and ingress were preserved.

The previous units are saved privately at
`/etc/silicon-iam/releases/testing-d0a8d58f60aa2e1be499d61615d2877efa7ca59e-1789384942889257061`.
Schema migrations are forward-only: an old image whose migration ledger differs
is not a safe automatic rollback. The reviewed deployment helper is
`deploy/aws/release-testing-environments.py`.

CloudFormation change set `interface-testing-d0a8d58` completed with only the
BackendImageUri parameter changed, using the previous live template and all
other previous parameters. The launch-template image is now the immutable image
above. No Auto Scaling rolling replacement policy was introduced; the same
instance remains Healthy/InService.

Validation before release:

- 378 Rust library tests pass.
- All 34 real PostgreSQL tests pass, including the restricted runtime role,
  existing main SLT/consent/import/upgrade protocols, exact scope/current
  membership checks, revoked-grant receipt denial, same-key replay, changed-body
  and different-session conflicts, concurrent creation quota, test-root login,
  refresh, introspection, logout, missing import and cross-world/production denial.
- Workspace Clippy with warnings denied, formatting, runtime grants,
  SECURITY DEFINER policy, OpenAPI route checks, generated CLI manuals and
  documentation build/link checks pass.

Public verification after release:

- Main and scoped `/readyz` return 200 and `/api/v1/version` both report the
  runtime revision above. The worker is active on the same image.
- Scoped world creation without a bearer returns 401.
- A test actor ID without a root returns 400; an invalid root returns 401.
- An unknown scoped SLT returns 400; missing introspection bearer returns 401.
- Main IAM's public application exchange still requires Basic authentication
  and returns 401 without it.
- Interface's exact production origin passes creation and auth CORS preflight,
  including the testing-root header. An unrelated origin is not reflected.

The scope migration defines availability, not blanket authorization. It changes
no application's declared scopes and grants no new user consent. The tos>iam
owner must append this scope through the standard application settings update,
then users explicitly consent to the resulting application scope version before
Interface can create a production-owned test world. At release verification,
positive lifecycle tests used disposable PostgreSQL; public smoke checks created
no user environment and used no production app secret.

Canonical documentation is published at
https://docs.iam.teamofsilicons.com/scoped-backend/ and
https://docs.iam.teamofsilicons.com/iam-scopes/.

GitHub CI run `34837471698` passed for deployed revision `d0a8d58`, including
fresh migrations, the restricted worker, live client contract and key activation.
The documentation-only follow-up records this evidence and clarifies the
non-critical permission classification; it changes no deployed runtime behavior.
