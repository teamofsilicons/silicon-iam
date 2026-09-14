# Interface scoped IAM SLT release — September 14, 2026

Scoped IAM now completes the registered `tos>iam` application's bundle SLT
without an application secret in Interface or scoped service configuration.
The initial login and SLT issuance remain in main IAM. Four scoped-only auth
routes reuse IAM's token, rotation, revocation, and current authorization code.

Deployed runtime revision: `3fb59036997a1e68a4a9174f6d81775057d9771d`.

Image:
`234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:efd955991bda2ddb14ec5ae3890e1fecac82573fca3a65c2faad0027bbd7b3da`.

Only `silicon-iam-scoped-api` was restarted on the existing IAM instance
`i-011c97da3d8b7ec74`. The scoped bootstrap installed the fixed `tos>iam` private
resolver without changing `_sqlx_migrations`. Main IAM and worker retained their
running image IDs and revision `d279512220e9c6001c3968bbdf1b0b9d03efe0d1`.
The release helper preserved the previous scoped systemd unit privately under
`/etc/silicon-iam/releases/scoped-slt-3fb59036997a1e68a4a9174f6d81775057d9771d-1789370700973102367`.

The source is on `codex/scoped-interface-slt` and draft PR
[23](https://github.com/teamofsilicons/silicon-iam/pull/23). A later documentation
commit publishes the additional scoped OpenAPI asset in the documentation site;
it changes no deployed runtime behavior. This deployment leaves the existing
CloudFormation main-image parameter untouched. Provision a replacement scoped
service with this image and its scoped initializer; do not redeploy main IAM just
to install the adapter.

Validation before publication: 377 Rust library tests passed; the real disposable
PostgreSQL lifecycle test passed, covering SLT single use and retries, scoped
organization snapshots, wrong-application credentials, refresh rotation, logout
revocation, suspended registration, main endpoint Basic authentication, body
limits, and isolation of per-credential throttling. Workspace Clippy with warnings
denied, formatting, main/scoped OpenAPI route checks, runtime-grant checks,
SQL-security checks, and documentation build/link checks passed.

Public HTTPS verification after deployment:

- Scoped readiness is 200 and its version reports the deployed revision.
- Main IAM readiness remains 200 and its version remains unchanged.
- A synthetic unknown SLT and refresh token each return 400 `invalid_grant`.
- Revoking a synthetic unknown refresh token returns 200 without a target mutation.
- Missing/unknown introspection bearer tokens return 401.
- Main IAM's general exchange still requires Basic authentication (401 without it).
- Scoped IAM still omits the general exchange and registration routes (404).
- Existing scoped business routes still require a bearer token (401 without it).
- Interface's exact production origin passes the auth CORS preflight.

No real user SLT/session was minted for these public checks; the positive token
lifecycle was verified against disposable PostgreSQL. Interface's real bundle
login is the remaining production end-to-end verification. No application
secret was requested, read, or configured, and no user or organization data was
mutated by the deployment or public checks.
