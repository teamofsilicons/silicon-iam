# Public membership identifiers and complete directory — September 18, 2026

Backend, Rust client and six-platform CLI release source:
`d32844ba89a943e88b11a7b4d782819ab1748577`.
Client and CLI version: **2.0.0**.

Immutable backend image:
`234951665042.dkr.ecr.us-east-1.amazonaws.com/silicon-iam-production@sha256:bdf473e4858222fa6b6f6d47da26bd868d91c849def8b3e663ef50de9b0934e1`.

## Runtime and migration

Main API, scoped API and worker run the image above. Both public readiness
endpoints return 200 and both version endpoints report the release source.
All three containers have zero restarts and no error-level logs after rollout.
The existing instance remains Healthy/InService.

Migration 0108 ran on both databases after verified PostgreSQL 17 backups.
Production has 108 ledger entries; testing has 121, including its overlays.
All 15 production and 109 testing memberships have canonical identifiers;
there are no missing mappings, incorrect canonical values, or incorrect scope
keys. Removed/inactive memberships are included. Private UUID row keys and
foreign keys remain intact. Runtime environment files were unchanged.

SSM rollout: `73e73bfa-f53d-493f-9dde-71ab90df5d11`.
Private backup/configuration/ledger evidence directory:
`/etc/silicon-iam/releases/memberships-d32844ba89a943e88b11a7b4d782819ab1748577-1789675709110572242`.

CloudFormation change set `membership-identifiers-d32844b` reached
`UPDATE_COMPLETE`, persisting the image and dependent launch-template version.
All other parameter values and resolved values were preserved.
Recovery requires forward repair or a coordinated database/runtime restore;
do not restart an older image against the new migration ledger.

## Public contract and compatibility

Ordinary API requests and the 2.0.0 client/CLI use `carbon_id[org_id]` or
`silicon_id[org_id]`, for example `saket[tos]` or `helper:tos[tos]`.
`GET /api/v1/organizations/{org_id}/directory/details` and
`iam --org tos --json member details` return a dictionary keyed by Carbon ID or
full Silicon ID, containing all visible active members and all permitted
profile, role, tag, hierarchy, capability and caller-relative trust details.
Profile-bearing directory, member and Carbon lookup responses include
`display_name`, subject to the existing profile disclosure scopes.

Existing official 1.x clients retain their UUID representation, including
authorization introspection and membership request paths. This compatibility
selection uses the SDK's existing user-agent prefix; it grants no authority and
all handler authorization remains enforced. Signed v1 webhook envelopes retain
their established UUID contract so existing receivers keep processing events.
New ordinary requests must use canonical membership paths.

Authenticated production checks returned five active `tos` directory entries,
all with canonical membership IDs, display names and trust fields. Canonical
single-member lookup succeeded. A legacy client returned the same six member
IDs as before the rollout, including the inactive entry. Existing Honeycomb
session introspection remained authenticated with the same organization role.
Unauthenticated access to the new endpoint returns 401 on both backends.

## Publications

- `silicon-iam-client` and `silicon-iam-cli` 2.0.0 are published on crates.io.
- GitHub native workflow `35268354773` built and verified all six OS/architecture
  targets and their pinned source receipts.
- Honeycomb `tos>iam` 2.0.0 is accepted and published. Release ID:
  `62d6fdac-b792-464b-96d6-bc5ac65ce895`; publication ID:
  `82c4c695-af1b-4843-afb5-dba9097d9876`.
- Combined archive SHA-256:
  `fe0b6a480f9caa52f4e270f70ddac61e24f6a75abf941a641b516cb1e1b241a2`.
- Frontend deployment `silicon-iam-frontend-aqict3tam` serves both IAM and auth
  custom domains. Live assets contain the canonical membership examples and
  current Honeycomb navigation.
- Documentation deployment `silicon-iam-docs-9bpioxybn` serves the new endpoint
  and 2.0.0 upgrade guide at `docs.iam.teamofsilicons.com`.

## Validation

Workspace tests, strict all-target/all-feature Clippy, formatting, OpenAPI route
checks, generated contracts/manuals, migration security, runtime grants,
frontend checks and 40 frontend tests passed. The disposable populated-database
upgrade verifies complete mapping, 107-member directory batching, caller-scope
redaction, legacy SDK compatibility and testing-world isolation.

The broader 40-test PostgreSQL protocol suite found one old admin-demotion
fixture still using a UUID URL. The other 39 passed; the fixture now uses the
canonical URL and its targeted rerun passed, including missing-step-up,
wrong-session-step-up and successful authorized-demotion checks. This follow-up
changes only the test URL and release evidence, not the published artifacts.
