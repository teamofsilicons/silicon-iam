# IAM CLI and browser session release — September 22, 2026

CLI 3.1.1 is released from `9b64a49dbc25225c60cf78c56251056e59f15a8c`.
It persists the original refresh dispatch time and retry key, saves the rotated
successor before recovering an expired cached response, and keeps the original
actor and testing context. The public SDK remains 3.1.0.

[Native release CI](https://github.com/teamofsilicons/silicon-iam/actions/runs/35662296906)
passed all six targets, package validation and Linux glibc 2.28 checks. Exact-source
[CI](https://github.com/teamofsilicons/silicon-iam/actions/runs/35662261006) also passed.
The `silicon-iam-cli 3.1.1` crate is published; anonymous bytes match the local
verified package. [GitHub v3.1.1](https://github.com/teamofsilicons/silicon-iam/releases/tag/v3.1.1)
has four anonymously downloaded and checksum-verified release assets.

Honeycomb accepted production release `1c012e2f-b579-4328-aafb-86379628fa7c`,
archive SHA-256 `42cf43f375b7018f67ff3d89311c2f50d7fd6b354c1d17a15e85cfb080a7460f`
(28,239,603 bytes). A fresh anonymous install executed 3.1.1 and correctly remained
signed out. Its native macOS ARM payload hash is
`2df088ff8a2bc6b6e5515ff30ff30d67680f03eb863db77661b347ddf75ed192`.
Maharaj's managed IAM CLI updated from 3.0.0 to 3.1.1; the existing Silicon actor,
organization and membership remained unchanged without another login.

The frontend deployment `dpl_BQXSEUkpVCckk2ktHKbejWc2j4VJ` is Ready and serves
both `iam.teamofsilicons.com` and `auth.iam.teamofsilicons.com`.
Anonymous session lookup returned 200/false and protected identity returned
401/sign_in_required. The existing Carbon browser login survived deployment and
reload, loaded its account and two organizations, and was retained after testing.
Browser refresh is single-flight, retains temporary failures, accounts for the
600-second response-replay bound, and retries stale access once with the same
request body and mutation key.

The separate OAuth refresh-family revocation correction and database migration
are recorded in their own deployment receipt; these CLI/frontend artifacts do
not by themselves prove that backend rollout.
