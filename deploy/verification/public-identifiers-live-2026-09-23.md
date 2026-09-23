# Public identifier cutover — September 23, 2026

IAM production and testing reached migration 0118, and all three IAM processes
run version 4.0.0 from `2e770b5de24529e6e029d0417805eeae6639f29c`.
The immutable ECR image digest is
`sha256:01d6137227d13178364849c6a64afaef0a788518f88b5cb08ae4ec6b58c5558c`.
Both local API planes (8080 and 8081) and the public `/readyz` and
`/api/v1/version` routes passed. An authenticated read with the existing owner
session returned `c:saket` without a credential rotation or another login.

Vercel deployment `dpl_CgLmi64FjrBssikdh7CBgLuZ4U8t` was promoted. Both
https://iam.teamofsilicons.com/ and https://auth.iam.teamofsilicons.com/login
returned HTML 200. The persistent runtime secret changed only
`IAM_HONEYCOMB_APP_ID` from `tos>honeycomb` to `honeycomb`; its other 26 keys were
preserved. The reviewed CloudFormation image-pointer update completed, advancing
the ASG's explicit launch-template version to 52 while retaining instance
`i-011c97da3d8b7ec74`. No instance refresh ran.

## Recovery checkpoint and scoped forward repair

The stopped, final backup is retained on the IAM host in:

```
/etc/silicon-iam/releases/public-identifiers-2e770b5de24529e6e029d0417805eeae6639f29c-1790169747500676343
```

The encrypted off-host archive is in bucket
`silicon-iam-recovery-234951665042-us-east-1`, key
`public-identifiers-2e770b5/quiesced-databases-and-config.tar.gz`, version
`sdBO1blBcQJVFpBbozqWcm8exOLMvIhp`. Its SHA-256 is
`8cc12f9c53829e4dcbe56a6e29a62f6a53aeccb26f61b093f8679c84269d9f88`.
Both database archives, configuration, immutable ledgers, mapping and retained
credential fingerprints were verified before migration. S3 upload used an
operator-signed request after the instance's existing role denied upload; no
role policy changed.

Migration completed and retained credentials matched, but startup exposed
116 old-format application encryption-context records left behind by prior
testing-environment erasure. The runtime loads every context and rejected these
orphan identifiers. There were no testing principals or applications remaining.
Production's 12 encryption contexts were already valid.

Under the user's authorization to erase all testing data, a separate forward
repair archived the exact 116 rows and a fresh retired-environment manifest.
All 39 referenced worlds were included among the 50 deleted IAM worlds.
It acquired exclusive locks, checked 13 testing identity/credential tables
without RLS hiding references, required them all to be empty, compared the
entire AAD table with the archived row set, and deleted only those orphan
contexts. The exact prior RLS enable/force modes were restored before commit.
Production's 12 contexts remained byte-identical. Applied migration 0118 was
not changed.

The protected release directory retains the exact reproducible SQL and evidence:

- `orphan-testing-aad-forward-repair.sql` (includes the exact archived row-set guard)
- `orphan-testing-aad-before.json`, SHA-256
  `13e13bb3fc9f5294678d90ca6b6ea6a969dfc7ab278abe201357dfff9a1dbe2d`
- `orphan-testing-aad-repair-receipt.json`
- `production-aad-before-repair.json`

SSM command `d3e987bd-2d0d-4dcd-a81a-ec72d08d5d10` succeeded, verified both
local API planes and all three exact-image containers, and updated the release
state to healthy. The preceding attempt rolled back on a SQL alias ambiguity
before deletion; no partial repair was committed.

Local nonsecret acceptance evidence is retained under
`/tmp/public-id-deployment-20260923/iam-public-acceptance.json` and
`iam-orphan-test-aad-repair-result.json`. The authenticated response and exact
backup data are private; do not publish them.

## Native CLI publication status

Workflow run `35867615565` successfully built all six native CLI 4.0.0 targets
from `728c2f461e1dff444d512ca90da15d304840f8a6`. CLI, client, Cargo and toolchain
sources are identical to the deployed backend revision; later differences only
concern release orchestration and test placement. Downloaded archive checksums,
six native receipts, executable formats, Linux ABI, licenses and native macOS ARM
version were verified.

Honeycomb upload is pending because Briefcase is intentionally paused during
the wider cutover. The first upload returned `503 integration_unavailable`
with Briefcase HTTP 502. Retry the **same** saved idempotency key after Briefcase
is healthy; do not create a second upload attempt. The upload plan, response,
archive and provenance are retained under
`/tmp/public-id-deployment-20260923/iam-cli-4.0.0/`. No CLI publication completion
is claimed by this receipt.
