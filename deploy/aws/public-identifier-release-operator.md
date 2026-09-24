# Public identifier release operator

`release-public-identifiers.py` is the dedicated migration 0118 operator. It requires an exact pre-0118 production/testing ledger and pinned ARM64 image. The historical UUID-to-text operator is a different migration and must not be used for this release.

Use the backend artifact's full source commit to generate the checksum manifest:

```sh
python3 deploy/aws/release-public-identifiers.py --write-manifest /private/release/manifest.json --revision FULL_BACKEND_COMMIT --source /path/to/silicon-iam
sudo python3 deploy/aws/release-public-identifiers.py --settings /private/release/settings.json --rehearse-only
```

Settings retain `revision`, `image`, `previous_revision`, `previous_image`, `postgres_image`, `region`, `production_host`, `production_secret_arn`, `testing_host`, `testing_secret_arn`, and `migration_manifest`. Every image uses an immutable digest. The PostgreSQL image must support both live database versions. The `revision` describes the backend image and runtime SQL, not a later operator-only commit. Record and compare both source revisions when these differ.

The rehearsal leaves live services running, takes fresh online dumps, restores them with ownership and role membership into a network-isolated PostgreSQL container, and runs migration 0118 as the normal migrator. It validates complete ledgers and scoped identity/AAD mappings, and fingerprints eleven credential/ciphertext/proof tables before and after. Failed rehearsals leave a private diagnostic container. No prepare/convert command from the older UUID migration runs. If `rehearsal_rds_role_admin` is needed to model an already-verified RDS role-administration capability, the same narrow role model as the historical operator is retained and documented in the private receipt.

Live execution is a coordinated cutover. Set `consumer_cutover_ready: true` only after the release coordinator has fenced consumer traffic and arranged compatible restart order. Omit `--rehearse-only` only when the coordinator authorizes IAM activation. The operator repeats the rehearsal, stops and verifies all three IAM writers, saves both final dumps plus units/configuration, verifies their checksums and restore inventories, and exports the exact identity map before any data change. Set `backup_bucket` and `backup_key` for a private versioned S3 copy of that archive; its encryption, object version and SHA256 receipt must match.

To complete the rehearsal before pausing consumers, use `--await-cutover-file /private/release/go.json` instead of the boolean gate. The operator waits at `awaiting-coordinator-cutover-gate` for at most 30 minutes with live IAM unchanged. After fencing consumers, the coordinator writes a root-owned mode-0600 JSON file containing exactly `release_directory`, `revision`, and `image` from that checkpoint. The unique release directory prevents reusing an old approval. The operator consumes the file and proceeds directly to quiescence and final backups without repeating the copy rehearsal during the outage. A missing, stale, or nonprivate gate cannot activate the release.

The September 23 owner explicitly authorized ending existing replay guarantees. `expire_live_replays: true` applies that authorization only after quiescence and both verified backups. The operator archives the exact replay rows and expires their deadlines under an exclusive table lock. It refuses an unexpected new replay ID and verifies that response bytes, hashes, leases and all fields other than expiry/update timestamps remain unchanged. It does not delete receipts. A later old retry may execute again; keep consumers fenced and clear their obsolete retry state. Without this setting, live replay windows must expire naturally. A rehearsal may expire only its restored copies. Pending sensitive-action approvals, incomplete Honeycomb operations, and unexpired secret responses remain blocking gates; the operator never cancels them.

Only the exact mapped `IAM_HONEYCOMB_APP_ID` environment value changes. Keyrings, app/service secrets, notification signing keys, database passwords, and unrelated environment bytes stay identical. IAM has no `IAM_APP_ID` setting. Application Basic-auth callers must change their username to the new bare app ID while retaining the existing secret; Silicon callers use `si:handle`. The scoped IAM SQL helper resolves bare `iam` and retains the explicit `tos` organization fence. Update persistent configuration sources such as Secrets Manager and launch templates through the coordinated release so a later bootstrap cannot restore old IDs.

After migration, the operator verifies complete ledgers, public-ID syntax, exact exported mappings, retained AAD context, and credential fingerprints; then updates the existing units and verifies both IAM readiness endpoints, source revision and container image. Runtime environment comparison allows only the mapped field. Authenticated consumer acceptance is still required before reopening traffic.

Any failure after data mutation leaves writers stopped. Restore both databases, saved configuration and prior image together, or repair forward. Never restart an old binary against migrated databases. Private dumps, mapping exports, original replay rows and logs contain credentials or account data and must remain protected.

Local checks:

```sh
IAM_OPERATOR_TEST_ADMIN_URL=postgresql://localhost/postgres python3 scripts/test-public-identifier-release.py
python3 scripts/test-public-id-schema-migration.py --admin-url postgresql://localhost/postgres
```
