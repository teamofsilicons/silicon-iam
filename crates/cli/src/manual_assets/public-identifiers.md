# Public ID schema cutover (0118 / SDK 4)

The canonical identities are `c:alice`, `si:chef`, and bare application IDs such as `commit`. Membership IDs are `c:alice[acme]` and `si:chef[acme]`. Organizations are explicit fields and authorization context; never infer them from Silicon/application IDs. Bundle IDs remain `acme>workspace`. IAM retains its existing text identity keys and unrelated UUID resource keys.

The new SDK and CLI major version is 4.0.0. Application Basic authentication uses the bare app ID with the existing secret. Silicon login takes `si:handle`; the CLI reads owning organization from `/me`. Application creation requires an explicit selected organization. Carbon signup APIs require `c:handle`; the first-party UI/CLI add `c:` to a handle entered at their prompts. Old public forms are not accepted as authentication aliases. New Carbon handles retain the existing no-zero rule; migration preserves existing handles containing zero.

## Cutover rules

1. Snapshot production and testing databases, deployment configuration, current binaries and cryptographic keyrings together. Inventory all active and removed identities. Silicon/application handles were previously organization scoped: any two old identities that would collapse to one new identity must be explicitly resolved before cutover. Do not silently merge or suffix them. Each isolated testing world has its own collision boundary.
2. Put all writers and consumers into maintenance, drain deliveries, complete Honeycomb operations and sensitive-action approvals, and wait for replay windows to expire. Migration 0118 rejects unexpired idempotency records, unfinished Honeycomb operations or unexpired secret responses, and pending/approved unexpired sensitive requests. Never delete a live replay record to bypass a guard. Drain queued webhooks before deploying consumers so an old signed envelope cannot be interpreted under the new contract.
3. Run the normal migrator against production and testing. Migration 0118 locks IAM tables and temporarily disables/restores their exact RLS settings; it runs atomically as the normal restricted migrator. Unique constraints fail closed on collisions, including removed accounts. A failure rolls back the entire operation.
4. Export `iam_private.public_id_schema_map` with its `scope_key`, `old_id`, `new_id`, `actor_type` and `org_id` columns to the coordinated consumer migration process. Empty scope is production; testing rows identify their exact world. This restricted table is evidence for exact identity mapping, not an authentication alias. Compare projected identities and ownership in every consumer against that inventory.
5. Update app configuration, Basic-auth usernames, actor IDs, membership IDs and OBO scope provider components. Deploy SDK 4 consumers, IAM, and Honeycomb together. Bundles retain their old namespace. Replace identity-bearing cached session state via fresh login/refresh before reopening traffic; no deployment is performed by this code change.

Typed identity references, membership transport values, policy actor arrays, and OBO scope provider IDs migrate by exact mapping. Arbitrary user text, UUID resources, hashes, keys and ciphertext are not replaced. Hash-bound replay responses/approval bodies remain unchanged. Credentials retain their secret bytes and token references. Previously encrypted app configuration used the qualified application ID as AEAD associated data: `iam_private.public_id_application_contexts` retains that exact context, and the crypto reader tries canonical, retained UUID and qualified contexts for that specific app/environment. New writes use the canonical context. Keep this table and the keyrings; never feed its legacy values to public identity parsers.

### Authorized replay invalidation for the September 23 cutover

The owner explicitly accepted ending old replay guarantees after being informed that a later retry may execute again. For this cutover only, once all writers are stopped and the final recoverable backups are verified, the operator may expire `iam.idempotency_records` in both planes. Retain the receipt rows, original hashes and response bytes; record the affected counts. Run the migration normally with its guards intact. This exception does not authorize discarding unfinished operations, approvals, secret responses or queued webhooks. Do not expire records on the still-serving deployment because new writes would immediately recreate them.

## Validation and recovery

```sh
python3 scripts/test-public-id-schema-migration.py --admin-url postgresql://localhost/postgres
cargo test --workspace --no-default-features
cd frontend && npm run check && npm test
```

The migration regression uses randomly named disposable PostgreSQL databases and a `NOSUPERUSER NOBYPASSRLS` owner. It covers production plus two testing worlds, collision rollback, resource/session references, ciphertext, runtime permissions and testing RLS reconciliation. Crypto unit coverage proves retained qualified AAD only works through the exact app mapping.

Rollback is a coordinated snapshot restore of databases, configuration and binaries before traffic resumes. Rolling back only a binary is unsupported. After new writes, prefer a forward repair; an inverse rename cannot recover new identities or safely reconstruct former org-scoped ownership. Retain the mapping and encrypted-key material through the recovery window. Do not modify old migration files or historical release evidence.
