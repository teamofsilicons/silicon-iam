#!/usr/bin/env python3
"""Rehearse or execute IAM migration 0118; never roll back only an image.

A restore rehearsal runs the actual migration on isolated copies before stopping
live writers. --rehearse-only stops before the live cutover.
Only IAM_HONEYCOMB_APP_ID changes through the exact private identity map.
Credential bytes, signing keys and application ownership are preserved.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import uuid

SERVICES = ("api", "scoped-api", "worker")
FLAGS = ("IAM_HONEYCOMB_APP_ID",)
CERT = "/opt/silicon-iam/aws-rds-global-bundle.pem"
IMAGE_RE = r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}"
CREDENTIAL_TABLES = ("authentication_sessions", "refresh_token_families", "refresh_tokens",
                     "access_tokens", "application_secrets", "silicon_credentials",
                     "application_access_keys", "application_webhook_endpoints",
                     "application_webhook_signing_keys", "application_webhook_event_projections", "obo_proofs")
CHECKPOINTS = (
    "Validate immutable images, current health, configuration and both existing ledgers",
    "Stop API, scoped API and worker; save private units/environment and both database dumps",
    "Validate both dump archives and checksums before marking migrations started",
    "Run dual-database iam-migrate, apply image runtime grants to both databases, initialize scoped helper",
    "Verify exact 0118 ledgers, public identity mapping, retained ciphertext and credentials",
    "Install immutable image into all three units and verify readiness/revision/container health",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def rewrite_runtime_configuration(text, aliases):
    """Change only the named, mapped public-ID value; never rewrite secrets."""
    result = []
    seen = False
    for line in text.splitlines(keepends=True):
        if line.startswith("IAM_HONEYCOMB_APP_ID="):
            require(not seen, "Duplicate IAM_HONEYCOMB_APP_ID entry")
            seen = True
            value = line.split("=", 1)[1].rstrip("\r\n")
            require(value in aliases, "Configured Honeycomb app is absent from exact production mapping")
            mapped = aliases[value]
            require(re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", mapped), "Invalid mapped Honeycomb app ID")
            suffix = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            line = "IAM_HONEYCOMB_APP_ID=" + mapped + suffix
        result.append(line)
    return "".join(result)


def replay_expiry_sql(ids):
    """Expire an exact backed-up set while preserving receipt/lease bytes."""
    require(ids and len(set(ids)) == len(ids), "Expected nonempty distinct replay IDs")
    values = ",".join("'" + str(uuid.UUID(value)) + "'::uuid" for value in ids)
    return f"""BEGIN;
LOCK TABLE iam.idempotency_records IN ACCESS EXCLUSIVE MODE;
CREATE TEMP TABLE public_id_replay_before ON COMMIT DROP AS
 SELECT id,to_jsonb(r)-ARRAY['expires_at','updated_at'] AS receipt FROM iam.idempotency_records r;
DO $expiry$ BEGIN
 IF EXISTS(SELECT 1 FROM iam.idempotency_records WHERE expires_at>clock_timestamp() AND NOT(id=ANY(ARRAY[{values}])))
 OR (SELECT count(*) FROM iam.idempotency_records WHERE id=ANY(ARRAY[{values}]))<>{len(ids)} THEN
  RAISE EXCEPTION 'Replay set changed after backup; no expiry performed'; END IF;
 UPDATE iam.idempotency_records SET expires_at=clock_timestamp()-interval '1 microsecond'
 WHERE id=ANY(ARRAY[{values}]);
 IF EXISTS(SELECT id,to_jsonb(r)-ARRAY['expires_at','updated_at'] FROM iam.idempotency_records r
           EXCEPT SELECT id,receipt FROM public_id_replay_before)
 OR EXISTS(SELECT id,receipt FROM public_id_replay_before
           EXCEPT SELECT id,to_jsonb(r)-ARRAY['expires_at','updated_at'] FROM iam.idempotency_records r) THEN
  RAISE EXCEPTION 'Expiry altered retained receipt bytes'; END IF;
END $expiry$;
SELECT count(*) FROM iam.idempotency_records WHERE id=ANY(ARRAY[{values}]) AND expires_at<=clock_timestamp();
COMMIT;"""


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def manifest(args):
    require(re.fullmatch(r"[a-f0-9]{40}", args.revision), "A full commit SHA is required")
    def git(*parts):
        return subprocess.check_output(["git", "-C", str(args.source), *parts])
    require(git("rev-parse", args.revision + "^{commit}").decode().strip() == args.revision,
            "Source revision does not resolve to the exact commit")
    rows = {"production": [], "testing": []}
    for name in git("ls-tree", "-r", "--name-only", args.revision, "migrations").decode().splitlines():
        match = re.fullmatch(r"migrations/(testing/)?([0-9]+)_[^/]+\.sql", name)
        if not match:
            continue
        row = {"version": int(match[2]), "checksum": hashlib.sha384(git("show", f"{args.revision}:{name}")).hexdigest()}
        if not match[1]:
            rows["production"].append(row)
        rows["testing"].append(row)
    for ledger in rows.values():
        ledger.sort(key=lambda row: row["version"])
        require(ledger and len({row["version"] for row in ledger}) == len(ledger), "Invalid committed migration inventory")
    require(not args.output.exists(), "Manifest output already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(args.output, {"revision": args.revision, "ledgers": rows})
    print(json.dumps({"manifest": str(args.output), "revision": args.revision,
                      "counts": {label: len(rows[label]) for label in rows}}))


class Release:
    def __init__(self, args):
        self.args = args
        self.inventory = json.loads(args.migration_manifest.read_text())
        require(self.inventory["revision"] == args.revision, "Manifest revision mismatch")
        for value in (args.image, args.previous_image, args.postgres_image):
            require(re.fullmatch(IMAGE_RE, value), "All image arguments require immutable sha256 digests")
        for value in (args.revision, args.previous_revision):
            require(re.fullmatch(r"[a-f0-9]{40}", value), "Full source revisions are required")
        self.root = Path("/etc/silicon-iam/releases") / f"public-identifiers-{args.revision}-{time.time_ns()}"
        self.state = {"revision": args.revision, "image": args.image, "previous_revision": args.previous_revision,
                      "previous_image": args.previous_image, "migration_started": False, "services_stopped": False}
        self.databases = {}

    def checkpoint(self, stage):
        self.state["stage"] = stage
        atomic_json(self.root / "state.json", self.state)
        print(json.dumps({"checkpoint": stage, "release_directory": str(self.root)}), flush=True)

    def run(self, command, env=None, stdin=None, stdout=None, sensitive=False):
        result = subprocess.run(command, env=env, stdin=stdin, stdout=stdout or subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
        if not sensitive:
            with (self.root / "operations-private.log").open("ab") as log:
                if stdout is None:
                    log.write(result.stdout or b"")
                log.write(result.stderr or b"")
        require(result.returncode == 0, f"{Path(command[0]).name} operation failed; inspect private release log")
        return result.stdout if stdout is None else b""

    def secret(self, arn):
        result = self.run(["aws", "secretsmanager", "get-secret-value", "--region", self.args.region,
                           "--secret-id", arn], sensitive=True)
        return json.loads(json.loads(result)["SecretString"])

    def pg(self, label, program, arguments, stdin=None, stdout=None):
        environment = self.databases[label][0]
        command = ["docker", "run", "--rm", "--network", "host", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:size=16m,mode=1777",
                   "--volume", f"{CERT}:{CERT}:ro"]
        if stdin is not None:
            command.append("--interactive")
        for key in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSSLMODE", "PGSSLROOTCERT"):
            command.extend(["--env", key])
        command.extend(["--entrypoint", program, self.args.postgres_image, *arguments])
        return self.run(command, environment, stdin, stdout)

    def sql(self, label, query):
        return self.pg(label, "psql", ["-X", "--no-password", "-At", "-v", "ON_ERROR_STOP=1", "-c", query]).decode().strip()

    def ledger(self, label, complete=False):
        output = self.sql(label, "SELECT version,encode(checksum,'hex'),success FROM _sqlx_migrations ORDER BY version")
        actual = {}
        for line in output.splitlines():
            version, checksum, success = line.split("|")
            require(success == "t", f"Failed migration in {label} ledger")
            actual[int(version)] = checksum
        expected = {row["version"]: row["checksum"] for row in self.inventory["ledgers"][label]}
        require(actual and all(expected.get(version) == checksum for version, checksum in actual.items()),
                f"Existing {label} ledger differs from pinned source; stop before deployment")
        require(118 in expected and all(version <= 118 or version >= 9000 for version in expected), "Manifest must end at public-ID migration118")
        if complete:
            require(actual == expected, f"Incomplete {label} migration ledger")
        else:
            require(actual == {version: checksum for version, checksum in expected.items() if version != 118},
                    f"Expected exact pre-0118 {label} schema; refuse unrelated upgrades or reruns")
        atomic_json(self.root / f"{label}-ledger-{'after' if complete else 'before'}.json", actual)

    def ready(self, port, revision):
        for _ in range(40):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=3) as response:
                    require(response.status == 200, "Not ready")
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/version", timeout=3) as response:
                    require(json.load(response)["commit"] == revision, "Revision mismatch")
                return
            except Exception:
                time.sleep(2)
        raise RuntimeError(f"Readiness/revision check failed on port {port}")

    def writers_stopped(self):
        require(self.state["services_stopped"], "Live replay expiry requires quiesced services")
        for service in SERVICES:
            value = self.run(["systemctl", "show", "--property=ActiveState", "--value", f"silicon-iam-{service}"]).decode().strip()
            require(value == "inactive", "IAM writer is not fully stopped")
            running = self.run(["docker", "ps", "--filter", f"name=^silicon-iam-{service}$", "--format", "{{.ID}}"]).decode().strip()
            require(not running, "IAM writer container remains running")

    def prepare_public_ids(self, label, sql, isolated=False):
        # A copy rehearsal can expire replay windows only in its isolated DB.
        # Live expiry is a separately authorized choice after verified backups.
        guards = sql("SELECT (SELECT count(*) FROM iam_private.organization_action_approvals WHERE status IN ('pending','approved') AND expires_at>clock_timestamp()),(SELECT count(*) FROM iam.honeycomb_operations WHERE NOT completed OR response_expires_at>clock_timestamp())")
        require(guards.strip() == "0|0", "Pending approval or Honeycomb operation blocks cutover; do not cancel production work")
        rows = json.loads(sql("SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') FROM iam.idempotency_records r WHERE expires_at>clock_timestamp()"))
        prefix = "rehearsal-" if isolated else ""
        atomic_json(self.root / f"{prefix}{label}-replay-records-before.json", rows)
        if not rows:
            return
        if not isolated:
            require(getattr(self.args, "expire_live_replays", False) is True,
                    "Live replay windows remain; drain naturally or explicitly authorize expiry")
            self.writers_stopped()
            backups = json.loads((self.root / "backups.json").read_text())
            for item in backups.values():
                require(digest(Path(item["path"])) == item["sha256"], "Quiesced backup digest changed")
            require(set(backups) == {'production', 'testing'}, "Both quiesced database backups are required")
            self.state['replay_expiry_started'] = True
            self.checkpoint('authorized-live-replay-expiry-started')
        ids = [row["id"] for row in rows]
        receipt = sql(replay_expiry_sql(ids))
        atomic_json(self.root / f"{prefix}{label}-replay-expiry-receipt.json",
                    {"ids": ids, "isolated": isolated, "result": receipt,
                     "reason": "user_authorized_test_reset_and_public_id_cutover"})

    def verify_public_ids(self, label, sql):
        result = sql("SELECT (SELECT count(*) FROM iam.carbons WHERE id<>carbon_id OR carbon_id!~'^c:[a-z0-9_-]{3,30}$'),(SELECT count(*) FROM iam.silicons WHERE id<>global_silicon_id OR global_silicon_id<>'si:'||silicon_handle),(SELECT count(*) FROM iam.applications WHERE id<>app_id OR app_id!~'^[a-z][a-z0-9_-]{0,79}$'),(SELECT count(*) FROM iam_private.public_id_schema_map m WHERE NOT EXISTS(SELECT 1 FROM iam.principals p WHERE p.id=m.new_id AND COALESCE(to_jsonb(p)->>'testing_environment_id','')=m.scope_key))")
        require(result.strip() == "0|0|0|0", f"Public ID invariant failed in {label}")
        ledger = sql("SELECT version,encode(checksum,'hex'),success FROM _sqlx_migrations ORDER BY version")
        actual = {int(line.split('|')[0]):line.split('|')[1] for line in ledger.splitlines() if line.split('|')[2] == 't'}
        expected = {row['version']:row['checksum'] for row in self.inventory['ledgers'][label]}
        require(actual == expected, f"Restored {label} ledger differs from exact pinned manifest")
        mapping = json.loads(sql("SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY scope_key,old_id),'[]') FROM iam_private.public_id_schema_map m"))
        before_path = self.root / "identity-mapping-before.json"
        if before_path.exists():
            before = json.loads(before_path.read_text())[label]
            require({(row['scope_key'], row['old_id'], row['new_id']) for row in mapping}
                    == {(row['scope_key'], row['old_id'], row['new_id']) for row in before},
                    "Final migration mapping differs from backed-up identity inventory")
        atomic_json(self.root / f"{label}-public-id-mapping-after.json", mapping)
        # Both the old UUID AAD and the old text AAD must remain available.
        require(sql("SELECT count(*)=(SELECT count(*) FROM iam.applications) FROM iam_private.public_id_application_contexts").strip() == 't', "Incomplete application AAD mapping")
        require(sql("SELECT count(*) FROM iam_private.public_id_application_contexts a WHERE NOT EXISTS(SELECT 1 FROM iam_private.public_id_schema_map m WHERE m.actor_type='application' AND m.new_id=a.application_id AND m.old_id=a.context_id AND m.scope_key=COALESCE(a.testing_environment_id::text,''))").strip() == '0', "Application AAD differs from exact scoped mapping")
        return mapping

    def export_identities(self):
        query = """SELECT COALESCE(jsonb_agg(jsonb_build_object(
          'scope_key',COALESCE(to_jsonb(p)->>'testing_environment_id',''),'old_id',p.id,
          'kind',p.kind::text,'org_id',COALESCE(s.organization_handle,o.org_id),
          'new_id',CASE p.kind WHEN 'carbon' THEN 'c:'||c.carbon_id
            WHEN 'silicon' THEN 'si:'||s.silicon_handle WHEN 'application' THEN split_part(a.app_id,'>',2)
            ELSE p.id END) ORDER BY p.id),'[]') FROM iam.principals p
          LEFT JOIN iam.carbons c ON c.id=p.id AND COALESCE(to_jsonb(c)->>'testing_environment_id','')=COALESCE(to_jsonb(p)->>'testing_environment_id','')
          LEFT JOIN iam.silicons s ON s.id=p.id AND COALESCE(to_jsonb(s)->>'testing_environment_id','')=COALESCE(to_jsonb(p)->>'testing_environment_id','')
          LEFT JOIN iam.applications a ON a.id=p.id AND COALESCE(to_jsonb(a)->>'testing_environment_id','')=COALESCE(to_jsonb(p)->>'testing_environment_id','')
          LEFT JOIN iam.organizations o ON o.id=a.organization_id"""
        result = {label: json.loads(self.sql(label, query)) for label in self.databases}
        for rows in result.values():
            require(all(row['new_id'] for row in rows), "Unmapped identity in final export")
            require(len({(row['scope_key'],row['new_id']) for row in rows}) == len(rows),
                    "Public handle collision; no identity will be renamed or merged automatically")
        atomic_json(self.root / "identity-mapping-before.json", result)

    def migrate_runtime_configuration(self, mapping):
        aliases = {row['old_id']:row['new_id'] for row in mapping if row['scope_key'] == '' and row['actor_type'] == 'application'}
        changes = []
        for path in Path('/etc/silicon-iam').glob('*.env'):
            original = path.read_bytes()
            require(original == (self.root / path.name).read_bytes(), "Runtime configuration changed after backup")
            old = original.decode('utf-8')
            new = rewrite_runtime_configuration(old, aliases)
            if new != old:
                before = digest(path)
                temporary = path.with_suffix(path.suffix + '.public-identifiers')
                with temporary.open('x') as stream:
                    stream.write(new); stream.flush(); os.fsync(stream.fileno())
                temporary.chmod(0o600); temporary.replace(path)
                changes.append({'file':str(path),'field':'IAM_HONEYCOMB_APP_ID','before_sha256':before,'after_sha256':digest(path)})
        atomic_json(self.root / 'runtime-configuration-changes.json', changes)

    @staticmethod
    def credential_fingerprint_query(table):
        require(table in CREDENTIAL_TABLES, "Unexpected credential table")
        # Only identity references change representation. Token digests, resource
        # IDs, expiry/revocation state, epochs, ciphertext and all other fields stay.
        # Audience is an application identity. Every other field, including
        # refresh provenance, expiry state and ciphertext, must remain identical.
        excluded = ("'subject_principal_id','client_application_id','audience_application_id',"
                    "'application_id','created_by_carbon_id','silicon_id','audience',"
                    "'issuer_application_id','consumed_by_application_id'")
        return (f"SELECT count(*)::text||':'||COALESCE(md5(string_agg("
                f"(to_jsonb(t)-ARRAY[{excluded}])::text,'' ORDER BY (to_jsonb(t)-ARRAY[{excluded}])::text)),md5('')) FROM iam.{table} t")

    def credential_fingerprints(self, label):
        return {table: self.sql(label, self.credential_fingerprint_query(table)) for table in CREDENTIAL_TABLES}

    def upload_quiesced_backup(self):
        bucket = getattr(self.args, "backup_bucket", None)
        key = getattr(self.args, "backup_key", None)
        if bucket is None and key is None:
            return
        require(bucket and key and re.fullmatch(r"[a-z0-9.-]+", bucket)
                and re.fullmatch(r"[A-Za-z0-9._/-]+", key), "Invalid private backup destination")
        archive = self.root / "quiesced-backup.tar.gz"
        paths = list(self.root.glob("*.env")) + list(self.root.glob("*.service"))
        paths += [self.root / name for name in (
            "production-before.dump", "testing-before.dump", "backups.json", "identity-mapping-before.json",
            "credential-fingerprints-before.json", "migration-manifest.json", "state.json",
            "production-ledger-before.json", "testing-ledger-before.json", "runtime-grants.sql")]
        with tarfile.open(archive, "x:gz") as output:
            for path in paths:
                require(path.is_file(), "Missing quiesced backup component")
                output.add(path, arcname=path.name, recursive=False)
        checksum = digest(archive)
        encoded = base64.b64encode(bytes.fromhex(checksum)).decode()
        response = json.loads(self.run(["aws", "s3api", "put-object", "--region", self.args.region,
            "--bucket", bucket, "--key", key, "--body", str(archive), "--server-side-encryption", "AES256",
            "--checksum-algorithm", "SHA256", "--checksum-sha256", encoded,
            "--metadata", "stage=quiesced,sha256=" + checksum]))
        require(response.get("VersionId") and response.get("ChecksumSHA256") == encoded
                and response.get("ServerSideEncryption") == "AES256", "Private backup receipt mismatch")
        atomic_json(self.root / "offhost-backup.json", {"bucket": bucket, "key": key,
            "version_id": response["VersionId"], "sha256": checksum, "bytes": archive.stat().st_size})

    def rehearse(self):
        """Restore online backups and run the exact cutover in an isolated network."""
        self.checkpoint("isolated-restore-rehearsal-started")
        name = "iam-restore-" + str(time.time_ns())
        backups = {}
        for label in self.databases:
            path = self.root / f"{label}-rehearsal.dump"
            with path.open("xb") as output:
                self.pg(label, "pg_dump", ["--no-password", "--format=custom"], stdout=output)
            require(path.stat().st_size > 0, "Empty rehearsal backup")
            backups[label] = {"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size}
        atomic_json(self.root / "rehearsal-backups.json", backups)
        self.run(["docker", "run", "--detach", "--name", name,
                  "--network", "none", "--memory", "1200m", "--cpus", "1",
                  "--env", "POSTGRES_HOST_AUTH_METHOD=trust", self.args.postgres_image])
        rehearsal_passed = False
        try:
            for attempt in range(60):
                probe = subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True)
                if probe.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Isolated restore database did not become ready")
            # Copy role attributes without password hashes. In particular the
            # testing definer must stay NOINHERIT for its security guard.
            roles = {}
            for label in self.databases:
                rows = json.loads(self.sql(label, "SELECT json_agg(json_build_object('name',rolname,'inherit',rolinherit,'login',rolcanlogin,'super',rolsuper,'createdb',rolcreatedb,'createrole',rolcreaterole,'replication',rolreplication,'bypassrls',rolbypassrls)) FROM pg_roles WHERE rolname NOT LIKE 'pg_%' AND rolname<>'postgres'"))
                for row in rows:
                    if row["name"] in roles:
                        require(roles[row["name"]] == row, "Role attributes differ between database planes")
                    roles[row["name"]] = row
            for role, values in sorted(roles.items()):
                quoted = '"' + role.replace('"', '""') + '"'
                attributes = " ".join(("" if values[key] else "NO") + flag for key, flag in
                                      [("inherit","INHERIT"),("login","LOGIN"),("super","SUPERUSER"),
                                       ("createdb","CREATEDB"),("createrole","CREATEROLE"),
                                       ("replication","REPLICATION"),("bypassrls","BYPASSRLS")])
                self.run(["docker", "exec", name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c", "CREATE ROLE " + quoted + " " + attributes])
            memberships = set()
            for label in self.databases:
                rows = json.loads(self.sql(label, "SELECT COALESCE(json_agg(json_build_object('role',r.rolname,'member',m.rolname,'admin',a.admin_option,'inherit',a.inherit_option,'set',a.set_option)), '[]'::json) FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member"))
                for row in rows:
                    memberships.add((row['role'], row['member'], row['admin'], row['inherit'], row['set']))
            for role, member, admin, inherit, can_set in sorted(memberships):
                quote = lambda value: '"' + value.replace('"', '""') + '"'
                grant = (f"GRANT {quote(role)} TO {quote(member)} WITH ADMIN {str(admin).upper()}, "
                         f"INHERIT {str(inherit).upper()}, SET {str(can_set).upper()}")
                self.run(["docker", "exec", name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c", grant])
            if getattr(self.args, "rehearsal_rds_role_admin", False):
                # RDS permits its rds_superuser members to administer this role
                # even without pg_auth_members.admin_option. Vanilla PostgreSQL
                # lacks that managed-service behavior. Model only the confirmed
                # membership operation; do not grant superuser or BYPASSRLS.
                owner = self.databases["testing"][0]["PGUSER"]
                require(roles[owner]["createrole"] and not roles[owner]["super"]
                        and not roles[owner]["bypassrls"], "Unexpected RDS migrator attributes")
                require(any(role == "rds_superuser" and member == owner and can_set
                            for role, member, admin, inherit, can_set in memberships),
                        "RDS role administration model requires actual rds_superuser membership")
                entry = next((row for row in memberships
                              if row[0] == "silicon_iam_testing_definer" and row[1] == owner), None)
                require(entry is not None, "Expected existing restricted testing-definer membership")
                quoted_owner = '"' + owner.replace('"', '""') + '"'
                grant = (f"GRANT silicon_iam_testing_definer TO {quoted_owner} WITH ADMIN TRUE, "
                         f"INHERIT {str(entry[3]).upper()}, SET {str(entry[4]).upper()}")
                self.run(["docker", "exec", name, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-c", grant])
                atomic_json(self.root / "rehearsal-rds-role-model.json",
                            {"member": owner, "role": "silicon_iam_testing_definer",
                             "capability": "managed RDS role administration", "isolated_only": True})
            urls = {}
            fingerprints = {}
            for label in self.databases:
                database = "rehearsal_" + label
                owner = self.databases[label][0]["PGUSER"]
                self.run(["docker", "exec", name, "createdb", "-U", "postgres", "--owner", owner, database])
                with Path(backups[label]["path"]).open("rb") as source:
                    self.run(["docker", "exec", "-i", name, "pg_restore", "-U", "postgres", "--exit-on-error", "-d", database], stdin=source)
                urls[label] = f"postgresql://{urllib.parse.quote(owner, safe='')}@127.0.0.1:5432/{database}?sslmode=disable"
                fingerprints[label] = {
                    table: self.run(["docker", "exec", name, "psql", "-U", owner, "-d", database,
                                     "-At", "-v", "ON_ERROR_STOP=1", "-c", self.credential_fingerprint_query(table)])
                    for table in CREDENTIAL_TABLES
                }
                def copy_sql(query, database=database, owner=owner):
                    return self.run(["docker", "exec", name, "psql", "-U", owner, "-d", database,
                                     "-At", "-v", "ON_ERROR_STOP=1", "-c", query]).decode().strip()
                self.prepare_public_ids(label, copy_sql, isolated=True)
            environment = dict(os.environ, IAM_MIGRATOR_DATABASE_URL=urls["production"],
                               IAM_TESTING_MIGRATOR_DATABASE_URL=urls["testing"])
            command = ["docker", "run", "--rm", "--network", "container:" + name,
                       "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                       "--env", "IAM_ENVIRONMENT=test", "--env", "IAM_TELEMETRY=off",
                       "--env", "IAM_MIGRATOR_DATABASE_URL", "--env", "IAM_TESTING_MIGRATOR_DATABASE_URL",
                       "--env", "IAM_MIGRATOR_DATABASE_STATEMENT_TIMEOUT_SECONDS=120", self.args.image]
            self.run([*command, "iam-migrate"], environment)
            for label, url in urls.items():
                database = "rehearsal_" + label
                owner = self.databases[label][0]["PGUSER"]
                with (self.root / "runtime-grants.sql").open("rb") as source:
                    self.run(["docker", "exec", "-i", name, "psql", "-U", owner, "-d", database, "-v", "ON_ERROR_STOP=1"], stdin=source)
                def copy_sql(query, database=database, owner=owner):
                    return self.run(["docker", "exec", name, "psql", "-U", owner, "-d", database,
                                     "-At", "-v", "ON_ERROR_STOP=1", "-c", query]).decode().strip()
                self.verify_public_ids(label, copy_sql)
                for table in CREDENTIAL_TABLES:
                    after = self.run(["docker", "exec", name, "psql", "-U", owner, "-d", database,
                                      "-At", "-v", "ON_ERROR_STOP=1", "-c", self.credential_fingerprint_query(table)])
                    require(after == fingerprints[label][table], f"Rehearsal altered retained {label} {table} credentials")
            self.run([*command, "iam-scoped-auth-init"], environment)
            self.checkpoint("both-databases-restored-and-cutover-rehearsed")
            rehearsal_passed = True
        finally:
            if rehearsal_passed:
                subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                self.state["isolated_rehearsal_container"] = name
                self.checkpoint("isolated-rehearsal-failed-live-unchanged")

    def execute(self):
        require(os.geteuid() == 0, "Execute only as root on the existing IAM host")
        os.umask(0o077)
        self.root.mkdir(parents=True, mode=0o700)
        self.checkpoint("preflight")
        password = self.run(["aws", "ecr", "get-login-password", "--region", self.args.region], sensitive=True)
        login = subprocess.run(["docker", "login", "--username", "AWS", "--password-stdin", self.args.image.split('/')[0]],
                               input=password, capture_output=True)
        require(login.returncode == 0, "ECR authentication failed")
        del password
        for image in (self.args.image, self.args.postgres_image):
            self.run(["docker", "pull", image])
        image = json.loads(self.run(["docker", "image", "inspect", self.args.image]))[0]
        require(image["Architecture"] == "arm64", "Expected ARM64 backend image")
        require(image["Config"]["Labels"]["org.opencontainers.image.revision"] == self.args.revision, "Image revision mismatch")
        for port in (8080, 8081):
            self.ready(port, self.args.previous_revision)
        replacements = []
        for service in SERVICES:
            self.run(["systemctl", "is-active", f"silicon-iam-{service}"])
            unit = Path(f"/etc/systemd/system/silicon-iam-{service}.service")
            text = unit.read_text()
            require(text.count(self.args.previous_image) == 1, f"Unexpected current image in {unit.name}")
            require(len(re.findall(IMAGE_RE, text)) == 1, f"Ambiguous image references in {unit.name}")
            require(not any(re.search(r"--env(?:=|\s+)" + flag + r"=", text) for flag in FLAGS),
                    "Inline Honeycomb flag override requires operator review")
            replacements.append((unit, text.replace(self.args.previous_image, self.args.image)))
            shutil.copy2(unit, self.root / unit.name)
        for path in Path("/etc/silicon-iam").glob("*.env"):
            destination = self.root / path.name
            shutil.copy2(path, destination)
            destination.chmod(0o600)
        for label, host, arn, name in (
            ("production", self.args.production_host, self.args.production_secret_arn, "silicon_iam"),
            ("testing", self.args.testing_host, self.args.testing_secret_arn, "silicon_iam_testing"),
        ):
            require(re.fullmatch(r"[a-zA-Z0-9.-]+\.rds\.amazonaws\.com", host), "Expected an RDS hostname")
            secret = self.secret(arn)
            environment = dict(os.environ, PGHOST=host, PGPORT="5432", PGDATABASE=name,
                               PGUSER=secret["username"], PGPASSWORD=secret["password"],
                               PGSSLMODE="verify-full", PGSSLROOTCERT=CERT)
            url = ("postgresql://" + urllib.parse.quote(secret["username"], safe="") + ":" +
                   urllib.parse.quote(secret["password"], safe="") + f"@{host}:5432/{name}?sslmode=verify-full&sslrootcert={CERT}")
            self.databases[label] = (environment, url)
            version = self.pg(label, "pg_dump", ["--version"]).decode()
            match = re.search(r"PostgreSQL\) (\d+)", version)
            require(match and int(match[1]) >= int(self.sql(label, "SHOW server_version_num")) // 10000,
                    "Backup client is older than the database server")
            self.ledger(label)
        container = self.run(["docker", "create", self.args.image]).decode().strip()
        try:
            self.run(["docker", "cp", container + ":/opt/silicon-iam/postgres/runtime-grants.sql",
                      str(self.root / "runtime-grants.sql")])
        finally:
            self.run(["docker", "rm", container])
        shutil.copy2(self.args.migration_manifest, self.root / "migration-manifest.json")
        self.rehearse()
        self.checkpoint("preflight-complete")
        if self.args.rehearse_only:
            return
        require(getattr(self.args, "consumer_cutover_ready", False) is True, "Coordinated consumer cutover gate is not ready")
        # From this checkpoint failures leave all writers stopped for operator review.
        self.state["services_stopped"] = True
        self.checkpoint("stopping-writers")
        self.run(["systemctl", "stop", *(f"silicon-iam-{service}" for service in SERVICES)])
        self.writers_stopped()
        credential_fingerprints = {label: self.credential_fingerprints(label) for label in self.databases}
        atomic_json(self.root / "credential-fingerprints-before.json", credential_fingerprints)
        backups = {}
        for label in self.databases:
            dump = self.root / f"{label}-before.dump"
            with dump.open("xb") as output:
                self.pg(label, "pg_dump", ["--no-password", "--format=custom"], stdout=output)
                output.flush()
                os.fsync(output.fileno())
            require(dump.stat().st_size > 0, f"Empty {label} backup")
            with dump.open("rb") as source:
                self.pg(label, "pg_restore", ["--list"], stdin=source)
            backups[label] = {"path": str(dump), "size": dump.stat().st_size, "sha256": digest(dump)}
        atomic_json(self.root / "backups.json", backups)
        self.export_identities()
        self.upload_quiesced_backup()
        self.checkpoint("both-backups-verified")
        for label in self.databases:
            self.prepare_public_ids(label, lambda query, label=label: self.sql(label, query))
        self.checkpoint("both-planes-replay-windows-drained-or-expired")
        self.state["migration_started"] = True
        self.checkpoint("migration-started-no-image-only-rollback")
        environment = dict(os.environ, IAM_MIGRATOR_DATABASE_URL=self.databases["production"][1],
                           IAM_TESTING_MIGRATOR_DATABASE_URL=self.databases["testing"][1])
        migrate = ["docker", "run", "--rm", "--network", "host", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:size=16m,mode=1777",
                   "--volume", f"{CERT}:{CERT}:ro", "--env", "IAM_ENVIRONMENT=production",
                   "--env", "IAM_TELEMETRY=off", "--env", "IAM_MIGRATOR_DATABASE_URL",
                   "--env", "IAM_TESTING_MIGRATOR_DATABASE_URL", "--env", "IAM_MIGRATOR_DATABASE_MAX_CONNECTIONS=2",
                   "--env", "IAM_MIGRATOR_DATABASE_STATEMENT_TIMEOUT_SECONDS=120", self.args.image]
        self.run([*migrate, "iam-migrate"], environment)
        for label in self.databases:
            with (self.root / "runtime-grants.sql").open("rb") as source:
                self.pg(label, "psql", ["-X", "--no-password", "-v", "ON_ERROR_STOP=1"], stdin=source)
        # Installs only the IAM-owned SQL authentication helper; creates no app identity.
        self.run([*migrate, "iam-scoped-auth-init"], environment)
        for label in self.databases:
            self.ledger(label, complete=True)
        for label in self.databases:
            mapping = self.verify_public_ids(label, lambda query, label=label: self.sql(label, query))
            if label == "production":
                self.migrate_runtime_configuration(mapping)
            require(self.credential_fingerprints(label) == credential_fingerprints[label],
                    f"Retained {label} credentials changed during identity conversion")
        self.checkpoint("schema-grants-ciphertext-and-scoped-helper-complete")
        for path, text in replacements:
            temporary = path.with_suffix(path.suffix + ".contracts-release")
            with temporary.open("w") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(0o644 if path.suffix == ".service" else 0o600)
            temporary.replace(path)
        self.run(["systemctl", "daemon-reload"])
        self.run(["systemctl", "start", *(f"silicon-iam-{service}" for service in SERVICES)])
        for port in (8080, 8081):
            self.ready(port, self.args.revision)
        time.sleep(5)
        for service in SERVICES:
            self.run(["systemctl", "is-active", f"silicon-iam-{service}"])
            state = json.loads(self.run(["docker", "inspect", f"silicon-iam-{service}"]))[0]
            require(state["State"]["Running"] and state["Config"]["Image"] == self.args.image,
                    f"Unexpected running container for {service}")
            values = dict(item.split("=", 1) for item in state["Config"]["Env"] if "=" in item)
            if "IAM_HONEYCOMB_APP_ID" in values:
                require(re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", values["IAM_HONEYCOMB_APP_ID"]),
                        "Running container retained an old Honeycomb application ID")
        self.state["services_stopped"] = False
        self.checkpoint("healthy-acceptance-gates-pending")

    def failure(self):
        # A final environment/readiness assertion can fail after services restart.
        # Such a failure still follows the post-migration recovery path.
        if self.state["services_stopped"] or self.state["migration_started"]:
            subprocess.run(["systemctl", "stop", *(f"silicon-iam-{service}" for service in SERVICES)], capture_output=True)
            self.state["services_stopped"] = True
        if self.state["migration_started"]:
            self.state["recovery"] = ("Keep all services stopped. Forward repair using the release migration ledger, or "
                "restore BOTH verified databases and saved configuration together before starting the previous image. "
                "Never restart the old image against migrated databases. Backups contain credentials; keep them private.")
        elif self.state.get('replay_expiry_started'):
            self.state["recovery"] = "Keep all writers stopped. Authorized replay expiry may have committed. Inspect the private before-records and receipts; restore both verified databases before restarting the previous deployment if replay guarantees must be restored."
        elif self.state["services_stopped"]:
            self.state["recovery"] = "No live migration started. Inspect the failed backup/preparation before restarting the saved previous units."
        else:
            self.state["recovery"] = "Live services and databases were unchanged. Inspect the preflight or isolated restore failure."
        self.checkpoint("failed-operator-recovery-required" if self.state["services_stopped"] else "failed-live-unchanged")


def main():
    parser = argparse.ArgumentParser(description="Pinned, dual-plane IAM public identifier cutover with actual restore rehearsal")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--settings", type=Path, help="Nonsecret JSON containing image/revision/database host and secret ARN metadata")
    mode.add_argument("--write-manifest", type=Path, help="Write the SQL checksum inventory from an exact Git revision")
    parser.add_argument("--source", type=Path, default=Path.cwd(), help="Git checkout used only for --write-manifest")
    parser.add_argument("--revision", help="Full Git SHA used only for --write-manifest")
    parser.add_argument("--rehearse-only", action="store_true", help="Verify backups and migrate isolated restored copies; leave live services and databases untouched")
    options = parser.parse_args()
    if options.write_manifest:
        if not options.revision or options.rehearse_only:
            parser.error("--write-manifest requires --revision and cannot use --rehearse-only")
        manifest(argparse.Namespace(source=options.source, revision=options.revision, output=options.write_manifest))
        return
    args = argparse.Namespace(**json.loads(options.settings.read_text()))
    args.migration_manifest = Path(args.migration_manifest)
    args.rehearse_only = options.rehearse_only
    with open("/run/silicon-iam-contract-release.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original_config = {path: path.read_bytes() for path in Path('/etc/silicon-iam').glob('*.env')}
        release = Release(args)
        try:
            release.execute()
            aliases = {}
            if not args.rehearse_only:
                rows = json.loads((release.root / 'production-public-id-mapping-after.json').read_text())
                aliases = {row['old_id']:row['new_id'] for row in rows if row['scope_key'] == '' and row['actor_type'] == 'application'}
            for path, original in original_config.items():
                expected = original if args.rehearse_only else rewrite_runtime_configuration(original.decode('utf-8'), aliases).encode('utf-8')
                require(path.read_bytes() == expected, "Unrelated runtime configuration changed")
            print(json.dumps({"revision": args.revision, "image": args.image, "rehearsal_only": args.rehearse_only,
                              "runtime_environment_changes": "exact mapped IAM_HONEYCOMB_APP_ID only", "release_directory": str(release.root)}))
        except Exception as error:
            if release.root.exists():
                release.state["failure_reason"] = str(error)
                release.failure()
            raise RuntimeError("Release failed; inspect protected release log: " + str(release.root)) from None

if __name__ == "__main__":
    main()
