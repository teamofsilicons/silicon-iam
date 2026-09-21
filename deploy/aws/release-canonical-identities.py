#!/usr/bin/env python3
"""Prepare or execute a pinned IAM dual-database release; never roll back only an image.

A restore rehearsal runs the actual migration on isolated copies before stopping
live writers. --rehearse-only stops before the live cutover. Runtime environment
files, credentials and application registrations are preserved.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request

SERVICES = ("api", "scoped-api", "worker")
FLAGS = ()
CERT = "/opt/silicon-iam/aws-rds-global-bundle.pem"
IMAGE_RE = r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}"
CREDENTIAL_TABLES = ("authentication_sessions", "refresh_token_families", "refresh_tokens",
                     "access_tokens", "application_secrets", "silicon_credentials")
CHECKPOINTS = (
    "Validate immutable images, current health, configuration and both existing ledgers",
    "Stop API, scoped API and worker; save private units/environment and both database dumps",
    "Validate both dump archives and checksums before marking migrations started",
    "Run dual-database iam-migrate, apply image runtime grants to both databases, initialize scoped helper",
    "Verify complete ledgers and convert encrypted historical payloads",
    "Install immutable image into all three units and verify readiness/revision/container health",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


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
        self.root = Path("/etc/silicon-iam/releases") / f"canonical-{args.revision}-{time.time_ns()}"
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
        if complete:
            require(actual == expected, f"Incomplete {label} migration ledger")
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

    def cutover_operator(self, url, phase, network="host", rehearsal=False):
        environment = dict(os.environ, IAM_DATABASE_URL=url)
        command = ["docker", "run", "--rm", "--network", network, "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--tmpfs", "/tmp:size=16m,mode=1777", "--volume", f"{CERT}:{CERT}:ro",
                   "--env-file", "/etc/silicon-iam/api.env", "--env", "IAM_DATABASE_URL",
                   "--env", "IAM_TESTING_DATABASE_URL=", "--env", "IAM_TELEMETRY=off",
                   "--env", "IAM_DATABASE_MAX_CONNECTIONS=2",
                   "--env", "IAM_DATABASE_STATEMENT_TIMEOUT_SECONDS=120"]
        if rehearsal:
            command.extend(["--env", "IAM_ENVIRONMENT=test"])
        self.run([*command, self.args.image, "iam-canonical-cutover", phase], environment)

    def verify_canonical(self, label):
        result = self.sql(label, "SELECT (SELECT count(*) FROM iam.carbons WHERE id<>carbon_id),"
                          "(SELECT count(*) FROM iam.silicons WHERE id<>global_silicon_id),"
                          "(SELECT count(*) FROM iam.applications WHERE id<>app_id),"
                          "(SELECT count(*) FROM iam_private.canonical_replay_cutover WHERE converted_at IS NULL)")
        require(result == "0|0|0|0", f"Canonical data invariant failed in {label}")

    def export_identities(self):
        """Retain the final pre-conversion mapping privately while writers are stopped."""
        query = """SELECT COALESCE(jsonb_agg(jsonb_build_object(
          'legacy_id',p.id::text,'kind',p.kind::text,
          'public_id',CASE p.kind WHEN 'carbon' THEN c.carbon_id
            WHEN 'silicon' THEN s.global_silicon_id WHEN 'application' THEN a.app_id
            WHEN 'service' THEN 'service/'||v.service_id END,
          'testing_environment_id',to_jsonb(p)->>'testing_environment_id',
          'memberships',COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'membership_id',m.id::text,'organization_id',o.id::text,'org_id',o.org_id,
            'membership_public_id',COALESCE(c.carbon_id,s.global_silicon_id)||'['||o.org_id||']'))
            FROM iam.organization_memberships m JOIN iam.organizations o ON o.id=m.organization_id
            WHERE m.principal_id=p.id),'[]'::jsonb)) ORDER BY p.id),'[]'::jsonb)
          FROM iam.principals p LEFT JOIN iam.carbons c ON c.id=p.id
          LEFT JOIN iam.silicons s ON s.id=p.id LEFT JOIN iam.applications a ON a.id=p.id
          LEFT JOIN iam.service_principals v ON v.id=p.id"""
        result = {label: json.loads(self.sql(label, query)) for label in self.databases}
        require(all(row["public_id"] for rows in result.values() for row in rows), "Unmapped identity in final export")
        atomic_json(self.root / "identity-mapping-before.json", result)

    @staticmethod
    def credential_fingerprint_query(table):
        require(table in CREDENTIAL_TABLES, "Unexpected credential table")
        # Only identity references change representation. Token digests, resource
        # IDs, expiry/revocation state, epochs, ciphertext and all other fields stay.
        excluded = ("'subject_principal_id','client_application_id','audience_application_id',"
                    "'application_id','created_by_carbon_id','silicon_id'")
        return (f"SELECT count(*)::text||':'||COALESCE(md5(string_agg("
                f"(to_jsonb(t)-ARRAY[{excluded}])::text,'' ORDER BY id)),md5('')) FROM iam.{table} t")

    def credential_fingerprints(self, label):
        return {table: self.sql(label, self.credential_fingerprint_query(table)) for table in CREDENTIAL_TABLES}

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
                self.cutover_operator(urls[label], "prepare", "container:" + name, True)
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
                self.cutover_operator(url, "convert", "container:" + name, True)
                for table in CREDENTIAL_TABLES:
                    after = self.run(["docker", "exec", name, "psql", "-U", owner, "-d", database,
                                      "-At", "-v", "ON_ERROR_STOP=1", "-c", self.credential_fingerprint_query(table)])
                    require(after == fingerprints[label][table], f"Rehearsal altered retained {label} {table} credentials")
                result = self.run(["docker", "exec", name, "psql", "-U", "postgres", "-d", database, "-Atc",
                                   "SELECT count(*) FROM iam_private.canonical_replay_cutover WHERE converted_at IS NOT NULL"]).decode().strip()
                require(result == "1", "Isolated conversion did not finish")
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
        # From this checkpoint failures leave all writers stopped for operator review.
        self.state["services_stopped"] = True
        self.checkpoint("stopping-writers")
        self.run(["systemctl", "stop", *(f"silicon-iam-{service}" for service in SERVICES)])
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
        self.checkpoint("both-backups-verified")
        for label in self.databases:
            self.cutover_operator(self.databases[label][1], "prepare")
        self.checkpoint("both-planes-replay-prepared")
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
            self.cutover_operator(self.databases[label][1], "convert")
            self.verify_canonical(label)
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
            require(all(values.get(flag) == "false" for flag in FLAGS), "Honeycomb cutover flag not disabled")
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
        elif self.state["services_stopped"]:
            self.state["recovery"] = "No live migration started. Inspect the failed backup/preparation before restarting the saved previous units."
        else:
            self.state["recovery"] = "Live services and databases were unchanged. Inspect the preflight or isolated restore failure."
        self.checkpoint("failed-operator-recovery-required" if self.state["services_stopped"] else "failed-live-unchanged")


def main():
    parser = argparse.ArgumentParser(description="Pinned, dual-plane IAM canonical cutover with actual restore rehearsal")
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
        hashes = {str(path): digest(path) for path in Path("/etc/silicon-iam").glob("*.env")}
        release = Release(args)
        try:
            release.execute()
            require(all(digest(Path(path)) == value for path, value in hashes.items()), "Runtime configuration changed")
            print(json.dumps({"revision": args.revision, "image": args.image, "rehearsal_only": args.rehearse_only,
                              "runtime_environment_unchanged": True, "release_directory": str(release.root)}))
        except Exception:
            if release.root.exists():
                release.failure()
            raise RuntimeError("Release failed; inspect protected release log: " + str(release.root)) from None

if __name__ == "__main__":
    main()
