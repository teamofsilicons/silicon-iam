#!/usr/bin/env python3
"""Restore live IAM reads into an isolated database, then rehearse a pinned image.

Neither command stops services or writes to a live database. Restore credentials
are fetched only on the host. Dumps, roles and logs remain in a private directory.
The migrator joins the network namespace of the network-none restore container.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.parse

SPEC = importlib.util.spec_from_file_location("contracts", Path(__file__).with_name("release-honeycomb-contracts.py"))
CONTRACTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACTS)
require, atomic_json, digest = CONTRACTS.require, CONTRACTS.atomic_json, CONTRACTS.digest
IDENTITIES = ("principals", "carbons", "silicons", "organizations", "organization_memberships")
CREDENTIALS = ("carbon_contacts", "silicon_credentials", "application_secrets")


def quote_identifier(value):
    return '"' + value.replace('"', '""') + '"'


def validate_ledger(output, inventory, complete=False):
    actual = {}
    for line in output.splitlines():
        version, checksum, success = line.split("|")
        require(success == "t", "Failed migration in ledger")
        require(int(version) not in actual, "Duplicate migration in ledger")
        actual[int(version)] = checksum
    expected = {row["version"]: row["checksum"] for row in inventory}
    require(actual and all(expected.get(key) == value for key, value in actual.items()),
            "Ledger differs from pinned source")
    require(not complete or actual == expected, "Incomplete migration ledger")
    return actual


def restore_command(name, image):
    require(re.fullmatch(r"iam-contract-rehearsal-[0-9]+", name), "Invalid isolated container name")
    require(re.fullmatch(CONTRACTS.IMAGE_RE, image), "PostgreSQL image must be immutable")
    return ["docker", "run", "--detach", "--name", name, "--network", "none",
            "--memory", "512m", "--cpus", "1", "--env", "POSTGRES_HOST_AUTH_METHOD=trust", image,
            "-c", "shared_buffers=64MB", "-c", "max_connections=20"]


class Rehearsal:
    run = CONTRACTS.Release.run
    secret = CONTRACTS.Release.secret
    pg = CONTRACTS.Release.pg
    sql = CONTRACTS.Release.sql

    def __init__(self, args):
        self.args, self.root = args, args.directory
        require(self.root.parent == Path("/etc/silicon-iam/releases")
                and re.fullmatch(r"rehearsal5-[0-9]+", self.root.name), "Unexpected rehearsal directory")
        self.inventory = json.loads(args.migration_manifest.read_text())
        require(re.fullmatch(r"[a-f0-9]{40}", self.inventory["revision"]), "Invalid source revision")
        require(re.fullmatch(CONTRACTS.IMAGE_RE, args.postgres_image), "PostgreSQL image must be immutable")
        self.databases = {}

    def checkpoint(self, stage):
        self.state["stage"] = stage
        atomic_json(self.root / "state.json", self.state)
        print(json.dumps({"stage": stage, "directory": str(self.root), "production_changed": False}), flush=True)

    def isolated_sql(self, database, owner, query):
        return self.run(["docker", "exec", self.state["container"], "psql", "-X", "-U", owner,
                         "-d", database, "-At", "-v", "ON_ERROR_STOP=1", "-c", query]).decode().strip()

    def preserved(self, database, owner):
        counts = {table: self.isolated_sql(database, owner, f"SELECT count(*) FROM iam.{table}")
                  for table in IDENTITIES}
        credentials = {table: self.isolated_sql(database, owner,
            f"SELECT count(*)::text || ':' || md5(COALESCE(string_agg(row_fingerprint, ',' ORDER BY row_fingerprint), '')) "
            f"FROM (SELECT md5(row_to_json(value)::text) AS row_fingerprint FROM iam.{table} value) fingerprints")
            for table in CREDENTIALS}
        return {"counts": counts, "credentials": credentials}

    def restore(self):
        require(not self.root.exists(), "Rehearsal directory already exists")
        self.root.mkdir(mode=0o700, parents=True)
        self.state = {"stage": "starting", "source_revision": self.inventory["revision"],
                      "postgres_image": self.args.postgres_image,
                      "container": "iam-contract-rehearsal-" + str(time.time_ns()), "databases": {}}
        self.checkpoint("online-read-only-backup")
        shutil.copy2(self.args.migration_manifest, self.root / "migration-manifest.json")
        self.run(["docker", "image", "inspect", self.args.postgres_image])
        metadata = json.loads(self.args.databases.read_text())
        require(set(metadata) == {"production", "testing"}, "Both IAM databases are required")
        roles, memberships = {}, set()
        for label, row in metadata.items():
            require(re.fullmatch(r"[a-zA-Z0-9.-]+\.rds\.amazonaws\.com", row["host"]), "Expected an RDS host")
            secret = self.secret(row["secret"])
            database = "silicon_iam" if label == "production" else "silicon_iam_testing"
            env = dict(os.environ, PGHOST=row["host"], PGPORT="5432", PGDATABASE=database,
                       PGUSER=secret["username"], PGPASSWORD=secret["password"],
                       PGSSLMODE="verify-full", PGSSLROOTCERT=CONTRACTS.CERT)
            self.databases[label] = (env, None)
            ledger = self.sql(label, "SELECT version,encode(checksum,'hex'),success FROM _sqlx_migrations ORDER BY version")
            validate_ledger(ledger, self.inventory["ledgers"][label])
            dump = self.root / (label + ".dump")
            with dump.open("xb") as output:
                self.pg(label, "pg_dump", ["--no-password", "--format=custom"], stdout=output)
                output.flush()
                os.fsync(output.fileno())
            require(dump.stat().st_size > 0, "Empty live backup")
            with dump.open("rb") as source:
                self.pg(label, "pg_restore", ["--list"], stdin=source)
            self.state["databases"][label] = {"owner": secret["username"], "dump_sha256": digest(dump),
                                              "dump_bytes": dump.stat().st_size}
            rows = json.loads(self.sql(label, "SELECT json_agg(json_build_object('name',rolname,'inherit',rolinherit,'login',rolcanlogin,'super',rolsuper,'createdb',rolcreatedb,'createrole',rolcreaterole,'replication',rolreplication,'bypassrls',rolbypassrls)) FROM pg_roles WHERE rolname NOT LIKE 'pg_%' AND rolname<>'postgres'"))
            for role in rows:
                require(role["name"] not in roles or roles[role["name"]] == role, "Database role attributes differ")
                roles[role["name"]] = role
            rows = json.loads(self.sql(label, "SELECT COALESCE(json_agg(json_build_object('role',r.rolname,'member',m.rolname,'admin',a.admin_option,'inherit',a.inherit_option,'set',a.set_option)), '[]'::json) FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member"))
            memberships.update((r['role'], r['member'], r['admin'], r['inherit'], r['set']) for r in rows)
        self.databases.clear()
        self.checkpoint("both-online-dumps-verified")
        self.run(restore_command(self.state["container"], self.args.postgres_image))
        for attempt in range(60):
            probe = subprocess.run(["docker", "exec", self.state["container"], "pg_isready", "-U", "postgres"], capture_output=True)
            if probe.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Isolated PostgreSQL did not become ready")
        for role, values in sorted(roles.items()):
            attributes = " ".join(("" if values[key] else "NO") + flag for key, flag in
                                  [("inherit", "INHERIT"), ("login", "LOGIN"), ("super", "SUPERUSER"),
                                   ("createdb", "CREATEDB"), ("createrole", "CREATEROLE"),
                                   ("replication", "REPLICATION"), ("bypassrls", "BYPASSRLS")])
            self.isolated_sql("postgres", "postgres", f"CREATE ROLE {quote_identifier(role)} {attributes}")
        for role, member, admin, inherit, can_set in sorted(memberships):
            self.isolated_sql("postgres", "postgres",
                f"GRANT {quote_identifier(role)} TO {quote_identifier(member)} WITH ADMIN {str(admin).upper()}, "
                f"INHERIT {str(inherit).upper()}, SET {str(can_set).upper()}")
        # Model only the RDS role-administration capability proven in the live
        # role inventory. The migrator retains NOSUPERUSER and NOBYPASSRLS.
        owner = self.state["databases"]["testing"]["owner"]
        require(roles[owner]["createrole"] and not roles[owner]["super"] and not roles[owner]["bypassrls"],
                "Unexpected live migrator role")
        require(any(r == "rds_superuser" and m == owner and s for r, m, a, i, s in memberships),
                "RDS administration model requires actual membership")
        entry = next((r for r in memberships if r[0] == "silicon_iam_testing_definer" and r[1] == owner), None)
        require(entry is not None, "Expected restricted testing definer membership")
        self.isolated_sql("postgres", "postgres", f"GRANT silicon_iam_testing_definer TO {quote_identifier(owner)} WITH ADMIN TRUE, INHERIT {str(entry[3]).upper()}, SET {str(entry[4]).upper()}")
        self.state["rds_role_admin_model"] = {"role": "silicon_iam_testing_definer", "member": owner, "isolated_only": True}
        for label, row in self.state["databases"].items():
            database, owner = "rehearsal_" + label, row["owner"]
            self.run(["docker", "exec", self.state["container"], "createdb", "-U", "postgres", "--owner", owner, database])
            with (self.root / (label + ".dump")).open("rb") as source:
                self.run(["docker", "exec", "-i", self.state["container"], "pg_restore", "-U", "postgres", "--exit-on-error", "-d", database], stdin=source)
            row["preserved_before"] = self.preserved(database, owner)
        self.checkpoint("both-databases-restored-awaiting-exact-image")

    def migrate(self):
        self.state = json.loads((self.root / "state.json").read_text())
        require(self.state["stage"] == "both-databases-restored-awaiting-exact-image", "Restore must complete before migration")
        require(self.inventory["ledgers"] == json.loads((self.root / "migration-manifest.json").read_text())["ledgers"], "Migration source changed after restore")
        require(re.fullmatch(CONTRACTS.IMAGE_RE, self.args.image), "Candidate image must be immutable")
        container = json.loads(self.run(["docker", "inspect", self.state["container"]]))[0]
        require(container["HostConfig"]["NetworkMode"] == "none" and not container["HostConfig"].get("PortBindings"), "Restore network isolation changed")
        image = json.loads(self.run(["docker", "image", "inspect", self.args.image]))[0]
        require(image["Architecture"] == "arm64" and image["Config"]["Labels"]["org.opencontainers.image.revision"] == self.inventory["revision"], "Image provenance mismatch")
        self.state.update(image=self.args.image, image_revision=self.inventory["revision"])
        environment = dict(os.environ)
        for label, variable in (("production", "IAM_MIGRATOR_DATABASE_URL"), ("testing", "IAM_TESTING_MIGRATOR_DATABASE_URL")):
            owner = self.state["databases"][label]["owner"]
            environment[variable] = f"postgresql://{urllib.parse.quote(owner, safe='')}@127.0.0.1:5432/rehearsal_{label}?sslmode=disable"
        command = ["docker", "run", "--rm", "--network", "container:" + self.state["container"],
                   "--memory", "256m", "--cpus", "1", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--env", "IAM_ENVIRONMENT=test", "--env", "IAM_TELEMETRY=off",
                   "--env", "IAM_MIGRATOR_DATABASE_URL", "--env", "IAM_TESTING_MIGRATOR_DATABASE_URL",
                   "--env", "IAM_MIGRATOR_DATABASE_MAX_CONNECTIONS=2", "--env", "IAM_MIGRATOR_DATABASE_STATEMENT_TIMEOUT_SECONDS=120", self.args.image]
        self.checkpoint("isolated-image-migration-started")
        self.run([*command, "iam-migrate"], environment)
        extraction = self.run(["docker", "create", self.args.image]).decode().strip()
        try:
            self.run(["docker", "cp", extraction + ":/opt/silicon-iam/postgres/runtime-grants.sql", str(self.root / "runtime-grants.sql")])
        finally:
            self.run(["docker", "rm", extraction])
        for label, row in self.state["databases"].items():
            database, owner = "rehearsal_" + label, row["owner"]
            with (self.root / "runtime-grants.sql").open("rb") as source:
                self.run(["docker", "exec", "-i", self.state["container"], "psql", "-X", "-U", owner, "-d", database, "-v", "ON_ERROR_STOP=1"], stdin=source)
            ledger = self.isolated_sql(database, owner, "SELECT version,encode(checksum,'hex'),success FROM _sqlx_migrations ORDER BY version")
            actual = validate_ledger(ledger, self.inventory["ledgers"][label], complete=True)
            require(self.preserved(database, owner) == row["preserved_before"], "Migration changed retained identities or credentials")
            row["verified_migrations"] = len(actual)
        self.run([*command, "iam-scoped-auth-init"], environment)
        self.checkpoint("exact-image-rehearsal-passed")
        self.run(["docker", "rm", "--force", "--volumes", self.state["container"]])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("restore", "migrate"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--migration-manifest", required=True, type=Path)
    parser.add_argument("--postgres-image", required=True)
    parser.add_argument("--databases", type=Path, help="Non-secret host/secret-ARN metadata for restore")
    parser.add_argument("--image", help="Locally available immutable ARM64 candidate for migrate")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    require(os.geteuid() == 0, "Run only as root on the IAM host")
    require(args.databases if args.command == "restore" else args.image, "Missing command-specific input")
    os.umask(0o077)
    with open("/run/silicon-iam-contract-rehearsal.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rehearsal = Rehearsal(args)
        getattr(rehearsal, args.command)()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
