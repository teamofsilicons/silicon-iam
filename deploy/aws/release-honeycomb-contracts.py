#!/usr/bin/env python3
"""Prepare or execute a pinned IAM dual-database release; never roll back only an image.

`manifest` reads committed SQL through Git. `plan` is read-only and is the default
operator review step. Only `execute` changes the host. No identity/bootstrap,
scope grant, secret-store write, or Honeycomb cutover is performed.
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
FLAGS = ("IAM_HONEYCOMB_SCHEDULED_TESTING", "IAM_HONEYCOMB_RETIRE_LEGACY_WRITERS")
CERT = "/opt/silicon-iam/aws-rds-global-bundle.pem"
IMAGE_RE = r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}"
CHECKPOINTS = (
    "Validate immutable images, current health, configuration and both existing ledgers",
    "Stop API, scoped API and worker; save private units/environment and both database dumps",
    "Validate both dump archives and checksums before marking migrations started",
    "Run dual-database iam-migrate, apply image runtime grants to both databases, initialize scoped helper",
    "Verify complete ledger checksums; force both Honeycomb cutover flags false",
    "Install immutable image into all three units and verify readiness/revision/container health",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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
        self.root = Path("/etc/silicon-iam/releases") / f"contracts-{args.revision}-{time.time_ns()}"
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
        for filename in ("api.env", "scoped.env", "worker.env"):
            path = Path("/etc/silicon-iam") / filename
            require(path.is_file(), f"Missing runtime environment {filename}")
            lines = [line for line in path.read_text().splitlines() if line.partition("=")[0] not in FLAGS]
            lines.extend(flag + "=false" for flag in FLAGS)
            replacements.append((path, "\n".join(lines) + "\n"))
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
        self.checkpoint("preflight-complete")
        # From this checkpoint failures leave all writers stopped for operator review.
        self.state["services_stopped"] = True
        self.checkpoint("stopping-writers")
        self.run(["systemctl", "stop", *(f"silicon-iam-{service}" for service in SERVICES)])
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
        self.checkpoint("both-backups-verified")
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
        self.checkpoint("schema-grants-and-scoped-helper-complete")
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
        if self.state["services_stopped"]:
            subprocess.run(["systemctl", "stop", *(f"silicon-iam-{service}" for service in SERVICES)], capture_output=True)
        self.state["recovery"] = ("Keep all services stopped. Forward repair using the release migration ledger, or explicitly "
            "restore BOTH verified databases and saved configuration together before starting the previous image. "
            "Never restart the old image against migrated databases. Backups contain credentials; keep them private.")
        self.checkpoint("failed-operator-recovery-required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("manifest", help="Read exact migration checksums from an existing Git commit")
    prepare.add_argument("--source", type=Path, default=Path.cwd())
    prepare.add_argument("--revision", required=True)
    prepare.add_argument("--output", required=True, type=Path)
    for name in ("plan", "execute"):
        release = commands.add_parser(name, help="Review checkpoints" if name == "plan" else "Change the production host")
        for field in ("image", "previous-image", "postgres-image", "revision", "previous-revision",
                      "production-host", "production-secret-arn", "testing-host", "testing-secret-arn"):
            release.add_argument("--" + field, required=True)
        release.add_argument("--migration-manifest", required=True, type=Path)
        release.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    if args.command == "manifest":
        manifest(args)
        return
    release = Release(args)
    if args.command == "plan":
        print(json.dumps({"revision": args.revision, "image": args.image, "checkpoints": CHECKPOINTS,
                          "migration_counts": {key: len(value) for key, value in release.inventory["ledgers"].items()},
                          "cutover_flags": {key: False for key in FLAGS}, "executes_changes": False}, indent=2))
        return
    require(os.geteuid() == 0, "Execute only as root")
    with open("/run/silicon-iam-contract-release.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            release.execute()
        except Exception:
            if release.root.exists():
                release.failure()
            raise RuntimeError(f"Release failed; inspect private state and log in {release.root}") from None


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
