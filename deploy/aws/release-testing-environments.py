#!/usr/bin/env python3
"""Apply the testing-permission release on the existing IAM host.

Updates only image references and the two schema ledgers. Runtime environment,
providers, keyrings, ingress and database login roles stay intact. A migration
failure requires forward repair: restoring an older image with an incompatible
embedded migration ledger is deliberately not attempted.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

SERVICES = ("api", "scoped-api", "worker")
CERT = "/opt/silicon-iam/aws-rds-global-bundle.pem"


def run(*args, env=None):
    result = subprocess.run(args, env=env, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[0]} operation failed ({result.returncode}); inspect privately on host")
    return result.stdout


def database_url(secret_arn, host, database, region):
    if not re.fullmatch(r"[a-zA-Z0-9.-]+\.rds\.amazonaws\.com", host):
        raise ValueError("Expected an RDS host")
    secret = json.loads(json.loads(run("aws", "secretsmanager", "get-secret-value",
        "--region", region, "--secret-id", secret_arn))["SecretString"])
    user = urllib.parse.quote(secret["username"], safe="")
    password = urllib.parse.quote(secret["password"], safe="")
    return f"postgresql://{user}:{password}@{host}:5432/{database}?sslmode=verify-full&sslrootcert={CERT}"


def ready(port, revision=None):
    for _ in range(30):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=3) as response:
                if response.status != 200:
                    continue
            if revision:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/version", timeout=3) as response:
                    if json.load(response)["commit"] != revision:
                        raise RuntimeError("Revision mismatch")
            return
        except Exception:
            time.sleep(2)
    raise RuntimeError(f"Readiness/revision check failed on {port}")


def release(args):
    if os.geteuid() != 0:
        raise RuntimeError("Run as root on the existing IAM instance")
    if not re.fullmatch(r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}", args.image):
        raise ValueError("Immutable image digest required")
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        raise ValueError("Full git revision required")
    run("docker", "image", "inspect", args.image)
    for port in (8080, 8081):
        ready(port)
    os.umask(0o077)
    backup = Path("/etc/silicon-iam/releases") / f"testing-{args.revision}-{time.time_ns()}"
    backup.mkdir(parents=True, mode=0o700)
    replacements = []
    for service in SERVICES:
        run("systemctl", "is-active", f"silicon-iam-{service}")
        unit = Path(f"/etc/systemd/system/silicon-iam-{service}.service")
        content, count = re.subn(r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}", args.image, unit.read_text())
        if count != 1:
            raise RuntimeError(f"Expected one immutable image reference in {unit.name}")
        shutil.copy2(unit, backup / unit.name)
        replacements.append((unit, content))
    env = os.environ.copy()
    env["IAM_MIGRATOR_DATABASE_URL"] = database_url(args.production_secret_arn,
        args.production_host, "silicon_iam", args.region)
    env["IAM_TESTING_MIGRATOR_DATABASE_URL"] = database_url(args.testing_secret_arn,
        args.testing_host, "silicon_iam_testing", args.region)
    command = ["docker", "run", "--rm", "--network", "host", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:size=16m,mode=1777", "--volume", f"{CERT}:{CERT}:ro",
        "--env", "IAM_ENVIRONMENT=production", "--env", "IAM_LOG_FILTER=silicon_iam=info", "--env", "IAM_TELEMETRY=off",
        "--env", "IAM_MIGRATOR_DATABASE_URL", "--env", "IAM_TESTING_MIGRATOR_DATABASE_URL", args.image]
    run("systemctl", "stop", *(f"silicon-iam-{service}" for service in SERVICES))
    run(*command, "iam-migrate", env=env)
    run(*command, "iam-scoped-auth-init", env=env)
    for unit, content in replacements:
        temporary = unit.with_suffix(".service.testing-release")
        temporary.write_text(content)
        temporary.chmod(0o644)
        temporary.replace(unit)
    run("systemctl", "daemon-reload")
    run("systemctl", "start", *(f"silicon-iam-{service}" for service in SERVICES))
    for port in (8080, 8081):
        ready(port, args.revision)
    time.sleep(5)
    for service in SERVICES:
        run("systemctl", "is-active", f"silicon-iam-{service}")
        running = run("docker", "inspect", "--format", "{{.State.Running}}", f"silicon-iam-{service}").strip()
        if running != "true":
            raise RuntimeError(f"Container stopped: {service}")
    print(json.dumps({"revision": args.revision, "image": args.image, "services": list(SERVICES),
        "status": "healthy", "backup": str(backup), "runtime_configuration": "preserved"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "revision", "production-secret-arn", "production-host", "testing-secret-arn", "testing-host"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--region", default="us-east-1")
    release(parser.parse_args())
