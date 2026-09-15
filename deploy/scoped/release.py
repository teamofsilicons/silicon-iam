#!/usr/bin/env python3
"""Release only scoped IAM on its existing host, retaining main IAM and worker."""
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


def run(*args, env=None):
    result = subprocess.run(args, env=env, check=False, capture_output=True, text=True)
    if result.returncode:
        # Commands can use private environment credentials. Their output never
        # becomes a deployment log or exception containing credential material.
        raise RuntimeError(f"{args[0]} operation failed with exit code {result.returncode}")
    return result.stdout


def container_state(name):
    return run("docker", "inspect", "--format", "{{.Image}} {{.State.Running}}", name).strip()


def ready(port):
    for _ in range(30):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=3) as response:
                if response.status == 200:
                    return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError(f"Readiness failed on port {port}")


def bootstrap(image, secret_arn, database_host, region):
    secret = json.loads(json.loads(run("aws", "secretsmanager", "get-secret-value",
        "--region", region, "--secret-id", secret_arn))["SecretString"])
    user = urllib.parse.quote(secret["username"], safe="")
    password = urllib.parse.quote(secret["password"], safe="")
    environment = os.environ.copy()
    environment["IAM_MIGRATOR_DATABASE_URL"] = (
        f"postgresql://{user}:{password}@{database_host}:5432/silicon_iam"
        "?sslmode=verify-full&sslrootcert=/opt/silicon-iam/aws-rds-global-bundle.pem"
    )
    run("docker", "run", "--rm", "--network", "host", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:size=16m,mode=1777",
        "--volume", "/opt/silicon-iam/aws-rds-global-bundle.pem:/opt/silicon-iam/aws-rds-global-bundle.pem:ro",
        "--env", "IAM_ENVIRONMENT=production", "--env", "IAM_LOG_FILTER=silicon_iam=info",
        "--env", "IAM_TELEMETRY=off", "--env", "IAM_MIGRATOR_DATABASE_URL",
        image, "iam-scoped-auth-init", env=environment)


def release(image, revision, secret_arn, database_host, region):
    if os.geteuid() != 0:
        raise RuntimeError("Run on the existing IAM instance as root")
    if not re.fullmatch(r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}", image):
        raise ValueError("An immutable image digest is required")
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("A full release revision is required")
    if not re.fullmatch(r"[a-zA-Z0-9.-]+\.rds\.amazonaws\.com", database_host):
        raise ValueError("An RDS database host is required")
    run("docker", "image", "inspect", image)
    before = {name: container_state(name) for name in ("silicon-iam-api", "silicon-iam-worker")}
    ready(8080)
    unit = Path("/etc/systemd/system/silicon-iam-scoped-api.service")
    original = unit.read_text()
    updated, count = re.subn(r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}", image, original)
    if count != 1:
        raise RuntimeError("Expected exactly one immutable scoped image in the unit")
    # No main migration/ledger, existing permission, token, keyring, or
    # application registration is changed by this scoped-owned bootstrap.
    bootstrap(image, secret_arn, database_host, region)
    os.umask(0o077)
    backup = Path("/etc/silicon-iam/releases") / f"scoped-slt-{revision}-{time.time_ns()}"
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(unit, backup / unit.name)
    try:
        temporary = unit.with_suffix(".service.scoped-release")
        temporary.write_text(updated)
        temporary.chmod(0o644)
        temporary.replace(unit)
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", "silicon-iam-scoped-api")
        ready(8081)
        with urllib.request.urlopen("http://127.0.0.1:8081/api/v1/version", timeout=5) as response:
            if json.load(response)["commit"] != revision:
                raise RuntimeError("Scoped deployment revision mismatch")
        ready(8080)
        after = {name: container_state(name) for name in before}
        if before != after or not all(value.endswith(" true") for value in after.values()):
            raise RuntimeError("Main IAM or worker state changed during scoped deployment")
    except Exception:
        shutil.copy2(backup / unit.name, unit)
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", "silicon-iam-scoped-api")
        raise RuntimeError(f"Scoped release failed; previous unit restored from {backup}") from None
    print(json.dumps({"revision": revision, "image": image, "scoped": "ready",
                      "main_and_worker": "unchanged", "rollback": str(backup)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--secret-arn", required=True)
    parser.add_argument("--database-host", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    release(args.image, args.revision, args.secret_arn, args.database_host, args.region)
