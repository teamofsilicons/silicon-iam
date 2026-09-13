#!/usr/bin/env python3
"""Install a pulled IAM image on the existing host, preserving keys and rollback files."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.request


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE, text=True)


def ready(port):
    for _ in range(40):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=3) as response:
                if response.status == 200:
                    return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError(f"Readiness failed on port {port}")


def install(image, secret_arn, revision, region):
    if os.geteuid() != 0:
        raise RuntimeError("Run on the IAM instance as root")
    if not re.fullmatch(r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}", image):
        raise ValueError("An immutable image digest is required")
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("A full release revision is required")
    run("docker", "image", "inspect", image)
    secret = json.loads(json.loads(run("aws", "secretsmanager", "get-secret-value",
        "--region", region, "--secret-id", secret_arn))["SecretString"])
    key = secret["IAM_TELEMETRY_KEY"]
    if not re.fullmatch(r"table-siliconiam-[0-9a-f]{32}", key):
        raise ValueError("A siliconiam recording key is required")
    os.umask(0o077)
    backup = Path("/etc/silicon-iam/releases") / (revision + "-" + str(time.time_ns()))
    backup.mkdir(parents=True, mode=0o700)
    replacements = []
    services = [("scoped-api", "scoped", 8081), ("api", "api", 8080), ("worker", "worker", None)]
    for service, env_name, _ in services:
        unit = Path(f"/etc/systemd/system/silicon-iam-{service}.service")
        env = Path(f"/etc/silicon-iam/{env_name}.env")
        text = unit.read_text()
        text, count = re.subn(r"[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}", image, text)
        if count != 1:
            raise RuntimeError(f"Expected one immutable image in {unit.name}")
        spool = Path(f"/var/lib/silicon-iam/telemetry/{service}")
        spool.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(spool, 10001, 10001)
        spool.chmod(0o700)
        volume = f"--volume {spool}:/var/lib/silicon-iam/telemetry "
        if volume not in text:
            text = text.replace(f"--env-file {env}", volume + f"--env-file {env}", 1)
        lines = [line for line in env.read_text().splitlines()
                 if not line.startswith(("IAM_TELEMETRY=", "IAM_TELEMETRY_KEY=", "IAM_TELEMETRY_KEY_FILE=", "IAM_TELEMETRY_HOME=", "IAM_TELEMETRY_URL="))]
        lines.extend(["IAM_TELEMETRY=on", "IAM_TELEMETRY_KEY=" + key,
                      "IAM_TELEMETRY_HOME=/var/lib/silicon-iam/telemetry"])
        for path, value in [(unit, text), (env, "\n".join(lines) + "\n")]:
            shutil.copy2(path, backup / path.name)
            replacements.append((path, value))
    try:
        for path, value in replacements:
            temporary = path.with_suffix(path.suffix + ".release")
            temporary.write_text(value)
            temporary.chmod(0o644 if path.suffix == ".service" else 0o600)
            temporary.replace(path)
        run("systemctl", "daemon-reload")
        for service, _, port in services:
            run("systemctl", "restart", f"silicon-iam-{service}")
            if port:
                ready(port)
        time.sleep(8)
        for service, _, _ in services:
            run("systemctl", "is-active", f"silicon-iam-{service}")
            state = run("docker", "inspect", "--format", "{{.State.Running}}", f"silicon-iam-{service}")
            if state.strip() != "true":
                raise RuntimeError("A released container stopped")
        with urllib.request.urlopen("http://127.0.0.1:8080/api/v1/version", timeout=5) as response:
            if json.load(response)["commit"] != revision:
                raise RuntimeError("The running API revision does not match")
    except Exception:
        for path, _ in replacements:
            shutil.copy2(backup / path.name, path)
        run("systemctl", "daemon-reload")
        for service, _, _ in services:
            subprocess.run(["systemctl", "restart", f"silicon-iam-{service}"], check=False, capture_output=True)
        raise RuntimeError(f"Release failed; previous configuration restored from {backup}") from None
    print(json.dumps({"revision": revision, "image": image, "services": "healthy", "rollback": str(backup)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--secret-arn", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    install(args.image, args.secret_arn, args.revision, args.region)
