#!/usr/bin/env python3
"""Plan/apply a scoped provider configuration change on an installed IAM host.

An external operator stages a new Secrets Manager version and moves AWSCURRENT
with RemoveFromVersionId equal to the plan's prior version. This script requires
only GetSecretValue on the host; it cannot promote a version or change a schema.
All subprocess output and credential material remain private.
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
import time
import urllib.request
import urllib.parse
import urllib.error

GOOGLE_FIELDS = frozenset(("IAM_GOOGLE_CLIENT_ID", "IAM_GOOGLE_CLIENT_SECRET"))
APPLE_FIELDS = frozenset(("IAM_APPLE_CLIENT_ID", "IAM_APPLE_CLIENT_SECRET"))
FIELDS = GOOGLE_FIELDS | APPLE_FIELDS
SERVICES = {"api": "api.env", "scoped-api": "scoped.env", "worker": "worker.env"}
AUTH_SERVICES = ("api", "scoped-api")
CONFIG = Path("/etc/silicon-iam")
CERT = "/opt/silicon-iam/aws-rds-global-bundle.pem"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(argv, env=None):
    result = subprocess.run(argv, env=env, capture_output=True, check=False)
    require(result.returncode == 0, f"{Path(argv[0]).name} failed; output suppressed")
    return result.stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data):
    temporary = path.with_name(path.name + ".pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def save(path, value):
    atomic(path, (json.dumps(value, indent=2) + "\n").encode())


def environment(raw):
    result = {}
    for line in raw.decode().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        require("=" in line, "Unsupported environment file line")
        key, value = line.split("=", 1)
        require(key not in result, "Duplicate environment key")
        result[key] = value
    return result


def validate_values(values):
    require(set(values) in (GOOGLE_FIELDS, FIELDS), "A complete Google pair and complete or absent Apple pair are required")
    for value in values.values():
        require(isinstance(value, str) and value and not any(c in value for c in "\r\n\x00"),
                "Provider values must be nonempty single-line strings")


def updated_environment(raw, values):
    existing = environment(raw)
    validate_values(values)
    if set(values) == GOOGLE_FIELDS:
        require(all(existing.get(key) == values[key] for key in GOOGLE_FIELDS),
                "Existing runtime Google credentials differ; refusing Apple-only removal")
        # Disable is strictly subtractive, retaining Google and all other bytes.
        return b"".join(line for line in raw.splitlines(keepends=True)
                        if line.split(b"=", 1)[0].decode() not in APPLE_FIELDS)
    # Preserve all unrelated bytes, including comments and order.
    kept = b"".join(line for line in raw.splitlines(keepends=True)
                    if line.split(b"=", 1)[0].decode() not in FIELDS)
    if kept and not kept.endswith(b"\n"):
        kept += b"\n"
    updated = kept + "".join(f"{key}={values[key]}\n" for key in sorted(values)).encode()
    require({k: v for k, v in environment(raw).items() if k not in FIELDS}
            == {k: v for k, v in environment(updated).items() if k not in FIELDS},
            "Unrelated environment change")
    return updated


def provider_values(previous, candidate, disable_apple=False):
    require(isinstance(previous, dict) and isinstance(candidate, dict), "Expected secret objects")
    require({k: v for k, v in previous.items() if k not in FIELDS}
            == {k: v for k, v in candidate.items() if k not in FIELDS},
            "Unrelated secret fields changed")
    expected_fields = GOOGLE_FIELDS if disable_apple else FIELDS
    require(set(candidate) & FIELDS == expected_fields, "Provider fields do not match the reviewed Apple enable/disable mode")
    values = {key: candidate[key] for key in expected_fields}
    validate_values(values)
    require(values["IAM_GOOGLE_CLIENT_ID"].endswith(".apps.googleusercontent.com"),
            "Unexpected Google client ID")
    if disable_apple:
        require(all(previous.get(key) == values[key] for key in GOOGLE_FIELDS),
                "Disabling Apple must preserve the existing Google credentials")
        return values
    require(values["IAM_APPLE_CLIENT_ID"] == "com.teamofsilicons.interface", "Unexpected Apple Services ID")
    try:
        header, claims, signature = values["IAM_APPLE_CLIENT_SECRET"].split(".")
        decode = lambda value: json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
        header, claims = decode(header), decode(claims)
        require(header.get("alg") == "ES256" and header.get("kid") == "RB4CTQPLR5"
                and header.get("typ", "JWT") == "JWT" and set(header) <= {"alg", "kid", "typ"},
                "Unexpected Apple JWT header")
        require(claims["iss"] == "LTBSK59BJ2" and claims["sub"] == values["IAM_APPLE_CLIENT_ID"]
                and claims["aud"] == "https://appleid.apple.com", "Apple JWT claims mismatch")
        require(time.time() - 86400 < claims["iat"] <= time.time() + 60
                and time.time() + 7 * 86400 < claims["exp"] <= claims["iat"] + 15777000,
                "Apple credential is stale or has an invalid expiry")
        require(len(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))) == 64,
                "Unexpected Apple signature length")
    except (KeyError, ValueError, TypeError):
        raise RuntimeError("Invalid Apple credential format") from None
    return values


def secret(args, version=None):
    command = ["aws", "--output", "json", "secretsmanager", "get-secret-value", "--region", args.region,
               "--secret-id", args.secret_arn]
    if version:
        command += ["--version-id", version]
    result = json.loads(run(command))
    return result["VersionId"], json.loads(result["SecretString"])


def get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
        require(response.status == 200, "HTTP health check failed")
        return json.load(response)


def ready(args, retry=False):
    for attempt in range(40 if retry else 1):
        try:
            for port in (8080, 8081):
                get(port, "/readyz")
                version = get(port, "/api/v1/version")
                require(version["commit"] == args.revision and version["build"] == "5.1.0",
                        "Required IAM 5.1 source is not installed")
            return
        except Exception:
            if not retry or attempt == 39:
                raise RuntimeError("Exact IAM source/readiness check failed") from None
            time.sleep(2)


def postgres_environment(url):
    """libpq does not expand a URI supplied only through PGDATABASE."""
    parsed = urllib.parse.urlsplit(url)
    options = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    require(parsed.scheme in ("postgres", "postgresql") and parsed.hostname
            and parsed.username and parsed.password and parsed.path.startswith("/")
            and not parsed.fragment, "Unsupported runtime database URL")
    require(set(options) == {"sslmode", "sslrootcert"}
            and options["sslmode"] == ["verify-full"]
            and options["sslrootcert"] == [CERT], "Unexpected database TLS settings")
    return {"PGHOST": parsed.hostname, "PGPORT": str(parsed.port or 5432),
            "PGDATABASE": urllib.parse.unquote(parsed.path[1:]),
            "PGUSER": urllib.parse.unquote(parsed.username),
            "PGPASSWORD": urllib.parse.unquote(parsed.password),
            "PGSSLMODE": "verify-full", "PGSSLROOTCERT": CERT}


def schema(args):
    inventory = json.loads(args.manifest.read_text())
    require(inventory["revision"] == args.revision, "Manifest source mismatch")
    values = environment((CONFIG / "api.env").read_bytes())
    for label, key in (("production", "IAM_DATABASE_URL"), ("testing", "IAM_TESTING_DATABASE_URL")):
        connection = postgres_environment(values[key])
        variables = [arg for name in connection for arg in ("--env", name)]
        output = run(["docker", "run", "--rm", "--network", "host", "--read-only", "--cap-drop", "ALL",
                      "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:size=16m,mode=1777",
                      "--volume", f"{CERT}:{CERT}:ro", *variables,
                      "--entrypoint", "psql", args.postgres_image, "-X", "--no-password", "-At",
                      "-v", "ON_ERROR_STOP=1", "-c",
                      "SELECT version,encode(checksum,'hex'),success FROM _sqlx_migrations ORDER BY version"],
                     env=dict(os.environ, **connection)).decode()
        expected = [f"{row['version']}|{row['checksum']}|t" for row in inventory["ledgers"][label]]
        require(output.splitlines() == expected, f"Exact {label} schema ledger mismatch")


def snapshot(args):
    ready(args)
    schema(args)
    files = {path.name: digest(path.read_bytes()) for path in CONFIG.glob("*.env")}
    units, images = {}, {}
    for service, filename in SERVICES.items():
        require(filename in files, "Missing required runtime environment")
        unit = Path(f"/etc/systemd/system/silicon-iam-{service}.service")
        text = unit.read_text()
        require(text.count(f"--env-file {CONFIG / filename}") == 1, "Unexpected environment source")
        require(not any(re.search(r"--env(?:=|\s+)" + key + r"(?:=|\s)", text) for key in FIELDS),
                "Inline provider override requires review")
        units[service] = digest(unit.read_bytes())
        require(not run(["systemctl", "show", f"silicon-iam-{service}", "--property=DropInPaths", "--value"]).strip(),
                "Systemd drop-ins require independent review")
        run(["systemctl", "is-active", f"silicon-iam-{service}"])
        info = json.loads(run(["docker", "inspect", f"silicon-iam-{service}"]))[0]
        require(info["State"]["Running"], "A runtime container is not running")
        require(info["Config"]["Labels"]["org.opencontainers.image.revision"] == args.revision,
                "Container source mismatch")
        configured = environment((CONFIG / filename).read_bytes())
        running = dict(item.split("=", 1) for item in info["Config"]["Env"])
        require({key: running.get(key) for key in FIELDS} == {key: configured.get(key) for key in FIELDS},
                "Running provider environment does not match its file")
        images[service] = info["Image"]
    return {"env_hashes": files, "unit_hashes": units, "images": images}


def assert_files(plan):
    require({p.name: digest(p.read_bytes()) for p in CONFIG.glob("*.env")} == plan["env_hashes"],
            "Runtime environment changed after preparation")
    for service, expected in plan["unit_hashes"].items():
        require(digest(Path(f"/etc/systemd/system/silicon-iam-{service}.service").read_bytes()) == expected,
                "Runtime unit changed after preparation")


def stop():
    run(["systemctl", "stop", *(f"silicon-iam-{service}" for service in AUTH_SERVICES)])
    for service in AUTH_SERVICES:
        info = json.loads(run(["docker", "inspect", f"silicon-iam-{service}"]))[0]
        require(not info["State"]["Running"], "IAM writer remained active")


def start(args):
    run(["systemctl", "start", *(f"silicon-iam-{service}" for service in AUTH_SERVICES)])
    ready(args, retry=True)
    for service in SERVICES:
        run(["systemctl", "is-active", f"silicon-iam-{service}"])


def verify_provider_discovery(disable_apple=False):
    response = get(8080, "/api/v1/signup/social/providers")
    rows = response.get("providers", response.get("data", {}).get("providers", []))
    expected = {"google": True, "apple": not disable_apple}
    require(len(rows) == 2 and {row.get("id") for row in rows} == set(expected)
            and all(row.get("enabled") is expected[row["id"]]
                    and row.get("login_enabled") is expected[row["id"]] for row in rows),
            "Provider discovery does not match the reviewed Google/Apple state")
    # src/api/mod.rs deliberately excludes authentication::router from Scoped.
    try:
        get(8081, "/api/v1/signup/social/providers")
    except urllib.error.HTTPError as error:
        require(error.code == 404, "Unexpected scoped provider discovery response")
    else:
        raise RuntimeError("Provider signup route unexpectedly exposed on scoped API")


def plan(args):
    require(not args.directory.exists(), "Activation directory already exists")
    version, _ = secret(args)
    require(version == args.previous_version, "Current secret version changed")
    state = snapshot(args)
    args.directory.mkdir(mode=0o700, parents=True)
    for name in state["env_hashes"]:
        shutil.copy2(CONFIG / name, args.directory / name)
        (args.directory / name).chmod(0o600)
    state.update(revision=args.revision, previous_version=version, secret_arn=args.secret_arn,
                 manifest_sha256=digest(args.manifest.read_bytes()), operator_sha256=digest(Path(__file__).read_bytes()),
                 disable_apple=args.disable_apple)
    save(args.directory / "plan.json", state)
    print(json.dumps({"prepared": True, "directory": str(args.directory), **state}))


def apply(args):
    state = json.loads((args.directory / "plan.json").read_text())
    require(not (args.directory / "started.json").exists(), "Activation already attempted; inspect its receipt")
    require(state["revision"] == args.revision and state["previous_version"] == args.previous_version
            and state["secret_arn"] == args.secret_arn
            and state.get("disable_apple", False) == args.disable_apple, "Activation plan mismatch")
    require(state["manifest_sha256"] == digest(args.manifest.read_bytes())
            and state["operator_sha256"] == digest(Path(__file__).read_bytes()), "Reviewed source changed")
    current, candidate = secret(args)
    require(current == args.candidate_version, "Candidate is not AWSCURRENT")
    _, previous = secret(args, args.previous_version)
    values = provider_values(previous, candidate, disable_apple=args.disable_apple)
    require(snapshot(args) == {key: state[key] for key in ("env_hashes", "unit_hashes", "images")},
            "Runtime changed after preparation")
    updated = {SERVICES[service]: updated_environment((CONFIG / SERVICES[service]).read_bytes(), values)
               for service in AUTH_SERVICES}
    save(args.directory / "started.json", {"candidate_version": current, "started_at": time.time()})
    stopped = False
    written = []
    try:
        stopped = True
        stop()
        assert_files(state)
        require(secret(args)[0] == current, "Current secret changed before environment installation")
        for name, value in updated.items():
            atomic(CONFIG / name, value)
            written.append(name)
        start(args)
        after = snapshot(args)
        require(after["unit_hashes"] == state["unit_hashes"] and after["images"] == state["images"],
                "Runtime units or image changed during activation")
        for name, old_hash in state["env_hashes"].items():
            require(after["env_hashes"][name] == (digest(updated[name]) if name in updated else old_hash),
                    "Unexpected environment mutation")
        verify_provider_discovery(disable_apple=args.disable_apple)
        require(secret(args)[0] == current, "Current secret changed during activation")
        receipt = {"activated": True, "revision": args.revision, "previous_version": args.previous_version,
                   "candidate_version": current, "changed_fields": sorted(key for key in FIELDS if previous.get(key) != candidate.get(key)),
                   "disabled_providers": ["apple"] if args.disable_apple else [], "runtime": after,
                   "oauth_acceptance": "Not performed by this configuration operator"}
        save(args.directory / "result.json", receipt)
        print(json.dumps(receipt))
    except Exception:
        recovered = False
        if stopped:
            try:
                stop()
                for service, expected in state["unit_hashes"].items():
                    require(digest(Path(f"/etc/systemd/system/silicon-iam-{service}.service").read_bytes()) == expected,
                            "Cannot restore across a concurrent unit change")
                for name in written:
                    require((CONFIG / name).read_bytes() == updated[name], "Cannot overwrite a concurrent environment change")
                    require(digest((args.directory / name).read_bytes()) == state["env_hashes"][name], "Backup changed")
                    atomic(CONFIG / name, (args.directory / name).read_bytes())
                start(args)
                recovered = True
            except Exception:
                pass
        save(args.directory / "failure.json", {"activated": False, "runtime_restored": recovered,
             "secret_rollback_required": True, "previous_version": args.previous_version,
             "candidate_version": current})
        raise RuntimeError("Provider activation failed; inspect private receipt and restore the prior secret stage with CAS") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--secret-arn", required=True)
    parser.add_argument("--previous-version", required=True)
    parser.add_argument("--candidate-version")
    parser.add_argument("--disable-apple", action="store_true", help="Remove only Apple credentials and retain the existing Google pair; bind this mode in both plan and apply.")
    parser.add_argument("--postgres-image", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    require(os.geteuid() == 0, "Run on IAM host as root")
    require(re.fullmatch(r"[0-9a-f]{40}", args.revision), "Full source revision required")
    require(re.fullmatch(r"[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}", args.postgres_image), "Pinned PostgreSQL image required")
    require(args.directory.parent == CONFIG / "provider-activations" and re.fullmatch(r"[A-Za-z0-9-]+", args.directory.name),
            "Use an isolated provider activation directory")
    require(args.action != "apply" or args.candidate_version, "Candidate version required")
    os.umask(0o077)
    with (CONFIG / "provider-activation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (plan if args.action == "plan" else apply)(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never serialize a subprocess exception, command output, or secret body.
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(json.dumps({"ok": False, "error": message}), file=sys.stderr)
        sys.exit(1)
