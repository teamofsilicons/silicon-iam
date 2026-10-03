#!/usr/bin/env python3
"""Stage only IAM social fields and promote/restore a secret with a version CAS.

Run from the operator's trusted workstation. Staging never moves AWSCURRENT.
After the host activation plan succeeds, promote before applying that plan.
If host activation fails, roll back the label before retrying anything.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

spec = importlib.util.spec_from_file_location("activation", Path(__file__).with_name("activate-social-providers.py"))
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)
require = activation.require


def aws(args, *parts):
    result = subprocess.run(["aws", "--profile", args.profile, "--region", args.region,
                             "--output", "json",
                             "secretsmanager", *parts], capture_output=True, check=False)
    require(result.returncode == 0, "Secrets Manager operation failed; output suppressed")
    return json.loads(result.stdout or "{}")


def get(args, version=None):
    extra = ["--version-id", version] if version else []
    result = aws(args, "get-secret-value", "--secret-id", args.secret_arn, *extra)
    return result["VersionId"], json.loads(result["SecretString"])


def serialized(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def stage(args):
    require(args.google and args.previous_version, "Google candidate and prior version required")
    require(bool(args.apple) != args.disable_apple, "Choose an Apple candidate or explicit --disable-apple")
    current, previous = get(args)
    require(current == args.previous_version, "AWSCURRENT changed; refresh the activation plan")
    patch = {}
    providers = [("GOOGLE", args.google)]
    if args.apple:
        providers.append(("APPLE", args.apple))
    for provider, path in providers:
        require(path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o077 == 0,
                "Candidate must be a private regular file")
        value = json.loads(path.read_text())
        require(set(value) == {f"IAM_{provider}_CLIENT_ID", f"IAM_{provider}_CLIENT_SECRET"},
                "Candidate contains unexpected fields")
        patch.update(value)
    candidate = dict(previous, **patch)
    if args.disable_apple:
        for key in activation.APPLE_FIELDS:
            candidate.pop(key, None)
    activation.provider_values(previous, candidate, disable_apple=args.disable_apple)
    payload = serialized(candidate)
    payload_hash = hashlib.sha256(payload).hexdigest()
    if args.receipt.exists():
        state = json.loads(args.receipt.read_text())
        require(state["previous_version"] == current and state["secret_arn"] == args.secret_arn
                and state["candidate_sha256"] == payload_hash
                and state.get("disable_apple", False) == args.disable_apple, "Existing operation belongs to different input")
        require(state["stage"] in ("prepared", "staged"), "Operation already promoted or restored")
    else:
        state = {"previous_version": current, "candidate_version": str(uuid.uuid4()),
                 "candidate_sha256": payload_hash, "secret_arn": args.secret_arn,
                 "changed_fields": sorted(key for key in activation.FIELDS if previous.get(key) != candidate.get(key)),
                 "disable_apple": args.disable_apple, "stage": "prepared"}
        activation.save(args.receipt, state)
    with tempfile.NamedTemporaryFile(dir=args.receipt.parent, prefix=".secret-", delete=False) as stream:
        path = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            require(get(args)[0] == current, "AWSCURRENT changed before staging")
            response = aws(args, "put-secret-value", "--secret-id", args.secret_arn,
                           "--client-request-token", state["candidate_version"],
                           "--version-stages", "iam-social-" + state["candidate_version"],
                           "--secret-string", "file://" + str(path.resolve()))
            require(response["VersionId"] == state["candidate_version"], "Unexpected staged version")
        finally:
            path.unlink(missing_ok=True)
    require(get(args)[0] == current, "AWSCURRENT changed while staging; do not promote")
    _, check = get(args, state["candidate_version"])
    require(serialized(check) == payload, "Staged secret does not match")
    state["stage"] = "staged"
    activation.save(args.receipt, state)
    print(json.dumps(state))


def move(args):
    state = json.loads(args.receipt.read_text())
    require(state["secret_arn"] == args.secret_arn, "Secret identity mismatch")
    current, _ = get(args)
    source, target = state["previous_version"], state["candidate_version"]
    if args.action == "rollback":
        source, target = target, source
    require(current in (source, target), "Current version differs; refusing to overwrite another change")
    _, previous = get(args, state["previous_version"])
    _, candidate = get(args, state["candidate_version"])
    require(hashlib.sha256(serialized(candidate)).hexdigest() == state["candidate_sha256"],
            "Candidate content mismatch")
    if args.action == "promote":
        activation.provider_values(previous, candidate, disable_apple=state.get("disable_apple", False))
        require(args.host_plan and args.host_plan.is_file(), "A successful installed-host activation plan is required")
        plan = json.loads(args.host_plan.read_text())
        require(plan.get("prepared") is True and plan["previous_version"] == source
                and plan["secret_arn"] == args.secret_arn
                and plan["revision"] == "45a3fdf90c32c9e35b61cb3bed789ebff71d800e"
                and plan.get("disable_apple", False) == state.get("disable_apple", False),
                "Installed-host plan does not match this activation")
    # AWS checks that this label is still on RemoveFromVersionId atomically.
    if current != target:
        aws(args, "update-secret-version-stage", "--secret-id", args.secret_arn,
            "--version-stage", "AWSCURRENT", "--move-to-version-id", target,
            "--remove-from-version-id", source)
    require(get(args)[0] == target, "Secret label did not reach the requested version")
    state["stage"] = "promoted" if args.action == "promote" else "restored"
    activation.save(args.receipt, state)
    print(json.dumps({"stage": state["stage"], "previous_version": source, "current_version": target}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("stage", "promote", "rollback"))
    parser.add_argument("--secret-arn", required=True)
    parser.add_argument("--previous-version")
    parser.add_argument("--google", type=Path)
    apple = parser.add_mutually_exclusive_group()
    apple.add_argument("--apple", type=Path)
    apple.add_argument("--disable-apple", action="store_true", help="Stage removal of only the Apple pair while preserving current Google credentials.")
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--host-plan", type=Path)
    parser.add_argument("--profile", default="silicon-production")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    os.umask(0o077)
    require(args.receipt.parent.is_dir() and not args.receipt.parent.is_symlink()
            and args.receipt.parent.stat().st_mode & 0o077 == 0, "Receipt directory must already be private")
    require(not args.receipt.is_symlink(), "Receipt cannot be a symlink")
    with args.receipt.with_suffix(args.receipt.suffix + ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (stage if args.action == "stage" else move)(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print(json.dumps({"ok": False, "error": message}))
        raise SystemExit(1) from None
