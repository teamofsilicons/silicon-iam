#!/usr/bin/env python3
"""Prepare an Apple client-secret candidate locally; never mutate runtime configuration."""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

DEFAULT_LIFETIME_DAYS = 90
MAX_LIFETIME_DAYS = 180
AUDIENCE = "https://appleid.apple.com"


class CandidateError(Exception):
    """Safe-to-display validation failure, without credential material."""


def _absolute(path):
    # Do not resolve symlinks: each component is opened with O_NOFOLLOW below.
    return Path(os.path.abspath(os.fspath(path)))


def _open_private_directory(path):
    """Anchor all subsequent operations to a verified directory descriptor."""
    path = _absolute(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise CandidateError("The key and output directories must be owned by the current user and private (0700).")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _load_key(path):
    path = _absolute(path)
    if path.suffix.lower() != ".p8":
        raise CandidateError("The signing key must be a protected .p8 file.")
    parent = _open_private_directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise CandidateError("The signing key must be a regular file owned by the current user.")
            if stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1:
                raise CandidateError("The signing key must have private permissions (0600) and no hard links.")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                key_bytes = source.read(65537)
            if len(key_bytes) > 65536:
                raise CandidateError("The signing key file exceeds the supported size.")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)
    try:
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
    except (ValueError, TypeError):
        raise CandidateError("The signing key must be an unencrypted PKCS#8 PEM private key.") from None
    if not key_bytes.startswith(b"-----BEGIN PRIVATE KEY-----"):
        raise CandidateError("The signing key must use PKCS#8 PEM format.")
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise CandidateError("Apple client-secret signing requires an EC P-256 private key.")
    return private_key


def _b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _encoded_json(value):
    return _b64url(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")


def _assert_absent(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise CandidateError("Output files must not already exist, including symlinks; choose fresh output names.")


def _publish_pair(parent, entries):
    """Publish fsynced 0600 files with link(2)'s atomic no-replace guarantee.

    Both files are prepared before publication. On a failure, remove only inodes
    created by this invocation, never an existing or replaced destination.
    """
    temporary = []
    published = []
    try:
        for name, payload in entries:
            _assert_absent(parent, name)
            temp_name = f".apple-client-secret-{secrets.token_hex(16)}.tmp"
            descriptor = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                os.fchmod(descriptor, 0o600)
                temporary.append((temp_name, os.fstat(descriptor)))
                with os.fdopen(descriptor, "wb", closefd=False) as destination:
                    destination.write(payload)
                    destination.flush()
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for (name, _), (temp_name, info) in zip(entries, temporary):
            os.link(temp_name, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            published.append((name, info))
        os.fsync(parent)
    except BaseException:
        for name, info in reversed(published):
            try:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                    os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass
        raise
    finally:
        for temp_name, _ in temporary:
            os.unlink(temp_name, dir_fd=parent)
        os.fsync(parent)


def generate_candidate(*, key_path, team_id, key_id, services_id, output, lifetime_days=DEFAULT_LIFETIME_DAYS, operation="generate", now=None):
    """Create a private JSON candidate and its adjacent nonsecret receipt."""
    if operation not in ("generate", "rotate"):
        raise CandidateError("The operation must be generate or rotate.")
    for label, identifier in (("Team ID", team_id), ("Key ID", key_id)):
        if not re.fullmatch(r"[A-Z0-9]{10}", identifier):
            raise CandidateError(f"Apple {label} must contain exactly 10 uppercase letters or digits.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,254}", services_id):
        raise CandidateError("Services ID must be the exact registered Apple identifier, using letters, digits, periods or hyphens.")
    if type(lifetime_days) is not int or not 1 <= lifetime_days <= MAX_LIFETIME_DAYS:
        raise CandidateError("Lifetime must be an integer from 1 to 180 days.")
    issued_at = int(time.time()) if now is None else now
    if type(issued_at) is not int or issued_at <= 0:
        raise CandidateError("The current UTC timestamp must be a positive integer.")
    output = _absolute(output)
    receipt_path = output.with_name(output.name + ".receipt.json")
    parent = _open_private_directory(output.parent)
    try:
        _assert_absent(parent, output.name)
        _assert_absent(parent, receipt_path.name)
        private_key = _load_key(key_path)
        header = {"alg": "ES256", "kid": key_id}
        expires_at = issued_at + lifetime_days * 86400
        claims = {"iss": team_id, "iat": issued_at, "exp": expires_at, "aud": AUDIENCE, "sub": services_id}
        signing_input = (_encoded_json(header) + "." + _encoded_json(claims)).encode("ascii")
        der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        # Verify the JOSE raw signature after round-tripping its exact 64 bytes.
        try:
            private_key.public_key().verify(
                encode_dss_signature(int.from_bytes(raw_signature[:32], "big"), int.from_bytes(raw_signature[32:], "big")),
                signing_input,
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature:
            raise CandidateError("Generated signature verification failed; no output was published.") from None
        client_secret = signing_input.decode("ascii") + "." + _b64url(raw_signature)
        candidate = {"IAM_APPLE_CLIENT_ID": services_id, "IAM_APPLE_CLIENT_SECRET": client_secret}
        # For short test lifetimes, retain at least half the lifetime before rotation.
        rotation_lead_seconds = min(14 * 86400, lifetime_days * 86400 // 2)
        public_der = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        receipt = {
            "format_version": 1,
            "operation": operation,
            "header": header,
            "claims": claims,
            "lifetime_days": lifetime_days,
            "generated_at": _utc(issued_at),
            "expires_at": _utc(expires_at),
            "rotation_due_at": _utc(expires_at - rotation_lead_seconds),
            "public_key_sha256": hashlib.sha256(public_der).hexdigest(),
            "signature_verified": True,
            "runtime_configuration_changed": False,
        }
        payloads = [(output.name, candidate), (receipt_path.name, receipt)]
        _publish_pair(parent, [(name, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")) for name, data in payloads])
        return {"candidate_path": str(output), "receipt_path": str(receipt_path), "expires_at": receipt["expires_at"], "rotation_due_at": receipt["rotation_due_at"]}
    finally:
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("generate", "rotate"), help="Both modes prepare a fresh local candidate; neither changes live configuration.")
    parser.add_argument("--key", required=True, type=Path, help="Protected Apple .p8 signing key (read only).")
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--services-id", required=True)
    parser.add_argument("--lifetime-days", type=int, default=DEFAULT_LIFETIME_DAYS)
    parser.add_argument("--output", required=True, type=Path, help="New protected candidate JSON; an adjacent .receipt.json is also created.")
    args = parser.parse_args(argv)
    try:
        result = generate_candidate(key_path=args.key, team_id=args.team_id, key_id=args.key_id, services_id=args.services_id, output=args.output, lifetime_days=args.lifetime_days, operation=args.operation)
    except CandidateError as error:
        print(f"apple-client-secret: {error}", file=sys.stderr)
        return 1
    except OSError:
        # File-system exception details can include sensitive paths; keep CLI failures generic.
        print("apple-client-secret: File access failed; require private regular files, nonsymlink directories and fresh output names.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
