#!/usr/bin/env python3
"""Verify a release executable's platform, native version, and source receipt."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

TARGETS = {
    "linux-x86_64": ("elf", 62),
    "linux-aarch64": ("elf", 183),
    "windows-x86_64": ("pe", 0x8664),
    "windows-aarch64": ("pe", 0xAA64),
    "macos-x86_64": ("macho", 0x01000007),
    "macos-aarch64": ("macho", 0x0100000C),
}


def verify_header(data: bytes, target: str) -> None:
    kind, machine = TARGETS[target]
    valid = False
    if kind == "elf":
        valid = (len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01"
                 and struct.unpack_from("<H", data, 18)[0] == machine)
    elif kind == "macho":
        valid = (len(data) >= 32 and data[:4] == b"\xcf\xfa\xed\xfe"
                 and struct.unpack_from("<I", data, 4)[0] == machine)
    elif len(data) >= 64 and data[:2] == b"MZ":
        offset = struct.unpack_from("<I", data, 60)[0]
        valid = (offset + 26 <= len(data) and data[offset:offset + 4] == b"PE\0\0"
                 and struct.unpack_from("<H", data, offset + 4)[0] == machine
                 and struct.unpack_from("<H", data, offset + 24)[0] == 0x20B)
    if not valid:
        raise ValueError(f"executable header does not match {target}")


def verify(binary: Path, target: str, revision: str, version: str, native: bool) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source revision must be a full lowercase commit SHA")
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("CLI version must be a stable semantic version")
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("executable must be a regular file")
    data = binary.read_bytes()
    verify_header(data, target)
    if target.startswith("linux-"):
        import importlib.util
        spec = importlib.util.spec_from_file_location("linux_abi", Path(__file__).with_name("check_linux_abi.py"))
        abi = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(abi)
        abi.verify_glibc_requirements(data)
    receipt = {
        "target": target, "source_revision": revision, "version": version,
        "file": binary.name, "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "native_version_verified": True,
    }
    if native:
        result = subprocess.run([str(binary.resolve()), "--version"], check=True,
                                capture_output=True, text=True, timeout=30)
        if result.stdout.strip() != f"iam {version}":
            raise ValueError("native executable reports an unexpected version")
    else:
        recorded = json.loads(binary.with_name("provenance.json").read_text())
        if recorded != receipt:
            raise ValueError("artifact differs from its native build receipt")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--native", action="store_true")
    args = parser.parse_args()
    receipt = verify(args.binary, args.target, args.revision, args.version, args.native)
    if args.native:
        args.binary.with_name("provenance.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Verified {args.target}: {receipt['sha256']}")
