#!/usr/bin/env python3
"""Package explicitly staged IAM binaries into one Honeycomb v1 archive."""
import argparse
import gzip
import io
import json
from pathlib import Path
import re
import tarfile

TARGETS = (
    "linux-x86_64", "linux-aarch64", "windows-x86_64", "windows-aarch64",
    "macos-x86_64", "macos-aarch64",
)


def package(staging: Path, output: Path, app_id: str, version: str) -> None:
    if not re.fullmatch(r"[a-z0-9_-]+>[a-z0-9_-]+", app_id):
        raise ValueError("app-id must be a qualified org>app identifier")
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("version must be a stable semantic version, e.g. 1.9.1")
    manifest = {"format_version": 1, "app_id": app_id, "version": version,
                "bin": {"iam": "iam"}, "targets": {}}
    payloads = []
    for target in TARGETS:
        executable = "iam.exe" if target.startswith("windows-") else "iam"
        source = staging / target / executable
        if source.is_symlink() or source.parent.is_symlink() or not source.is_file():
            raise ValueError(f"missing regular binary: {source}")
        if source.stat().st_size == 0:
            raise ValueError(f"empty binary: {source}")
        root = f"targets/{target}"
        manifest["targets"][target] = {"root": root, "executables": {"iam": f"bin/{executable}"}}
        payloads.append((f"{root}/bin/{executable}", source.read_bytes(), 0o755))
        payloads.append((f"{root}/LICENSE", (Path(__file__).resolve().parents[1] / "LICENSE").read_bytes(), 0o644))
    # JSON is valid YAML; no YAML dependency or quoting ambiguities are needed.
    payloads.insert(0, ("honeycomb.yaml", (json.dumps(manifest, indent=2) + "\n").encode(), 0o644))
    # Enumerate only binaries and release metadata; never archive a workspace or home.
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as archive:
            for name, data, mode in payloads:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.mtime = len(data), mode, 0
                archive.addfile(entry, io.BytesIO(data))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", type=Path, required=True, help="Directory with <target>/iam[.exe] for all six targets")
    parser.add_argument("--output", type=Path, required=True, help="New .tar.gz path; existing files are never overwritten")
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        package(args.staging, args.output, args.app_id, args.version)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Cannot package IAM: {error}\n")
