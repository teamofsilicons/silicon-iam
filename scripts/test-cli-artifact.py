#!/usr/bin/env python3
"""Reject wrong architectures, altered bytes, and mismatched release receipts."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("verify", Path(__file__).with_name("verify-cli-artifact.py"))
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def fixture(target):
    kind, machine = VERIFY.TARGETS[target]
    data = bytearray(128)
    if kind == "elf":
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18, machine)
    elif kind == "macho":
        data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", data, 4, machine)
    else:
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"PE\0\0"
        struct.pack_into("<H", data, 68, machine)
        struct.pack_into("<H", data, 88, 0x20B)
    return bytes(data)


class ArtifactTests(unittest.TestCase):
    def test_all_six_headers_require_exact_platform(self):
        for target in VERIFY.TARGETS:
            VERIFY.verify_header(fixture(target), target)
            for wrong in VERIFY.TARGETS:
                if target != wrong:
                    with self.assertRaises(ValueError):
                        VERIFY.verify_header(fixture(target), wrong)

    def test_empty_truncated_and_malformed_headers_rejected(self):
        for target in VERIFY.TARGETS:
            for data in (b"", b"not an executable", fixture(target)[:20]):
                with self.assertRaises(ValueError):
                    VERIFY.verify_header(data, target)

    def test_receipt_is_bound_to_bytes_source_version_and_native_check(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "iam"
            data = fixture("linux-x86_64")
            binary.write_bytes(data)
            receipt = {"target": "linux-x86_64", "source_revision": "a" * 40,
                       "version": "1.11.0", "file": "iam", "size": len(data),
                       "sha256": hashlib.sha256(data).hexdigest(), "native_version_verified": True}
            path = binary.with_name("provenance.json")
            path.write_text(json.dumps(receipt))
            self.assertEqual(VERIFY.verify(binary, "linux-x86_64", "a" * 40, "1.11.0", False), receipt)
            for field, value in (("source_revision", "b" * 40), ("version", "1.10.0"),
                                 ("native_version_verified", False)):
                path.write_text(json.dumps({**receipt, field: value}))
                with self.assertRaises(ValueError):
                    VERIFY.verify(binary, "linux-x86_64", "a" * 40, "1.11.0", False)
            path.write_text(json.dumps(receipt))
            binary.write_bytes(data + b"tampered")
            with self.assertRaises(ValueError):
                VERIFY.verify(binary, "linux-x86_64", "a" * 40, "1.11.0", False)


if __name__ == "__main__":
    unittest.main()
