#!/usr/bin/env python3
"""Regression tests for the release's Linux glibc compatibility gate."""

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

from check_linux_abi import required_glibc_versions, verify_glibc_requirements


def elf_requirements(versions, machine=183, extra=b""):
    """A small ELF with real GNU version-need records and linked string table."""
    strings = bytearray(b"\0libc.so.6\0")
    names = []
    for version in versions:
        names.append(len(strings))
        strings.extend(version.encode() + b"\0")
    needs = bytearray(struct.pack("<HHIII", 1, len(names), 1, 16, 0))
    for index, name in enumerate(names):
        needs.extend(struct.pack("<IHHII", 0, 0, index + 2, name,
                                 16 if index + 1 < len(names) else 0))
    strings_offset = 64
    needs_offset = strings_offset + len(strings)
    extra_offset = needs_offset + len(needs)
    table_offset = extra_offset + len(extra)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
        2, machine, 1, 0, 0, table_offset, 0, 64, 0, 0, 64, 4, 0,
    )
    sections = bytes(64)
    for kind, offset, size, link, info in [
        (3, strings_offset, len(strings), 0, 0),
        (0x6FFFFFFE, needs_offset, len(needs), 1, 1),
        (1, extra_offset, len(extra), 0, 0),
    ]:
        sections += struct.pack("<IIQQQQIIQQ", 0, kind, 0, 0, offset, size, link, info, 1, 0)
    return header + strings + needs + extra + sections


class LinuxAbiTests(unittest.TestCase):
    def test_accepts_release_baseline_and_compares_versions_numerically(self):
        data = elf_requirements(["GLIBC_2.9", "GLIBC_2.17", "GLIBC_2.28"])
        self.assertEqual(verify_glibc_requirements(data), (2, 28))

    def test_rejects_ubuntu_24_requirements_from_broken_release(self):
        for machine in [62, 183]:
            with self.subTest(machine=machine):
                data = elf_requirements(["GLIBC_2.28", "GLIBC_2.38", "GLIBC_2.39"], machine)
                with self.assertRaisesRegex(ValueError, "requires GLIBC_2.39"):
                    verify_glibc_requirements(data)

    def test_ignores_version_strings_outside_dynamic_requirements(self):
        data = elf_requirements(["GLIBC_2.28"], extra=b"GLIBC_9.99\0")
        self.assertEqual(required_glibc_versions(data), {(2, 28)})

    def test_rejects_unknown_glibc_abi_requirements(self):
        with self.assertRaisesRegex(ValueError, "unsupported glibc requirement"):
            verify_glibc_requirements(elf_requirements(["GLIBC_ABI_DT_RELR"]))

    def test_rejects_missing_truncated_and_invalid_metadata(self):
        data = elf_requirements(["GLIBC_2.28"])
        invalid_link = bytearray(data)
        table_offset = struct.unpack_from("<Q", data, 40)[0]
        struct.pack_into("<I", invalid_link, table_offset + 2 * 64 + 40, 99)
        missing_section = bytearray(data)
        struct.pack_into("<I", missing_section, table_offset + 2 * 64 + 4, 1)
        for bad in [b"", data[:63], data[:-1], bytes(invalid_link), bytes(missing_section)]:
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    verify_glibc_requirements(bad)



if __name__ == "__main__":
    unittest.main()
