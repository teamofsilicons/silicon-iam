#!/usr/bin/env python3
"""Check actual ELF version requirements without host-specific binutils."""

import argparse
from pathlib import Path
import re
import struct


GLIBC_BASELINE = (2, 28)
SHT_GNU_VERNEED = 0x6FFFFFFE


def _unpack(layout: str, data: bytes, offset: int) -> tuple:
    if offset < 0 or offset + struct.calcsize(layout) > len(data):
        raise ValueError("truncated ELF version metadata")
    return struct.unpack_from(layout, data, offset)


def _string(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if offset < 0 or offset >= len(data) or end < 0:
        raise ValueError("invalid ELF version string")
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("non-ASCII ELF version string") from error


def required_glibc_versions(data: bytes) -> set[tuple[int, ...]]:
    """Read SHT_GNU_verneed, not incidental version-like binary strings.

    Release GNU/Linux executables must retain their dynamic version metadata.
    Missing, truncated or unknown GLIBC requirements fail closed.
    """
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a little-endian ELF64 executable")
    (table_offset,) = _unpack("<Q", data, 40)
    entry_size, count = _unpack("<HH", data, 58)
    if entry_size != 64 or count == 0:
        raise ValueError("missing or unsupported ELF section table")
    sections = [
        _unpack("<IIQQQQIIQQ", data, table_offset + index * entry_size)
        for index in range(count)
    ]

    def contents(section: tuple) -> bytes:
        offset, size = section[4:6]
        if offset + size > len(data):
            raise ValueError("truncated ELF section")
        return data[offset : offset + size]

    requirements = [section for section in sections if section[1] == SHT_GNU_VERNEED]
    if len(requirements) != 1:
        raise ValueError("expected one ELF dynamic version-requirement section")
    section = requirements[0]
    if section[6] >= len(sections) or sections[section[6]][1] != 3:
        raise ValueError("invalid ELF version string-table link")
    strings = contents(sections[section[6]])
    versions = contents(section)
    result = set()
    offset = 0
    records = 0
    while True:
        version, auxiliary_count, library, auxiliary, following = _unpack(
            "<HHIII", versions, offset
        )
        if version != 1 or auxiliary_count == 0 or auxiliary < 16:
            raise ValueError("invalid ELF version-requirement record")
        _string(strings, library)
        position = offset + auxiliary
        for index in range(auxiliary_count):
            _, _, _, name, next_auxiliary = _unpack("<IHHII", versions, position)
            requirement = _string(strings, name)
            if requirement.startswith("GLIBC_"):
                if not re.fullmatch(r"GLIBC_\d+(?:\.\d+)+", requirement):
                    raise ValueError(f"unsupported glibc requirement: {requirement}")
                result.add(tuple(map(int, requirement.removeprefix("GLIBC_").split("."))))
            if index + 1 < auxiliary_count:
                if next_auxiliary < 16:
                    raise ValueError("invalid ELF auxiliary version chain")
                position += next_auxiliary
            elif next_auxiliary != 0:
                raise ValueError("inconsistent ELF auxiliary version count")
        records += 1
        if following == 0:
            break
        if following < 16:
            raise ValueError("invalid ELF version-requirement chain")
        offset += following
    if records != section[7] or not result:
        raise ValueError("missing or inconsistent glibc version requirements")
    return result


def verify_glibc_requirements(data: bytes) -> tuple[int, ...]:
    required = max(required_glibc_versions(data))
    if required > GLIBC_BASELINE:
        version = ".".join(map(str, required))
        raise ValueError(f"requires GLIBC_{version}; supported maximum is GLIBC_2.28")
    return required


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executables", nargs="+", type=Path)
    args = parser.parse_args()
    for executable in args.executables:
        try:
            required = verify_glibc_requirements(executable.read_bytes())
        except ValueError as error:
            parser.exit(1, f"{executable}: {error}\n")
        print(f"{executable}: requires glibc {'.'.join(map(str, required))} (maximum 2.28)")


if __name__ == "__main__":
    main()
