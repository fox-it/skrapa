# -*- coding: utf-8 -*-

import re
from pathlib import Path
from typing import Iterable, Tuple

from skrapa.base import Architecture
from skrapa.exceptions import OpenProcessError
from skrapa.linux.attributes import AccessProtectionType, MemoryAttributes

ELFMAG = b"\x7fELF"
# EI_CLASS
ELFCLASSNONE = 0x00
ELFCLASS32 = 0x01
ELFCLASS64 = 0x02
ELFCLASSNUM = 0x03


PROPERTY_PATTERN = re.compile(r"([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([rwxp-]{4})")


def get_architecture(pid: int) -> str:
    """Get process architecture from specified PID."""

    pid_path = Path("/proc") / str(pid)
    if not pid_path.exists():
        raise OpenProcessError(f"Can't find PID in /proc: {pid}")

    try:
        with (pid_path / "exe").open("rb") as elf_file:
            elf_header = elf_file.read(16)

            if elf_header[:4] != ELFMAG:
                raise Exception("Invalid header magic")

            if elf_header[4] == ELFCLASS32:
                return Architecture.X86
            elif elf_header[4] == ELFCLASS64:
                return Architecture.AMD64
    except FileNotFoundError:
        # This can happen when the exe file is a symlink
        return None


def get_pid_maps(pid: int) -> Iterable[Tuple[int, int, MemoryAttributes]]:
    """Function to retrieve the memory maps of the specified PID."""

    pid_path = Path("/proc") / str(pid)
    if not pid_path.exists():
        raise OpenProcessError(f"Can't find PID in /proc: {pid}")

    try:
        with (pid_path / "maps").open("r") as maps:
            for line in maps:
                # It's technically not really an MBI but it's a nice name
                mem_properties = re.match(PROPERTY_PATTERN, line)

                if not mem_properties:
                    continue

                region_start = int(mem_properties.group(1), 16)

                # vsyscall address, unsure what it does or how to parse
                if region_start > 0xFFFFFFFFFFFF:
                    continue

                region_end = int(mem_properties.group(2), 16)

                mem_perms = MemoryAttributes(AccessProtectionType(mem_properties.group(3)))

                yield region_start, region_end, mem_perms
    except FileNotFoundError:
        raise OpenProcessError(f"Can't open maps file for PID {pid}")
