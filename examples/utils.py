# -*- coding: utf-8 -*-
# Common utilities for example scripts

import argparse
import logging
from enum import Enum
from typing import NamedTuple

from skrapa import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_OVERLAP_SIZE,
    PY_PLATFORM,
    AccessProtectionType,
    BytePattern,
    HexPattern,
    read_process_memory,
)
from skrapa.base import PatternType
from skrapa.exceptions import ReadProcessMemoryError

if PY_PLATFORM == "windows":
    from skrapa import AllocationType


logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S", level=logging.DEBUG
)


def member_names(attribute_enum: Enum) -> list[str]:
    return [attribute.name for attribute in attribute_enum]


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--protect",
        metavar="PROTECT",
        choices=member_names(AccessProtectionType),
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=(
            "chunk size to use for when reading memory "
            f"(default: {DEFAULT_CHUNK_SIZE} ({DEFAULT_CHUNK_SIZE // 1024 // 1024}MB))"
        ),
    )
    parser.add_argument(
        "--overlap-size",
        type=int,
        default=DEFAULT_OVERLAP_SIZE,
        help=(
            "number of bytes to account for overlap when chunk size is exceeded "
            f"(default: {DEFAULT_OVERLAP_SIZE} ({DEFAULT_OVERLAP_SIZE // 1024}MB))"
        ),
    )
    # Attributes for the Windows platform
    if PY_PLATFORM == "windows":
        parser.add_argument(
            "--alloc-protect",
            metavar="ALLOC_PROTECT",
            choices=member_names(AccessProtectionType),
        )
        parser.add_argument(
            "--type",
            metavar="TYPE",
            choices=member_names(AllocationType),
        )
        parser.add_argument(
            "--state",
            metavar="STATE",
            choices=member_names(AllocationType),
        )


def gather_patterns(args: argparse.Namespace) -> list[PatternType]:
    patterns = []

    patterns.extend(args.regex or [])
    patterns.extend(map(BytePattern, args.string or []))
    patterns.extend(map(HexPattern, args.hex or []))

    return patterns


def generate_description() -> str:
    enums = [("PROTECT", AccessProtectionType)]

    if PY_PLATFORM == "windows":
        enums.extend(
            [
                ("ALLOC_PROTECT", AccessProtectionType),
                ("TYPE", AllocationType),
                ("STATE", AllocationType),
            ]
        )

    description = []
    for metavar, enum_type in enums:
        description.append(f"{metavar} options:")
        for name in member_names(enum_type):
            description.append(f" - {name}")
        description.append("")

    return "\n".join(description)


def parse_hit(scanhit: NamedTuple) -> None:
    """Function to pretty print the scan result."""

    pid = scanhit.process.pid
    pname = scanhit.process.name
    ppath = scanhit.process.path
    parch = scanhit.process.architecture

    scan_match = scanhit.match

    region_start = hex(scanhit.region_start)
    region_size = hex(scanhit.region_size)
    region_end = hex(scanhit.region_start + scanhit.region_size)

    match_address = hex(scanhit.address)

    try:
        match_content = read_process_memory(pid, scanhit.address, 64)
    except ReadProcessMemoryError:
        # Process memory is volatile, page likely not accessible (anymore)
        logging.error(f"[pid: {pid}] Failed to read process memory at [{hex(scanhit.address)}]")
        match_content = None

    print(f"Process: {pname} [{pid}]")
    print(f"Architecture: {parch}")
    print(f"Path: {ppath}")
    print(f"Memory Info:\n\tregion:{region_start} - {region_end} [{region_size} bytes]")
    print(f"\taddress:{match_address} -> {scan_match}")
    print(f"\tcontent:{match_content}\n")
