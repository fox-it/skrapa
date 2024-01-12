# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Callable, Iterator, Union

from skrapa.base import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_OVERLAP_SIZE,
    PY_ARCH,
    PY_PLATFORM,
    Architecture,
    BytePattern,
    HexPattern,
    PageInfo,
    PatternType,
    PointerPattern,
    ProcessInfo,
    RegexPattern,
    SkrapaHit,
)
from skrapa.exceptions import OpenProcessError

if PY_PLATFORM == "windows":
    from skrapa.windows import AllocationType  # noqa
    from skrapa.windows import (
        AccessProtectionType,
        MemoryAttributes,
        VirtualMemoryStream,
        get_pids,
        get_process_info,
        get_processes,
        read_process_memory,
        scan_pid,
    )

    def casefold(s):
        return s.casefold()

    __extra__ = ["AllocationType"]
elif PY_PLATFORM == "linux":
    from skrapa.linux import (
        AccessProtectionType,
        MemoryAttributes,
        VirtualMemoryStream,
        get_pids,
        get_process_info,
        get_processes,
        read_process_memory,
        scan_pid,
    )

    def casefold(s):
        return s

    __extra__ = []


def scan_all(
    patterns: Union[PatternType, list[PatternType]],
    attributes: MemoryAttributes = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap_size: int = DEFAULT_OVERLAP_SIZE,
    page_filter: Callable[[PageInfo], bool] = None,
) -> Iterator[SkrapaHit]:
    """Scan process memory of all processes with the specified pattern.

    Args:
        patterns: Patterns to search for in memory.
        attributes: Limit scan to memory pages with these attributes.
        chunk_size: Search the memories in chunks of x size.
        overlap_size: Search for the pattern making use of an overlap of the previous read chunk.
        page_filter: A user-defined function that can be used as a conditional match on the page.

    Returns:
        Iterator of :class:`skrapa.base.SkrapaHit` objects.
    """

    for pid in get_pids():
        try:
            yield from scan_pid(pid, patterns, attributes, chunk_size, overlap_size, page_filter)
        except OpenProcessError:
            # Allow silent failing when scanning all processes
            continue


def scan_process(
    process: ProcessInfo,
    patterns: Union[PatternType, list[PatternType]],
    attributes: MemoryAttributes = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap_size: int = DEFAULT_OVERLAP_SIZE,
    page_filter: Callable[[PageInfo], bool] = None,
) -> Iterator[SkrapaHit]:
    """Scan the process memory of the process with the specified pattern.

    Parameters:
        process: Process info of the process to scan.
        patterns: Pattern to search for in memory.
        attributes: Limit scan to memory pages with these attributes.
        chunk_size: Search the memories in chunks of x size.
        overlap_size: Search for the pattern making use of an overlap of the previous read chunk.
        page_filter: A user-defined function that can be used as a conditional match on the page.

    Returns:
        Iterator of :class:`skrapa.base.SkrapaHit` objects.
    """

    yield from scan_pid(process.pid, patterns, attributes, chunk_size, overlap_size, page_filter)


def scan_process_name(
    name: str,
    patterns: Union[PatternType, list[PatternType]],
    attributes: MemoryAttributes = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap_size: int = DEFAULT_OVERLAP_SIZE,
    page_filter: Callable[[PageInfo], bool] = None,
) -> Iterator[SkrapaHit]:
    """Scan the process memory of the process name with the specified pattern.

    Parameters:
        name: Process name of the process to scan.
        patterns: Pattern to search for in memory.
        attributes: Limit scan to memory pages with these attributes.
        chunk_size: Search the memories in chunks of x size.
        overlap_size: Search for the pattern making use of an overlap of the previous read chunk.
        page_filter: A user-defined function that can be used as a conditional match on the page.

    Returns:
        Iterator of :class:`skrapa.base.SkrapaHit` objects.
    """

    found = False
    for process in get_processes():
        if casefold(process.name) == casefold(name):
            found = True
            yield from scan_pid(process.pid, patterns, attributes, chunk_size, overlap_size, page_filter)

    if not found:
        raise ValueError(f"Unknown process name: {name}")


__all__ = __extra__ + [
    "PY_ARCH",
    "PY_PLATFORM",
    "Architecture",
    "AccessProtectionType",
    "MemoryAttributes",
    "VirtualMemoryStream",
    "get_pids",
    "get_processes",
    "get_process_info",
    "read_process_memory",
    "scan",
    "scan_pid",
    "scan_process",
    "RegexPattern",
    "HexPattern",
    "BytePattern",
    "PointerPattern",
]
