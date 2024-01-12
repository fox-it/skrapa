# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from bisect import bisect_right
from pathlib import Path
from typing import Callable, Iterator, Union

from skrapa.base import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_OVERLAP_SIZE,
    PageInfo,
    Pattern,
    PatternType,
    ProcessInfo,
    SkrapaHit,
    VirtualStream,
    parse_patterns,
)
from skrapa.exceptions import OpenProcessError, ReadProcessMemoryError
from skrapa.linux.attributes import MemoryAttributes
from skrapa.linux.helpers import get_architecture, get_pid_maps


def get_process_info(pid: int) -> ProcessInfo:
    """Get process information from a specified PID."""

    pid_path = Path("/proc") / str(pid)
    if not pid_path.exists():
        raise OpenProcessError(f"Can't find PID in /proc: {pid}")

    try:
        filename = (pid_path / "comm").read_text().rstrip("\n")
    except FileNotFoundError:
        filename = None

    try:
        filepath = (pid_path / "exe").readlink()
    except FileNotFoundError:
        filepath = None

    architecture = get_architecture(pid)

    return ProcessInfo(
        pid=pid,
        name=filename,
        path=filepath,
        architecture=architecture,
    )


def get_processes() -> list[ProcessInfo]:
    """Get a list of all processes."""

    processes = []
    for pid in get_pids():
        try:
            processes.append(get_process_info(pid))
        except OpenProcessError:
            continue

    return processes


def get_pids(exclude_own: bool = True) -> list[int]:
    """Get a list of all pids.

    Args:
        exclude_own: Exclude own process ID when ``True``.

    Returns:
        A list containing the process IDs.
    """

    pids = []
    own_pid = os.getpid() if exclude_own else None

    for proc in Path("/proc").glob("[0-9]*"):
        pid = int(proc.name)
        if exclude_own and pid == own_pid:
            continue
        pids.append(pid)

    return pids


def scan_pid(
    pid: int,
    patterns: Union[PatternType, list[PatternType]],
    attributes: MemoryAttributes = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap_size: int = DEFAULT_OVERLAP_SIZE,
    page_filter: Callable[[PageInfo], bool] = None,
) -> Iterator[SkrapaHit]:
    """Scan the memory pages of each process.

    Parameters:
        pid: PID of the process to scan.
        patterns: Patterns to search for in memory.
        attributes: Limit scan to memory pages with these attributes.
        chunk_size: Search the memories in chunks of x size.
        overlap_size: Search for the pattern making use of an overlap of the previous read chunk.
        page_filter: A function that can be used to filter on page sizes.

    Returns:
        Iterator of :class:`skrapa.base.SkrapaHit` objects.
    """

    pid_path = Path("/proc") / str(pid)
    if not pid_path.exists():
        raise OpenProcessError(f"Can't find PID in /proc: {pid}")

    patterns: list[Pattern] = parse_patterns(patterns)

    process_info = get_process_info(pid)

    buffer = bytearray(chunk_size + overlap_size)
    buffer_view = memoryview(buffer)

    try:
        with (pid_path / "mem").open("rb") as mem:
            for region_start, region_end, mem_perms in get_pid_maps(pid):
                region_size = region_end - region_start

                if callable(page_filter):
                    if not page_filter(PageInfo(process=process_info, attributes=mem_perms, size=region_size)):
                        continue

                if (
                    attributes is not None
                    and attributes.protect is not None
                    and attributes.protect != mem_perms.protect
                ):
                    continue

                # Reset the overlap for each memory region so we don't have a poluted buffer
                current_overlap = 0
                current_offset = region_start

                while current_offset < region_end:
                    mem.seek(region_start)

                    # Read in chunks of 64M unless we have less
                    read_size = min(region_end - current_offset, chunk_size)

                    try:
                        mem.readinto(buffer_view[current_overlap : current_overlap + read_size])
                    except OSError:
                        # This can happen in the higher memory ranges
                        break

                    for pattern in patterns:
                        for pmatch in pattern.match(buffer_view[: current_overlap + read_size]):
                            yield SkrapaHit(
                                process=process_info,
                                attributes=mem_perms,
                                name=pmatch.name,
                                pattern=pmatch.pattern,
                                match=pmatch.match,
                                region_start=current_offset,
                                region_size=region_size,
                                address=current_offset + pmatch.offset - current_overlap,
                            )

                    # Store 64K of memory overlap
                    current_overlap = min(read_size, overlap_size)
                    buffer_view[:current_overlap] = buffer_view[max(0, read_size - current_overlap) : read_size]

                    current_offset += read_size

    except IOError:
        raise ReadProcessMemoryError(f"Can't open mem file for PID {pid}")


def read_process_memory(pid: int, address: int, size: int) -> bytes:
    """Function to read the process memory and return the contents if successful.

    Args:
        pid: PID of the process memory to read the contents of.
        address: Memory address to start reading from.
        size: Amount of bytes to read from the address.

    Returns:
        Buffer of the bytes read if the read was successful.
    """

    pid_path = Path("/proc") / str(pid)
    if not pid_path.exists():
        raise OpenProcessError(f"Can't find PID in /proc: {pid}")

    try:
        with (pid_path / "mem").open("rb") as mem:
            mem.seek(address)

            try:
                return mem.read(size)
            except OSError as e:
                raise ReadProcessMemoryError(f"Failed to read memory for PID {pid}: {e}")

    except FileNotFoundError:
        raise ReadProcessMemoryError(f"Can't open mem file for PID {pid}")


class VirtualMemoryStream(VirtualStream):
    def __init__(self, pid: int):
        super().__init__()

        pid_path = Path("/proc") / str(pid)
        if not pid_path.exists():
            raise OpenProcessError(f"Can't find PID in /proc: {pid}")

        self.pid = pid
        self.maps = [None] + list(get_pid_maps(pid))
        self._lookup = [mbi[0] for mbi in self.maps if mbi]
        self._fh = (pid_path / "mem").open("rb")

    def readinto(self, b: bytearray) -> int:
        view = memoryview(b)
        length = len(b)

        total_read = 0
        map_idx = bisect_right(self._lookup, self._pos)
        while length > 0:
            mbi = self.maps[map_idx]

            next_mbi = None
            if map_idx + 1 < len(self.maps):
                next_mbi = self.maps[map_idx + 1]

            if mbi is None or self._pos >= mbi[1]:
                # Out of bounds of this region
                if next_mbi is None:
                    break

                next_region_start, _, _ = next_mbi
                gap_to_next_region = next_region_start - self._pos
                if gap_to_next_region < 0:
                    break

                map_idx += 1
                self._pos += gap_to_next_region
                length -= gap_to_next_region
                continue

            region_start, region_end, _ = mbi

            region_size = region_end - region_start
            offset_in_region = self._pos - region_start
            remaining_in_region = region_size - offset_in_region

            read_size = min(length, remaining_in_region)
            self._fh.seek(self._pos)
            try:
                self._fh.readinto(view[:read_size])
            except OSError:
                # Dunno, ignore?
                continue
            finally:
                view = view[read_size:]

                map_idx += 1
                total_read += read_size
                self._pos += read_size
                length -= read_size

        return total_read

    def close(self) -> None:
        self._fh.close()
        super().close()
