# -*- coding: utf-8 -*-
from __future__ import annotations

import ctypes
import ntpath
import os
from typing import Callable, Iterator, Union

from skrapa.base import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_OVERLAP_SIZE,
    PY_ARCH,
    Architecture,
    PageInfo,
    PatternType,
    ProcessInfo,
    SkrapaHit,
    VirtualStream,
    parse_patterns,
)
from skrapa.exceptions import (
    EnumProcessesError,
    GetProcessImageFileNameError,
    OpenProcessError,
    ReadProcessMemoryError,
)
from skrapa.windows.attributes import AllocationType, MemoryAttributes
from skrapa.windows.helpers import (
    MEMORY_BASIC_INFORMATION,
    ErrorCode,
    get_process_architecture,
    get_process_file_name,
    open_process,
    raw_read_process_memory,
    se_debug,
    system_info,
)

# Necessary DLL's
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi


def get_process_info(pid: int) -> ProcessInfo:
    """Get process information from a specified PID."""

    hProcess = open_process(pid)

    try:
        path = get_process_file_name(hProcess)
    except GetProcessImageFileNameError:
        path = None

    name = ntpath.basename(path) if path else None
    architecture = get_process_architecture(hProcess)

    kernel32.CloseHandle(hProcess)

    return ProcessInfo(
        pid=pid,
        name=name,
        path=path,
        architecture=architecture,
    )


def get_processes() -> list[ProcessInfo]:
    """Get a list of all processes."""

    processes = []
    for pid in get_pids():
        try:
            processes.append(get_process_info(pid))
        except (OpenProcessError, GetProcessImageFileNameError):
            continue

    return processes


def get_pids(exclude_own: bool = True) -> list[int]:
    """Get a list of all pids.

    Args:
        exclude_own: Exclude own process ID when `True`.

    Returns:
        A list containing the process IDs.
    """

    pids = []
    count = 32
    bytes_returned = 0
    own_pid = os.getpid() if exclude_own else None

    # Enumerate the running processes
    while True:
        cpids = (ctypes.c_ulong * count)()
        cb = ctypes.sizeof(cpids)
        bytes_returned = ctypes.c_ulong()

        if psapi.EnumProcesses(
            ctypes.byref(cpids),
            cb,
            ctypes.byref(bytes_returned),
        ):
            if bytes_returned.value < cb:
                break
            else:
                count *= 2
        else:
            raise EnumProcessesError("Call to EnumProcesses failed")

    for pid in cpids[: bytes_returned.value // ctypes.sizeof(ctypes.c_ulong)]:
        if exclude_own and pid == own_pid:
            continue
        pids.append(pid)

    return pids


@se_debug
def scan_pid(
    pid: int,
    patterns: Union[PatternType, list[PatternType]],
    attributes: MemoryAttributes = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap_size: int = DEFAULT_OVERLAP_SIZE,
    page_filter: Callable[[PageInfo], bool] = None,
) -> Iterator[SkrapaHit]:
    """Scan the process memory of the given PID with the specified pattern.

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

    patterns = parse_patterns(patterns)

    # Obtain a handle to the process we want to scan
    hProcess = open_process(pid)

    process_info = get_process_info(pid)

    base_address = 0
    max_address = system_info.max_address
    # Dirty hack but don't know how to properly fix this
    # Scanning 32bit processes on 64bit will eventually cause an overflow on the address
    # Which returns weird values for VirtualQueryEx
    if (PY_ARCH, process_info.architecture) == (Architecture.AMD64, Architecture.X86):
        max_address = 0xFFFFFFFF

    # Loop over the memory pages of each process and only read the process
    # memory if the memory attributes are matching, or if the scan_all is set.
    mbi = MEMORY_BASIC_INFORMATION()

    buffer = bytearray(chunk_size + overlap_size)
    buffer_view = memoryview(buffer)

    while base_address < max_address:
        status = kernel32.VirtualQueryEx(
            hProcess,
            base_address,
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )

        # Break if we can't obtain information using VirtualQueryEx
        if status == 0:
            break

        # Use the region size that was determined with VirtualQueryEx
        region_size = mbi.RegionSize
        region_end = base_address + region_size

        # Error encountered with PAGE_GUARD (ERROR_INVALID_PARAMETER)
        # Skip regions with memory that was already freed (MEM_FREE state)
        # Skip regions with memory that was only set to reserved (MEM_RESERVE state)
        if status == ErrorCode.ERROR_INVALID_PARAMETER or mbi.State in (
            AllocationType.MEM_FREE,
            AllocationType.MEM_RESERVE,
        ):
            base_address += region_size
            continue

        mbi_attributes = MemoryAttributes(mbi.Protect, mbi.AllocationProtect, mbi.Type, mbi.State)

        if callable(page_filter):
            if not page_filter(PageInfo(process=process_info, attributes=mbi_attributes, size=region_size)):
                base_address += region_size
                continue

        if attributes is not None and not all(x is None or x == y for x, y in zip(attributes, mbi_attributes)):
            base_address += region_size
            continue

        # Reset the overlap for each memory region so we don't have a poluted buffer
        current_overlap = 0

        while base_address < region_end:
            read_size = min(region_end - base_address, chunk_size)
            try:
                raw_read_process_memory(
                    hProcess, base_address, buffer_view[current_overlap : current_overlap + read_size]
                )
            except ReadProcessMemoryError:
                base_address += read_size
                continue

            for pattern in patterns:
                for pmatch in pattern.match(buffer_view[: current_overlap + read_size]):
                    yield SkrapaHit(
                        process=process_info,
                        attributes=mbi_attributes,
                        name=pmatch.name,
                        pattern=pmatch.pattern,
                        match=pmatch.match,
                        region_start=base_address,
                        region_size=region_size,
                        address=base_address + pmatch.offset - current_overlap,
                    )

            # Store memory overlap
            current_overlap = min(read_size, overlap_size)
            buffer_view[:current_overlap] = buffer_view[max(0, read_size - current_overlap) : read_size]

            base_address += read_size

    kernel32.CloseHandle(hProcess)


@se_debug
def read_process_memory(pid: int, address: int, size: int) -> bytes:
    """Function to read the process memory and return the contents if successful.

    Args:
        pid: PID of the process memory to read the contents of.
        address: Memory address to start reading from.
        size: Amount of bytes to read from the address.

    Returns:
        Buffer of the bytes read if the read was successful.
    """

    # Obtain a handle to the process we want to read from
    hProcess = open_process(pid)

    buffer = bytearray(size)
    raw_read_process_memory(hProcess, address, buffer)

    kernel32.CloseHandle(hProcess)
    return bytes(buffer)


class VirtualMemoryStream(VirtualStream):
    @se_debug
    def __init__(self, pid: int):
        super().__init__()

        self.pid = pid
        self._hProcess = open_process(pid)

    def readinto(self, b):
        view = memoryview(b)
        length = len(b)

        total_read = 0

        while length > 0:
            mbi = MEMORY_BASIC_INFORMATION()
            status = kernel32.VirtualQueryEx(
                self._hProcess,
                self._pos,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )

            if status == ErrorCode.ERROR_INVALID_PARAMETER:
                raise ReadProcessMemoryError("PAGE_GUARD (ERROR_INVALID_PARAMETER)")

            region_size = mbi.RegionSize
            base_address = mbi.BaseAddress
            offset_in_region = self._pos - base_address
            remaining_in_region = region_size - offset_in_region

            read_size = min(length, remaining_in_region)
            try:
                raw_read_process_memory(self._hProcess, self._pos, view[:read_size])
                view = view[read_size:]
            except ReadProcessMemoryError:
                break

            total_read += read_size
            self._pos += read_size
            length -= read_size

        return total_read

    def close(self):
        kernel32.CloseHandle(self._hProcess)
        super().close()
