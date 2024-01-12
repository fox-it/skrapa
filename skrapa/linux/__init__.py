# -*- coding: utf-8 -*-

from skrapa.base import PY_PLATFORM
from skrapa.linux.attributes import AccessProtectionType, MemoryAttributes

if PY_PLATFORM == "linux":
    from skrapa.linux.base import (
        VirtualMemoryStream,
        get_pids,
        get_process_info,
        get_processes,
        read_process_memory,
        scan_pid,
    )

__all__ = [
    "AccessProtectionType",
    "MemoryAttributes",
    "VirtualMemoryStream",
    "get_pids",
    "get_process_info",
    "get_processes",
    "read_process_memory",
    "scan_pid",
]
