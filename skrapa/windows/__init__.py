# -*- coding: utf-8 -*-

from skrapa.base import PY_PLATFORM
from skrapa.windows.attributes import (
    AccessProtectionType,
    AllocationType,
    MemoryAttributes,
)

if PY_PLATFORM == "windows":
    from skrapa.windows.base import (
        VirtualMemoryStream,
        get_pids,
        get_process_info,
        get_processes,
        read_process_memory,
        scan_pid,
    )

__all__ = [
    "AccessProtectionType",
    "AllocationType",
    "MemoryAttributes",
    "VirtualMemoryStream",
    "get_pids",
    "get_process_info",
    "get_processes",
    "read_process_memory",
    "scan_pid",
]
