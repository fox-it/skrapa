# -*- coding: utf-8 -*-

from enum import IntEnum
from typing import NamedTuple


class AccessProtectionType(IntEnum):
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400
    SEC_FILE = 0x800000
    SEC_IMAGE = 0x1000000
    SEC_VLM = 0x2000000
    SEC_RESERVE = 0x4000000
    SEC_COMMIT = 0x8000000
    SEC_NOCACHE = 0x10000000


class AllocationType(IntEnum):
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_DECOMMIT = 0x4000
    MEM_RELEASE = 0x8000
    MEM_FREE = 0x10000
    MEM_PRIVATE = 0x20000
    MEM_MAPPED = 0x40000
    MEM_RESET = 0x80000
    MEM_TOP_DOWN = 0x100000
    MEM_IMAGE = 0x1000000
    MEM_4MB_PAGES = 0x80000000


class MemoryAttributes(NamedTuple):
    protect: AccessProtectionType = AccessProtectionType.PAGE_EXECUTE_READWRITE
    allocation_protect: AccessProtectionType = AccessProtectionType.PAGE_EXECUTE_READWRITE
    type: AllocationType = AllocationType.MEM_PRIVATE
    state: AllocationType = AllocationType.MEM_COMMIT
