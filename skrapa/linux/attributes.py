# -*- coding: utf-8 -*-

from enum import Enum
from typing import NamedTuple


class StrEnum(str, Enum):
    """Sortable and serializible string-based enum"""


class AccessProtectionType(StrEnum):
    PAGE_NOACCESS = "---p"
    PAGE_READONLY = "r--p"
    PAGE_WRITEONLY = "-w-p"
    PAGE_READWRITE = "rw-p"
    PAGE_EXECUTE = "--xp"
    PAGE_EXECUTE_READ = "r-xp"
    PAGE_EXECUTE_READWRITE = "rwxp"


class MemoryAttributes(NamedTuple):
    protect: AccessProtectionType = AccessProtectionType.PAGE_EXECUTE_READWRITE
