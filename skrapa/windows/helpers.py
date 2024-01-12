# -*- coding: utf-8 -*-

import ctypes
from enum import IntEnum
from functools import wraps

from skrapa.base import PY_ARCH, Architecture
from skrapa.exceptions import (
    AdjustTokenPrivilegesError,
    ArchError,
    GetProcessImageFileNameError,
    LookupPrivilegeError,
    OpenProcessError,
    ReadProcessMemoryError,
    TokenPrivilegeError,
)

LPVOID = ctypes.c_void_p
LPCVOID = ctypes.c_void_p
HANDLE = ctypes.c_size_t
PHANDLE = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
QWORD = ctypes.c_ulonglong
DWORD = ctypes.c_ulong
WORD = ctypes.c_ushort
BOOL = ctypes.c_ulong
PBOOL = ctypes.POINTER(ctypes.c_long)


class ErrorCode(IntEnum):
    ERROR_SUCCESS = 0x0
    ERROR_ACCESS_DENIED = 0x5
    ERROR_INVALID_PARAMETER = 0x57
    ERROR_PARTIAL_COPY = 0x12B
    ERROR_NOT_ALL_ASSIGNED = 0x514


class ProcessToken(IntEnum):
    TOKEN_QUERY = 0x0008
    TOKEN_ADJUST_PRIVILEGES = 0x0020


class ProcessAccess(IntEnum):
    PROCESS_TERMINATE = 0x0001
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_DUP_HANDLE = 0x0040
    PROCESS_CREATE_PROCESS = 0x0080
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_QUERY_INFORMATION = 0x0400
    SYNCHRONIZE = 0x00100000
    PROCESS_ALL_ACCESS = 0x1F0FFF


# Define ctypes.Structure for MEMORY_BASIC_INFORMATION as per MSDN:
# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", DWORD),
        ("AllocationBase", DWORD),
        ("AllocationProtect", DWORD),
        ("RegionSize", DWORD),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", QWORD),
        ("AllocationBase", QWORD),
        ("AllocationProtect", DWORD),
        ("__alignment1", DWORD),
        ("RegionSize", QWORD),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
        ("__alignment2", DWORD),
    ]


# Define ctypes.Structure for SYSTEMINFO as per MSDN:
# https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
class SYSTEM_INFO(ctypes.Structure):
    class _U(ctypes.Union):
        class _S(ctypes.Structure):
            _fields_ = (
                ("wProcessorArchitecture", WORD),
                ("wReserved", WORD),
            )

        _fields_ = (
            ("dwOemId", WORD),
            ("_s", _S),
        )

        _anonymous_ = ("_s",)

    _fields_ = (
        ("_u", _U),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", LPVOID),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    )

    _anonymous_ = ("_u",)


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", DWORD),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", 1 * LUID_AND_ATTRIBUTES),
    ]


if PY_ARCH == Architecture.AMD64:
    MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION64
elif PY_ARCH == Architecture.X86:
    MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION32


# Necessary DLL's
advapi32 = ctypes.windll.advapi32
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi


# GetSystemInfo API
# LPSYSTEM_INFO needs to point to the SYSTEM_INFO struct
LPSYSTEM_INFO = ctypes.POINTER(SYSTEM_INFO)


# Define the expected argument types
kernel32.GetSystemInfo.argtypes = (LPSYSTEM_INFO,)
kernel32.IsWow64Process.argtypes = [HANDLE, PBOOL]
advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
kernel32.ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
kernel32.VirtualQueryEx.argtypes = [HANDLE, LPCVOID, LPVOID, SIZE_T]


# Define some of the expected return types
kernel32.GetSystemInfo.restype = None
kernel32.OpenProcess.restype = HANDLE
psapi.EnumProcesses.restype = SIZE_T
psapi.GetProcessImageFileNameA.restype = SIZE_T


MAX_PATH = 260


class _SystemInfo:
    __slots__ = "system_info"

    def __init__(self):
        # Retrieve the system information
        self.system_info = SYSTEM_INFO()

        kernel32.GetSystemInfo(ctypes.byref(self.system_info))

    @property
    def processor_architecture(self):
        arch_map = {0: Architecture.X86, 9: Architecture.AMD64}

        arch = arch_map.get(self.system_info.wProcessorArchitecture, None)
        if arch is None:
            raise ArchError("Unknown system architecture")

        return arch

    @property
    def base_address(self):
        # Get the first address of the first page
        return self.system_info.lpMinimumApplicationAddress

    @property
    def max_address(self):
        # Get the last address to scan so we know when to stop scanning
        return self.system_info.lpMaximumApplicationAddress


system_info = _SystemInfo()


def se_debug(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        if not hasattr(set_debug_privilege, "__has_priv__"):
            set_debug_privilege()
            setattr(set_debug_privilege, "__has_priv__", 1)
        return func(*args, **kwargs)

    return decorator


def set_debug_privilege():
    """Set the SeDebugPrivilege for the current process."""

    kernel32.SetLastError(0)

    hToken = LPVOID()
    hCurrentProcess = kernel32.GetCurrentProcess()

    status = advapi32.OpenProcessToken(
        hCurrentProcess,
        ProcessToken.TOKEN_ADJUST_PRIVILEGES | ProcessToken.TOKEN_QUERY,
        ctypes.byref(hToken),
    )

    if status == 0:
        raise OpenProcessError(f"OpenProcessToken Error: 0x{kernel32.GetLastError():x}")

    tp = TOKEN_PRIVILEGES()
    luid = LUID()
    bEnablePrivilege = 0x00000002

    result = advapi32.LookupPrivilegeValueW(
        None,
        "SeDebugPrivilege",
        ctypes.byref(luid),
    )

    if not result:
        raise LookupPrivilegeError(f"LookupPrivilegeValue error: 0x{kernel32.GetLastError():x}")

    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = bEnablePrivilege

    result = advapi32.AdjustTokenPrivileges(
        hToken,
        False,
        ctypes.byref(tp),
        ctypes.sizeof(TOKEN_PRIVILEGES),
        None,
        None,
    )

    if not result:
        raise AdjustTokenPrivilegesError(f"AdjustTokenPrivileges error: 0x{kernel32.GetLastError():x}")

    if kernel32.GetLastError() == ErrorCode.ERROR_NOT_ALL_ASSIGNED:
        raise TokenPrivilegeError("Failed to set debug privilege: the token does not have the specified privilege!")


@se_debug
def open_process(pid: int) -> int:
    """Obtain a handle for the given PID."""

    kernel32.SetLastError(0)

    hProcess = kernel32.OpenProcess(
        ProcessAccess.PROCESS_ALL_ACCESS | ProcessAccess.PROCESS_QUERY_INFORMATION,
        False,
        pid,
    )

    # Skip some processes we can't get valid handles on
    # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

    # ERROR_INVALID_PARAMETER -> System Idle Process
    if kernel32.GetLastError() == ErrorCode.ERROR_INVALID_PARAMETER:
        raise OpenProcessError(f"OpenProcess ERROR_INVALID_PARAMETER, likely tried opening System Process [pid: {pid}]")

    # ERROR_ACCESS_DENIED -> Likely CSRSS Process
    if kernel32.GetLastError() == ErrorCode.ERROR_ACCESS_DENIED:
        raise OpenProcessError(f"OpenProcess ERROR_ACCES_DENIED, likely tried opening CSRSS process [pid: {pid}]")

    # No valid handle could be obtained, display the error code
    if hProcess == 0:
        raise OpenProcessError(f"OpenProcess Error: 0x{kernel32.GetLastError():x} [pid: {pid}]")

    return hProcess


def get_process_file_name(hProcess: int) -> str:
    """Retrieve the filename by using the length to cut off the full directory."""

    kernel32.SetLastError(0)

    filename = (ctypes.c_char * MAX_PATH)()
    process_name_length = psapi.GetProcessImageFileNameA(
        hProcess,
        filename,
        MAX_PATH,
    )

    if process_name_length == 0:
        raise GetProcessImageFileNameError(f"GetProcessImageFileName Error: 0x{kernel32.GetLastError():x}")

    return filename[:process_name_length].decode("utf-8")


def get_process_architecture(hProcess: int) -> Architecture:
    """Retrieve the architecture of the process."""

    if system_info.processor_architecture == Architecture.AMD64:
        # Check if the process is 32bit or 64bit
        # IsWow64Process if the system is a 64bit system,
        # it's an x86 process otherwise
        isWOW64 = ctypes.c_long()

        kernel32.IsWow64Process(
            hProcess,
            ctypes.byref(isWOW64),
        )

        return Architecture.X86 if isWOW64.value else Architecture.AMD64

    elif system_info.processor_architecture == Architecture.X86:
        return Architecture.X86


def raw_read_process_memory(hProcess: int, address: int, buffer: bytearray) -> bytes:
    """Helper function for reading process memory. Assumes debug privileges."""

    kernel32.SetLastError(0)

    buffer_size = len(buffer)
    cbuffer = (ctypes.c_char * buffer_size).from_buffer(buffer)
    bytes_read = SIZE_T(0)

    status = kernel32.ReadProcessMemory(
        hProcess,
        address,
        cbuffer,
        buffer_size,
        ctypes.byref(bytes_read),
    )

    if status != 0:
        return bytes_read.value
    else:
        raise ReadProcessMemoryError(f"ReadProcessMemory Error: 0x{kernel32.GetLastError():x}")
