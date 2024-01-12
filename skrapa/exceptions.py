# -*- coding: utf-8 -*-

# Module specific exceptions


class Error(Exception):
    pass


class ArchError(Error):
    pass


class OpenProcessError(Error):
    pass


class LookupPrivilegeError(Error):
    pass


class AdjustTokenPrivilegesError(Error):
    pass


class TokenPrivilegeError(Error):
    pass


class EnumProcessesError(Error):
    pass


class GetProcessImageFileNameError(Error):
    pass


class ReadProcessMemoryError(Error):
    pass
