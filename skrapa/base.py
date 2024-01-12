# -*- coding: utf-8 -*-
from __future__ import annotations

import ctypes
import io
import platform
import re
import struct
from enum import Enum, auto
from typing import TYPE_CHECKING, Iterator, NamedTuple, Optional, Union

if TYPE_CHECKING:
    from skrapa.linux import MemoryAttributes as LinuxMemoryAttributes
    from skrapa.windows import MemoryAttributes as WindowsMemoryAttributes


try:
    import yara

    HAS_YARA = True
except ImportError:
    HAS_YARA = False


class Architecture(Enum):
    X86 = auto()
    AMD64 = auto()


PY_PLATFORM = platform.system().lower()
if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
    PY_ARCH = Architecture.AMD64
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
    PY_ARCH = Architecture.X86


DEFAULT_CHUNK_SIZE = 1 * 1024 * 1024
DEFAULT_OVERLAP_SIZE = 8 * 1024


PatternStr = Union[str, bytes]
PatternType = Union[PatternStr, "Pattern"]


class ProcessInfo(NamedTuple):
    pid: int
    name: str
    path: str
    architecture: Architecture


class SkrapaHit(NamedTuple):
    process: ProcessInfo
    attributes: Union[LinuxMemoryAttributes, WindowsMemoryAttributes]
    name: str
    pattern: Pattern
    match: Union[re.Match, bytes]
    region_start: int
    region_size: int
    address: int


class PatternMatch(NamedTuple):
    """Match result from a Pattern."""

    offset: int
    pattern: Pattern
    match: Union[re.Match, bytes]
    name: str


class PageInfo(NamedTuple):
    """Memory Page or Map attributes used in `page_filter` callback."""

    process: ProcessInfo
    attributes: Union[LinuxMemoryAttributes, WindowsMemoryAttributes]
    size: int


class Pattern:
    """Base class for patterns.

    Args:
        name: Optional pattern name.
    """

    def __init__(self, name=None):
        self.name = name

    def match(self, buffer: bytes) -> Iterator[PatternMatch]:
        """Match this pattern on the given buffer.

        Args:
            buffer: The buffer to match against.

        Returns:
            An iterator for all found matches, yielding `PatternMatch`.
            `PatternMatch.match` can be any object relevant to this ``Pattern``.
        """
        raise NotImplementedError()


class RegexPattern(Pattern):
    """Regex pattern matches.

    The caller is responsible for any escaping that may be necessary.

    Args:
        pattern: The regex pattern.
        flags: Optional regex flags.
        name: Optional pattern name.
    """

    def __init__(
        self, pattern: Union[PatternStr, re.Pattern[bytes]], flags: re.RegexFlag = 0, name: Optional[str] = None
    ):
        super().__init__(name)
        self.re_pattern = compile_pattern(pattern, flags)

    def match(self, buffer: bytes) -> Iterator[PatternMatch]:
        """Match this regex pattern on the given buffer.

        Args:
            buffer: The buffer to match against.

        Returns:
            An iterator of `PatternMatch`.
        """
        for match in re.finditer(self.re_pattern, buffer):
            yield PatternMatch(match.start(), self, match, self.name)


class YaraPattern(Pattern):
    """YARA pattern matches.

    Args:
        rules: An instance of ``yara.Rules``.
        name: Optional pattern name.
    """

    def __init__(self, rules: yara.Rules, name: Optional[str] = None):
        super().__init__(name)
        self.rules = rules

    def match(self, buffer: bytes) -> Iterator[PatternMatch]:
        """Match the YARA rules on the given buffer.

        Args:
            buffer: The buffer to match against.

        Returns:
            An iterator of `PatternMatch`.
        """
        for match in self.rules.match(data=buffer):
            for offset, string_identifier, string_data in match.strings:
                yield PatternMatch(offset, self, string_data, f"{match.rule}:{string_identifier}")


class HexPattern(RegexPattern):
    """Hex pattern matches.

    Args:
        pattern: The hex pattern to convert.
        name: Optional pattern name.
    """

    def __init__(self, pattern: str, name: Optional[str] = None):
        super().__init__(self._hex_pattern(pattern), name=name)

    @staticmethod
    def _hex_pattern(pattern: str) -> bytes:
        """Convert hex regex patterns to byte patterns.

        Args:
            pattern: The pattern to convert.
        """

        if isinstance(pattern, bytes):
            raise TypeError("Can only convert hex patterns to bytes, pattern is already of type bytes")

        def _replace_hex(match):
            return re.escape(bytes.fromhex(match.group(0).decode()))

        # Search for any non-hex character
        if re.search(r"(?<!\\)([^a-fA-F0-9.^$*+?{}()\-\[\]\\|])", pattern):
            raise ValueError(f"Not a hex pattern: {pattern}")

        # Hex string must be multiple of 2
        if len(re.findall(r"(?<![\\])[a-fA-F0-9]", pattern)) % 2:
            raise ValueError(f"Invalid hex string: {pattern}")

        # Replace all hex characters
        return re.sub(rb"(?<![\\{])([a-fA-F0-9]{2})+", _replace_hex, pattern.encode())


class BytePattern(RegexPattern):
    """Create a raw pattern that will exact match by escaping regex tokens.

    Args:
        pattern: The pattern to escape.
        name: Optional pattern name.
    """

    def __init__(self, pattern: PatternStr, name: Optional[str] = None):
        if isinstance(pattern, str):
            pattern = pattern.encode()
        super().__init__(re.escape(pattern), name=name)


class PointerPattern(BytePattern):
    """Create a pointer pattern to a given address.

    Args:
        address: The address to create a pattern for.
        arch: The architecture to create a pointer for. ``Architecure.AMD64`` or ``Architecture.X86``
    """

    def __init__(self, address: int, arch: Architecture = PY_ARCH, name: Optional[str] = None):
        if arch == Architecture.AMD64:
            pack_fmt = "<Q"
        elif arch == Architecture.X86:
            pack_fmt = "<I"
        else:
            raise ValueError(f"Unknown architecture: {arch}")
        pattern = struct.pack(pack_fmt, address)
        super().__init__(pattern, name=name)


def parse_patterns(patterns: Union[PatternType, list[PatternType]]) -> list[Pattern]:
    """Parse a pattern or list of patterns into :class:`~skrapa.base.Pattern` objects.

    Args:
        patterns: The patterns to parse.
    """
    patterns = [patterns] if not isinstance(patterns, list) else patterns

    results = []
    for pattern in patterns:
        if isinstance(pattern, Pattern):
            results.append(pattern)
        elif HAS_YARA and isinstance(pattern, yara.Rules):
            results.append(YaraPattern(pattern))
        else:
            results.append(RegexPattern(pattern))

    return results


def compile_pattern(pattern: Union[PatternStr, re.Pattern[bytes]], flags: re.RegexFlag = 0) -> re.Pattern[bytes]:
    """Compile regex pattern for bytes matching.

    Args:
        pattern: The pattern to compile. If the pattern is already `re.Pattern` it will be returned as is.
        flags: The regex flags to compile the pattern with. Ignored if `pattern` is already a `re.Pattern`.
    """
    if isinstance(pattern, str):
        pattern = pattern.encode()
    elif isinstance(pattern, re.Pattern):
        return pattern
    return re.compile(pattern, flags=flags)


class VirtualStream(io.RawIOBase):
    """Base class for virtual streams."""

    def __init__(self):
        self._pos = 0

    def readinto(self, b: bytearray) -> int:
        raise NotImplementedError()

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            if pos < 0:
                raise ValueError(f"negative seek position {pos}")
        elif whence == io.SEEK_CUR:
            pos = max(0, self._pos + pos)

        self._pos = pos
        return pos

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True
