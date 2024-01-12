import re

import pytest

from skrapa import Architecture, base


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ("beef", b"\xbe\xef"),
        ("dead[beef]", b"\xde\xad[\xbe\xef]"),
        ("dead[beef]", b"\xde\xad[\xbe\xef]"),
        ("\\deadbeeff", b"\\d\xea\xdb\xee\xff"),
        (
            "(DEADBEEF|C001D00D)[^CAFEBABE]|BAAAAAAD$",
            b"(\xde\xad\xbe\xef|\xc0\x01\xd0\\\x0d)[^\xca\xfe\xba\xbe]|\xba\xaa\xaa\xad$",
        ),
        ("6162636465666768696a6b6c6d6e6f70", b"abcdefghijklmnop"),
        ("000000[00-FF]", b"\x00\x00\x00[\x00-\xFF]"),
        ("000000[00-FF]{64}", b"\x00\x00\x00[\x00-\xFF]{64}"),
    ],
)
def test_hex_pattern(test_input, expected):
    print(base.HexPattern(test_input).re_pattern)
    assert base.HexPattern(test_input).re_pattern == re.compile(expected)


def test_hex_pattern_fail():
    with pytest.raises(ValueError):
        base.HexPattern("deadbee")


def test_byte_pattern():
    assert base.BytePattern(b"test[ing]").re_pattern == re.compile(rb"test\[ing\]")
    assert base.BytePattern("beef[beef]").re_pattern == re.compile(rb"beef\[beef\]")


def test_regex_pattern():
    pattern = base.RegexPattern(b"test")
    results = list(pattern.match(b"some testing buffer"))
    assert len(results) == 1
    assert results[0].offset, results[0].match == (5, b"test")

    assert base.RegexPattern("test").re_pattern.pattern == b"test"
    assert base.RegexPattern("beef").re_pattern.pattern == b"beef"
    assert base.RegexPattern(base.BytePattern("beef").re_pattern).re_pattern.pattern == b"beef"
    assert base.RegexPattern(base.HexPattern("beef").re_pattern).re_pattern.pattern == b"\xbe\xef"


def test_regex_pattern_flags():
    # verbose regex (ignores whitespace in pattern and comments)
    re_verbose = base.RegexPattern(
        rb"""
        a{4}        # match 4 a's
        ...         # match 3 anything
        b{5}        # match 5 b's
    """,
        re.VERBOSE,
    )
    assert len(list(re_verbose.match(b"hello world aaaa123bbbbb"))) == 1
    assert len(list(re_verbose.match(b"hello world aaaabbbbb"))) == 0

    # case insensitive
    re_ignore_case = base.RegexPattern(b"skrapa", flags=re.IGNORECASE)
    results = list(re_ignore_case.match(b"SkRaPa SKRAPA skrapa"))
    assert len(results) == 3
    matches = [result[2].group() for result in results]
    assert matches == [b"SkRaPa", b"SKRAPA", b"skrapa"]

    # capture groups
    re_group = base.RegexPattern(r"(\w+) (\w+)")
    results = list(re_group.match(b"Isaac Newton, physicist"))
    assert len(results) == 1
    assert results[0].match.groups() == (b"Isaac", b"Newton")

    # existing regex (ensure it's a byte pattern)
    regex = base.RegexPattern(re.compile(rb"(?i)testing\d+"))
    assert len(list(regex.match(b"Testing0 TeSTiNg1 testingfoo testingbar testing12345"))) == 3


def test_compile_pattern():
    assert base.compile_pattern("test").pattern == b"test"
    assert base.compile_pattern(b"test").pattern == b"test"
    assert base.compile_pattern(re.compile(b"already compiled")).pattern == b"already compiled"


def test_pointer_pattern():
    ptr_pattern = base.PointerPattern(0x12345)
    buffer = 0x12345.to_bytes(8, "little")
    assert len(list(ptr_pattern.match(buffer))) == 1

    ptr_pattern = base.PointerPattern(0x424242, Architecture.X86)
    buffer = 0x424242.to_bytes(4, "little")
    assert len(list(ptr_pattern.match(buffer))) == 1

    ptr_pattern = base.PointerPattern(0x123456789, Architecture.AMD64)
    buffer = 0x123456789.to_bytes(8, "little")
    assert len(list(ptr_pattern.match(buffer))) == 1

    with pytest.raises(ValueError):
        ptr_pattern = base.PointerPattern(0x123456789, None)
