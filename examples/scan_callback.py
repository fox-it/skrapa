# -*- coding: utf-8 -*-
# Code example showing how to scan all of the process memory with a given pattern,
# defining own filters to apply on the memory pages.

import argparse
import logging

from skrapa.base import PY_PLATFORM, PageInfo

if PY_PLATFORM == "windows":
    from skrapa import AllocationType

from utils import add_common_arguments, gather_patterns, generate_description, parse_hit

from skrapa import AccessProtectionType, MemoryAttributes, scan_all


def page_filter(pageinfo: PageInfo) -> bool:
    """Function used as callback, conditions are checked by user when scanning pages.

    Args:
        pageinfo: A `PageInfo` namedtuple containing the page attributes and size.

    Returns:
        `False` to skip scanning the memory page, otherwise `True`.
    """

    return (
        0x300000 > pageinfo.size <= 0x400000
        and pageinfo.attributes.protect.name != "PAGE_NOACCESS"
        and pageinfo.attributes.protect.name == "PAGE_READWRITE"
    )


def main():
    parser = argparse.ArgumentParser(
        description=generate_description(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--regex", nargs="*", help="regex pattern to search for")
    parser.add_argument("--string", nargs="*", help="string pattern to search for")
    parser.add_argument("--hex", nargs="*", help="hex pattern to search for")
    add_common_arguments(parser)

    args = parser.parse_args()

    if not any([args.regex, args.string, args.hex]):
        parser.error("no search patterns, need at least one of [--regex, --string, --hex]")

    # Set the attributes to the MemoryAttributes namedtuple
    if PY_PLATFORM == "windows":
        mem_attributes = MemoryAttributes(
            protect=AccessProtectionType[args.protect].value if args.protect else None,
            allocation_protect=AccessProtectionType[args.alloc_protect].value if args.alloc_protect else None,
            type=AllocationType[args.type].value if args.type else None,
            state=AllocationType[args.state].value if args.state else None,
        )
    elif PY_PLATFORM == "linux":
        mem_attributes = MemoryAttributes(protect=AccessProtectionType[args.protect].value if args.protect else None)
    else:
        logging.error("Unsupported platform!")
        exit(1)

    logging.info("scanning all processes")
    for hit in scan_all(
        gather_patterns(args), mem_attributes, args.chunk_size, args.overlap_size, page_filter=page_filter
    ):
        parse_hit(hit)
    logging.info("done!")


if __name__ == "__main__":
    main()
