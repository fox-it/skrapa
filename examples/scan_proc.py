# -*- coding: utf-8 -*-
# Code example showing how to scan a given process name with a given pattern.

import argparse
import logging

from skrapa.base import PY_PLATFORM

if PY_PLATFORM == "windows":
    from skrapa import AllocationType

from utils import add_common_arguments, gather_patterns, generate_description, parse_hit

from skrapa import AccessProtectionType, MemoryAttributes, scan_process_name


def main():
    parser = argparse.ArgumentParser(
        description=generate_description(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--name", required=True, help="process name to scan")
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

    logging.info(f"scanning: {args.name}")
    for hit in scan_process_name(args.name, gather_patterns(args), mem_attributes, args.chunk_size, args.overlap_size):
        parse_hit(hit)
    logging.info("done!")


if __name__ == "__main__":
    main()
