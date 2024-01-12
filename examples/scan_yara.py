# -*- coding: utf-8 -*-
# Code example showing how to scan a PID using the YARA rule specified.

import argparse
import logging

from skrapa.base import PY_PLATFORM

if PY_PLATFORM == "windows":
    from skrapa import AllocationType

from utils import add_common_arguments, generate_description, parse_hit

from skrapa import AccessProtectionType, MemoryAttributes, scan_pid

try:
    import yara
except ImportError:
    logging.error("YARA Python module not found, install it with: pip install yara-python")
    exit(1)


def main():
    parser = argparse.ArgumentParser(
        description=generate_description(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--pid", required=True, type=int, help="PID to scan")
    parser.add_argument("--rule", required=True, help="path to YARA rule file to load")
    add_common_arguments(parser)

    args = parser.parse_args()

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

    # Compile the YARA rule to use during scanning
    patterns = yara.compile(filepath=args.rule)

    logging.info(f"scanning pid: {args.pid}")
    for hit in scan_pid(args.pid, patterns, mem_attributes, args.chunk_size, args.overlap_size):
        parse_hit(hit)
    logging.info("done!")


if __name__ == "__main__":
    main()
