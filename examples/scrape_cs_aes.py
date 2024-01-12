import logging
from typing import NamedTuple, Optional, Tuple

# External dependencies
from skrapa import AccessProtectionType, AllocationType, MemoryAttributes, read_process_memory, scan_all
from skrapa.exceptions import ReadProcessMemoryError

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S", level=logging.DEBUG
)


CS_KEY_PATTERN = b"\x00([\x00-\xff]{32})abcdefghijklmnop\x00\x00\x00\x00"


def get_aes_key(scanhit: NamedTuple) -> Tuple[int, Optional[str]]:
    """Scan for the Cobalt Strike x64 beacon AES key.

    Args:
        scanhit: namedtuple containing the scan results like the PID and address in memory

    Returns:
        pid, aes_key: A PID as integer and the HMAC + AES key as a hex string
    """

    pid = scanhit.process.pid
    address = scanhit.address

    try:
        match_content = read_process_memory(pid, address, 64)
    except ReadProcessMemoryError:
        # Process memory is volatile, page likely not accessible (anymore)
        logging.error(f"[pid: {pid}] Failed to read process memory at [{address:02x}]")

    aes_key = match_content[1:33].hex() if match_content else None

    return pid, aes_key


def main():
    # Set the attributes to the Cobalt Strike memory attributes for scraping the AES key
    mem_attributes = MemoryAttributes(
        protect=AccessProtectionType.PAGE_EXECUTE_READWRITE,
        allocation_protect=AccessProtectionType.PAGE_EXECUTE_READWRITE,
        type=AllocationType.MEM_PRIVATE,
        state=AllocationType.MEM_COMMIT,
    )

    logging.info("scanning all processes")
    for hit in scan_all(CS_KEY_PATTERN, mem_attributes):
        pid, aes_key = get_aes_key(hit)
        if aes_key:
            logging.info(f"found AES key in pid: {pid} - [{aes_key}]")
    logging.info("done!")


if __name__ == "__main__":
    main()
