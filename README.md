# Skrapa

Skrapa is a zero dependency and customizable Python library for scanning Windows and Linux process memory.

Contents
========
- [Installation](#installation)
- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Usage](#usage)
  - [Scanning a PID](#scanning-a-pid)
  - [Scan using YARA](#scan-using-yara)
  - [Page filters](#page-filters)
- [Features](#features)

## Installation

Installation can be done using `pip`:

```bash
$ pip install skrapa
```

You can also include YARA support by installing the `yara` variant:

```bash
$ pip install skrapa[yara]
```

## Quickstart

Start scanning with a given process ID after installing the library:

```bash
python examples/scan_pid.py --pid 8320 --hex 0000488B0557F402004833C448894424 --protect PAGE_EXECUTE_READ --alloc-protect PAGE_EXECUTE_WRITECOPY --type MEM_IMAGE --state MEM_COMMIT
```


## How it works

Skrapa differs slightly from the traditional sense of memory scanning in that it allows you to filter on specific memory attributes, which can greatly reduce the time it takes to scan process memory.

On the Windows and Linux platforms the memory regions assigned to a specific process each hold their own set of permissions. These permissions can basically be boiled down to the permissions we know and love: `READ`, `WRITE`, and `EXECUTE`. Within process memory these permissions can be combined as some process memory needs to be readable as well as executable when we want to execute code from this memory region.

The API was designed to be transparent so it doesn't matter if the script was written for Windows or Linux (with the single exception for a permission that is only available on Windows).

> **Warning**
> to effectively scan the memory space on Windows or Linux you will need administrative privileges on the target system.

## Usage

### Scanning a PID

Let's try to scan for the hex pattern of `0000488B0557F402004833C448894424` on Windows. To speed up the scanning process we assume that the following memory permissions are set for the region that the pattern should exist in:
+ Protect: `PAGE_EXECUTE_READ`
+ Allocation Protect: `PAGE_EXECUTE_WRITECOPY`
+ Type: `MEM_IMAGE`
+ State: `MEM_COMMIT`

Any memory region that does not have these permissions set will be exempt from the matching process, increasing the speed of the scan. The boilerplate code for such a scan would look something like this:

```python
from skrapa import AccessProtectionType, HexPattern, MemoryAttributes, scan_pid

mem_attributes = MemoryAttributes(
    protect=AccessProtectionType.PAGE_EXECUTE_READ,
    allocation_protect=AccessProtectionType.PAGE_EXECUTE_WRITECOPY,
    type=AllocationType.MEM_IMAGE,
    state=AllocationType.MEM_COMMIT,
)

for hit in scan_pid(pid=8320, patterns=HexPattern("0000488B0557F402004833C448894424"), attributes=mem_attributes):
    print(hit)
```

For each hit on the pattern we can look at the different attributes belonging to the process:
+ Process name: `hit.process.name`
+ Process path: `hit.process.path`
+ Process architecture: `hit.process.architecture`

Or for the associated memory region:
+ Memory region start: `hit.region_start`
+ Memory region size: `hit.region_size`
+ Memory region end: `hit.region_start + hit.region_size`
+ Address of the match: `hit.address`

We can read 128 bytes from the start of the pattern match because we might know there will be some interesting information after this pattern:

```python
from skrapa import read_process_memory

match_content = read_process_memory(pid=8320, address=hit.address, size=128)
```

You can then do whatever post processing you want on these bytes.

### Scan using YARA

Note: to use the YARA functionality of Skrapa, you'll need to have `yara-python` installed. You can install this manually or run `pip install skrapa[yara]`.

We're continuing our search leveraging YARA to find a pattern in the process memory of `notepad.exe`. Using YARA rules with Skrapa is as easy as pointing to your YARA file containing the rule(s) you want to match within the process memory. The YARA rule we're using for this example is:

```yara
rule l33t_notepad_rule {
    strings:
        $ = {
            00 00 48 8B 05 57 F4 02
            00 48 33 C4 48 89 44 24
        }
    condition:
        any of them
}
```

We can use the YARA rule from above to find the pattern in the process memory:

```python
from skrapa import AccessProtectionType, MemoryAttributes, scan_pid

try:
    import yara
except ImportError:
    logging.error("YARA Python module not found, install it with: pip install yara-python")
    exit(1)

mem_attributes = MemoryAttributes(
    protect=AccessProtectionType.PAGE_EXECUTE_READ,
    allocation_protect=AccessProtectionType.PAGE_EXECUTE_WRITECOPY,
    type=AllocationType.MEM_IMAGE,
    state=AllocationType.MEM_COMMIT,
)

patterns = yara.compile(
    source="rule l33t_notepad { strings: $ = {0000488B0557F402004833C448894424} condition: any of them }"
)

for hit in scan_pid(pid=8320, patterns=patterns, attributes=mem_attributes):
    print(hit)
```

The results of the above scan can be used in the exact same manner as the previous example shown. If you'd rather load in a YARA from a specified file you can switch the `source=` parameter of the `yara.compile` call with `filepath=`.

### Page filters

Skrapa allows users to define more complex memory filtering conditions by making use of a callback function. The callback function can also be used to check the size of the memory region before trying to match the given pattern.

For this example we will define the following `page_filter` function that will first check if:
+ The given region is bigger than `0x300000` and smaller than `0x400000`
+ The given region does not have the `PAGE_NOACCESS` protect attribute set
+ The given region has the `PAGE_READWRITE` protect attribute set

Note that we will not provide any of the memory attributes when using the above `page_filter` definition, instead we define every condition in the function:

```python
from skrapa import AccessProtectionType, HexPattern, MemoryAttributes, scan_pid

def page_filter(pageinfo) -> bool:
    return (
        0x300000 > pageinfo.size <= 0x400000
        and pageinfo.attributes.protect.name != "PAGE_NOACCESS"
        and pageinfo.attributes.protect.name == "PAGE_READWRITE"
    )

mem_attributes = MemoryAttributes(protect=None, allocation_protect=None, type=None, state=None)

for hit in scan_pid(pid=8320, patterns=HexPattern("0000488B0557F402004833C448894424"), attributes=mem_attributes, page_filter=page_filter):
    print(hit)
```

We will now only receive hits if the `page_filter` conditions were met.

Check out the `examples/` folder to quickly get started!

## Features

+ Supports x86 and x64 Windows and Linux platforms;
+ Scan a single process by name or PID, or scan the entire memory space;
+ Support for YARA signatures;
+ Support for page filters for more complex conditions;
