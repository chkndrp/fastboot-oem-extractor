# fastboot-oem-extractor
![PyPI - Version](https://img.shields.io/pypi/v/fastboot-oem-extractor?logo=python&logoColor=white) ![PyPI - Downloads](https://img.shields.io/pypi/dm/fastboot-oem-extractor?logo=python&logoColor=white) ![PyPI - Typing](https://img.shields.io/pypi/types/fastboot-oem-extractor?logo=python&logoColor=white)

Extract hidden "fastboot oem" commands from firmware blobs

---

## Supported firmware
These firmware blobs will be accepted by this tool 
- `ABL` (Qualcomm)
- `LK1st, LK2nd` (Qualcomm, Second BLs)
- `DTB, FDT, FIT` (Device trees, U-Boot)
- `DHTB` Signed binaries (U-Boot)
- `LK, BFBF, SSSS` (MediaTek)
- `FBPK` Containers (Google)
- `ELF` Linux binaries
- Anything else containing UEFI PEs

This is an artificial barrier for when this tool is ran in a loop against firmware images

---

## Installing:
```shell
# With PyPi (recommended)
pip install fastboot_oem_extractor
```

```shell
# When running from source/clone
pip install -r requirements.txt
```

---

## Using as a CLI tool:
1. Prepare your firmware images from the internet, or by pulling them off the device with `adb`
2. Run the installed CLI against the image
```shell
# PyPi
python -m fastboot_oem_extractor ./abl.elf
```
```shell
# Source/clone
python ./extractor.py ./abl.elf
```

3. Fetch the output
```shell
# Example output for Redmi Note 14 Pro+ 5G (amethyst)
            
(x) File contains common bootloader magic bytes
(x) Reading firmware image (first 10MB): abl.elf
(x) Found valid UEFI firmware structure at offset: 0x1000
(x) Extracting firmware...
(x) Found 1 UEFI portable executable(s)
(x) Matching 'oem *' ascii strings

fastboot oem allow-wipe-userdata
fastboot oem audio-framework
fastboot oem device-info
fastboot oem disable-charger-screen
fastboot oem dm-verity-enforcing
fastboot oem edl
fastboot oem enable-charger-screen
fastboot oem fbreason
fastboot oem getguid
fastboot oem hwid
fastboot oem lkmsg
fastboot oem lock
fastboot oem lpmsg
fastboot oem off-mode-charge
fastboot oem poweroff
fastboot oem ramdump fat
fastboot oem select-display-panel
fastboot oem set-gpu-preemption
fastboot oem set-hw-fence-value
fastboot oem uart-enable
fastboot oem uefilog
fastboot oem unlock
```

If your file is some raw image that does not contain any UEFI PEs or common binary magic bytes,
you can force the string lookup via this command line option:
```shell
--force-string-lookup
```

---

### Using as a Python library
This project can also be used as a library for other tools that want to integrate this.
There are two public functions:

```python
# Check if a firmware image has no known magic bytes or UEFI structures
is_raw_image(firmware_file) -> bool
```

This function is intended to help determine whenever to use 
`force_string_lookup` when calling `extract_commands()`

- `firmware_file` (`str | pathlib.Path`): Path to the firmware image.
- **Returns:** 
    - `True` if the file has no recognized magic bytes or UEFI headers.
    - `False` otherwise.
- **Raises:** `OSError` if the file cannot be read.

```python
# Extract unique 'fastboot oem' commands from a firmware image
extract_commands(firmware_file, force_string_lookup=False) -> list[str] | None
```

- `firmware_file` (`str | pathlib.Path`): Path to the firmware image.
- `force_string_lookup` (`bool`): Force the oem command string lookup on raw images. Defaults to `False`.
- **Returns:** 
    - A sorted list of unique command strings when the format is recognized.
    - An empty list if no commands are found.
    - `None` if the format is unrecognized and `force_string_lookup` is `False`.
- **Raises:** `OSError` if the file cannot be read.

#### **Quick example:**
```python
# from pathlib import Path
from fastboot_oem_extractor import extract_commands

# israw = is_raw_image(Path("./abl.elf"))
israw = is_raw_image("./abl.elf")

# commands = extract_commands(Path("./abl.elf"))
commands = extract_commands("./abl.elf", force_string_lookup=israw)

if commands is None:
    print("Unrecognized firmware format.")
elif commands:
    print(commands)
    # Example output: ['fastboot oem allow-wipe-userdata', ...]
else:
    print("No OEM commands found.")
```

---

## Disclaimer:
Due to the nature of simply matching "oem" strings, the output may contain some invalid commands,
or commands that don't work after the device is sent out of factory. Keep this in mind

Also, some FBPK containers (e.g. `barbret` bootloader) are very difficult to extract
`oem` commands from, and may not work. Most work just fine though.

---

## Similar project
If you want to extract bootloader/charging pictures from a `imagefv` partition on your Qualcomm device,
use my other tool:

[chkndrp/imagefv-extractor](https://github.com/chkndrp/imagefv-extractor)

---

## Requirements
- Python 3.10 or newer
- Installed `uefi_firmware` pip package
