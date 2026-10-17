# fastboot-oem-extractor 
Extract hidden "fastboot oem" commands from firmware blobs

## Supported firmware
These firmware blobs will be accepted by this tool 
- `ABL` (Qualcomm)
- `LK1st, LK2nd` (Qualcomm, Second BLs)
- `LK` (MediaTek)
- `FBPK` Containers (Google)
- `DHTB` Signed binaries (U-Boot)
- `ELF` Linux binaries
- Anything else containing UEFI PEs

This is an artificial barrier for when this tool is ran in a loop against firmware images

## Using as a CLI tool:
1. Installing:
```shell
# With PyPi (recommended)
pip install fasboot_oem_extractor
```

```shell
# From source/clone
pip install -r requirements.txt
```

2. Prepare your firmware images from the internet, or by pulling them off the device with `adb`
3. Run the installed CLI against the image
```shell
# PyPi
python -m fastboot_oem_extractor ./abl.elf
```

```shell
# Source/clone
python ./extractor.py ./abl.elf
```

4. Fetch the output
```shell
# Example output for Redmi Note 14 Pro+ 5G (amethyst)
            
(x) File contains common bootloader magic bytes
(x) Reading firmware file (first 10MB): abl.elf
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

If your file is some sparse image that does not contain any UEFI PEs or common binary magic bytes,
you can force the string lookup via this command line option:
```shell
--force-string-lookup
```

### Using as a Python library
This project can also be used as a library for other tools that want to integrate this.
There is one public function:

```python
extract_commands(firmware_file, force_string_lookup=False) -> list[str] | None
```

- `firmware_file` (`str | pathlib.Path`): Path to the firmware image.
- `force_string_lookup` (`bool`): Force the oem command string lookup on raw images. Defaults to `False`.
- **Returns:** 
    - A sorted list of unique command strings when the format is recognized.
    - An empty list if no commands are found.
    - `None` if the format is unrecognized and `force_string_lookup` is `False`.
- **Raises:** `OSError` if the file cannot be read.

**Quick example:**
```python
# from pathlib import Path
from fastboot_oem_extractor import extract_commands

# commands = extract_commands(Path("./abl.elf"))
commands = extract_commands("./abl.elf")

if commands is None:
    print("Unrecognized firmware format.")
elif commands:
    print(commands)
    # Example output: ['fastboot oem allow-wipe-userdata', ...]
else:
    print("No OEM commands found.")
```

## Disclaimer:
Due to the nature of simply matching "oem" strings, the output may contain some invalid commands,
or commands that don't work after the device is sent out of factory. Keep this in mind

Also, some FBPK containers (e.g. `barbret` bootloader) are very difficult to extract
`oem` commands from, and may not work. Most work just fine though.

## Similar project
If you want to extract bootloader/charging pictures from a `imagefv` partition on your Qualcomm device,
use my other tool:

[chkndrp/imagefv-extractor](https://github.com/chkndrp/imagefv-extractor)

## Requirements
- Python 3.10 or newer
- Installed `uefi_firmware` pip package
