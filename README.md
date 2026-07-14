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

## How to use:
1. Install python requirements
```shell
pip install -r requirements.txt
```

2. Prepare your firmware images from the internet, or by pulling them off the device with `adb`
3. Run extractor.py against the image
```shell
# Example for Redmi Note 14 Pro+ 5G (amethyst)

╭─user@hostname ~/fboem ‹master› 
╰─$ python ./extractor.py ./abl.elf
                  
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
