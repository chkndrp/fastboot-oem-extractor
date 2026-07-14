#!/usr/bin/env python3

#  Extract hidden "fastboot oem" commands from firmware blobs
#  Copyright (C) 2026 chkndrp
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import re
import contextlib
import logging
import tempfile

from pathlib import Path
from uefi_firmware import AutoParser

BL_MAGIC_PATTERNS = [
    bytes.fromhex('4D 5A'),        # Portable Executable (PE)
    bytes.fromhex('88 16 88 58'),  # Little Kernel (LK)
    bytes.fromhex('46 42 50 4B'),  # FBPK container
    bytes.fromhex('44 48 54 42'),  # DHTB signed binary
    bytes.fromhex('7F 45 4C 46'),  # ELF binary
    bytes.fromhex('41 4E 44 52 4F 49 44 21')  # Second bootloaders (lk1st, lk2nd)
]

MUTE_STDOUT = contextlib.redirect_stdout(None)
MUTE_STDERR = contextlib.redirect_stderr(None)

def setup_logging() -> logging.Logger:
    """Configure logging"""

    class PrefixFormatter(logging.Formatter):
        def format(self, record):
            record.msg = f"(x) {record.msg}"
            return super().format(record)

    log = logging.getLogger('fastboot-oem-extractor')
    log.setLevel(logging.INFO)
    log.propagate = False

    # Custom prefix
    handler = logging.StreamHandler()
    handler.setFormatter(PrefixFormatter('%(message)s'))
    log.addHandler(handler)

    return log


def find_oem_commands(firmware_file: Path, quiet: bool = False) -> int:
    """Extract oem commands from a firmware file. Returns count of commands found."""

    # Matching for "oem <xxx>"
    content = firmware_file.read_bytes()
    strings = re.findall(rb'oem\s+([^\x00\n]+)', content, re.IGNORECASE)

    if strings:
        cmds = sorted(set(
            # (compatibility) pylint: disable=inconsistent-quotes
            f'fastboot oem {s.decode("ascii", "ignore").strip()}'
            for s in strings
                # Filter only strings containing 2-5 words (avoid long sentence fragments)
                if 2 <= len(f'oem {s.decode("ascii", "ignore").strip()}'.split()) <= 5

                # Exclude help text patterns (ex. "oem off-mode-charge 0/1")
                and '<' not in s.decode("ascii", "ignore")
                and '>' not in s.decode("ascii", "ignore")
                and '/' not in s.decode("ascii", "ignore")
                and '%' not in s.decode("ascii", "ignore")
        ))
        if cmds:
            logger.info('Matching \'oem *\' ascii strings')
            print('\n' + '\n'.join(cmds))
            return len(cmds)

    if not quiet:
        logger.info('No fastboot oem commands found')

    return 0


def extract_pe_files(parser: AutoParser) -> bool:
    """Extract firmware file and search for portable executables"""

    with tempfile.TemporaryDirectory() as tmpdir:
        logger.info('Extracting firmware...')

        # Stop dump() from writing to stdout
        with MUTE_STDOUT, MUTE_STDERR:
            parsed = parser.parse()
            if parsed is not None:
                parsed.dump(tmpdir)

        # Glob for files with the extension '.pe' recursively
        pe_files = list(Path(tmpdir).rglob('*.pe'))
        if not pe_files:
            logger.info('No UEFI portable executables found')
            return True

        logger.info('Found %s UEFI portable executable(s)', len(pe_files))
        for pe in pe_files:
            find_oem_commands(pe)
    return True


def check_firmware(firmware_file: Path, force_string_lookup: bool = False) -> bool:
    """Analyze firmware file for OEM commands"""

    # Ensure firmware_file is Path and not String
    firmware_file = Path(firmware_file)

    def check_uefi_structure(data: bytes) -> bool | None:
        """Search for UEFI firmware structure (first 10MB)"""
        max_offsets = min(len(data) // 2048, 100)

        for i in range(max_offsets):
            offset = i * 2048
            if offset >= len(data):
                break

            with MUTE_STDOUT, MUTE_STDERR:
                parser = AutoParser(data[offset:], search=False)

            if parser.type() != 'unknown':
                logger.info('Found valid UEFI firmware structure at offset: 0x%x', offset)
                return extract_pe_files(parser)
        return None

    def extract_bootloader_pe_files() -> bool:
        """Extract PE files from bootloader (first 10MB)"""
        try:
            with open(firmware_file, 'rb') as fh:
                bootloader_data = fh.read(10 * 1024 * 1024)
        except OSError:
            return False

        with tempfile.TemporaryDirectory() as tmpdir:
            pe_offsets = [i for i in range(len(bootloader_data) - 1)
                          if bootloader_data[i:i+2] == b'MZ']
            if not pe_offsets:
                return False

            logger.info('Found %s embedded PE file(s)', len(pe_offsets))
            for idx, offset in enumerate(pe_offsets):
                try:
                    end_offset = pe_offsets[idx + 1] if idx + 1 < len(pe_offsets) else len(bootloader_data)
                    pe_file = Path(tmpdir) / f'embedded_pe_{idx}.efi'
                    pe_file.write_bytes(bootloader_data[offset:end_offset])
                    find_oem_commands(pe_file)
                except (OSError, ValueError) as e:
                    logger.debug('Failed to process PE at 0x%x: %s', offset, e)
            return True

    def check_bootloader_magic() -> bool | None:
        """Check bootloader magic (first 0x50 bytes)"""
        try:
            with open(firmware_file, 'rb') as fh:
                header = fh.read(0x50)
        except OSError:
            return None

        if header.startswith(bytes.fromhex('4D 5A')):
            logger.info('File contains portable executable magic bytes')
            if extract_bootloader_pe_files():
                return True
            return None  # Continue to UEFI check

        for pattern in BL_MAGIC_PATTERNS[1:]:
            if header.startswith(pattern):
                logger.info('File contains common bootloader magic bytes')

                # Try string lookup first, then UEFI parsing
                if find_oem_commands(firmware_file, quiet=True) > 0:
                    return True

                return None  # Continue to UEFI check
        return None

    if force_string_lookup:
        return find_oem_commands(firmware_file)

    if check_bootloader_magic() is True:
        return True

    try:
        logger.info('Reading firmware file (first 10MB): %s', firmware_file)
        with open(firmware_file, 'rb') as fh:
            input_data = fh.read(10 * 1024 * 1024)
    except OSError as e:
        logger.error('Cannot read file (%s): %s', firmware_file, e)
        return False

    if check_uefi_structure(input_data):
        del input_data # memory cleanup
        return True

    logger.error('Could not recognize the provided firmware file')
    return False


def main() -> bool:
    """Main entry point"""

    parser = argparse.ArgumentParser(
        description='Extract hidden "fastboot oem" commands from firmware blobs',
        add_help=False
    )
    parser.add_argument(
        'file', 
        help='Firmware file to analyze'
    )
    parser.add_argument(
        '-fsl', '--force-string-lookup',
        help='Force string lookup on unsupported files',
        action='store_true',
        dest='fsl',
    )
    args = parser.parse_args()
    return check_firmware(args.file, args.fsl)


# Initialize logger
logger = setup_logging()

if __name__ == '__main__':
    main()
