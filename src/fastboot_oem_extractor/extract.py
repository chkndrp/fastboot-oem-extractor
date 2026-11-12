"""Main entry"""

# Extract hidden "fastboot oem" commands from firmware blobs
# Copyright (C) 2026 chkndrp
#
# This library is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

import contextlib
import logging
import re
import tempfile

from pathlib import Path
from uefi_firmware import AutoParser

BL_MAGIC_PATTERNS = [
    bytes.fromhex("4D 5A"),        # Portable Executable (PE)
    bytes.fromhex("88 16 88 58"),  # Little Kernel (LK)
    bytes.fromhex("46 42 50 4B"),  # FBPK container
    bytes.fromhex("44 48 54 42"),  # DHTB signed binary
    bytes.fromhex("7F 45 4C 46"),  # ELF binary
    bytes.fromhex("42 46 42 46"),  # MTK Legacy GFH image
    bytes.fromhex("53 53 53 53"),  # MTK Signed container
    bytes.fromhex("D0 0D FE ED"),  # FDT/DTB/FIT Big endian
    bytes.fromhex("0D D0 ED FE"),  # FDT/DTB/FIT Little endian
    bytes.fromhex("41 4E 44 52 4F 49 44 21"),  # Second bootloaders
]

logger = logging.getLogger("fastboot-oem-extractor")


def _find_oem_commands(data: bytes, quiet: bool = False) -> list[str]:
    """Find and return OEM command strings in firmware data"""

    strings = re.findall(
        rb"oem\s+([^\x00\n]+)", 
        data, re.IGNORECASE
    )
    commands: set[str] = set()

    for raw_value in strings:
        value = raw_value.decode("ascii", "ignore").strip()
        command = f"fastboot oem {value}"

        if not 2 <= len(f"oem {value}".split()) <= 5:
            continue
        if any(character in value for character in "<>/%"):
            continue

        commands.add(command)

    if commands:
        logger.info("Matching 'oem *' ascii strings")
    elif not quiet:
        logger.info("No fastboot oem commands found")

    return sorted(commands)


def _extract_pe_files(parser: AutoParser) -> list[str]:
    """Extract firmware image and search for portable executables"""

    commands: set[str] = set()

    with tempfile.TemporaryDirectory() as tmpdir:
        logger.info("Extracting firmware...")

        with contextlib.redirect_stdout(None), contextlib.redirect_stderr(None):
            parsed = parser.parse()

            if parsed is not None:
                parsed.dump(tmpdir)

        pe_files = list(Path(tmpdir).rglob("*.pe"))
        if not pe_files:
            logger.info("No UEFI portable executables found")
            return []

        logger.info("Found %s UEFI portable executable(s)", len(pe_files))
        for pe_file in pe_files:
            commands.update(
                _find_oem_commands(
                    pe_file.read_bytes(),
                    quiet=True
                )
            )

    return sorted(commands)


def _find_uefi_parser(data: bytes) -> tuple[AutoParser, int] | None:
    """Search for valid UEFI firmware structure in data (first 10MB)"""

    for offset in range(0, len(data), 2048):
        with contextlib.redirect_stdout(None), contextlib.redirect_stderr(None):
            parser = AutoParser(
                data[offset:],
                search=False
            )

        if parser.type() != "unknown":
            return parser, offset

    return None


def _check_uefi_structure(data: bytes, base_offset: int = 0) -> list[str] | None:
    """Search for UEFI firmware structure (first 10MB)"""

    res = _find_uefi_parser(data)
    if res is not None:
        parser, offset = res

        logger.info(
            "Found valid UEFI firmware structure at offset: 0x%x",
            base_offset + offset
        )
        return _extract_pe_files(parser)

    return None


def _extract_bootloader_pe_files(firmware_file: Path, offset: int = 0) -> list[str] | None:
    """Extract PE files from bootloader (first 10MB)"""

    with firmware_file.open("rb") as firmware:
        firmware.seek(offset)
        bootloader_data = firmware.read(10 * 1024 * 1024)

    pe_offsets = [
            pe_offset
            for pe_offset in range(len(bootloader_data) - 1)
            if bootloader_data[pe_offset:pe_offset + 2] == b"MZ"
    ]

    if not pe_offsets:
        return None

    logger.info("Found %s embedded PE file(s)", len(pe_offsets))
    commands: set[str] = set()

    for index, pe_offset in enumerate(pe_offsets):
        end_offset = (
            pe_offsets[index + 1]
            if index + 1 < len(pe_offsets)
            else len(bootloader_data)
        )

        commands.update(
            _find_oem_commands(
                bootloader_data[pe_offset:end_offset],
                quiet=True
            )
        )

    return sorted(commands)


def _scan_firmware(
    firmware_file: Path,
    force_string_lookup: bool,
    offset: int = 0
) -> tuple[list[str], bool]:
    """Scan a firmware image for fastboot OEM commands"""

    if force_string_lookup:
        with firmware_file.open("rb") as firmware:
            firmware.seek(offset)
            return _find_oem_commands(firmware.read()), True

    with firmware_file.open("rb") as firmware:
        firmware.seek(offset)
        header = firmware.read(0x50)

    if header.startswith(BL_MAGIC_PATTERNS[0]):
        logger.info("File contains portable executable magic bytes")

        commands = _extract_bootloader_pe_files(firmware_file, offset)
        if commands is not None:
            return commands, True
    elif any(header.startswith(pattern) for pattern in BL_MAGIC_PATTERNS[1:]):
        logger.info("File contains common bootloader magic bytes")

        with firmware_file.open("rb") as firmware:
            firmware.seek(offset)
            commands = _find_oem_commands(
                firmware.read(),
                quiet=True
            )

        if commands:
            return commands, True

    logger.info("Reading firmware image (first 10MB): %s", firmware_file)
    with firmware_file.open("rb") as firmware:
        firmware.seek(offset)
        input_data = firmware.read(10 * 1024 * 1024)

    commands = _check_uefi_structure(input_data, offset)
    if commands is not None:
        return commands, True

    logger.error("Could not recognize the provided firmware image")
    return [], False


def _validate_input(firmware_file: str | Path, offset: int, force_string_lookup: bool = False) -> None:
    """Validate pulbic function input parameters"""

    if not isinstance(firmware_file, (str, Path)):
        raise ValueError("firmware_file must be a string or pathlib.Path")

    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative integer")

    file_size = Path(firmware_file).stat().st_size
    if offset > file_size:
        raise ValueError(f"offset ({offset}) exceeds firmware file size ({file_size} bytes)")

    if not isinstance(force_string_lookup, bool):
        raise ValueError("force_string_lookup must be a boolean")


def is_raw_image(firmware_file: str | Path, offset: int = 0) -> bool:
    """
    Check if a firmware image has no known magic bytes or UEFI structures

    This function is intended to help determine whenever to use 
    `force_string_lookup` when calling `extract_commands()`

    :param firmware_file: Path to the firmware image.
    :type firmware_file: str | pathlib.Path
    :param offset: Byte offset at which the firmware image starts.
    :type offset: int

    :returns: `True` if the file has no recognized magic bytes or UEFI headers.
        `False` otherwise.
    :rtype: bool

    :raises OSError: If `firmware_file` cannot be read.
    :raises ValueError: if `firmware_file` is not `str` or `pathlib.Path`,
        or `offset` is not a non-negative `int` within the file size.
    """

    _validate_input(firmware_file, offset)

    path = Path(firmware_file)

    with path.open("rb") as firmware:
        firmware.seek(offset)
        header = firmware.read(0x50)

    if any(header.startswith(pattern) for pattern in BL_MAGIC_PATTERNS):
        return False

    with path.open("rb") as firmware:
        firmware.seek(offset)
        input_data = firmware.read(10 * 1024 * 1024)

    return _find_uefi_parser(input_data) is None


def extract_commands(
    firmware_file: str | Path,
    force_string_lookup: bool = False,
    offset: int = 0
) -> list[str] | None:
    """
    Extract unique 'fastboot oem' commands from a firmware image

    :param firmware_file: Path to the firmware image.
    :type firmware_file: str | pathlib.Path

    :param force_string_lookup: Force the OEM command string lookup on raw images.
        `is_raw_image()` can be used to decide whenever to use this argument or not
    :type force_string_lookup: bool
    :param offset: Byte offset at which the firmware image starts.
    :type offset: int

    :returns: A sorted list of command strings when the format is
        recognized; an empty list if no commands are found; or `None` if the format
        is unrecognized and `force_string_lookup` is `False`.
    :rtype: list[str] | None

    :raises OSError: If `firmware_file` cannot be read.
    :raises ValueError: if `firmware_file` is not `str` or `pathlib.Path`,
        `force_string_lookup` is not a `bool`, or `offset` is not a non-negative
        `int` within the file size.
    """

    _validate_input(firmware_file, offset, force_string_lookup)

    commands, recognized = _scan_firmware(
        Path(firmware_file),
        force_string_lookup,
        offset
    )

    if recognized:
        return commands
    return None
