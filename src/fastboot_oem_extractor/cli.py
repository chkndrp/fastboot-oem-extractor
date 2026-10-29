"""CLI interface."""

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

import argparse
import logging

from collections.abc import Sequence
from pathlib import Path
from .extract import _scan_firmware

logger = logging.getLogger("fastboot-oem-extractor")


class _PrefixFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return f"(x) {super().format(record)}"


def _configure_logging() -> None:
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(_PrefixFormatter("%(message)s"))
        logger.addHandler(handler)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI main entry"""

    _configure_logging()

    parser = argparse.ArgumentParser(
        description='Extract hidden "fastboot oem" commands from firmware blobs'
    )
    parser.add_argument(
        "file",
        help="Firmware image to analyze"
    )
    parser.add_argument(
        "-fsl", "--force-string-lookup",
        help="Force string lookup on unsupported files",
        action="store_true",
        dest="fsl",
    )
    args = parser.parse_args(argv)

    try:
        commands, recognized = _scan_firmware(Path(args.file), args.fsl)
    except OSError as error:
        logger.error("Cannot read file (%s): %s", args.file, error)
        return 1

    if commands:
        print("\n" + "\n".join(commands))

    if recognized == 0:
        return 1
    return 0
