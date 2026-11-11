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
        help="Firmware image to analyze",
    )
    parser.add_argument(
        "-f", "--force-string-lookup",
        help="Force string lookup on unsupported files",
        action="store_true",
    )
    parser.add_argument(
        "-o", "--offset",
        help="Start scanning at this byte offset",
        metavar="DEC/HEX BYTES",
        type=lambda x: int(x, 0),
        default=0,
    )
    parser.add_argument(
        "-O", "--output",
        help="Save extracted commands to a file",
    )
    args = parser.parse_args(argv)

    try:
        commands, recognized = _scan_firmware(
            Path(args.file),
            args.force_string_lookup,
            args.offset
        )
    except OSError as error:
        logger.error("Cannot read file (%s): %s", args.file, error)
        return 1

    if commands:
        print("\n" + "\n".join(commands))

    if args.output:
        print()

        try:
            out_path = Path(args.output)

            if out_path.is_dir():
                logger.error("Output path (%s) is a directory, not saving anything", out_path)
                return 1

            if out_path.exists():
                logger.warning("Output file (%s) already exists, overwriting!", out_path)

            out_path.write_text(
                "\n".join(commands) + ("\n" if commands else ""),
                encoding="utf-8"
            )
        except OSError as error:
            logger.error("Cannot write output file (%s): %s", out_path, error)
            return 1

        logger.info("Saved extracted commands to %s", out_path)

    if recognized == 0:
        return 1
    return 0
