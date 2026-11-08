# Multitool 3DS macOS — portage macOS de « Convertisseur-3DS-CIA »
# Copyright (C) 2026 Jérôme Pepermans
# Copyright (C) 2024 TheRinzler65 — œuvre d'origine
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License v2
# for more details: <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>
#
# SPDX-License-Identifier: GPL-2.0-only

"""Point d'entrée : `python3 -m multitool3ds` (GUI) ou sous-commandes CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import converter, gui


def _converter(args) -> converter.Converter:
    settings = converter.Settings(
        output_dir=Path(args.output or Path.home() / "Desktop" / "Multitool 3DS"),
        xorpad_dir=Path(args.xorpads or Path.home() / "3ds-xorpads"),
        makerom=args.makerom,
    )
    return converter.Converter(settings, log=lambda m: print(m, flush=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="multitool-3ds", description="Multitool 3DS")
    parser.add_argument("--gui", action="store_true", help="lance l'interface (défaut)")
    sub = parser.add_subparsers(dest="command")

    for name, help_text in (
        ("to-cia", "convertit des .3ds/.cci en .cia"),
        ("to-3ds", "convertit des .cia en .3ds"),
        ("decrypt", "déchiffre des .3ds/.cci"),
        ("ncchinfo", "génère ncchinfo.bin"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("files", nargs="+")
        cmd.add_argument("-o", "--output")
        cmd.add_argument("--xorpads")
        cmd.add_argument("--makerom")
        cmd.add_argument("--keys", help="boot9.bin ou keys.txt (decrypt)")

    args = parser.parse_args(argv)
    if not args.command or args.command == "gui":
        return gui.main()

    conv = _converter(args)
    files = [Path(f) for f in args.files]
    try:
        if args.command == "to-cia":
            for f in files:
                conv.to_cia(f)
        elif args.command == "to-3ds":
            for f in files:
                conv.to_3ds(f)
        elif args.command == "decrypt":
            for f in files:
                conv.decrypt(f, args.keys)
        elif args.command == "ncchinfo":
            conv.build_ncchinfo(files)
    except (converter.ConversionError, OSError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
