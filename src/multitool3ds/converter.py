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

"""Pipelines métier : .3ds → .cia, .cia → .3ds, déchiffrement, xorpads."""

from __future__ import annotations

import binascii
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import cia, crypto, rom, toolchain
from .headers import FormatError, detect_container, read_ncch_header, read_ncsd_header
from .ncchinfo import write_ncchinfo

SUPPORTED_3DS = {".3ds", ".cci", ".3dsx"}
SUPPORTED_CIA = {".cia"}
SUPPORTED_ZIP = {".zip"}
CIA_HEADER_MAGIC = b"\x20\x20\x00\x00"  # hdrSize = 0x2020, type/version = 0


class ConversionError(Exception):
    pass


def _cia_ok(code: int, out: Path, lines: list[str]) -> bool:
    return code == 0 and out.exists() and out.stat().st_size > 0


def content_args(parts: list[tuple[int, str]]) -> list[str]:
    """Arguments `-content` avec des index séquentiels (0,1,2…).

    Reproduction du comportement de `make_cia` d'origine : les index de contenu
    d'une CIA sont contigus, jamais les numéros de partition du NCSD. makerom
    v0.19 plante (SIGSEGV) quand on lui donne des index troués (0, 1, 7).
    """
    args: list[str] = []
    for position, (_partition_index, path) in enumerate(sorted(parts)):
        args += ["-content", f"{path}:{position}:{position}"]
    return args


def _describe_failure(code: int, lines: list[str]) -> str:
    if code < 0:
        return f"makerom a planté (signal {-code})"
    if lines:
        return lines[-1]
    return f"code {code}"


@dataclass
class Settings:
    output_dir: Path
    xorpad_dir: Path
    makerom: str | None = None


class Converter:
    def __init__(self, settings: Settings, log=print):
        self.settings = settings
        self.log = log
        self._makerom: str | None = settings.makerom or toolchain.find_makerom()

    # -- utilitaires ------------------------------------------------------- #
    @property
    def makerom(self) -> str:
        if not self._makerom:
            raise ConversionError(
                "makerom est introuvable. Installez-le (menu Réglages) ou via "
                "« brew install makerom »."
            )
        return self._makerom

    def _crc32(self, path: Path) -> int:
        crc = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                crc = binascii.crc32(chunk, crc)
        return crc & 0xFFFFFFFF

    def _expanded(self, path: Path) -> list[tuple[Path, int | None]]:
        """Développe un .zip : retourne [(fichier, crc32 imposé ou None)]."""
        if path.suffix.lower() not in SUPPORTED_ZIP:
            return [(path, None)]
        entries: list[tuple[Path, int | None]] = []
        tmpdir = Path(tempfile.mkdtemp(prefix="mt3ds-zip-"))
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                name = os.path.basename(info.filename)
                if not name.lower().endswith(".3ds"):
                    continue
                target = tmpdir / name
                with zf.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                entries.append((target, info.CRC & 0xFFFFFFFF))
        if not entries:
            raise ConversionError(f"Aucune ROM .3ds dans {path.name}.")
        return entries

    # -- .3ds → .cia ------------------------------------------------------- #
    def to_cia(self, source: Path) -> list[Path]:
        """Convertit une ROM en CIA. Retourne les fichiers produits."""
        self.settings.output_dir.mkdir(parents=True, exist_ok=True)
        produced: list[Path] = []

        for path, forced_crc in self._expanded(source):
            try:
                produced.extend(self._one_to_cia(path, forced_crc))
            finally:
                if path != source and path.parent.name.startswith("mt3ds-zip-"):
                    shutil.rmtree(path.parent, ignore_errors=True)
        return produced

    def _one_to_cia(self, rom_path: Path, forced_crc: int | None) -> list[Path]:
        crc32 = forced_crc if forced_crc is not None else self._crc32(rom_path)
        self.log(f"── {rom_path.name} (CRC32 {crc32:08x})")

        with open(rom_path, "rb") as fh:
            if detect_container(fh) != "ncsd":
                raise ConversionError(
                    f"{rom_path.name} : ce n'est pas un NCSD (.3ds/.cci). "
                    "Pour une CIA, utilisez la conversion inverse."
                )
            ncsd = read_ncsd_header(fh)
            main = read_ncch_header(fh, ncsd.partitions[0].offset if ncsd.partitions else 0)

        xorpad = None
        if not main.is_decrypted:
            xorpad = rom.find_xorpad(str(self.settings.xorpad_dir), ncsd.title_id, crc32)
            if not xorpad:
                raise ConversionError(
                    f"Xorpad manquant pour {ncsd.title_id} (CRC32 {crc32:08x}).\n"
                    "Générez-le depuis l'onglet « Xorpads », puis relancez."
                )
            self.log(f"   xorpad : {os.path.basename(xorpad)}")
        else:
            self.log("   ROM déjà déchiffrée : aucun xorpad requis.")

        with open(rom_path, "rb") as fh:
            if not rom.verify_xorpad(fh, ncsd.partitions[0].offset, xorpad):
                raise ConversionError(
                    "Xorpad invalide (ou ROM corrompue) : le hash de l'exheader ne "
                    "correspond pas."
                )

        tmpdir = Path(tempfile.mkdtemp(prefix="mt3ds-"))
        try:
            parts = rom.extract_partitions(str(rom_path), str(tmpdir))
            if not parts:
                raise ConversionError("Aucune partition NCCH extraite.")

            cxi = tmpdir / "0.cxi"
            save_size = rom.fix_cxi(str(cxi), xorpad)
            self.log(f"   exheader corrigé (save {save_size} Ko)")

            out = self.settings.output_dir / (rom_path.stem + ".cia")

            # 1) Assemblage explicite. Les index sont *séquentiels* (0,1,2…) comme le
            #    faisait make_cia : makerom plante (SIGSEGV) sur des index troués.
            args = ["-f", "cia", "-ignoresign", "-target", "p", "-o", str(out)]
            args += content_args(parts)

            code, lines = toolchain.run_makerom(self.makerom, args, log=self.log)
            if _cia_ok(code, out, lines):
                self.log(f"   ✔ {out.name} ({out.stat().st_size / 1_048_576:.1f} Mo)")
                return [out]

            self.log(
                f"   ⚠ assemblage direct impossible ({_describe_failure(code, lines)}) ; "
                "repli sur -ccitocia."
            )

            # 2) Repli : makerom convertit lui-même la CCI (après correction de
            #    l'exheader sur une copie de la ROM, pour ne pas toucher l'original).
            work = tmpdir / "work.3ds"
            shutil.copy2(rom_path, work)
            rom.fix_rom_exheader(str(work), ncsd.partitions[0].offset, xorpad)

            if out.exists():
                out.unlink()
            code, lines = toolchain.run_makerom(
                self.makerom,
                ["-ccitocia", str(work), "-o", str(out), "-target", "p", "-ignoresign"],
                log=self.log,
            )
            if not _cia_ok(code, out, lines):
                raise ConversionError(
                    f"makerom n'a pas pu produire la CIA de {rom_path.name} : "
                    f"{_describe_failure(code, lines)}"
                )
            self.log(f"   ✔ {out.name} ({out.stat().st_size / 1_048_576:.1f} Mo) [via -ccitocia]")
            return [out]
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # -- .cia → .3ds ------------------------------------------------------- #
    def to_3ds(self, source: Path, out: Path | None = None) -> list[Path]:
        self.settings.output_dir.mkdir(parents=True, exist_ok=True)
        if source.suffix.lower() not in SUPPORTED_CIA:
            raise ConversionError(f"{source.name} : une CIA (.cia) est attendue.")

        info, summary = cia.describe(str(source))
        self.log(f"   CIA : {summary.replace(chr(10), ' ')}")
        if info.problems:
            raise ConversionError(
                f"{source.name} : cette CIA n'est pas exploitable — "
                + " ; ".join(info.problems)
            )

        out = out or (self.settings.output_dir / (source.stem + ".3ds"))
        # -target p = clés de production : indispensable pour déchiffrer le titre
        # d'une CIA du commerce (le défaut de makerom est « test »).
        variants = [
            ["-ciatocci", str(source), "-o", str(out), "-target", "p", "-ignoresign"],
            ["-ciatocci", str(source), "-o", str(out), "-target", "p"],
            ["-ciatocci", str(source), "-o", str(out), "-ignoresign"],
            ["-ciatocci", str(source), "-o", str(out)],
        ]
        last_lines: list[str] = []
        for args in variants:
            if out.exists():
                out.unlink()
            code, last_lines = toolchain.run_makerom(self.makerom, args, log=self.log)
            if code == 0 and out.exists() and out.stat().st_size:
                self.log(f"✔ {out.name} ({out.stat().st_size / 1_048_576:.1f} Mo)")
                if info.encrypted:
                    self.log(
                        "   note : les contenus restent chiffrés au niveau NCCH — "
                        "enchaînez avec « Déchiffrer » pour un usage émulateur."
                    )
                return [out]

        detail = " | ".join(last_lines[-3:]) if last_lines else "aucune sortie"
        raise ConversionError(
            f"{source.name} : makerom n'a pas pu convertir cette CIA ({detail})."
        )

    # -- déchiffrement ----------------------------------------------------- #
    def decrypt(self, source: Path, keys_path: str | None = None) -> list[Path]:
        """Déchiffre une ROM, ou une CIA (convertie en CCI au préalable)."""
        self.settings.output_dir.mkdir(parents=True, exist_ok=True)
        produced: list[Path] = []

        for path, _crc in self._expanded(source):
            tmpdir: Path | None = None
            work = path
            with open(work, "rb") as fh:
                head = fh.read(4)
            if head == CIA_HEADER_MAGIC:
                self.log(f"── {path.name} : CIA détectée, conversion en CCI d'abord")
                tmpdir = Path(tempfile.mkdtemp(prefix="mt3ds-cia-"))
                work = tmpdir / (path.stem + ".3ds")
                try:
                    self.to_3ds(path, out=work)
                except ConversionError:
                    shutil.rmtree(tmpdir, ignore_errors=True)
                    raise
            else:
                with open(work, "rb") as fh:
                    kind = detect_container(fh)
                if kind != "ncsd":
                    raise ConversionError(f"{path.name} : un .3ds/.cci est attendu ici.")

            keys = crypto.find_keys(keys_path)
            self.log(f"Clés : {keys.source}")
            out = self.settings.output_dir / f"{path.stem}-decrypted.3ds"
            try:
                report = rom.decrypt_ncch_file(str(work), str(out), keys, log=self.log)
            finally:
                if tmpdir:
                    shutil.rmtree(tmpdir, ignore_errors=True)
            for warning in report.warnings:
                self.log("   ⚠ " + warning)
            self.log(
                f"   ✔ {out.name} ({report.ncch_count} partition(s), "
                f"{report.already_clear} déjà en clair)"
            )
            produced.append(out)
        return produced

    # -- xorpads ----------------------------------------------------------- #
    def build_ncchinfo(self, sources: list[Path]) -> Path:
        files: list[tuple[str, int]] = []
        for source in sources:
            with open(source, "rb") as fh:
                kind = detect_container(fh)
            if kind != "ncsd":
                raise ConversionError(f"{source.name} : un .3ds/.cci est attendu.")
            files.append((str(source), self._crc32(source)))

        out = self.settings.output_dir / "ncchinfo.bin"
        self.settings.output_dir.mkdir(parents=True, exist_ok=True)
        requests = write_ncchinfo(str(out), files)
        self.log(f"ncchinfo.bin écrit ({len(requests)} xorpad(s) demandé(s)) :")
        for req in requests:
            self.log(f"   • {req.filename} ({req.size_mb} Mo)")
        self.log(
            "Copiez ncchinfo.bin sur la carte SD, lancez GodMode9 → "
            "« XORpad options » → « Generate ncchinfo xorpads », puis placez les "
            "xorpads dans le dossier Xorpads de l'application."
        )
        return out
