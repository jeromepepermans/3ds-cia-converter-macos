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

"""Génération de ncchinfo.bin (format Decrypt9/GodMode9).

Reproduction octet pour octet de `ncchinfo_gen()` du dépôt d'origine :

    offset  taille  contenu
    0x00    4       0xFFFFFFFF
    0x04    4       0xF0000004 (version 4)
    0x08    4       nombre d'entrées
    0x0C    4       réservé
    puis, par entrée (168 octets) :
    0x00    16      counter AES-CTR
    0x10    16      KeyY
    0x20    4       taille de section en Mo (arrondie au supérieur)
    0x24    4       réservé
    0x28    4       flags[7] du NCCH (crypto fixe / seed)
    0x2C    4       flags[3] (méthode de crypto)
    0x30    8       title id (u64 LE, depuis program id)
    0x38    112     nom du fichier xorpad (UTF-8, terminé par \0)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable

from .headers import FormatError, NcchHeader, detect_container, read_ncsd_header, read_ncch_header

NCCHINFO_MAGIC = 0xFFFFFFFF
NCCHINFO_VERSION = 0xF0000004
ENTRY_SIZE = 168
NAME_SIZE = 112

# Types de section, valeurs identiques au dépôt d'origine.
SECTION_EXHEADER = 1
SECTION_EXEFS = 2
SECTION_ROMFS = 3

SECTION_LABELS = {
    SECTION_EXHEADER: "exheader",
    SECTION_EXEFS: "exefs",
    SECTION_ROMFS: "romfs",
}


@dataclass(frozen=True)
class XorpadRequest:
    """Une entrée de ncchinfo.bin : un xorpad à faire générer par la console."""

    filename: str  # nom attendu du fichier .xorpad
    title_id: str
    crc32: int
    partition: str
    section: str
    size_mb: int


def _round_up(value: int, multiple: int) -> int:
    if multiple == 0:
        return value
    remainder = abs(value) % multiple
    if remainder == 0:
        return value
    if value < 0:
        return -(abs(value) - remainder)
    return value + multiple - remainder


def aes_counter(ncch: NcchHeader, section: int, profile: str = "reference") -> bytes:
    """Compteur AES-CTR d'une section.

    Deux formules coexistent :

    - ``reference`` (défaut) : `partition_id << 64 | section << 56`, où
      `partition_id` est l'u64 LE de l'en-tête NCCH (0x108). C'est la formule
      utilisée par le matériel, validée par pyctr et par les xorpads réels.
      Indépendante de `formatVersion`.
    - ``legacy`` : formule du script d'origine, qui dépend de `formatVersion`.
      Conservée pour reproduire à l'identique l'ancien comportement.
    """
    if profile == "legacy":
        counter = bytearray(16)
        if ncch.format_version in (0, 2):
            counter[:8] = _title_id_bytes(ncch)[::-1]
            counter[8:9] = bytes([section])
        elif ncch.format_version == 1:
            offset = 0x200
            if section == SECTION_EXEFS:
                offset = ncch.exefs_offset
            elif section == SECTION_ROMFS:
                offset = ncch.romfs_offset
            counter[:8] = _title_id_bytes(ncch)
            counter[12:16] = struct.pack(">I", offset & 0xFFFFFFFF)
        return bytes(counter)

    if profile != "reference":
        raise ValueError(f"profil de compteur inconnu : {profile}")
    partition_id = struct.unpack_from("<Q", _title_id_bytes(ncch), 0)[0]
    return (partition_id << 64 | (section << 56)).to_bytes(16, "big")


def _title_id_bytes(ncch: NcchHeader) -> bytes:
    return struct.pack("<Q", int(ncch.title_id, 16))


def section_mb(size_bytes: int) -> int:
    mb = _round_up(size_bytes, 1024 * 1024) // (1024 * 1024)
    return mb or 1


def _xorpad_name(title_id: str, crc32: int, partition: str, section: str) -> str:
    return f"/{title_id}.{crc32:08x}.{partition}.{section}.xorpad"


def _build_entry(ncch: NcchHeader, crc32: int, partition: str, section: int) -> tuple[bytes, XorpadRequest]:
    counter = aes_counter(ncch, section)
    size = ncch.exheader_size if section == SECTION_EXHEADER else 0
    mb = section_mb(size) if size else 1
    body = struct.pack(
        "<16s16sIIIIQ",
        counter,
        ncch.key_y,
        mb,
        0,
        ncch.flag7,
        1 if ncch.uses_fixed_key else ncch.crypto_method,
        ncch.program_id,
    )
    name = _xorpad_name(ncch.title_id, crc32, partition, SECTION_LABELS[section])
    if len(name.encode("utf-8")) > NAME_SIZE:
        raise FormatError("Nom de xorpad trop long (ne devrait jamais arriver).")
    padded = name.encode("utf-8") + b"\x00" * (NAME_SIZE - len(name.encode("utf-8")))
    request = XorpadRequest(
        filename=name.lstrip("/"),
        title_id=ncch.title_id,
        crc32=crc32,
        partition=partition,
        section=SECTION_LABELS[section],
        size_mb=mb,
    )
    return body + padded, request


def build_ncchinfo(files: Iterable[tuple[str, int]]) -> tuple[bytes, list[XorpadRequest]]:
    """Construit le contenu de ncchinfo.bin.

    `files` : itérable de (chemin, crc32 du fichier tel qu'il sera lu par la console).
    Retourne (contenu binaire, liste des xorpads attendus).
    """
    entries: list[bytes] = []
    requests: list[XorpadRequest] = []

    for path, crc32 in files:
        with open(path, "rb") as fh:
            kind = detect_container(fh)
            if kind == "ncsd":
                header = read_ncsd_header(fh)
                ncchs = []
                for p in header.partitions:
                    try:
                        ncchs.append((p.name, read_ncch_header(fh, p.offset)))
                    except FormatError:
                        continue
            else:
                ncchs = [("Main", read_ncch_header(fh, 0))]

        for partition, ncch in ncchs:
            if ncch.exheader_size:
                data, request = _build_entry(ncch, crc32, partition, SECTION_EXHEADER)
                entries.append(data)
                requests.append(request)

    header = struct.pack("<IIII", NCCHINFO_MAGIC, NCCHINFO_VERSION, len(entries), 0)
    return header + b"".join(entries), requests


def write_ncchinfo(path: str, files: Iterable[tuple[str, int]]) -> list[XorpadRequest]:
    content, requests = build_ncchinfo(files)
    with open(path, "wb") as fh:
        fh.write(content)
    return requests


def parse_ncchinfo(data: bytes) -> list[dict]:
    """Lecture défensive (utile pour vérifier un fichier produit)."""
    if len(data) < 16:
        raise FormatError("ncchinfo.bin trop court.")
    magic, version, count, _ = struct.unpack_from("<IIII", data, 0)
    if magic != NCCHINFO_MAGIC:
        raise FormatError("Magie ncchinfo.bin invalide.")
    out = []
    for i in range(count):
        base = 16 + i * ENTRY_SIZE
        if base + ENTRY_SIZE > len(data):
            raise FormatError("ncchinfo.bin tronqué.")
        counter, key_y, mb, _res, flag7, flag3, title_id = struct.unpack_from("<16s16sIIIIQ", data, base)
        name = data[base + 0x38 : base + ENTRY_SIZE].split(b"\x00", 1)[0].decode("utf-8", "replace")
        out.append(
            dict(
                counter=counter.hex().upper(),
                key_y=key_y.hex().upper(),
                size_mb=mb,
                flag7=flag7,
                flag3=flag3,
                title_id=f"{title_id:016X}",
                name=name,
                version=version,
            )
        )
    return out
