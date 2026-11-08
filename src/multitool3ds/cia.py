"""Lecture d'une CIA (en-tête, ticket, TMD) pour diagnostiquer avant conversion.

Sert uniquement au diagnostic : la conversion réelle est faite par makerom.
Une erreur « CIA invalide » côté makerom est ainsi expliquée précisément.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

CIA_HEADER_SIZE = 0x2020
CIA_ALIGN = 0x40


class CiaError(Exception):
    pass


@dataclass
class CiaContent:
    content_id: int
    index: int
    type: int
    size: int

    @property
    def encrypted(self) -> bool:
        return bool(self.type & 0x0001)


@dataclass
class CiaInfo:
    header_size: int
    type: int
    version: int
    cert_size: int
    ticket_size: int
    tmd_size: int
    meta_size: int
    content_size: int
    title_id: str = ""
    title_version: int = 0
    ticket_key_id: int = 0
    contents: list[CiaContent] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def encrypted(self) -> bool:
        return any(c.encrypted for c in self.contents)


def _align(value: int, align: int = CIA_ALIGN) -> int:
    return (value + align - 1) // align * align


def read_cia(path: str) -> CiaInfo:
    with open(path, "rb") as fh:
        head = fh.read(CIA_HEADER_SIZE)
        if len(head) < 0x20:
            raise CiaError("Fichier trop court pour être une CIA.")

        hdr_size, cia_type, cia_version, cert, tik, tmd, meta = struct.unpack_from("<IHHIIII", head, 0)
        content_size = struct.unpack_from("<Q", head, 0x18)[0]
        info = CiaInfo(hdr_size, cia_type, cia_version, cert, tik, tmd, meta, content_size)

        if hdr_size != CIA_HEADER_SIZE:
            info.problems.append(
                f"en-tête de 0x{hdr_size:X} octet(s) au lieu de 0x{CIA_HEADER_SIZE:X}"
            )
        if cia_type != 0 or cia_version != 0:
            info.problems.append(
                f"type/version de CIA inattendus ({cia_type}/{cia_version}) au lieu de 0/0"
            )
        if not cert or not tik or not tmd or not content_size:
            info.problems.append("une des tailles d'en-tête (certificats, ticket, TMD, contenus) est nulle")
        if info.problems:
            return info

        tik_off = _align(hdr_size) + _align(cert)
        tmd_off = tik_off + _align(tik)
        content_off = tmd_off + _align(tmd)

        if tik >= 0x2AC:
            fh.seek(tik_off)
            ticket = fh.read(tik)
            if len(ticket) == tik:
                info.ticket_key_id = ticket[0x1F1]
                info.title_id = ticket[0x1DC:0x1E4][::-1].hex().upper()

        fh.seek(tmd_off)
        tmd_data = fh.read(tmd)
        if len(tmd_data) < 0x1404:
            info.problems.append("TMD tronqué")
            return info
        if not info.title_id:
            info.title_id = tmd_data[0x18C:0x194][::-1].hex().upper()
        count = struct.unpack_from("<H", tmd_data, 0x1E8)[0]
        info.title_version = struct.unpack_from("<H", tmd_data, 0x1E6)[0]
        if count == 0 or count > 64:
            info.problems.append(f"nombre de contenus invalide ({count})")
            return info
        if len(tmd_data) < 0x1404 + count * 0x30:
            info.problems.append("table des contenus du TMD tronquée")
            return info
        for i in range(count):
            cid, index, ctype, size = struct.unpack_from("<IHHQ", tmd_data, 0x1404 + i * 0x30)
            info.contents.append(CiaContent(cid, index, ctype, size))

        total = sum(c.size for c in info.contents)
        if total != content_size:
            info.problems.append(
                f"taille des contenus incohérente (annoncée {content_size}, réelle {total})"
            )
        file_size = os.path.getsize(path)
        needed = content_off + content_size
        if file_size < needed:
            info.problems.append(
                f"fichier tronqué ({file_size} octets, {needed} attendus)"
            )
        return info


def describe(path: str) -> tuple[CiaInfo, str]:
    """Retourne (infos, message lisible)."""
    info = read_cia(path)
    if info.contents:
        etat = "contenus chiffrés" if info.encrypted else "contenus en clair"
    else:
        etat = "contenus illisibles"
    lines = [
        f"titre {info.title_id or '?'} · version {info.title_version} · "
        f"{len(info.contents)} contenu(s) · {etat}"
    ]
    if info.problems:
        lines.append("problème(s) : " + " ; ".join(info.problems))
    return info, "\n".join(lines)
