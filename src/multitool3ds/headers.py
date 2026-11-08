"""Structures et parsing des en-têtes NCSD (CCI/.3ds) et NCCH (CXI/CFA).

Portage fidèle de `convertisseur_3ds_cia.py` (Python 2) vers Python 3, avec
parsing explicite (struct) au lieu de ctypes : plus portable (macOS arm64/x86_64)
et testable hors ligne.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MEDIA_UNIT = 0x200

PARTITION_NAMES = (
    "Main",
    "Manual",
    "DownloadPlay",
    "Partition4",
    "Partition5",
    "Partition6",
    "Partition7",
    "UpdateData",
)


class FormatError(Exception):
    """Fichier qui n'est ni un NCSD (.3ds/.cci) ni un NCCH (.cxi/.cfa) lisible."""


@dataclass(frozen=True)
class Partition:
    index: int
    name: str
    offset: int  # octets
    size: int  # octets


@dataclass(frozen=True)
class NcsdHeader:
    title_id: str  # hexadécimal majuscule, ordre lisible (BE)
    partitions: tuple[Partition, ...]
    media_size: int


@dataclass(frozen=True)
class NcchHeader:
    offset: int
    title_id: str  # hexadécimal majuscule (BE), depuis 0x108
    program_id: int  # u64 depuis 0x118 (LE)
    key_y: bytes  # 16 octets (signature)
    product_code: str
    format_version: int  # octet 0x113
    size: int  # octets (ncchSize * MEDIA_UNIT)
    exheader_size: int
    exefs_offset: int  # octets
    exefs_size: int  # octets
    romfs_offset: int
    romfs_size: int
    flags: bytes  # 8 octets (0x188)
    exheader_hash: bytes  # 0x160, SHA-256 de l'exheader en clair

    @property
    def flag7(self) -> int:
        return self.flags[7]

    @property
    def is_decrypted(self) -> bool:
        """Bit 2 de flags[7] : contenu non chiffré (NoCrypto)."""
        return bool(self.flag7 & 0x04)

    @property
    def uses_fixed_key(self) -> bool:
        return bool(self.flag7 & 0x01)

    @property
    def uses_seed_crypto(self) -> bool:
        return bool(self.flag7 & 0x20)

    @property
    def crypto_method(self) -> int:
        return self.flags[3]


def _rev_hex(raw: bytes) -> str:
    return raw[::-1].hex().upper()


def read_ncsd_header(fh) -> NcsdHeader:
    fh.seek(0)
    data = fh.read(0x200)
    if len(data) < 0x200:
        raise FormatError("Fichier trop court pour un en-tête NCSD.")
    if data[0x100:0x104] != b"NCSD":
        raise FormatError("Ce fichier n'est pas un NCSD (.3ds / .cci).")

    media_size = struct.unpack_from("<I", data, 0x104)[0] * MEDIA_UNIT
    title_id = _rev_hex(data[0x108:0x110])

    partitions = []
    for i in range(8):
        off_units, size_units = struct.unpack_from("<II", data, 0x120 + i * 8)
        if off_units:
            partitions.append(
                Partition(
                    index=i,
                    name=PARTITION_NAMES[i],
                    offset=off_units * MEDIA_UNIT,
                    size=size_units * MEDIA_UNIT,
                )
            )
    return NcsdHeader(title_id=title_id, partitions=tuple(partitions), media_size=media_size)


def read_ncch_header(fh, offset: int = 0) -> NcchHeader:
    fh.seek(offset)
    data = fh.read(0x200)
    if len(data) < 0x200:
        raise FormatError("Fichier trop court pour un en-tête NCCH.")
    if data[0x100:0x104] != b"NCCH":
        raise FormatError("Ce fichier n'est pas un NCCH (.cxi / .cfa).")

    size = struct.unpack_from("<I", data, 0x104)[0] * MEDIA_UNIT
    title_id = _rev_hex(data[0x108:0x110])
    program_id = struct.unpack_from("<Q", data, 0x118)[0]
    product_code = data[0x150:0x160].split(b"\x00", 1)[0].decode("ascii", "replace")
    format_version = data[0x112]

    exheader_size = struct.unpack_from("<I", data, 0x180)[0]
    flags = data[0x188:0x190]

    exefs_off_u = struct.unpack_from("<I", data, 0x1A0)[0]
    exefs_size_u = struct.unpack_from("<I", data, 0x1A4)[0]
    romfs_off_u = struct.unpack_from("<I", data, 0x1B0)[0]
    romfs_size_u = struct.unpack_from("<I", data, 0x1B4)[0]

    return NcchHeader(
        offset=offset,
        title_id=title_id,
        program_id=program_id,
        key_y=data[0x00:0x10],
        product_code=product_code,
        format_version=format_version,
        size=size,
        exheader_size=exheader_size,
        exefs_offset=exefs_off_u * MEDIA_UNIT,
        exefs_size=exefs_size_u * MEDIA_UNIT,
        romfs_offset=romfs_off_u * MEDIA_UNIT,
        romfs_size=romfs_size_u * MEDIA_UNIT,
        flags=flags,
        exheader_hash=data[0x160:0x180],
    )


def detect_container(fh) -> str:
    """Retourne 'ncsd', 'ncch' ou lève FormatError."""
    fh.seek(0x100)
    magic = fh.read(4)
    if magic == b"NCSD":
        return "ncsd"
    if magic == b"NCCH":
        return "ncch"
    raise FormatError(
        "Format non reconnu (ni NCSD .3ds/.cci, ni NCCH .cxi/.cfa)."
    )


def iter_ncch(fh):
    """Itère les NCCH d'un fichier NCSD ou d'un NCCH autonome."""
    kind = detect_container(fh)
    if kind == "ncch":
        yield read_ncch_header(fh, 0)
        return
    ncsd = read_ncsd_header(fh)
    for p in ncsd.partitions:
        try:
            yield read_ncch_header(fh, p.offset)
        except FormatError:
            continue
