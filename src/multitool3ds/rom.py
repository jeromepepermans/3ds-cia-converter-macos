"""Opérations sur les ROM : extraction de partitions, xorpads, déchiffrement NCCH.

Portage de `extract_rom`, `fix_cxi`, `verify_xorpad`, `find_xorpad` du script
d'origine, plus un déchiffrement NCCH autonome (keys + AES-CTR) validé par le
hash de l'exheader.
"""

from __future__ import annotations

import hashlib
import os
import struct
import zipfile
from dataclasses import dataclass

from . import crypto
from .headers import (
    FormatError,
    NcchHeader,
    detect_container,
    read_ncch_header,
    read_ncsd_header,
)
from .ncchinfo import SECTION_EXEFS, SECTION_EXHEADER, SECTION_ROMFS

MEDIA_UNIT = 0x200


class RomError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Xorpads
# --------------------------------------------------------------------------- #


def xor(data: bytes, pad: bytes) -> bytes:
    if len(data) > len(pad):
        raise RomError("Le xorpad est trop petit")
    return bytes(a ^ b for a, b in zip(data, pad))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def xorpad_name(title_id: str, crc32: int) -> str:
    return f"{title_id}.{crc32:08x}.Main.exheader.xorpad"


def find_xorpad(xorpad_dir: str, title_id: str, crc32: int) -> str | None:
    """Cherche un xorpad d'exheader, dans un dossier ou dans les .zip qu'il contient."""
    if not os.path.isdir(xorpad_dir):
        return None
    expected = xorpad_name(title_id, crc32).lower()
    legacy = f"{title_id}.main.exheader.xorpad".lower()

    for entry in sorted(os.listdir(xorpad_dir)):
        path = os.path.join(xorpad_dir, entry)
        if not os.path.isfile(path):
            continue
        low = entry.lower()
        if low.endswith(".xorpad") and low in (expected, legacy):
            return path
        if low.endswith(".zip") and zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if os.path.basename(info.filename).lower() == expected:
                        target = os.path.join(xorpad_dir, xorpad_name(title_id, crc32))
                        with zf.open(info) as src, open(target, "wb") as dst:
                            dst.write(src.read())
                        return target
    return None


def verify_xorpad(fh, ncch_offset: int, xorpad_path: str | None) -> bool:
    """Le xorpad déchiffre-t-il bien l'exheader (SHA-256 de l'en-tête) ?"""
    ncch = read_ncch_header(fh, ncch_offset)
    fh.seek(ncch_offset + 0x200)
    exheader = fh.read(0x400)
    if xorpad_path is not None:
        with open(xorpad_path, "rb") as pad:
            exheader = xor(exheader, pad.read(0x400))
    return sha256(exheader) == ncch.exheader_hash


# --------------------------------------------------------------------------- #
# Extraction / préparation
# --------------------------------------------------------------------------- #


def extract_partitions(path: str, destdir: str) -> list[tuple[int, str]]:
    """Extrait les partitions NCCH d'un NCSD vers destdir (0.cxi, 1.cfa, …)."""
    out: list[tuple[int, str]] = []
    with open(path, "rb") as fh:
        header = read_ncsd_header(fh)
        for part in header.partitions:
            ext = ".cxi" if part.index == 0 else ".cfa"
            target = os.path.join(destdir, f"{part.index}{ext}")
            fh.seek(part.offset)
            with open(target, "wb") as dst:
                remaining = part.size
                while remaining:
                    chunk = fh.read(min(1 << 20, remaining))
                    if not chunk:
                        break
                    dst.write(chunk)
                    remaining -= len(chunk)
            out.append((part.index, target))
    return out


def fix_cxi(path: str, xorpad_path: str | None) -> int:
    """Met le flag SD/carte dans l'exheader et met à jour son SHA-256.

    Retourne la taille de sauvegarde en Ko (utilisée pour la CIA).
    """
    with open(path, "r+b") as fh:
        fh.seek(0x200)
        exheader = bytearray(fh.read(0x400))
        if len(exheader) != 0x400:
            raise RomError("Exheader tronqué.")
        if xorpad_path is not None:
            with open(xorpad_path, "rb") as pad:
                exheader = bytearray(xor(exheader, pad.read(0x400)))

        exheader[0x0D] |= 0x02  # flag "SD application"
        fh.seek(0x160)
        fh.write(sha256(bytes(exheader)))

        save_size = struct.unpack_from("<Q", exheader, 0x1C0)[0] // 1024

        if xorpad_path is not None:
            with open(xorpad_path, "rb") as pad:
                exheader = bytearray(xor(exheader, pad.read(0x400)))
        fh.seek(0x200)
        fh.write(exheader)
    return save_size


def fix_rom_exheader(path: str, ncch_offset: int, xorpad_path: str | None) -> int:
    """Corrige l'exheader *dans* une ROM (copie de travail), pas dans un .cxi extrait.

    Même opération que `fix_cxi` : flag SD (0x0D |= 0x02), SHA-256 recalculé en
    0x160, taille de sauvegarde relue en 0x1C0. Retourne la taille en Ko.
    """
    with open(path, "r+b") as fh:
        fh.seek(ncch_offset + 0x200)
        exheader = bytearray(fh.read(0x400))
        if len(exheader) != 0x400:
            raise RomError("Exheader tronqué.")
        pad = None
        if xorpad_path is not None:
            with open(xorpad_path, "rb") as f:
                pad = f.read(0x400)
            exheader = bytearray(xor(bytes(exheader), pad))

        exheader[0x0D] |= 0x02
        save_size = struct.unpack_from("<Q", exheader, 0x1C0)[0] // 1024
        digest = sha256(bytes(exheader))

        fh.seek(ncch_offset + 0x160)
        fh.write(digest)

        if pad is not None:
            exheader = bytearray(xor(bytes(exheader), pad))
        fh.seek(ncch_offset + 0x200)
        fh.write(exheader)
    return save_size


# --------------------------------------------------------------------------- #
# Déchiffrement NCCH
# --------------------------------------------------------------------------- #

# Méthode de crypto (flags[3]) -> keyslot de la clé « extra » (ExeFS .code, RomFS)
EXTRA_KEYSLOT = {0x00: 0x2C, 0x01: 0x25, 0x0A: 0x18, 0x0B: 0x1B}

SECTION_IDS = {"exheader": SECTION_EXHEADER, "exefs": SECTION_EXEFS, "romfs": SECTION_ROMFS}

EXEFS_PLAIN_FILES = {"icon", "banner"}

ZERO_KEY = bytes(16)
FIXED_SYSTEM_KEY = bytes.fromhex("527CE630A9CA305F3696F3CDE954194B")


@dataclass
class DecryptReport:
    ncch_count: int
    already_clear: int
    profiles_used: set[str]
    warnings: list[str]


def _counter(ncch: NcchHeader, section: int, profile: str) -> int:
    from .ncchinfo import aes_counter

    return int.from_bytes(aes_counter(ncch, section, profile=profile), "big")


def _exheader_key(ncch: NcchHeader, keys: crypto.Keys) -> bytes:
    if ncch.uses_fixed_key:
        return FIXED_SYSTEM_KEY if (ncch.program_id & (0x10 << 32)) else ZERO_KEY
    return keys.normal_key(0x2C, ncch.key_y)


def _try_profile(fh, ncch: NcchHeader, key: bytes, profile: str) -> tuple[bytes, bool]:
    """Déchiffre l'exheader avec un profil de compteur et vérifie son hash."""
    section = SECTION_IDS["exheader"]
    fh.seek(ncch.offset + 0x200)
    cipher = fh.read(0x400)
    stream = crypto.PureAesCtr(key, _counter(ncch, section, profile)).keystream(len(cipher))
    plain = crypto.xor_bytes(cipher, stream)
    return plain, sha256(plain) == ncch.exheader_hash


def decrypt_ncch_file(src_path: str, dst_path: str, keys: crypto.Keys, log=lambda *_: None) -> DecryptReport:
    """Copie `src_path` vers `dst_path` en déchiffrant les NCCH rencontrés."""
    with open(src_path, "rb") as probe:
        kind = detect_container(probe)

    log(f"Copie de {os.path.basename(src_path)}…")
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        remaining = os.path.getsize(src_path)
        while remaining:
            chunk = src.read(min(1 << 20, remaining))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)

    with open(src_path, "rb") as src, open(dst_path, "r+b") as dst:
        if kind == "ncsd":
            ncchs = [
                (p.name, read_ncch_header(src, p.offset))
                for p in read_ncsd_header(src).partitions
            ]
        else:
            ncchs = [("Main", read_ncch_header(src, 0))]

        report = DecryptReport(ncch_count=len(ncchs), already_clear=0, profiles_used=set(), warnings=[])
        for name, ncch in ncchs:
            if ncch.is_decrypted:
                report.already_clear += 1
                log(f"  {name} : déjà en clair (flag NoCrypto).")
                continue

            if ncch.uses_seed_crypto and ncch.crypto_method != 0:
                raise RomError(
                    f"{name} : ce titre utilise le chiffrement par seed (9.6+). "
                    "Le déchiffrement n'est pas pris en charge sans seeddb : utilisez le "
                    "chemin xorpad/GodMode9 pour ce jeu."
                )

            if ncch.uses_fixed_key:
                exheader_key = _exheader_key(ncch, crypto.Keys())
            else:
                exheader_key = _exheader_key(ncch, keys)

            plain, ok = _try_profile(src, ncch, exheader_key, "reference")
            profile = "reference"
            if not ok:
                plain, ok = _try_profile(src, ncch, exheader_key, "legacy")
                profile = "legacy"
            if not ok:
                raise RomError(
                    f"{name} : impossible de valider le déchiffrement (clés incorrectes "
                    "ou ROM protégée). Vérifiez votre boot9.bin."
                )
            report.profiles_used.add(profile)
            log(f"  {name} : clés validées (compteur {profile}).")

            # Exheader
            dst.seek(ncch.offset + 0x200)
            dst.write(plain)

            # ExeFS (.code avec la clé extra, icon/banner avec la clé principale)
            if ncch.exefs_size:
                if ncch.crypto_method == 0 or ncch.uses_seed_crypto:
                    extra_key = exheader_key
                else:
                    extra_key = keys.normal_key(EXTRA_KEYSLOT[ncch.crypto_method], ncch.key_y)

                base = _counter(ncch, SECTION_EXEFS, profile)
                dst.seek(ncch.offset + ncch.exefs_offset)
                header_block = dst.read(0x200)
                header_block = crypto.xor_bytes(
                    header_block, crypto.PureAesCtr(exheader_key, base).keystream(0x200)
                )
                dst.seek(ncch.offset + ncch.exefs_offset)
                dst.write(header_block)

                ranges: list[tuple[int, int, bytes]] = []
                if ncch.exefs_size > 0x200:
                    ranges.append((0x200, ncch.exefs_size - 0x200, exheader_key))
                for i in range(10):
                    entry = header_block[i * 16 : i * 16 + 16]
                    fname = entry[:8].split(b"\x00", 1)[0].decode("ascii", "replace")
                    if not fname:
                        continue
                    off, size = struct.unpack_from("<II", entry, 8)
                    if not size:
                        continue
                    key = exheader_key if fname in EXEFS_PLAIN_FILES else extra_key
                    ranges.append((0x200 + off, size, key))

                for start, size, key in ranges:
                    crypto.decrypt_range(
                        src,
                        dst,
                        ncch.offset + ncch.exefs_offset + start,
                        size,
                        key,
                        (base + (start >> 4)) & ((1 << 128) - 1),
                    )

            # RomFS
            if ncch.romfs_size:
                if ncch.crypto_method == 0 or ncch.uses_seed_crypto:
                    extra_key = exheader_key
                else:
                    extra_key = keys.normal_key(EXTRA_KEYSLOT[ncch.crypto_method], ncch.key_y)
                crypto.decrypt_range(
                    src,
                    dst,
                    ncch.offset + ncch.romfs_offset,
                    ncch.romfs_size,
                    extra_key,
                    _counter(ncch, SECTION_ROMFS, profile),
                )

            # Flag NoCrypto + gel du hash d'exheader déjà corrigé ci-dessus
            dst.seek(ncch.offset + 0x188 + 7)
            flag7 = dst.read(1)[0] | 0x04
            dst.seek(ncch.offset + 0x188 + 7)
            dst.write(bytes([flag7]))

        return report
