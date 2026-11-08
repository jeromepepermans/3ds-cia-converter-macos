"""Jeu de tests hors ligne (aucune ROM requise) : `python3 tests/test_core.py`."""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from multitool3ds import crypto, ncchinfo, rom  # noqa: E402
from multitool3ds.headers import (  # noqa: E402
    detect_container,
    read_ncch_header,
    read_ncsd_header,
)

MEDIA = 0x200
TITLE_ID = 0x0004000000123400
PROGRAM_ID = 0x0004000000123400
KEY_Y = bytes(range(0x10, 0x20))


# --------------------------------------------------------------------------- #
# Fabrique de ROM synthétique
# --------------------------------------------------------------------------- #


def build_ncch(plain_exheader: bytes, exefs_plain: bytes, romfs_plain: bytes, crypto_method: int = 0) -> dict:
    exefs_off = 0x200 + 0x400
    romfs_off = exefs_off + len(exefs_plain)
    total = romfs_off + len(romfs_plain)
    assert exefs_off % MEDIA == 0 and romfs_off % MEDIA == 0

    header = bytearray(MEDIA)
    header[0:0x10] = KEY_Y
    header[0x100:0x104] = b"NCCH"
    header[0x104:0x108] = struct.pack("<I", total // MEDIA)
    header[0x108:0x110] = struct.pack("<Q", TITLE_ID)
    header[0x112] = 0  # formatVersion
    header[0x118:0x120] = struct.pack("<Q", PROGRAM_ID)
    header[0x150:0x158] = b"CTR-TEST"
    header[0x160:0x180] = hashlib.sha256(plain_exheader).digest()
    header[0x180:0x184] = struct.pack("<I", 0x400)
    header[0x188] = 0
    header[0x18B] = crypto_method
    header[0x188 + 7] = 0
    header[0x1A0:0x1A4] = struct.pack("<I", exefs_off // MEDIA)
    header[0x1A4:0x1A8] = struct.pack("<I", len(exefs_plain) // MEDIA)
    header[0x1B0:0x1B4] = struct.pack("<I", romfs_off // MEDIA)
    header[0x1B4:0x1B8] = struct.pack("<I", len(romfs_plain) // MEDIA)

    return dict(
        header=bytes(header),
        exheader=plain_exheader,
        exefs=exefs_plain,
        romfs=romfs_plain,
        exefs_off=exefs_off,
        romfs_off=romfs_off,
        total=total,
        crypto_method=crypto_method,
    )


def encrypt_ncch(ncch: dict, main_key: bytes, extra_key: bytes) -> bytes:
    """Produit le NCCH chiffré (comme sur la cartouche)."""
    blob = bytearray(ncch["header"] + ncch["exheader"] + ncch["exefs"] + ncch["romfs"])
    header = ncch["header"]

    def section_counter(section: int) -> int:
        from multitool3ds.ncchinfo import aes_counter

        hdr = read_ncch_header(_BytesReader(header), 0)
        return int.from_bytes(aes_counter(hdr, section, profile="reference"), "big")

    exheader = bytearray(blob[0x200 : 0x200 + 0x400])
    stream = crypto.PureAesCtr(main_key, section_counter(ncchinfo.SECTION_EXHEADER)).keystream(0x400)
    blob[0x200 : 0x200 + 0x400] = crypto.xor_bytes(bytes(exheader), stream)

    # Toute la région ExeFS est chiffrée avec la clé principale…
    exefs = bytes(ncch["exefs"])
    base = section_counter(ncchinfo.SECTION_EXEFS)
    header_plain = exefs[:0x200]
    enc_exefs = bytearray(
        crypto.xor_bytes(exefs, crypto.PureAesCtr(main_key, base).keystream(len(exefs)))
    )

    # … puis .code est re-chiffré avec la clé « extra ».
    for i in range(10):
        entry = header_plain[i * 16 : i * 16 + 16]
        name = entry[:8].split(b"\x00", 1)[0].decode("ascii", "replace")
        if not name:
            continue
        off, size = struct.unpack_from("<II", entry, 8)
        if name in {"icon", "banner"}:
            continue
        start = 0x200 + off
        data = exefs[start : start + size]
        stream = crypto.PureAesCtr(extra_key, base + (start >> 4)).keystream(size)
        enc_exefs[start : start + size] = crypto.xor_bytes(data, stream)

    blob[ncch["exefs_off"] : ncch["exefs_off"] + len(exefs)] = enc_exefs

    romfs = bytes(ncch["romfs"])
    base_r = section_counter(ncchinfo.SECTION_ROMFS)
    blob[ncch["romfs_off"] : ncch["romfs_off"] + len(romfs)] = crypto.xor_bytes(
        romfs, crypto.PureAesCtr(extra_key, base_r).keystream(len(romfs))
    )
    return bytes(blob)


def build_ncsd(ncch_blob: bytes, offset: int = 0x4000) -> bytes:
    header = bytearray(MEDIA)
    header[0x100:0x104] = b"NCSD"
    header[0x104:0x108] = struct.pack("<I", (offset + len(ncch_blob)) // MEDIA)
    header[0x108:0x110] = struct.pack("<Q", TITLE_ID)
    struct.pack_into("<II", header, 0x120, offset // MEDIA, len(ncch_blob) // MEDIA)
    return bytes(header) + b"\x00" * (offset - MEDIA) + ncch_blob


def exefs_plain() -> bytes:
    code = bytes((i * 7) & 0xFF for i in range(0x600))
    icon = b"ICON" * 0x80
    banner = b"BANNER" + b"\x00" * 0x1A
    header = bytearray(0x200)
    entries = [("code", code), ("icon", icon), ("banner", banner)]
    pos = 0
    for idx, (name, payload) in enumerate(entries):
        struct.pack_into("<8sII", header, idx * 16, name.encode(), pos, len(payload))
        pos += len(payload)
    body = b"".join(payload for _n, payload in entries)
    body += b"\x00" * (0x1000 - 0x200 - len(body))
    return bytes(header) + body


class _BytesReader:
    """Mini objet fichier pour read_ncch_header sur un buffer."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def seek(self, pos: int, whence: int = 0):
        self._pos = pos if whence == 0 else self._pos + pos
        return self._pos

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = len(self._data) - self._pos
        chunk = self._data[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(condition), detail))


def test_headers_and_ncchinfo(tmp: str) -> None:
    plain_ex = bytearray(0x400)
    plain_ex[0x0D] = 0
    struct.pack_into("<Q", plain_ex, 0x1C0, 0x20000)  # 128 Ko de sauvegarde
    ncch = build_ncch(bytes(plain_ex), exefs_plain(), b"\xAA" * 0x1000)
    path = os.path.join(tmp, "test.3ds")
    with open(path, "wb") as fh:
        fh.write(build_ncsd(encrypt_ncch(ncch, b"\x11" * 16, b"\x22" * 16)))

    with open(path, "rb") as fh:
        check("detect NCSD", detect_container(fh) == "ncsd")
        ncsd = read_ncsd_header(fh)
        check("title id NCSD", ncsd.title_id == "0004000000123400", ncsd.title_id)
        check("1 partition", len(ncsd.partitions) == 1)
        hdr = read_ncch_header(fh, ncsd.partitions[0].offset)
        check("magic NCCH + product code", hdr.product_code == "CTR-TEST", hdr.product_code)
        check("non chiffré ?", hdr.is_decrypted is False)
        check("exheader 0x400", hdr.exheader_size == 0x400)

    data, requests = ncchinfo.build_ncchinfo([(path, 0xDEADBEEF)])
    check("ncchinfo taille", len(data) == 16 + 168, str(len(data)))
    check("ncchinfo magie", struct.unpack_from("<I", data, 0)[0] == 0xFFFFFFFF)
    check("ncchinfo version", struct.unpack_from("<I", data, 4)[0] == 0xF0000004)
    check("ncchinfo 1 entrée", struct.unpack_from("<I", data, 8)[0] == 1)
    parsed = ncchinfo.parse_ncchinfo(data)[0]
    check(
        "nom xorpad",
        parsed["name"] == "/0004000000123400.deadbeef.Main.exheader.xorpad",
        parsed["name"],
    )
    check("keyY dans l'entrée", parsed["key_y"] == KEY_Y.hex().upper())
    check("title id entrée", parsed["title_id"] == "0004000000123400", parsed["title_id"])
    check("taille Mb exheader", parsed["size_mb"] == 1, str(parsed["size_mb"]))
    check("1 requête xorpad", len(requests) == 1)


def test_xorpad_flow(tmp: str) -> None:
    plain_ex = bytearray(0x400)
    plain_ex[0x0D] = 0
    struct.pack_into("<Q", plain_ex, 0x1C0, 0x20000)
    ncch = build_ncch(bytes(plain_ex), exefs_plain(), b"\xAA" * 0x1000)
    blob = encrypt_ncch(ncch, b"\x11" * 16, b"\x22" * 16)
    rom_path = os.path.join(tmp, "xor.3ds")
    with open(rom_path, "wb") as fh:
        fh.write(build_ncsd(blob))

    # Le xorpad d'exheader est le flux de clé appliqué à partir de 0x200
    key = b"\x11" * 16
    with open(rom_path, "rb") as fh:
        ncsd = read_ncsd_header(fh)
        off = ncsd.partitions[0].offset
        hdr = read_ncch_header(fh, off)
    counter = int.from_bytes(
        ncchinfo.aes_counter(hdr, ncchinfo.SECTION_EXHEADER, profile="reference"), "big"
    )
    pad = crypto.PureAesCtr(key, counter).keystream(0x400)
    pad_path = os.path.join(tmp, "0004000000123400.deadbeef.Main.exheader.xorpad")
    with open(pad_path, "wb") as fh:
        fh.write(pad)

    with open(rom_path, "rb") as fh:
        check("verify_xorpad OK", rom.verify_xorpad(fh, off, pad_path) is True)
        check("verify_xorpad mauvais pad", rom.verify_xorpad(fh, off, None) is False)

    xdir = os.path.join(tmp, "xorpads")
    os.makedirs(xdir, exist_ok=True)
    with open(os.path.join(xdir, os.path.basename(pad_path)), "wb") as fh:
        fh.write(pad)
    found = rom.find_xorpad(xdir, hdr.title_id, 0xDEADBEEF)
    check("find_xorpad", found is not None)

    # fix_cxi : SD flag + hash recalculé + taille de sauvegarde
    ext = os.path.join(tmp, "0.cxi")
    rom.extract_partitions(rom_path, tmp)
    size_kb = rom.fix_cxi(ext, pad_path)
    check("fix_cxi save size", size_kb == 128, str(size_kb))
    with open(ext, "rb") as fh:
        fixed = read_ncch_header(fh, 0)
        fh.seek(0x200)
        enc = fh.read(0x400)
    dec = rom.xor(enc, pad)
    check("flag SD posé", bool(dec[0x0D] & 0x02))
    check("hash exheader recalculé", hashlib.sha256(dec).digest() == fixed.exheader_hash)
    check("fichier final ré-encrypté", enc != dec)


def test_decrypt(tmp: str) -> None:
    key_x = 0x11223344556677889900AABBCCDDEEFF
    key_y_int = int.from_bytes(KEY_Y, "big")
    main_key = crypto.keygen(key_x, key_y_int)
    extra_x = 0xFFEEDDCCBBAA00998877665544332211
    extra_key = crypto.keygen(extra_x, key_y_int)

    plain_ex = bytearray(0x400)
    plain_ex[0x0D] = 0x01
    struct.pack_into("<Q", plain_ex, 0x1C0, 0x1000)
    ncch = build_ncch(bytes(plain_ex), exefs_plain(), bytes(range(256)) * 8, crypto_method=0x01)
    blob = encrypt_ncch(ncch, main_key, extra_key)

    src = os.path.join(tmp, "enc.3ds")
    with open(src, "wb") as fh:
        fh.write(build_ncsd(blob))

    keys_file = os.path.join(tmp, "keys.txt")
    with open(keys_file, "w") as fh:
        fh.write(f"slot0x2CKeyX={key_x:032X}\nslot0x25KeyX={extra_x:032X}\n")
    keys = crypto.Keys.from_file(keys_file)

    dst = os.path.join(tmp, "dec.3ds")
    report = rom.decrypt_ncch_file(src, dst, keys)
    check("déchiffrement : 1 NCCH", report.ncch_count == 1)

    with open(dst, "rb") as fh:
        data = fh.read()
    off = 0x4000
    hdr = read_ncch_header(_BytesReader(data[off:]), 0)
    check("flag NoCrypto posé", hdr.is_decrypted)

    ok_ex = data[off + 0x200 : off + 0x200 + 0x400] == bytes(plain_ex)
    check("exheader en clair", ok_ex)

    exefs_plain_bytes = exefs_plain()
    start = off + ncch["exefs_off"]
    ok_exefs = data[start : start + len(exefs_plain_bytes)] == exefs_plain_bytes
    check("exefs en clair (.code + icon + banner)", ok_exefs)

    start = off + ncch["romfs_off"]
    ok_romfs = data[start : start + 0x800] == bytes(range(256)) * 8
    check("romfs en clair", ok_romfs)

    # Mauvaises clés → erreur explicite
    bad = os.path.join(tmp, "bad_keys.txt")
    with open(bad, "w") as fh:
        fh.write("slot0x2CKeyX=" + "00" * 16 + "\n")
    try:
        rom.decrypt_ncch_file(src, os.path.join(tmp, "bad.3ds"), crypto.Keys.from_file(bad))
        check("mauvaises clés rejetées", False)
    except rom.RomError as exc:
        check("mauvaises clés rejetées", "clés incorrectes" in str(exc).lower(), str(exc)[:60])


def test_crypto_vectors() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = crypto._encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"), crypto._expand_key(key))
    check("AES-128 vecteur FIPS-197", block.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a")

    # keygen recoupé avec la formule de pyctr 0.7.6
    def rol(v, c, bits=128):
        c %= bits
        v &= (1 << bits) - 1
        return ((v << c) | (v >> (bits - c))) & ((1 << bits) - 1)

    kx, ky = 0x00112233445566778899AABBCCDDEEFF, 0xFFEEDDCCBBAA99887766554433221100
    expected = rol((rol(kx, 2) ^ ky) + 0x1FF9E9AAC5FE0408024591DC5D52768A, 87).to_bytes(16, "big")
    check("keygen == pyctr", crypto.keygen(kx, ky) == expected)

    if crypto.OpenSslAesCtr.available():
        import subprocess

        data = bytes(range(256)) * 64
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ref = subprocess.run(
            ["openssl", "enc", "-aes-128-ctr", "-K", key.hex(), "-iv", iv.hex()],
            input=data,
            capture_output=True,
        ).stdout
        expected_stream = bytes(a ^ b for a, b in zip(data, ref))
        pure = crypto.PureAesCtr(key, int.from_bytes(iv, "big")).keystream(len(data))
        check("CTR pur Python == OpenSSL", pure == expected_stream)
        ossl = crypto.OpenSslAesCtr(key, int.from_bytes(iv, "big")).keystream(len(data))
        check("CTR OpenSSL backend == OpenSSL CLI", ossl == expected_stream)


def build_cia(tmp: str, encrypted: bool = True, truncate: int = 0) -> str:
    """Fabrique une CIA minimale (en-tête + ticket + TMD + un contenu)."""
    import struct as _s

    cert = b"\x00" * 0x100
    ticket = bytearray(0x350)
    ticket[0x1BF:0x1CF] = b"\x11" * 16
    ticket[0x1DC:0x1E4] = _s.pack("<Q", TITLE_ID)
    ticket[0x1F1] = 0
    tmd = bytearray(0x1404 + 0x30)
    tmd[0x18C:0x194] = _s.pack("<Q", TITLE_ID)
    _s.pack_into("<H", tmd, 0x1E6, 0)      # version
    _s.pack_into("<H", tmd, 0x1E8, 1)      # 1 contenu
    _s.pack_into("<IHHQ", tmd, 0x1404, 0x00000001, 0, 1 if encrypted else 0, 0x1000)
    content = b"\xAA" * 0x1000

    hdr = bytearray(0x2020)
    _s.pack_into("<IHHIIIIQ", hdr, 0, 0x2020, 0, 0, len(cert), len(ticket), len(tmd), 0, len(content))

    def align(n):
        return (n + 0x3F) // 0x40 * 0x40

    data = (bytes(hdr) + b"\x00" * (align(0x2020) - 0x2020) + cert)
    data += b"\x00" * (align(len(cert)) - len(cert)) + bytes(ticket)
    data += b"\x00" * (align(len(ticket)) - len(ticket)) + bytes(tmd)
    data += b"\x00" * (align(len(tmd)) - len(tmd)) + content
    if truncate:
        data = data[:-truncate]
    path = os.path.join(tmp, "test.cia")
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def test_cia_parsing(tmp: str) -> None:
    from multitool3ds import cia

    path = build_cia(tmp)
    info = cia.read_cia(path)
    check("CIA : en-tête lue", info.header_size == 0x2020)
    check("CIA : titre", info.title_id == "0004000000123400", info.title_id)
    check("CIA : 1 contenu", len(info.contents) == 1)
    check("CIA : contenus chiffrés", info.encrypted is True)
    check("CIA : aucun problème", not info.problems, " ; ".join(info.problems))

    plain = build_cia(tmp + "/plain", encrypted=False) if os.path.isdir(tmp + "/plain") else None
    if plain:
        check("CIA : contenus en clair", cia.read_cia(plain).encrypted is False)

    bad = build_cia(tmp, truncate=0x800)
    check("CIA tronquée détectée", bool(cia.read_cia(bad).problems))


def test_seed_crypto_refused(tmp: str) -> None:
    key_x = 0x11223344556677889900AABBCCDDEEFF
    main_key = crypto.keygen(key_x, int.from_bytes(KEY_Y, "big"))
    plain_ex = bytearray(0x400)
    ncch = build_ncch(bytes(plain_ex), exefs_plain(), b"\x00" * 0x1000, crypto_method=0x01)
    header = bytearray(ncch["header"])
    header[0x18F] = 0x20  # seed crypto
    ncch["header"] = bytes(header)
    src = os.path.join(tmp, "seed.3ds")
    with open(src, "wb") as fh:
        fh.write(build_ncsd(encrypt_ncch(ncch, main_key, main_key)))

    keys_file = os.path.join(tmp, "keys_seed.txt")
    with open(keys_file, "w") as fh:
        fh.write(f"slot0x2CKeyX={key_x:032X}\n")
    keys = crypto.Keys.from_file(keys_file)

    try:
        rom.decrypt_ncch_file(src, os.path.join(tmp, "seed_dec.3ds"), keys)
        check("seed crypto refusé", False)
    except rom.RomError as exc:
        check("seed crypto refusé", "seed" in str(exc).lower(), str(exc)[:70])


def test_content_args_and_rom_fix(tmp: str) -> None:
    from multitool3ds import converter

    args = converter.content_args([(0, "a.cxi"), (1, "b.cfa"), (7, "c.cfa")])
    check(
        "index de contenus séquentiels (0,1,7 → 0,1,2)",
        args == ["-content", "a.cxi:0:0", "-content", "b.cfa:1:1", "-content", "c.cfa:2:2"],
        str(args),
    )
    check("crash makerom décrit comme signal", "signal 11" in converter._describe_failure(-11, []))

    # fix_rom_exheader sur une ROM chiffrée + xorpad
    key = b"\x11" * 16
    plain_ex = bytearray(0x400)
    struct.pack_into("<Q", plain_ex, 0x1C0, 0x20000)
    ncch = build_ncch(bytes(plain_ex), exefs_plain(), b"\x00" * 0x1000)
    blob = encrypt_ncch(ncch, key, key)
    rom_path = os.path.join(tmp, "fix.3ds")
    with open(rom_path, "wb") as fh:
        fh.write(build_ncsd(blob))

    with open(rom_path, "rb") as fh:
        off = read_ncsd_header(fh).partitions[0].offset
        hdr = read_ncch_header(fh, off)
    counter = int.from_bytes(ncchinfo.aes_counter(hdr, ncchinfo.SECTION_EXHEADER), "big")
    pad = os.path.join(tmp, "fix.xorpad")
    with open(pad, "wb") as fh:
        fh.write(crypto.PureAesCtr(key, counter).keystream(0x400))

    kb = rom.fix_rom_exheader(rom_path, off, pad)
    check("fix_rom_exheader : taille de sauvegarde", kb == 128, str(kb))

    with open(rom_path, "rb") as fh:
        fh.seek(off + 0x200)
        enc = fh.read(0x400)
    dec = rom.xor(enc, crypto.PureAesCtr(key, counter).keystream(0x400))
    check("fix_rom_exheader : flag SD posé", bool(dec[0x0D] & 0x02))
    with open(rom_path, "rb") as fh:
        fh.seek(off)
        fixed_hdr = read_ncch_header(fh, off)
    check("fix_rom_exheader : hash dans l'en-tête", fixed_hdr.exheader_hash == hashlib.sha256(dec).digest())


def test_import_keys(tmp: str) -> None:
    """Import depuis une carte SD simulée (gm9/out/boot9.bin + keys.txt)."""
    sd = os.path.join(tmp, "sdcard")
    os.makedirs(os.path.join(sd, "gm9", "out"), exist_ok=True)
    boot9 = bytearray(0x8000)
    blob = bytearray(0x400)
    blob[0x170 : 0x170 + 16] = bytes(range(16))  # KeyX 0x2C
    boot9[0x5860 : 0x5860 + 0x400] = blob
    with open(os.path.join(sd, "gm9", "out", "boot9.bin"), "wb") as fh:
        fh.write(boot9)
    with open(os.path.join(sd, "gm9", "out", "keys.txt"), "w") as fh:
        fh.write("slot0x25KeyX=" + "AB" * 16 + "\n")

    os.environ["MULTITOOL_KEYS_DIR"] = os.path.join(tmp, "imported")
    found = crypto.import_keys(sd, log=lambda *_: None)
    kinds = {f["kind"] for f in found}
    check("import : boot9 + texte trouvés", kinds == {"boot9", "texte"}, str(kinds))
    check(
        "import : copie dans le dossier de clés",
        all(os.path.isfile(f["dest"]) for f in found),
    )
    keys = crypto.Keys.from_file(os.path.join(tmp, "imported", "boot9.bin"))
    check("import : KeyX 0x2C lisible", 0x2C in keys.key_x, str(sorted(keys.key_x))[:40])
    os.environ.pop("MULTITOOL_KEYS_DIR", None)


def main() -> int:
    test_crypto_vectors()
    with tempfile.TemporaryDirectory() as tmp:
        test_headers_and_ncchinfo(tmp)
        test_xorpad_flow(tmp)
        test_decrypt(tmp)
        test_seed_crypto_refused(tmp)
        os.makedirs(tmp + "/plain", exist_ok=True)
        test_cia_parsing(tmp)
        test_import_keys(tmp)
        test_content_args_and_rom_fix(tmp)

    failures = [r for r in RESULTS if not r[1]]
    for name, ok, detail in RESULTS:
        print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail and not ok else ""))
    print(f"\n{len(RESULTS) - len(failures)}/{len(RESULTS)} tests passés")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
