"""Crypto 3DS : keygen AES, AES-128-CTR (OpenSSL CLI ou repli pur Python), clés.

Références : algorithme de keygen et disposition des clés vérifiés sur
pyctr 0.7.6 (MIT) ; constantes de keyslots issues de 3dbrew.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import subprocess
import threading
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Keygen 3DS
# --------------------------------------------------------------------------- #

KEYGEN_CONST = 0x1FF9E9AAC5FE0408024591DC5D52768A
MASK128 = (1 << 128) - 1


def rol(value: int, count: int, bits: int = 128) -> int:
    count %= bits
    mask = (1 << bits) - 1
    return ((value << count) | (value >> (bits - count))) & mask


def keygen(key_x: int, key_y: int) -> bytes:
    """Clé normale = rol(rol(KeyX, 2) ^ KeyY + C, 87) sur 128 bits."""
    mixed = (rol(key_x, 2, 128) ^ key_y) + KEYGEN_CONST
    return rol(mixed & MASK128, 87, 128).to_bytes(16, "big")


# --------------------------------------------------------------------------- #
# AES-128 (repli pur Python, ~40 Ko/s)
# --------------------------------------------------------------------------- #


def _build_tables():
    def xtime(a: int) -> int:
        a <<= 1
        return (a ^ 0x1B) & 0xFF if a & 0x100 else a

    def mul(a: int, b: int) -> int:
        out = 0
        while b:
            if b & 1:
                out ^= a
            a = xtime(a)
            b >>= 1
        return out & 0xFF

    sbox = [0] * 256
    for i in range(256):
        inv = 0
        if i:
            for j in range(1, 256):
                if mul(i, j) == 1:
                    inv = j
                    break
        x = inv
        s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sbox[i] = s ^ 0x63
    return bytes(sbox)


SBOX = _build_tables()
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _expand_key(key: bytes) -> list[bytes]:
    if len(key) != 16:
        raise ValueError("AES-128 : clé de 16 octets attendue")
    w = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return [bytes(sum(w[4 * r : 4 * r + 4], [])) for r in range(11)]


def _encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    s = [b ^ k for b, k in zip(block, round_keys[0])]
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        # ShiftRows (état colonne-major : s[c*4 + r])
        s = [s[((c + r) % 4) * 4 + r] for c in range(4) for r in range(4)]
        if rnd != 10:
            mixed = []
            for c in range(4):
                a = s[4 * c : 4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                mixed.extend(
                    [
                        a[0] ^ t ^ _xtime(a[0] ^ a[1]),
                        a[1] ^ t ^ _xtime(a[1] ^ a[2]),
                        a[2] ^ t ^ _xtime(a[2] ^ a[3]),
                        a[3] ^ t ^ _xtime(a[3] ^ a[0]),
                    ]
                )
            s = mixed
        s = [b ^ k for b, k in zip(s, round_keys[rnd])]
    return bytes(s)


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


class PureAesCtr:
    """AES-128-CTR en Python pur (aucune dépendance). Lent mais portable."""

    name = "python"

    def __init__(self, key: bytes, counter: int):
        self._rk = _expand_key(key)
        self._counter = counter & MASK128

    def keystream(self, length: int) -> bytes:
        out = bytearray()
        ctr = self._counter
        while len(out) < length:
            out += _encrypt_block(ctr.to_bytes(16, "big"), self._rk)
            ctr = (ctr + 1) & MASK128
        self._counter = ctr
        return bytes(out[:length])


class OpenSslAesCtr:
    """AES-128-CTR via le binaire `openssl` (présent sur macOS et Linux).

    Le flux est produit par un thread producteur (zéros sur stdin) pendant que
    le thread appelant consomme stdout : pas d'interblocage, mémoire bornée.
    """

    name = "openssl"
    _path: str | None = None

    def __init__(self, key: bytes, counter: int):
        self._key = key.hex()
        self._iv = counter.to_bytes(16, "big").hex()
        if OpenSslAesCtr._path is None:
            OpenSslAesCtr._path = shutil.which("openssl") or ""
        if not OpenSslAesCtr._path:
            raise RuntimeError("openssl introuvable")

    @classmethod
    def available(cls) -> bool:
        if cls._path is None:
            cls._path = shutil.which("openssl") or ""
        if not cls._path:
            return False
        try:
            out = subprocess.run(
                [cls._path, "enc", "-aes-128-ctr", "-K", "00" * 16, "-iv", "00" * 16],
                input=b"",
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return out.returncode == 0

    def keystream(self, length: int) -> bytes:
        """Flux de clé de `length` octets (utilisé pour les tests)."""
        out = bytearray()
        for chunk in self._iter_keystream(length):
            out += chunk
        return bytes(out)

    def _iter_keystream(self, length: int):
        proc = subprocess.Popen(
            [OpenSslAesCtr._path, "enc", "-aes-128-ctr", "-K", self._key, "-iv", self._iv],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        assert proc.stdin and proc.stdout
        zero = b"\x00" * CHUNK

        def feed():
            try:
                remaining = length
                while remaining:
                    proc.stdin.write(zero[: min(CHUNK, remaining)])
                    remaining -= min(CHUNK, remaining)
            except (BrokenPipeError, ValueError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except (BrokenPipeError, ValueError):
                    pass

        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        try:
            remaining = length
            while remaining:
                data = _read_exactly(proc.stdout, min(CHUNK, remaining))
                if not data:
                    break
                remaining -= len(data)
                yield data
        finally:
            writer.join(timeout=30)
            proc.stdout.close()
            proc.wait()


def make_ctr(key: bytes, counter: int):
    """Meilleur backend disponible pour ce poste."""
    if OpenSslAesCtr.available():
        return OpenSslAesCtr(key, counter)
    return PureAesCtr(key, counter)


def xor_bytes(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --------------------------------------------------------------------------- #
# Clés
# --------------------------------------------------------------------------- #

BOOT9_KEYBLOB_OFFSET = 0x5860  # ARM9 bootrom (0x8000 ou 0x10000 octets)
KEY_X_TABLE_OFFSET = 0x170  # dans le keyblob, commence au keyslot 0x2C


class KeyError_(Exception):
    pass


@dataclass
class Keys:
    key_x: dict[int, int] = field(default_factory=dict)
    normal: dict[int, bytes] = field(default_factory=dict)
    source: str = ""

    # -- chargement -------------------------------------------------------- #
    @classmethod
    def from_file(cls, path: str) -> "Keys":
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) in (0x8000, 0x10000):
            return cls.from_boot9(data, path)
        text = data.decode("utf-8", "replace")
        return cls.from_text(text, path)

    @classmethod
    def from_boot9(cls, boot9: bytes, source: str = "boot9.bin") -> "Keys":
        if len(boot9) == 0x10000:
            boot9 = boot9[0x8000:]
        if len(boot9) != 0x8000:
            raise KeyError_("boot9.bin doit faire 0x8000 ou 0x10000 octets")
        blob = boot9[BOOT9_KEYBLOB_OFFSET : BOOT9_KEYBLOB_OFFSET + 0x400]
        if len(blob) != 0x400:
            raise KeyError_("blob de clés absent de ce boot9.bin")
        keys = cls(source=source)
        pos = KEY_X_TABLE_OFFSET
        for slot in (0x2C, 0x30, 0x34, 0x38):
            value = int.from_bytes(blob[pos : pos + 16], "big")
            for i in range(4):
                keys.key_x[slot + i] = value
            pos += 16
        for i in range(4):
            keys.key_x[0x3C + i] = int.from_bytes(blob[pos : pos + 16], "big")
            pos += 16
        return keys

    @classmethod
    def from_text(cls, text: str, source: str = "keys.txt") -> "Keys":
        keys = cls(source=source)
        pattern = re.compile(r"^\s*(?:slot)?0x([0-9A-Fa-f]{2})\s*(KeyX|KeyY|KeyN|Key|Normal)\s*[=:]\s*([0-9A-Fa-f]{32})", re.M)
        for match in pattern.finditer(text):
            slot = int(match.group(1), 16)
            kind = match.group(2).lower()
            value = int(match.group(3), 16)
            if kind in ("keyx",):
                keys.key_x[slot] = value
            elif kind in ("keyn", "normal", "key"):
                keys.normal[slot] = value.to_bytes(16, "big")
        if not keys.key_x and not keys.normal:
            raise KeyError_(
                "Aucune clé reconnue. Formats acceptés : boot9.bin, ou un fichier "
                "texte avec des lignes du type « slot0x2CKeyX=… »."
            )
        return keys

    # -- accès ------------------------------------------------------------- #
    def has_ncch_keys(self) -> bool:
        return 0x2C in self.key_x or 0x2C in self.normal

    def normal_key(self, slot: int, key_y: bytes) -> bytes:
        if slot in self.normal:
            return self.normal[slot]
        if slot not in self.key_x:
            raise KeyError_(
                f"clé absente : slot 0x{slot:02X} (KeyX). Fournissez boot9.bin ou "
                f"« slot0x{slot:02X}KeyX=… »."
            )
        return keygen(self.key_x[slot], int.from_bytes(key_y, "big"))


def default_key_paths() -> list[str]:
    home = os.path.expanduser("~")
    key_dir = keys_dir()
    paths = [os.path.join(key_dir, "boot9.bin"), os.path.join(home, "boot9.bin")]
    if os.path.isdir(key_dir):
        for entry in sorted(os.listdir(key_dir)):
            low = entry.lower()
            if low.endswith((".bin", ".txt")) and low not in ("boot9.bin",):
                paths.append(os.path.join(key_dir, entry))
    paths += [os.path.join(home, "keys.txt"), os.path.join(home, "aes_keys.txt")]
    return paths


KEYS_DIR_NAME = "3ds-keys"


def keys_dir() -> str:
    path = os.environ.get("MULTITOOL_KEYS_DIR") or os.path.join(
        os.path.expanduser("~"), KEYS_DIR_NAME
    )
    os.makedirs(path, exist_ok=True)
    return path


# Sous-dossiers utiles d'une carte SD de console (recherche bornée, jamais récursive globale)
SD_KEY_PATHS = ("", "gm9/out", "gm9/support", "boot9strap", "luma/payloads", "3ds")


def import_keys(source: str, log=print) -> list[dict]:
    """Importe des clés depuis un fichier ou une carte SD montée.

    Cherche ``boot9.bin`` (0x8000/0x10000 octets) et les fichiers texte contenant
    des ``slot0xNNKeyX``, valide chacun, puis copie dans ``~/3ds-keys/``.
    """
    import shutil as _shutil

    found: list[dict] = []
    candidates: list[str] = []
    if os.path.isfile(source):
        candidates = [source]
    elif os.path.isdir(source):
        for rel in SD_KEY_PATHS:
            base = os.path.join(source, rel)
            if not os.path.isdir(base):
                continue
            try:
                entries = os.listdir(base)
            except OSError:
                continue
            for entry in entries:
                low = entry.lower()
                if low.endswith((".bin", ".txt")):
                    candidates.append(os.path.join(base, entry))
    else:
        raise KeyError_(f"Chemin introuvable : {source}")

    dest_dir = keys_dir()
    for path in candidates:
        name = os.path.basename(path)
        kind = ""
        try:
            size = os.path.getsize(path)
            if size in (0x8000, 0x10000) and name.lower().startswith("boot9"):
                Keys.from_boot9(open(path, "rb").read(), path)
                kind = "boot9"
            elif name.lower().endswith(".txt"):
                Keys.from_text(open(path, "r", encoding="utf-8", errors="replace").read(), path)
                kind = "texte"
            else:
                continue
        except (OSError, KeyError_):
            continue

        dest = os.path.join(dest_dir, name)
        _shutil.copy2(path, dest)
        found.append({"source": path, "dest": dest, "kind": kind, "name": name})
        log(f"   clé importée : {name} → {dest}")
    return found


def find_keys(explicit: str | None = None) -> Keys:
    for path in ([explicit] if explicit else []) + default_key_paths():
        if os.path.isfile(path):
            return Keys.from_file(path)
    raise KeyError_(
        "Aucune clé trouvée.\n\n"
        "Il faut un dump boot9.bin de la console :\n"
        "  GodMode9 → [1:] MEMORY VIRTUAL → boot9.bin → A → Copy to 0:/gm9/out\n"
        "puis placez ce fichier dans ~/3ds-keys/boot9.bin (dossier à créer) "\
        "ou choisissez-le dans le champ « Clés ».\n\n"
        "Un fichier texte contenant « slot0x2CKeyX=… » (+ slot0x25KeyX pour les jeux "
        "post-7.0) fonctionne aussi."
    )


# --------------------------------------------------------------------------- #
# Chiffrement de flux
# --------------------------------------------------------------------------- #

CHUNK = 1 << 20


def _read_exactly(fh, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = fh.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def decrypt_range(src, dst, offset: int, size: int, key: bytes, counter: int) -> None:
    """Déchiffre `size` octets de `src` à `offset` vers `dst` (même position)."""
    if size <= 0:
        return
    src.seek(offset)
    dst.seek(offset)
    if OpenSslAesCtr.available():
        ctr = OpenSslAesCtr(key, counter)
        chunks = ctr._iter_keystream(size)
        remaining = size
        for stream in chunks:
            plain = src.read(len(stream))
            if not plain:
                break
            dst.write(xor_bytes(plain, stream[: len(plain)]))
            remaining -= len(plain)
        if remaining > 0:
            raise RuntimeError("flux de déchiffrement interrompu")
        return

    ctr = PureAesCtr(key, counter)
    remaining = size
    while remaining:
        chunk = src.read(min(CHUNK, remaining))
        if not chunk:
            break
        dst.write(xor_bytes(chunk, ctr.keystream(len(chunk))))
        remaining -= len(chunk)
