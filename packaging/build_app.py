#!/usr/bin/env python3
"""Assemble « Multitool 3DS.app » (universel Apple Silicon + Intel) depuis Linux.

Composants :
- python-build-standalone (astral-sh) : runtime Python 3.12 reproductible, avec Tk ;
- makerom v0.19.0 (Project_CTR) : binaires officiels macOS arm64 et x86_64 ;
- le code du module `multitool3ds` (pur Python).

Usage : python3 packaging/build_app.py [--out dist]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP_NAME = "Multitool 3DS"
BUNDLE_ID = "com.rinzler.multitool3ds"
VERSION = "1.3.0"

PBS_TAG = "20261026"
PBS_VERSION = "3.12.16"
PBS_URLS = {
    "arm64": (
        f"https://github.com/astral-sh/python-build-standalone/releases/download/{PBS_TAG}/"
        f"cpython-{PBS_VERSION}%2B{PBS_TAG}-aarch64-apple-darwin-install_only.tar.gz"
    ),
    "x86_64": (
        f"https://github.com/astral-sh/python-build-standalone/releases/download/{PBS_TAG}/"
        f"cpython-{PBS_VERSION}%2B{PBS_TAG}-x86_64-apple-darwin-install_only.tar.gz"
    ),
}

MAKEROM_URLS = {
    "arm64": "https://github.com/3DSGuy/Project_CTR/releases/download/makerom-v0.19.0/makerom-v0.19.0-macos_arm64.zip",
    "x86_64": "https://github.com/3DSGuy/Project_CTR/releases/download/makerom-v0.19.0/makerom-v0.19.0-macos_x86_64.zip",
}
MAKEROM_SHA256 = {
    "arm64": "ea222647bf362d1aa0d8b7570dc65e7968ce6b3d7b103e9cc815a99698d930e0",
    "x86_64": "a52563e5549cd2dd84e9b8d1cb0d1fdf15ea9bd0f6241e2e178fe4e4bf3a9277",
}

PRUNE_DIRS = [
    "lib/python3.12/test",
    "lib/python3.12/idlelib",
    "lib/python3.12/lib2to3",
    "lib/python3.12/ensurepip",
    "lib/python3.12/turtledemo",
    "lib/python3.12/site-packages/pip",
    "share/man",
    "lib/pkgconfig",
]
PRUNE_SUFFIX = (".a", ".pyc")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> Path:
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  ↓ {url.rsplit('/', 1)[-1]}")
    urllib.request.urlretrieve(url, dest)
    return dest


def prepare_runtime(arch: str, cache: Path) -> Path:
    archive = download(PBS_URLS[arch], cache / f"python-{arch}.tar.gz")
    out = cache / f"runtime-{arch}"
    if (out / "python").is_dir():
        return out / "python"
    out.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tf:
        tf.extractall(out)
    runtime = out / "python"
    for rel in PRUNE_DIRS:
        shutil.rmtree(runtime / rel, ignore_errors=True)
    for path in runtime.rglob("*"):
        if path.is_file() and path.name.endswith(PRUNE_SUFFIX):
            path.unlink()
    return runtime


def prepare_makerom(arch: str, cache: Path) -> Path:
    archive = download(MAKEROM_URLS[arch], cache / f"makerom-{arch}.zip")
    digest = sha256(archive)
    if digest != MAKEROM_SHA256[arch]:
        raise SystemExit(f"SHA-256 inattendu pour makerom {arch}: {digest}")
    out = cache / f"makerom-{arch}"
    if not (out / "makerom").is_file():
        out.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(out)
    binary = out / "makerom"
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return binary


def slim_bin(bin_dir: Path) -> None:
    """Supprime les lanceurs inutiles et remplace les liens par de vrais fichiers.

    Évite toute dépendance à la préservation des liens symboliques par l'outil
    qui décompresse l'archive.
    """
    for name in ("2to3", "2to3-3.12", "idle3", "idle3.12", "pydoc3", "pydoc3.12",
                 "pip", "pip3", "pip3.12", "python3-config", "python3.12-config"):
        (bin_dir / name).unlink(missing_ok=True)
    target = bin_dir / "python3.12"
    if target.is_file():
        for name in ("python3", "python"):
            link = bin_dir / name
            if link.is_symlink() or link.exists():
                link.unlink()
        # un seul exemplaire du binaire (18 Mo), nommé comme le lanceur l'attend
        target.rename(bin_dir / "python3")
        (bin_dir / "python3").chmod(0o755)


def write_launcher(app: Path) -> None:
    launcher = app / "Contents" / "MacOS" / APP_NAME
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text(
        """#!/bin/sh
# Lanceur : choisit le runtime Python correspondant à l'architecture de la machine.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
RES="$HERE/../Resources"
ARCH=$(uname -m)
if [ "$ARCH" != "arm64" ]; then ARCH="x86_64"; fi
export MULTITOOL_MAKEROM="$RES/tools/$ARCH/makerom"
export PATH="$RES/tools/$ARCH:$PATH"
export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1
exec "$RES/runtime/$ARCH/bin/python3" "$RES/app/launch.py"
""",
        encoding="utf-8",
    )
    launcher.chmod(0o755)


def write_plist(app: Path) -> None:
    plist = {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleExecutable": APP_NAME,
        "CFBundleIconFile": "icon.icns",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "CFBundleInfoDictionaryVersion": "6.0",
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
        "NSHumanReadableCopyright": "Portage macOS — code d'origine TheRinzler65 (MIT)",
        "LSApplicationCategoryType": "public.app-category.utilities",
    }
    with open(app / "Contents" / "Info.plist", "wb") as fh:
        plistlib.dump(plist, fh)


def copy_app_code(app: Path) -> None:
    dst = app / "Contents" / "Resources" / "app"
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / "src" / "multitool3ds", dst / "multitool3ds",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (dst / "launch.py").write_text(
        """import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
os.chdir(BASE)

from multitool3ds import gui

if __name__ == "__main__":
    raise SystemExit(gui.main())
""",
        encoding="utf-8",
    )


def copy_docs(app: Path) -> None:
    res = app / "Contents" / "Resources"
    for name in ("README.md", "LICENCE-AMONT.txt", "THIRD-PARTY.md"):
        src = ROOT / name
        if src.is_file():
            shutil.copy2(src, res / name)


def build(out_dir: Path, cache: Path) -> Path:
    app = out_dir / f"{APP_NAME}.app"
    if app.exists():
        shutil.rmtree(app)
    (app / "Contents" / "Resources").mkdir(parents=True)

    print("Runtime Python (python-build-standalone) :")
    for arch in ("arm64", "x86_64"):
        runtime = prepare_runtime(arch, cache)
        target = app / "Contents" / "Resources" / "runtime" / arch
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(runtime, target, symlinks=True)
        print(f"  • {arch} : {du(target):.0f} Mo")

    for arch in ("arm64", "x86_64"):
        slim_bin(app / "Contents" / "Resources" / "runtime" / arch / "bin")

    print("makerom (Project_CTR) :")
    for arch in ("arm64", "x86_64"):
        binary = prepare_makerom(arch, cache)
        target = app / "Contents" / "Resources" / "tools" / arch / "makerom"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, target)
        target.chmod(0o755)
        print(f"  • {arch} : {binary.stat().st_size // 1024} Ko")

    copy_app_code(app)
    copy_docs(app)
    write_launcher(app)
    write_plist(app)

    icon = ROOT / "packaging" / "icon.icns"
    if icon.is_file():
        shutil.copy2(icon, app / "Contents" / "Resources" / "icon.icns")

    return app


def zip_app(app: Path, archive: Path) -> None:
    """Archive en conservant modes et liens symboliques (comme `ditto`/`zip -y`)."""
    import time

    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(app):
            for name in sorted(dirs) + sorted(files):
                path = Path(root) / name
                arc = path.relative_to(app.parent).as_posix()
                if path.is_symlink():
                    info = zipfile.ZipInfo(arc)
                    info.create_system = 3
                    info.external_attr = (0o120777 & 0xFFFF) << 16
                    zf.writestr(info, os.readlink(path))
                elif path.is_dir():
                    info = zipfile.ZipInfo(arc + "/")
                    info.create_system = 3
                    info.external_attr = ((0o40755 & 0xFFFF) << 16) | 0x10
                    zf.writestr(info, b"")
                elif path.is_file():
                    st = path.stat()
                    info = zipfile.ZipInfo(arc)
                    info.create_system = 3
                    info.external_attr = (st.st_mode & 0xFFFF) << 16
                    info.date_time = time.localtime(st.st_mtime)[:6]
                    info.compress_type = zipfile.ZIP_DEFLATED
                    with open(path, "rb") as src, zf.open(info, "w") as dst:
                        shutil.copyfileobj(src, dst)


def du(path: Path) -> float:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            fp = os.path.join(root, name)
            if os.path.isfile(fp) and not os.path.islink(fp):
                total += os.path.getsize(fp)
    return total / 1_048_576


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "dist"))
    parser.add_argument("--cache", default=str(ROOT / ".cache"))
    parser.add_argument("--zip", action="store_true", help="produit aussi l'archive de distribution")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    app = build(out_dir, Path(args.cache))
    print(f"\n{app}  ({du(app):.0f} Mo)")

    if args.zip:
        archive = out_dir / "Multitool-3DS-macOS.zip"
        zip_app(app, archive)
        print(f"{archive}  ({archive.stat().st_size / 1_048_576:.0f} Mo)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
