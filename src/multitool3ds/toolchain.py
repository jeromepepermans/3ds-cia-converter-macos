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

"""Localisation et exécution de makerom (Project_CTR), le seul binaire requis."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import urllib.request
import zipfile

MAKEROM_VERSION = "makerom-v0.19.0"
MAKEROM_URLS = {
    "arm64": "https://github.com/3DSGuy/Project_CTR/releases/download/makerom-v0.19.0/makerom-v0.19.0-macos_arm64.zip",
    "x86_64": "https://github.com/3DSGuy/Project_CTR/releases/download/makerom-v0.19.0/makerom-v0.19.0-macos_x86_64.zip",
    "linux": "https://github.com/3DSGuy/Project_CTR/releases/download/makerom-v0.19.0/makerom-v0.19.0-ubuntu_x86_64.zip",
}
# SHA-256 des archives officielles (vérifiées le 2026-11-08)
MAKEROM_SHA256 = {
    "arm64": "ea222647bf362d1aa0d8b7570dc65e7968ce6b3d7b103e9cc815a99698d930e0",
    "x86_64": "a52563e5549cd2dd84e9b8d1cb0d1fdf15ea9bd0f6241e2e178fe4e4bf3a9277",
    "linux": "287b809dec064e0ad597e3d272c49ecb7eed41693d5ee6fef9d8a8aa24c2497e",
}


class ToolchainError(Exception):
    pass


def _resource_dir() -> str:
    """Dossier Resources du bundle .app, ou dossier du paquet en développement."""
    here = os.path.dirname(os.path.abspath(__file__))
    # .../Contents/Resources/app/multitool3ds -> .../Contents/Resources
    candidate = os.path.abspath(os.path.join(here, "..", ".."))
    if os.path.isdir(os.path.join(candidate, "tools")):
        return candidate
    # dépôt : src/multitool3ds -> racine
    root = os.path.abspath(os.path.join(here, "..", ".."))
    if os.path.isdir(os.path.join(root, "tools")):
        return root
    return here


def arch_tag() -> str:
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "arm64"
    if platform.system() == "Darwin":
        return "x86_64"
    return "linux"


def candidate_paths() -> list[str]:
    env = os.environ.get("MULTITOOL_MAKEROM")
    paths = []
    if env:
        paths.append(env)
    res = _resource_dir()
    tag = arch_tag()
    paths += [
        os.path.join(res, "tools", tag, "makerom"),
        os.path.join(res, "tools", "makerom"),
        os.path.join(os.path.expanduser("~"), "3ds-tools", "makerom"),
        "/opt/homebrew/bin/makerom",
        "/usr/local/bin/makerom",
        "/usr/bin/makerom",
    ]
    return paths


def find_makerom() -> str | None:
    for path in candidate_paths():
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    found = shutil.which("makerom")
    return found


def ensure_executable(path: str) -> None:
    mode = os.stat(path).st_mode
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def download_makerom(dest_dir: str, log=print) -> str:
    tag = arch_tag()
    if tag not in MAKEROM_URLS:
        raise ToolchainError(f"Pas de binaire makerom pour cette plateforme ({tag}).")
    os.makedirs(dest_dir, exist_ok=True)
    archive = os.path.join(dest_dir, "makerom.zip")
    log(f"Téléchargement de makerom ({tag})…")
    urllib.request.urlretrieve(MAKEROM_URLS[tag], archive)
    digest = hashlib.sha256(open(archive, "rb").read()).hexdigest()
    expected = MAKEROM_SHA256.get(tag)
    if expected and digest != expected:
        os.remove(archive)
        raise ToolchainError(
            f"Archive makerom corrompue (SHA-256 {digest} ≠ {expected}). Réessayez."
        )
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest_dir)
    os.remove(archive)
    target = os.path.join(dest_dir, "makerom")
    if not os.path.isfile(target):
        for root, _dirs, files in os.walk(dest_dir):
            if "makerom" in files:
                target = os.path.join(root, "makerom")
                break
    if not os.path.isfile(target):
        raise ToolchainError("Archive makerom inattendue.")
    ensure_executable(target)
    log(f"makerom installé : {target}")
    return target


def makerom_version(path: str) -> str:
    out = subprocess.run([path], capture_output=True, text=True, timeout=20)
    first = (out.stdout or out.stderr or "").strip().splitlines()
    return first[0] if first else "version inconnue"


def run_makerom(
    path: str, args: list[str], cwd: str | None = None, log=print
) -> tuple[int, list[str]]:
    """Exécute makerom et retourne (code de sortie, lignes de sortie)."""
    log("$ makerom " + " ".join(args))
    proc = subprocess.Popen(
        [path] + args,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert proc.stdout
    lines: list[str] = []
    for line in proc.stdout:
        line = line.rstrip()
        if line:
            lines.append(line)
            log("  " + line)
    return proc.wait(), lines
