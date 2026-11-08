"""Interface macOS (Tkinter) du Multitool 3DS.

Quatre modes : .3ds → .cia, .cia → .3ds, déchiffrement, xorpads.
Le travail tourne dans un thread ; l'UI ne reçoit que des messages via une file.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__, converter, crypto, rom, toolchain

APP_NAME = "Multitool 3DS"

MODES = [
    ("to_cia", "3DS → CIA", "Convertit une ROM .3ds/.cci (ou .zip) en .cia installable."),
    ("to_3ds", "CIA → 3DS", "Reconstruit une ROM .3ds depuis une .cia."),
    ("decrypt", "Déchiffrer", "Déchiffre une ROM .3ds/.cci avec votre boot9.bin."),
    ("xorpads", "Xorpads", "Génère ncchinfo.bin pour faire produire les xorpads par la console."),
]

EXTENSIONS = {
    "to_cia": [("ROM 3DS", "*.3ds *.cci *.zip"), ("Tous les fichiers", "*.*")],
    "to_3ds": [("CIA", "*.cia"), ("Tous les fichiers", "*.*")],
    "decrypt": [("ROM / CIA", "*.3ds *.cci *.cia"), ("Tous les fichiers", "*.*")],
    "xorpads": [("ROM 3DS", "*.3ds *.cci"), ("Tous les fichiers", "*.*")],
}


def support_dir() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "multitool-3ds"
    base.mkdir(parents=True, exist_ok=True)
    return base


@dataclass
class Prefs:
    output_dir: str = field(default_factory=lambda: str(Path.home() / "Desktop" / "Multitool 3DS"))
    xorpad_dir: str = field(default_factory=lambda: str(support_dir() / "xorpads"))
    keys_path: str = ""
    mode: str = "to_cia"

    @classmethod
    def load(cls) -> "Prefs":
        path = support_dir() / "prefs.json"
        prefs = cls()
        if path.is_file():
            try:
                data = json.loads(path.read_text("utf-8"))
                for key, value in data.items():
                    if hasattr(prefs, key) and isinstance(value, str):
                        setattr(prefs, key, value)
            except (OSError, ValueError):
                pass
        Path(prefs.output_dir).mkdir(parents=True, exist_ok=True)
        Path(prefs.xorpad_dir).mkdir(parents=True, exist_ok=True)
        return prefs

    def save(self) -> None:
        (support_dir() / "prefs.json").write_text(json.dumps(self.__dict__, indent=2), "utf-8")


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.prefs = Prefs.load()
        self.queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.files: list[Path] = []
        self.running = False

        root.title(APP_NAME)
        root.geometry("1000x720")
        root.minsize(880, 620)

        self._build_styles()
        self._build_header()
        self._build_body()
        self._build_log()
        self._refresh_makerom_state()
        root.after(120, self._drain)

    # -- construction ------------------------------------------------------ #
    def _build_styles(self) -> None:
        style = ttk.Style(self.root)
        if "aqua" in style.theme_names():
            style.theme_use("aqua")
        style.configure("Title.TLabel", font=("Helvetica Neue", 22, "bold"))
        style.configure("Sub.TLabel", font=("Helvetica Neue", 12))
        style.configure("Hint.TLabel", font=("Helvetica Neue", 11))
        style.configure("Go.TButton", font=("Helvetica Neue", 13, "bold"), padding=(14, 8))

    def _build_header(self) -> None:
        header = ttk.Frame(self.root, padding=(20, 16, 20, 6))
        header.pack(fill="x")
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=f"Convertisseur 3DS ↔ CIA · déchiffrement · xorpads — v{__version__}",
            style="Sub.TLabel",
        ).pack(anchor="w")
        self.tool_status = ttk.Label(header, text="", style="Hint.TLabel")
        self.tool_status.pack(anchor="w", pady=(6, 0))

    def _build_body(self) -> None:
        body = ttk.Frame(self.root, padding=(20, 6, 20, 0))
        body.pack(fill="both", expand=True)

        modes = ttk.Frame(body)
        modes.pack(fill="x", pady=(0, 8))
        self.mode_var = tk.StringVar(value=self.prefs.mode)
        for value, label, _hint in MODES:
            ttk.Radiobutton(
                modes, text=label, value=value, variable=self.mode_var, command=self._on_mode
            ).pack(side="left", padx=(0, 18))

        self.hint = ttk.Label(body, text="", style="Hint.TLabel", wraplength=900)
        self.hint.pack(anchor="w", pady=(0, 8))

        columns = ("name", "size")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=8)
        self.tree.heading("name", text="Fichier")
        self.tree.heading("size", text="Taille")
        self.tree.column("name", width=560)
        self.tree.column("size", width=110, anchor="e")
        self.tree.pack(fill="both", expand=True)

        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=8)
        ttk.Button(buttons, text="Ajouter des fichiers…", command=self._add_files).pack(side="left")
        ttk.Button(buttons, text="Retirer", command=self._remove_selected).pack(side="left", padx=6)
        ttk.Button(buttons, text="Tout retirer", command=self._clear_files).pack(side="left")

        self.options = ttk.LabelFrame(body, text="Réglages", padding=12)
        self.options.pack(fill="x", pady=(2, 0))

        self.out_var = tk.StringVar(value=self.prefs.output_dir)
        self.xor_var = tk.StringVar(value=self.prefs.xorpad_dir)
        self.keys_var = tk.StringVar(value=self.prefs.keys_path)

        self.out_row = self._path_row(self.options, "Dossier de sortie", self.out_var, self._pick_out)
        self.xor_row = self._path_row(self.options, "Dossier des xorpads", self.xor_var, self._pick_xor)
        self.keys_row = self._path_row(self.options, "Clés (boot9.bin / keys.txt)", self.keys_var, self._pick_keys)
        self.import_row = ttk.Frame(self.options)
        ttk.Button(
            self.import_row, text="Importer les clés depuis la carte SD…", command=self._import_keys
        ).pack(side="left")
        ttk.Button(self.import_row, text="Aide", command=self._keys_help).pack(side="left", padx=6)

        action = ttk.Frame(body)
        action.pack(fill="x", pady=(10, 0))
        self.go = ttk.Button(action, text="Convertir", style="Go.TButton", command=self._start)
        self.go.pack(side="left")
        ttk.Button(action, text="Ouvrir le dossier de sortie", command=self._open_output).pack(
            side="left", padx=8
        )
        self.progress = ttk.Progressbar(action, mode="indeterminate")
        self.progress.pack(side="left", fill="x", expand=True, padx=(8, 0))

        self._on_mode()

    def _path_row(self, parent, label: str, var: tk.StringVar, command) -> ttk.Frame:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=3)
        ttk.Label(row, text=label, width=28).pack(side="left")
        entry = ttk.Entry(row, textvariable=var)
        entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Choisir…", command=command).pack(side="left", padx=(6, 0))
        return row

    def _build_log(self) -> None:
        frame = ttk.Frame(self.root, padding=(20, 8, 20, 16))
        frame.pack(fill="both")
        self.log_text = tk.Text(frame, height=10, wrap="word", font=("Menlo", 11))
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.log_text.configure(state="disabled")

    # -- état -------------------------------------------------------------- #
    def _refresh_makerom_state(self) -> None:
        found = toolchain.find_makerom()
        if found:
            self.tool_status.configure(text=f"makerom : {found}")
            self.toolchain_ok = True
        else:
            self.tool_status.configure(
                text="makerom introuvable — nécessaire pour les conversions (pas pour le déchiffrement)."
            )
            self.toolchain_ok = False

    def _on_mode(self, *_args) -> None:
        mode = self.mode_var.get()
        self.prefs.mode = mode
        hint = next(h for m, _l, h in MODES if m == mode)
        if mode == "decrypt":
            try:
                keys = crypto.find_keys(self.keys_var.get() or None)
                hint += f"\nClés détectées : {keys.source}"
            except crypto.KeyError_:
                hint += (
                    "\nAucune clé trouvée : GodMode9 → [1:] MEMORY VIRTUAL → boot9.bin → "
                    "A → Copy to 0:/gm9/out, puis « Importer les clés » depuis la carte SD."
                )
        self.hint.configure(text=hint)
        self._show(self.xor_row, mode == "to_cia")
        self._show(self.keys_row, mode == "decrypt")
        self._show(self.import_row, mode == "decrypt")
        labels = {
            "to_cia": "Convertir en CIA",
            "to_3ds": "Convertir en 3DS",
            "decrypt": "Déchiffrer",
            "xorpads": "Générer ncchinfo.bin",
        }
        self.go.configure(text=labels[mode])
        self._refresh_file_list()

    @staticmethod
    def _show(widget, visible: bool) -> None:
        if visible:
            widget.pack(fill="x", pady=4)
        else:
            widget.pack_forget()

    # -- fichiers ---------------------------------------------------------- #
    def _add_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Choisir des fichiers", filetypes=EXTENSIONS[self.mode_var.get()]
        )
        for path in paths:
            p = Path(path)
            if p not in self.files:
                self.files.append(p)
        self._refresh_file_list()

    def _remove_selected(self) -> None:
        for item in self.tree.selection():
            idx = int(self.tree.item(item, "tags")[0])
            if 0 <= idx < len(self.files):
                self.files.pop(idx)
        self._refresh_file_list()

    def _clear_files(self) -> None:
        self.files.clear()
        self._refresh_file_list()

    def _refresh_file_list(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for idx, path in enumerate(self.files):
            try:
                size = f"{path.stat().st_size / 1_048_576:.1f} Mo"
            except OSError:
                size = "—"
            self.tree.insert("", "end", values=(path.name, size), tags=(str(idx),))

    # -- sélecteurs -------------------------------------------------------- #
    def _pick_out(self) -> None:
        path = filedialog.askdirectory(title="Dossier de sortie", initialdir=self.prefs.output_dir)
        if path:
            self.out_var.set(path)
            self.prefs.output_dir = path
            self.prefs.save()

    def _pick_xor(self) -> None:
        path = filedialog.askdirectory(title="Dossier des xorpads", initialdir=self.prefs.xorpad_dir)
        if path:
            self.xor_var.set(path)
            self.prefs.xorpad_dir = path
            self.prefs.save()

    def _pick_keys(self) -> None:
        path = filedialog.askopenfilename(
            title="Fichier de clés (boot9.bin, keys.txt…)",
            filetypes=[("Clés", "*.bin *.txt"), ("Tous les fichiers", "*.*")],
        )
        if path:
            self.keys_var.set(path)
            self.prefs.keys_path = path
            self.prefs.save()

    def _import_keys(self) -> None:
        folder = filedialog.askdirectory(
            title="Carte SD de la console (ou dossier contenant boot9.bin)"
        )
        if not folder:
            return
        self.log(f"Recherche de clés dans {folder}…")
        try:
            found = crypto.import_keys(folder, log=self.log)
        except crypto.KeyError_ as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        if not found:
            messagebox.showwarning(
                APP_NAME,
                "Aucune clé trouvée.\n\n"
                "Sur la carte SD, le fichier doit être dans gm9/out/boot9.bin "
                "(GodMode9 → [1:] MEMORY VIRTUAL → boot9.bin → A → Copy to 0:/gm9/out).",
            )
            return
        boot9 = next((f for f in found if f["kind"] == "boot9"), found[0])
        self.keys_var.set(boot9["dest"])
        self.prefs.keys_path = boot9["dest"]
        self.prefs.save()
        self.log(f"Clés importées : {boot9['dest']}")
        self._on_mode()

    def _keys_help(self) -> None:
        messagebox.showinfo(
            "Obtenir boot9.bin",
            "1. Lancer GodMode9 sur la console (via Luma3DS).\n"
            "2. Choisir le lecteur [1:] MEMORY VIRTUAL.\n"
            "3. Sélectionner boot9.bin → A → « Copy to 0:/gm9/out ».\n"
            "4. Éteindre, monter la carte SD sur le Mac.\n"
            "5. Ici : « Importer les clés depuis la carte SD… ».\n\n"
            "Le fichier fait 32 Ko (0x8000) ou 64 Ko (0x10000).\n"
            "S'il n'apparaît pas dans MEMORY VIRTUAL, GodMode9 est trop ancien "
            "ou n'a pas l'accès boot9 (mettre à jour GodMode9.firm).",
        )

    def _open_output(self) -> None:
        path = self.out_var.get()
        Path(path).mkdir(parents=True, exist_ok=True)
        if sys.platform == "darwin":
            subprocess.Popen(["open", path])
        elif sys.platform.startswith("linux"):
            subprocess.Popen(["xdg-open", path])
        else:
            subprocess.Popen(["explorer", path])

    # -- journal ----------------------------------------------------------- #
    def log(self, message: str) -> None:
        self.queue.put(("log", message))

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "done":
                    self._finish(bool(payload))
        except queue.Empty:
            pass
        self.root.after(120, self._drain)

    def _append_log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # -- exécution --------------------------------------------------------- #
    def _start(self) -> None:
        if self.running:
            return
        if not self.files:
            messagebox.showinfo(APP_NAME, "Ajoutez d'abord au moins un fichier.")
            return

        mode = self.mode_var.get()
        if mode in ("to_cia", "to_3ds") and not getattr(self, "toolchain_ok", False):
            messagebox.showerror(
                APP_NAME,
                "makerom est introuvable.\n\n"
                "L'application embarque normalement son propre makerom ; si le message "
                "persiste, placez un binaire makerom dans ~/3ds-tools/makerom, "
                "puis relancez l'application.",
            )
            return

        self.prefs.output_dir = self.out_var.get()
        self.prefs.xorpad_dir = self.xor_var.get()
        self.prefs.keys_path = self.keys_var.get()
        self.prefs.save()

        settings = converter.Settings(
            output_dir=Path(self.out_var.get()),
            xorpad_dir=Path(self.xor_var.get()),
        )
        files = list(self.files)
        keys_path = self.keys_var.get() or None

        self.running = True
        self.go.configure(state="disabled")
        self.progress.start(12)

        thread = threading.Thread(
            target=self._work, args=(mode, files, settings, keys_path), daemon=True
        )
        thread.start()

    def _work(self, mode: str, files: list[Path], settings, keys_path) -> None:
        ok = True
        try:
            conv = converter.Converter(settings, log=self.log)
            for path in files:
                try:
                    if mode == "to_cia":
                        conv.to_cia(path)
                    elif mode == "to_3ds":
                        conv.to_3ds(path)
                    elif mode == "decrypt":
                        conv.decrypt(path, keys_path)
                    else:
                        conv.build_ncchinfo([path])
                except (converter.ConversionError, rom.RomError, crypto.KeyError_, OSError) as exc:
                    ok = False
                    self.log(f"✖ {path.name} : {exc}")
            self.log("Terminé." if ok else "Terminé avec des erreurs.")
        except Exception as exc:  # noqa: BLE001 - message utilisateur
            ok = False
            self.log(f"✖ Erreur inattendue : {exc}")
        finally:
            self.queue.put(("done", ok))

    def _finish(self, ok: bool) -> None:
        self.running = False
        self.go.configure(state="normal")
        self.progress.stop()


def main() -> int:
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
