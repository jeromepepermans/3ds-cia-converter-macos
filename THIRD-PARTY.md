# Composants tiers embarqués

| Composant | Version | Auteur / source | Licence | Rôle |
|---|---|---|---|---|
| `makerom` | 0.19.0 | 3DSGuy — https://github.com/3DSGuy/Project_CTR | dépôt sans fichier de licence explicite ; binaires officiels redistribués tels que publiés | construction des CIA / CCI |
| Python runtime | 3.12.16 | astral-sh/python-build-standalone | Python-2.0 (runtime) / MPL-2.0 (scripts de build) | exécution de l'application |
| Tcl/Tk | 9.0 | Tcl Core Team | BSD-style | interface graphique |
| Code applicatif | — | ce dépôt + TheRinzler65/Convertisseur-3DS-CIA | **GPL-2.0** | logique de conversion |

Sources des binaires (téléchargement direct, SHA-256 vérifié à la construction) :

- `makerom-v0.19.0-macos_arm64.zip` — `ea222647bf362d1aa0d8b7570dc65e7968ce6b3d7b103e9cc815a99698d930e0`
- `makerom-v0.19.0-macos_x86_64.zip` — `a52563e5549cd2dd84e9b8d1cb0d1fdf15ea9bd0f6241e2e178fe4e4bf3a9277`
- `cpython-3.12.16+20261026-aarch64-apple-darwin-install_only.tar.gz`
- `cpython-3.12.16+20261026-x86_64-apple-darwin-install_only.tar.gz`

Formules cryptographiques (AES *keygen* 3DS, disposition des clés) recoupées avec
`pyctr` 0.7.6 (MIT) — aucune ligne de code de pyctr n'est embarquée.
