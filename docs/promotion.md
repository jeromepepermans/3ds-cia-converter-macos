# Promotion — textes prêts à poster

Règles : **un message par communauté**, en anglais, en te présentant comme l'auteur, limites
annoncées. Pas de relance, pas de copier-coller dans 5 fils le même jour. Le seul canal qui amène
du trafic réel ici, ce sont les fils où la question est déjà posée.

## 1. Réponse type à un fil existant (GBAtemp / Reddit)

> For anyone landing here later: I ported this tool to macOS — same pipeline, wrapped in a single
> `.app` (no Python, no Homebrew, no Wine): **https://github.com/jeromepepermans/3ds-cia-converter-macos**
>
> It does 3DS → CIA (with an exheader xorpad, or directly if the ROM is already decrypted),
> CIA → 3DS, ROM decryption, and generates `ncchinfo.bin` for GodMode9. Universal binary
> (Apple Silicon + Intel).
>
> Two honest caveats: the app is not notarized, so first launch needs right-click → Open (or
> `xattr -dr com.apple.quarantine`), and 9.6+ titles using seed crypto are refused for decryption
> (no seeddb bundled). Feedback welcome — especially logs from ROMs that fail, that's how the
> remaining edge cases get fixed.

## 2. Post r/3dshacks (self-post, image + texte)

**Titre** : `I ported the 3DS↔CIA converter to macOS as a self-contained .app (no Python, no Wine)`

> Original Windows tool: TheRinzler65/Convertisseur-3DS-CIA. I rewrote the Python 2 script for
> Python 3, built a Tkinter GUI, and packaged everything — Python runtime and `makerom` 0.19 —
> into one universal `.app` for Apple Silicon and Intel.
>
> **What it does**
> - 3DS → CIA: works with an exheader xorpad, or directly on already-decrypted ROMs; the xorpad is
>   validated against the exheader SHA-256 before anything is written.
> - CIA → 3DS: uses `makerom -target p` (production keys), which is what the original batch was
>   missing — retail CIAs otherwise die with exit code 253.
> - Decrypt: reads `boot9.bin` from `~/3ds-keys/`, verifies the decrypted exheader hash, refuses
>   wrong keys instead of writing a silently broken ROM.
> - Xorpads: generates `ncchinfo.bin` for GodMode9.
>
> **Caveats** — not notarized (right-click → Open the first time); 9.6+ seed-crypto titles are
> refused for decryption; the produced CIAs carry fake signatures, so install on a console running
> Luma3DS. 48 offline tests run in CI on Python 3.10–3.13; the 3DS → CIA path is validated on real
> hardware-level files, CIA → 3DS and decryption are validated offline only.
>
> Code (GPL-2.0, same licence as upstream): https://github.com/jeromepepermans/3ds-cia-converter-macos
>
> I'm the author of the port, not of the original tool. Happy to fix what the logs report.

## 3. Message Discord (fil d'entraide / #homebrew, court)

> Hi — I just released a macOS port of the 3DS↔CIA converter (single `.app`, Python + makerom
> bundled, Apple Silicon & Intel): https://github.com/jeromepepermans/3ds-cia-converter-macos
>
> 3DS → CIA (xorpad or already-decrypted), CIA → 3DS, decrypt with `boot9.bin`, and `ncchinfo.bin`
> generation. Not notarized → right-click → Open on first launch. If a conversion fails, paste the
> log line here, it names the exact makerom error.

## 4. Issue sur le dépôt d'origine

Titre : `macOS port available (Python 3 + .app), if you want to link it`

> Hi, and thanks for the tool — it's the only one that handles the xorpad path cleanly.
>
> I ported it to macOS: the Python 2 script rewritten for Python 3, a Tkinter GUI, and a
> self-contained universal `.app` (Python runtime + `makerom` 0.19 bundled, nothing to install).
> Same pipeline — exheader fix (SD flag + SHA-256), `ncchinfo.bin` generation, decryption verified
> against the exheader hash — plus the reverse conversion and the non-contiguous-partition fix
> (content indices 0,1,7 used to make `makerom` crash).
>
> Repo: https://github.com/jeromepepermans/3ds-cia-converter-macos — GPL-2.0, credits you as the
> original author. Feel free to link it from the README if you think it's useful; no obligation.
>
> Note: the repo's `decrypt.exe` is a stripped Windows binary, so I reimplemented NCCH decryption
> from the format instead of shipping it.

## 5. Fils où la question est déjà posée

À ouvrir dans un navigateur (les dates ne sont pas vérifiables par script : Reddit et GBAtemp
renvoient 403 aux robots). Vérifier que le fil n'est pas verrouillé et que la dernière réponse
date de moins de ~2 ans avant de poster.

| Fil | Lien | Angle |
|---|---|---|
| GBAtemp — « How to convert .3ds to .cia via Mac OSX » | https://gbatemp.net/threads/q-how-to-convert-3ds-to-cia-via-mac-osx.437647 | la question exacte, historique |
| GBAtemp — « Need help with .3ds to .cia conversion (ncchinfo.bin) » | https://gbatemp.net/threads/need-help-with-3ds-to-cia-conversion-ncchinfo-bin.514436 | xorpads : l'onglet Xorpads répond |
| r/Roms — « How to convert .cia rom to .3ds rom on mac? » | https://www.reddit.com/r/Roms/comments/1d2pdnd/ | conversion inverse |
| r/3dspiracy — « How to convert CIA to 3ds on Mac » | https://www.reddit.com/r/3dspiracy/comments/1i2fsxn/ | conversion inverse |
| r/Roms — « Is there a good way to decrypt 3DS roms on a Mac? » | https://www.reddit.com/r/Roms/comments/ne06w1/ | déchiffrement |
| r/Citra — « Convert Cia 3DS games to 3DS roms usable on Citra » | https://www.reddit.com/r/Citra/comments/v8ivuw/ | usage émulateur |
| r/Roms — « Is there a way of converting .3ds files to .cia » | https://www.reddit.com/r/Roms/comments/taccph/ | générique |

Ordre conseillé : (1) issue sur le dépôt d'origine, (2) un fil GBAtemp récent, (3) r/3dshacks en
post autonome, (4) Discord. Espacer de quelques jours et regarder `Insights → Traffic` après
chaque envoi : c'est la seule mesure qui dit quel canal travaille.
