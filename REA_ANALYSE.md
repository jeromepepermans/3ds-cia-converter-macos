# REA — analyse du dépôt et spécification de la reconstruction macOS

**Objet** : [`TheRinzler65/Convertisseur-3DS-CIA`](https://github.com/TheRinzler65/Convertisseur-3DS-CIA)
**Méthode** : REA (lecture du code réel, exécution des binaires, vérification par oracle)
**Date** : 2026-11-08 · commit analysé : `51014f67` (2024-11-26) · licence amont : **GPL-2.0**

> Convention de lecture : **observé** = lu dans le code ou obtenu en exécutant l'outil ;
> **déduit** = reconstruction à partir de l'observation, non prouvée par un test réel ;
> **inconnu** = non déterminable sans matériel/ROM.

---

## 1. Inventaire observé

| Élément | Contenu |
|---|---|
| `convertisseur_3ds_cia.py` | 639 lignes, **Python 2** (`platform.machine()`, `struct.pack` avec `str`), dépend de `colorama` |
| `multitool_3ds.bat` | menu 5 entrées ; appelle le `.py` et enchaîne deux scripts batch |
| `Batch CIA 3DS Decryptor.bat` | 143 lignes : déchiffrement `.3ds`/`.cia` via `decrypt.exe` + `makerom` |
| `tools/win32`, `tools/win64` | `ctrtool.exe`, `decrypt.exe` (binaire Go strippé), `make_cia.exe` (3DSGuy 2013), `makerom.exe` |
| `xorpads/` | 2 429 fichiers `.xorpad` (9,7 Mo) — **données de jeux**, pas du code |
| `README.md` | menu documenté ; l'entrée « 4. » est vide ; « Linux : prochainement » |

Le dépôt est donc **un script de conversion + un lot de binaires Windows** ; aucune partie du
traitement n'est native macOS.

## 2. Comportement observé, fonction par fonction

### 2.1 `.3ds` → `.cia` (`convertisseur_3ds_cia.py`)

1. `glob("roms/*.3ds|.cia|.zip")` ; les `.zip` sont ouverts et **le CRC32 de l'entrée** sert
   d'identifiant (pas le CRC du fichier écrit).
2. Lecture de l'en-tête NCSD (0x100 = `NCSD`), table de partitions à 0x120 (8 × `offset,size`
   en unités de 0x200), puis de chaque en-tête NCCH (0x100 = `NCCH`).
3. `flags[7] & 0x04` ⇒ ROM déjà en clair, sinon recherche d'un xorpad
   `xorpads/<titleId>.<crc32>.Main.exheader.xorpad` (ou `.zip` contenant ce nom).
4. `verify_xorpad()` : XOR du xorpad sur l'exheader (0x200, 0x400 octets) et comparaison du
   SHA-256 avec le champ 0x160. **C'est l'oracle de validité du dépôt.**
5. `extract_rom()` : chaque partition devient `0.cxi` (index 0) ou `N.cfa`.
6. `fix_cxi()` : force le bit `0x02` (« SD application ») de l'exheader en 0x0D, recalcule le
   SHA-256 en 0x160, relit la taille de sauvegarde (u64 en 0x1C0, en Ko).
7. `make_cia -v -o cia/<nom>.cia --savesize=N --content0=0.cxi --id_0=0 --index_0=0 …`
8. Avertissement si `flags[7] & 0x20` (crypto par *seed*, jeux 9.6+).

### 2.2 `.cia` → `.3ds` (`multitool_3ds.bat`)

`makerom -ciatocci "<rom>.cia"` puis renommage `.cci` → `.3ds` et déplacement dans `.3ds/`.
Aucune vérification de sortie : un échec de `makerom` est silencieux.

### 2.3 Déchiffrement (`Batch CIA 3DS Decryptor.bat`)

- `.3ds` : `decrypt.exe` produit `<nom>.<Partition>.ncch`, puis
  `makerom -f cci -ignoresign -target p -o <nom>-decrypted.3ds -i "<ncch>:<idx>:<idx>" …`
- `.cia` : `ctrtool -tmd` pour lire les *content ids*, `decrypt.exe`, puis `makerom -f cia`
  (patch / DLC détectés par `findstr` sur les préfixes de titre `0004000E` / `0004008C`),
  enfin `-ciatocci` sur la CIA reconstruite.
- Le script contient un `exit` au milieu de la branche `.cia` (ligne 42) : la seconde moitié du
  traitement d'un lot de `.cia` n'est jamais exécutée.

### 2.4 Défauts observés

| # | Défaut | Effet |
|---|---|---|
| 1 | Python 2 uniquement | inutilisable sur macOS récent (pas de Python 2) |
| 2 | `BITS = "64" if platform.machine().endswith("64")` | sur `arm64`, renvoie « 32 » ⇒ mauvais dossier d'outils |
| 3 | `get_tools_path()` ne gère que `win32`/`linux` | renvoie `None` sur macOS ⇒ `TypeError` dans `which()` |
| 4 | `.bat` uniquement, `chcp 65001`, `start`, `findstr` | aucun équivalent POSIX |
| 5 | `decrypt.exe` (Go, Windows) | pas de source dans le dépôt, pas de build macOS |
| 6 | Compteur AES de la branche `formatVersion == 1` | voir §3 : divergence avec la référence, silencieuse |
| 7 | `except` absent autour de `make_cia` | l'échec est signalé mais le fichier partiel reste |
| 8 | Aucun test, aucune journalisation structurée | non vérifiable automatiquement |

## 3. Point technique : deux formules de compteur AES

Le script calcule le compteur AES-CTR du xorpad selon `formatVersion` :

- `v0`/`v2` : `titleId` inversé + `section` en octet 8 ;
- `v1` : `titleId` brut + l'**offset en octets** dans les 4 derniers octets.

La référence matérielle (implémentée par `pyctr`, `citra`, `makerom`) est :
`iv = partition_id << 64 | section << 56`, puis `iv + (offset >> 4)` — **sans dépendre de
`formatVersion`**, avec `partition_id` lu en little-endian en 0x108.

La branche `v1` du script paraît donc fausse (endianness inversée **et** absence du décalage
`>> 4`). On ne peut pas le prouver sans ROM, mais l'outil embarque désormais :

- `profile="reference"` par défaut (formule matérielle) ;
- `profile="legacy"` pour reproduire l'ancien comportement ;
- **auto-vérification** : à l'usage d'un xorpad, le hash d'exheader tranche ; au déchiffrement,
  les deux profils sont essayés et celui qui valide le hash est retenu.

## 4. Reconstruction macOS — décisions

| ID | Décision | Pourquoi | Alternative écartée |
|---|---|---|---|
| D1 | Portage Python 3 du script, GUI **Tkinter** (stdlib), interface FR | zéro dépendance, tourne dans le runtime embarqué | Electron/Qt : +200 Mo, inutile ici |
| D2 | `makerom` v0.19.0 **officiel macOS** (arm64 + x86_64) remplace `make_cia` | binaire publié par l'amont, signé, deux architectures ; `-content fichier:index:id` couvre le besoin | recompiler `make_cia` (Windows/2013), ou réécrire la CIA en Python (crypto non vérifiable) |
| D3 | Déchiffrement réécrit en Python (keygen AES + AES-CTR) au lieu de `decrypt.exe` | `decrypt.exe` est un binaire Windows sans source ; la logique NCCH est documentée | Wine, ou binaire Go à recompiler (Go absent sur macOS par défaut) |
| D4 | Deux backends AES : `openssl` (natif, rapide) et **repli pur Python** | macOS fournit `openssl` ; le repli garantit le fonctionnement hors ligne | dépendance `cryptography` (roues par architecture) |
| D5 | Déchiffrement **validé par l'oracle** (SHA-256 de l'exheader) avant d'écrire | empêche de produire une ROM silencieusement fausse | faire confiance à la clé fournie |
| D6 | Conteneur `.3ds` conservé tel quel au déchiffrement (flag NoCrypto posé) | plus fidèle que le `.bat` (qui reconstruit un CCI) et plus rapide | repasser par `makerom` |
| D7 | `ncchinfo.bin` généré avec la formule de référence | c'est la console qui doit déchiffrer le xorpad, pas l'outil | garder la formule `v1` d'origine |
| D8 | Bundle `.app` **universel** : deux runtimes `python-build-standalone` + deux `makerom`, lanceur qui choisit via `uname -m` | un seul fichier à livrer, aucun prérequis (pas de Python, pas de Homebrew) | `.app` par architecture, ou script d'installation |
| D9 | Reprise de la licence **GPL-2.0** de l'amont | œuvre dérivée | — |

## 4 bis. Correctif v1.1 — pourquoi `-ciatocci` échouait (code 253)

Le `.bat` d'origine appelle `makerom -ciatocci` **sans `-target`**, donc avec le jeu de clés
« test » par défaut. Or `makerom/src/keyset.c` ne charge `ctr_common_etd_key_ppki` (clés
communes **retail**) que pour `pki_PRODUCTION` : avec `-target t`, `GetTikTitleKey()` retourne
`false`, les contenus chiffrés ne peuvent pas être déchiffrés et makerom sort en 253
(`FAILED_TO_IMPORT_FILE` / `INCOMPAT_CIA`). Toute CIA du commerce est donc rejetée.

Correctif : `-ciatocci … -target p -ignoresign` essayé en premier, puis replis `-target p`,
`-ignoresign`, défaut. La CIA est en outre **lue avant** l'appel (`cia.py` : en-tête 0x2020,
ticket 0x350, TMD, contenus) pour remplacer « la CIA est peut-être chiffrée » par un diagnostic
précis (taille incohérente, fichier tronqué, contenus chiffrés ou non).

## 4 ter. Correctif v1.3 — SIGSEGV de makerom à l'assemblage (`code -11`)

Symptôme : `makerom -f cia -content …` meurt par SIGSEGV (code de retour −11, aucune sortie)
sur une ROM à partitions non contiguës (Animal Crossing : partitions 0, 1 et 7). L'ancien
`make_cia` recevait, lui, des index **séquentiels** (0,1,2…) et non les numéros de partition.

Correctif en deux temps :
1. `content_args()` renumérote les contenus 0…n−1 comme `make_cia` ;
2. si l'assemblage échoue encore (plantage ou refus), repli sur `-ccitocia` après correction de
   l'exheader **dans une copie** de la ROM (`fix_rom_exheader`) ;
3. le message d'erreur distingue un plantage (`signal 11`) d'un refus argumenté.

La cause exacte du SIGSEGV n'a pas pu être reproduite ici (fixtures synthétiques rejetées avant
le point de plantage) : l'hypothèse « index troués » est cohérente avec `ProcessContentFiles`
(`contentPath[i]` indexé par l'index fourni) mais reste **déduite**.

## 4 quater. Validation sur machine réelle (2026-11-08)

Conversion **.3ds → .cia** exécutée avec succès par Jérôme sur macOS (Animal Crossing — New Leaf,
ROM déjà déchiffrée, partitions 0/1/7). Le correctif v1.3 (index de contenus séquentiels, repli
`-ccitocia`) a permis la conversion ; le chemin exact retenu par makerom n'a pas été instrumenté,
donc la cause du SIGSEGV reste **attribuée** à l'hypothèse des index troués, non prouvée.

Reste non exercé sur machine réelle : **.cia → .3ds** et **déchiffrement** (validés hors ligne
seulement), ainsi que les ROM chiffrées sans xorpad.

## 5. Ce qui reste inconnu / non vérifié

- **Aucune conversion réelle** n'a été exécutée ici : pas de ROM commerciale, pas de macOS.
  Les commandes `makerom` ont été validées en syntaxe (le binaire atteint la validation de
  contenu et répond `[CIA ERROR] Content 0 Is Corrupt` sur une CXI synthétique), pas en résultat.
- **CIA chiffrée** (contenu AES-CBC avec *titlekey* du ticket) : non déchiffrée. Le chemin
  prévu est `.cia → .3ds` (makerom) **puis** déchiffrement NCCH ; le déchiffrement direct d'une
  CIA eShop reste à faire.
- **Crypto par seed** (jeux 9.6+, `flags[7] & 0x20`) : le déchiffrement s'arrête sur un
  avertissement explicite ; une `seeddb` n'est pas fournie.
- **Équivalence `make_cia` ↔ `makerom`** : même famille de CIA (en-tête 0x2020, ticket, TMD,
  contenus, signature factice) ; l'octet près n'est pas garanti.
- Le contenu de `decrypt.exe` (binaire Go strippé) n'a pas été analysé plus loin que ses
  chaînes ; il n'est pas utilisé.
