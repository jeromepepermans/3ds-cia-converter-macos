# Multitool 3DS — macOS

> **English** — macOS port of *Multitool 3DS* (3DS ↔ CIA conversion, ROM decryption, xorpads).
> Self-contained universal `.app` (Apple Silicon + Intel) bundling its own Python runtime and
> `makerom` 0.19 — nothing to install. Download the `.app` from the **Releases** page.
> GPL-2.0, derivative work of
> [TheRinzler65/Convertisseur-3DS-CIA](https://github.com/TheRinzler65/Convertisseur-3DS-CIA).
> Not affiliated with Nintendo; no keys, no ROMs are provided.

Portage macOS du *Multitool 3DS* de TheRinzler65 : conversion **.3ds ↔ .cia**, déchiffrement de
ROM et génération de **xorpads**. Application unique, sans installation : aucun Python, aucun
Homebrew, aucun outil tiers à télécharger.

## 1. Installer

1. Dézipper `Multitool-3DS-macOS.zip`.
2. Glisser **Multitool 3DS.app** dans le dossier **Applications**.
3. Premier lancement : **clic droit → Ouvrir** (l'application n'est pas signée par un
   développeur identifié par Apple).

Si macOS refuse avec « application endommagée », ouvrez le Terminal et lancez une fois :

```bash
xattr -dr com.apple.quarantine "/Applications/Multitool 3DS.app"
```

> Le paquet contient deux copies du runtime : **Apple Silicon** (`arm64`) et **Intel**
> (`x86_64`). Le lanceur choisit automatiquement selon la machine. Rien à décider.

## 2. Utiliser

Quatre modes, dans la barre du haut.

### 3DS → CIA

1. Ajouter un `.3ds`, `.cci` ou un `.zip` contenant des `.3ds`.
2. Vérifier le **dossier de sortie**.
3. Cliquer **Convertir en CIA**.

Le fichier `.cia` est écrit dans le dossier de sortie. Cas possibles :

- **ROM déjà déchiffrée** (flag `NoCrypto`) : conversion directe.
- **ROM chiffrée** : il faut le **xorpad** de l'exheader. S'il manque, l'application s'arrête en
  le disant et propose l'onglet **Xorpads**.
- Un xorpad **invalide** est refusé : le hash de l'exheader ne correspond pas, donc la ROM serait
  corrompue à l'arrivée.

### CIA → 3DS

Ajouter les `.cia`, cliquer **Convertir en 3DS**. L'application lit d'abord l'en-tête, le ticket
et le TMD de la CIA, puis appelle `makerom` avec les **clés de production** (`-target p`) :
c'est indispensable pour une CIA du commerce, dont le *titlekey* est chiffré avec la clé
commune retail (le réglage par défaut de makerom, « test », échoue avec un code 253).

La ROM obtenue garde le chiffrement NCCH d'origine : pour un émulateur, enchaîner avec
**Déchiffrer** (qui accepte directement une `.cia` et fait la conversion intermédiaire).

### Déchiffrer

Nécessite un fichier de clés, dans cet ordre de préférence :

1. `boot9.bin` (dump de la console, 32 ou 64 Ko) — placé dans `~/3ds-keys/boot9.bin`
   ou choisi via le champ **Clés** ;
2. un fichier texte contenant au minimum `slot0x2CKeyX=…` (et `slot0x25KeyX=…` pour les jeux
   post-7.0).

**Obtenir `boot9.bin`** (le chemin exact, souvent mal indiqué) :

1. GodMode9 sur la console → lecteur **`[1:] MEMORY VIRTUAL`**
   (et **non** `SYSNAND VIRTUAL`, où ce fichier n'existe pas) ;
2. `boot9.bin` → **A** → *Copy to 0:/gm9/out* ;
3. monter la carte SD sur le Mac et cliquer **Importer les clés depuis la carte SD…** :
   l'application cherche `gm9/out/boot9.bin`, le valide (taille 32/64 Ko) et le copie dans
   `~/3ds-keys/`.

Si `boot9.bin` n'apparaît pas dans `MEMORY VIRTUAL` : GodMode9 est trop ancien, ou il n'a pas
l'accès bootrom (mettre à jour `GodMode9.firm`, lancé sous Luma3DS/boot9strap).

Le déchiffrement est **vérifié** : l'exheader déchiffré doit retomber sur son SHA-256 d'origine.
Si les clés sont fausses, l'application s'arrête au lieu de produire une ROM silencieusement
invalide. Sortie : `<nom>-decrypted.3ds`.

### Xorpads

Ajouter les ROM concernées, cliquer **Générer ncchinfo.bin**. Ensuite, sur la console :

1. copier `ncchinfo.bin` à la racine de la carte SD ;
2. GodMode9 → `XORpad options` → `Generate ncchinfo xorpads` (ou Decrypt9 → `ncchinfo padgen`) ;
3. copier les `.xorpad` produits dans le dossier **xorpads** de l'application.

## 3. Réglages

Les chemins (sortie, xorpads, clés) sont mémorisés dans
`~/Library/Application Support/Multitool 3DS/prefs.json`.

`makerom` (v0.19.0, Project_CTR) est **fourni dans l'application**, dans
`Contents/Resources/tools/<arch>/`. Si vous en avez une autre copie, l'application utilise
`MULTITOOL_MAKEROM`, puis `~/3ds-tools/makerom`, puis `PATH`.

## 4. Ligne de commande (optionnelle)

```bash
"/Applications/Multitool 3DS.app/Contents/Resources/runtime/arm64/bin/python3" \
  "/Applications/Multitool 3DS.app/Contents/Resources/app/launch.py"
```

Les sous-commandes existent aussi depuis les sources (`to-cia`, `to-3ds`, `decrypt`,
`ncchinfo`, `--keys`, `-o`, `--xorpads`).

## 5. Limites connues

| Cas | État |
|---|---|
| ROM `.3ds` commerciale chiffrée sans xorpad | refuse la conversion (message explicite) |
| CIA eShop chiffrée (contenu AES-CBC, *titlekey*) | géré : `-target p` puis déchiffrement NCCH ; **Déchiffrer** accepte une `.cia` directement |
| Jeux 9.6+ en crypto *seed* (`flags[7] & 0x20`) | refusé avec message explicite : pas de *seeddb* embarquée |
| ROM > 2 Go | pris en charge (pas de limite 32 bits) |
| Signature des CIA produites | factice : installation sur console avec Luma3DS (patches de signature) |

## 6. Développement

```text
src/multitool3ds/    headers.py  parsing NCSD/NCCH
                     ncchinfo.py génération ncchinfo.bin
                     crypto.py   keygen, AES-CTR (openssl + repli pur Python), clés
                     rom.py      extraction, xorpads, déchiffrement validé
                     converter.py pipelines
                     toolchain.py makerom
                     gui.py      interface Tkinter
tests/test_core.py   32 vérifications hors ligne (aucune ROM requise)
packaging/build_app.py  assemblage du .app universel
```

```bash
python3 tests/test_core.py          # 32/32 attendus
python3 packaging/build_app.py      # construit dist/Multitool 3DS.app
```

## 7. Crédits et licence

- Code d'origine : **TheRinzler65**, `Convertisseur-3DS-CIA` (GPL-2.0), d'après `drizzt`,
  `mid-kid`, `3DSGuy` (`make_cia`), `ArchShift`/`d0k3` (`ncchinfo_gen`).
- `makerom` : **3DSGuy**, *Project_CTR* — binaires officiels macOS v0.19.0.
- Runtime Python : **python-build-standalone** (astral-sh), Python 3.12.
- Vérification crypto : formules recoupées avec **pyctr** (MIT).

Ce portage est distribué sous **GPL-2.0**, comme l'œuvre d'origine (voir `LICENSE`).
L'outil n'est pas affilié à Nintendo ; il ne contourne aucune protection et ne fournit ni clé
ni ROM.
