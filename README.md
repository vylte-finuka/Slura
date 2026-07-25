# Slura OS — Lunée Kernel & Plugin Figma — Spec Pixel-Perfect

**Vyft Ltd · 2026**  
Kernel UEFI `lunee-ker` · Rust `no_std` · `x86_64-unknown-uefi`  
Langage applicatif : **Maratine** (`.mara` → OVC bytecode → interprété par le kernel)

---

## Table des matières

1. [Architecture](#1-architecture)
2. [Langage Mara — Référence complète](#2-langage-mara--référence-complète)
3. [Scaling — Système de coordonnées](#3-scaling--système-de-coordonnées)
4. [API GPU — Référence exhaustive](#4-api-gpu--référence-exhaustive)
5. [Règles critiques pixel-perfect](#5-règles-critiques-pixel-perfect)
6. [Pipeline d'assets Figma](#6-pipeline-dassets-figma)
7. [Plugin TypeScript — Codegen complet](#7-plugin-typescript--codegen-complet)
8. [Patterns UI — Recettes prêtes à l'emploi](#8-patterns-ui--recettes-prêtes-à-lemploi)
9. [Limitations connues et contournements](#9-limitations-connues-et-contournements)
10. [Sécurité](#10-sécurité)
11. [Versionning & Build](#11-versionning--build)
12. [Pipeline de build & test ISO/VM](#12-pipeline-de-build--test-isovm)

---

## 1. Architecture

```
slr_clk_bt/
├── x64/amd64/esp/
│   ├── EFI/BOOT/BOOTX64.EFI     ← Sélecteur de boot UEFI
│   ├── slr_clk_bt.efi            ← Kernel Lunée
│   ├── sources/                  ← Drivers .slul compilés
│   └── SDC/slu64/
│       ├── DrivRequirment/       ← Drivers système
│       ├── apps/                 ← Applications installées
│       └── assets/               ← Polices, images système
├── SluGpu.slul/                  ← Driver GPU (Mara + Rust HAL)
├── SluHIIDMan.slul/              ← Driver HID (clavier/souris), ACPI/UEFI standard
├── SluFontConf.slul/             ← Chargeur polices TTF (stb_truetype)
├── SRFSMan.slul/                 ← Système de fichiers SRFS
├── SluEnvSys.slul/               ← Variables d'environnement
├── CryptoAssetSupport.slul/      ← Wallet crypto
└── ShiLauncher.marep/            ← Launcher principale
crates/vuc-core/lunee-ker/src/
├── ovc_exec.rs                   ← Interpréteur OVC + dispatch DrvAPIInterCon
├── kernel_runtime.rs             ← Boucle de rendu
└── bundle_loader/
    ├── marep_loader.rs           ← Auto-install assets → SDC:/apps/
    ├── slul_loader.rs            ← Chargeur drivers
    └── zip_reader.rs             ← Décompresseur ZIP
```

**Framebuffer GOP UEFI** : 1440 × 1037 pixels (résolution design de référence : 1440 × 1024), ARGB 32 bpp.  
**GPU physique** : Mali-G68 MP2.

---

## 2. Langage Mara — Référence complète

### 2.1 Types

| Type | Description |
|---|---|
| `<i32>` | Entier signé 32 bits — **seul type numérique disponible** |
| `<ptr>` | Pointeur opaque (handles SVG, polices) |
| `string` | Chaîne de caractères littérale |

**Pas de float.** Toute valeur décimale doit être émise en fixed-point entier (×1000 ou ×10000 selon le contexte).

### 2.2 Variables

```mara
let x: <i32> = 42;        // immuable — ne peut pas être réassignée
var y: <i32> = 0;         // mutable — peut être réassignée avec =

let h: <ptr> = nullptr;   // pointeur nul
```

> **Règle** : `var` et `let` ne peuvent être déclarés **qu'à l'intérieur** d'un `rel op` ou `rel cl`.  
> Aucune variable globale n'existe en dehors d'une fonction.

### 2.3 Fonctions

```mara
// rel op = fonction publique (exportée)
rel op NomFonction: [param1 i32, param2 string] [
    let r: <i32> = param1 + 1;
    ret r;
];

// rel cl = closure / fonction locale (non exportée)
rel cl Helper: [x i32] [
    ret x * 2;
];
```

### 2.4 Structures de contrôle

```mara
if (condition) [ ... ];
if (a && b) [ ... ];
if (a || b) [ ... ];

while (1) [
    // boucle infinie
];
```

### 2.5 Appels API kernel

Syntaxe `DrvAPIInterCon` — dispatch direct vers le kernel OVC :

```mara
let result: <i32> = <DrvAPIInterCon***NomFonction***>(arg1, arg2);
let _: <i32> = <DrvAPIInterCon***GpuDrawRect***>(x, y, w, h, color);
```

Le `let _: <i32> = ...` est le pattern standard pour ignorer la valeur de retour.

### 2.6 Interdictions syntaxiques

| Interdit | Alternative |
|---|---|
| `x--` | `x = x - 1` |
| `-0` | `0` |
| Variables globales | Déclarer dans `rel op` |
| Floats | Fixed-point ×1000 |
| `log:` | Pas de log en Mara — utiliser le debug kernel |

### 2.7 Structure d'un `.marep`

```
MonApp.marep/
├── Maraset.yaml            ← Métadonnées + design_size
├── RAbstractallowing.xml   ← Signature AuthARoot
├── base/
│   ├── TemplateView.mara   ← Renderer principal
│   └── Components.mara     ← Un rel op par Component Figma
└── MonApp.slasset/
    ├── img1.png            ← Wallpaper
    ├── img2.png …          ← Icônes (RGBA obligatoire)
    └── vec1.svg …          ← Vecteurs
```

**`TemplateView.mara` doit exposer deux rel op :**

```mara
#base <std***ComTpe***SlulFrmt***[ DrvAPIInterCon ]>;
#base <MaratineKit>;

rel op Render: [ctx string, fnt ptr] [
    // tout le code de rendu ici
    let gpuResult: <i32> = <DrvAPIInterCon***GpuFlushRenderContext***>(ctx);
    if (gpuResult != 0) [ ret 1; ];
    ret 0;
];

rel op Destroy: [] [ ret 0; ];
```

### 2.8 Cycle de vie réel d'une app — `LAPrevent::Launch` se réexécute À CHAQUE FRAME

**Fait contre-intuitif mais vérifié empiriquement** (journal série QEMU/VMware) : `rel op Launch` d'une `.marep` n'est **pas** exécuté une seule fois pour la durée de vie de l'app. Chaque frame noyau relance la chaîne complète depuis `OEntry` :

```
[CM] TemplateView::Destroy
[FN] TemplateView::Destroy
[OVC] exec_marep done
[OVC] exec_marep start        ← nouvelle frame, tout redémarre ICI
[OVC] constructors start
[FN] LAPrevent::LAPrevent
[OVC] OEntry start
[FN] OEntry::OEntry
[CM] LAPrevent::Launch        ← Launch() s'exécute À NOUVEAU
[FN] LAPrevent::Launch
```

Le `loop (running) [ ... TemplateView***Render ... ]` à l'intérieur de `Launch` ne fait en réalité tourner **qu'un seul** `Render` avant que `ret 1` (retourné par `GpuFlushRenderContext != 0`) ne mette fin à la boucle — le noyau lui-même rappelle alors `exec_marep` depuis zéro pour la frame suivante.

**Conséquence critique** : tout code placé dans `Launch`, AVANT la boucle, en pensant qu'il ne s'exécute "qu'une fois au lancement" s'exécute en fait **à chaque frame**. Lire `WindowManGetLaunchArg` de cette façon (pattern historique de ce projet, maintenant corrigé — voir §4.9) redéclenchait la même action à l'infini, rendant impossible toute navigation ultérieure.

**Règle** : toute logique qui ne doit s'exécuter qu'une fois par événement (pas par frame) doit vivre **dans `TemplateView***Render`** (qui tourne aussi chaque frame, mais où l'état persistant via `SCROLL_SCRATCH` — voir §2.9 — permet un vrai edge-detect), jamais comme un "one-shot avant la boucle" dans `LAPrevent.mara`.

### 2.9 Persistance d'état entre frames — `SCROLL_SCRATCH`

Les variables locales `let`/`var` ne survivent PAS d'une frame à l'autre (voir §2.8 — tout redémarre). Le seul mécanisme de persistance inter-frames pour les valeurs numériques est un tableau **global au noyau**, 64 emplacements `i64`, partagé par TOUTES les apps/drivers en cours d'exécution :

```mara
let v: <i32> = <DrvAPIInterCon***ScrollGet***>(slot);
let _: <i32> = <DrvAPIInterCon***ScrollSet***>(slot, newValue);
```

(Les variables `<string>` de classe dans `LAPrevent.mara` persistent aussi, par un mécanisme séparé — mais pas les `<ptr>`, non propagés depuis `self***`.)

**⚠️ RÈGLE CRITIQUE — allocation des slots** : `SCROLL_SCRATCH` est un tableau **unique pour tout le système**, pas par-app. Deux apps qui tournent en même temps (le dock `ShiLauncher` tourne TOUJOURS en parallèle de n'importe quelle autre app ouverte) et qui utilisent le même slot pour des sémantiques différentes se marchent dessus silencieusement. Avant d'utiliser un nouveau slot dans un fichier `.mara`, **documenter en commentaire l'allocation complète connue** (voir l'en-tête de `ShiLooker.marep/base/TemplateView.mara` pour un exemple) et vérifier qu'aucun autre fichier actif en parallèle ne l'utilise déjà.

Allocation connue à ce jour (non exhaustive — toujours vérifier le fichier lui-même) :

| Slot(s) | Propriétaire | Usage |
|---|---|---|
| 1–6, 16 | `ShiLooker.marep/TemplateView.mara` | Navigation colonne droite, edge-detect, génération launch_arg |
| 8 | `ShiLauncher.marep/ContextMenu.mara` | Edge-detect clic du menu contextuel du dock |
| 9–10 | `ShiLauncher.marep/ContextMenu.mara` | Ancre (x, y) du sous-menu flottant (ex: "System power") |
| 12 | `SluWWANManSrv.marep/TemplateView.mara` | Edge-detect clic |
| 15 | `ShiLooker.marep/TemplateView.mara` | Génération du dernier clic traité sur le menu contextuel générique (GlobalMenu mode contexte — remplace FolderMenu.mara, supprimé) |
| 20–25 | `ShiLooker.marep/TemplateView.mara` | Intégration VMware (TBD) |
| 26–29 | `ShiLooker.marep/TemplateView.mara` | Menu Photo/Video (26), enregistrement vidéo (27), throttle capture (28), tick "photo saved" (29) |
| 30 | `ShiLooker.marep/TemplateView.mara` | Edge-detect clic du badge dossier (widget ShiCamera) |
| 31 | `ShiLooker.marep/CaptureFolderPicker.mara` | Edge-detect clic du sélecteur de dossier de capture |
| 40+n | `ShiLauncher.marep/TemplateView.mara` | Compteur d'appui long par icône du dock (n = index registre) |
| 48 | Partagé (toute app avec menu contextuel interne, ex: `ShiLooker.marep/TemplateView.mara`) | Flag "ce clic droit a déjà ouvert un menu contextuel plus spécifique" — lu par `ShiLauncher.marep/LAPrevent.mara` avant d'ouvrir GlobalMenu, remis à 0 chaque tick |
| 49+wi | `ShiLauncher.marep/LAPrevent.mara` | Edge-detect clic droit du menu global "in-app" (par fenêtre `wi`) — clic droit n'importe où dans une app, plus de bouton dédié |
| 50 | `ShiLauncher.marep/GlobalMenu.mara` | Edge-detect clic gauche du menu global |

---

## 3. Scaling — Système de coordonnées

### 3.1 Principe

Slura OS tourne sur plusieurs résolutions d'écran. Le design Figma est exporté à `1440 × 1024` px. À l'exécution, toutes les coordonnées sont scalées proportionnellement.

```mara
let sw: <i32> = <DrvAPIInterCon***GpuGetWidth***>();
let sh: <i32> = <DrvAPIInterCon***GpuGetHeight***>();
let sW: <i32> = (sw * 1000) / 1440;   // facteur horizontal ×1000
let sH: <i32> = (sh * 1000) / 1024;   // facteur vertical ×1000
```

### 3.2 Formule de scaling (arrondi au plus proche)

```
coord_écran = (valeur_design × scale + 500) / 1000
```

**Exemples :**
```mara
// x=526 design → écran
let x: <i32> = ((526 * sW + 500) / 1000);

// Rayon moyen (évite la distorsion)
let r: <i32> = (((30 * sW + 500) / 1000 + (30 * sH + 500) / 1000) / 2);
```

### 3.3 Fill-screen vs Fit-screen

| Mode | Formule | Usage |
|---|---|---|
| **fill-screen** | `sW = sw*1000/1440`, `sH = sh*1000/1024` (indépendants) | Wallpaper PNG — couvre sans bandes noires |
| **fit-screen uniforme** | `scale = min(sW, sH)` + offset centrage | UI overlay — préserve proportions Figma |

Pour le wallpaper plein écran :
```mara
let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, 0, 0, sw, sh);
```

### 3.4 Plugin TypeScript — Scaling

```typescript
const sW = (screenW * 1000) / 1440;
const sH = (screenH * 1000) / 1024;
const sc = (v: number, axis: 'x' | 'y') =>
    Math.floor((v * (axis === 'x' ? sW : sH) + 500) / 1000);
const scR = (r: number) =>
    Math.floor(((r * sW + 500) / 1000 + (r * sH + 500) / 1000) / 2);

// Emit dans le code Mara :
// `((${vDesign} * sW + 500) / 1000)` pour x/w
// `((${vDesign} * sH + 500) / 1000)` pour y/h
// `(((${r} * sW + 500) / 1000 + (${r} * sH + 500) / 1000) / 2)` pour r
```

---

## 4. API GPU — Référence exhaustive

### 4.1 Contrôle d'état (stateful — persistent jusqu'au Reset)

#### `GpuSetOpacity(alpha i32)` / `GpuResetOpacity()`

```mara
let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(77);    // 30%
// draws...
let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();
```

**Sémantique SET** — remplace l'opacité courante, pas de stack.  
**Effet** : `final_alpha = (color_alpha * GPU_OPACITY) / 255`  
**⚠️ DOUBLE-ALPHA** : voir §5.1.

---

#### `GpuSetTransform2D(cosA, sinA, negSinA, cosB, cx, cy)` / `GpuResetTransform()`

```mara
// Rotation 46° autour du centre de l'élément
let _: <i32> = <DrvAPIInterCon***GpuSetTransform2D***>(6947, 7193, -7193, 6947, cx, cy);
// draws...
let _: <i32> = <DrvAPIInterCon***GpuResetTransform***>();
```

- Valeurs en **fixed-point ×10000** : `cos(46°)=6947`, `sin(46°)=7193`
- `cx`, `cy` = **pivot = centre de l'élément en pixels écran** (post-scale)
- La translation interne est calculée par le kernel :  
  `tx = (cx*(10000-cosA) + cy*sinA) / 10000`  
  `ty = (cy*(10000-cosA) - cx*sinA) / 10000`
- Appliqué à tous les draws jusqu'à `GpuResetTransform()`

**Angles prédéfinis :**

| Angle | cos (×10000) | sin (×10000) |
|---|---|---|
| 0° | 10000 | 0 |
| 45° | 7071 | 7071 |
| 46° (dock diamonds) | 6947 | 7193 |
| 90° (ShiContacts) | 0 | 10000 |
| 135° | -7071 | 7071 |

**⚠️ FORWARD TRANSFORM GAPS** : voir §5.3.

---

#### `GpuSetBlendMode(mode i32)` / `GpuResetBlendMode()`

| mode | Nom | Formule |
|---|---|---|
| 0 | NORMAL (défaut) | `src·α + dst·(1−α)` |
| 1 | MULTIPLY | `src·dst/255` |
| 2 | SCREEN | `1−(1−src)(1−dst)` |
| 3 | OVERLAY | Multiply si dst<128, Screen sinon |
| 4 | DARKEN | `min(src, dst)` |
| 5 | LIGHTEN | `max(src, dst)` |
| 6 | COLOR_DODGE | `dst / (1−src)` |
| 7 | COLOR_BURN | `1 − (1−dst) / src` |
| 8 | HARD_LIGHT | Overlay inversé |
| 9 | SOFT_LIGHT | Formule Pegtop |
| 10 | DIFFERENCE | `\|src − dst\|` |
| 11 | EXCLUSION | `src + dst − 2·src·dst` |

---

### 4.2 Primitives de dessin

#### `GpuDrawRect(x, y, w, h, color)` → `i32`
Rectangle plein ARGB. GPU_OPACITY et GPU_TRANSFORM appliqués.

#### `GpuDrawRoundedRectAlpha(x, y, w, h, r, color)` → `i32`
Rectangle arrondi avec Porter-Duff alpha blending.  
`color` = ARGB 0xAARRGGBB. `r` = rayon de coin uniforme (tous les 4 coins).  
GPU_OPACITY appliqué : `final_alpha = (color_alpha * GPU_OPACITY) / 255`.

#### `GpuDrawRoundedRectFull(x, y, w, h, rTL, rTR, rBL, rBR, color)` → `i32`
Coins arrondis **individuellement**. Utiliser quand Figma exporte des `cornerRadius` asymétriques.

#### `GpuDrawRoundedRectSolid(x, y, w, h, r, color)` → `i32`
Identique à `GpuDrawRoundedRectAlpha` mais force alpha=255.

#### `GpuDrawEllipse(x, y, w, h, color)` → `i32`
Ellipse pleine ARGB. Porter-Duff alpha blending.

#### `GpuFill(color)` → `i32`
Remplit tout le framebuffer. Utilisé comme fond avant le premier draw.

---

### 4.3 Images

#### `ImageLoad(path string)` → `i32`
Charge un PNG depuis SRFS. Retourne un handle `i32` (1–8, cache LRU).  
Chemin : `"SDC:/apps/<AppName>/<AppName>.slasset/imgN.png"`

**Cache LRU 8 slots.** Toujours réutiliser une seule `var im: <i32> = 0`.

```mara
// CORRECT
var im: <i32> = 0;
im = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/App/App.slasset/img1.png");
let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, ...);
im = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/App/App.slasset/img2.png");
let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, ...);
```

#### `ImageDraw(handle, x, y, drawW, drawH)` → `i32`
Blit nearest-neighbour + Porter-Duff Over.  
GPU_OPACITY module le canal alpha PNG : `a = png_alpha * GPU_OPACITY / 255`.  
**⚠️ PNG SANS ALPHA** : voir §9.2.

#### `GpuDrawRotatedImage(handle, cx, cy, dw, dh, angleDeg)` → `i32`
Dessin d'image avec rotation par inverse mapping (anticrénelage naturel, pas de trous).  
`cx`, `cy` = centre de l'image sur l'écran. `angleDeg` = angle en degrés.  
**Préférer à `GpuSetTransform2D + ImageDraw` pour les images — résultat sans gaps.**

---

### 4.4 Texte

#### `FontLoad(path string)` → `ptr`
Charge une police TTF depuis SRFS.  
**⚠️ APPELER DIRECTEMENT dans `rel op Render`** — ne jamais utiliser le paramètre `fnt` du kernel (null au démarrage, SRFS_CACHE vide).

```mara
// CORRECT — toujours en début de Render
let font: <ptr> = <DrvAPIInterCon***FontLoad***>("SDC:/slu64/assets/fonts/brsonomasemibold.ttf");
```

#### `GpuDrawTextFont(x, y, text, fgColor, bgColor, fontHandle, size)` → `i32`
Texte aligné à gauche.

#### `GpuDrawTextFontAlign(x, y, maxW, text, fgColor, bgColor, fontHandle, size, align)` → `i32`
Texte avec alignement dans une largeur max.  
`align` : 0=gauche 1=centre 2=droite.

#### `GpuDrawTextFontFull(x, y, text, fgColor, bgColor, fontHandle, size, letterSp, lineH, align, deco)` → `i32`
Texte complet. `letterSp`=espacement lettres en px. `lineH`=hauteur de ligne en px.  
`deco` : 0=aucun 1=souligné 2=barré.

---

### 4.5 SVG

#### `SvgLoad(path string)` → `ptr`
Charge un SVG depuis SRFS. Handle `<ptr>` (pas `<i32>`).

#### `SvgDraw(handle, x, y, w, h)` → `i32`
Rend le SVG mis à l'échelle pour remplir (w × h).

#### `SvgFree(handle)` → `i32`
Libère le slot SVG du cache kernel.

**⚠️ SUPPORT SVG PARTIEL** : voir §9.3.

---

### 4.6 Effets visuels

#### `GpuBackgroundBlur(x, y, w, h, r, sigma)` → `i32`
Flou gaussien (box blur 3 passes) en place sur le framebuffer courant.  
`r` = rayon de coin de clip (0 = rectangle). `sigma` = rayon du flou [1–16].

**⚠️ ORDRE OBLIGATOIRE** : appeler **avant** le tint/overlay. Le blur opère sur les pixels déjà rendus.

```mara
// CORRECT — blur d'abord, tint ensuite
let _: <i32> = <DrvAPIInterCon***GpuBackgroundBlur***>(x, y, w, h, r, 8);
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(x, y, w, h, r, 0xFFE0E0E0);

// FAUX — tint d'abord, blur ensuite (le fill est incorporé dans le blur)
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(x, y, w, h, r, 0xFFE0E0E0); // ← ERREUR
let _: <i32> = <DrvAPIInterCon***GpuBackgroundBlur***>(x, y, w, h, r, 8);
```

#### `GpuDrawDropShadow(x, y, w, h, cr, ox, oy, blur, color)` → `i32`
Ombre portée avec box blur.  
**⚠️ ARTEFACT box_blur** : le blur s'étend hors de la zone (`sx-blur, sy_-blur`). Visible comme bande sombre rectangulaire si `blur ≥ oy`.  
**→ Préférer `GpuDrawGlow` ou `GpuDrawLinearGradient` pour les shadows dock/card** — voir §9.4.

#### `GpuDrawGlow(x, y, w, h, r, glowColor, glowRadius, intensity)` → `i32`
Lueur extérieure SDF + falloff linéaire. **Aucun artefact.**  
`glowColor` = ARGB (canal alpha ignoré — `intensity` contrôle l'opacité).  
`glowRadius` = rayon en pixels screen. `intensity` [0–255] = opacité max à l'arête.  
**Ignoré par GPU_OPACITY** — indépendant du contexte GpuSetOpacity.  
**Symétrique** (haut+bas+côtés). Pour shadow directionnelle : utiliser `GpuDrawLinearGradient`.

#### `GpuDrawLinearGradient(x, y, w, h, r, angleDeg, c1, p1, c2, p2, stopCount)` → `i32`
`angleDeg` : 0=gauche→droite, -90=haut→bas, 90=bas→haut, 180=droite→gauche.  
`c1/c2` = ARGB. `p1/p2` = position [0–1000]. `stopCount` = 2.

**Shadow directionnelle sous un élément (bas uniquement) :**
```mara
// Bande gradient de 12px sous le dock — aucun artefact
let _: <i32> = <DrvAPIInterCon***GpuDrawLinearGradient***>(
    dkX, (dkY + dkH), dkW, 12, 0, -90,
    0x30000000, 0, 0x00000000, 1000, 2
);
```

#### `GpuDrawRadialGradient(x, y, w, h, radius, c1, p1, c2, p2, stopCount)` → `i32`
Gradient radial centré sur le rect. `radius` = rayon en pixels.

#### `GpuDrawNoisePatch(x, y, w, h, r, alpha, seed)` → `i32`
Bruit grain xorshift procédural. `alpha` [0–255] = opacité du grain. `seed` = graine initiale.

#### `GpuDrawGrainNoise(x, y, w, h, radius, color, grainSize)` → `i32`
Bruit hash déterministe. `color` = ARGB. `grainSize` : 1=ultra-fin, 2=fin, 4=grossier.

#### `GpuDrawStroke(x, y, w, h, r, weight, color)` → `i32`
Contour rectangle arrondi. `weight` = épaisseur. `color` = ARGB.

---

### 4.7 Masques et clip

#### `GpuPushClip(x, y, w, h [, r])` / `GpuPopClip()`
Empile une zone de clip arrondie. Tous les draws suivants sont clippés à cette zone.

---

### 4.8 Ordre de rendu standard

```
1. ImageDraw(wallpaper, 0, 0, sw, sh)                  ← fond plein écran
2. GpuDrawLinearGradient(shadow strip)                  ← ombres directionnelles
3. GpuDrawGlow(dock/card bounds)                        ← halo symétrique
4. GpuBackgroundBlur → GpuSetOpacity → GpuDrawRoundedRectAlpha → GpuResetOpacity
5. GpuSetTransform2D → 4× GpuDrawRoundedRectAlpha → GpuResetTransform
6. ImageDraw (icônes, logos)
7. GpuDrawTextFontAlign (textes)
8. GpuFlushRenderContext(ctx)                           ← commit framebuffer
```

### 4.9 Fenêtrage, registre d'apps, dock & menu contextuel

Ces `DrvAPIInterCon***...***` ne dessinent rien elles-mêmes — elles pilotent l'état noyau (fenêtres ouvertes, registre d'apps, menu contextuel) que le code applicatif (`ShiLauncher.marep`, dock) interroge pour se dessiner.

#### Registre d'apps installées (`AppRegistry...`)

Le dock n'affiche que les apps réellement installées sous `SDC:/slu64/apps/<App>/` (présence de `Maraset.yaml`), pas une liste codée en dur.

| Fonction | Retour | Description |
|---|---|---|
| `AppRegistryCount()` | `i32` | Nombre d'apps installées |
| `AppRegistryGetName(i)` | `ptr` | Nom du dossier (utilisé comme identifiant de fenêtre) |
| `AppRegistryGetIconPath(i)` | `ptr` | Chemin SRFS de l'icône, ou `nullptr` |
| `AppRegistryGetDiamondColor(i)` | `i32` | Couleur ARGB du losange dock (`diamond_color` du `Maraset.yaml`) |
| `AppRegistryGetPinned(i)` / `AppRegistrySetPinned(i, 0/1)` | `i32` | Épinglage au dock (survit à la session, pas au reboot) |
| `AppRegistryGetMenuItemCount(i)` / `GetMenuItemLabel(i, j)` | `i32`/`ptr` | Items du menu contextuel déclarés par l'app (voir ci-dessous) |
| `AppRegistryGetMenuItemSubmenuCount(i, j)` / `GetMenuItemSubmenuLabel(i, j, k)` | `i32`/`ptr` | Sous-menu d'un item |

**`dock_menu_items` (`Maraset.yaml`)** — scalaire une ligne (le parseur `Maraset.yaml` ne supporte AUCUNE liste YAML, seulement `clé: valeur`) :

```yaml
dock_menu_items: "New Folder|New File>txt,md,bmp|Mount SDC|Mount A"
```

`|` sépare les items du menu principal. `>sub1,sub2,...` (optionnel) déclare un sous-menu pour l'item qui précède.

#### Fenêtrage (`WindowMan...`)

| Fonction | Retour | Description |
|---|---|---|
| `WindowManCount()` | `i32` | Fenêtres ouvertes |
| `WindowManFindByName(name)` | `i32` | Index de la fenêtre nommée `name`, ou `-1` |
| `WindowManLaunch(name [, arg])` | `i32` | Lance une NOUVELLE instance — **ne déduplique jamais par nom** (voir §9.7), toujours vérifier `WindowManFindByName` avant d'appeler |
| `WindowManGetX/Y/W/H(i)` | `i32` | Géométrie de la fenêtre |
| `WindowManGetOpenTick(i)` | `i32` | Tick d'ouverture (animations dock) |
| `WindowManGetLaunchArg(i)` | `ptr` | Argument passé par `WindowManLaunch`/`WindowManSetLaunchArg` — pointeur nul-terminé, jamais vide (`"\0"` si aucun) |
| `WindowManGetLaunchArgGen(i)` | `i32` | Génération de `launch_arg` — incrémentée à chaque écriture. À comparer à une valeur stockée en `SCROLL_SCRATCH` pour ne traiter un argument qu'UNE fois (voir §2.8/§2.9) |
| `WindowManSetLaunchArg(i, arg)` | `i32` | Met à jour l'argument d'une fenêtre **déjà ouverte**, sans la relancer (bump la génération) |

#### Menu contextuel du dock (`Menu...`, `ShiLauncher.marep/base/ContextMenu.mara`)

État noyau minimal (ouvert/fermé, propriétaire, position) — la LISTE d'items n'est jamais dupliquée côté noyau, recalculée chaque frame depuis `AppRegistryGetMenuItemCount/Label`.

```mara
let _: <i32> = <DrvAPIInterCon***MenuOpen***>(ownerIdx, anchorX, anchorY);
let isOpen: <i32> = <DrvAPIInterCon***MenuIsOpen***>();
let ownerIdx: <i32> = <DrvAPIInterCon***MenuGetOwnerIdx***>();
let _: <i32> = <DrvAPIInterCon***MenuClose***>();
let _: <i32> = <DrvAPIInterCon***MenuOpenSubmenu***>(itemIdx);
let openSub: <i32> = <DrvAPIInterCon***MenuGetOpenSubmenuIdx***>();
```

Rendu = carte givrée, **toujours** dans cet ordre (voir §5.2) : `GpuSetTransform2D` → `GpuBackgroundBlur` → `GpuResetTransform` → `GpuDrawDropShadow` → `GpuDrawRoundedRectAlpha`.

**⚠️ Ce state est GLOBAL au noyau (voir §9.7)** — n'importe quel autre menu contextuel dans le système DOIT utiliser son propre jeu d'entiers dédié (voir `FolderMenu***` de `ShiLooker.marep` comme modèle : `FolderMenuOpen/Close/IsOpen/GetRow/GetX/GetY`), jamais réutiliser `Menu***`.

#### Menu global in-app (`GlobalMenu***`, `ShiLauncher.marep/base/GlobalMenu.mara`)

Menu global affiché depuis le **bouton menu** en haut à droite (Figma 900:88). Affiche TOUS les apps **épinglés** au dock avec leurs losanges et `dock_menu_items`, séparés par des lignes noires.

**Slot SCROLL_SCRATCH : 50** = edge-detect clic gauche pour le bouton global menu.

```mara
// Ouvrir le menu global (bouton menu haut-droit)
let _: <i32> = <DrvAPIInterCon***MenuOpenGlobal***>(anchorX, anchorY);

// Vérifier si ouvert
let isOpen: <i32> = <DrvAPIInterCon***MenuIsOpenGlobal***>();

// Position du menu
let x: <i32> = <DrvAPIInterCon***MenuGetGlobalX***>();
let y: <i32> = <DrvAPIInterCon***MenuGetGlobalY***>();

// Fermer
let _: <i32> = <DrvAPIInterCon***MenuCloseGlobal***>();
```

**Itération des apps épinglés :**
```mara
let pinnedCount: <i32> = <DrvAPIInterCon***AppRegistryGetPinnedCount***>();
let appIdx: <i32> = <DrvAPIInterCon***AppRegistryGetPinnedIndex***>(i);
```

### 4.10 Disques, navigation fichiers, texte

| Fonction | Retour | Description |
|---|---|---|
| `MountTableCount()` | `i32` | Disques réellement montés |
| `MountTableGetLetter(i)` | `ptr` | Lettre réelle (ex `"SDC:\"`) |
| `MountTableGetDiskId(i)` | `i32` | `0`=SRFS(SDC:) `1`=NTFS(A:) |
| `MountTableGetLabel(i)` | `ptr` | Libellé compact une-ligne construit côté Rust, ex `"Disque systeme (SDC:)"` — jamais concaténer nom+lettre côté Mara |
| `DiskMount(id)` / `DiskUnmount(id)` | `i32` | Idempotent ; **affichage seulement** — rien ne route réellement les I/O via `MOUNT_TABLE` aujourd'hui |
| `DiskFormat(id)` / `DiskIsFormattedSession(id)` | `i32` | Marque un flag **session uniquement**, ne touche jamais l'image disque réelle |
| `DiskBrowseReset(letterPtr)` / `DiskBrowseGetPath()` | — / `ptr` | Réinitialise/lit le chemin de navigation courant (`"SDC:/..."`) |
| `DiskBrowseNavigateInto(name)` / `DiskBrowseNavigateUp()` | `i32` | Navigation dossier |
| `DiskBrowseCreateEntry(kind)` | `i32` | Crée fichier/dossier depuis `TextField*` — `kind` : `0`=dossier `1`=.txt `2`=.md `3`=.bmp — **session uniquement, non persistant** |
| `DiskCacheDirCount(pathPtr)` / `DiskCacheDirGetName(i)` | `i32` / `ptr` | Liste le "dossier" courant — pour `SDC:`, fusionne le VRAI contenu de la partition ESP hôte (lecture UEFI `SimpleFileSystem` réelle) ET les entrées créées cette session (`SRFS_CACHE`) ; pour `A:`, cache seulement |
| `FolderColorGet(basePtr, namePtr)` / `FolderColorSet(basePtr, namePtr, argb)` | `i32` | Couleur personnalisée d'un dossier (clé = chemin complet, construit côté Rust) |
| `TextFieldAppendChar(code)` / `Backspace()` / `Clear()` / `GetPtr()` | — / `ptr` | Champ de saisie générique (nom de fichier) — `KeyGetCode()` ne donne qu'UNE touche par frame, ce buffer accumule |

Les noms de dossier renvoyés par `DiskCacheDirGetName` se terminent par `/` — tester via `StrCharAt(name, StrLen(name)-1) == 47` (code ASCII de `/`).

### 4.11 Utilitaires chaînes (`DrvManSpec`)

**Mara n'a aucune concaténation de chaîne fiable** (`<string> + <string>`/`+<i32>` compile mais n'a aucune garantie d'exécution réelle côté interpréteur OVC — aucun opcode Concat/Sprintf). Toute construction de chemin/libellé doit se faire côté Rust (voir `disk_browse_create_entry`, `mount_table_label_ptr` pour des exemples) et être exposée comme un pointeur déjà prêt.

| Fonction | Retour | Description |
|---|---|---|
| `StrLen(ptr)` | `i32` | Longueur (hors terminateur nul) |
| `StrCharAt(ptr, idx)` | `i32` | Code ASCII du caractère à `idx` — bornes vérifiées, renvoie `0` hors limites (jamais de lecture hors-tampon) |
| `StrEqual(ptrA, ptrB)` | `i32` | `1` si chaînes identiques, `0` sinon — utile pour comparer `WindowManGetLaunchArg()` à des littéraux connus |

---

## 5. Règles critiques pixel-perfect

### 5.1 ⚠️ Règle Double-Alpha (CRITIQUE)

**`GpuSetOpacity(v)` multiplie `color_alpha` de la couleur passée à `GpuDrawRoundedRectAlpha`.**

`final_alpha = (color_alpha × GPU_OPACITY) / 255`

**FAUX :**
```mara
// 0x4D=77 dans la couleur ET GpuSetOpacity(77) → 77*77/255 = 23 (9%)
let color: <i32> = 0x4DF5E3E1;
let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(77);
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(..., color);
let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();
```

**CORRECT :**
```mara
// 0xFF dans la couleur → l'opacité 30% est portée uniquement par GpuSetOpacity(77)
let color: <i32> = 0xFFF5E3E1;
let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(77);
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(..., color);
let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();
```

**Règle plugin** : toute couleur d'un layer avec `opacity < 1.0` → `GpuSetOpacity(Math.round(opacity*255))` + forcer `0xFF` en alpha ARGB.  
Exception : couleurs avec transparence ARGB propre (ex: `0x33B9B9B9`) → **ne jamais** les envelopper dans un GpuSetOpacity.

---

### 5.2 ⚠️ Ordre GpuBackgroundBlur (CRITIQUE)

Le blur opère **en place** sur les pixels déjà dessinés dans le GOP framebuffer.

```
RÈGLE : GpuBackgroundBlur AVANT le tint/overlay
TOUJOURS : blur → fill → svg/texte → GpuResetOpacity
```

Si le fill est dessiné avant le blur, la couleur solide est incorporée dans le flou et le résultat est un rectangle grisé indistinct.

---

### 5.3 ⚠️ Forward Transform Gaps (rotation)

`GpuSetTransform2D` + `GpuDrawRoundedRectAlpha` utilise un **forward mapping** : pour chaque pixel source `(x+col, y+row)`, le kernel écrit au pixel de sortie `(fx, fy)`. À 46°, le taux de couverture ≈ 51% → trous visibles ("effiloché").

**Correction : 4-pass draw**

Appeler `GpuDrawRoundedRectAlpha` 4 fois avec des décalages de 1px en x et/ou y. Les 4 projections couvrent des positions de sortie différentes → couverture ~100%.

```mara
let _: <i32> = <DrvAPIInterCon***GpuSetTransform2D***>(6947, 7193, -7193, 6947, cx, cy);
// Pass 1 : (x, y)
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(x, y, w, h, r, color);
// Pass 2 : (x+1, y+1)
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>((x + 1), (y + 1), w, h, r, color);
// Pass 3 : (x+1, y)
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>((x + 1), y, w, h, r, color);
// Pass 4 : (x, y+1)
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(x, (y + 1), w, h, r, color);
let _: <i32> = <DrvAPIInterCon***GpuResetTransform***>();
```

**Note sur l'accumulation d'alpha :** pour les couleurs avec `alpha=0xFF`, chaque pixel ne peut être écrit qu'une fois à 100% — pas d'accumulation. Pour les couleurs semi-transparentes (ex: `0x33B9B9B9`=20%), 4 passes accumulent : `1-(1-0.2)^4 ≈ 59%`. Ajuster la couleur source en conséquence si nécessaire.

---

### 5.4 ⚠️ GpuSetTransform2D — Pivot = centre écran

Args 4–5 = pivot en **pixels écran post-scale**, pas les coordonnées Figma brutes.

```typescript
// Plugin TS — pivot pour un élément Figma
const pivotX = Math.round((node.absoluteBoundingBox.x + node.width  / 2) * scaleW / 1000);
const pivotY = Math.round((node.absoluteBoundingBox.y + node.height / 2) * scaleH / 1000);
// → GpuSetTransform2D(cos, sin, -sin, cos, pivotX, pivotY)
```

Ne jamais passer `node.relativeTransform[0][2]` / `[1][2]` (champs `tx/ty` Figma — valeurs différentes du pivot).

---

### 5.5 ⚠️ Rayon de coin et forme rotée

Un carré de 45×45px avec `r=16` (35% du côté) est quasi-circulaire après rotation → perd l'aspect losange.

| r / taille | Apparence après rotation 45° |
|---|---|
| 0% | Diamant parfait (angles vifs) |
| 11% (r=5 sur 45px) | Diamant avec coins légèrement arrondis ✅ |
| 35% (r=16 sur 45px) | Quasi-ovale ❌ |
| 50%+ | Cercle ❌ |

**Règle** : `r` pour les éléments rotatifs ≤ 15% de la taille.

---

### 5.6 ⚠️ Coins arrondis asymétriques (barre d'état)

`GpuDrawRoundedRectAlpha` arrondit les **4 coins** uniformément. Pour une barre en haut de l'écran (y=0) avec seulement les coins bas arrondis :

```mara
// TECHNIQUE : étendre le rect vers y<0 — les coins supérieurs se trouvent hors-écran
// Le guard `fy < 0 { continue }` du kernel les clippe silencieusement
let r: <i32> = 8;
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(
    0, (0 - r), w, (h + r), r, color
);
// Résultat : bords haut droits (contre l'écran), coins bas arrondis ✅
```

---

### 5.7 ⚠️ FontLoad — Ne jamais utiliser `fnt`

Le paramètre `fnt ptr` de `rel op Render: [ctx string, fnt ptr]` est **null au démarrage** (SRFS_CACHE vide avant la première frame). Toujours appeler `FontLoad` directement.

```mara
rel op Render: [ctx string, fnt ptr] [
    // CORRECT
    let font: <ptr> = <DrvAPIInterCon***FontLoad***>("SDC:/slu64/assets/fonts/brsonomasemibold.ttf");
    // Utiliser font (pas fnt) dans GpuDrawTextFontAlign
];
```

---

### 5.8 ⚠️ IMAGE_CACHE — 8 slots LRU

Le cache image kernel est limité à 8 handles. Si plus de 8 `ImageLoad` sont actifs simultanément, les handles les moins récents sont évincés et renvoient 0 à l'usage suivant.

**Pattern correct :**
```mara
// Une seule variable im réutilisée — séquentiel, jamais de références croisées
var im: <i32> = 0;
im = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/.../img1.png");
let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, ...);
// im peut maintenant être réutilisée — img1 reste en cache seulement si < 8 autres loads
im = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/.../img2.png");
let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, ...);
```

---

### 5.9 ⚠️ GpuSetOpacity — Sémantique SET (pas de stack)

Chaque `GpuSetOpacity` **remplace** l'opacité courante. Il n'y a pas de push/pop.

```mara
// CORRECT
let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(77);
// draws à 30%
let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();
// draws à 100%
let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(178);
// draws à 70%
let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();

// FAUX — deux SetOpacity sans Reset entre eux
let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(77);
let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(178); // ← écrase 77 sans Reset
```

---

## 6. Pipeline d'assets Figma

### 6.1 Export PNG

**Toujours exporter en PNG avec canal alpha (RGBA 32-bit).** Sans alpha, les pixels transparents deviennent blancs → coins blancs visibles sur les icônes.

| Paramètre Figma | Valeur |
|---|---|
| Format | PNG |
| Fond | Transparent (décocher "Include background color") |
| Profondeur | 32-bit (automatique si PNG) |
| Résolution | 1× (la mise à l'échelle est faite par le kernel) |

Nommage : `img1.png`, `img2.png`... (indices 1-based utilisés dans `ImageLoad`).

### 6.2 Export SVG

Avant export SVG, dans Figma :
1. **Flatten** le vecteur (Ctrl+E) — simplifie les paths complexes
2. **Outline Stroke** si contours — les strokes vectoriels deviennent des fills
3. Vérifier qu'aucun path ne contient de commande `C/S/Q/A` (cubic bezier non supporté)
4. Remplacer `stroke="url(#gradientId)"` par une couleur fixe

**Support SVG :**

| Commande | Supporté |
|---|---|
| `M`, `m`, `L`, `l` | ✅ |
| `H`, `h`, `V`, `v` | ✅ |
| `Z`, `z` | ✅ |
| `rect`, `circle`, `ellipse`, `line`, `polygon` | ✅ |
| `C`, `S`, `Q`, `A` (courbes) | ❌ ignoré |
| `stroke="url(#...)"` | ❌ transparent |
| `<filter>`, `<feGaussianBlur>` | ❌ ignoré |

**Alternative pour formes complexes** : exporter en PNG RGBA et utiliser `ImageLoad + ImageDraw`.

### 6.3 Chemins SRFS

```
SDC:/apps/<AppName>/<AppName>.slasset/img1.png
SDC:/apps/<AppName>/<AppName>.slasset/vec1.svg
SDC:/slu64/assets/fonts/brsonomasemibold.ttf
```

Toujours utiliser le format `SDC:/...` (pas de `/` relatif).

---

## 7. Plugin TypeScript — Codegen complet

### 7.1 Utilitaires de base

```typescript
// ── Constantes design ────────────────────────────────────────────────
const DESIGN_W = 1440;
const DESIGN_H = 1024;

// ── Émetteur de code ─────────────────────────────────────────────────
const lines: string[] = [];
const emit = (line: string) => lines.push(line);

// ── Conversion numérique Figma → i32 ─────────────────────────────────
const i32 = (v: number): number => Math.round(v);

// ── Facteurs d'échelle (runtime, pas compile-time) ────────────────────
// Mara génère des expressions scalées inline — le plugin émet le pattern :
// ((designValue * sW + 500) / 1000) pour x/w
// ((designValue * sH + 500) / 1000) pour y/h
const sx = (v: number) => `((${i32(v)} * sW + 500) / 1000)`;
const sy = (v: number) => `((${i32(v)} * sH + 500) / 1000)`;
const sr = (r: number) => `(((${i32(r)} * sW + 500) / 1000 + (${i32(r)} * sH + 500) / 1000) / 2)`;

// ── Conversion couleur Figma → ARGB i32 ──────────────────────────────
const toARGB = (r: number, g: number, b: number, a: number): string => {
    const ri = Math.round(r * 255);
    const gi = Math.round(g * 255);
    const bi = Math.round(b * 255);
    const ai = Math.round(a * 255);
    return `0x${ai.toString(16).padStart(2,'0').toUpperCase()}` +
           `${ri.toString(16).padStart(2,'0').toUpperCase()}` +
           `${gi.toString(16).padStart(2,'0').toUpperCase()}` +
           `${bi.toString(16).padStart(2,'0').toUpperCase()}`;
};

// Couleur avec alpha FORCÉ à 0xFF (pour blocs GpuSetOpacity)
const toARGBOpaque = (r: number, g: number, b: number): string =>
    toARGB(r, g, b, 1.0);

// ── Opacité Figma → GpuSetOpacity ────────────────────────────────────
const toOpacity = (figmaOpacity: number): number =>
    Math.round(figmaOpacity * 255);

// ── Pivot pour GpuSetTransform2D ─────────────────────────────────────
const pivot = (node: SceneNode) => {
    const bb = (node as LayoutMixin).absoluteBoundingBox!;
    return {
        x: sx(bb.x + bb.width  / 2),
        y: sy(bb.y + bb.height / 2),
    };
};

// ── Matrice de rotation ───────────────────────────────────────────────
const cosFixed = (deg: number) => Math.round(Math.cos(deg * Math.PI / 180) * 10000);
const sinFixed = (deg: number) => Math.round(Math.sin(deg * Math.PI / 180) * 10000);

const emitRotation = (deg: number, pivotX: string, pivotY: string) => {
    const cos = cosFixed(deg), sin = sinFixed(deg);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuSetTransform2D***>(${cos}, ${sin}, ${-sin}, ${cos}, ${pivotX}, ${pivotY});`);
};
```

### 7.2 Génération de l'en-tête Render

```typescript
const emitHeader = (designW: number, designH: number) => {
    emit(`#base <std***ComTpe***SlulFrmt***[ DrvAPIInterCon ]>;`);
    emit(`#base <MaratineKit>;`);
    emit(``);
    emit(`rel op Render: [ctx string, fnt ptr] [`);
    emit(`    var im: <i32> = 0;`);
    emit(``);
    emit(`    let sw: <i32> = <DrvAPIInterCon***GpuGetWidth***>();`);
    emit(`    let sh: <i32> = <DrvAPIInterCon***GpuGetHeight***>();`);
    emit(`    let sW: <i32> = (sw * 1000) / ${designW};`);
    emit(`    let sH: <i32> = (sh * 1000) / ${designH};`);
    emit(``);
    emit(`    let font: <ptr> = <DrvAPIInterCon***FontLoad***>("SDC:/slu64/assets/fonts/brsonomasemibold.ttf");`);
};
```

### 7.3 Mapping Layer Figma → Appel Mara

#### RECTANGLE / FRAME sans effet

```typescript
const emitRect = (node: RectangleNode | FrameNode, imgIndex?: number) => {
    const bb = node.absoluteBoundingBox!;
    const x = sx(bb.x), y = sy(bb.y), w = sx(bb.width), h = sy(bb.height);
    const r = sr('cornerRadius' in node ? (node.cornerRadius as number) || 0 : 0);
    const fill = node.fills[0];

    if (fill?.type === 'IMAGE') {
        emit(`        im = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/APP/APP.slasset/img${imgIndex}.png");`);
        emit(`        let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, ${x}, ${y}, ${w}, ${h});`);
        return;
    }

    const opacity = node.opacity ?? 1.0;
    const color = fill?.type === 'SOLID'
        ? (opacity < 1 ? toARGBOpaque(fill.color.r, fill.color.g, fill.color.b)
                       : toARGB(fill.color.r, fill.color.g, fill.color.b, fill.opacity ?? 1))
        : '0x00000000';

    if (opacity < 1.0 && opacity > 0) {
        emit(`        let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(${toOpacity(opacity)});`);
        emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(${x}, ${y}, ${w}, ${h}, ${r}, ${color});`);
        emit(`        let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();`);
    } else {
        emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(${x}, ${y}, ${w}, ${h}, ${r}, ${color});`);
    }
};
```

#### FRAME avec Background Blur (frosted glass)

```typescript
const emitFrostedGlass = (node: FrameNode, imgIndex?: number) => {
    const bb = node.absoluteBoundingBox!;
    const x = sx(bb.x), y = sy(bb.y), w = sx(bb.width), h = sy(bb.height);
    const cr = 'cornerRadius' in node ? (node.cornerRadius as number) || 0 : 0;
    const r = sr(cr);
    const opacity = node.opacity ?? 1.0;
    const fill = node.fills[0] as SolidPaint;
    const color = toARGBOpaque(fill.color.r, fill.color.g, fill.color.b);
    const blurEffect = node.effects?.find(e => e.type === 'BACKGROUND_BLUR') as BlurEffect;
    const sigma = blurEffect ? Math.round(blurEffect.radius / 2) : 3;

    // ⚠️ Coins bas uniquement (si y=0, arête haute contre l'écran) :
    const atScreenTop = Math.round(bb.y) === 0;
    const yExpr = atScreenTop ? `(0 - ${r})` : y;
    const hExpr = atScreenTop ? `(${h} + ${r})` : h;

    emit(`        let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(${toOpacity(opacity)});`);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuBackgroundBlur***>(${x}, ${y}, ${w}, ${h}, ${r}, ${sigma});`);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(${x}, ${yExpr}, ${w}, ${hExpr}, ${r}, ${color});`);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();`);
};
```

#### DROP_SHADOW (Figma effect)

```typescript
const emitDropShadow = (node: SceneNode, effect: DropShadowEffect) => {
    const bb = (node as LayoutMixin).absoluteBoundingBox!;
    const w = sx(bb.width), h = sy(bb.height);
    const cr = 'cornerRadius' in node ? sr((node as any).cornerRadius || 0) : '0';
    const c = effect.color;
    const color = toARGB(c.r, c.g, c.b, c.a);
    const blur = Math.round(effect.radius);
    const oy = Math.round(effect.offset.y);

    // ⚠️ Choisir GpuDrawLinearGradient (ombre directionnelle bas uniquement, sans artefact)
    // plutôt que GpuDrawDropShadow (box_blur → artefact si blur ≥ oy)
    if (oy > 0 && Math.round(effect.offset.x) === 0) {
        // Shadow strictement sous l'élément → gradient strip
        const dkY = sy(bb.y);
        const dkX = sx(bb.x);
        const shadowAlpha = Math.round(c.a * 48);
        const shadowColor = `0x${shadowAlpha.toString(16).padStart(2,'0').toUpperCase()}000000`;
        emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawLinearGradient***>(${dkX}, (${dkY} + ${h}), ${w}, ${Math.max(blur * 2, 8)}, 0, -90, ${shadowColor}, 0, 0x00000000, 1000, 2);`);
    } else {
        // Shadow multi-directionnelle → GpuDrawDropShadow
        const ox = Math.round(effect.offset.x);
        const x = sx(bb.x), y = sy(bb.y);
        emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawDropShadow***>(${x}, ${y}, ${w}, ${h}, ${cr}, ${ox}, ${oy}, ${blur}, ${color});`);
    }
};
```

#### VECTOR / SVG

```typescript
const emitSvg = (node: VectorNode, vecIndex: number) => {
    const bb = node.absoluteBoundingBox!;
    const x = sx(bb.x), y = sy(bb.y), w = sx(bb.width), h = sy(bb.height);
    const varName = `svg${vecIndex}`;
    emit(`        let ${varName}: <ptr> = <DrvAPIInterCon***SvgLoad***>("SDC:/apps/APP/APP.slasset/vec${vecIndex}.svg");`);
    emit(`        let _: <i32> = <DrvAPIInterCon***SvgDraw***>(${varName}, ${x}, ${y}, ${w}, ${h});`);
    emit(`        let _: <i32> = <DrvAPIInterCon***SvgFree***>(${varName});`);
};
```

#### Élément ROTATIF (GpuSetTransform2D + 4-pass fill)

```typescript
const emitRotatedRect = (
    node: SceneNode,
    rotDeg: number,
    color: string,
    varColor: string
) => {
    const bb = (node as LayoutMixin).absoluteBoundingBox!;
    const x = sx(bb.x), y = sy(bb.y), w = sx(bb.width), h = sy(bb.height);
    const { x: cx, y: cy } = pivot(node);
    // ⚠️ Rayon ≤ 15% de la taille pour garder la forme losange
    const rDesign = Math.min(('cornerRadius' in node ? (node as any).cornerRadius || 0 : 0),
                             Math.round(bb.width * 0.12));
    const r = sr(rDesign);
    const cos = cosFixed(rotDeg), sin = sinFixed(rotDeg);

    emit(`        // [${varColor} — ${rotDeg}° / 4-pass anti-gap]`);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuSetTransform2D***>(${cos}, ${sin}, ${-sin}, ${cos}, ${cx}, ${cy});`);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(${x}, ${y}, ${w}, ${h}, ${r}, ${color});`);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>((${x} + 1), (${y} + 1), ${w}, ${h}, ${r}, ${color});`);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>((${x} + 1), ${y}, ${w}, ${h}, ${r}, ${color});`);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(${x}, (${y} + 1), ${w}, ${h}, ${r}, ${color});`);
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuResetTransform***>();`);
};
```

#### TEXT

```typescript
const emitText = (node: TextNode, font: string = 'font') => {
    const bb = node.absoluteBoundingBox!;
    const x = sx(bb.x), y = sy(bb.y), w = sx(bb.width);
    const fill = node.fills[0] as SolidPaint;
    const fg = toARGB(fill.color.r, fill.color.g, fill.color.b, fill.opacity ?? 1);
    const size = sr(node.fontSize as number);
    const align = node.textAlignHorizontal === 'CENTER' ? 1
                : node.textAlignHorizontal === 'RIGHT'  ? 2 : 0;
    const text = (node.characters as string).replace(/"/g, '\\"');
    emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawTextFontAlign***>(${x}, ${y}, ${w}, "${text}", ${fg}, 0x00000000, ${font}, ${size}, ${align});`);
};
```

#### LINEAR_GRADIENT fill

```typescript
const emitLinearGradient = (node: SceneNode, fill: GradientPaint) => {
    const bb = (node as LayoutMixin).absoluteBoundingBox!;
    const x = sx(bb.x), y = sy(bb.y), w = sx(bb.width), h = sy(bb.height);
    const cr = 'cornerRadius' in node ? sr((node as any).cornerRadius || 0) : '0';

    // Calculer l'angle depuis la transform Figma
    const t = fill.gradientTransform;
    const angleRad = Math.atan2(t[1][0], t[0][0]);
    const angleDeg = Math.round(angleRad * 180 / Math.PI);

    const s0 = fill.gradientStops[0];
    const s1 = fill.gradientStops[1] || s0;
    const c1 = toARGB(s0.color.r, s0.color.g, s0.color.b, s0.color.a);
    const c2 = toARGB(s1.color.r, s1.color.g, s1.color.b, s1.color.a);
    const p1 = Math.round(s0.position * 1000);
    const p2 = Math.round(s1.position * 1000);

    emit(`        let _: <i32> = <DrvAPIInterCon***GpuDrawLinearGradient***>(${x}, ${y}, ${w}, ${h}, ${cr}, ${angleDeg}, ${c1}, ${p1}, ${c2}, ${p2}, 2);`);
};
```

### 7.4 Pied de fichier

```typescript
const emitFooter = () => {
    emit(`    let gpuResult: <i32> = <DrvAPIInterCon***GpuFlushRenderContext***>(ctx);`);
    emit(`    if (gpuResult != 0) [ ret 1; ];`);
    emit(`    ret 0;`);
    emit(`];`);
    emit(``);
    emit(`rel op Destroy: [] [ ret 0; ];`);
};
```

### 7.5 Traversée des layers (ordre peintre)

```typescript
const processLayers = (nodes: readonly SceneNode[], imgCounter = {n: 1}, vecCounter = {n: 1}) => {
    // Figma : du bas vers le haut dans le panel Layers = ordre de rendu de fond vers avant-plan
    const ordered = [...nodes].reverse();

    for (const node of ordered) {
        if (!node.visible) continue;

        // DROP_SHADOW effect → émettre en premier (sous l'élément)
        if ('effects' in node) {
            for (const effect of (node as GeometryMixin).effects || []) {
                if (effect.type === 'DROP_SHADOW' && effect.visible) {
                    emitDropShadow(node, effect as DropShadowEffect);
                }
            }
        }

        switch (node.type) {
            case 'RECTANGLE':
                const rect = node as RectangleNode;
                if (rect.fills[0]?.type === 'IMAGE') {
                    emitRect(rect, imgCounter.n++);
                } else if (rect.fills[0]?.type === 'GRADIENT_LINEAR') {
                    emitLinearGradient(rect, rect.fills[0] as GradientPaint);
                } else {
                    emitRect(rect);
                }
                break;

            case 'FRAME': {
                const frame = node as FrameNode;
                const hasBlur = frame.effects?.some(e => e.type === 'BACKGROUND_BLUR' && e.visible);
                if (hasBlur) {
                    emitFrostedGlass(frame);
                } else {
                    emitRect(frame);
                }
                // Récursion sur les enfants
                if ('children' in frame) processLayers(frame.children, imgCounter, vecCounter);
                break;
            }

            case 'VECTOR':
            case 'BOOLEAN_OPERATION':
            case 'STAR':
            case 'POLYGON':
                emitSvg(node as VectorNode, vecCounter.n++);
                break;

            case 'TEXT':
                emitText(node as TextNode);
                break;

            case 'COMPONENT':
            case 'INSTANCE':
                // Traiter comme FRAME
                emitRect(node as FrameNode);
                if ('children' in node) processLayers((node as FrameNode).children, imgCounter, vecCounter);
                break;
        }
    }
};
```

---

## 8. Patterns UI — Recettes prêtes à l'emploi

### 8.1 Wallpaper plein écran (fill-screen)

```mara
im = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/App/App.slasset/img1.png");
let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, 0, 0, sw, sh);
```

### 8.2 Dock pill frosted glass avec shadow

```mara
let dkX: <i32> = ((526 * sW + 500) / 1000);
let dkY: <i32> = ((900 * sH + 500) / 1000);
let dkW: <i32> = ((405 * sW + 500) / 1000);
let dkH: <i32> = ((80 * sH + 500) / 1000);
let dkR: <i32> = (((30 * sW + 500) / 1000 + (30 * sH + 500) / 1000) / 2);

// Shadow directionnelle — gradient strip sous le dock
let _: <i32> = <DrvAPIInterCon***GpuDrawLinearGradient***>(dkX, (dkY + dkH), dkW, 12, 0, -90, 0x30000000, 0, 0x00000000, 1000, 2);

// Dock bar à 30% (double-alpha rule : color alpha = 0xFF)
let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(77);
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(dkX, dkY, dkW, dkH, dkR, 0xFFF5E3E1);
let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();
```

### 8.3 Barre sysbar frosted glass (coins bas arrondis seulement)

```mara
let swR: <i32> = (((8 * sW + 500) / 1000 + (8 * sH + 500) / 1000) / 2);
let swW: <i32> = ((1440 * sW + 500) / 1000);
let swH: <i32> = ((30 * sH + 500) / 1000);

let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(178);
let _: <i32> = <DrvAPIInterCon***GpuBackgroundBlur***>(0, 0, swW, swH, swR, 3);
// y=(0-swR) → coins supérieurs hors-écran, seuls les coins bas sont arrondis
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(0, (0 - swR), swW, (swH + swR), swR, 0xFFE0E0E0);
let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();
```

### 8.4 Icône losange (rotated rounded rect + 4-pass)

```mara
// cx, cy = centre du losange en pixels écran
let cx: <i32> = ((571 * sW + 500) / 1000);
let cy: <i32> = ((940 * sH + 500) / 1000);
let dx: <i32> = ((548 * sW + 500) / 1000);
let dy: <i32> = ((917 * sH + 500) / 1000);
let dw: <i32> = ((45 * sW + 500) / 1000);
let dh: <i32> = ((45 * sH + 500) / 1000);
let dr: <i32> = (((5 * sW + 500) / 1000 + (5 * sH + 500) / 1000) / 2);  // r ≤ 12% de taille

let _: <i32> = <DrvAPIInterCon***GpuSetTransform2D***>(6947, 7193, -7193, 6947, cx, cy);
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(dx, dy, dw, dh, dr, 0xFFFFDDC0);
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>((dx + 1), (dy + 1), dw, dh, dr, 0xFFFFDDC0);
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>((dx + 1), dy, dw, dh, dr, 0xFFFFDDC0);
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(dx, (dy + 1), dw, dh, dr, 0xFFFFDDC0);
let _: <i32> = <DrvAPIInterCon***GpuResetTransform***>();

// Icône centrée (non rotée)
im = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/App/App.slasset/img4.png");
let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, ((544 * sW + 500) / 1000), ((913 * sH + 500) / 1000), ((57 * sW + 500) / 1000), ((57 * sH + 500) / 1000));
```

### 8.5 Card notification (shadow + rounded rect + texte)

```mara
// Shadow
let _: <i32> = <DrvAPIInterCon***GpuDrawDropShadow***>(
    ((30 * sW + 500) / 1000), ((200 * sH + 500) / 1000),
    ((456 * sW + 500) / 1000), ((112 * sH + 500) / 1000),
    (((12 * sW + 500) / 1000 + (12 * sH + 500) / 1000) / 2),
    0, 4, 8, 0x28000000
);
// Card background blanc opaque
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(
    ((30 * sW + 500) / 1000), ((200 * sH + 500) / 1000),
    ((456 * sW + 500) / 1000), ((112 * sH + 500) / 1000),
    (((12 * sW + 500) / 1000 + (12 * sH + 500) / 1000) / 2),
    0xFFFFFFFF
);
// Texte
let _: <i32> = <DrvAPIInterCon***GpuDrawTextFontAlign***>(
    ((44 * sW + 500) / 1000), ((216 * sH + 500) / 1000),
    ((428 * sW + 500) / 1000),
    "ShiSettings • SluPwManSrv", 0xFF1A1A1A, 0x00000000,
    font, (((13 * sW + 500) / 1000 + (13 * sH + 500) / 1000) / 2), 0
);
```

### 8.6 Élément semi-transparent (layer opacity Figma)

```mara
// Layer opacity = 0.20 (20%) → GpuSetOpacity(51)
// Couleur alpha = 0xFF (pas double-alpha)
let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(51);
let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(x, y, w, h, r, 0xFFB9B9B9);
let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();
```

### 8.7 Image avec blend mode (MULTIPLY)

```mara
let _: <i32> = <DrvAPIInterCon***GpuSetBlendMode***>(1);   // MULTIPLY
im = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/App/App.slasset/overlay.png");
let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, x, y, w, h);
let _: <i32> = <DrvAPIInterCon***GpuResetBlendMode***>();
```

---

## 9. Limitations connues et contournements

### 9.1 `GpuDrawDropShadow` — Artefact box_blur

**Problème** : la zone de box_blur s'étend à `(sx-blur, sy_-blur, w+2*blur, h+2*blur)`. Quand `blur ≥ oy`, le blur monte au-dessus de l'élément → bande sombre rectangulaire visible.

**Contournement A — Shadow directionnelle (sous seulement) :**
```mara
// GpuDrawLinearGradient — aucun artefact
GpuDrawLinearGradient(dkX, (dkY + dkH), dkW, 12, 0, -90, 0x30000000, 0, 0x00000000, 1000, 2);
```

**Contournement B — Halo symétrique propre :**
```mara
// GpuDrawGlow — SDF + falloff linéaire, aucun artefact box_blur
GpuDrawGlow(x, y, w, h, r, 0x000000, 10, 45);
```

**Utiliser `GpuDrawDropShadow` uniquement quand `oy > blur`** (le blur region commence SOUS le bord supérieur de l'élément) et avec des valeurs faibles (`blur ≤ 4`, `color_alpha ≤ 0x40`).

---

### 9.2 PNG sans canal alpha — Coins blancs

ImageDraw utilise Porter-Duff OVER sur le canal alpha du PNG (octet [3]). Si le PNG est en RGB sans alpha, l'octet [3] = 255 → tous les pixels opaques → coins blancs visibles.

**Solution** : Re-exporter depuis Figma en PNG RGBA avec fond transparent.  
**Test rapide** : ouvrir le PNG dans un éditeur d'image — si les coins sont blancs, il manque l'alpha.

---

### 9.3 Support SVG limité

| Non supporté | Contournement |
|---|---|
| Commandes `C/S/Q/A` (courbes de Bézier) | Flatten dans Figma → `M/L/H/V/Z` seulement |
| `stroke="url(#gradientId)"` | Remplacer par couleur fixe dans le SVG |
| `<filter>`, `<feGaussianBlur>` | Supprimer, utiliser `GpuBackgroundBlur` côté Mara |
| Formes complexes | Exporter en PNG RGBA + `ImageDraw` |

**Exemple de correction SVG (stroke gradient → couleur fixe) :**
```xml
<!-- Avant (invalide) -->
<path d="M6.5 2.5H221.5" stroke="url(#paint0_linear)"/>

<!-- Après (supporté) -->
<path d="M6.5 2.5H221.5" stroke="#878787" stroke-width="5" stroke-linecap="round"/>
```

---

### 9.4 Forward Transform Gaps (rotation)

**Cause** : forward mapping → trous à environ 50% de couverture à 46°.  
**Solution** : 4-pass draw — voir §5.3.  
**Alternative propre** : utiliser `GpuDrawRotatedImage` pour les images (inverse mapping, pas de trous).

---

### 9.5 DrawText=0 — FontLoad retourne null

Si `GpuDrawTextFontAlign` ne dessine rien (`DrawText=0` dans le debug kernel), `FontLoad` a retourné `nullptr`. Causes :
1. Le chemin SRFS est incorrect (`SDC:/...`)
2. Le fichier n'existe pas dans l'asset bundle
3. Le format TTF n'est pas supporté (utiliser un TTF standard, pas OTF)

**Debug** : chercher dans `SDC:/slu64/assets/fonts/` les polices disponibles.

---

### 9.6 IMAGE_CACHE — Éviction LRU

Si plus de 8 `ImageLoad` sont actifs simultanément dans le même `rel op Render`, les handles les plus anciens sont invalides. Toujours utiliser **une seule `var im: <i32>`** réutilisée séquentiellement.

### 9.7 État noyau partagé entre apps — jamais réutiliser un jeu d'entiers d'état pour deux menus différents

`ShiLauncher.marep` (le dock) tourne **en permanence** en parallèle de n'importe quelle autre app ouverte, et relit son propre état de menu contextuel (`Menu***`, voir §4.9) à chaque frame pour se dessiner. Un second menu contextuel ailleurs dans le système (ex: menu couleur de dossier de `ShiLooker.marep`) qui réutiliserait le MÊME état `Menu***` casserait les deux : dès que le second menu écrit son propre "propriétaire" (un index de ligne, pas un index d'app), le dock l'interprète comme un index d'app invalide et dessine n'importe quoi par-dessus (ou en dessous) de ce que montre l'autre app.

**Règle** : tout nouveau menu contextuel / overlay UI mono-instance doit avoir son **propre** jeu de statics Rust + FFI dédiées (voir `FolderMenuOpen/Close/IsOpen/GetRow/GetX/GetY` de `ShiLooker.marep/base/FolderMenu.mara` comme modèle), même si la logique de rendu est copiée du menu existant. Ne jamais supposer qu'un seul menu peut être ouvert à la fois dans TOUT le système — seulement qu'un seul peut être ouvert par mécanisme d'état.

### 9.8 `WindowManLaunch` ne déduplique jamais par nom

`WindowManLaunch(name, arg)` charge et instancie **toujours** une nouvelle fenêtre — il n'existe aucune vérification interne pour un nom déjà en cours d'exécution. Un appel sur une app déjà ouverte crée une **seconde instance indépendante** au lieu d'agir sur celle existante.

**Règle** : avant tout `WindowManLaunch(name, ...)` déclenché par un menu/bouton (pas le lancement initial normal d'une app), vérifier `WindowManFindByName(name)` :

```mara
let existingIdx: <i32> = <DrvAPIInterCon***WindowManFindByName***>(name);
if (existingIdx < 0) [ let _: <i32> = <DrvAPIInterCon***WindowManLaunch***>(name, arg); ];
if (existingIdx >= 0) [ let _: <i32> = <DrvAPIInterCon***WindowManSetLaunchArg***>(existingIdx, arg); ];
```

Voir §2.8 pour pourquoi l'app cible doit lire cet argument avec un edge-detect par génération (`WindowManGetLaunchArgGen`), pas un simple "lu une fois avant la boucle".

---

## 10. Sécurité

`PRIMARY_VALIDATOR_PRIVKEY` est une constante de validation intégrée dans le kernel. **Ne jamais modifier.**

Pipeline de chargement `.marep` :
1. Lecture du bundle ZIP depuis l'ESP (SimpleFileSystem UEFI)
2. Vérification AuthARoot (`Maraset.yaml` SRID ↔ `RAbstractallowing.xml`)
3. Auto-install assets → `SDC:/apps/<AppName>/`
4. Exécution OVC via `exec_marep` (entry point `OEntry` → `Render`)

---

## 11. Versionning & Build

### 11.1 Deux axes indépendants

Slura distingue deux identifiants qui ne se substituent jamais l'un à l'autre :

- **Version sémantique** (`package.version` dans `Maraset.yaml`, et `version` dans chaque `Cargo.toml`) — `MAJOR.MINOR.PATCH`, changée à la main, uniquement quand une compatibilité ou une fonctionnalité change réellement. Chaque crate Rust (`lunee-ker`, `vuc-platform`, `vuc-core`...) et chaque bundle Maratine (`.slul`/`.marep`) porte SA PROPRE semver, indépendante des autres — un `lunee-ker 0.1.0` n'a aucun rapport avec le `1.0.0` d'un driver `.slul`.
- **Horodatage de build** (`package.build` dans `Maraset.yaml`, champ `Marav`, nom de fichier `.iso`) — format **`DDMMYYHH`** (jour, mois, année sur 2 chiffres, heure), généré à chaque build. Identifie QUAND un artefact précis a été produit — pas ce qu'il contient ni sa compatibilité.

### 11.2 Format `DDMMYYHH`

```text
DD MM YY HH
29 06 26 17   →  29 juin 2026, 17h
```

| Champ | Sens                        | Chiffres  |
| ----- | --------------------------- | --------- |
| `DD`  | Jour du mois                | 01–31     |
| `MM`  | Mois                        | 01–12     |
| `YY`  | Année (2 derniers chiffres) | 26 = 2026 |
| `HH`  | Heure du build, 24h         | 00–23     |

Généré **dynamiquement** par la tâche `make: booter.iso` (`.vscode/tasks.json`) à chaque run — `$stamp = Get-Date -Format 'ddMMyyHH'`, pas une valeur figée dans le fichier :

```text
Slura1_NAVERTA_dev_build17072617.iso
 │     │        │   └─ DDMMYYHH : horodatage réel du build (Get-Date)
 │     │        └─ canal de release (§11.3b)
 │     └─ codename de la ligne de release (§11.3)
 └─ numéro de distribution Slura
```

Le **même** stamp est propagé aux `Maraset.yaml` sources (`build:`, `Marav:`, et les versions `dependencies.basecon`) par la tâche `stamp: Maraset build (dynamic)` (`slr_clk_bt/x64/amd64/stamp-maraset.ps1`), qui s'exécute automatiquement avant tout `marai build` (dépendance de `make: ESP dirs`). Les deux tâches partagent le même input `releaseChannel` — un seul choix de canal par run, réutilisé partout.

### 11.3 Nom de release / codename

`NAVERTA` est le codename de la ligne de release courante — apparaît dans `package.version` des `.marep` (ex: `v1 NAVERTA build 20260714-01` dans `ShiLauncher.marep/Maraset.yaml`) et dans le nom de l'ISO. Il change avec la ligne de release (pas à chaque build individuel).

### 11.3b Canal de release

La tâche `make: booter.iso` demande le canal via l'input VS Code `releaseChannel` (`pickString`, menu déroulant à chaque run) :

| Canal     | Usage                       |
| --------- | --------------------------- |
| `dev`     | Build dev en cours (defaut) |
| `beta`    | Candidat pre-release        |
| `release` | Distribution stable         |

Le canal choisi est injecté tel quel dans le nom de fichier ISO — voir §11.2.

### 11.4 SRID — un identifiant partagé, PAS une version

Le `SRID` (`SRID_slura_os_29062617` — identique dans TOUS les `Maraset.yaml`/`RAbstractallowing.xml` du dépôt) sert à la vérification AuthARoot au chargement — ce n'est ni une version ni un build. Contrairement à une convention SRID-par-composant, Slura utilise un SRID unique pour l'ensemble de l'OS (décision produit — voir historique de conversation), donc il ne distingue plus les composants entre eux, seulement l'appartenance à Slura OS.

### 11.5 État actuel du dépôt — écart connu

Le générateur d'apps (`tools/maratinekit-tool-builder/src/generator/templates.ts`, fonction `buildStamp()`) produit aujourd'hui `YYYYMMDD-01` pour `package.build`/`Marav` (ex: `20260714-01`), et la plupart des `Maraset.yaml` existants suivent encore ce format hérité — pas `DDMMYYHH`. Seuls le nom du fichier ISO (`build29062617.iso`, littéral dans `tasks.json`) et `package.version` de `TestApp.marep` (`v1 NAVERTA build 29062617`) utilisent réellement `DDMMYYHH` aujourd'hui.

**`DDMMYYHH` est la structure cible** pour tout nouveau build — les fichiers encore en `YYYYMMDD-01` ne sont pas alignés et devront être migrés (générateur inclus) séparément ; cette section documente la convention à suivre, elle ne corrige pas encore le générateur.

---

## 12. Pipeline de build & test ISO/VM

### 12.1 `efiboot.img` — pourquoi l'ISO a besoin d'une vraie image FAT

`make: booter.iso` (`.vscode/tasks.json`) construit l'ISO via `xorriso -as mkisofs ... -eltorito-alt-boot -e efiboot.img -no-emul-boot -isohybrid-gpt-basdat`. Le fichier référencé par `-e` doit être une **vraie partition FAT32** contenant tout `esp/` (BOOTX64.EFI, slr_clk_bt.efi, drivers, apps) — pas le `.EFI` brut. QEMU/OVMF tolère un exécutable PE nu comme image El Torito "no emulation", mais **le firmware EFI de VMware Workstation ne le supporte pas** et échoue silencieusement en "No Media" sur le lecteur CD-ROM.

`efiboot.img` est construit via WSL (`mkfs.vfat` + montage loop — aucun outil équivalent fiable côté Windows natif) :

```bash
dd if=/dev/zero of=efiboot.img bs=1M count=512
mkfs.vfat -F 32 -n SLURA_ESP efiboot.img
mount -o loop efiboot.img /mnt/efimnt
cp -r esp/. /mnt/efimnt/
umount /mnt/efimnt
```

**⚠️ Piège poupée russe** : `efiboot.img` est copié DANS `esp/` (`esp/efiboot.img`) pour être référençable par `xorriso` comme un fichier normal de l'arborescence source. Si `esp/efiboot.img` d'un run précédent n'est PAS supprimé avant de reconstruire une nouvelle image, le nouveau `efiboot.img` s'embarque lui-même récursivement — 26 Mo → 96 Mo → 218 Mo → ... à chaque run. **Toujours supprimer `esp/efiboot.img` (et `esp/sources/install.slin`, même piège — voir §11.5 commentaire du générateur `install.slin`) au tout début du pipeline** (`make: ESP dirs`, le premier point de passage commun), pas seulement dans la tâche qui les régénère — sinon une tâche EN AMONT dans le graphe de dépendances (ex: `marai image: create install.slin`, qui capture tout `esp/` comme source) embarque la version encore présente de l'autre fichier avant que sa propre tâche de nettoyage ait pu s'exécuter.

### 12.2 `boot_selector.cpp` — timeout de démarrage automatique

Le sélecteur de boot (`BOOTX64.EFI`) attend une touche avant de charger `slr_clk_bt.efi`. Sans limite de temps, ce blocage est invisible avec un clavier réel mais bloque **tout test automatisé** — VMware Workstation n'autorise l'injection de touches/souris par script qu'avec des identifiants invité (non disponibles pour une VM sans OS installé). `boot_selector.cpp` implémente donc un timeout de 5 secondes (`for (int waited = 0; waited < 100; ++waited) { ...ReadKeyStroke...; bs->Stall(50000); }`) qui démarre automatiquement si aucune touche n'arrive, sans supprimer la possibilité d'appuyer plus tôt.

### 12.3 Test QEMU headless (le plus simple, mais limité)

```bash
qemu-system-x86_64 \
    -nodefaults -machine q35,accel=tcg -m 1024M \
    -device virtio-vga -display none \
    -device qemu-xhci,id=xhci \
    -device usb-tablet,bus=xhci.0 -device usb-kbd,bus=xhci.0 \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE_4M.fd,id=ovmf_code \
    -drive if=pflash,format=raw,file=OVMF_VARS_4M.fd,id=ovmf_vars \
    -drive if=ide,format=raw,file=fat:rw:esp/ \
    -chardev file,id=ser0,path=serial.log -serial chardev:ser0 \
    -monitor none -no-reboot -no-shutdown
```

**⚠️ `-drive file=fat:rw:esp/` mappe le dossier `esp/` directement comme un disque FAT synthétique** — si `esp/` dépasse ~512 Mo (typiquement à cause de `efiboot.img` qui y réside en permanence après un `make: booter.iso`), QEMU refuse de démarrer (`Directory does not fit in FAT16`). Ceci n'affecte QUE ce chemin de test rapide, pas l'ISO réelle (xorriso ne souffre pas de cette limite) — dans ce cas, tester directement via l'ISO + VMware (§12.4), ou temporairement déplacer `efiboot.img` hors de `esp/` avant le test QEMU.

Pilotage programmatique (pas d'accès souris/clavier interactif requis) via le moniteur QMP :

```python
import socket, json, time
s = socket.create_connection(("127.0.0.1", 4450))
s.recv(4096)
s.sendall(json.dumps({"execute": "qmp_capabilities"}).encode() + b"\n"); s.recv(4096)
# Touche : {"execute":"input-send-event","arguments":{"events":[{"type":"key","data":{"down":True,"key":{"type":"qcode","data":"ret"}}}]}}
# Capture écran (fonctionne même avec -display none) : {"execute":"screendump","arguments":{"filename":"/tmp/shot.ppm"}}
```

`screendump` produit un PPM brut — convertible en PNG sans dépendance externe (zlib de la stdlib suffit pour encoder un PNG minimal).

### 12.4 Test VMware Workstation

`6️⃣ vmware: run UEFI test` repère automatiquement le dernier ISO `Slura1_NAVERTA_*.iso` (par date de modification) et corrige `ide1:0.fileName` dans `VyftUEFI.vmx` avant `vmrun -T ws start ... nogui` — sans ça, VMware rejoue une référence figée, potentiellement un ISO supprimé (→ "No Media").

**Diagnostic sans accès souris/clavier** (aucun identifiant invité disponible pour `vmrun`) : ajouter un port série redirigé vers un fichier dans le `.vmx` — le noyau écrit déjà tous ses logs sur COM1 (`0x3F8`) :

```ini
serial0.present  = "TRUE"
serial0.fileType = "file"
serial0.fileName = "VyftUEFI-serial.log"
```

Puis surveiller `vmware.log` (`Guest: Status upon boot failure: No Media` — vérifier QUEL périphérique : `ide0:0`/disque dur vide = normal et attendu tant qu'aucun OS n'y est installé, `ide1:0`/CD-ROM = problème réel, voir §12.1) et `VyftUEFI-serial.log` (doit continuer à grossir frame après frame si le noyau tourne).

---

## État pixel-perfect — Checklist avant build

| ✓ | Vérification |
|---|---|
| ☐ | Wallpaper `ImageDraw(im, 0, 0, sw, sh)` — pas de h=1037 hardcodé |
| ☐ | Toute couleur dans bloc `GpuSetOpacity` a alpha `0xFF` en ARGB (pas double-alpha) |
| ☐ | `GpuBackgroundBlur` AVANT `GpuDrawRoundedRectAlpha` pour chaque frosted glass |
| ☐ | `GpuSetOpacity` suivi exactement d'un `GpuResetOpacity` par groupe |
| ☐ | `GpuSetTransform2D` suivi de 4-pass fill + `GpuResetTransform` |
| ☐ | Rayon de coin des éléments rotatifs ≤ 15% de la taille |
| ☐ | Barre sysbar à y=0 : `y=(0-r), h=(h+r)` pour cacher coins supérieurs |
| ☐ | Shadow dock : `GpuDrawLinearGradient` (pas `GpuDrawDropShadow` si blur ≥ oy) |
| ☐ | `FontLoad` appelé directement dans `Render`, pas via `fnt` |
| ☐ | Une seule `var im: <i32> = 0` réutilisée pour toutes les images |
| ☐ | PNGs exportés RGBA (fond transparent dans Figma) |
| ☐ | SVGs sans commandes `C/S/Q/A` (Flatten dans Figma avant export) |
| ☐ | Pivot `GpuSetTransform2D` = centre de l'élément en pixels écran (post-scale) |
| ☐ | Nouveau slot `SCROLL_SCRATCH` documenté en en-tête de fichier, vérifié non utilisé par une autre app active en parallèle (§2.9) |
| ☐ | Toute logique "ne doit s'exécuter qu'une fois" vit dans `Render` avec edge-detect, jamais comme code "avant la boucle" dans `LAPrevent***Launch` (§2.8) |
| ☐ | Tout nouveau menu contextuel a son propre état noyau dédié, jamais partagé avec `Menu***` (§9.7) |
| ☐ | `WindowManLaunch` déclenché par un menu/bouton précédé d'un `WindowManFindByName` (§9.8) |
| ☐ | `esp/efiboot.img` et `esp/sources/install.slin` supprimés avant tout run complet du pipeline ISO (§12.1) |

---

*Slura OS © 2026 Vyft Ltd. Tous droits réservés.*
