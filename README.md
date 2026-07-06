# Slura OS — Lunée Kernel

**Vyft Ltd · 2026**  
Système d'exploitation UEFI custom. Kernel `lunee-ker` en Rust `no_std` ciblant `x86_64-unknown-uefi`.  
Langage applicatif : **Maratine** (`.mara` → OVC LLVM IR → exécuté par l'interpréteur intégré).

---

## Architecture

```
slr_clk_bt/
├── x64/amd64/esp/           ← Image ESP bootable
│   ├── EFI/BOOT/BOOTX64.EFI ← Sélecteur de boot
│   ├── slr_clk_bt.efi       ← Kernel Lunée (entry point UEFI)
│   ├── sources/             ← Drivers .slul compilés
│   └── SDC/slu64/
│       ├── DrivRequirment/  ← Drivers système
│       ├── apps/            ← Applications installées
│       └── assets/          ← Polices, images
├── SluGpu.slul/             ← Driver GPU (Maratine + Rust HAL)
├── SluKeyMouse.slul/        ← Driver clavier/souris
├── SluFontConf.slul/        ← Chargeur de polices TTF
├── SRFSMan.slul/            ← Système de fichiers SRFS
├── SluEnvSys.slul/          ← Variables d'environnement
├── CryptoAssetSupport.slul/ ← Wallet crypto
└── ShiLauncher.marep/       ← Application launcher principale
crates/vuc-core/lunee-ker/src/
├── ovc_exec.rs              ← Interpréteur OVC + dispatch DrvAPIInterCon
├── kernel_runtime.rs        ← Boucle de rendu principale
├── bundle_loader/           ← Chargeur .marep et .slul
│   ├── marep_loader.rs      ← Auto-install assets → SDC:/apps/
│   ├── slul_loader.rs       ← Chargeur de drivers
│   └── zip_reader.rs        ← Décompresseur ZIP (stored + DEFLATE)
```

---

## Build

```powershell
# Kernel UEFI
cargo build -p lunee-ker --lib --target x86_64-unknown-uefi --release

# Full pipeline (kernel + drivers + ISO)
# → utiliser la tâche VS Code : "🚀 Full Slura build (kernel + drivers + ISO)"
```

---

## API GPU — `SluGpu.slul` / `DrvAPIInterCon`

Toutes les fonctions GPU sont exposées depuis Maratine via `rel op` dans `GpuImpl.mara`  
et dispatchées côté kernel dans `ovc_exec.rs`.  
Le framebuffer est le GOP UEFI (1440 × 1037, ARGB 32 bpp).

> **Miroir pixel-perfect Figma → Slura OS** — Mali-G68 MP2  
> Toutes les fonctions ci-dessous sont obligatoires. Sans l'une d'elles le rendu n'est pas un miroir à 100%.

### Rendu confirmé sur device (ShiXbook)

| Élément | Statut | Fonctions impliquées |
|---|---|---|
| Wallpaper PNG plein écran | ✅ Visible | `ImageLoad` + `ImageDraw` (fast-path opaque) |
| Dock bar frosted glass | ✅ Visible | `GpuSetOpacity(77)` + `GpuDrawRoundedRectAlpha` |
| Dock icons losanges (6) | ✅ Visibles | `GpuSetTransform2D` pivot + `GpuDrawRoundedRectAlpha` |
| PNG icons dans les losanges | ✅ Visibles | `ImageDraw` Porter-Duff + GPU_OPACITY |
| Gesture bar gradient | 🔧 Partiel | `GpuDrawLinearGradient` |
| Shi Windows SVG wave | 🔧 À implémenter | `SvgLoad` + `SvgDraw` |

### Compositing

| # | Fonction | Impact si absente |
|---|---|---|
| 1 | `ImageDraw(handle, x, y, w, h)` — Porter-Duff Over par canal : `out = (src·α + dst·(255−α)) / 255`. `handle` = `i32` retourné par `ImageLoad`. GPU_OPACITY module le canal alpha du PNG : `a = png_alpha * GPU_OPACITY / 255`. | Fond blanc sur toute image transparente |
| 2 | `GpuSetOpacity(opacity)` / `GpuResetOpacity()` — sémantique SET (pas de stack) : `final_alpha = color_alpha * GPU_OPACITY / 255`. | `0x33B9B9B9` rendu plein au lieu de 20% transparent |
| 3 | `GpuSetBlendMode(mode)` / `GpuResetBlendMode()` — 12 modes (0 NORMAL…11 EXCLUSION) | Calques blend mode = rendu plat incorrect |

### Formes et géométrie

| # | Fonction | Impact si absente |
|---|---|---|
| 4 | `SvgLoad(path)→ptr` / `SvgDraw(svg, x, y, w, h)` / `SvgFree(svg)` | Shi Windows, gesture bar, beziers = rectangles pleins |
| 5 | `GpuDrawRoundedRectFull(x, y, w, h, rTL, rTR, rBL, rBR, color)` | Coins asymétriques Figma = valeur moyenne incorrecte |
| 6 | `GpuSetTransform2D(cos, sin, neg_sin, cos, pivot_x, pivot_y)` / `GpuResetTransform()` — valeurs ×10000 ; args 4–5 = **pivot** (centre de rotation en pixels), le kernel calcule la translation affine en interne | Éléments rotatifs dessinés droits |

### Effets visuels

| # | Fonction | Impact si absente |
|---|---|---|
| 7 | `GpuBackgroundBlur(x, y, w, h, r, radius)` — capture GOP → blur σ=radius/3 → reblit | Dock pill = rectangle plat, pas de verre dépoli |
| 8 | `GpuGaussianBlur(x, y, w, h, radius)` — blur in-place sur la région | LAYER_BLUR Figma = bords incorrectement nets |
| 9 | `GpuDrawDropShadow(x, y, w, h, cr, offX, offY, blurR, color)` | Icônes et dock sans ombre = aspect 2D plat |
| 10 | `GpuDrawInnerShadow(x, y, w, h, cr, offX, offY, blurR, color)` | Inner shadows Figma absentes |
| 11 | `GpuDrawGlow(x, y, w, h, r, glowColor, glowRadius, intensity)` — SDF rounded rect + falloff linéaire | LED strip dorée Shixbook absente |

### Typographie

| # | Fonction | Impact si absente |
|---|---|---|
| 12 | `GpuDrawTextFontAlign(x, y, maxW, text, fg, bg, font, size, align)` — align : 0=left 1=center 2=right | Titres centrés Figma = alignés à gauche |
| 13 | `GpuDrawTextFontFull(x, y, text, fg, bg, font, size, letterSp, lineH, align, deco)` — deco : 0=none 1=underline 2=strikethrough | Espacement lettres, line-height, soulignement incorrects |

### Dégradés

| # | Fonction | Impact si absente |
|---|---|---|
| 14 | `GpuDrawLinearGradient(x, y, w, h, r, angleDeg, c1, pos1, c2, pos2, stopCount)` — pos 0–1000 | Dégradés = couleur uniforme du premier stop |
| 15 | `GpuDrawRadialGradient(x, y, w, h, radius, c1, pos1, c2, pos2, stopCount)` — centre = rect center, pos 0–1000 | Dégradés radiaux Figma incorrects |
| 16 | `GpuDrawEllipse(x, y, w, h, color)` | Formes elliptiques invisibles |
| 17 | `GpuDrawGrainNoise(x, y, w, h, radius, color, grainSize)` — hash déterministe | Effet grain absent (navbar gesture) |

### Masques et clip

| # | Fonction | Impact si absente |
|---|---|---|
| 18 | `GpuPushClip(x, y, w, h, r)` / `GpuPopClip()` | Contenu débordant hors des conteneurs |
| 19 | `GpuCaptureMask(x, y, w, h)→ptr` / `GpuApplyAlphaMask(mask)` | Masques alpha Figma non appliqués |

### Images

| # | Fonction | Impact si absente |
|---|---|---|
| 18 | `GpuDrawRotatedImage(img, cx, cy, w, h, angleDeg)` | Images avec rotation dessinées droites |

### Rendu de base

| Fonction | Paramètres | Description |
|---|---|---|
| `GpuDrawRect` | `x, y, w, h, color` | Rectangle uni-couleur (ARGB) |
| `GpuDrawRoundedRectAlpha` | `x, y, w, h, r, color` | Rectangle arrondi avec alpha |
| `GpuDrawRoundedRectFull` | `x, y, w, h, rTL, rTR, rBL, rBR, color` | Coins arrondis par coin |
| `GpuFlushRenderContext` | — | Flush du framebuffer GOP |
| `GpuFill` | `color` | Remplissage écran entier |

### Opacité & Blend modes

| Fonction | Paramètres | Description |
|---|---|---|
| `GpuSetOpacity` | `opacity` (0–255) | Opacité globale pour tous les draws suivants |
| `GpuResetOpacity` | — | Remet l'opacité à 255 |
| `GpuSetBlendMode` | `mode` | Mode de fusion (voir table ci-dessous) |
| `GpuResetBlendMode` | — | Remet le mode à NORMAL (0) |

**Modes de fusion (`mode`)** :

| Valeur | Nom | Formule |
|---|---|---|
| 0 | NORMAL | `src·α + dst·(1−α)` |
| 1 | MULTIPLY | `src·dst/255` |
| 2 | SCREEN | `1−(1−src)(1−dst)` |
| 3 | OVERLAY | Multiply si dst < 128, Screen sinon |
| 4 | DARKEN | `min(src, dst)` |
| 5 | LIGHTEN | `max(src, dst)` |
| 6 | COLOR_DODGE | `dst / (1−src)` |
| 7 | COLOR_BURN | `1 − (1−dst) / src` |
| 8 | HARD_LIGHT | Overlay inversé source/dest |
| 9 | SOFT_LIGHT | Formule Pegtop |
| 10 | DIFFERENCE | `|src − dst|` |
| 11 | EXCLUSION | `src + dst − 2·src·dst` |

### Transformation 2D

| Fonction | Paramètres | Description |
|---|---|---|
| `GpuSetTransform2D` | `cos, sin, neg_sin, cos, pivot_x, pivot_y` | Rotation affine 2×2 (×10000) autour d'un pivot. Le kernel calcule `tx/ty` en interne : `tx = (px*(10000−cos) + py*sin) / 10000` |
| `GpuResetTransform` | — | Remet la matrice à l'identité |

Identité : `GpuSetTransform2D(10000, 0, 0, 10000, 0, 0)`.  
Rotation 45° autour de (cx, cy) : `GpuSetTransform2D(7071, 7071, -7071, 7071, cx, cy)`.  
Rotation 46° (dock diamonds) : `GpuSetTransform2D(6947, 7193, -7193, 6947, cx, cy)`.  
Args 4–5 sont le **pivot** (centre de l'élément en px écran) — pas la translation Figma.  
La transformation s'applique à tous les draws jusqu'au prochain `GpuResetTransform()`.

### Images

| Fonction | Paramètres | Description |
|---|---|---|
| `ImageLoad` | `path` | Charge un PNG depuis SRFS → `i32` handle (1–8, cache LRU). Chemin : `SDC:/apps/<App>/…` |
| `ImageDraw` | `handle i32, x, y, w, h` | Blit nearest-neighbour + Porter-Duff Over. GPU_OPACITY appliqué au canal alpha PNG. |
| `GpuDrawRotatedImage` | `handle i32, cx, cy, w, h, angleDeg` | Dessin d'image avec rotation (inverse mapping) |

### Gradients

| Fonction | Paramètres | Description |
|---|---|---|
| `GpuDrawLinearGradient` | `x, y, w, h, r, angleDeg, c1, pos1, c2, pos2, stopCount` | Gradient linéaire 2 stops |
| `GpuDrawRadialGradient` | `x, y, w, h, cx, cy, r, c1, c2` | Gradient radial |
| `GpuDrawGradientStroke` | `x, y, w, h, r, weight, stops_ptr, stopCount` | Contour avec gradient |

### Effets

| Fonction | Paramètres | Description |
|---|---|---|
| `GpuGaussianBlur` | `x, y, w, h, radius` | Flou gaussien (approximation box blur 3 passes) |
| `GpuBackgroundBlur` | `x, y, w, h, r, radius` | Flou de fond (shape arrondie) |
| `GpuProgressiveBlur` | `x, y, w, h, rMin, rMax` | Flou progressif du haut vers le bas |
| `GpuDrawDropShadow` | `x, y, w, h, cr, offX, offY, blurR, color` | Ombre portée externe |
| `GpuDrawInnerShadow` | `x, y, w, h, cr, offX, offY, blurR, color` | Ombre interne |

### Clip & Masque

| Fonction | Paramètres | Description |
|---|---|---|
| `GpuPushClip` | `x, y, w, h [, r]` | Empile une zone de clip |
| `GpuPopClip` | — | Dépile la zone de clip courante |
| `GpuCaptureMask` | `x, y, w, h` | Capture la région → handle masque |
| `GpuApplyAlphaMask` | `handle` | Applique la luminance du masque comme alpha |

### Bruit & Texture

| Fonction | Paramètres | Description |
|---|---|---|
| `GpuDrawNoisePatch` | `x, y, w, h, r, alpha, seed` | Bruit gris aléatoire (Xorshift) |
| `GpuDrawColoredNoise` | `x, y, w, h, r, alpha, seed, hue` | Bruit coloré |

### Contours (strokes)

| Fonction | Paramètres | Description |
|---|---|---|
| `GpuDrawStroke` | `x, y, w, h, r, weight, align, color` | Contour rectangle (inside/center/outside) |
| `GpuDrawDashedStroke` | `x, y, w, h, r, weight, dash, gap, color` | Contour pointillé |
| `GpuDrawGradientStroke` | `x, y, w, h, r, weight, stops_ptr, stopCount` | Contour dégradé |

### Texte

| Fonction | Paramètres | Description |
|---|---|---|
| `GpuDrawText` | `x, y, text, fg, bg` | Texte bitmap 8×16 (CP437) |
| `GpuDrawTextFont` | `x, y, text, fg, bg, font, size` | Texte TTF via stb_truetype pipeline |
| `GpuDrawTextFontAlign` | `x, y, maxW, text, fg, bg, font, size, align` | Texte TTF aligné (0=gauche, 1=centre, 2=droite) |
| `GpuDrawTextFontFull` | `x, y, text, fg, bg, font, size, letterSp, lineH, align, deco` | Texte complet (espacement, retours, décorations) |

### SVG

| Fonction | Paramètres | Description |
|---|---|---|
| `SvgLoad` | `path` | Charge un fichier SVG depuis SRFS → handle |
| `SvgDraw` | `handle, x, y, w, h` | Rend le SVG à l'écran (rect, circle, ellipse, line, polygon, path M/L/H/V/Z) |
| `SvgFree` | `handle` | Libère le slot SVG |

### Divers

| Fonction | Paramètres | Description |
|---|---|---|
| `TouchGetEvent` | — | Retourne 0 (pas de touch en UEFI boot) |

---

## Figma → Mara Bridge

Le plugin Figma exporte un design vers du code Maratine exécutable nativement sur Slura OS, avec état lié aux services système réels.

### Pipeline

```
Figma  →  Plugin TS  →  JSON tree  →  marai gen  →  .mara  →  marai build  →  .marep  →  Slura OS
```

### Règles de codegen obligatoires (plugin → Mara buildable)

Mara n'a que des entiers (`i32`). Le plugin **doit** appliquer ces transformations avant d'émettre du code :

| Source Figma | Règle de génération | Exemple |
|---|---|---|
| Coordonnée flottante (`570.5`) | `Math.round(v)` → `i32` | `570.5` → `571` |
| Pivot de rotation (`pivot_x`, `pivot_y`) | Centre de l'élément en px écran — **pas** les champs `tx/ty` de la transform matrix Figma | `node.x + node.width/2` → `571` |
| Valeur négative composée (`--7071`) | Calculer la valeur finale : `-(-7071) = 7071` | émettre `7071` |
| Valeur `-0` | Émettre `0` | `-0` → `0` |
| Opacité flottante (`0.30 * 255`) | `Math.round(opacity * 255)` | `0.30` → `77` |
| `sin`/`cos` de rotation (×10000) | `Math.round(Math.cos(deg * Math.PI/180) * 10000)` | `46°` → `6947` |

En TypeScript dans le plugin :

```typescript
// Utilitaires à utiliser pour toute valeur numérique émise en Mara
const i32 = (v: number): number => Math.round(v);
const cosFixed = (deg: number): number => Math.round(Math.cos(deg * Math.PI / 180) * 10000);
const sinFixed = (deg: number): number => Math.round(Math.sin(deg * Math.PI / 180) * 10000);

// Matrice 2D pour une rotation autour du centre de l'élément (pivot).
// pivotX/Y = centre de l'élément en pixels écran (absoluteBoundingBox.x + w/2, y + h/2).
// Ne pas passer les champs tx/ty de la transform matrix Figma — ce sont des valeurs différentes.
function rotationMatrix(deg: number, pivotX: number, pivotY: number): string {
    const cos = cosFixed(deg), sin = sinFixed(deg);
    return `${cos}, ${sin}, ${-sin}, ${cos}, ${i32(pivotX)}, ${i32(pivotY)}`;
}
// Emit:  <DrvAPIInterCon***GpuSetTransform2D***>(${rotationMatrix(deg, pivotX, pivotY)});
```

### Mapping layer Figma → GPU Mara

| Layer Figma | Appel Mara (SluGpu) | Propriétés exportées |
|---|---|---|
| `FRAME` | `GpuDrawRoundedRectFull` + `GpuBackgroundBlur` si blur | x, y, w, h, cornerRadius, fills[0], backgroundBlur |
| `TEXT` | `GpuDrawTextFontAlign` / `GpuDrawTextFontFull` | characters, fontSize, fills, textAlignHorizontal, letterSpacing, lineHeight |
| `RECTANGLE` + image | `ImageLoad` + `ImageDraw` | fills[0] (IMAGE) → path SRFS |
| `RECTANGLE` + DROP_SHADOW | `GpuDrawDropShadow` | effect.offset.x/y, effect.radius, effect.color |
| `RECTANGLE` + INNER_SHADOW | `GpuDrawInnerShadow` | idem, rendu après le rect parent |
| Gradient linéaire | `GpuDrawLinearGradient` | gradientStops, gradientTransform → angleDeg |
| `VECTOR` / `BOOLEAN_OPERATION` | `SvgLoad` + `SvgDraw` | Exporté en SVG via l'API Figma |
| Blend mode | `GpuSetBlendMode` + `GpuResetBlendMode` | MULTIPLY→1, SCREEN→2, OVERLAY→3… |
| Opacity | `GpuSetOpacity` + `GpuResetOpacity` | layer.opacity → 0–255 |
| `COMPONENT` (instance) | `rel op` paramétré | Chaque component Figma devient un `rel op` réutilisable |

### Structure du `.marep` généré

```
MonApp.marep/
├── Maraset.yaml
├── RAbstractallowing.xml
├── base/
│   ├── OEntry.mara       ← point d'entrée généré
│   ├── Components.mara   ← un rel op par Component Figma
│   └── State.mara        ← liaisons services OS
└── MonApp.slasset/
    ├── wallpaper.png     ← assets exportés depuis Figma
    └── icons/*.svg
```

### Liaison état réel (OS services)

Les variables Mara se lient aux services système. **Mara n'a pas de variables globales** : toutes les `var` doivent être déclarées à l'intérieur d'un `rel op`. Le plugin génère les variables d'état directement au début du `rel op OEntry`, avant la boucle de rendu.

| Service | Fonctions clés | Données |
|---|---|---|
| `SluPwManSrv` | `GetBatteryLevel()`, `IsCharging()` | Batterie 0–100, état charge |
| `SluFSInfo` | `GetFreePercent("SDC:")`, `ListMountPoints()` | Espace disque |
| `SluNotifSrv` | `GetCount()`, `GetBody(i)`, `GetAppName(i)` | Notifications actives |
| `SluEnvSys` | `Get("DEVICE_NAME")`, `Get("OS_VERSION")` | Variables système |
| `SluAppRegistry` | `GetInstalledCount()`, `GetApp(i)` | Apps installées |
| `SluTimeSrv` | `GetTimeString()`, `GetDateString()` | Horloge système |

### Organisation des fichiers générés

`Components.mara` ne contient que des `rel op` (pas de variables). Les variables d'état vivent dans `OEntry.mara` :

```text
MonApp.marep/
├── Maraset.yaml
├── RAbstractallowing.xml
├── base/
│   ├── OEntry.mara       ← vars d'état + boucle de rendu
│   └── Components.mara   ← un rel op par Component Figma (pas de var)
└── MonApp.slasset/
    ├── wallpaper.png
    └── icons/*.svg
```

### Composants Mara (un `rel op` par Component Figma)

`Components.mara` ne contient que des `rel op` paramétrés — jamais de `var` au niveau fichier :

```mara
// Component "NotifCard" Figma → rel op paramétré
rel op NotifCard: [x i32, y i32, appName string, body string, time string, iconHandle i32] [
    let W: i32 = 456; let H: i32 = 112; let R: i32 = 12;
    GpuDrawDropShadow(x, y, W, H, R, 0, 4, 20, 0x28000000);
    GpuDrawRoundedRectFull(x, y, W, H, R, R, R, R, 0xFFFFFFFF);
    GpuDrawTextFont(x+14, y+16, time, 0xFF888888, 0, font, 13);
    ImageDraw(iconHandle, x+64, y+13, 20, 20);
    GpuDrawTextFont(x+90, y+16, appName, 0xFF1A1A1A, 0, font, 13);
    GpuDrawTextFontFull(x+54, y+44, body, 0xFF555555, 0, font, 13, 0, 20, 0, 0);
];
```

### Boucle de rendu avec refresh état OS (OEntry.mara)

Les variables d'état sont déclarées avec `var` (mutable) **à l'intérieur** du `rel op OEntry`, avant la boucle :

```mara
rel op OEntry: [] [
    let font: ptr = FontLoad("SDC:/assets/fonts/brsonomasemibold.ttf");

    // ── État réel — initialisé une fois, rafraîchi chaque frame ──
    var battLevel:  i32    = <SluPwManSrv***GetBatteryLevel***>();
    var isCharging: i32    = <SluPwManSrv***IsCharging***>();
    var timeStr:    string = <SluTimeSrv***GetTimeString***>();
    var notifCount: i32    = <SluNotifSrv***GetCount***>();
    var deviceName: string = <SluEnvSys***Get***>("DEVICE_NAME");
    var activeTab:  i32    = 0;

    while (1) [
        // rendu ...
        GpuFlushRenderContext();

        // Refresh état OS chaque frame
        battLevel  = <SluPwManSrv***GetBatteryLevel***>();
        notifCount = <SluNotifSrv***GetCount***>();
        timeStr    = <SluTimeSrv***GetTimeString***>();
    ];
];
```

---

## Pipeline de chargement `.marep`

1. Lecture du bundle ZIP depuis l'ESP (SimpleFileSystem)
2. Vérification AuthARoot (SRID dans `Maraset.yaml` ↔ `RAbstractallowing.xml`)
3. **Auto-install assets** → `SDC:/apps/<AppName>/` (avant exécution OVC)
4. Exécution OVC via `exec_marep` (entry point `OEntry`)

---

## Scaling proportionnel — React Native style

Le plugin Figma génère les coordonnées sur la base du design cible (ex : 1440×1024).
À l'exécution OVC, les coordonnées sont scalées dynamiquement selon les dimensions réelles de l'écran :

```mara
let sw: <i32> = <DrvAPIInterCon***GpuGetWidth***>();
let sh: <i32> = <DrvAPIInterCon***GpuGetHeight***>();
let scaleW: <i32> = (sw * 1000) / 1440;
let scaleH: <i32> = (sh * 1000) / 1024;
var scale:  <i32> = scaleW;
if (scaleH < scaleW) [ scale = scaleH; ];
let offX: <i32> = (sw - (1440 * scale) / 1000) / 2;
let offY: <i32> = (sh - (1024 * scale) / 1000) / 2;
```

**Formule coordonnée scalée :** `(v * scale + 500) / 1000` — arrondi au plus proche (round-to-nearest).

Le plugin doit émettre `Math.round(v * scale / 1000)` pour toutes les valeurs numériques.
Les dimensions design (`designW`, `designH`) sont extraites de `Maraset.yaml → metadata.design_size`.

---

## Sécurité

`PRIMARY_VALIDATOR_PRIVKEY` est une constante de validation — ne pas modifier.

---

*Slura OS © 2026 Vyft Ltd. Tous droits réservés.*
