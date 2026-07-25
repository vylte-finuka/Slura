// Composition SUR une forme déjà existante — le plugin ne choisit JAMAIS la
// TEINTE DE BASE : toujours dérivée du fill de la forme d'origine, jamais
// une couleur inventée. Deux traitements distincts selon le mode (voir
// blob.ts, `paths.highlight` sert de signal de mode) :
//   - Anneau (paperFacets/innerRim, `highlight` = null) : reste STRICTEMENT
//     MAT — variations plus SOMBRES uniquement, aucun blanc/glossy, confirmé
//     explicitement par l'utilisateur.
//   - Ruban de soie (`highlight` non-null) : signature ShiUI référencée sur
//     le fond d'écran Windows 11 — highlights CLAIRS explicitement autorisés
//     ICI par l'utilisateur (dégradé satiné + sheen), pas un aplat.
import { LayerPaths } from "./blob";

interface OriginalFill {
  fills: Paint[];
  blendMode: BlendMode;
  opacity: number;
}

/** Lit le fill EXACT de la forme sélectionnée — jamais remplacé par une
 *  couleur du plugin. Si la forme n'a pas de fill exploitable (fills mixed,
 *  ou type sans fill), repli sur un gris neutre plutôt que d'échouer. */
function readOriginalFill(node: SceneNode): OriginalFill {
  const hasFills = "fills" in node && node.fills !== figma.mixed && (node.fills as Paint[]).length > 0;
  const fills = hasFills ? (node.fills as Paint[]) : [{ type: "SOLID", color: { r: 0.6, g: 0.6, b: 0.6 } } as SolidPaint];
  const blendMode = "blendMode" in node ? (node as MinimalBlendMixin).blendMode : "NORMAL";
  const opacity = "opacity" in node ? (node as MinimalBlendMixin).opacity : 1;
  return { fills, blendMode, opacity };
}

/** Couleur "principale" du fill de l'utilisateur : un SOLID directement, ou
 *  le premier stop d'un dégradé — sert UNIQUEMENT à dériver la teinte claire
 *  du segment d'anneau (même ton éclairci, jamais une couleur inventée).
 *  null si aucune couleur n'est extractible (fill image par ex.). */
function primaryColorOf(fills: Paint[]): RGB | null {
  const first = fills[0];
  if (!first) return null;
  if (first.type === "SOLID") return first.color;
  if (first.type === "GRADIENT_LINEAR" || first.type === "GRADIENT_RADIAL" ||
      first.type === "GRADIENT_ANGULAR" || first.type === "GRADIENT_DIAMOND") {
    const stop = first.gradientStops[0];
    if (stop) return { r: stop.color.r, g: stop.color.g, b: stop.color.b };
  }
  return null;
}

/** Éclaircit la couleur de l'utilisateur vers son propre ton pastel (mélange
 *  partiel, PAS du blanc pur — mat, comme le segment bleu clair du spinner de
 *  référence). */
function lighten(c: RGB, amount: number): RGB {
  return {
    r: c.r + (1 - c.r) * amount,
    g: c.g + (1 - c.g) * amount,
    b: c.b + (1 - c.b) * amount,
  };
}

/** Assombrit la couleur de l'utilisateur vers le ton neutre sombre (mélange
 *  partiel) — utilisé pour les facettes "papier" : une feuille plus sombre
 *  du MÊME ton, jamais une couleur inventée ni un blanc/glossy. */
function darken(c: RGB, amount: number): RGB {
  return {
    r: c.r + (DARK_TONE.r - c.r) * amount,
    g: c.g + (DARK_TONE.g - c.g) * amount,
    b: c.b + (DARK_TONE.b - c.b) * amount,
  };
}

function buildShadowFill(): SolidPaint {
  return { type: "SOLID", color: DARK_TONE };
}

const DARK_TONE: RGB = { r: 0.05, g: 0.05, b: 0.12 };

/** Rotation-autour-du-centre du carré unité (0.5,0.5) — formule standard
 *  dérivée par nous-mêmes (transformed = R·(p-c)+c), déjà réutilisée dans ce
 *  projet pour orienter un dégradé Figma. 0° = horizontal gauche→droite. */
function gradientTransformFromAngle(angleDeg: number): Transform {
  const a = (angleDeg * Math.PI) / 180;
  const cos = Math.cos(a);
  const sin = Math.sin(a);
  return [
    [cos, -sin, 0.5 - 0.5 * cos + 0.5 * sin],
    [sin, cos, 0.5 - 0.5 * sin - 0.5 * cos],
  ];
}

/** Dégradé satiné (ruban de soie) : sombre -> teinte de base -> clair ->
 *  presque-blanc -> sombre, façon soie qui capte la lumière en travers d'une
 *  courbe — highlights CLAIRS explicitement autorisés pour CE mode
 *  (confirmé par l'utilisateur, référence fond d'écran Windows 11), à la
 *  différence de l'anneau qui reste mat. Toujours dérivé de la couleur
 *  choisie par l'utilisateur, jamais une teinte inventée. */
function buildSatinGradient(tone: RGB): GradientPaint {
  const dark = darken(tone, 0.4);
  const soft = lighten(tone, 0.35);
  const bright = lighten(tone, 0.85);
  return {
    type: "GRADIENT_LINEAR",
    gradientTransform: gradientTransformFromAngle(50),
    gradientStops: [
      { position: 0, color: { ...dark, a: 1 } },
      { position: 0.32, color: { ...tone, a: 1 } },
      { position: 0.58, color: { ...soft, a: 1 } },
      { position: 0.74, color: { ...bright, a: 1 } },
      { position: 1, color: { ...dark, a: 1 } },
    ],
  };
}

/** Sheen radial (halo satiné) — un vrai reflet clair, PAS du blanc pur
 *  (mélange avec la teinte de base), en blend SCREEN pour un vrai éclat
 *  optique plutôt qu'un aplat clair posé dessus. */
function buildSheenGradient(tone: RGB): GradientPaint {
  const bright = lighten(tone, 0.9);
  return {
    type: "GRADIENT_RADIAL",
    gradientTransform: [
      [1, 0, 0],
      [0, 1, 0],
    ],
    gradientStops: [
      { position: 0, color: { ...bright, a: 0.9 } },
      { position: 1, color: { ...bright, a: 0 } },
    ],
  };
}

export interface ApplyReliefOptions {
  withShadow: boolean;
  shadowBlur: number;
  /** NONZERO pour un blob plein, EVENODD pour l'anneau (le 2e sous-chemin
   *  creuse le trou du donut — voir blob.ts, buildRingDonutPath). */
  winding: WindingRule;
  /** Intensité (0..1) des facettes papier — 0 = pas de calque "Paper facets"
   *  du tout (bandeau parfaitement uni), l'effet "cordon torsadé" ne se voit
   *  QUE via ces facettes (jamais via le contour, toujours un cercle
   *  parfait). Pilote à la fois l'assombrissement de la facette et
   *  l'intensité de son ombre portée. */
  twistIntensity: number;
}

/** Construit les couches (ombre + corps [fill d'origine] + segment clair
 *  éventuel) et REMPLACE la forme sélectionnée par ce groupe, à la même
 *  position/centre, même index dans son parent. Rendu MAT : blend NORMAL
 *  partout sauf l'ombre (MULTIPLY), aucun SCREEN/glossy. */
export function applyWaveRelief(target: SceneNode, paths: LayerPaths, opts: ApplyReliefOptions): GroupNode {
  // Tous les types concrets de SceneNode (l'union complète des nœuds Figma)
  // portent x/y/width/height via LayoutMixin — pas de garde nécessaire ici,
  // le filtrage sur les types "forme" (VECTOR/RECTANGLE/...) se fait déjà
  // côté appelant (voir code.ts, SHAPE_TYPES).
  const originalCenter = { x: target.x + target.width / 2, y: target.y + target.height / 2 };
  const originalFill = readOriginalFill(target);
  const originalName = target.name;

  const parent = target.parent;
  if (!parent || !("insertChild" in parent)) {
    throw new Error(`"${target.name}" n'a pas de parent exploitable.`);
  }
  const container = parent as ChildrenMixin & BaseNode;
  const index = "children" in parent ? (parent as ChildrenMixin).children.indexOf(target) : 0;

  const layers: SceneNode[] = [];

  const shadow = figma.createVector();
  shadow.name = "Shadow";
  shadow.vectorPaths = [{ windingRule: opts.winding, data: paths.shadow }];
  shadow.fills = [buildShadowFill()];
  shadow.effects = opts.shadowBlur > 0 ? [{ type: "LAYER_BLUR", radius: opts.shadowBlur, visible: true } as BlurEffect] : [];
  shadow.blendMode = "MULTIPLY";
  shadow.opacity = opts.withShadow ? 0.58 : 0;
  layers.push(shadow);

  // `paths.highlight` non-null == mode Ruban de soie (voir blob.ts) — seul
  // mode où un dégradé satiné avec highlights clairs remplace le fill plat.
  const isSilkRibbon = paths.highlight !== null;
  const tone = primaryColorOf(originalFill.fills);

  const body = figma.createVector();
  body.name = "Body";
  body.vectorPaths = [{ windingRule: opts.winding, data: paths.body }];
  body.fills = isSilkRibbon && tone ? [buildSatinGradient(tone)] : originalFill.fills;
  body.blendMode = originalFill.blendMode;
  body.opacity = originalFill.opacity;
  layers.push(body);

  if (paths.highlight && tone) {
    // Sheen satiné excentré — highlight CLAIR explicitement autorisé pour ce
    // mode (voir en-tête de fichier), jamais pour l'anneau.
    const highlight = figma.createVector();
    highlight.name = "Sheen";
    highlight.vectorPaths = [{ windingRule: "NONZERO", data: paths.highlight }];
    highlight.fills = [buildSheenGradient(tone)];
    highlight.blendMode = "SCREEN";
    highlight.opacity = 0.8;
    layers.push(highlight);
  }

  if (paths.innerRim && opts.withShadow) {
    // Occlusion ambiante près du bord intérieur — même réflexe qu'un vrai
    // rendu 3D (l'intérieur d'un tube s'assombrit), toujours en MULTIPLY
    // neutre. Couplée au toggle "ombre" plutôt qu'un réglage séparé.
    const innerRim = figma.createVector();
    innerRim.name = "Inner rim shadow";
    innerRim.vectorPaths = [{ windingRule: "EVENODD", data: paths.innerRim }];
    innerRim.fills = [buildShadowFill()];
    innerRim.blendMode = "MULTIPLY";
    innerRim.opacity = 0.42;
    layers.push(innerRim);
  }

  if (paths.paperFacets && opts.twistIntensity > 0) {
    // "Effet papier" : facettes ALTERNÉES en aplat (pas un dégradé peint) —
    // une feuille plus sombre du même ton + sa propre ombre portée franche,
    // façon ruban de papier plié. Fill SOLID opaque (NORMAL, pas MULTIPLY) :
    // une vraie feuille de papier est une surface opaque avec sa propre
    // teinte, pas un lavis translucide. Le contour reste un cercle parfait
    // (voir blob.ts, buildRingPaperFacetsPath) — seule cette facette-là porte
    // une teinte assombrie + une ombre, jamais le contour lui-même.
    const facetColor = tone ? darken(tone, 0.35 + opts.twistIntensity * 0.4) : DARK_TONE;
    const facets = figma.createVector();
    facets.name = "Paper facets";
    facets.vectorPaths = [{ windingRule: "NONZERO", data: paths.paperFacets }];
    facets.fills = [{ type: "SOLID", color: facetColor } as SolidPaint];
    facets.blendMode = "NORMAL";
    facets.opacity = 1;
    // Ombre DOUCE par défaut (diffuse, comme une vraie feuille de papier
    // légèrement soulevée sous éclairage ambiant — pas un décroché dur) :
    // flou généreux + faible décalage, c'est le flou qui vend "papier",
    // un bord dur lirait comme une simple découpe plate. Best-effort :
    // Figma applique en général un DROP_SHADOW par région de remplissage
    // disjointe d'un même vecteur, mais ce détail n'a pas pu être vérifié
    // dans un vrai Figma depuis cet environnement.
    facets.effects = [
      {
        type: "DROP_SHADOW",
        color: { r: 0, g: 0, b: 0, a: 0.5 * Math.max(0, Math.min(1, opts.twistIntensity)) },
        offset: { x: 0.75, y: 1.5 },
        radius: 9,
        spread: 0,
        visible: true,
        blendMode: "NORMAL",
      } as DropShadowEffect,
    ];
    layers.push(facets);
  }

  if (paths.segment) {
    if (tone) {
      const segment = figma.createVector();
      segment.name = "Segment";
      segment.vectorPaths = [{ windingRule: "NONZERO", data: paths.segment }];
      segment.fills = [{ type: "SOLID", color: lighten(tone, 0.45) } as SolidPaint];
      segment.blendMode = "NORMAL";
      segment.opacity = 1;
      layers.push(segment);
    }
  }

  let insertAt = index;
  for (const layer of layers) {
    container.insertChild(insertAt, layer);
    insertAt++;
  }

  const group = figma.group(layers, container);
  group.name = originalName;
  group.x = originalCenter.x - group.width / 2;
  group.y = originalCenter.y - group.height / 2;

  target.remove();
  return group;
}
