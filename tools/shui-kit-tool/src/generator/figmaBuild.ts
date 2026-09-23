// Composition SUR une forme déjà existante — le plugin ne choisit JAMAIS la
// teinte de base : toujours dérivée du fill de la forme d'origine, jamais
// une couleur inventée. Deux traitements distincts selon le mode
// (`paths.highlight` sert de signal — non-null == ruban de soie) :
//   - Ruban de soie : dégradé satiné + sheen — highlights CLAIRS
//     explicitement voulus pour cette signature (référence : fond d'écran
//     Windows 11).
//   - Anneau : reste STRICTEMENT MAT (variations sombres uniquement, jamais
//     de blanc/glossy) ET SANS AUCUNE TEXTURE — aplat uni + ombre + occlusion
//     intérieure, éventuellement un segment plus clair comme seul repère de
//     rotation. Le plugin ne doit JAMAIS pouvoir produire un anneau
//     "texturé/facetté", quel que soit le réglage — cette fonctionnalité a
//     été retirée plutôt que désactivée par défaut.
import { LayerPaths } from "./blob";

const DARK_TONE: RGB = { r: 0.05, g: 0.05, b: 0.12 };

interface OriginalFill {
  fills: Paint[];
  blendMode: BlendMode;
  opacity: number;
}

/** Lit le fill EXACT de la forme sélectionnée — jamais remplacé par une
 *  couleur du plugin. Repli sur un gris neutre si le fill n'est pas
 *  exploitable (mixed, ou type sans fill) plutôt que d'échouer. */
function readOriginalFill(node: SceneNode): OriginalFill {
  const hasFills = "fills" in node && node.fills !== figma.mixed && (node.fills as Paint[]).length > 0;
  const fills = hasFills ? (node.fills as Paint[]) : [{ type: "SOLID", color: { r: 0.6, g: 0.6, b: 0.6 } } as SolidPaint];
  const blendMode = "blendMode" in node ? (node as MinimalBlendMixin).blendMode : "NORMAL";
  const opacity = "opacity" in node ? (node as MinimalBlendMixin).opacity : 1;
  return { fills, blendMode, opacity };
}

/** Couleur "principale" du fill de l'utilisateur : un SOLID directement, ou
 *  le premier stop d'un dégradé — jamais une teinte inventée. null si aucune
 *  couleur n'est extractible (fill image par ex.). */
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

function lighten(c: RGB, amount: number): RGB {
  return {
    r: c.r + (1 - c.r) * amount,
    g: c.g + (1 - c.g) * amount,
    b: c.b + (1 - c.b) * amount,
  };
}

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

/** Rotation-autour-du-centre du carré unité (0.5,0.5) — formule standard
 *  (transformed = R·(p-c)+c) pour orienter un GradientPaint Figma. 0° =
 *  horizontal gauche→droite (transform identité). */
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
 *  courbe. Toujours dérivé de la couleur choisie par l'utilisateur. */
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

/** Sheen radial (halo satiné) — un vrai reflet, pas du blanc pur (mélange
 *  avec la teinte de base), en blend SCREEN pour un éclat optique réel
 *  plutôt qu'un aplat clair posé dessus. */
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
  /** NONZERO pour le ruban, EVENODD pour l'anneau (2e sous-chemin creuse le
   *  trou du donut — voir blob.ts, ringDonutPath). */
  winding: WindingRule;
  /** Nom donné au groupe résultant — le MÊME nom pour toutes les keyframes
   *  d'une même animation (voir animate.ts), JAMAIS `target.name` repris tel
   *  quel : Smart Animate (Figma Motion) apparie les calques par NOM à
   *  chaque niveau d'imbrication, et un workflow courant (dupliquer une
   *  forme pour créer les keyframes) fait que Figma incrémente
   *  automatiquement leurs noms ("Ellipse 1", "Ellipse 2"...) — avec un nom
   *  de groupe différent par keyframe, Smart Animate ne les reconnaîtrait
   *  jamais comme "le même calque" et l'animation ne s'interpolerait pas.
   */
  groupName: string;
}

/** Construit les couches et REMPLACE la forme sélectionnée par le groupe
 *  résultant, à la même position/centre, même index dans son parent. */
export function applyWaveRelief(target: SceneNode, paths: LayerPaths, opts: ApplyReliefOptions): GroupNode {
  // Tous les types concrets de SceneNode portent x/y/width/height via
  // LayoutMixin — le filtrage sur les types "forme" se fait côté appelant
  // (voir code.ts, SHAPE_TYPES).
  const originalCenter = { x: target.x + target.width / 2, y: target.y + target.height / 2 };
  const originalFill = readOriginalFill(target);

  const parent = target.parent;
  if (!parent || !("insertChild" in parent)) {
    throw new Error(`"${target.name}" n'a pas de parent exploitable.`);
  }
  const container = parent as ChildrenMixin & BaseNode;
  const index = "children" in parent ? (parent as ChildrenMixin).children.indexOf(target) : 0;

  const layers: SceneNode[] = [];
  const isSilkRibbon = paths.highlight !== null;
  const tone = primaryColorOf(originalFill.fills);

  const shadow = figma.createVector();
  shadow.name = "Shadow";
  shadow.vectorPaths = [{ windingRule: opts.winding, data: paths.shadow }];
  shadow.fills = [buildShadowFill()];
  shadow.effects = opts.shadowBlur > 0 ? [{ type: "LAYER_BLUR", radius: opts.shadowBlur, visible: true } as BlurEffect] : [];
  shadow.blendMode = "MULTIPLY";
  shadow.opacity = opts.withShadow ? 0.58 : 0;
  layers.push(shadow);

  const body = figma.createVector();
  body.name = "Body";
  body.vectorPaths = [{ windingRule: opts.winding, data: paths.body }];
  body.fills = isSilkRibbon && tone ? [buildSatinGradient(tone)] : originalFill.fills;
  body.blendMode = originalFill.blendMode;
  body.opacity = originalFill.opacity;
  layers.push(body);

  if (paths.highlight && tone) {
    const highlight = figma.createVector();
    highlight.name = "Sheen";
    highlight.vectorPaths = [{ windingRule: "NONZERO", data: paths.highlight }];
    highlight.fills = [buildSheenGradient(tone)];
    highlight.blendMode = "SCREEN";
    highlight.opacity = 0.8;
    layers.push(highlight);
  }

  if (paths.innerRim && opts.withShadow) {
    // Occlusion ambiante près du bord intérieur — "l'intérieur d'un tube
    // s'assombrit" — toujours en MULTIPLY neutre, couplée au toggle "ombre".
    const innerRim = figma.createVector();
    innerRim.name = "Inner rim shadow";
    innerRim.vectorPaths = [{ windingRule: "EVENODD", data: paths.innerRim }];
    innerRim.fills = [buildShadowFill()];
    innerRim.blendMode = "MULTIPLY";
    innerRim.opacity = 0.42;
    layers.push(innerRim);
  }

  if (paths.segment && tone) {
    const segment = figma.createVector();
    segment.name = "Segment";
    segment.vectorPaths = [{ windingRule: "NONZERO", data: paths.segment }];
    // Éclaircissement MODÉRÉ (pas 0.45) : sur une base déjà pastel/claire,
    // trop d'éclaircissement fait basculer le segment vers un blanc lavé,
    // perdant la teinte — "toujours pastel" doit rester vrai pour CE calque
    // aussi, pas seulement pour le corps.
    segment.fills = [{ type: "SOLID", color: lighten(tone, 0.28) } as SolidPaint];
    segment.blendMode = "NORMAL";
    segment.opacity = 1;
    layers.push(segment);
  }

  let insertAt = index;
  for (const layer of layers) {
    container.insertChild(insertAt, layer);
    insertAt++;
  }

  const group = figma.group(layers, container);
  group.name = opts.groupName;
  group.x = originalCenter.x - group.width / 2;
  group.y = originalCenter.y - group.height / 2;

  target.remove();
  return group;
}
