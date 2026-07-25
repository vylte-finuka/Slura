// Génération de la géométrie d'un blob organique ("liquid wave" façon
// Floava) OU d'un anneau rotatif (spinner, voir plus bas) — PUR calcul de
// PATH, aucune couleur ici : le fill du corps est copié depuis la forme
// d'origine, jamais choisi par ce plugin (voir figmaBuild.ts). Esthétique
// ShUI = MATE et épurée : pas de reflet glossy/blanc plaqué, le relief vient
// uniquement d'une ombre portée neutre (noir flouté). Le blob est un cercle
// de N points dont le rayon individuel varie dans le temps, lissé en courbe
// fermée par des Bézier cubiques de type Catmull-Rom (formule uniforme
// standard, tension implicite 1/6 — voir pointsToSmoothClosedPath).
//
// Le nombre de points N est FIXE pour toutes les frames d'une même
// animation : c'est ce qui permet à Smart Animate de Figma d'interpoler les
// points un à un (vrai morph liquide), pas un simple fondu — Smart Animate
// ne peut apparier des vecteurs point-à-point QUE si leur topologie (même
// nombre de points, même ordre) est identique entre les deux frames.
export interface BlobPoint {
  x: number;
  y: number;
}

export interface BlobShapeParams {
  cx: number;
  cy: number;
  baseRadius: number;
  pointCount: number;
  /** Amplitude de la "respiration" du rayon par point, 0..1 (0 = cercle parfait). */
  jitter: number;
  /** Phase fixe par point (0..1), dérivée du seed — garantit la MÊME
   *  topologie de forme sur toutes les frames d'une animation, seule la
   *  valeur de `timeT` fait "respirer"/tourner le blob dans le temps. */
  pointPhases: number[];
  /** Position dans le cycle d'animation, 0..1 — 0 et 1 produisent EXACTEMENT
   *  la même forme (boucle continue, aucun à-coup au raccord). */
  timeT: number;
  /** Nombre de tours de rotation sur tout le cycle (0 = pas de rotation, pur
   *  effet de respiration). */
  rotationTurns: number;
}

/** Dérive N phases fixes (0..1) à partir du PRNG — appelé UNE fois par blob,
 *  réutilisé pour toutes ses frames d'animation (voir commentaire ci-dessus). */
export function derivePointPhases(pointCount: number, rnd: () => number): number[] {
  const phases: number[] = [];
  for (let i = 0; i < pointCount; i++) phases.push(rnd());
  return phases;
}

export function generateBlobPoints(p: BlobShapeParams): BlobPoint[] {
  const points: BlobPoint[] = [];
  const rotation = p.rotationTurns * Math.PI * 2 * p.timeT;
  for (let i = 0; i < p.pointCount; i++) {
    const angle = (i / p.pointCount) * Math.PI * 2 + rotation;
    // "Respiration" : oscillation sinusoïdale du rayon, déphasée par point —
    // periode = 1 tour de timeT donc frame(timeT=0) === frame(timeT=1).
    const wobble = Math.sin(Math.PI * 2 * (p.timeT + p.pointPhases[i]));
    const r = p.baseRadius * (1 + wobble * p.jitter * 0.5);
    points.push({ x: p.cx + Math.cos(angle) * r, y: p.cy + Math.sin(angle) * r });
  }
  return points;
}

/** Catmull-Rom uniforme -> Bézier cubique, courbe FERMÉE (le dernier point
 *  se raccorde au premier). Formule standard : cp1 = p1 + (p2-p0)/6,
 *  cp2 = p2 - (p3-p1)/6. Le `d` produit est un chemin SVG, directement
 *  utilisable comme `VectorPath.data` côté API Figma (voir figmaBuild.ts) —
 *  SÉPARATEURS ESPACE UNIQUEMENT (pas de virgule) : le parser de chemin de
 *  `vectorPaths` s'est révélé plus strict que la spec SVG générale et rejette
 *  la virgule ("Invalid command at ,"), constaté à l'usage réel du plugin. */
export function pointsToSmoothClosedPath(points: BlobPoint[]): string {
  const n = points.length;
  if (n < 3) return "";
  const at = (i: number): BlobPoint => points[((i % n) + n) % n];
  const fmt = (v: number): string => v.toFixed(2);

  let d = `M ${fmt(at(0).x)} ${fmt(at(0).y)} `;
  for (let i = 0; i < n; i++) {
    const p0 = at(i - 1);
    const p1 = at(i);
    const p2 = at(i + 1);
    const p3 = at(i + 2);
    const c1x = p1.x + (p2.x - p0.x) / 6;
    const c1y = p1.y + (p2.y - p0.y) / 6;
    const c2x = p2.x - (p3.x - p1.x) / 6;
    const c2y = p2.y - (p3.y - p1.y) / 6;
    d += `C ${fmt(c1x)} ${fmt(c1y)} ${fmt(c2x)} ${fmt(c2y)} ${fmt(p2.x)} ${fmt(p2.y)} `;
  }
  return d + "Z";
}

/** Chemin complet d'un blob pour une frame d'animation donnée (timeT), à un
 *  centre/rayon explicites. */
export function buildBlobPath(
  cx: number,
  cy: number,
  baseRadius: number,
  pointCount: number,
  jitter: number,
  pointPhases: number[],
  timeT: number,
  rotationTurns: number
): string {
  const points = generateBlobPoints({ cx, cy, baseRadius, pointCount, jitter, pointPhases, timeT, rotationTurns });
  return pointsToSmoothClosedPath(points);
}

export interface LayerPaths {
  body: string;
  shadow: string;
  /** Segment d'arc plus clair (anneau uniquement — c'est lui qui rend la
   *  rotation lisible, comme sur un vrai spinner) ; null en mode blob. */
  segment: string | null;
  /** Ombre d'occlusion près du bord intérieur (façon "intérieur d'un tube" —
   *  accentue la profondeur perçue du bandeau) ; null en mode blob ou si
   *  ombre désactivée. Contour TOUJOURS un cercle parfait (retour
   *  utilisateur explicite : "un anneau parfait"). */
  innerRim: string | null;
  /** Facettes "papier" alternées (une torsion sur deux) façon ruban de
   *  papier plié — chaque facette est un aplat (pas un dégradé), avec sa
   *  propre ombre portée en figmaBuild.ts pour l'effet "feuilles empilées"
   *  ("effet papier" demandé) ; null en mode blob/ruban ou si torsion
   *  désactivée. */
  paperFacets: string | null;
  /** Silhouette de reflet (ruban de soie uniquement) — une forme plus petite
   *  et excentrée, remplie d'un dégradé CLAIR (voir figmaBuild.ts) pour le
   *  sheen satiné ; null en mode anneau (qui reste mat, voir plus bas). */
  highlight: string | null;
}

/** Prépare les chemins (ombre décalée+agrandie, corps, reflet excentré) pour
 *  UNE frame de RUBAN DE SOIE — mêmes pointPhases/timeT/rotationTurns donc
 *  topologie identique entre les couches ET entre toutes les frames d'une
 *  animation. Les couches partagent la même origine locale (0,0)..
 *  (canvasSize, canvasSize) : le décalage de l'ombre/reflet est "cuit" dans
 *  les coordonnées du path lui-même, pas géré via un repositionnement de
 *  nœud après coup. Signature ShiUI (référence utilisateur : vagues de soie
 *  façon fond d'écran Windows 11) — highlights CLAIRS autorisés pour ce mode
 *  spécifiquement (voir figmaBuild.ts, dégradé satiné), contrairement au mode
 *  Anneau qui reste strictement mat. */
export function buildBlobLayerPaths(
  canvasSize: number,
  baseRadius: number,
  pointCount: number,
  jitter: number,
  pointPhases: number[],
  timeT: number,
  rotationTurns: number
): LayerPaths {
  const cx = canvasSize / 2;
  const cy = canvasSize / 2;
  const shadowOffset = baseRadius * 0.11;
  const highlightOffset = baseRadius * 0.26;

  return {
    body: buildBlobPath(cx, cy, baseRadius, pointCount, jitter, pointPhases, timeT, rotationTurns),
    shadow: buildBlobPath(
      cx + shadowOffset, cy + shadowOffset, baseRadius * 1.08,
      pointCount, jitter, pointPhases, timeT, rotationTurns
    ),
    highlight: buildBlobPath(
      cx - highlightOffset, cy - highlightOffset, baseRadius * 0.55,
      pointCount, jitter, pointPhases, timeT, rotationTurns
    ),
    segment: null,
    innerRim: null,
    paperFacets: null,
  };
}

// ── Anneau rotatif (bandeau torsadé) ─────────────────────────────────────────
// "Un anneau PARFAIT" (retour utilisateur explicite) : le contour extérieur
// ET intérieur restent des cercles concentriques parfaits, épaisseur de
// bande CONSTANTE — aucune déformation de silhouette, quelle que soit
// l'intensité de la torsion. L'effet "cordon torsadé photoréaliste" se lit
// ENTIÈREMENT dans le SHADING : un vrai dégradé Figma multi-stops
// (GRADIENT_ANGULAR, voir figmaBuild.ts) posé en MULTIPLY sur `body`, avec
// une transition continue et lisse — c'est ce qui évite le rendu "2D plat" à
// bords durs (l'ancienne version en bandes séparées) sans jamais éclaircir
// la couleur d'origine (rendu mat maintenu, confirmé par l'utilisateur).
//
// Le trou est obtenu par DEUX cercles concentriques dans un même path avec
// windingRule EVENODD (voir figmaBuild.ts) — un vrai anneau vectoriel, pas
// deux formes empilées. Le segment plus clair façon spinner reste optionnel
// (withSegment, off par défaut).

/** Nombre d'échantillons FIXE (topologie constante entre keyframes — requis
 *  par le morph Smart Animate, même règle que le blob). */
const RING_SAMPLES = 48;
const SEGMENT_STEPS = 12;
/** Balayage du segment clair (~80°, comme le spinner de référence). */
const SEGMENT_SWEEP = 1.4;

interface RingGeom {
  cx: number;
  cy: number;
  outerRadius: number;
  thickness: number;
  timeT: number;
  rotationTurns: number;
}

function ringPoint(theta: number, radius: number, g: RingGeom): BlobPoint {
  return { x: g.cx + Math.cos(theta) * radius, y: g.cy + Math.sin(theta) * radius };
}

/** Cercles concentriques PARFAITS (contour toujours rond, épaisseur toujours
 *  constante) — le nombre de points reste fixe (topologie requise par Smart
 *  Animate), le rayon ne varie JAMAIS avec l'angle. */
function buildRingDonutPath(g: RingGeom): string {
  const outer: BlobPoint[] = [];
  const inner: BlobPoint[] = [];
  const innerRadius = Math.max(1, g.outerRadius - g.thickness);
  for (let i = 0; i < RING_SAMPLES; i++) {
    const theta = (i / RING_SAMPLES) * Math.PI * 2;
    outer.push(ringPoint(theta, g.outerRadius, g));
    inner.push(ringPoint(theta, innerRadius, g));
  }
  // Deux sous-chemins fermés dans un seul `data` — EVENODD creuse le trou.
  return pointsToSmoothClosedPath(outer) + " " + pointsToSmoothClosedPath(inner);
}

/** Segment d'arc (bande partielle de l'anneau, optionnelle) — bords radiaux
 *  droits comme le spinner de référence. Tourne avec l'anneau (départ =
 *  offset de rotation dérivé de timeT, pour suivre l'animation). */
function buildRingSegmentPath(g: RingGeom): string {
  const start = g.rotationTurns * Math.PI * 2 * g.timeT;
  const innerRadius = Math.max(1, g.outerRadius - g.thickness);
  const fmt = (v: number): string => v.toFixed(2);
  let d = "";
  for (let i = 0; i <= SEGMENT_STEPS; i++) {
    const theta = start + (i / SEGMENT_STEPS) * SEGMENT_SWEEP;
    const p = ringPoint(theta, g.outerRadius, g);
    d += (i === 0 ? `M ${fmt(p.x)} ${fmt(p.y)} ` : `L ${fmt(p.x)} ${fmt(p.y)} `);
  }
  for (let i = SEGMENT_STEPS; i >= 0; i--) {
    const theta = start + (i / SEGMENT_STEPS) * SEGMENT_SWEEP;
    const p = ringPoint(theta, innerRadius, g);
    d += `L ${fmt(p.x)} ${fmt(p.y)} `;
  }
  return d + "Z";
}

/** Ombre d'occlusion fine juste à l'intérieur du bord intérieur du bandeau —
 *  façon "on voit l'intérieur d'un tube qui s'assombrit" : un vrai réflexe
 *  de rendu 3D (ambient occlusion), ici un second anneau très fin en blend
 *  MULTIPLY, toujours parfaitement concentrique (aucune déformation). */
function buildRingInnerRimPath(g: RingGeom, rimWidth: number): string {
  const rimOuter = Math.max(1, g.outerRadius - g.thickness);
  const rimInner = Math.max(0.5, rimOuter - rimWidth);
  const outer: BlobPoint[] = [];
  const inner: BlobPoint[] = [];
  for (let i = 0; i < RING_SAMPLES; i++) {
    const theta = (i / RING_SAMPLES) * Math.PI * 2;
    outer.push(ringPoint(theta, rimOuter, g));
    inner.push(ringPoint(theta, rimInner, g));
  }
  return pointsToSmoothClosedPath(outer) + " " + pointsToSmoothClosedPath(inner);
}

/** Nombre d'échantillons par bord de facette — les bords restent des cordes
 *  quasi droites (arcs étroits), 2 suffisent pour suivre la courbure sans
 *  facette d'aliasing visible. */
const PAPER_EDGE_SAMPLES = 2;

/** Facettes "papier" alternées façon ruban plié : le tour est divisé en
 *  `facetCount` secteurs égaux, MAIS le bord intérieur de chaque secteur est
 *  décalé (skew) par rapport à son bord extérieur — c'est ce décalage qui lit
 *  comme une torsion (barber pole) plutôt qu'un simple découpage en parts de
 *  tarte. Une facette sur deux est retournée (k pair uniquement) : les
 *  facettes manquantes laissent voir `body` en dessous — l'alternance
 *  "aplat plus sombre / couleur d'origine" est ce qui donne l'effet "feuilles
 *  de papier pliées", pas un dégradé peint. Contour TOUJOURS un cercle
 *  parfait (les bords radiaux de chaque facette suivent exactement
 *  outerRadius/innerRadius du bandeau, jamais une déformation). */
function buildRingPaperFacetsPath(g: RingGeom, facetCount: number): string {
  if (facetCount <= 0) return "";
  const rot = g.rotationTurns * Math.PI * 2 * g.timeT;
  const gap = (Math.PI * 2) / facetCount;
  // Décalage MODESTE (pas 0.85 de l'ancienne version, bien trop agressif) :
  // au-delà d'environ un quart de la largeur d'une facette, les quadrilatères
  // deviennent des parallélogrammes très inclinés qui se chevauchent en se
  // repliant vers le centre — exactement l'artefact "iris d'appareil photo"
  // remonté par l'utilisateur, pas un ruban torsadé. 0.25 donne un décalage
  // encore lisible comme une torsion douce sans auto-intersection.
  const skew = gap * 0.25;
  // Léger DÉBORDEMENT sur la facette voisine (non dessinée, couleur d'origine
  // visible dessous) — sans lui, la facette s'arrête pile au bord de son
  // "trou" et son ombre portée tombe dans le vide (rien à assombrir juste à
  // côté) : elle se voit à peine, d'où le rendu plat remonté. Avec le
  // débordement, le bord de la facette (et donc son ombre) tombe VISIBLEMENT
  // sur la couleur d'origine juste à côté — c'est ce petit surplomb qui lit
  // comme "un pli de papier posé par-dessus l'autre", pas un aplat plaqué.
  const overlap = gap * 0.12;
  const innerRadius = Math.max(1, g.outerRadius - g.thickness);
  const fmt = (v: number): string => v.toFixed(2);
  let d = "";

  for (let k = 0; k < facetCount; k += 2) {
    const outerStart = rot + k * gap - overlap;
    const outerEnd = rot + (k + 1) * gap + overlap;
    const innerStart = outerStart + skew;
    const innerEnd = outerEnd + skew;

    const pts: BlobPoint[] = [];
    for (let s = 0; s <= PAPER_EDGE_SAMPLES; s++) {
      const t = s / PAPER_EDGE_SAMPLES;
      pts.push(ringPoint(outerStart + (outerEnd - outerStart) * t, g.outerRadius, g));
    }
    for (let s = PAPER_EDGE_SAMPLES; s >= 0; s--) {
      const t = s / PAPER_EDGE_SAMPLES;
      pts.push(ringPoint(innerStart + (innerEnd - innerStart) * t, innerRadius, g));
    }

    d += `M ${fmt(pts[0].x)} ${fmt(pts[0].y)} `;
    for (let i = 1; i < pts.length; i++) d += `L ${fmt(pts[i].x)} ${fmt(pts[i].y)} `;
    d += "Z ";
  }
  return d.trim();
}

/** Prépare les chemins (ombre, bandeau PARFAITEMENT rond, occlusion
 *  intérieure, facettes papier alternées, segment clair optionnel) pour UNE
 *  frame d'ANNEAU. `thicknessRatio` = fraction du rayon extérieur (0..1) —
 *  épaisseur CONSTANTE tout le tour, aucune exception. `facetCount` = nombre
 *  de facettes papier réparties sur le tour (0 = bandeau uni, aucun effet
 *  torsadé). */
export function buildRingLayerPaths(
  canvasSize: number,
  outerRadius: number,
  thicknessRatio: number,
  timeT: number,
  rotationTurns: number,
  withSegment: boolean,
  facetCount: number
): LayerPaths {
  const cx = canvasSize / 2;
  const cy = canvasSize / 2;
  const thickness = Math.max(2, Math.min(outerRadius - 2, outerRadius * thicknessRatio));
  const geom: RingGeom = { cx, cy, outerRadius, thickness, timeT, rotationTurns };
  const shadowOffset = outerRadius * 0.09;
  const shadowGeom: RingGeom = {
    ...geom, cx: cx + shadowOffset, cy: cy + shadowOffset, outerRadius: outerRadius * 1.06,
  };

  return {
    body: buildRingDonutPath(geom),
    shadow: buildRingDonutPath(shadowGeom),
    segment: withSegment ? buildRingSegmentPath(geom) : null,
    innerRim: buildRingInnerRimPath(geom, thickness * 0.28),
    paperFacets: facetCount > 0 ? buildRingPaperFacetsPath(geom, facetCount) : null,
    highlight: null,
  };
}
