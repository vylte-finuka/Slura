// Génération de la géométrie — PUR calcul de PATH, aucune couleur ici (le
// fill vient toujours de la forme d'origine, jamais choisi par ce plugin,
// voir figmaBuild.ts). Deux formes :
//   - Ruban de soie : silhouette organique fermée (blob), N points dont le
//     rayon "respire" dans le temps, lissée en Bézier (Catmull-Rom).
//   - Anneau : bandeau à contour TOUJOURS parfaitement circulaire — la
//     torsion se lit uniquement via le shading (figmaBuild.ts), jamais via
//     une déformation de silhouette.
//
// IMPORTANT (vérifié à l'usage réel du plugin, pas dans la doc SVG) : le
// parser de `VectorPath.data` de l'API Figma est plus strict que la spec SVG
// générale et rejette la virgule comme séparateur ("Invalid command at ,").
// Toutes les fonctions ci-dessous n'utilisent QUE l'espace comme séparateur.
//
// Le nombre de points/échantillons est FIXE pour toutes les frames d'une
// même animation : c'est ce qui permet à Smart Animate de Figma d'interpoler
// les points un à un (vrai morph), pas un simple fondu — Smart Animate ne
// peut apparier des vecteurs point-à-point QUE si leur topologie (même
// nombre de points, même ordre) est identique entre les deux frames.

export interface Point {
  x: number;
  y: number;
}

function fmt(v: number): string {
  return v.toFixed(2);
}

/** Catmull-Rom uniforme -> Bézier cubique, courbe FERMÉE (le dernier point se
 *  raccorde au premier). Formule standard : cp1 = p1 + (p2-p0)/6,
 *  cp2 = p2 - (p3-p1)/6. */
export function pointsToSmoothClosedPath(points: Point[]): string {
  const n = points.length;
  if (n < 3) return "";
  const at = (i: number): Point => points[((i % n) + n) % n];

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

export interface LayerPaths {
  body: string;
  shadow: string;
  /** Ruban de soie uniquement : silhouette de reflet, plus petite et
   *  excentrée, destinée à un dégradé CLAIR (figmaBuild.ts) — signal de mode
   *  utilisé par figmaBuild.ts (non-null == ruban de soie). */
  highlight: string | null;
  /** Anneau uniquement : segment d'arc plus clair façon indicateur de
   *  spinner, optionnel. */
  segment: string | null;
  /** Anneau uniquement : ombre d'occlusion fine près du bord intérieur
   *  ("intérieur d'un tube" qui s'assombrit). */
  innerRim: string | null;
}

// ── Ruban de soie ────────────────────────────────────────────────────────────

interface BlobGeom {
  cx: number;
  cy: number;
  baseRadius: number;
  pointCount: number;
  /** Amplitude de la "respiration" du rayon par point, 0..1 (0 = cercle parfait). */
  jitter: number;
  /** Phase fixe par point (0..1), dérivée du seed — garantit la MÊME
   *  topologie de forme sur toutes les frames d'une animation, seule
   *  `timeT` fait "respirer"/tourner la silhouette dans le temps. */
  pointPhases: number[];
  /** Position dans le cycle d'animation, 0..1 — 0 et 1 produisent EXACTEMENT
   *  la même forme (boucle continue, aucun à-coup au raccord). */
  timeT: number;
  /** Tours de rotation sur tout le cycle (0 = pas de rotation, pure respiration). */
  rotationTurns: number;
}

/** Dérive N phases fixes (0..1) à partir du PRNG — appelé UNE fois par
 *  forme, réutilisé pour toutes ses frames d'animation. */
export function derivePointPhases(pointCount: number, rnd: () => number): number[] {
  const phases: number[] = [];
  for (let i = 0; i < pointCount; i++) phases.push(rnd());
  return phases;
}

function blobPoints(g: BlobGeom): Point[] {
  const points: Point[] = [];
  const rotation = g.rotationTurns * Math.PI * 2 * g.timeT;
  for (let i = 0; i < g.pointCount; i++) {
    const angle = (i / g.pointCount) * Math.PI * 2 + rotation;
    const wobble = Math.sin(Math.PI * 2 * (g.timeT + g.pointPhases[i]));
    const r = g.baseRadius * (1 + wobble * g.jitter * 0.5);
    points.push({ x: g.cx + Math.cos(angle) * r, y: g.cy + Math.sin(angle) * r });
  }
  return points;
}

function blobPath(g: BlobGeom): string {
  return pointsToSmoothClosedPath(blobPoints(g));
}

/** Prépare les chemins (ombre, corps, reflet) pour UNE frame de RUBAN DE
 *  SOIE — mêmes pointPhases/timeT/rotationTurns donc topologie identique
 *  entre les couches ET entre toutes les frames d'une animation. */
export function buildRibbonLayerPaths(
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
  const base: Omit<BlobGeom, "cx" | "cy" | "baseRadius"> = {
    pointCount, jitter, pointPhases, timeT, rotationTurns,
  };

  return {
    body: blobPath({ ...base, cx, cy, baseRadius }),
    shadow: blobPath({ ...base, cx: cx + shadowOffset, cy: cy + shadowOffset, baseRadius: baseRadius * 1.08 }),
    highlight: blobPath({
      ...base, cx: cx - highlightOffset, cy: cy - highlightOffset, baseRadius: baseRadius * 0.55,
    }),
    segment: null,
    innerRim: null,
  };
}

// ── Anneau ───────────────────────────────────────────────────────────────────
// Contour TOUJOURS un cercle parfait (concentrique, épaisseur constante),
// couleur TOUJOURS l'aplat d'origine (jamais de motif/facette) — le plugin
// ne doit JAMAIS pouvoir produire un anneau "texturé", quels que soient les
// réglages : ce n'est pas un défaut réglable à 0, la géométrie/le rendu
// correspondants ont été retirés. Seul repère de rotation possible : le
// segment d'arc plus clair, optionnel (façon indicateur de spinner).

const RING_SAMPLES = 48;
const SEGMENT_STEPS = 12;
/** Balayage du segment clair, ~80° façon indicateur de spinner. */
const SEGMENT_SWEEP = 1.4;

interface RingGeom {
  cx: number;
  cy: number;
  outerRadius: number;
  thickness: number;
  timeT: number;
  rotationTurns: number;
}

function ringPoint(theta: number, radius: number, g: RingGeom): Point {
  return { x: g.cx + Math.cos(theta) * radius, y: g.cy + Math.sin(theta) * radius };
}

function ringInnerRadius(g: RingGeom): number {
  return Math.max(1, g.outerRadius - g.thickness);
}

function ringDonutPath(g: RingGeom): string {
  const outer: Point[] = [];
  const inner: Point[] = [];
  const innerRadius = ringInnerRadius(g);
  for (let i = 0; i < RING_SAMPLES; i++) {
    const theta = (i / RING_SAMPLES) * Math.PI * 2;
    outer.push(ringPoint(theta, g.outerRadius, g));
    inner.push(ringPoint(theta, innerRadius, g));
  }
  // Deux sous-chemins fermés dans un seul `data` — EVENODD (figmaBuild.ts)
  // creuse le trou : un vrai anneau vectoriel, pas deux formes empilées.
  return pointsToSmoothClosedPath(outer) + " " + pointsToSmoothClosedPath(inner);
}

function ringSegmentPath(g: RingGeom): string {
  const start = g.rotationTurns * Math.PI * 2 * g.timeT;
  const innerRadius = ringInnerRadius(g);
  let d = "";
  for (let i = 0; i <= SEGMENT_STEPS; i++) {
    const theta = start + (i / SEGMENT_STEPS) * SEGMENT_SWEEP;
    const p = ringPoint(theta, g.outerRadius, g);
    d += i === 0 ? `M ${fmt(p.x)} ${fmt(p.y)} ` : `L ${fmt(p.x)} ${fmt(p.y)} `;
  }
  for (let i = SEGMENT_STEPS; i >= 0; i--) {
    const theta = start + (i / SEGMENT_STEPS) * SEGMENT_SWEEP;
    const p = ringPoint(theta, innerRadius, g);
    d += `L ${fmt(p.x)} ${fmt(p.y)} `;
  }
  return d + "Z";
}

function ringInnerRimPath(g: RingGeom, rimWidth: number): string {
  const rimOuter = ringInnerRadius(g);
  const rimInner = Math.max(0.5, rimOuter - rimWidth);
  const outer: Point[] = [];
  const inner: Point[] = [];
  for (let i = 0; i < RING_SAMPLES; i++) {
    const theta = (i / RING_SAMPLES) * Math.PI * 2;
    outer.push(ringPoint(theta, rimOuter, g));
    inner.push(ringPoint(theta, rimInner, g));
  }
  return pointsToSmoothClosedPath(outer) + " " + pointsToSmoothClosedPath(inner);
}

/** Prépare les chemins (ombre, bandeau parfaitement rond, occlusion
 *  intérieure, segment clair optionnel) pour UNE frame d'ANNEAU.
 *  `thicknessRatio` = fraction du rayon extérieur (0..1) — épaisseur
 *  CONSTANTE tout le tour. Le seul repère de rotation possible est
 *  `withSegment` — aucun autre paramètre ne peut produire de motif/texture
 *  sur le bandeau (voir commentaire d'en-tête de section). */
export function buildRingLayerPaths(
  canvasSize: number,
  outerRadius: number,
  thicknessRatio: number,
  timeT: number,
  rotationTurns: number,
  withSegment: boolean
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
    body: ringDonutPath(geom),
    shadow: ringDonutPath(shadowGeom),
    highlight: null,
    segment: withSegment ? ringSegmentPath(geom) : null,
    innerRim: ringInnerRimPath(geom, thickness * 0.28),
  };
}
