// Mise à l'échelle responsive — même convention que TemplateView.mara (ShiLauncher) :
// toute valeur littérale du design est émise comme "((v * sX + 500) / 1000)" où sX est
// sW (axe X), sH (axe Y) ou sU (uniforme : formes pivotées / carrées qui ne doivent pas
// se déformer quand le ratio écran diffère du ratio du design).

export type Axis = "x" | "y" | "u";

/** Formate une valeur design en expression Mara mise à l'échelle. */
export function scaled(v: number, axis: Axis): string {
  const n = Math.round(v);
  const s = axis === "x" ? "sW" : axis === "y" ? "sH" : "sU";
  return `((${n} * ${s} + 500) / 1000)`;
}

/** Rayon "mixte" (moyenne des composantes X et Y mises à l'échelle) — utilisé quand la
 *  forme s'étire (sW/sH séparés) mais que son rayon de coin doit rester rond. */
export function scaledRadiusMixed(r: number): string {
  const n = Math.round(r);
  return `(((${n} * sW + 500) / 1000 + (${n} * sH + 500) / 1000) / 2)`;
}

/** Heuristique : la forme doit-elle être mise à l'échelle uniformément (sU) ?
 *  Nœud (quasi) carré ET (pivoté OU entièrement arrondi ≈ cercle/losange). */
export function isUniform(w: number, h: number, rotationDeg: number, cornerRadius: number): boolean {
  const nearSquare = Math.abs(w - h) <= Math.max(2, 0.02 * Math.max(w, h));
  const rotated = Math.abs(rotationDeg) > 0.5;
  const fullyRounded = cornerRadius >= Math.min(w, h) * 0.4;
  return nearSquare && (rotated || fullyRounded);
}

/** Préambule sW/sH/sU à émettre en tête de Render. */
export function scalePreamble(designW: number, designH: number): string[] {
  return [
    `    // ── Full-stretch responsive — généré par MaratineKit tool's builder ──`,
    `    let sw: <i32> = <DrvAPIInterCon***GpuGetWidth***>();`,
    `    let sh: <i32> = <DrvAPIInterCon***GpuGetHeight***>();`,
    `    let sW: <i32> = (sw * 1000) / ${Math.round(designW)};`,
    `    let sH: <i32> = (sh * 1000) / ${Math.round(designH)};`,
    `    let sU: <i32> = (sW + sH) / 2;`,
  ];
}
