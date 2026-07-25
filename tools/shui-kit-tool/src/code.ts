// Thread principal du plugin (sandbox Figma — a `figma`, pas de DOM). Rien
// n'est créé "depuis rien" : le plugin exige une sélection de FORME(S)
// EXISTANTE(S) (pas un frame — un vecteur/rectangle/ellipse/etc. déjà posé
// et déjà stylé) et régénère UNIQUEMENT leur géométrie + une ombre neutre —
// voir generator/animate.ts. Deux modes : "blob" (silhouette organique) et
// "ring" (anneau rotatif, épaisseur/vitesse personnalisables). La couleur du
// corps est TOUJOURS copiée depuis la forme d'origine, jamais choisie par ce
// plugin — esthétique ShUI mate et épurée, aucun reflet glossy. Aucun
// export/rasterisation : vraies formes vectorielles Figma natives.
import { mulberry32, seedFromString } from "./generator/random";
import { generateWaveOnShapes, WaveMode } from "./generator/animate";

figma.showUI(__html__, { width: 380, height: 600 });

interface GenerateMsg {
  type: "generate";
  mode: WaveMode;
  sizeRatio: number;
  pointCount: number;
  jitter: number;
  rotationTurns: number;
  thicknessRatio: number;
  ringSegment: boolean;
  withShadow: boolean;
  shadowBlur: number;
  autoplayDelayMs: number;
  wireAutoplay: boolean;
  seed: string;
}

interface ShapeSummary {
  id: string;
  name: string;
  width: number;
  height: number;
}

// Types de nœuds considérés comme "une forme" (ont un fill exploitable) —
// délibérément SANS FRAME/GROUP/TEXT/COMPONENT : ce plugin s'applique à une
// forme déjà dessinée par l'utilisateur, pas à un conteneur.
const SHAPE_TYPES = new Set<SceneNode["type"]>([
  "VECTOR", "RECTANGLE", "ELLIPSE", "POLYGON", "STAR", "LINE", "BOOLEAN_OPERATION",
]);

function status(text: string): void {
  figma.ui.postMessage({ type: "status", text });
}

function currentShapeSelection(): SceneNode[] {
  return figma.currentPage.selection.filter((n) => SHAPE_TYPES.has(n.type));
}

/** Informe l'UI de la sélection courante (nombre/noms/tailles de formes) —
 *  appelé à l'ouverture du plugin ET à chaque changement de sélection, pour
 *  que le panneau reflète toujours "sur quoi" la génération va s'appliquer
 *  plutôt que de laisser l'utilisateur générer à l'aveugle. */
function postSelection(): void {
  const shapes = currentShapeSelection() as (SceneNode & LayoutMixin)[];
  const summary: ShapeSummary[] = shapes
    .slice()
    .sort((a, b) => a.x - b.x)
    .map((s) => ({ id: s.id, name: s.name, width: Math.round(s.width), height: Math.round(s.height) }));
  figma.ui.postMessage({ type: "selection", shapes: summary });
}

figma.on("selectionchange", postSelection);
postSelection();

async function generate(msg: GenerateMsg): Promise<void> {
  const targetShapes = currentShapeSelection().sort(
    (a, b) => (a as SceneNode & LayoutMixin).x - (b as SceneNode & LayoutMixin).x
  );
  if (targetShapes.length === 0) {
    status(
      "Aucune forme sélectionnée. Sélectionnez 1 forme existante (silhouette statique) ou 2+ formes (keyframes d'animation, dans l'ordre gauche -> droite) — pas un frame — puis relancez."
    );
    return;
  }

  const mode: WaveMode = msg.mode === "ring" ? "ring" : "blob";
  const pointCount = Math.max(4, Math.min(16, Math.round(msg.pointCount)));
  const jitter = Math.max(0, Math.min(1, msg.jitter));
  const shadowBlur = Math.max(0, Math.min(200, msg.shadowBlur));
  const sizeRatio = Math.max(0.1, Math.min(1, msg.sizeRatio));
  const thicknessRatio = Math.max(0.05, Math.min(0.5, msg.thicknessRatio));

  const seedStr = msg.seed.trim() || String(Date.now());
  const rnd = mulberry32(seedFromString(seedStr));

  status(
    `Génération (${mode === "ring" ? "anneau" : "blob"}) sur ${targetShapes.length} forme(s) sélectionnée(s)${targetShapes.length > 1 ? " (animation)" : ""}...`
  );

  const { shapes, reactionWarnings } = await generateWaveOnShapes({
    targetShapes,
    mode,
    sizeRatio,
    pointCount,
    jitter,
    rotationTurns: msg.rotationTurns,
    thicknessRatio,
    ringSegment: msg.ringSegment === true,
    withShadow: msg.withShadow,
    shadowBlur,
    autoplayDelayMs: msg.autoplayDelayMs,
    wireAutoplay: msg.wireAutoplay,
    rnd,
  });

  figma.currentPage.selection = shapes;
  figma.viewport.scrollAndZoomIntoView(shapes);

  let msgText = `${shapes.length} forme(s) transformée(s) en ${mode === "ring" ? "anneau" : "vague"} (couleur d'origine conservée, seed=${seedStr}).`;
  if (targetShapes.length > 1) {
    msgText += msg.wireAutoplay
      ? " Prototype bouclé câblé (délai -> Smart Animate) sur les frames contenant vos formes — ouvrez le mode Présentation pour la voir jouer/tourner."
      : " Câblage du prototype désactivé — reliez vos frames manuellement (onglet Prototype) pour l'animer.";
  } else if (mode === "ring") {
    // Honnêteté : avec 1 seule forme, aucune rotation visible n'est possible
    // (rien à interpoler pour Smart Animate) — silhouette statique à l'angle
    // de départ, rotationTurns sans effet (voir animate.ts).
    msgText += " Anneau statique (silhouette figée) — pour une vraie rotation animée, sélectionnez 2+ formes (une par keyframe, posées chacune dans son propre frame).";
  }
  if (reactionWarnings.length > 0) {
    msgText += `\n\nAvertissement(s) :\n${reactionWarnings.join("\n")}`;
  }
  status(msgText);
}

figma.ui.onmessage = (msg: { type: string } & Partial<GenerateMsg>) => {
  if (msg.type === "generate") {
    generate(msg as GenerateMsg).catch((err) => {
      status(`Erreur de génération : ${err instanceof Error ? err.message : String(err)}`);
    });
    return;
  }
  if (msg.type === "cancel") {
    figma.closePlugin();
  }
};
