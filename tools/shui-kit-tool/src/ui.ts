// Iframe UI (DOM — pas de `figma` ici, tout passe par postMessage). Purement
// un panneau de contrôle : la génération réelle des nœuds Figma vit dans
// code.ts (sandbox `figma`), jamais ici. Le panneau reflète en direct la
// sélection Figma courante (messages "selection" envoyés par code.ts) —
// impossible de générer sans avoir sélectionné une forme existante. Aucun
// contrôle de couleur ici : le fill vient de la forme d'origine, dérivé (pas
// remplacé) selon le mode choisi.
const statusEl = document.getElementById("status") as HTMLDivElement;
const selectionInfoEl = document.getElementById("selection-info") as HTMLDivElement;
const generateBtn = document.getElementById("generate") as HTMLButtonElement;
const modeRibbonEl = document.getElementById("mode-ribbon") as HTMLDivElement;
const modeRingEl = document.getElementById("mode-ring") as HTMLDivElement;
const ringOnlyEl = document.getElementById("ring-only") as HTMLDivElement;
const ribbonOnlyEl = document.getElementById("ribbon-only") as HTMLDivElement;
const rotationLabelEl = document.getElementById("rotation-label") as HTMLLabelElement;
const sizeRatioEl = document.getElementById("sizeratio") as HTMLInputElement;
const pointsEl = document.getElementById("points") as HTMLInputElement;
const jitterEl = document.getElementById("jitter") as HTMLInputElement;
const thicknessEl = document.getElementById("thickness") as HTMLInputElement;
const ringSegmentEl = document.getElementById("ringsegment") as HTMLInputElement;
const seedEl = document.getElementById("seed") as HTMLInputElement;
const shadowEl = document.getElementById("shadow") as HTMLInputElement;
const shadowBlurEl = document.getElementById("shadowblur") as HTMLInputElement;
const rotationEl = document.getElementById("rotation") as HTMLInputElement;
const delayEl = document.getElementById("delay") as HTMLInputElement;
const autoplayEl = document.getElementById("autoplay") as HTMLInputElement;

let hasValidSelection = false;
let mode: "ribbon" | "ring" = "ribbon";

function applyModeUi(): void {
  modeRibbonEl.classList.toggle("selected", mode === "ribbon");
  modeRingEl.classList.toggle("selected", mode === "ring");
  // Points/Organicité ne s'appliquent QU'au ruban (silhouette organique) —
  // l'anneau n'a aucun réglage de texture : son bandeau reste un aplat uni,
  // sans exception (voir figmaBuild.ts). Épaisseur/segment n'existent qu'en
  // mode anneau.
  ringOnlyEl.style.display = mode === "ring" ? "" : "none";
  ribbonOnlyEl.style.display = mode === "ribbon" ? "" : "none";
  rotationLabelEl.firstChild!.textContent = mode === "ring" ? "Vitesse de rotation " : "Tours de rotation sur la boucle ";
}

modeRibbonEl.addEventListener("click", () => {
  mode = "ribbon";
  applyModeUi();
});
modeRingEl.addEventListener("click", () => {
  mode = "ring";
  applyModeUi();
});
applyModeUi();

function bindRangeDisplay(input: HTMLInputElement, valueEl: HTMLElement, fmt: (v: number) => string): void {
  const update = (): void => {
    valueEl.textContent = fmt(Number(input.value));
  };
  input.addEventListener("input", update);
  update();
}

bindRangeDisplay(sizeRatioEl, document.getElementById("sizeratio-val")!, (v) => `${v}%`);
bindRangeDisplay(pointsEl, document.getElementById("points-val")!, (v) => String(v));
bindRangeDisplay(jitterEl, document.getElementById("jitter-val")!, (v) => `${v}%`);
bindRangeDisplay(thicknessEl, document.getElementById("thickness-val")!, (v) => `${v}%`);
bindRangeDisplay(shadowBlurEl, document.getElementById("shadowblur-val")!, (v) => String(v));
bindRangeDisplay(rotationEl, document.getElementById("rotation-val")!, (v) => (v / 100).toFixed(2));

interface ShapeSummary {
  id: string;
  name: string;
  width: number;
  height: number;
}

// Un anneau parfaitement uni a une symétrie de rotation totale : l'animer
// tourner sur lui-même ne changerait RIEN à l'image, la rotation serait
// invisible. Un "vrai curseur professionnel" (spinner) a toujours un repère
// asymétrique (le segment plus clair) pour que la rotation se voie — donc dès
// qu'on détecte une animation (2+ formes) en mode anneau, on active ce
// repère automatiquement, UNE SEULE FOIS à la transition 1 -> 2+ formes (pas
// à chaque changement ensuite, pour ne pas écraser un choix déjà fait par
// l'utilisateur). Aucun autre réglage n'est touché : l'anneau reste un aplat
// uni dans tous les cas, seul ce segment peut apparaître.
let lastShapeCount = 0;

function renderSelection(shapes: ShapeSummary[]): void {
  hasValidSelection = shapes.length > 0;
  generateBtn.disabled = !hasValidSelection;
  selectionInfoEl.classList.toggle("valid", hasValidSelection);

  if (mode === "ring" && lastShapeCount <= 1 && shapes.length > 1) {
    ringSegmentEl.checked = true;
  }
  lastShapeCount = shapes.length;

  if (shapes.length === 0) {
    selectionInfoEl.textContent = "Aucune forme sélectionnée.";
    return;
  }
  if (shapes.length === 1) {
    const s = shapes[0];
    selectionInfoEl.textContent = `1 forme : "${s.name}" (${s.width}×${s.height}) — silhouette statique.`;
    return;
  }
  const names = shapes.map((s, i) => `${i + 1}. ${s.name} (${s.width}×${s.height})`).join("\n");
  selectionInfoEl.textContent = `${shapes.length} formes (ordre gauche → droite = ordre d'animation) :\n${names}`;
}

document.getElementById("generate")!.addEventListener("click", () => {
  if (!hasValidSelection) return;
  parent.postMessage(
    {
      pluginMessage: {
        type: "generate",
        mode,
        sizeRatio: Number(sizeRatioEl.value) / 100,
        pointCount: Number(pointsEl.value),
        jitter: Number(jitterEl.value) / 100,
        rotationTurns: Number(rotationEl.value) / 100,
        thicknessRatio: Number(thicknessEl.value) / 100,
        ringSegment: ringSegmentEl.checked,
        withShadow: shadowEl.checked,
        shadowBlur: Number(shadowBlurEl.value),
        autoplayDelayMs: Number(delayEl.value),
        wireAutoplay: autoplayEl.checked,
        seed: seedEl.value,
      },
    },
    "*"
  );
  statusEl.textContent = "Génération en cours...";
});

document.getElementById("cancel")!.addEventListener("click", () => {
  parent.postMessage({ pluginMessage: { type: "cancel" } }, "*");
});

window.onmessage = (event: MessageEvent) => {
  const msg = event.data.pluginMessage;
  if (!msg) return;
  if (msg.type === "status") {
    statusEl.textContent = msg.text;
  }
  if (msg.type === "selection") {
    renderSelection(msg.shapes as ShapeSummary[]);
  }
};
