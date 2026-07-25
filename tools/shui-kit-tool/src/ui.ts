// Iframe UI (DOM — pas de `figma` ici, tout passe par postMessage). Purement
// un panneau de contrôle : la génération réelle des nœuds Figma vit dans
// code.ts (sandbox `figma`), jamais ici. Le panneau reflète en direct la
// sélection Figma courante (messages "selection" envoyés par code.ts) —
// impossible de générer sans avoir sélectionné une forme existante. Aucun
// contrôle de couleur ni de reflet ici : le fill vient de la forme
// d'origine, le rendu est mat (esthétique ShUI, aucun glossy/blanc).
const statusEl = document.getElementById("status") as HTMLDivElement;
const selectionInfoEl = document.getElementById("selection-info") as HTMLDivElement;
const generateBtn = document.getElementById("generate") as HTMLButtonElement;
const modeBlobEl = document.getElementById("mode-blob") as HTMLDivElement;
const modeRingEl = document.getElementById("mode-ring") as HTMLDivElement;
const ringOnlyEl = document.getElementById("ring-only") as HTMLDivElement;
const pointsLabelEl = document.getElementById("points-label") as HTMLLabelElement;
const jitterLabelEl = document.getElementById("jitter-label") as HTMLLabelElement;
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
let mode: "blob" | "ring" = "blob";

function applyModeUi(): void {
  modeBlobEl.classList.toggle("selected", mode === "blob");
  modeRingEl.classList.toggle("selected", mode === "ring");
  // Épaisseur/segment n'existent qu'en mode anneau (le contour du blob n'a
  // pas d'épaisseur de bandeau) — mais Points/Organicité s'appliquent aux
  // DEUX modes, juste avec un sens différent : silhouette organique en blob,
  // ombrage de torsion (jamais le contour, qui reste un cercle parfait) en
  // ring — d'où le relabel plutôt qu'un masquage.
  ringOnlyEl.style.display = mode === "ring" ? "" : "none";
  pointsLabelEl.firstChild!.textContent = mode === "ring" ? "Torsions " : "Complexité (points) ";
  jitterLabelEl.firstChild!.textContent = mode === "ring" ? "Intensité de la torsion " : "Organicité ";
  rotationLabelEl.firstChild!.textContent = mode === "ring" ? "Vitesse de rotation " : "Tours de rotation sur la boucle ";
}

modeBlobEl.addEventListener("click", () => {
  mode = "blob";
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

function renderSelection(shapes: ShapeSummary[]): void {
  hasValidSelection = shapes.length > 0;
  generateBtn.disabled = !hasValidSelection;
  selectionInfoEl.classList.toggle("valid", hasValidSelection);

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
