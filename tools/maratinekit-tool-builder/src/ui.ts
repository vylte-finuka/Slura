// Iframe UI (DOM/Blob/téléchargement — pas de `figma` ici, tout passe par postMessage).
// Reçoit les fichiers générés par code.ts, construit le zip <AppName>.marep.zip via
// JSZip (dossier racine <AppName>.marep/), déclenche le téléchargement navigateur.

import JSZip from "jszip";

type UiFile = { path: string; text?: string; bytes?: Uint8Array; centerCrop?: boolean };

const statusEl = document.getElementById("status") as HTMLDivElement;
const appNameEl = document.getElementById("appname") as HTMLInputElement;
const desktopEl = document.getElementById("desktop") as HTMLInputElement;
const iconRatioEl = document.getElementById("iconratio") as HTMLInputElement | null;
const diamondColorEl = document.getElementById("diamondcolor") as HTMLInputElement | null;

/** Parse "0x33B9B9B9" / "33B9B9B9" → nombre ARGB. Retombe sur le défaut si invalide/vide. */
function parseArgbHex(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const cleaned = raw.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{1,8}$/.test(cleaned)) return fallback;
  const n = parseInt(cleaned, 16);
  return Number.isFinite(n) ? (n >>> 0) : fallback;
}
const iconFileEl = document.getElementById("iconfile") as HTMLInputElement | null;

// Logo personnalisé : reste côté UI (accès Blob/Canvas). S'il est fourni, il devient
// l'icône du dock <App>.png (recadrée+centrée comme un nœud AppIcon), prioritaire sur
// le design. On ne fait qu'informer code.ts de sa présence (hasCustomIcon) pour qu'il
// écrive la ligne Maraset icon: et NE réémette PAS l'icône du nœud AppIcon.
let customIconBytes: Uint8Array | null = null;
if (iconFileEl) {
  iconFileEl.addEventListener("change", async () => {
    const f = iconFileEl.files && iconFileEl.files[0];
    if (!f) { customIconBytes = null; return; }
    customIconBytes = new Uint8Array(await f.arrayBuffer());
    statusEl.textContent = `Logo chargé : ${f.name} (${Math.round(f.size / 1024)} Ko) — deviendra l'icône du dock.`;
  });
}

// Recadre un PNG sur son contenu (alpha > seuil) puis le centre dans un canvas
// CARRÉ, sans padding asymétrique → l'icône du dock est parfaitement centrée quel
// que soit le padding de l'export Figma (corrige le "défaut de décalage").
//   ratio = fraction du canvas occupée par le contenu (0.48 ≈ petite icône, verre
//   du losange visible autour ; 1.0 = l'icône remplit le losange).
async function cropCenterSquarePng(bytes: Uint8Array, ratio: number): Promise<Uint8Array> {
  const blob = new Blob([bytes as unknown as BlobPart], { type: "image/png" });
  const bmp = await createImageBitmap(blob);
  const w = bmp.width, h = bmp.height;
  const c = document.createElement("canvas");
  c.width = w; c.height = h;
  const cx = c.getContext("2d")!;
  cx.drawImage(bmp, 0, 0);
  const data = cx.getImageData(0, 0, w, h).data;
  let minX = w, minY = h, maxX = -1, maxY = -1;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (data[(y * w + x) * 4 + 3] > 10) {
        if (x < minX) minX = x; if (x > maxX) maxX = x;
        if (y < minY) minY = y; if (y > maxY) maxY = y;
      }
    }
  }
  if (maxX < minX) return bytes; // image vide → inchangée
  const cw = maxX - minX + 1, ch = maxY - minY + 1;
  const side = Math.max(cw, ch);
  const canvas = Math.max(1, Math.round(side / Math.min(1, Math.max(0.1, ratio))));
  const out = document.createElement("canvas");
  out.width = canvas; out.height = canvas;
  const octx = out.getContext("2d")!;
  octx.imageSmoothingEnabled = true;
  octx.drawImage(bmp, minX, minY, cw, ch, (canvas - cw) / 2, (canvas - ch) / 2, cw, ch);
  const outBlob: Blob = await new Promise((res) => out.toBlob((b) => res(b!), "image/png"));
  return new Uint8Array(await outBlob.arrayBuffer());
}

document.getElementById("generate")!.addEventListener("click", () => {
  statusEl.textContent = "Génération en cours...";
  parent.postMessage(
    {
      pluginMessage: {
        type: "generate",
        appName: appNameEl.value.trim(),
        isDesktop: desktopEl.checked,
        hasCustomIcon: customIconBytes !== null,
        diamondColor: parseArgbHex(diamondColorEl?.value, 0x33b9b9b9),
      },
    },
    "*"
  );
});

document.getElementById("cancel")!.addEventListener("click", () => {
  parent.postMessage({ pluginMessage: { type: "cancel" } }, "*");
});

async function downloadZip(appName: string, files: UiFile[]): Promise<void> {
  const zip = new JSZip();
  const root = zip.folder(`${appName}.marep`)!;
  const ratio = iconRatioEl && iconRatioEl.value ? Number(iconRatioEl.value) : 0.48;
  for (const f of files) {
    if (f.bytes !== undefined) {
      // L'icône (centerCrop) est recadrée+centrée avant d'entrer dans le zip.
      const bytes = f.centerCrop ? await cropCenterSquarePng(f.bytes, ratio) : f.bytes;
      root.file(f.path, bytes);
    } else {
      root.file(f.path, f.text ?? "");
    }
  }
  // Logo personnalisé : recadré+centré comme une icône AppIcon, écrit en <App>.png
  // (écrase l'entrée éventuelle du nœud AppIcon — le logo choisi ici est prioritaire).
  if (customIconBytes) {
    const iconPng = await cropCenterSquarePng(customIconBytes, ratio);
    root.file(`${appName}.slasset/${appName}.png`, iconPng);
  }
  const blob = await zip.generateAsync({ type: "blob" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${appName}.marep.zip`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

window.onmessage = (event: MessageEvent) => {
  const msg = event.data.pluginMessage;
  if (!msg) return;
  if (msg.type === "status") {
    statusEl.textContent = msg.text;
  } else if (msg.type === "files") {
    downloadZip(msg.appName, msg.files).catch((err) => {
      statusEl.textContent = `Erreur zip : ${err instanceof Error ? err.message : String(err)}`;
    });
  }
};
