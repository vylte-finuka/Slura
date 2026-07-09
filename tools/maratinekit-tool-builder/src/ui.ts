// Iframe UI (DOM/Blob/téléchargement — pas de `figma` ici, tout passe par postMessage).
// Reçoit les fichiers générés par code.ts, construit le zip <AppName>.marep.zip via
// JSZip (dossier racine <AppName>.marep/), déclenche le téléchargement navigateur.

import JSZip from "jszip";

type UiFile = { path: string; text?: string; bytes?: Uint8Array };

const statusEl = document.getElementById("status") as HTMLDivElement;
const appNameEl = document.getElementById("appname") as HTMLInputElement;
const desktopEl = document.getElementById("desktop") as HTMLInputElement;

document.getElementById("generate")!.addEventListener("click", () => {
  statusEl.textContent = "Génération en cours...";
  parent.postMessage(
    {
      pluginMessage: {
        type: "generate",
        appName: appNameEl.value.trim(),
        isDesktop: desktopEl.checked,
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
  for (const f of files) {
    if (f.bytes !== undefined) {
      root.file(f.path, f.bytes);
    } else {
      root.file(f.path, f.text ?? "");
    }
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
