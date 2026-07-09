// Thread principal du plugin (sandbox Figma — a `figma`, pas de DOM/Blob/téléchargement).
// Orchestration : sélection → classification (classify.ts, exports d'assets inclus) →
// émission Mara (emitMara.ts) + gabarits (templates.ts) → envoi des fichiers à l'UI,
// qui construit le zip (JSZip) et déclenche le téléchargement.

import { classifyFrame } from "./generator/classify";
import { emitTemplateView } from "./generator/emitMara";
import { OENTRY_MARA, laPreventMara, marasetYaml, rabstractallowingXml, AppMeta } from "./generator/templates";

figma.showUI(__html__, { width: 400, height: 420 });

interface GenerateMsg {
  type: "generate";
  appName: string;
  isDesktop: boolean;
}

type UiFile = { path: string; text?: string; bytes?: Uint8Array };

function sanitizeAppName(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, "");
  if (cleaned.length === 0) return "";
  return cleaned[0].toUpperCase() + cleaned.slice(1);
}

function status(text: string): void {
  figma.ui.postMessage({ type: "status", text });
}

async function generate(msg: GenerateMsg): Promise<void> {
  const selection = figma.currentPage.selection;
  if (selection.length !== 1) {
    status("Sélectionnez exactement UN frame (l'écran de l'app).");
    return;
  }
  const node = selection[0];
  if (node.type !== "FRAME" && node.type !== "COMPONENT" && node.type !== "INSTANCE") {
    status(`La sélection doit être un FRAME/COMPONENT (reçu : ${node.type}).`);
    return;
  }

  const appName = sanitizeAppName(msg.appName || node.name);
  if (!appName) {
    status("Nom d'app invalide (alphanumérique requis).");
    return;
  }

  status(`Analyse de "${node.name}" (${Math.round(node.width)}×${Math.round(node.height)})...`);

  const result = await classifyFrame(node);
  const templateView = emitTemplateView(result, appName, node.width, node.height);

  const meta: AppMeta = {
    appName,
    isDesktop: msg.isDesktop,
    hasAssets: result.pngs.length > 0 || result.svgs.length > 0 || result.cursorRefPng !== null,
    iconFile: result.pngs.length > 0 ? "img1.png" : null,
  };

  const files: UiFile[] = [
    { path: "Maraset.yaml", text: marasetYaml(meta) },
    { path: "RAbstractallowing.xml", text: rabstractallowingXml(meta) },
    { path: "base/OEntry.mara", text: OENTRY_MARA },
    { path: "base/LAPrevent.mara", text: laPreventMara(meta) },
    { path: "base/TemplateView.mara", text: templateView },
  ];
  result.pngs.forEach((bytes, i) => {
    files.push({ path: `${appName}.slasset/img${i + 1}.png`, bytes });
  });
  result.svgs.forEach((bytes, i) => {
    files.push({ path: `${appName}.slasset/vec${i + 1}.svg`, bytes });
  });
  if (result.cursorRefPng) {
    files.push({ path: `${appName}.slasset/HIDcursor_reference.png`, bytes: result.cursorRefPng });
  }

  figma.ui.postMessage({ type: "files", appName, files });
  status(
    `Généré : ${files.length} fichier(s) — ${result.pngs.length} png, ${result.svgs.length} svg` +
      `${result.hasCursor ? ", curseur" : ""}${result.launches.length ? `, ${result.launches.length} zone(s) [launch:]` : ""}.` +
      `\nDézippez dans slr_clk_bt/ puis lancez la tâche "marai build: ${appName}.marep".`
  );
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
