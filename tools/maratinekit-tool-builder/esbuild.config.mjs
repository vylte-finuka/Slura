// Build du plugin Figma "MaratineKit tool's builder".
//
// Deux bundles séparés (réalités JS différentes, cf. plan) :
//   - code.ts → dist/code.js   : thread principal, sandbox Figma (a `figma`, pas de DOM/Blob).
//   - ui.ts   → dist/ui.html   : iframe UI (DOM/Blob/téléchargement, pas de `figma`) — le JS
//                                 buildé est inliné directement dans le HTML (Figma charge `ui`
//                                 comme un unique fichier HTML autonome, pas de <script src>
//                                 externe fiable dans ce contexte).

import { context } from "esbuild";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const watch = process.argv.includes("--watch");

mkdirSync(join(here, "dist"), { recursive: true });

function writeUiHtml(js) {
  const htmlTemplate = readFileSync(join(here, "src/ui.html"), "utf8");
  const html = htmlTemplate.replace("__BUNDLE_JS__", () => js);
  writeFileSync(join(here, "dist/ui.html"), html, "utf8");
}

async function run() {
  const codeCtx = await context({
    entryPoints: [join(here, "src/code.ts")],
    outfile: join(here, "dist/code.js"),
    bundle: true,
    format: "iife",
    target: "es2019",
    platform: "browser",
    logLevel: "info",
  });

  const uiCtx = await context({
    entryPoints: [join(here, "src/ui.ts")],
    bundle: true,
    format: "iife",
    target: "es2019",
    platform: "browser",
    write: false,
    logLevel: "info",
    plugins: [
      {
        name: "inline-into-ui-html",
        setup(build) {
          build.onEnd((result) => {
            const out = result.outputFiles?.[0];
            if (out) writeUiHtml(out.text);
          });
        },
      },
    ],
  });

  if (watch) {
    await codeCtx.watch();
    await uiCtx.watch();
    console.log("Watching for changes (code.ts + ui.ts)...");
  } else {
    await codeCtx.rebuild();
    await uiCtx.rebuild();
    await codeCtx.dispose();
    await uiCtx.dispose();
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
