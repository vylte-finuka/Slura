// Smoke test de l'émetteur Mara (hors Figma) : arbre de DrawOp construit à la main →
// vérifie que le texte généré contient les patterns attendus du catalogue.
// Lancement : npm test (esbuild-runner via node, cf. package.json).

import { emitTemplateView } from "../src/generator/emitMara";
import type { ClassifyResult } from "../src/generator/classify";

const result: ClassifyResult = {
  ops: [
    { kind: "rect", x: 0, y: 0, w: 1440, h: 1024, r: 0, color: 0xff202030, uniform: false },
    { kind: "rectFull", x: 0, y: 0, w: 1440, h: 30, rTL: 16, rTR: 16, rBL: 0, rBR: 0, color: 0xffe0e0e0 },
    {
      kind: "rotate", cos10k: 6947, sin10k: 7193, pivotX: 571, pivotY: 940,
      children: [{ kind: "rect", x: 548, y: 917, w: 45, h: 45, r: 16, color: 0x33b9b9b9, uniform: true }],
    },
    { kind: "image", x: 543, y: 912, w: 57, h: 57, index: 1, uniform: true },
    { kind: "svg", x: 569, y: 2, w: 23, h: 23, index: 1, uniform: true },
    { kind: "text", x: 604, y: 7, maxW: 209, content: "Hello Slura", fg: 0xff000000, size: 12, align: 0 },
    { kind: "blur", x: 490, y: 706, w: 280, h: 62, r: 22, amount: 10 },
    { kind: "gradient", x: 604, y: 1000, w: 228, h: 5, r: 2, angle: -90, c1: 0xff878787, p1: 0, c2: 0xffb9b9b9, p2: 1000 },
    { kind: "opacity", value: 77, children: [{ kind: "rect", x: 490, y: 706, w: 280, h: 62, r: 22, color: 0xfff5e3e1, uniform: false }] },
    { kind: "shadow", x: 100, y: 100, w: 50, h: 50, r: 8, offX: 0, offY: 4, blur: 4, color: 0x40000000 },
  ],
  launches: [{ x: 548, y: 917, w: 45, h: 45, app: "TestApp" }],
  pngs: [new Uint8Array(0)],
  svgs: [new Uint8Array(0)],
  cursorRefPng: new Uint8Array(0),
  hasCursor: true,
  hasText: true,
};

const mara = emitTemplateView(result, "ShiDemo", 1440, 1024);

const mustContain = [
  "let sW: <i32> = (sw * 1000) / 1440;",
  "let sH: <i32> = (sh * 1000) / 1024;",
  "let sU: <i32> = (sW + sH) / 2;",
  "GpuDrawRoundedRectAlpha***>(((0 * sW + 500) / 1000), ((0 * sH + 500) / 1000), ((1440 * sW + 500) / 1000), ((1024 * sH + 500) / 1000)",
  "GpuDrawRoundedRectFull***>",
  "GpuSetTransform2D***>(6947, 7193, -7193, 6947, ((571 * sW + 500) / 1000), ((940 * sH + 500) / 1000));",
  "GpuResetTransform***>();",
  '<DrvAPIInterCon***ImageLoad***>("SDC:/apps/ShiDemo/ShiDemo.slasset/img1.png");',
  "((57 * sU + 500) / 1000)", // taille d'image uniforme via sU
  '<DrvAPIInterCon***SvgLoad***>("SDC:/apps/ShiDemo/ShiDemo.slasset/vec1.svg");',
  "SvgFree***>(svg1);",
  '"Hello Slura", 0xFF000000, 0x00000000, font,',
  'var font: <ptr> = <DrvAPIInterCon***FontLoad***>("SDC:/assets/fonts/brsonomasemibold.ttf");',
  "GpuBackgroundBlur***>",
  "GpuDrawLinearGradient***>",
  "-90, 0xFF878787, 0, 0xFFB9B9B9, 1000, 2);",
  "GpuSetOpacity***>(77);",
  "GpuResetOpacity***>();",
  "GpuDrawDropShadow***>",
  'CursorLoad***>("SDC:/apps/ShiDemo/ShiDemo.slasset/HIDcursor.sluc");',
  "WindowManCount***()",
  'WindowManFindByName***>("TestApp");',
  'WindowManLaunch***>("TestApp");',
  "GpuFlushRenderContext***>(ctx);",
  "rel op Destroy: [] [ ret 0; ];",
  "var im: <i32> = 0;",
];

let failures = 0;
for (const needle of mustContain) {
  if (!mara.includes(needle)) {
    console.error(`ÉCHEC — motif absent : ${needle}`);
    failures++;
  }
}

// Le curseur ayant déjà lu mx/my, le bloc launch ne doit PAS les redéclarer.
const mxCount = (mara.match(/let mx: <i32>/g) || []).length;
if (mxCount !== 1) {
  console.error(`ÉCHEC — mx déclaré ${mxCount} fois (attendu 1 : curseur déjà émis)`);
  failures++;
}

if (failures > 0) {
  console.error(`\n${failures} échec(s).\n\n--- Sortie générée ---\n${mara}`);
  process.exit(1);
}
console.log("emit.test OK — tous les motifs du catalogue présents.");
