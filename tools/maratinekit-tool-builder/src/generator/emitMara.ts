// Émission du texte Mara (TemplateView.mara) à partir de l'arbre de DrawOp.
// Catalogue des patterns et signatures : cf. plan (issus de TemplateView.mara/ovc_exec.rs).
// Testable hors Figma : ne dépend que des types de classify.ts, pas de `figma`.

import type { ClassifyResult, DrawOp, LaunchZone } from "./classify";
import { scaled, scaledRadiusMixed, scalePreamble } from "./scale";

function hex(color: number): string {
  return "0x" + (color >>> 0).toString(16).toUpperCase().padStart(8, "0");
}

interface EmitState {
  appName: string;
  imDeclared: boolean;
  fontDeclared: boolean;
  lines: string[];
  diamondColor: number; // ARGB — couleur intérieure des losanges [diamond], réglée via l'UI
}

function assetPath(state: EmitState, file: string): string {
  return `"SDC:/apps/${state.appName}/${state.appName}.slasset/${file}"`;
}

function ensureFont(state: EmitState): void {
  if (state.fontDeclared) return;
  state.fontDeclared = true;
  state.lines.push(
    `        // Police NOYAU via FontGetDefault() : GpuDrawTextFontAlign rastérise avec`,
    `        // ctx.font_len (longueur de la police du noyau) ; il FAUT donc lui passer le`,
    `        // MÊME pointeur (celui de srfs_font_ptr = FontGetDefault), sinon le parseur TTF`,
    `        // lit une mauvaise taille et ne produit aucun glyphe. (Famille/style Figma ignorés.)`,
    `        var font: <ptr> = <DrvAPIInterCon***FontGetDefault***>();`
  );
}

function emitOp(op: DrawOp, state: EmitState, indent: string): void {
  const L = state.lines;
  switch (op.kind) {
    case "comment":
      L.push(`${indent}// ${op.text}`);
      break;

    case "rect": {
      const ax = op.uniform ? "u" : "x";
      const ay = op.uniform ? "u" : "y";
      const radius = op.uniform ? scaled(op.r, "u") : scaledRadiusMixed(op.r);
      L.push(
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(` +
          `${scaled(op.x, "x")}, ${scaled(op.y, "y")}, ${scaled(op.w, ax)}, ${scaled(op.h, ay)}, ${radius}, ${hex(op.color)});`
      );
      break;
    }

    case "rectFull":
      L.push(
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectFull***>(` +
          `${scaled(op.x, "x")}, ${scaled(op.y, "y")}, ${scaled(op.w, "x")}, ${scaled(op.h, "y")}, ` +
          `${scaledRadiusMixed(op.rTL)}, ${scaledRadiusMixed(op.rTR)}, ${scaledRadiusMixed(op.rBL)}, ${scaledRadiusMixed(op.rBR)}, ${hex(op.color)});`
      );
      break;

    case "gradient":
      L.push(
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuDrawLinearGradient***>(` +
          `${scaled(op.x, "x")}, ${scaled(op.y, "y")}, ${scaled(op.w, "x")}, ${scaled(op.h, "y")}, ${scaledRadiusMixed(op.r)}, ` +
          `${op.angle}, ${hex(op.c1)}, ${op.p1}, ${hex(op.c2)}, ${op.p2}, 2);`
      );
      break;

    case "image": {
      if (!state.imDeclared) {
        state.imDeclared = true;
        // déclaré en tête de Render par emitTemplateView — ici on ne fait que l'utiliser
      }
      L.push(`${indent}im = <DrvAPIInterCon***ImageLoad***>(${assetPath(state, `img${op.index}.png`)});`);
      if (op.uniform) {
        // Aspect préservé (sU) ET position CENTRÉE sur le centre design : un coin
        // haut-gauche en sW/sH + une taille en sU décale l'icône hors de sa tuile
        // dès que l'écran/fenêtre n'a pas le ratio du design.
        const cx = Math.round(op.x + op.w / 2);
        const cy = Math.round(op.y + op.h / 2);
        const v = `icw${op.index}`;
        L.push(
          `${indent}let ${v}: <i32> = ${scaled(op.w, "u")};`,
          `${indent}let ${v}h: <i32> = ${scaled(op.h, "u")};`,
          `${indent}let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, (${scaled(cx, "x")} - (${v} / 2)), (${scaled(cy, "y")} - (${v}h / 2)), ${v}, ${v}h);`
        );
      } else {
        L.push(
          `${indent}let _: <i32> = <DrvAPIInterCon***ImageDraw***>(im, ${scaled(op.x, "x")}, ${scaled(op.y, "y")}, ${scaled(op.w, "x")}, ${scaled(op.h, "y")});`
        );
      }
      break;
    }

    case "svg": {
      const ax = op.uniform ? "u" : "x";
      const ay = op.uniform ? "u" : "y";
      L.push(
        `${indent}let svg${op.index}: <ptr> = <DrvAPIInterCon***SvgLoad***>(${assetPath(state, `vec${op.index}.svg`)});`,
        `${indent}let _: <i32> = <DrvAPIInterCon***SvgDraw***>(svg${op.index}, ${scaled(op.x, "x")}, ${scaled(op.y, "y")}, ${scaled(op.w, ax)}, ${scaled(op.h, ay)});`,
        `${indent}let _: <i32> = <DrvAPIInterCon***SvgFree***>(svg${op.index});`
      );
      break;
    }

    case "text":
      ensureFont(state);
      L.push(
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuDrawTextFontAlign***>(` +
          `${scaled(op.x, "x")}, ${scaled(op.y, "y")}, ${scaled(op.maxW, "x")}, "${op.content}", ` +
          `${hex(op.fg)}, 0x00000000, font, ${scaled(op.size, "u")}, ${op.align});`
      );
      break;

    case "blur":
      L.push(
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuBackgroundBlur***>(` +
          `${scaled(op.x, "x")}, ${scaled(op.y, "y")}, ${scaled(op.w, "x")}, ${scaled(op.h, "y")}, ${scaledRadiusMixed(op.r)}, ${op.amount});`
      );
      break;

    case "shadow":
      L.push(
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuDrawDropShadow***>(` +
          `${scaled(op.x, "x")}, ${scaled(op.y, "y")}, ${scaled(op.w, "x")}, ${scaled(op.h, "y")}, ${scaledRadiusMixed(op.r)}, ` +
          `${op.offX}, ${op.offY}, ${op.blur}, ${hex(op.color)});`
      );
      break;

    case "rotate":
      L.push(
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuSetTransform2D***>(` +
          `${op.cos10k}, ${op.sin10k}, ${-op.sin10k}, ${op.cos10k}, ${scaled(op.pivotX, "x")}, ${scaled(op.pivotY, "y")});`
      );
      for (const child of op.children) emitOp(child, state, indent);
      L.push(`${indent}let _: <i32> = <DrvAPIInterCon***GpuResetTransform***>();`);
      break;

    case "opacity":
      L.push(`${indent}let _: <i32> = <DrvAPIInterCon***GpuSetOpacity***>(${op.value});`);
      for (const child of op.children) emitOp(child, state, indent);
      L.push(`${indent}let _: <i32> = <DrvAPIInterCon***GpuResetOpacity***>();`);
      break;

    case "diamond": {
      // Losange verre (façon dock/Shi Windows) : anneau extérieur blanc translucide fixe
      // (glass, cohérent avec le reste de l'OS) + losange intérieur dans la couleur
      // PERSONNALISABLE (réglée dans l'UI du plugin, pas le fill Figma du nœud [diamond]).
      // sU (uniforme) pour la taille/rayon : pas de déformation même si sW≠sH.
      const cx = op.x + op.w / 2, cy = op.y + op.h / 2;
      const size = Math.round((op.w + op.h) / 2);
      L.push(
        `${indent}// Losange [diamond] — couleur personnalisable via le plugin`,
        `${indent}let dvx: <i32> = ${scaled(cx, "x")};`,
        `${indent}let dvy: <i32> = ${scaled(cy, "y")};`,
        `${indent}let dmw: <i32> = ${scaled(size, "u")};`,
        `${indent}let dmr: <i32> = ${scaled(op.r, "u")};`,
        `${indent}let dix: <i32> = (dvx - (dmw / 2));`,
        `${indent}let diy: <i32> = (dvy - (dmw / 2));`,
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuSetTransform2D***>(6947, 7193, -7193, 6947, dvx, dvy);`,
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>((dix - 1), (diy - 1), (dmw + 2), (dmw + 2), (dmr + 1), 0x66FFFFFF);`,
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectAlpha***>(dix, diy, dmw, dmw, dmr, ${hex(state.diamondColor)});`,
        `${indent}let _: <i32> = <DrvAPIInterCon***GpuResetTransform***>();`
      );
      break;
    }
  }
}

function emitCursor(state: EmitState): void {
  state.lines.push(
    ``,
    `        // [Curseur HID — nœud "HIDcursor" détecté dans le design]`,
    `        // NOTE : CursorLoad attend le format texte .sluc (RLE <rect>), pas un PNG.`,
    `        // Un HIDcursor_reference.png est exporté dans le .slasset comme référence —`,
    `        // convertissez-le en HIDcursor.sluc (cf. ShiLauncher.slasset) sinon le curseur`,
    `        // sera simplement absent (CursorLoad retourne 0, CursorDraw no-op).`,
    `        let mx: <i32> = <DrvAPIInterCon***PointerGetX***>();`,
    `        let my: <i32> = <DrvAPIInterCon***PointerGetY***>();`,
    `        let cur: <i32> = <DrvAPIInterCon***CursorLoad***>(${assetPath(state, "HIDcursor.sluc")});`,
    `        let _: <i32> = <DrvAPIInterCon***CursorDraw***>(cur, mx, my);`,
    `        let _: <i32> = <DrvAPIInterCon***CursorFree***>(cur);`
  );
}

function emitLaunches(launches: LaunchZone[], state: EmitState, cursorEmitted: boolean): void {
  const L = state.lines;
  L.push(``, `    // ── Lancement d'apps ([launch:Nom] dans le design) — occlusion incluse ──`);
  if (!cursorEmitted) {
    L.push(
      `    let mx: <i32> = <DrvAPIInterCon***PointerGetX***>();`,
      `    let my: <i32> = <DrvAPIInterCon***PointerGetY***>();`
    );
  }
  L.push(
    `    let pbtn: <i32> = <DrvAPIInterCon***PointerGetBtn***()>;`,
    `    let wcountTV: <i32> = <DrvAPIInterCon***WindowManCount***()>;`,
    `    var occluded: <bool> = false;`,
    `    var wj: <i32> = 0;`,
    `    loop (wj < wcountTV) [`,
    `        let owx: <i32> = <DrvAPIInterCon***WindowManGetX***>(wj);`,
    `        let owy: <i32> = <DrvAPIInterCon***WindowManGetY***>(wj);`,
    `        let oww: <i32> = <DrvAPIInterCon***WindowManGetW***>(wj);`,
    `        let owh: <i32> = <DrvAPIInterCon***WindowManGetH***>(wj);`,
    `        if (mx >= owx && mx <= (owx + oww) && my >= (owy - 28) && my <= (owy + owh)) [`,
    `            occluded = true;`,
    `        ];`,
    `        wj = wj + 1;`,
    `    ];`
  );
  for (const lz of launches) {
    const x0 = scaled(lz.x, "x");
    const y0 = scaled(lz.y, "y");
    const x1 = scaled(lz.x + lz.w, "x");
    const y1 = scaled(lz.y + lz.h, "y");
    L.push(
      ``,
      `    if (occluded == false && (pbtn & 1) != 0 && mx >= ${x0} && mx <= ${x1} && my >= ${y0} && my <= ${y1}) [`,
      `        let existing_${lz.app}: <i32> = <DrvAPIInterCon***WindowManFindByName***>("${lz.app}");`,
      `        if (existing_${lz.app} < 0) [`,
      `            let _: <i32> = <DrvAPIInterCon***WindowManLaunch***>("${lz.app}");`,
      `        ];`,
      `    ];`
    );
  }
}

function countImages(ops: DrawOp[]): boolean {
  for (const op of ops) {
    if (op.kind === "image") return true;
    if ((op.kind === "rotate" || op.kind === "opacity") && countImages(op.children)) return true;
  }
  return false;
}

/** Génère TemplateView.mara complet.
 *  diamondColor : couleur ARGB des losanges [diamond] (réglée dans l'UI du plugin) —
 *  défaut 0x33B9B9B9, celle utilisée par ShiLauncher (dock/Shi Windows). */
export function emitTemplateView(
  result: ClassifyResult, appName: string, designW: number, designH: number,
  diamondColor: number = 0x33b9b9b9
): string {
  const state: EmitState = { appName, imDeclared: false, fontDeclared: false, lines: [], diamondColor };
  const L = state.lines;

  L.push(
    `#base <std***ComTpe***SlulFrmt***[ DrvAPIInterCon ]>;`,
    `#base <MaratineKit>;`,
    ``,
    `// Généré par MaratineKit tool's builder (plugin Figma) — design ${Math.round(designW)}×${Math.round(designH)}.`,
    `// Renderer stateless : une seule var im réutilisée (cache image kernel = 8 slots).`,
    `rel op Render: [ctx string, fnt ptr] [`
  );
  if (countImages(result.ops)) {
    L.push(`    var im: <i32> = 0;`);
    state.imDeclared = true;
  }
  L.push(...scalePreamble(designW, designH), ``);

  for (const op of result.ops) emitOp(op, state, "        ");

  if (result.hasCursor) emitCursor(state);
  if (result.launches.length > 0) emitLaunches(result.launches, state, result.hasCursor);

  L.push(
    ``,
    `    let gpuResult: <i32> = <DrvAPIInterCon***GpuFlushRenderContext***>(ctx);`,
    `    if (gpuResult != 0) [ ret 1; ];`,
    `    ret 0;`,
    `];`,
    ``,
    `// Destroy sans params — attendu par le framework OVC après chaque Render`,
    `rel op Destroy: [] [ ret 0; ];`,
    ``
  );
  return L.join("\n");
}
