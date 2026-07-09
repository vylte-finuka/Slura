// Classification des nœuds Figma → arbre de DrawOp typés (structure intermédiaire,
// traduite en texte Mara par emitMara.ts). Tourne dans le sandbox Figma (accès `figma`).
//
// Ordre de peinture : children[0] = fond → dernier = dessus (même ordre que Figma).
// Conventions de nommage reconnues (cf. plan) :
//   - nœud nommé exactement "HIDcursor"      → boilerplate curseur (pas d'ImageDraw)
//   - nom contenant "[launch:NomApp]"        → hit-test + WindowManLaunch("NomApp")

import { isUniform } from "./scale";

export type DrawOp =
  | { kind: "comment"; text: string }
  | { kind: "rect"; x: number; y: number; w: number; h: number; r: number; color: number; uniform: boolean }
  | { kind: "rectFull"; x: number; y: number; w: number; h: number; rTL: number; rTR: number; rBL: number; rBR: number; color: number }
  | { kind: "gradient"; x: number; y: number; w: number; h: number; r: number; angle: number; c1: number; p1: number; c2: number; p2: number }
  | { kind: "image"; x: number; y: number; w: number; h: number; index: number; uniform: boolean }
  | { kind: "svg"; x: number; y: number; w: number; h: number; index: number; uniform: boolean }
  | { kind: "text"; x: number; y: number; maxW: number; content: string; fg: number; size: number; align: number }
  | { kind: "blur"; x: number; y: number; w: number; h: number; r: number; amount: number }
  | { kind: "shadow"; x: number; y: number; w: number; h: number; r: number; offX: number; offY: number; blur: number; color: number }
  | { kind: "rotate"; cos10k: number; sin10k: number; pivotX: number; pivotY: number; children: DrawOp[] }
  | { kind: "opacity"; value: number; children: DrawOp[] };

export interface LaunchZone { x: number; y: number; w: number; h: number; app: string }

export interface ClassifyResult {
  ops: DrawOp[];
  launches: LaunchZone[];
  pngs: Uint8Array[];   // img1.png, img2.png, ... (ordre de traversée)
  svgs: Uint8Array[];   // vec1.svg, ...
  cursorRefPng: Uint8Array | null; // export PNG de référence du nœud HIDcursor (le .sluc reste manuel)
  iconPng: Uint8Array | null;      // export PNG du nœud "AppIcon" → icône du dock (recadrée+centrée par l'UI)
  hasCursor: boolean;
  hasText: boolean;
}

interface Ctx {
  rootX: number;
  rootY: number;
  result: ClassifyResult;
}

function colorToArgb(c: RGB, opacity: number): number {
  const a = Math.round(Math.max(0, Math.min(1, opacity)) * 255) & 0xff;
  const r = Math.round(c.r * 255) & 0xff;
  const g = Math.round(c.g * 255) & 0xff;
  const b = Math.round(c.b * 255) & 0xff;
  // >>> 0 pour rester en non-signé (0xFF...... dépasse i32 signé en JS bitwise)
  return ((a << 24) | (r << 16) | (g << 8) | b) >>> 0;
}

function nodeRect(node: SceneNode, ctx: Ctx): { x: number; y: number; w: number; h: number; cx: number; cy: number } | null {
  const bb = (node as LayoutMixin).absoluteBoundingBox;
  if (!bb) return null;
  // Centre du AABB = centre de la forme même pivotée ; w/h = dimensions NON pivotées
  // (le pattern GpuSetTransform2D dessine la forme "droite" et laisse le kernel pivoter).
  const w = "width" in node ? node.width : bb.width;
  const h = "height" in node ? node.height : bb.height;
  const cx = bb.x + bb.width / 2 - ctx.rootX;
  const cy = bb.y + bb.height / 2 - ctx.rootY;
  return { x: cx - w / 2, y: cy - h / 2, w, h, cx, cy };
}

function cornerRadii(node: SceneNode): { uniform: number | null; tl: number; tr: number; bl: number; br: number } {
  const n = node as RectangleNode; // les mixins de coin existent sur rect/frame/component/instance
  const cr = "cornerRadius" in n ? n.cornerRadius : 0;
  if (typeof cr === "number") return { uniform: cr, tl: cr, tr: cr, bl: cr, br: cr };
  const tl = "topLeftRadius" in n ? n.topLeftRadius : 0;
  const tr = "topRightRadius" in n ? n.topRightRadius : 0;
  const bl = "bottomLeftRadius" in n ? n.bottomLeftRadius : 0;
  const br = "bottomRightRadius" in n ? n.bottomRightRadius : 0;
  if (tl === tr && tl === bl && tl === br) return { uniform: tl, tl, tr, bl, br };
  return { uniform: null, tl, tr, bl, br };
}

function gradientAngleDeg(gt: Transform): number {
  return Math.round((Math.atan2(gt[0][1], gt[0][0]) * 180) / Math.PI);
}

/** Effets (ombre portée, flous) — émis AVANT les fills du nœud. */
function effectOps(node: SceneNode, r: { x: number; y: number; w: number; h: number }, radius: number, out: DrawOp[]): void {
  if (!("effects" in node)) return;
  for (const fx of node.effects) {
    if (fx.visible === false) continue;
    if (fx.type === "DROP_SHADOW") {
      out.push({
        kind: "shadow",
        x: r.x, y: r.y, w: r.w, h: r.h, r: radius,
        offX: Math.round(fx.offset.x), offY: Math.round(fx.offset.y),
        blur: Math.round(fx.radius),
        color: colorToArgb(fx.color, fx.color.a),
      });
    } else if (fx.type === "BACKGROUND_BLUR" || fx.type === "LAYER_BLUR") {
      out.push({
        kind: "blur",
        x: r.x, y: r.y, w: r.w, h: r.h, r: radius,
        amount: Math.max(1, Math.min(16, Math.round(fx.radius / 2))),
      });
    }
  }
}

/** Fills du nœud → ops (couleur unie, gradient 2 stops, image → export PNG). */
async function fillOps(node: SceneNode, r: { x: number; y: number; w: number; h: number }, ctx: Ctx): Promise<{ ops: DrawOp[]; consumedChildren: boolean }> {
  const out: DrawOp[] = [];
  if (!("fills" in node) || node.fills === figma.mixed) return { ops: out, consumedChildren: false };

  const rot = "rotation" in node ? node.rotation : 0;
  const radii = cornerRadii(node);
  const uni = isUniform(r.w, r.h, rot, radii.uniform ?? 0);

  for (const fill of node.fills as readonly Paint[]) {
    if (fill.visible === false) continue;
    const fillOpacity = fill.opacity === undefined ? 1 : fill.opacity;

    if (fill.type === "SOLID") {
      if (radii.uniform !== null) {
        out.push({ kind: "rect", x: r.x, y: r.y, w: r.w, h: r.h, r: radii.uniform, color: colorToArgb(fill.color, fillOpacity), uniform: uni });
      } else {
        out.push({ kind: "rectFull", x: r.x, y: r.y, w: r.w, h: r.h, rTL: radii.tl, rTR: radii.tr, rBL: radii.bl, rBR: radii.br, color: colorToArgb(fill.color, fillOpacity) });
      }
    } else if (fill.type === "GRADIENT_LINEAR" && fill.gradientStops.length === 2) {
      const s0 = fill.gradientStops[0];
      const s1 = fill.gradientStops[1];
      out.push({
        kind: "gradient",
        x: r.x, y: r.y, w: r.w, h: r.h, r: radii.uniform ?? 0,
        angle: gradientAngleDeg(fill.gradientTransform),
        c1: colorToArgb(s0.color, s0.color.a * fillOpacity), p1: Math.round(s0.position * 1000),
        c2: colorToArgb(s1.color, s1.color.a * fillOpacity), p2: Math.round(s1.position * 1000),
      });
    } else if (fill.type === "IMAGE") {
      // Export du nœud ENTIER en PNG (fill image + enfants aplatis) — même approche
      // que le wallpaper de ShiLauncher ; les enfants ne sont pas re-traversés.
      const bytes = await (node as ExportMixin).exportAsync({ format: "PNG" });
      ctx.result.pngs.push(bytes);
      out.push({ kind: "image", x: r.x, y: r.y, w: r.w, h: r.h, index: ctx.result.pngs.length, uniform: uni });
      return { ops: out, consumedChildren: true };
    } else {
      out.push({ kind: "comment", text: `TODO: fill ${fill.type} non supporté par le générateur v1 (nœud "${node.name}")` });
    }
  }
  return { ops: out, consumedChildren: false };
}

async function classifyNode(node: SceneNode, ctx: Ctx): Promise<DrawOp[]> {
  if (node.visible === false) return [];
  const out: DrawOp[] = [];
  const r = nodeRect(node, ctx);
  if (!r) return out;

  // ── Conventions de nommage ────────────────────────────────────────────────
  if (node.name === "HIDcursor") {
    ctx.result.hasCursor = true;
    ctx.result.cursorRefPng = await (node as ExportMixin).exportAsync({ format: "PNG" });
    return out; // dessin remplacé par le boilerplate curseur en fin de Render
  }
  // Nœud "AppIcon" (ou "[icon]") = icône du dock. Exporté puis recadré+centré par
  // l'UI (Canvas) → aucun padding transparent asymétrique, contenu parfaitement
  // centré dans un canvas carré (corrige le "décalage" des icônes exportées brutes).
  // Nœud marqueur : PAS dessiné dans l'écran (placez-le hors cadre ou masqué).
  if (node.name === "AppIcon" || node.name.includes("[icon]")) {
    ctx.result.iconPng = await (node as ExportMixin).exportAsync({ format: "PNG" });
    return out;
  }
  const launchMatch = node.name.match(/\[launch:([A-Za-z0-9_]+)\]/);
  if (launchMatch) {
    ctx.result.launches.push({ x: r.x, y: r.y, w: r.w, h: r.h, app: launchMatch[1] });
    // le nœud est AUSSI dessiné normalement (c'est l'icône cliquable) — on continue.
  }

  const rot = "rotation" in node ? node.rotation : 0;
  const radii = cornerRadii(node);
  let ops: DrawOp[] = [];

  // Effets avant fills (ombre sous la forme, blur de fond sous le verre).
  effectOps(node, r, radii.uniform ?? 0, ops);

  switch (node.type) {
    case "TEXT": {
      ctx.result.hasText = true;
      const t = node as TextNode;
      const fills = t.fills !== figma.mixed ? (t.fills as readonly Paint[]) : [];
      const solid = fills.find((f) => f.type === "SOLID" && f.visible !== false) as SolidPaint | undefined;
      const fg = solid ? colorToArgb(solid.color, solid.opacity ?? 1) : 0xff000000;
      const size = typeof t.fontSize === "number" ? Math.round(t.fontSize) : 12;
      const alignMap: Record<string, number> = { LEFT: 0, CENTER: 1, RIGHT: 2, JUSTIFIED: 0 };
      ops.push({
        kind: "text",
        x: r.x, y: r.y, maxW: r.w,
        content: t.characters.replace(/["\\]/g, "'").replace(/\r?\n/g, " "),
        fg, size,
        align: alignMap[t.textAlignHorizontal] ?? 0,
      });
      break;
    }
    case "VECTOR":
    case "BOOLEAN_OPERATION":
    case "STAR":
    case "POLYGON":
    case "LINE": {
      const bytes = await (node as ExportMixin).exportAsync({ format: "SVG" });
      ctx.result.svgs.push(bytes);
      ops.push({ kind: "svg", x: r.x, y: r.y, w: r.w, h: r.h, index: ctx.result.svgs.length, uniform: isUniform(r.w, r.h, rot, 0) });
      break;
    }
    case "ELLIPSE": {
      // Approximation : rect arrondi à rayon = min/2 (cercle exact si w==h).
      const { ops: fops } = await fillOps(node, r, ctx);
      ops.push(...fops.map((op) => (op.kind === "rect" ? { ...op, r: Math.min(r.w, r.h) / 2 } : op)));
      break;
    }
    default: {
      // RECTANGLE / FRAME / GROUP / COMPONENT / INSTANCE / SECTION...
      const { ops: fops, consumedChildren } = await fillOps(node, r, ctx);
      ops.push(...fops);
      if (!consumedChildren && "children" in node) {
        for (const child of node.children) {
          ops.push(...(await classifyNode(child, ctx)));
        }
      }
      break;
    }
  }

  // Rotation : les ops PROPRES au nœud passent sous GpuSetTransform2D ; les enfants
  // déjà traités récursivement gardent leur propre logique (un enfant droit dans un
  // parent pivoté est approximé droit — limitation v1 documentée dans le plan).
  if (Math.abs(rot) > 0.5) {
    const rad = (rot * Math.PI) / 180;
    ops = [{
      kind: "rotate",
      cos10k: Math.round(Math.cos(rad) * 10000),
      sin10k: Math.round(Math.sin(rad) * 10000),
      pivotX: r.cx, pivotY: r.cy,
      children: ops,
    }];
  }

  // Opacité de calque (distincte de l'alpha des fills, déjà porté par la couleur).
  const nodeOpacity = "opacity" in node ? node.opacity : 1;
  if (nodeOpacity < 0.999) {
    ops = [{ kind: "opacity", value: Math.round(nodeOpacity * 255), children: ops }];
  }

  out.push(...ops);
  return out;
}

/** Point d'entrée : classifie tout le frame sélectionné (les enfants, pas le frame lui-même —
 *  son fond éventuel est traité comme premier op via fillOps sur le root). */
export async function classifyFrame(root: FrameNode | ComponentNode | InstanceNode): Promise<ClassifyResult> {
  const bb = root.absoluteBoundingBox;
  const result: ClassifyResult = {
    ops: [], launches: [], pngs: [], svgs: [],
    cursorRefPng: null, iconPng: null, hasCursor: false, hasText: false,
  };
  const ctx: Ctx = { rootX: bb ? bb.x : 0, rootY: bb ? bb.y : 0, result };

  // Fond du frame racine (fill éventuel), puis enfants dans l'ordre de peinture.
  const rootRect = { x: 0, y: 0, w: root.width, h: root.height };
  const { ops: rootFills } = await fillOps(root, rootRect, ctx);
  result.ops.push(...rootFills);
  for (const child of root.children) {
    result.ops.push(...(await classifyNode(child, ctx)));
  }
  return result;
}
