// Orchestration multi-formes : le plugin ne crée AUCUNE forme depuis rien —
// il prend les formes déjà sélectionnées par l'utilisateur (déjà stylées :
// leur fill est copié/dérivé tel quel, voir figmaBuild.ts) et régénère
// UNIQUEMENT leur géométrie + relief. 1 forme sélectionnée = silhouette
// statique ; 2+ formes = keyframes d'une animation (même topologie de
// points sur toutes -> vrai morph Smart Animate, pas un fondu, voir blob.ts).
//
// Deux modes : "ribbon" (ruban de soie, silhouette organique + dégradé
// satiné) et "ring" (anneau mat, aplat uni — AUCUNE texture/facette
// possible, retiré volontairement, voir figmaBuild.ts) — la couleur de base
// reste TOUJOURS celle de la forme d'origine dans les deux cas.
//
// Le câblage du prototype (boucle "après délai -> Smart Animate") a besoin
// de nœuds FRAME de premier niveau pour naviguer (limite de l'API Figma,
// pas de ce plugin) : il cherche donc, pour chaque forme, son frame ancêtre
// de premier niveau (s'il existe) et câble CES frames-là — sans jamais créer
// ni renommer de frame. Si une forme n'a pas un tel ancêtre, le relief est
// quand même généré pour elle ; seul le câblage auto du prototype est ignoré
// (signalé dans les avertissements).
//
// IMPORTANT (honnêteté) : une rotation VISIBLE nécessite TOUJOURS 2+ formes/
// keyframes — une frame câblée sur ELLE-MÊME n'a rien à interpoler pour
// Smart Animate, donc ça ne tournerait pas malgré une réaction acceptée.
// Avec 1 seule forme sélectionnée, le résultat est une silhouette statique
// à l'angle de départ (timeT figé à 0), signalé dans le message de statut
// (code.ts).
import { buildRibbonLayerPaths, buildRingLayerPaths, derivePointPhases, LayerPaths } from "./blob";
import { applyWaveRelief } from "./figmaBuild";

export type WaveMode = "ribbon" | "ring";

export interface WaveOnShapesOptions {
  targetShapes: readonly SceneNode[];
  mode: WaveMode;
  /** Fraction (0..1) du plus petit côté de CHAQUE forme occupée par la forme générée. */
  sizeRatio: number;
  /** Ruban uniquement : nombre de points de la silhouette organique. Sans
   *  effet en mode anneau (bandeau toujours uni, sans facette). */
  pointCount: number;
  /** Ruban uniquement : organicité (0 = cercle parfait). Sans effet en mode
   *  anneau. */
  jitter: number;
  /** Vitesse de rotation — tours sur tout le cycle d'animation. */
  rotationTurns: number;
  /** Anneau uniquement : épaisseur du bandeau, fraction du rayon extérieur (0..1). */
  thicknessRatio: number;
  /** Anneau uniquement : segment plus clair façon indicateur de spinner —
   *  désactivé par défaut. */
  ringSegment: boolean;
  withShadow: boolean;
  shadowBlur: number;
  autoplayDelayMs: number;
  wireAutoplay: boolean;
  rnd: () => number;
}

export interface WaveOnShapesResult {
  shapes: GroupNode[];
  reactionWarnings: string[];
}

export async function generateWaveOnShapes(opts: WaveOnShapesOptions): Promise<WaveOnShapesResult> {
  const targets = opts.targetShapes;
  const frameCount = targets.length;
  // Mêmes phases pour toutes les formes de CETTE animation : condition
  // nécessaire au morph Smart Animate (topologie de points identique). Sans
  // effet en mode anneau (silhouette toujours un cercle parfait) mais
  // dérivées quand même pour garder un seed cohérent entre les deux modes.
  const pointPhases = derivePointPhases(opts.pointCount, opts.rnd);
  const shapes: GroupNode[] = [];
  const winding: WindingRule = opts.mode === "ring" ? "EVENODD" : "NONZERO";
  // MÊME nom de groupe pour TOUTES les keyframes (dérivé de la première
  // forme sélectionnée) — condition nécessaire à Smart Animate/Figma Motion,
  // voir figmaBuild.ts (ApplyReliefOptions.groupName) pour le détail.
  const groupName = targets[0]?.name ?? (opts.mode === "ring" ? "Ring" : "Ribbon");

  for (let i = 0; i < frameCount; i++) {
    const target = targets[i];
    if (!("width" in target) || !("height" in target)) continue;
    const w = (target as SceneNode & LayoutMixin).width;
    const h = (target as SceneNode & LayoutMixin).height;

    // Taille dérivée de la forme CIBLE elle-même — jamais une valeur absolue
    // choisie hors contexte : chaque forme garde ses propres proportions.
    const baseRadius = (Math.min(w, h) / 2) * opts.sizeRatio;
    const canvasSize = Math.ceil(baseRadius * 3.4);
    const timeT = frameCount <= 1 ? 0 : i / frameCount;

    const paths: LayerPaths =
      opts.mode === "ring"
        ? buildRingLayerPaths(canvasSize, baseRadius, opts.thicknessRatio, timeT, opts.rotationTurns, opts.ringSegment)
        : buildRibbonLayerPaths(canvasSize, baseRadius, opts.pointCount, opts.jitter, pointPhases, timeT, opts.rotationTurns);

    shapes.push(
      applyWaveRelief(target, paths, {
        withShadow: opts.withShadow,
        shadowBlur: opts.shadowBlur,
        winding,
        groupName,
      })
    );
  }

  const reactionWarnings: string[] = [];
  if (opts.wireAutoplay && frameCount > 1) {
    await wireAutoplayLoop(shapes, opts.autoplayDelayMs, reactionWarnings);
  }

  return { shapes, reactionWarnings };
}

/** Remonte jusqu'au frame de premier niveau (parent direct = la page) —
 *  `null` si la forme n'est pas posée dans un tel frame. */
function findTopLevelFrame(node: SceneNode): FrameNode | null {
  let current: BaseNode = node;
  while (current.parent && current.parent.type !== "PAGE") {
    current = current.parent;
  }
  if (current.parent && current.parent.type === "PAGE" && current.type === "FRAME") {
    return current as FrameNode;
  }
  return null;
}

function smartAnimateReaction(destinationId: string, delaySec: number): Reaction {
  return {
    trigger: { type: "AFTER_TIMEOUT", timeout: delaySec },
    actions: [
      {
        type: "NODE",
        destinationId,
        navigation: "NAVIGATE",
        transition: {
          type: "SMART_ANIMATE",
          easing: { type: "LINEAR" },
          duration: Math.min(0.9, delaySec * 0.8),
        },
        preserveScrollPosition: false,
      },
    ],
  };
}

/** Câble une boucle "après délai -> Smart Animate -> frame suivante" sur les
 *  frames ANCÊTRES des formes (jamais de frame créée par le plugin), la
 *  dernière bouclant sur la première. Best-effort : la forme exacte de
 *  l'API Reaction a pu évoluer entre versions de Figma — si
 *  `setReactionsAsync` rejette, les FORMES restent utilisables, seul le
 *  câblage auto échoue (message ajouté à `warnings`, à câbler alors à la
 *  main via l'onglet Prototype). */
async function wireAutoplayLoop(shapes: GroupNode[], delayMs: number, warnings: string[]): Promise<void> {
  const seen = new Set<string>();
  const frames: FrameNode[] = [];
  for (const shape of shapes) {
    const frame = findTopLevelFrame(shape);
    if (!frame) {
      warnings.push(`"${shape.name}" n'est pas posée dans un frame de premier niveau — câblage du prototype ignoré pour elle.`);
      continue;
    }
    if (!seen.has(frame.id)) {
      seen.add(frame.id);
      frames.push(frame);
    }
  }
  if (frames.length < 2) {
    warnings.push("Moins de 2 frames de premier niveau distinctes trouvées — pas de boucle de prototype câblée.");
    return;
  }

  const delaySec = Math.max(0.05, delayMs / 1000);
  for (let i = 0; i < frames.length; i++) {
    const current = frames[i];
    const next = frames[(i + 1) % frames.length];
    try {
      await current.setReactionsAsync([smartAnimateReaction(next.id, delaySec)]);
    } catch (err) {
      warnings.push(
        `"${current.name}" -> "${next.name}" : cablage auto du prototype refuse (${err instanceof Error ? err.message : String(err)}), a faire a la main (onglet Prototype).`
      );
    }
  }
}
