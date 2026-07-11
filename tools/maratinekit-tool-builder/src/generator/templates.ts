// Gabarits fixes des fichiers d'un bundle .marep — copiés depuis les sources réelles
// du repo Slura (ShiLauncher.marep / TestApp.marep), seules les valeurs par-app changent.

/** base/OEntry.mara — identique caractère pour caractère entre toutes les apps. */
export const OENTRY_MARA = `#base <std***core***self***[ RegistrationRoot, CaseComponentActivity ]>;
#base <MaratineKit>;
#include <std***gcc***arch***[ ArchitectureInfo ]>;

rel cl OEntry: <[string RegistrationRoot]>t [

    let ObtProcess: <[string PIDActivity]>        = <MaratineKit***PIDActivity***ObtInfo>;
    let PAccess:    <[string AuthARoot]>           = <MaratineKit***AuthARoot>;

    let ResLayout:    <[string CaseComponentActivity]>                     = ObtProcess(<MaratineKit***RenRootUI>);
    let RenderRootUI: <[string RegistrationRoot***[ SRIDAtt, KeyReg, PAccessAuth ]]> = PAccess(ResLayout);

    let ArchInfo:     <[string ArchitectureInfo]> = <gcc***archInfo***()>;
    log: ArchInfo;

    let Architecture: <string> = ArchInfo;
    let AppMain: <i32> = <std***core***self***LAPrevent***Launch>(Architecture);
    ret AppMain;
];
`;

function buildStamp(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-01`;
}

export interface AppMeta {
  appName: string;       // ex. "ShiNotes" — aussi nom du dossier .slasset
  screenName: string;    // écran courant (nom du frame Figma) → titre "AppName - Screen"
  isDesktop: boolean;    // variante bureau/shell (boucle WindowMan dans LAPrevent)
  hasAssets: boolean;    // au moins un png/svg exporté
  iconFile: string | null; // ex. "img1.png" (relatif au .slasset), ou null
}

export function marasetYaml(meta: AppMeta): string {
  const srid = `SRID_${meta.appName.toLowerCase()}`;
  const stamp = buildStamp();
  // Titre de la barre « Shi Windows » : "AppName - Screen" (le nom du frame = l'écran
  // courant). Si le frame porte déjà le nom de l'app, on n'ajoute pas de sous-titre.
  const screen = meta.screenName && meta.screenName !== meta.appName ? meta.screenName : "";
  const displayTitle = screen ? `${meta.appName}  - ${screen}` : meta.appName;
  const perms = ["gpu.framebuffer", "fs.read"];
  if (meta.hasAssets) perms.push("fs.write");
  const permLines = perms.map((p) => `    - ${p}`).join("\n");
  const iconLine = meta.iconFile ? `    icon: ${meta.appName}.slasset/${meta.iconFile}\n` : "";
  const assetsBlock = meta.hasAssets ? `\n  assets:\n    - ${meta.appName}.slasset/\n` : "\n";
  return `package:
  name: base***${meta.appName}
  version: v1 NAVERTA build ${stamp}
  build: ${stamp}

metadata:
  bundle: marep
  target: arm64
  attributes:
    SRID: ${srid}
    Marav: 0.1 build ${stamp}
${iconLine}    display_name: "${displayTitle}"
    description: |
      ${meta.appName} — application Slura OS générée par MaratineKit tool's builder.
    slura_min: 1
    slura_max: 5.0

  entry: OEntry
  lifecycle: LAPrevent

  permissions:
${permLines}
${assetsBlock}
dependencies:
  basecon:
    base***LAPrevent: 1.0.0
    base***OEntry: 1.0.0

resources:
  - path: RAbstractallowing.xml
    type: xml
    description: "Règles d'autorisation abstraites pour le sandbox Slura."

scripts:
  postinstall: |
    slura-reg add --srid \${metadata.attributes.SRID}
`;
}

export function rabstractallowingXml(meta: AppMeta): string {
  const srid = `SRID_${meta.appName.toLowerCase()}`;
  const perms = ["gpu.framebuffer", "fs.read"];
  if (meta.hasAssets) perms.push("fs.write");
  const allowLines = perms.map((p) => `        <Allow>${p}</Allow>`).join("\n");
  return `<?xml version="1.0" encoding="utf-8"?>
<RAbstractallowing>
    <!-- Identifiant unique du bundle — doit correspondre à Maraset.yaml -->
    <SRID>${srid}</SRID>

    <!-- Éditeur déclaré -->
    <Publisher>Vyft Ltd</Publisher>

    <!-- Clé de vérification publique (hex 33 bytes, format secp256k1) -->
    <SigningKey>PRIMARY_VALIDATOR_PUBKEY</SigningKey>

    <!-- Permissions explicitement accordées (sous-ensemble de Maraset.yaml) -->
    <Permissions>
${allowLines}
    </Permissions>

    <!-- Drivers autorisés à être chargés par ce bundle -->
    <DriverDeps/>
</RAbstractallowing>
`;
}

/** Boucle de gestion des fenêtres (variante bureau/shell uniquement) — reprise de
 *  LAPrevent.mara de ShiLauncher : composition, chrome « Shi Windows » redimensionné
 *  à chaque fenêtre, fermer/redimensionner/déplacer. */
const DESKTOP_WINDOW_LOOP = `
            // ── Bureau à fenêtres — logique en Maratine, primitives WindowMan*** en Rust ──
            let wcount: <i32> = <DrvAPIInterCon***WindowManCount***()>;
            let px: <i32> = <DrvAPIInterCon***PointerGetX***()>;
            let py: <i32> = <DrvAPIInterCon***PointerGetY***()>;
            let pbtn: <i32> = <DrvAPIInterCon***PointerGetBtn***()>;
            var wi: <i32> = 0;
            loop (wi < wcount) [
                let wx: <i32> = <DrvAPIInterCon***WindowManGetX***>(wi);
                let wy: <i32> = <DrvAPIInterCon***WindowManGetY***>(wi);
                let ww: <i32> = <DrvAPIInterCon***WindowManGetW***>(wi);
                let wh: <i32> = <DrvAPIInterCon***WindowManGetH***>(wi);

                let _: <i32> = <DrvAPIInterCon***WindowManRenderAndComposite***>(wi);

                // Chrome : bandeau « Shi Windows » à la largeur de CETTE fenêtre
                let _: <i32> = <DrvAPIInterCon***GpuDrawRoundedRectFull***>(wx, (wy - 28), ww, 28, 12, 12, 0, 0, 0xFFE0E0E0);
                let closeIcon: <ptr> = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/ShiLauncher/ShiLauncher.slasset/img18_close_x.png");
                let _: <i32> = <DrvAPIInterCon***ImageDraw***>(closeIcon, (wx + ww - 28), (wy - 28), 20, 20);
                let reduceIcon: <ptr> = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/ShiLauncher/ShiLauncher.slasset/img17_reduce_cropped.png");
                let _: <i32> = <DrvAPIInterCon***ImageDraw***>(reduceIcon, (wx + ww - 56), (wy - 28), 20, 20);
                let increaseIcon: <ptr> = <DrvAPIInterCon***ImageLoad***>("SDC:/apps/ShiLauncher/ShiLauncher.slasset/img11_increase_merged.png");
                let _: <i32> = <DrvAPIInterCon***ImageDraw***>(increaseIcon, (wx + ww - 84), (wy - 28), 20, 20);

                // Fermer (bouton close, bande de titre)
                if ((pbtn & 1) != 0 && px >= (wx + ww - 28) && px <= (wx + ww - 8) && py >= (wy - 28) && py <= (wy - 8)) [
                    let _: <i32> = <DrvAPIInterCon***WindowManClose***>(wi);
                ];

                // Redimensionner (coin bas-droit, 16×16)
                if ((pbtn & 1) != 0 && px >= (wx + ww - 16) && px <= (wx + ww) && py >= (wy + wh - 16) && py <= (wy + wh)) [
                    let _: <i32> = <DrvAPIInterCon***WindowManSetW***>(wi, (px - wx));
                    let _: <i32> = <DrvAPIInterCon***WindowManSetH***>(wi, (py - wy));
                ];

                // Déplacer (bande de titre, hors boutons) — snap sur le curseur
                if ((pbtn & 1) != 0 && px >= wx && px <= (wx + ww - 90) && py >= (wy - 28) && py <= wy) [
                    let _: <i32> = <DrvAPIInterCon***WindowManSetX***>(wi, (px - (ww / 2)));
                    let _: <i32> = <DrvAPIInterCon***WindowManSetY***>(wi, (py + 28));
                ];

                wi = wi + 1;
            ];
`;

export function laPreventMara(meta: AppMeta): string {
  const windowLoop = meta.isDesktop ? DESKTOP_WINDOW_LOOP : "";
  return `#base <std***core***self***[ AppLifecycle, ComponentView, RenderContext ]>;
#base <std***ComTpe***SlulFrmt***[ DrvAPIInterCon ]>;
#base <MaratineKit>;
#base <std***core***self***[ TemplateView ]>;

// ${meta.appName} — généré par MaratineKit tool's builder.
rel op LAPrevent: <[string AppLifecycle]>t [

    // Seules les vars <string> persistent via class vars — <ptr> non propagées depuis self***
    var Architecture: <string> = "";
    var _ctx:         <string> = "";

    rel op Launch: [arch string] [
        Architecture = arch;
        log: "${meta.appName}: demarrage - arch " + arch;

        _ctx = <MaratineKit***RenderContext***New()>;

        var fnt: <ptr> = <DrvAPIInterCon***FontLoad***>("SDC:/assets/fonts/brsonomasemibold.ttf");
        if (fnt == nullptr) [ fnt = <DrvAPIInterCon***FontGetDefault***>(); ];

        var running: <bool> = true;
        loop (running) [
            let renderResult: <i32> = <TemplateView***Render>(_ctx, fnt);
${windowLoop}
            if (renderResult != 0) [ running = false; ];
        ];

        let _: <i32> = self***onDestroy();
        ret 0;
    ];

    rel op onPause: [] [
        let _: <i32> = <MaratineKit***RenderContext***Suspend()>;
        ret 0;
    ];

    rel op onResume: [] [
        let _: <i32> = <MaratineKit***RenderContext***Resume()>;
        ret 0;
    ];

    rel cl onDestroy: [] [
        let _: <i32> = <MaratineKit***RenderContext***Destroy()>;
        log: "${meta.appName}: arrete";
        ret 0;
    ];
];
`;
}
