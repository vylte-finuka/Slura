//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — registre des apps installées (bureau à fenêtres, étape 2/N) ___

//! Scanne `SDC/slu64/apps/*/Maraset.yaml` (installé sur l'ESP par la tâche
//! `install: <App> → apps SRFS`, ou par le kernel au chargement) pour construire la liste
//! des apps installées. Le dock de `TemplateView.mara` est piloté DYNAMIQUEMENT par ce
//! registre (via les builtins `DrvAPIInterCon***AppRegistry...***`) : une app n'apparaît
//! au dock que si elle est réellement installée — comme un vrai système.

use crate::ovc_exec::serial_log;
use uefi::proto::media::{
    file::{Directory, File, FileAttribute, FileMode, FileType},
    fs::SimpleFileSystem,
};
use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::table::{Boot, SystemTable};
use uefi::{CString16, Handle};

pub struct AppManifest {
    pub folder_name:  alloc::string::String,
    pub display_name: alloc::string::String,
    pub icon_rel:     alloc::string::String,
    pub srid:         alloc::string::String,
    pub diamond_color: u32, // ARGB — couleur du losange (dock + barre de titre) ; défaut si absent
    // Items du menu contextuel du dock, scalaire "Label1|Label2>sub1,sub2|Label3" —
    // Maraset.yaml ne supporte que des scalaires clé:valeur sur une ligne (aucune liste
    // YAML n'est jamais parsée nulle part dans ce noyau), d'où cette syntaxe déléguée.
    pub dock_menu_items: alloc::string::String,
}

/// Couleur de losange par défaut (verre gris) — utilisée si `diamond_color` est absent du
/// Maraset.yaml ou invalide. Même valeur que l'ancien littéral codé en dur dans ShiLauncher.
pub const DEFAULT_DIAMOND_COLOR: u32 = 0x33B9B9B9;

/// Parse "0x33B8E8C4" ou "33B8E8C4" (avec/sans préfixe) → u32 ARGB. Retombe sur le défaut.
fn parse_argb_hex(s: &str) -> u32 {
    let cleaned = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(cleaned, 16).unwrap_or(DEFAULT_DIAMOND_COLOR)
}

/// Extrait la valeur d'une clé scalaire simple `key: valeur` — même format que
/// `marep_loader::extract_yaml_scalar`, dupliqué ici (fonction privée à son module, et le
/// couplage entre les deux fichiers n'apporte rien pour un format aussi simple).
fn extract_yaml_scalar<'a>(yaml: &'a [u8], key: &str) -> Option<&'a str> {
    let text = core::str::from_utf8(yaml).ok()?;
    let prefix = alloc::format!("{}:", key);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix(prefix.as_str()) {
            let v = rest.trim().trim_matches('"');
            if !v.is_empty() { return Some(v); }
        }
    }
    None
}

fn read_whole_file(dir: &mut Directory, file_name: &str) -> Option<alloc::vec::Vec<u8>> {
    let cname = CString16::try_from(file_name).ok()?;
    let fh = dir.open(&cname, FileMode::Read, FileAttribute::empty()).ok()?;
    let mut file = match fh.into_type().ok()? {
        FileType::Regular(f) => f,
        FileType::Dir(_) => return None,
    };
    let mut buf = alloc::vec::Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
    if buf.is_empty() { None } else { Some(buf) }
}

/// Parcourt `SDC\slu64\apps\*\Maraset.yaml` sur le premier volume qui les contient et retourne
/// un `AppManifest` par sous-dossier où la lecture/le parsing réussissent.
pub fn scan_installed_apps(st: &mut SystemTable<Boot>, image_handle: Handle) -> alloc::vec::Vec<AppManifest> {
    let mut result: alloc::vec::Vec<AppManifest> = alloc::vec::Vec::new();

    let handles = match st.boot_services().find_handles::<SimpleFileSystem>() {
        Ok(h) => h,
        Err(_) => {
            serial_log(b"[REGISTRY] SimpleFileSystem introuvable\r\n");
            return result;
        }
    };
    serial_log(alloc::format!(
        "[REGISTRY] {} volume(s) SimpleFileSystem a scanner\r\n", handles.len()
    ).as_bytes());

    'volumes: for (vol_i, &fs_handle) in handles.iter().enumerate() {
        serial_log(alloc::format!("[REGISTRY] volume {} : ouverture...\r\n", vol_i).as_bytes());
        let mut fs = match unsafe {
            st.boot_services().open_protocol::<SimpleFileSystem>(
                OpenProtocolParams { handle: fs_handle, agent: image_handle, controller: None },
                OpenProtocolAttributes::GetProtocol,
            )
        } {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut root = match fs.open_volume() {
            Ok(r) => r,
            Err(_) => continue,
        };

        let apps_dir_handle = match root.open(
            uefi::cstr16!("\\SDC\\slu64\\apps"), FileMode::Read, FileAttribute::empty(),
        ) {
            Ok(f) => f,
            Err(_) => continue, // pas ce volume — normal, un seul volume porte SDC en pratique
        };
        let mut apps_dir: Directory = match apps_dir_handle.into_type() {
            Ok(FileType::Dir(d)) => d,
            _ => continue,
        };

        loop {
            let entry = match apps_dir.read_entry_boxed() {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(_) => break,
            };
            if !entry.is_directory() { continue; }
            let folder_name = alloc::string::String::from(entry.file_name());
            if folder_name == "." || folder_name == ".." { continue; }

            let sub_handle = match apps_dir.open(entry.file_name(), FileMode::Read, FileAttribute::empty()) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut sub_dir: Directory = match sub_handle.into_type() {
                Ok(FileType::Dir(d)) => d,
                _ => continue,
            };

            let Some(maraset) = read_whole_file(&mut sub_dir, "Maraset.yaml") else {
                serial_log(alloc::format!("[REGISTRY] {} : Maraset.yaml absent, ignore\r\n", folder_name).as_bytes());
                continue;
            };

            let display_name = extract_yaml_scalar(&maraset, "display_name").unwrap_or(&folder_name).into();
            let icon_rel      = extract_yaml_scalar(&maraset, "icon").unwrap_or("").into();
            let srid          = extract_yaml_scalar(&maraset, "SRID").unwrap_or("SRID_unknown").into();
            let diamond_color = extract_yaml_scalar(&maraset, "diamond_color")
                .map(parse_argb_hex)
                .unwrap_or(DEFAULT_DIAMOND_COLOR);
            let dock_menu_items = extract_yaml_scalar(&maraset, "dock_menu_items").unwrap_or("").into();

            result.push(AppManifest { folder_name, display_name, icon_rel, srid, diamond_color, dock_menu_items });
        }

        // Le dossier `\SDC\slu64\apps` a été trouvé et parcouru sur CE volume —
        // s'arrêter ici, qu'il contienne 0 ou N apps. Avant, on ne s'arrêtait
        // que si `result` était non vide : un dossier apps présent mais vide
        // (ou ne contenant que des sous-dossiers sans Maraset.yaml valide)
        // faisait continuer la boucle sur TOUS les volumes SimpleFileSystem
        // restants — sans effet sur QEMU/VMware (un seul volume ESP), mais
        // coûteux sur bare-metal avec plusieurs disques/partitions physiques
        // (chaque tentative d'accès sur un volume qui ne porte pas SDC a une
        // latence matérielle réelle, contrairement à un disque virtuel).
        break 'volumes;
    }

    serial_log(alloc::format!("[REGISTRY] {} app(s) :\r\n", result.len()).as_bytes());
    for app in &result {
        serial_log(alloc::format!(
            "[REGISTRY]   {} (nom={} icon={} srid={} diamond=0x{:08X})\r\n",
            app.folder_name, app.display_name, app.icon_rel, app.srid, app.diamond_color
        ).as_bytes());
    }

    result
}

// ── Registre exposé à Maratine (dock dynamique) ──────────────────────────────
// Liste plate des apps LANÇABLES (le shell "ShiLauncher" est exclu — il ne se lance
// pas dans son propre dock). Chaque entrée précalcule des buffers nul-terminés pour que
// les builtins `DrvAPIInterCon***AppRegistry...***` renvoient des pointeurs STABLES
// consommables directement par ImageLoad/WindowManLaunch (qui lisent jusqu'au `\0`).
/// Un item de menu contextuel du dock, éventuellement avec un sous-menu (ex: "New
/// File" ▸ txt/md/bmp). Parsé depuis le scalaire `dock_menu_items` du Maraset.yaml —
/// syntaxe `"Label1|Label2>sub1,sub2|Label3"` (`|` sépare les items, `>subs` optionnel
/// suivi de sous-items séparés par `,`).
struct MenuItem {
    label_c: alloc::vec::Vec<u8>,                    // "<label>\0"
    submenu_c: alloc::vec::Vec<alloc::vec::Vec<u8>>,  // "<sub>\0" par sous-item, vide si pas de sous-menu
}

/// Résout un item `@AppName` en les items RÉELS de l'app référencée (lue depuis son
/// propre `dock_menu_items`, sans jamais dupliquer leur texte en dur ailleurs) —
/// optionnel : un item normal peut se trouver n'importe où dans la séquence `|`,
/// mélangé aux items propres de l'app (ex: "...propres...|@ShiLauncher"). Une seule
/// profondeur de résolution (pas de `@` récursif dans l'app référencée) suffit au
/// besoin actuel et évite toute boucle infinie entre deux apps qui se référencent
/// mutuellement.
fn resolve_menu_ref(name: &str, apps: &[AppManifest]) -> alloc::vec::Vec<MenuItem> {
    match apps.iter().find(|a| a.folder_name == name) {
        Some(a) => parse_dock_menu_items_raw(&a.dock_menu_items),
        None => alloc::vec::Vec::new(),
    }
}

/// Parse le scalaire `dock_menu_items` SANS résoudre les références `@AppName` —
/// utilisé pour lire les items propres d'une app référencée (une seule profondeur,
/// voir `resolve_menu_ref`).
fn parse_dock_menu_items_raw(raw: &str) -> alloc::vec::Vec<MenuItem> {
    let mut items = alloc::vec::Vec::new();
    for part in raw.split('|') {
        let part = part.trim();
        if part.is_empty() || part.starts_with('@') { continue; }
        let (label, subs_raw) = match part.split_once('>') {
            Some((l, s)) => (l.trim(), s),
            None => (part, ""),
        };
        if label.is_empty() { continue; }
        let mut label_c = alloc::string::String::from(label).into_bytes();
        label_c.push(0);
        let mut submenu_c = alloc::vec::Vec::new();
        for sub in subs_raw.split(',') {
            let sub = sub.trim();
            if sub.is_empty() { continue; }
            let mut sc = alloc::string::String::from(sub).into_bytes();
            sc.push(0);
            submenu_c.push(sc);
        }
        items.push(MenuItem { label_c, submenu_c });
    }
    items
}

/// Parse "Label1|Label2>sub1,sub2|@AppName|Label3" en résolvant chaque token `@AppName`
/// (optionnel, mélangeable avec des items normaux) en les items réels de l'app
/// référencée — voir le commentaire de `AppManifest::dock_menu_items`.
fn parse_dock_menu_items(raw: &str, apps: &[AppManifest]) -> alloc::vec::Vec<MenuItem> {
    let mut items = alloc::vec::Vec::new();
    for part in raw.split('|') {
        let part = part.trim();
        if part.is_empty() { continue; }
        if let Some(name) = part.strip_prefix('@') {
            items.extend(resolve_menu_ref(name.trim(), apps));
            continue;
        }
        let (label, subs_raw) = match part.split_once('>') {
            Some((l, s)) => (l.trim(), s),
            None => (part, ""),
        };
        if label.is_empty() { continue; }
        let mut label_c = alloc::string::String::from(label).into_bytes();
        label_c.push(0);
        let mut submenu_c = alloc::vec::Vec::new();
        for sub in subs_raw.split(',') {
            let sub = sub.trim();
            if sub.is_empty() { continue; }
            let mut sc = alloc::string::String::from(sub).into_bytes();
            sc.push(0);
            submenu_c.push(sc);
        }
        items.push(MenuItem { label_c, submenu_c });
    }
    items
}

struct RegEntry {
    name_c: alloc::vec::Vec<u8>,    // "<folder>\0"          (nom de lancement)
    icon_c: alloc::vec::Vec<u8>,    // "SDC:/apps/<folder>/<icon_rel>\0" ou vide si pas d'icône
    display_c: alloc::vec::Vec<u8>, // "<display_name>\0"    (titre de la barre « Shi Windows »)
    diamond_color: i64,             // ARGB — couleur du losange (dock + barre de titre), donnée du .marep
    pinned: bool,                   // épinglé au dock — mutable au runtime (Pin/Unpin), session-only
    menu_items: alloc::vec::Vec<MenuItem>, // items du menu contextuel propres à cette app
}

static mut REGISTRY: alloc::vec::Vec<RegEntry> = alloc::vec::Vec::new();

/// Apps système par défaut : TOUJOURS présentes et épinglées en tête du dock, dans cet
/// ordre, même si le scan de l'ESP ne les trouve pas (installées par défaut, non
/// retirables — comme Finder sur macOS). ShiLooker est le « Finder » de Slura.
const PINNED_DEFAULTS: &[&str] = &["ShiLooker"];

fn make_entry(folder: &str, icon_rel: &str, display: &str, diamond_color: u32, pinned: bool, dock_menu_items: &str, apps: &[AppManifest]) -> RegEntry {
    let mut name_c = alloc::string::String::from(folder).into_bytes();
    name_c.push(0);
    let icon_c = if icon_rel.is_empty() {
        alloc::vec::Vec::new()
    } else {
        let mut s = alloc::format!("SDC:/apps/{}/{}", folder, icon_rel).into_bytes();
        s.push(0);
        s
    };
    let disp = if display.is_empty() { folder } else { display };
    let mut display_c = alloc::string::String::from(disp).into_bytes();
    display_c.push(0);
    let menu_items = parse_dock_menu_items(dock_menu_items, apps);
    RegEntry { name_c, icon_c, display_c, diamond_color: diamond_color as i64, pinned, menu_items }
}

/// Publie la liste pour consommation par les builtins (appelé une fois au boot).
/// Les apps épinglées par défaut (`PINNED_DEFAULTS`) viennent d'abord et sont garanties
/// présentes ; les autres apps installées suivent (le shell « ShiLauncher » est exclu —
/// il ne figure pas dans son propre dock). Seules les apps de `PINNED_DEFAULTS`
/// démarrent épinglées — le reste démarre désépinglé, l'utilisateur épingle au besoin
/// (AppRegistrySetPinned) ; l'état vit en mémoire noyau de session (pas de persistance
/// au reboot, voir la chaîne SluEnvSys qui est totalement non câblée aujourd'hui).
pub fn publish_registry(apps: &[AppManifest]) {
    let mut v: alloc::vec::Vec<RegEntry> = alloc::vec::Vec::new();

    // 1) Défauts épinglés en tête, toujours présents (icône du manifeste scanné si dispo,
    //    sinon convention `<App>.slasset/<App>.png`).
    for &pinned in PINNED_DEFAULTS {
        let manifest = apps.iter().find(|a| a.folder_name == pinned);
        let icon_rel = manifest
            .map(|a| a.icon_rel.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| alloc::format!("{}.slasset/{}.png", pinned, pinned));
        let display = manifest.map(|a| a.display_name.clone()).unwrap_or_default();
        let diamond_color = manifest.map(|a| a.diamond_color).unwrap_or(DEFAULT_DIAMOND_COLOR);
        let menu_items = manifest.map(|a| a.dock_menu_items.clone()).unwrap_or_default();
        v.push(make_entry(pinned, &icon_rel, &display, diamond_color, true, &menu_items, apps));
    }

    // 2) Autres apps installées (hors shell et hors défauts déjà ajoutés) — démarrent
    //    désépinglées, l'utilisateur choisit de les épingler au dock.
    for a in apps {
        if a.folder_name == "ShiLauncher" { continue; }
        if PINNED_DEFAULTS.iter().any(|&p| p == a.folder_name) { continue; }
        v.push(make_entry(&a.folder_name, &a.icon_rel, &a.display_name, a.diamond_color, false, &a.dock_menu_items, apps));
    }

    serial_log(alloc::format!(
        "[REGISTRY] dock : {} app(s) ({} epingle(s) par defaut)\r\n",
        v.len(), PINNED_DEFAULTS.len()
    ).as_bytes());
    unsafe { REGISTRY = v; }
}

pub fn registry_count() -> i64 {
    unsafe { REGISTRY.len() as i64 }
}

/// Pointeur nul-terminé vers le nom de lancement de l'app `i`, ou 0 si hors bornes.
pub fn registry_name_ptr(i: usize) -> i64 {
    unsafe { REGISTRY.get(i).map(|e| e.name_c.as_ptr() as i64).unwrap_or(0) }
}

/// Pointeur nul-terminé vers le chemin d'icône de l'app `i`, ou 0 si absente/hors bornes.
pub fn registry_icon_ptr(i: usize) -> i64 {
    unsafe {
        REGISTRY
            .get(i)
            .map(|e| if e.icon_c.is_empty() { 0 } else { e.icon_c.as_ptr() as i64 })
            .unwrap_or(0)
    }
}

/// Résout un nom de lancement (folder) → (ptr nom null-terminé, ptr icône null-terminé)
/// depuis le registre. Sert au chrome de fenêtre (barre « Shi Windows » : titre + icône
/// d'app PAR fenêtre ouverte). Retourne (0, 0) si le nom est introuvable au registre.
pub fn registry_name_icon_for(name: &str) -> (i64, i64) {
    unsafe {
        for e in REGISTRY.iter() {
            let nlen = e.name_c.len().saturating_sub(1); // name_c = "<folder>\0"
            if core::str::from_utf8(&e.name_c[..nlen]).map(|s| s == name).unwrap_or(false) {
                let icon = if e.icon_c.is_empty() { 0 } else { e.icon_c.as_ptr() as i64 };
                return (e.name_c.as_ptr() as i64, icon);
            }
        }
        (0, 0)
    }
}

/// Ptr null-terminé vers le display_name (titre « AppName - CurrentScreen ») de l'app
/// `name`, ou 0 si absente. Sert au titre de la barre « Shi Windows ».
pub fn registry_display_ptr_for(name: &str) -> i64 {
    unsafe {
        for e in REGISTRY.iter() {
            let nlen = e.name_c.len().saturating_sub(1);
            if core::str::from_utf8(&e.name_c[..nlen]).map(|s| s == name).unwrap_or(false) {
                return e.display_c.as_ptr() as i64;
            }
        }
        0
    }
}

/// Couleur ARGB du losange (dock) de l'app `i`, ou le défaut (verre gris) si hors bornes —
/// donnée du Maraset.yaml (`diamond_color`), PAS codée en dur : chaque app porte sa couleur.
pub fn registry_diamond_color(i: usize) -> i64 {
    unsafe { REGISTRY.get(i).map(|e| e.diamond_color).unwrap_or(DEFAULT_DIAMOND_COLOR as i64) }
}

/// Couleur ARGB du losange (barre de titre « Shi Windows ») de l'app `name`, ou le défaut
/// si introuvable au registre. Sert au chrome de fenêtre (une fenêtre par app ouverte).
pub fn registry_diamond_color_for(name: &str) -> i64 {
    unsafe {
        for e in REGISTRY.iter() {
            let nlen = e.name_c.len().saturating_sub(1);
            if core::str::from_utf8(&e.name_c[..nlen]).map(|s| s == name).unwrap_or(false) {
                return e.diamond_color;
            }
        }
        DEFAULT_DIAMOND_COLOR as i64
    }
}

/// 1 si l'app `i` est épinglée au dock, 0 sinon (0 aussi si hors bornes).
pub fn registry_get_pinned(i: usize) -> i64 {
    unsafe { REGISTRY.get(i).map(|e| e.pinned as i64).unwrap_or(0) }
}

/// Épingle/désépingle l'app `i` au dock (état de session, pas persisté au reboot — voir
/// commentaire de `publish_registry`). Retourne 0 si succès, -1 si `i` hors bornes.
pub fn registry_set_pinned(i: usize, pinned: bool) -> i64 {
    unsafe {
        match REGISTRY.get_mut(i) {
            Some(e) => { e.pinned = pinned; 0 }
            None => -1,
        }
    }
}

/// Nombre d'apps épinglées au dock (pour le menu global in-app).
pub fn registry_pinned_count() -> i64 {
    unsafe {
        REGISTRY.iter().filter(|e| e.pinned).count() as i64
    }
}

/// Retourne l'index dans REGISTRY de la i-ième app épinglée (tri par index régulier).
/// Par ex: registry_pinned_index(0) = premier app épinglée par index croissant.
pub fn registry_pinned_index(i: usize) -> i64 {
    unsafe {
        let mut count = 0;
        for (idx, e) in REGISTRY.iter().enumerate() {
            if e.pinned {
                if count == i { return idx as i64; }
                count += 1;
            }
        }
        -1
    }
}

/// Nombre d'items du menu contextuel propres à l'app `i` (0 si hors bornes ou aucun item
/// déclaré via `dock_menu_items` dans son Maraset.yaml).
pub fn registry_menu_item_count(i: usize) -> i64 {
    unsafe { REGISTRY.get(i).map(|e| e.menu_items.len() as i64).unwrap_or(0) }
}

/// Pointeur nul-terminé vers le libellé de l'item `j` du menu de l'app `i`, ou 0 si hors
/// bornes.
pub fn registry_menu_item_label_ptr(i: usize, j: usize) -> i64 {
    unsafe {
        REGISTRY.get(i)
            .and_then(|e| e.menu_items.get(j))
            .map(|m| m.label_c.as_ptr() as i64)
            .unwrap_or(0)
    }
}

/// Nombre de sous-items du sous-menu de l'item `j` de l'app `i` (0 = pas de sous-menu).
pub fn registry_menu_item_submenu_count(i: usize, j: usize) -> i64 {
    unsafe {
        REGISTRY.get(i)
            .and_then(|e| e.menu_items.get(j))
            .map(|m| m.submenu_c.len() as i64)
            .unwrap_or(0)
    }
}

/// Pointeur nul-terminé vers le libellé du sous-item `k` du sous-menu de l'item `j` de
/// l'app `i`, ou 0 si hors bornes.
pub fn registry_menu_item_submenu_label_ptr(i: usize, j: usize, k: usize) -> i64 {
    unsafe {
        REGISTRY.get(i)
            .and_then(|e| e.menu_items.get(j))
            .and_then(|m| m.submenu_c.get(k))
            .map(|s| s.as_ptr() as i64)
            .unwrap_or(0)
    }
}
