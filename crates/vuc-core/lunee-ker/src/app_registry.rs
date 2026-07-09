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

    'volumes: for &fs_handle in handles.iter() {
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

            result.push(AppManifest { folder_name, display_name, icon_rel, srid });
        }

        if !result.is_empty() { break 'volumes; }
    }

    serial_log(alloc::format!("[REGISTRY] {} app(s) :\r\n", result.len()).as_bytes());
    for app in &result {
        serial_log(alloc::format!(
            "[REGISTRY]   {} (nom={} icon={} srid={})\r\n",
            app.folder_name, app.display_name, app.icon_rel, app.srid
        ).as_bytes());
    }

    result
}

// ── Registre exposé à Maratine (dock dynamique) ──────────────────────────────
// Liste plate des apps LANÇABLES (le shell "ShiLauncher" est exclu — il ne se lance
// pas dans son propre dock). Chaque entrée précalcule des buffers nul-terminés pour que
// les builtins `DrvAPIInterCon***AppRegistry...***` renvoient des pointeurs STABLES
// consommables directement par ImageLoad/WindowManLaunch (qui lisent jusqu'au `\0`).
struct RegEntry {
    name_c: alloc::vec::Vec<u8>, // "<folder>\0"          (nom de lancement)
    icon_c: alloc::vec::Vec<u8>, // "SDC:/apps/<folder>/<icon_rel>\0" ou vide si pas d'icône
}

static mut REGISTRY: alloc::vec::Vec<RegEntry> = alloc::vec::Vec::new();

/// Apps système par défaut : TOUJOURS présentes et épinglées en tête du dock, dans cet
/// ordre, même si le scan de l'ESP ne les trouve pas (installées par défaut, non
/// retirables — comme Finder sur macOS). ShiLooker est le « Finder » de Slura.
const PINNED_DEFAULTS: &[&str] = &["ShiLooker"];

fn make_entry(folder: &str, icon_rel: &str) -> RegEntry {
    let mut name_c = alloc::string::String::from(folder).into_bytes();
    name_c.push(0);
    let icon_c = if icon_rel.is_empty() {
        alloc::vec::Vec::new()
    } else {
        let mut s = alloc::format!("SDC:/apps/{}/{}", folder, icon_rel).into_bytes();
        s.push(0);
        s
    };
    RegEntry { name_c, icon_c }
}

/// Publie la liste pour consommation par les builtins (appelé une fois au boot).
/// Les apps épinglées par défaut (`PINNED_DEFAULTS`) viennent d'abord et sont garanties
/// présentes ; les autres apps installées suivent (le shell « ShiLauncher » est exclu —
/// il ne figure pas dans son propre dock).
pub fn publish_registry(apps: &[AppManifest]) {
    let mut v: alloc::vec::Vec<RegEntry> = alloc::vec::Vec::new();

    // 1) Défauts épinglés en tête, toujours présents (icône du manifeste scanné si dispo,
    //    sinon convention `<App>.slasset/<App>.png`).
    for &pinned in PINNED_DEFAULTS {
        let icon_rel = apps
            .iter()
            .find(|a| a.folder_name == pinned)
            .map(|a| a.icon_rel.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| alloc::format!("{}.slasset/{}.png", pinned, pinned));
        v.push(make_entry(pinned, &icon_rel));
    }

    // 2) Autres apps installées (hors shell et hors défauts déjà ajoutés).
    for a in apps {
        if a.folder_name == "ShiLauncher" { continue; }
        if PINNED_DEFAULTS.iter().any(|&p| p == a.folder_name) { continue; }
        v.push(make_entry(&a.folder_name, &a.icon_rel));
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
