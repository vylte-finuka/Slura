//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — .marep application loader ___
//
//! Charge le bundle application Maratine de démarrage (`.marep`) et
//! transfère le contrôle à son entry-point `OEntry`.
//!
//! ## Cycle de vie d'une app .marep
//! ```text
//! 1. Lire home.marep            (SimpleFileSystem)
//! 2. Extraire native.bin        (ZipReader)
//! 3. AllocatePages LOADER_CODE  (UEFI Boot Services)
//! 4. Copier native.bin → pages
//! 5. Appeler OEntry()           (offset 0 du binaire PIC)
//!    └─ OEntry entre dans la boucle principale de l'OS
//! ```
//!
//! ## Contrat du binaire
//! `native.bin` est un binaire **Position-Independent** (PIC / PIE) produit
//! par `marai build --flat --no-compress`.  `OEntry` est à l'offset 0 et
//! possède la signature C-ABI `int OEntry(void)`.
//!
//! L'appel à `OEntry` ne retourne normalement pas : il s'agit de la boucle
//! principale de l'interface Slura OS.

extern crate alloc;
use alloc::vec::Vec;

use core::sync::atomic::{compiler_fence, Ordering};

use uefi::{
    cstr16, Handle,
    proto::media::{
        file::{File, FileAttribute, FileMode, FileType},
        fs::SimpleFileSystem,
    },
    table::{
        boot::{AllocateType, MemoryType, OpenProtocolAttributes, OpenProtocolParams},
        Boot, SystemTable,
    },
};

use super::{zip_reader::ZipReader, BundleError, FnOEntry};

/// Chemin absolu — cohérent avec les drivers dans \sources\.
const HOME_MAREP: &uefi::CStr16 = cstr16!("\\ShiLauncher.marep");

/// Charge `ShiLauncher.marep`, vérifie l'OVC et transfère au driver SluGpu.
/// Le rendu est géré par le driver HAL (SluGpu.slul) chargé par hal_manager.
pub fn load_and_run(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
) -> Result<i32, BundleError> {
    crate::ovc_exec::screen_log(st, "[MARATINE] load_marep_modules start", 0);
    // Flush AVANT l'étape risquée, pas seulement après : si load_marep_modules
    // plante (fault matériel, pas juste un Err propre), rien après ce point ne
    // s'exécuterait — sans ce flush préalable, le fichier ESP resterait vide
    // et on perdrait justement les logs des étapes qui viennent de se lancer.
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);
    let (_, modules) = load_marep_modules(st, image_handle, HOME_MAREP)?;
    crate::ovc_exec::screen_log(st, &alloc::format!(
        "[MARATINE] load_marep_modules OK, {} module(s), appel render_from_marep", modules.len()
    ), 0);
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);
    crate::kernel_runtime::render_from_marep(st, image_handle, &modules);
    Ok(0)
}

/// Extrait la valeur d'une clé scalaire simple `key: valeur` depuis le YAML plat de
/// Maraset.yaml (une ligne, sans gestion de nesting/indentation — suffisant pour les
/// clés du bloc `metadata.attributes` : SRID, icon, display_name...).
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

/// Extrait le SRID depuis Maraset.yaml (`SRID: SRID_xxx`).
fn extract_srid<'a>(yaml: &'a [u8]) -> &'a str {
    extract_yaml_scalar(yaml, "SRID").unwrap_or("SRID_unknown")
}

/// Vérifie AuthARoot : le SRID du manifeste doit figurer dans RAbstractallowing.xml.
fn verify_auth_root(xml: &[u8], srid: &str) -> bool {
    core::str::from_utf8(xml).map(|t| t.contains(srid)).unwrap_or(false)
}

/// Charge un `.marep` situé à `path` : lit le bundle, vérifie AuthARoot (log
/// seulement, non bloquant), découvre dynamiquement tous les `base/*.ovc`,
/// installe les assets (+ `Maraset.yaml`) sur l'ESP. Retourne `(app_name, modules)`
/// — modules **possédés** (`String`/`Vec<u8>`, pas des emprunts sur `bundle`) pour
/// pouvoir être conservés après le retour de cette fonction, ex. exécuté aux côtés
/// d'un autre `.marep` déjà chargé (plan bureau à fenêtres, jalon 1 étape 3).
pub fn load_marep_modules(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    path:         &uefi::CStr16,
) -> Result<(alloc::string::String, alloc::vec::Vec<(alloc::string::String, alloc::vec::Vec<u8>)>), BundleError> {
    crate::ovc_exec::screen_log(st, "[MARATINE] find_and_read start", 0);
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);
    let bundle = find_and_read(st, image_handle, path)?;
    crate::ovc_exec::screen_log(st, &alloc::format!(
        "[MARATINE] find_and_read OK, {} octets", bundle.len()
    ), 0);
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);
    let zip = ZipReader::new(&bundle)?;
    crate::ovc_exec::screen_log(st, "[MARATINE] ZipReader::new OK", 0);
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);

    // ── AuthARoot : vérification SRID ────────────────────────────────────────
    let maraset  = zip.extract_file("Maraset.yaml").unwrap_or_default();
    let xml      = zip.extract_file("RAbstractallowing.xml").unwrap_or_default();
    let srid     = extract_srid(&maraset);
    let auth_ok  = verify_auth_root(&xml, srid);

    // Métadonnées lanceur (étape 1/N vers un bureau à fenêtres) — pas encore
    // consommées par le rendu, juste extraites et logguées pour valider le
    // format avant que le registre d'apps (app_registry.rs) ne s'en serve.
    let icon         = extract_yaml_scalar(&maraset, "icon").unwrap_or("");
    let display_name = extract_yaml_scalar(&maraset, "display_name").unwrap_or("");

    crate::ovc_exec::screen_log(st, if auth_ok {
        "[AuthARoot] SRID verifie OK"
    } else {
        "[AuthARoot] WARN: SRID non verifie"
    }, 0);
    crate::ovc_exec::screen_log(st, &alloc::format!(
        "[MARASET] srid={} icon={} name={}", srid, icon, display_name
    ), 0);
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);

    // ── OVC ──────────────────────────────────────────────────────────────────
    const MAGIC: &[u8] = b"# Vyft OVC v1.0";

    let oentry = zip.extract_file("base\\OEntry.ovc")?;
    if oentry.is_empty() { return Err(BundleError::EmptyBinary); }
    if oentry.len() < MAGIC.len() || &oentry[..MAGIC.len()] != MAGIC {
        return Err(BundleError::EmptyBinary);
    }
    crate::ovc_exec::screen_log(st, "[MARATINE] OEntry.ovc extrait et magic verifie OK", 0);
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);

    // Découverte dynamique des OVC depuis le répertoire central du ZIP.
    // Le kernel ne hardcode aucun nom de module — tous les base/*.ovc sont chargés.
    // OEntry est le seul point d'entrée universel ; les autres sont passés pour
    // la résolution cross-module dans exec_marep.
    let ovc_names: alloc::vec::Vec<alloc::string::String> = zip.list_ovc_modules();
    let mut modules: alloc::vec::Vec<(alloc::string::String, alloc::vec::Vec<u8>)> = alloc::vec::Vec::new();

    for name_owned in &ovc_names {
        let bytes = {
            let p = alloc::format!("base/{}.ovc", name_owned);
            let b = zip.extract_file(&p).unwrap_or_default();
            if !b.is_empty() { b } else {
                let p2 = alloc::format!("base\\{}.ovc", name_owned);
                zip.extract_file(&p2).unwrap_or_default()
            }
        };
        if !bytes.is_empty() {
            modules.push((name_owned.clone(), bytes));
        }
    }

    crate::ovc_exec::screen_log(st, &alloc::format!(
        "[MARATINE] {} modules OVC charges", modules.len()
    ), 0);
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);

    // ── Installation automatique des assets → SDC:/apps/<AppName>/ ──────────
    // Chaque .marep est installé sur l'ESP au premier chargement.
    // Les fichiers assets (*.slasset/) sont copiés dans SDC/slu64/apps/<AppName>/
    // avant que l'OVC tourne, de sorte que les ImageLoad("SDC:/apps/...") réussissent.
    let app_name = zip.find_app_name().unwrap_or_else(|| alloc::string::String::from("App"));
    crate::ovc_exec::screen_log(st, &alloc::format!(
        "[MARATINE] app_name={} - install_assets_to_esp start", app_name
    ), 0);
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);
    install_assets_to_esp(st, image_handle, &zip, &app_name, &maraset);
    crate::ovc_exec::screen_log(st, "[MARATINE] install_assets_to_esp done", 0);
    crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);

    Ok((app_name, modules))
}

// ── Lecture ───────────────────────────────────────────────────────────────────

/// Parcourt tous les volumes SimpleFileSystem et retourne les octets du
/// premier `.marep` trouvé à `path`.
fn find_and_read(st: &mut SystemTable<Boot>, image_handle: Handle, path: &uefi::CStr16) -> Result<Vec<u8>, BundleError> {
    let handles = st
        .boot_services()
        .find_handles::<SimpleFileSystem>()
        .map_err(|_| BundleError::UefiError)?;
    crate::ovc_exec::serial_log(alloc::format!(
        "[MARATINE] find_and_read: {} volume(s) SimpleFileSystem\r\n", handles.len()
    ).as_bytes());

    for (i, &fs_handle) in handles.iter().enumerate() {
        crate::ovc_exec::serial_log(alloc::format!(
            "[MARATINE] find_and_read: essai volume {}\r\n", i
        ).as_bytes());
        if let Ok(bytes) = read_from_volume(st, image_handle, fs_handle, path) {
            crate::ovc_exec::serial_log(alloc::format!(
                "[MARATINE] find_and_read: trouve sur volume {} ({} octets)\r\n", i, bytes.len()
            ).as_bytes());
            return Ok(bytes);
        }
    }

    crate::ovc_exec::serial_log(b"[MARATINE] find_and_read: introuvable sur tous les volumes\r\n");
    Err(BundleError::FileNotFound)
}

fn read_from_volume(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    fs_handle:    Handle,
    path:         &uefi::CStr16,
) -> Result<Vec<u8>, BundleError> {
    // GET_PROTOCOL : accès non-exclusif — évite l'échec si OVMF tient le protocole.
    let mut fs = unsafe {
        st.boot_services().open_protocol::<SimpleFileSystem>(
            OpenProtocolParams {
                handle:     fs_handle,
                agent:      image_handle,
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .map_err(|_| BundleError::UefiError)?;

    let mut root = fs.open_volume().map_err(|_| BundleError::UefiError)?;

    let fh = root
        .open(path, FileMode::Read, FileAttribute::empty())
        .map_err(|_| BundleError::FileNotFound)?;

    let mut file = match fh.into_type().map_err(|_| BundleError::UefiError)? {
        FileType::Regular(f) => f,
        FileType::Dir(_)     => return Err(BundleError::FileNotFound),
    };

    read_all(&mut file)
}

fn read_all(file: &mut uefi::proto::media::file::RegularFile) -> Result<Vec<u8>, BundleError> {
    let mut buf   = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(BundleError::UefiError),
        }
    }

    if buf.is_empty() {
        return Err(BundleError::EmptyBinary);
    }

    Ok(buf)
}

// ── Installation assets → ESP ─────────────────────────────────────────────────

/// Copie tous les assets du ZIP vers `SDC/slu64/apps/<app_name>/` sur l'ESP.
/// Appelé une fois par chargement de marep, avant l'exécution OVC.
fn install_assets_to_esp(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    zip:          &super::zip_reader::ZipReader<'_>,
    app_name:     &str,
    maraset:      &[u8],
) {
    use uefi::proto::media::{
        file::{File, FileAttribute, FileMode, FileType},
        fs::SimpleFileSystem,
    };

    let assets = zip.list_all_assets();
    crate::ovc_exec::screen_log(st, &alloc::format!(
        "[INSTALL] {} asset(s) a installer", assets.len()
    ), 0);
    if assets.is_empty() && maraset.is_empty() { return; }

    let handles = match st.boot_services().find_handles::<SimpleFileSystem>() {
        Ok(h) => h,
        Err(_) => {
            crate::ovc_exec::screen_log(st, "[INSTALL] find_handles::<SimpleFileSystem> echoue", 0);
            return;
        }
    };
    crate::ovc_exec::screen_log(st, &alloc::format!(
        "[INSTALL] {} volume(s) SimpleFileSystem trouve(s)", handles.len()
    ), 0);

    // installed > 0 une fois que les assets sont écrits — log après que fs est droppé.
    let mut installed = 0usize;
    'volumes: for (vol_i, &fs_handle) in handles.iter().enumerate() {
        // screen_log emprunte `st` en mutable (stdout()) — impossible à
        // l'intérieur du scope fs/root ci-dessous, qui emprunte aussi `st`.
        // serial_log seul (pas de dépendance à `st`) reste utilisable dedans ;
        // l'écran est mis à jour juste après, une fois le scope fermé.
        crate::ovc_exec::serial_log(alloc::format!(
            "[INSTALL] volume {} : ouverture...\r\n", vol_i
        ).as_bytes());
        let wrote = {
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
            crate::ovc_exec::serial_log(alloc::format!(
                "[INSTALL] volume {} ouvert, ecriture de {} asset(s)\r\n", vol_i, assets.len()
            ).as_bytes());
            let mut w = 0usize;
            for (rel_path, data) in &assets {
                let dest = alloc::format!("SDC\\slu64\\apps\\{}\\{}",
                    app_name, rel_path.replace('/', "\\"));
                esp_ensure_parent_dirs(&mut root, &dest);
                if esp_write_file(&mut root, &dest, data) { w += 1; }
            }
            crate::ovc_exec::serial_log(alloc::format!(
                "[INSTALL] volume {}: {}/{} asset(s) ecrits\r\n", vol_i, w, assets.len()
            ).as_bytes());
            // Copie Maraset.yaml à côté du .slasset installé — permet à
            // app_registry.rs de découvrir icône/nom sans rouvrir le .marep zip
            // (dont le fichier source n'est de toute façon plus accessible une
            // fois l'app installée sur l'ESP).
            if !maraset.is_empty() {
                let dest = alloc::format!("SDC\\slu64\\apps\\{}\\Maraset.yaml", app_name);
                esp_ensure_parent_dirs(&mut root, &dest);
                let _ = esp_write_file(&mut root, &dest, maraset);
            }
            w
            // fs et root droppés ici → borrow sur st libéré
        };
        // Flush + affichage écran hors du scope fs/root (borrow sur st libéré)
        // — après chaque volume, pas seulement à la fin : si l'écriture d'un
        // asset bloque (I/O disque bare-metal), l'écran garde quand même la
        // trace du dernier volume/compte atteint avant le blocage.
        crate::ovc_exec::screen_log(st, &alloc::format!(
            "[INSTALL] volume {}: {} asset(s) ecrits", vol_i, wrote
        ), 0);
        crate::ovc_exec::flush_boot_log_to_esp(st, image_handle);
        if wrote > 0 { installed = wrote; break 'volumes; }
    }

    if installed > 0 {
        use core::fmt::Write;
        let _ = write!(st.stdout(),
            "[INSTALL] {}/{} assets installes dans SDC/apps/{}\r\n",
            installed, assets.len(), app_name);
    }
}

/// Construit un chemin UCS-2 pour l'API UEFI (séparateur `\`, préfixe `\`).
fn esp_ucs2(path: &str) -> alloc::vec::Vec<u16> {
    let mut v: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(path.len() + 2);
    v.push(b'\\' as u16);
    let mut last_sep = true;
    for b in path.bytes() {
        if b == b'\\' || b == b'/' {
            if !last_sep { v.push(b'\\' as u16); }
            last_sep = true;
        } else {
            v.push(b as u16);
            last_sep = false;
        }
    }
    v.push(0u16);
    v
}

/// Crée récursivement chaque composant de répertoire du chemin (hors fichier final).
fn esp_ensure_parent_dirs(
    root: &mut uefi::proto::media::file::Directory,
    full_path: &str,
) {
    use uefi::proto::media::file::{File, FileAttribute, FileMode};
    let parts: alloc::vec::Vec<&str> = full_path
        .split('\\')
        .filter(|s| !s.is_empty())
        .collect();
    let dir_count = parts.len().saturating_sub(1);
    let mut cum = alloc::string::String::new();
    for i in 0..dir_count {
        if !cum.is_empty() { cum.push('\\'); }
        cum.push_str(parts[i]);
        let ucs2 = esp_ucs2(&cum);
        if let Ok(p) = uefi::CStr16::from_u16_with_nul(&ucs2) {
            // Ouvre si existant, crée si absent — ignorer l'erreur dans les deux cas.
            let _ = root.open(p, FileMode::CreateReadWrite, FileAttribute::DIRECTORY);
        }
    }
}

/// Crée ou écrase le fichier à `path` avec `data`.
fn esp_write_file(
    root: &mut uefi::proto::media::file::Directory,
    path: &str,
    data: &[u8],
) -> bool {
    use uefi::proto::media::file::{File, FileAttribute, FileMode, FileType};
    let ucs2 = esp_ucs2(path);
    let p = match uefi::CStr16::from_u16_with_nul(&ucs2) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let fh = match root.open(p, FileMode::CreateReadWrite, FileAttribute::empty()) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut file = match fh.into_type() {
        Ok(FileType::Regular(f)) => f,
        _ => return false,
    };
    let mut off = 0usize;
    while off < data.len() {
        let end = data.len().min(off + 4096);
        match file.write(&data[off..end]) {
            Ok(()) => off = end,
            Err(_) => return false,
        }
    }
    true
}

// ── Mapping exécutable ────────────────────────────────────────────────────────

/// Extrait `native.bin` du bundle, alloue des pages `LOADER_CODE` et y
/// copie le code.  Retourne un pointeur de fonction vers l'offset 0 (OEntry).
fn map_executable(
    _st:    &mut SystemTable<Boot>,
    bundle: &[u8],
) -> Result<FnOEntry, BundleError> {
    // Les bundles .marep contiennent du LLVM IR (.ovc) compilé par marai build.
    // base\OEntry.ovc — le ZIP marai utilise des backslashes Windows.
    // L'exécution réelle se fait via platform_bridge::slura_mgc_execute (UVM).
    let zip = ZipReader::new(bundle)?;
    let ovc = zip.extract_file("base\\OEntry.ovc")?;
    if ovc.is_empty() {
        return Err(BundleError::EmptyBinary);
    }
    // OVC trouvé — l'affichage sera géré par SluGpu.slul + HelloSlura.marep
    // via le runtime UVM (platform_bridge). Le kernel ne fait pas de rendu.
    Err(BundleError::NotInitialized)
}
