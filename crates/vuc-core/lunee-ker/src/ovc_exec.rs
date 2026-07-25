//___  Vyft Ltd __  (c) 2026  ___
// ___ Lunée Kernel — OVC Executor (LLVM IR minimal, no_std) ___
//
//! Interpréteur LLVM IR texte pour les OVC Vyft (GpuImpl.ovc, APrevent.ovc…).
//! Supporte le sous-ensemble utilisé par SluGpu.slul / SluHIIDMan.slul.
//!
//! Toutes les valeurs sont des i64 (pointeurs = entiers via inttoptr).
//! Les appels `DrvManSpec___*` et `printf` sont dispatché via `ExecCtx`.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ── Stockage des OVC drivers (chargés par slul_loader) ───────────────────────

static mut GPU_OVC:          Option<Vec<u8>> = None;
static mut FONT_TTF_OVC:     Option<Vec<u8>> = None;
static mut FONT_RAST_OVC:    Option<Vec<u8>> = None;
static mut FONT_WOFF_OVC:    Option<Vec<u8>> = None;

// ── Cache SRFS (SDC: → octets chargés à la demande depuis l'ESP) ─────────────
// Plus aucun fichier hardcodé dans slul_loader.
// FontLoad(path) charge le fichier depuis l'ESP UEFI au premier appel.
// 32 slots + LRU : 8 slots saturaient dès le boot (police + Maraset.yaml + curseur
// + vecs du launcher) et srfs_register_file jetait silencieusement tout fichier
// suivant → SvgLoad retournait 0 pour TOUS les assets d'une app (aucun SVG rendu).
static mut SRFS_CACHE: [Option<(String, Vec<u8>)>; 32] = [const { None }; 32];
static mut SRFS_AGE:  [u32; 32] = [0; 32];
static mut SRFS_TICK: u32 = 0;

// Cache d'images décodées (PNG → RGBA).  handle = index+1 (0 = erreur).
// 8 slots avec éviction LRU — ImageLoad inline juste avant ImageDraw.
static mut IMAGE_CACHE: [Option<(u32, u32, Vec<u8>)>; 8] = [None, None, None, None, None, None, None, None];
static mut IMAGE_CACHE_AGE:  [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
static mut IMAGE_CACHE_TICK: u32 = 0;

// Cache d'images PRÉ-REDIMENSIONNÉES (ARGB prêt à blitter). Le fond d'écran
// plein écran repassait par img_sample_box PAR PIXEL À CHAQUE FRAME (~2M
// échantillonnages) : coût dominant du bureau → souris peu réactive. Clé =
// (ptr des pixels source, dw, dh) ; 2 slots (fond d'écran + 1 grand visuel),
// réservé aux draws ≥ 65536 px pour ne pas thrasher avec les icônes.
static mut SCALED_CACHE: [Option<(usize, i32, i32, Vec<u32>)>; 2] = [None, None];
static mut SCALED_NEXT: usize = 0;

// Handles UEFI pour le chargement à la demande — initialisés par render_from_marep
static mut UEFI_ST_PTR:     *mut core::ffi::c_void = core::ptr::null_mut();
static mut UEFI_IMG_HANDLE: usize = 0;

// Copie en mémoire de tout ce qu'écrit `serial_log` — sur une machine bare-metal
// sans câble UART/port série accessible, le port 0x3F8 est écrit dans le vide et
// invisible. Ce buffer permet de sauver le même contenu vers un fichier sur l'ESP
// (voir `flush_boot_log_to_esp`), lisible après coup en rebootant sur un autre OS
// ou en retirant le disque — aucun matériel supplémentaire requis pour diagnostiquer.
static mut BOOT_LOG_BUF: Vec<u8> = Vec::new();

/// Écrit `BOOT_LOG_BUF` dans `\slura_boot.log` à la racine de l'ESP (créé ou écrasé).
/// Appelé à des points de contrôle du boot (pas à chaque `serial_log`, pour éviter
/// le coût d'un open/write/close UEFI par ligne) — voir les appels dans
/// marep_loader.rs et kernel_runtime.rs autour du chargement de ShiLauncher.
pub fn flush_boot_log_to_esp(st: &mut uefi::table::SystemTable<uefi::table::Boot>, image_handle: uefi::Handle) {
    use uefi::proto::media::{
        file::{File, FileAttribute, FileMode, FileType},
        fs::SimpleFileSystem,
    };
    use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

    let handles = match st.boot_services().find_handles::<SimpleFileSystem>() {
        Ok(h) => h,
        Err(_) => return,
    };
    let path = match uefi::CStr16::from_u16_with_nul(
        &[0x005C, 0x0073,0x006C,0x0075,0x0072,0x0061,0x005F,0x0062,0x006F,0x006F,0x0074,
          0x002E,0x006C,0x006F,0x0067, 0x0000] // "\slura_boot.log\0"
    ) {
        Ok(p) => p,
        Err(_) => return,
    };
    let data: &[u8] = unsafe { &BOOT_LOG_BUF };
    for &fs_handle in handles.iter() {
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
        let fh = match root.open(path, FileMode::CreateReadWrite, FileAttribute::empty()) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut file = match fh.into_type() {
            Ok(FileType::Regular(f)) => f,
            _ => continue,
        };
        let mut off = 0usize;
        let mut wrote_all = true;
        while off < data.len() {
            let end = data.len().min(off + 4096);
            match file.write(&data[off..end]) {
                Ok(()) => off = end,
                Err(_) => { wrote_all = false; break; }
            }
        }
        if wrote_all { return; } // premier volume accepté suffit
    }
}

// Fenêtres applicatives ouvertes (bureau à fenêtres) — source de vérité pour les
// builtins DrvAPIInterCon***WindowMan...***, pilotés depuis LAPrevent.mara. La
// LOGIQUE de fenêtrage (quand déplacer/redimensionner/fermer/lancer) vit en
// Maratine ; cette liste + les primitives ci-dessous (buffer, exec_marep imbriqué,
// composition) sont la seule part Rust, dans le même esprit que les autres caches
// process-wide de ce fichier (SRFS_CACHE, IMAGE_CACHE...).
static mut RUNNING_APPS: Vec<crate::window_manager::RunningApp> = Vec::new();

/// Initialise les handles UEFI pour le chargement dynamique des assets.
/// Appelé par kernel_runtime avant exec_marep.
pub fn init_uefi_handles(st_ptr: *mut core::ffi::c_void, image_handle: usize) {
    unsafe { UEFI_ST_PTR = st_ptr; UEFI_IMG_HANDLE = image_handle; }
}

/// Charge un fichier depuis l'ESP UEFI via le chemin SRFS `SDC:\...` à la demande.
/// Utilise le SystemTable stocké par init_uefi_handles.
fn srfs_load_on_demand(path_ptr: i64) -> i64 {
    // Chargeur SRFS générique — partagé par ImageLoad, SvgLoad, FontLoad ET CursorLoad.
    // Le tag "[SRFS]" (pas "[FONT]") reflète ça : ce n'est PAS une lecture de police,
    // juste des octets bruts quel que soit le type de fichier demandé.
    if path_ptr == 0 { return 0; }

    serial_log(b"[SRFS] uefi_read: ");
    serial_log(b"\r\n");

    // Extract the null-terminated string from the pointer
    let c_str_ptr = path_ptr as *const u8;
    let mut len = 0usize;
    unsafe {
        while *c_str_ptr.add(len) != 0 {
            len += 1;
            // Prevent infinite loop on invalid strings
            if len > 256 {
                break;
            }
        }
    }
    if len == 0 {
        serial_log(b"[SRFS] Empty path\r\n");
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts(c_str_ptr, len) };
    let rel = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            serial_log(b"[SRFS] Invalid UTF-8 in path\r\n");
            return 0;
        }
    };

    serial_log(b"[SRFS] Path: ");
    serial_log(rel.as_bytes());
    serial_log(b"\r\n");

    // SDC:/path → SDC/slu64/path  (emplacement réel sur l'ESP)
    // Tout autre chemin → chemin relatif sans / initial
    let uefi_rel_owned: alloc::string::String =
        if rel.to_ascii_uppercase().starts_with("SDC:") {
            let after = rel[4..].trim_matches(|c: char| c == '/' || c == '\\');
            alloc::format!("SDC/slu64/{}", after)
        } else {
            rel.trim_start_matches(|c: char| c == '/' || c == '\\').to_string()
        };

    // Cache d'abord : sans ce test, chaque appel relisait le fichier depuis l'ESP
    // ET ré-enregistrait un doublon — le cache se remplissait de copies du même
    // asset en quelques frames et tous les chargements suivants échouaient.
    unsafe {
        SRFS_TICK = SRFS_TICK.wrapping_add(1);
        for (i, slot) in SRFS_CACHE.iter().enumerate() {
            if let Some((ref k, ref d)) = slot {
                if keys_match(k.as_str(), rel) {
                    SRFS_AGE[i] = SRFS_TICK;
                    return d.as_ptr() as i64;
                }
            }
        }
    }

    let st_raw = unsafe { UEFI_ST_PTR };
    if st_raw.is_null() {
        serial_log(b"[SRFS] ST_PTR null! init_uefi_handles non appele\r\n");
        return 0;
    }

    let data = match unsafe { srfs_uefi_read(st_raw, &uefi_rel_owned) } {
        Some(d) => d,
        None => {
            serial_log(b"[SRFS] fichier introuvable\r\n");
            return 0;
        }
    };

    // Register the loaded data in SRFS cache for future use
    let key_owned = rel.to_string(); // Owned String for the key
    unsafe {
        srfs_register_file(key_owned, data);
        // Find the pointer to the data we just registered
        for slot in SRFS_CACHE.iter() {
            if let Some((ref k, ref d)) = slot {
                if k.as_str() == rel {
                    return d.as_ptr() as i64;
                }
            }
        }
    }
    // L'enregistrement a pu échouer si les 32 slots sont TOUS occupés par des
    // fichiers protégés (police) — cas théorique, loggé pour diagnostic.
    serial_log(b"[SRFS] cache plein, chargement perdu\r\n");
    0
}

/// Lit un fichier depuis l'ESP UEFI en utilisant SimpleFileSystem.
unsafe fn srfs_uefi_read(st_raw: *mut core::ffi::c_void, rel_path: &str)
    -> Option<alloc::vec::Vec<u8>>
{
    use uefi::table::{Boot, SystemTable};
    use uefi::proto::media::{
        file::{File, FileAttribute, FileMode, FileType},
        fs::SimpleFileSystem,
    };
    use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

    let mut st: SystemTable<Boot> = SystemTable::from_ptr(st_raw)?;
    // Build UCS-2 UEFI path.
    // Mara emits "\\" (double backslash) per path separator in OVC string constants.
    // Deduplicate consecutive separators to avoid "\\\path" → keep "\path".
    let mut ucs2: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(rel_path.len() + 2);
    ucs2.push(b'\\' as u16);  // mandatory leading separator
    let mut last_sep = true;   // skip duplicate separators at start of rel_path
    for b in rel_path.bytes() {
        if b == b'\\' || b == b'/' {
            if !last_sep { ucs2.push(b'\\' as u16); }
            last_sep = true;
        } else {
            ucs2.push(b as u16);
            last_sep = false;
        }
    }
    ucs2.push(0u16);
    let uefi_path = uefi::CStr16::from_u16_with_nul(&ucs2).ok()?;
    let img = uefi::Handle::from_ptr(UEFI_IMG_HANDLE as *mut core::ffi::c_void)?;
    let handles = st.boot_services().find_handles::<SimpleFileSystem>().ok()?;
    for &fs_h in handles.iter() {
        let mut fs = match st.boot_services().open_protocol::<SimpleFileSystem>(
            OpenProtocolParams { handle: fs_h, agent: img, controller: None },
            OpenProtocolAttributes::GetProtocol,
        ) { Ok(f) => f, Err(_) => continue };
        let mut root = match fs.open_volume() { Ok(r) => r, Err(_) => continue };
        let fh = match root.open(uefi_path, FileMode::Read, FileAttribute::empty()) {
            Ok(f) => f, Err(_) => continue };
        let mut file = match fh.into_type() {
            Ok(FileType::Regular(f)) => f, _ => continue };
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match file.read(&mut chunk) {
                Ok(0) => break, Ok(n) => buf.extend_from_slice(&chunk[..n]), Err(_) => break,
            }
        }
        if !buf.is_empty() { return Some(buf); }
    }
    None
}

/// Écrit RÉELLEMENT un fichier sur l'ESP (UEFI SimpleFileSystem, PAS SRFS_CACHE
/// qui est RAM-only et perdu au reboot) — crée les répertoires intermédiaires
/// manquants. Essaie chaque filesystem découvert jusqu'à ce qu'un accepte
/// l'écriture (un volume en lecture seule, ex. le CD Vmwaretool lui-même,
/// échouera silencieusement et le prochain filesystem — l'ESP — est tenté ;
/// pas besoin de désambiguïser explicitement quel handle est "le bon").
/// Utilisé par UefiInstallFile (voir plus bas) pour une installation qui
/// persiste réellement au reboot, contrairement à CaWriteFile (SRFS_CACHE).
unsafe fn srfs_uefi_write(st_raw: *mut core::ffi::c_void, rel_path: &str, data: &[u8]) -> bool {
    use uefi::table::{Boot, SystemTable};
    use uefi::proto::media::{
        file::{Directory, File, FileAttribute, FileMode, FileType},
        fs::SimpleFileSystem,
    };
    use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

    let st: SystemTable<Boot> = match SystemTable::from_ptr(st_raw) { Some(s) => s, None => return false };
    let img = match uefi::Handle::from_ptr(UEFI_IMG_HANDLE as *mut core::ffi::c_void) { Some(h) => h, None => return false };
    let handles = match st.boot_services().find_handles::<SimpleFileSystem>() { Ok(h) => h, Err(_) => return false };

    let segments: alloc::vec::Vec<&str> = rel_path.split(|c| c == '/' || c == '\\').filter(|s| !s.is_empty()).collect();
    let last = match segments.last() { Some(&s) => s, None => return false };

    'fs: for &fs_h in handles.iter() {
        let mut fs = match st.boot_services().open_protocol::<SimpleFileSystem>(
            OpenProtocolParams { handle: fs_h, agent: img, controller: None },
            OpenProtocolAttributes::GetProtocol,
        ) { Ok(f) => f, Err(_) => continue };
        let mut dir: Directory = match fs.open_volume() { Ok(r) => r, Err(_) => continue };

        for &seg in &segments[..segments.len() - 1] {
            let mut ucs2: alloc::vec::Vec<u16> = seg.encode_utf16().collect();
            ucs2.push(0);
            let cname = match uefi::CStr16::from_u16_with_nul(&ucs2) { Ok(c) => c, Err(_) => continue 'fs };
            let handle = match dir.open(cname, FileMode::CreateReadWrite, FileAttribute::DIRECTORY) {
                Ok(h) => h, Err(_) => continue 'fs,
            };
            dir = match handle.into_type() {
                Ok(FileType::Dir(d)) => d,
                _ => continue 'fs,
            };
        }

        let mut ucs2: alloc::vec::Vec<u16> = last.encode_utf16().collect();
        ucs2.push(0);
        let cname = match uefi::CStr16::from_u16_with_nul(&ucs2) { Ok(c) => c, Err(_) => continue };
        let handle = match dir.open(cname, FileMode::CreateReadWrite, FileAttribute::empty()) {
            Ok(h) => h, Err(_) => continue,
        };
        let mut file = match handle.into_type() {
            Ok(FileType::Regular(f)) => f, _ => continue,
        };
        if file.write(data).is_ok() { return true; }
    }
    false
}

// ── Capture média (ShiCamera, ShiLooker) ──────────────────────────────────────
// Compteur de fichiers + tampon vidéo en cours d'enregistrement. Plafonné
// (MAX_VIDEO_FRAMES) car chaque frame BGR non compressée pèse lourd — voir
// avi_frame_geometry (media_encode.rs) : à l'écran de design ~1440x1024, une
// frame ≈ 4.4 Mo, donc 40 frames ≈ 175 Mo, volontairement conservateur pour
// un environnement UEFI à mémoire limitée.
// ── Détection de format (EncDecProcMan) ───────────────────────────────────
static mut ENCDEC_NAME_BUF: [u8; 40] = [0u8; 40];

fn encdec_format_name_ptr(fmt: i32) -> i64 {
    let name = crate::format_detect::format_name(fmt);
    unsafe {
        let bytes = name.as_bytes();
        let n = bytes.len().min(ENCDEC_NAME_BUF.len() - 1);
        ENCDEC_NAME_BUF[..n].copy_from_slice(&bytes[..n]);
        ENCDEC_NAME_BUF[n] = 0;
        ENCDEC_NAME_BUF.as_ptr() as i64
    }
}

static mut CAPTURE_COUNTER: u32 = 0;
static mut VIDEO_FRAMES: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
static mut VIDEO_W: i32 = 0;
static mut VIDEO_H: i32 = 0;
const MAX_VIDEO_FRAMES: usize = 40;
// Dossier de destination configurable pour les captures ShiCamera — nul-terminé,
// même convention que DISK_BROWSE_PATH. Défaut "SDC/slu64/captures" (sans préfixe "SDC:").
static mut CAPTURE_DIR: alloc::vec::Vec<u8> = alloc::vec::Vec::new();

pub fn capture_dir_get() -> i64 {
    unsafe {
        if CAPTURE_DIR.is_empty() {
            CAPTURE_DIR.extend_from_slice(b"SDC/slu64/captures\0");
        }
        CAPTURE_DIR.as_ptr() as i64
    }
}

pub fn capture_dir_set(path: &str) {
    let mut v = path.trim_end_matches('/').as_bytes().to_vec();
    v.push(0);
    unsafe { CAPTURE_DIR = v; }
}

/// Framebuffer courant → RGBA8 row-major top-down (format attendu par
/// png_encode). Lecture volatile directe du framebuffer réel (ctx.fb) —
/// capture la frame telle qu'affichée à l'écran à cet instant.
fn capture_rgba(ctx: &ExecCtx) -> alloc::vec::Vec<u8> {
    let w = ctx.width.max(0) as usize;
    let h = ctx.height.max(0) as usize;
    let stride = ctx.stride.max(0) as usize;
    let mut out = alloc::vec::Vec::with_capacity(w * h * 4);
    unsafe {
        for y in 0..h {
            let row_ptr = ctx.fb.add(y * stride);
            for x in 0..w {
                let px = row_ptr.add(x).read_volatile();
                out.push(((px >> 16) & 0xFF) as u8); // R
                out.push(((px >> 8) & 0xFF) as u8);  // G
                out.push((px & 0xFF) as u8);          // B
                out.push(((px >> 24) & 0xFF) as u8); // A
            }
        }
    }
    out
}

/// Framebuffer courant → BGR24 bottom-up, lignes paddées à 4 octets (format
/// DIB/BI_RGB attendu par avi_encode).
fn capture_bgr_bottomup(ctx: &ExecCtx) -> alloc::vec::Vec<u8> {
    let w = ctx.width.max(0) as usize;
    let h = ctx.height.max(0) as usize;
    let stride = ctx.stride.max(0) as usize;
    let (padded_row, frame_size) = crate::media_encode::avi_frame_geometry(w as u32, h as u32);
    let mut out = alloc::vec![0u8; frame_size];
    unsafe {
        for y in 0..h {
            let row_ptr = ctx.fb.add(y * stride);
            let dest_start = (h - 1 - y) * padded_row;
            for x in 0..w {
                let px = row_ptr.add(x).read_volatile();
                let o = dest_start + x * 3;
                out[o]     = (px & 0xFF) as u8;          // B
                out[o + 1] = ((px >> 8) & 0xFF) as u8;   // G
                out[o + 2] = ((px >> 16) & 0xFF) as u8;  // R
            }
        }
    }
    out
}

/// Nombre de modes GOP disponibles (lecture seule, aucune mutation du framebuffer
/// — sûr à appeler n'importe quand, contrairement à un changement de mode réel qui
/// doit rester piloté par kernel_runtime.rs, seul propriétaire du backbuffer/de la
/// synchro largeur-hauteur-stride). Reconstruit un accès GOP frais à chaque appel
/// via UEFI_ST_PTR/UEFI_IMG_HANDLE, même mécanisme que srfs_uefi_read ci-dessus.
unsafe fn gop_mode_count(st_raw: *mut core::ffi::c_void) -> u32 {
    use uefi::table::{Boot, SystemTable};
    use uefi::proto::console::gop::GraphicsOutput;
    use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};
    let st: SystemTable<Boot> = match SystemTable::from_ptr(st_raw) { Some(s) => s, None => return 0 };
    let img = match uefi::Handle::from_ptr(UEFI_IMG_HANDLE as *mut core::ffi::c_void) { Some(h) => h, None => return 0 };
    let handles = match st.boot_services().find_handles::<GraphicsOutput>() { Ok(h) => h, Err(_) => return 0 };
    let h0 = match handles.first() { Some(h) => *h, None => return 0 };
    let gop = match st.boot_services().open_protocol::<GraphicsOutput>(
        OpenProtocolParams { handle: h0, agent: img, controller: None },
        OpenProtocolAttributes::GetProtocol,
    ) { Ok(g) => g, Err(_) => return 0 };
    gop.modes(st.boot_services()).count() as u32
}

/// (largeur, hauteur) du mode GOP d'index `idx` — mêmes garanties/mécanisme que
/// gop_mode_count. `None` si l'index est hors limites ou le GOP indisponible.
unsafe fn gop_mode_wh(st_raw: *mut core::ffi::c_void, idx: u32) -> Option<(u32, u32)> {
    use uefi::table::{Boot, SystemTable};
    use uefi::proto::console::gop::GraphicsOutput;
    use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};
    let st: SystemTable<Boot> = SystemTable::from_ptr(st_raw)?;
    let img = uefi::Handle::from_ptr(UEFI_IMG_HANDLE as *mut core::ffi::c_void)?;
    let handles = st.boot_services().find_handles::<GraphicsOutput>().ok()?;
    let h0 = *handles.first()?;
    let gop = st.boot_services().open_protocol::<GraphicsOutput>(
        OpenProtocolParams { handle: h0, agent: img, controller: None },
        OpenProtocolAttributes::GetProtocol,
    ).ok()?;
    let mode = gop.modes(st.boot_services()).nth(idx as usize)?;
    let (w, h) = mode.info().resolution();
    Some((w as u32, h as u32))
}

/// Énumère RÉELLEMENT le contenu d'un dossier de la partition ESP hôte (SDC:)
/// via SimpleFileSystem — contrairement à SRFS_CACHE (qui ne reflète que les
/// fichiers déjà lus en mémoire cette session), ceci lit le VRAI système de
/// fichiers, comme `srfs_uefi_read` mais sur un FileType::Dir plutôt qu'un
/// FileType::Regular. `rel_path` est au format DISK_BROWSE_PATH ("SDC:/apps/"
/// par ex., toujours préfixé "SDC:" et terminé par '/'). Retourne None si le
/// volume/dossier est introuvable (pas fatal : l'appelant retombe sur le cache
/// seul — voir disk_cache_dir_rebuild). Sous-dossiers marqués d'un '/' final,
/// même convention que disk_cache_dir_rebuild pour que isFolderEntry (Mara,
/// StrCharAt sur le dernier octet) fonctionne pareil pour les deux sources.
unsafe fn srfs_uefi_list_dir(st_raw: *mut core::ffi::c_void, rel_path: &str)
    -> Option<alloc::vec::Vec<alloc::string::String>>
{
    use uefi::table::{Boot, SystemTable};
    use uefi::proto::media::{
        file::{File, FileAttribute, FileMode, FileType},
        fs::SimpleFileSystem,
    };
    use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

    let after = rel_path.trim_start_matches("SDC:").trim_matches(|c: char| c == '/' || c == '\\');
    let uefi_rel: alloc::string::String = if after.is_empty() {
        alloc::string::String::from("SDC/slu64")
    } else {
        alloc::format!("SDC/slu64/{}", after)
    };

    let mut st: SystemTable<Boot> = SystemTable::from_ptr(st_raw)?;
    let mut ucs2: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(uefi_rel.len() + 2);
    ucs2.push(b'\\' as u16);
    let mut last_sep = true;
    for b in uefi_rel.bytes() {
        if b == b'\\' || b == b'/' {
            if !last_sep { ucs2.push(b'\\' as u16); }
            last_sep = true;
        } else {
            ucs2.push(b as u16);
            last_sep = false;
        }
    }
    ucs2.push(0u16);
    let uefi_path = uefi::CStr16::from_u16_with_nul(&ucs2).ok()?;
    let img = uefi::Handle::from_ptr(UEFI_IMG_HANDLE as *mut core::ffi::c_void)?;
    let handles = st.boot_services().find_handles::<SimpleFileSystem>().ok()?;
    for &fs_h in handles.iter() {
        let mut fs = match st.boot_services().open_protocol::<SimpleFileSystem>(
            OpenProtocolParams { handle: fs_h, agent: img, controller: None },
            OpenProtocolAttributes::GetProtocol,
        ) { Ok(f) => f, Err(_) => continue };
        let mut root = match fs.open_volume() { Ok(r) => r, Err(_) => continue };
        let fh = match root.open(uefi_path, FileMode::Read, FileAttribute::empty()) {
            Ok(f) => f, Err(_) => continue };
        let mut dir = match fh.into_type() {
            Ok(FileType::Dir(d)) => d, _ => continue };
        let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
        loop {
            match dir.read_entry_boxed() {
                Ok(Some(info)) => {
                    let name = alloc::string::String::from_utf16_lossy(info.file_name().to_u16_slice());
                    if name == "." || name == ".." { continue; }
                    if info.is_directory() {
                        names.push(alloc::format!("{}/", name));
                    } else {
                        names.push(name);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        return Some(names);
    }
    None
}

// ── Horloge système (UEFI RuntimeServices::get_time) ──────────────────────────
// Utilisée par ShiLooker (TemplateView.mara) pour l'heure/date réelles affichées
// dans la barre système — contrairement à SRFS_CACHE ceci n'est PAS un cache :
// `ClockRefresh` relit l'horloge matérielle à chaque appel (bon marché, appelé
// au plus une fois par frame). GetTime est valide à tout moment (avant/après
// ExitBootServices), donc aucune restriction de phase supplémentaire ici.
static mut CLOCK_TIME_BUF: [u8; 8]  = [0u8; 8];   // "HH:MM\0"
static mut CLOCK_DATE_BUF: [u8; 32] = [0u8; 32];  // "Ddd, DD Month YYYY\0"

const WEEKDAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTH_NAMES: [&str; 12] = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
];

/// Jour de la semaine (0=dimanche) via l'algorithme de Sakamoto — le `Time`
/// UEFI ne fournit que year/month/day, pas le jour de semaine.
fn weekday_index(year: u16, month: u8, day: u8) -> usize {
    const T: [i32; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let mut y = year as i32;
    let m = month.clamp(1, 12) as usize;
    if month < 3 { y -= 1; }
    (((y + y / 4 - y / 100 + y / 400 + T[m - 1] + day as i32) % 7 + 7) % 7) as usize
}

/// Relit l'horloge UEFI et reformate CLOCK_TIME_BUF/CLOCK_DATE_BUF. Retourne
/// false (buffers inchangés) si le SystemTable n'est pas encore initialisé ou
/// si GetTime échoue. Appelé par `DrvAPIInterCon***ClockRefresh***`.
pub fn clock_refresh() -> bool {
    use uefi::table::{Boot, SystemTable};
    let st_raw = unsafe { UEFI_ST_PTR };
    if st_raw.is_null() { return false; }
    let st: SystemTable<Boot> = match unsafe { SystemTable::from_ptr(st_raw) } {
        Some(s) => s,
        None => return false,
    };
    let time = match st.runtime_services().get_time() {
        Ok(t) => t,
        Err(_) => return false,
    };

    let time_s = alloc::format!("{:02}:{:02}", time.hour(), time.minute());
    let wd = WEEKDAY_NAMES[weekday_index(time.year(), time.month(), time.day())];
    let mo = MONTH_NAMES[(time.month().clamp(1, 12) - 1) as usize];
    let date_s = alloc::format!("{}, {:02} {} {}", wd, time.day(), mo, time.year());

    unsafe {
        let tb = time_s.as_bytes();
        let n = tb.len().min(CLOCK_TIME_BUF.len() - 1);
        CLOCK_TIME_BUF[..n].copy_from_slice(&tb[..n]);
        CLOCK_TIME_BUF[n] = 0;

        let db = date_s.as_bytes();
        let n2 = db.len().min(CLOCK_DATE_BUF.len() - 1);
        CLOCK_DATE_BUF[..n2].copy_from_slice(&db[..n2]);
        CLOCK_DATE_BUF[n2] = 0;
    }
    true
}

/// Pointeur nul-terminé vers "HH:MM" (dernier `ClockRefresh` réussi).
pub fn clock_time_str_ptr() -> i64 {
    unsafe { CLOCK_TIME_BUF.as_ptr() as i64 }
}

/// Pointeur nul-terminé vers "Ddd, DD Month YYYY" (dernier `ClockRefresh` réussi).
pub fn clock_date_str_ptr() -> i64 {
    unsafe { CLOCK_DATE_BUF.as_ptr() as i64 }
}

/// Enregistre un fichier SRFS (path = "SDC:\\...") depuis slul_loader.
/// Dédoublonne par clé, puis slot libre, puis éviction LRU — en protégeant les
/// polices .ttf : leur pointeur est détenu à travers les frames (font_ptr,
/// TtfParser::Load), les évincer casserait tout le rendu texte.
pub fn srfs_register_file(path: String, data: Vec<u8>) {
    unsafe {
        SRFS_TICK = SRFS_TICK.wrapping_add(1);
        for (i, slot) in SRFS_CACHE.iter_mut().enumerate() {
            if let Some((ref k, _)) = slot {
                if keys_match(k.as_str(), path.as_str()) {
                    SRFS_AGE[i] = SRFS_TICK;
                    *slot = Some((path, data));
                    return;
                }
            }
        }
        for (i, slot) in SRFS_CACHE.iter_mut().enumerate() {
            if slot.is_none() {
                SRFS_AGE[i] = SRFS_TICK;
                *slot = Some((path, data));
                return;
            }
        }
        let mut victim: Option<usize> = None;
        for (i, slot) in SRFS_CACHE.iter().enumerate() {
            if let Some((ref k, _)) = slot {
                if k.ends_with(".ttf") || k.ends_with(".TTF") { continue; }
                if victim.map_or(true, |v| SRFS_AGE[i] < SRFS_AGE[v]) { victim = Some(i); }
            }
        }
        if let Some(v) = victim {
            SRFS_AGE[v] = SRFS_TICK;
            SRFS_CACHE[v] = Some((path, data));
        }
    }
}

/// Retourne le pointeur + taille de la police TTF si chargée via SRFS.
pub fn srfs_font_ptr() -> (*const u8, usize) {
    unsafe {
        // Cherche SPÉCIFIQUEMENT le .ttf (le 1er slot pouvait être une Maraset.yaml ou un
        // PNG → TtfParser::Load parsait du non-TTF, aucun glyphe). Repli : 1er slot.
        for slot in SRFS_CACHE.iter() {
            if let Some((ref k, ref v)) = slot {
                if k.ends_with(".ttf") || k.ends_with(".TTF") { return (v.as_ptr(), v.len()); }
            }
        }
        for slot in SRFS_CACHE.iter() {
            if let Some((_, ref v)) = slot { return (v.as_ptr(), v.len()); }
        }
    }
    (core::ptr::null(), 0)
}

fn srfs_find(path_ptr: i64) -> Option<&'static [u8]> {
    if path_ptr == 0 { return None; }
    let p = path_ptr as *const u8;
    let mut len = 0usize;
    unsafe { while *p.add(len) != 0 { len += 1; } }
    let req = unsafe { core::str::from_utf8(core::slice::from_raw_parts(p, len)).ok()? };
    unsafe {
        for slot in SRFS_CACHE.iter() {
            if let Some((ref key, ref data)) = slot {
                // Comparer de façon case-insensitive (SDC: est Windows-style)
                if keys_match(req, key.as_str()) {
                    return Some(data.as_slice());
                }
            }
        }
    }
    None
}

fn keys_match(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    a.bytes().zip(b.bytes()).all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

// ── Décodeur PNG minimal (signature + IHDR/IDAT/IEND + filtres) ──────────────

fn paeth_predictor(a: u8, b: u8, c: u8) -> u8 {
    let (ai, bi, ci) = (a as i32, b as i32, c as i32);
    let p = ai + bi - ci;
    let (pa, pb, pc) = ((p - ai).abs(), (p - bi).abs(), (p - ci).abs());
    if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c }
}

/// Décode un PNG 8-bit RGB ou RGBA en pixels RGBA bruts.
/// Retourne (width, height, rgba_bytes) ou None si le format n'est pas supporté.
fn png_decode_rgba(data: &[u8]) -> Option<(u32, u32, alloc::vec::Vec<u8>)> {
    if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" { return None; }
    let mut pos = 8usize;
    let mut width = 0u32; let mut height = 0u32; let mut color_type = 0u8;
    let mut idat: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    while pos + 8 <= data.len() {
        let clen = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        let typ  = &data[pos+4..pos+8];
        let end  = pos + 8 + clen;
        if end > data.len() { break; }
        let cd = &data[pos+8..end];
        match typ {
            b"IHDR" if cd.len() >= 13 => {
                width       = u32::from_be_bytes([cd[0], cd[1], cd[2], cd[3]]);
                height      = u32::from_be_bytes([cd[4], cd[5], cd[6], cd[7]]);
                let bd      = cd[8]; color_type = cd[9];
                if bd != 8 || (color_type != 2 && color_type != 6) { return None; }
            }
            b"IDAT" => idat.extend_from_slice(cd),
            b"IEND" => break,
            _ => {}
        }
        pos = end + 4; // sauter CRC
    }
    if width == 0 || height == 0 || idat.is_empty() { return None; }
    let bpp  = if color_type == 6 { 4usize } else { 3 };
    let srow = width as usize * bpp;
    let exp  = (srow + 1) * height as usize;
    // PNG IDAT = zlib : 2-byte header + raw DEFLATE + 4-byte Adler32
    if idat.len() < 6 { return None; }
    let deflate = &idat[2..idat.len().saturating_sub(4)];
    let mut dec = alloc::vec![0u8; exp.max(1)];
    let mut dzox = miniz_oxide::inflate::core::DecompressorOxide::new();
    let (st, _, out_n) = miniz_oxide::inflate::core::decompress(
        &mut dzox, deflate, &mut dec, 0,
        miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    if st != miniz_oxide::inflate::TINFLStatus::Done || out_n < exp { return None; }
    dec.truncate(out_n);
    let mut out  = alloc::vec![0u8; width as usize * height as usize * 4];
    let mut prev = alloc::vec![0u8; srow]; // ligne précédente reconstruite
    for row in 0..height as usize {
        let rs  = row * (srow + 1);
        let flt = dec[rs];
        let src = &dec[rs + 1..rs + 1 + srow];
        let mut recon = alloc::vec![0u8; srow];
        for i in 0..srow {
            let fx = src[i];
            let a  = if i >= bpp { recon[i - bpp] } else { 0 };
            let b  = prev[i];
            let c  = if i >= bpp { prev[i - bpp] } else { 0 };
            recon[i] = match flt {
                0 => fx,
                1 => fx.wrapping_add(a),
                2 => fx.wrapping_add(b),
                3 => fx.wrapping_add(((a as u16 + b as u16) / 2) as u8),
                4 => fx.wrapping_add(paeth_predictor(a, b, c)),
                _ => fx,
            };
        }
        let o = row * width as usize * 4;
        for px in 0..width as usize {
            let s = px * bpp;
            out[o + px*4]     = recon[s];
            out[o + px*4 + 1] = recon[s + 1];
            out[o + px*4 + 2] = recon[s + 2];
            out[o + px*4 + 3] = if bpp == 4 { recon[s + 3] } else { 255 };
        }
        prev.copy_from_slice(&recon);
    }
    Some((width, height, out))
}

pub fn register_gpu_ovc(ovc: Vec<u8>) {
    unsafe { GPU_OVC = Some(ovc); }
}

pub fn register_font_ovc(ttf_parser: Vec<u8>, glyph_rasterizer: Vec<u8>, woff_reader: Vec<u8>) {
    unsafe {
        FONT_TTF_OVC  = Some(ttf_parser);
        FONT_RAST_OVC = Some(glyph_rasterizer);
        FONT_WOFF_OVC = Some(woff_reader);
    }
}

pub fn font_ovc_ready() -> bool {
    unsafe { FONT_TTF_OVC.is_some() && FONT_RAST_OVC.is_some() }
}

pub fn gpu_ovc() -> Option<&'static [u8]> {
    unsafe { GPU_OVC.as_deref() }
}

pub fn gpu_ready() -> bool {
    unsafe { GPU_OVC.is_some() }
}

// ── Police bitmap 8×16 (CP437 ASCII 0x00–0x7F) ───────────────────────────────
// Retournée par DrvManSpec___GetBitmapFont8x16___().
// Format : font[char_ascii * 16 + row], row ∈ 0..15, bit7 = pixel gauche.

#[rustfmt::skip]
static FONT8X8: &[[u8;8]; 128] = &[
[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8], // 0x00-0x07
[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8], // 0x08-0x0F
[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8], // 0x10-0x17
[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8], // 0x18-0x1F
// 0x20-0x7F
[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0x18,0x3C,0x3C,0x18,0x18,0x00,0x18,0x00],
[0x6C,0x6C,0x6C,0x00,0x00,0x00,0x00,0x00],[0x6C,0x6C,0xFE,0x6C,0xFE,0x6C,0x6C,0x00],
[0x18,0x7E,0xC0,0x7C,0x06,0x7E,0x18,0x00],[0x00,0xC6,0xCC,0x18,0x30,0x66,0xC6,0x00],
[0x38,0x6C,0x38,0x76,0xDC,0xCC,0x76,0x00],[0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00],
[0x0E,0x1C,0x30,0x30,0x30,0x1C,0x0E,0x00],[0x70,0x38,0x0C,0x0C,0x0C,0x38,0x70,0x00],
[0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00],[0x00,0x30,0x30,0xFC,0x30,0x30,0x00,0x00],
[0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30],[0x00,0x00,0x00,0xFC,0x00,0x00,0x00,0x00],
[0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00],[0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0x00],
[0x7C,0xC6,0xCE,0xDE,0xF6,0xE6,0x7C,0x00],[0x30,0x70,0x30,0x30,0x30,0x30,0xFC,0x00],
[0x78,0xCC,0x0C,0x38,0x60,0xCC,0xFC,0x00],[0x78,0xCC,0x0C,0x38,0x0C,0xCC,0x78,0x00],
[0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x1E,0x00],[0xFC,0xC0,0xF8,0x0C,0x0C,0xCC,0x78,0x00],
[0x38,0x60,0xC0,0xF8,0xCC,0xCC,0x78,0x00],[0xFC,0xCC,0x0C,0x18,0x30,0x30,0x30,0x00],
[0x78,0xCC,0xCC,0x78,0xCC,0xCC,0x78,0x00],[0x78,0xCC,0xCC,0x7C,0x0C,0x18,0x70,0x00],
[0x00,0x18,0x18,0x00,0x18,0x18,0x00,0x00],[0x00,0x18,0x18,0x00,0x18,0x18,0x30,0x00],
[0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0x00],[0x00,0x00,0xFC,0x00,0x00,0xFC,0x00,0x00],
[0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0x00],[0x78,0xCC,0x0C,0x18,0x18,0x00,0x18,0x00],
[0x7C,0xC6,0xDE,0xDE,0xDE,0xC0,0x78,0x00],[0x30,0x78,0xCC,0xCC,0xFC,0xCC,0xCC,0x00],
[0xFC,0x66,0x66,0x7C,0x66,0x66,0xFC,0x00],[0x3C,0x66,0xC0,0xC0,0xC0,0x66,0x3C,0x00],
[0xF8,0x6C,0x66,0x66,0x66,0x6C,0xF8,0x00],[0xFE,0x62,0x68,0x78,0x68,0x62,0xFE,0x00],
[0xFE,0x62,0x68,0x78,0x68,0x60,0xF0,0x00],[0x3C,0x66,0xC0,0xC0,0xCE,0x66,0x3E,0x00],
[0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0x00],[0x3C,0x18,0x18,0x18,0x18,0x18,0x3C,0x00],
[0x1E,0x0C,0x0C,0x0C,0xCC,0xCC,0x78,0x00],[0xE6,0x66,0x6C,0x78,0x6C,0x66,0xE6,0x00],
[0xF0,0x60,0x60,0x60,0x62,0x66,0xFE,0x00],[0xC6,0xEE,0xFE,0xFE,0xD6,0xC6,0xC6,0x00],
[0xC6,0xE6,0xF6,0xDE,0xCE,0xC6,0xC6,0x00],[0x38,0x6C,0xC6,0xC6,0xC6,0x6C,0x38,0x00],
[0xFC,0x66,0x66,0x7C,0x60,0x60,0xF0,0x00],[0x78,0xCC,0xCC,0xCC,0xDC,0x78,0x1C,0x00],
[0xFC,0x66,0x66,0x7C,0x6C,0x66,0xE6,0x00],[0x78,0xCC,0xE0,0x70,0x1C,0xCC,0x78,0x00],
[0xFC,0xB4,0x30,0x30,0x30,0x30,0x78,0x00],[0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xFC,0x00],
[0xCC,0xCC,0xCC,0xCC,0xCC,0x78,0x30,0x00],[0xC6,0xC6,0xC6,0xD6,0xFE,0xEE,0xC6,0x00],
[0xC6,0x6C,0x38,0x38,0x38,0x6C,0xC6,0x00],[0xCC,0xCC,0xCC,0x78,0x30,0x30,0x78,0x00],
[0xFE,0xC6,0x8C,0x18,0x32,0x66,0xFE,0x00],[0x3C,0x30,0x30,0x30,0x30,0x30,0x3C,0x00],
[0xC0,0x60,0x30,0x18,0x0C,0x06,0x02,0x00],[0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00],
[0x18,0x3C,0x66,0xC3,0x00,0x00,0x00,0x00],[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF],
[0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00],[0x00,0x00,0x78,0x0C,0x7C,0xCC,0x76,0x00],
[0xE0,0x60,0x60,0x7C,0x66,0x66,0xDC,0x00],[0x00,0x00,0x78,0xCC,0xC0,0xCC,0x78,0x00],
[0x1C,0x0C,0x0C,0x7C,0xCC,0xCC,0x76,0x00],[0x00,0x00,0x78,0xCC,0xFC,0xC0,0x78,0x00],
[0x38,0x6C,0x60,0xF0,0x60,0x60,0xF0,0x00],[0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0xF8],
[0xE0,0x60,0x6C,0x76,0x66,0x66,0xE6,0x00],[0x30,0x00,0x70,0x30,0x30,0x30,0x78,0x00],
[0x0C,0x00,0x0C,0x0C,0x0C,0xCC,0xCC,0x78],[0xE0,0x60,0x66,0x6C,0x78,0x6C,0xE6,0x00],
[0x70,0x30,0x30,0x30,0x30,0x30,0x78,0x00],[0x00,0x00,0xCC,0xFE,0xFE,0xD6,0xC6,0x00],
[0x00,0x00,0xF8,0xCC,0xCC,0xCC,0xCC,0x00],[0x00,0x00,0x78,0xCC,0xCC,0xCC,0x78,0x00],
[0x00,0x00,0xDC,0x66,0x66,0x7C,0x60,0xF0],[0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0x1E],
[0x00,0x00,0xDC,0x76,0x66,0x60,0xF0,0x00],[0x00,0x00,0x7C,0xC0,0x78,0x0C,0xF8,0x00],
[0x10,0x30,0x7C,0x30,0x30,0x34,0x18,0x00],[0x00,0x00,0xCC,0xCC,0xCC,0xCC,0x76,0x00],
[0x00,0x00,0xCC,0xCC,0xCC,0x78,0x30,0x00],[0x00,0x00,0xC6,0xD6,0xFE,0xFE,0x6C,0x00],
[0x00,0x00,0xC6,0x6C,0x38,0x6C,0xC6,0x00],[0x00,0x00,0xCC,0xCC,0xCC,0x7C,0x0C,0xF8],
[0x00,0x00,0xFC,0x98,0x30,0x64,0xFC,0x00],[0x1C,0x30,0x30,0xE0,0x30,0x30,0x1C,0x00],
[0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x00],[0xE0,0x30,0x30,0x1C,0x30,0x30,0xE0,0x00],
[0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00],[0x00,0x10,0x38,0x6C,0xC6,0xC6,0xFE,0x00],
];

const fn build_font8x16() -> [u8; 128 * 16] {
    let mut f = [0u8; 128 * 16];
    let mut c = 0usize;
    while c < 128 {
        let g = FONT8X8[c];
        let mut r = 0usize;
        while r < 8 { f[c * 16 + r + 4] = g[r]; r += 1; }
        c += 1;
    }
    f
}
static FONT8X16: [u8; 128 * 16] = build_font8x16();

// ── Globals partagés SluFontConf / GlyphRasterizer ───────────────────────────
static mut FONT_UNITS_PER_EM: u32 = 1000;
static mut RAST_W: u32 = 0;
static mut RAST_H: u32 = 0;
// Offsets du dernier bitmap rastérisé, relatifs au point de plume sur la BASELINE
// (xoff = left side bearing, yoff = distance baseline → haut du bitmap, négatif).
static mut RAST_XOFF: i32 = 0;
static mut RAST_YOFF: i32 = 0;

// ── Primitives natives stb_truetype (stb_font.obj, wrapper de stb_truetype.h) ──
// Exposées EXACTEMENT sous les noms que SluFontConf.slul appelle via <stb_*___> ;
// le dispatch FFI (plus bas) relaie ces builtins vers ces symboles extern "C".
extern "C" {
    fn stb_font_init(data: *const u8) -> i32;
    fn stb_glyph_index(codepoint: i32) -> i32;
    fn stb_set_current_glyph(gi: i32);
    fn stb_get_current_glyph() -> i32;
    fn stb_scale_k(pixel_size: i32) -> i32;
    fn stb_rasterize(glyph_idx: i32, scale_k: i32) -> *const u8;
    fn stb_bmp_w() -> i32;
    fn stb_bmp_h() -> i32;
    fn stb_bmp_yoff() -> i32;
    fn stb_bmp_xoff() -> i32;
    fn stb_advance(glyph_idx: i32, scale_k: i32) -> i32;
    fn stb_ascent(scale_k: i32) -> i32;
    fn stb_kern(g1: i32, g2: i32, scale_k: i32) -> i32;
}

// Cache de parse_string_consts par (OVC text pointer + taille en octets).
// La taille discrimine les modules même quand leurs 32 premiers octets sont identiques
// (tous les OVC marai partagent le même header "# Vyft OVC v1.0 …").
// Exemple : APrevent.ovc CryptoAssetSupport ≠ taille TemplateView.ovc.
// Box::into_raw → fuite permanente justifiée (UEFI boot, ~8 modules max).
static mut CONSTS_CACHE: [(usize, usize, *const BTreeMap<String, i64>); 8] =
    [(0, 0, core::ptr::null()); 8];

// ── Arène statique pour MemAlloc OVC (bitmaps glyphes, flagBuf, etc.) ────────
// Évite d'utiliser le heap UEFI (limité, fragmentation). Reset entre glyphes.
static mut OVC_ARENA: [u8; 512 * 1024] = [0u8; 512 * 1024];  // 512KB
static mut OVC_ARENA_POS: usize = 0;

fn ovc_arena_alloc(size: usize, align: usize) -> *mut u8 {
    if size == 0 { return core::ptr::null_mut(); }
    unsafe {
        let pos = (OVC_ARENA_POS + align - 1) & !(align - 1);
        if pos + size > OVC_ARENA.len() { return core::ptr::null_mut(); }
        OVC_ARENA_POS = pos + size;
        OVC_ARENA[pos] = 0;  // mark first byte (bulk zeroing done lazily)
        core::ptr::write_bytes(OVC_ARENA[pos..pos+size].as_mut_ptr(), 0, size);
        OVC_ARENA[pos..].as_mut_ptr()
    }
}

pub fn ovc_arena_reset() { unsafe { OVC_ARENA_POS = 0; } }

// Cache parse_blocks par (ovc_ptr, func_start_ptr) — évite de re-allouer
// des centaines de BTreeMap<String,Vec<String>> par appel OVC.
static mut BLOCKS_CACHE: [(usize, usize, *const BTreeMap<String, Vec<String>>); 32] =
    [(0, 0, core::ptr::null()); 32];

// ── Registres OVC sans String (hash FNV-1a 64 bits) ─────────────────────────
// Remplace BTreeMap<String,i64> pour regs : zéro allocation String.
// Le Vec grossit en place — une seule alloc heap pour toute la durée de vie.
type Regs = Vec<(u64, i64)>;

#[inline(always)]
fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}
fn regs_get(r: &Regs, name: &str) -> i64 {
    let k = fnv64(name);
    r.iter().rev().find(|&&(h, _)| h == k).map(|&(_, v)| v).unwrap_or(0)
}
fn regs_set(r: &mut Regs, name: &str, val: i64) {
    let k = fnv64(name);
    if let Some(e) = r.iter_mut().rev().find(|(h, _)| *h == k) { e.1 = val; }
    else { r.push((k, val)); }
}

// ── TtfParser state (DrvManSpec***TtfGetData/Set + TtfScratchGet/Set) ─────────
// Partagé entre Load / GetGlyphId / GetGlyfOffset car ces appels
// passent par le dispatcher global, pas par les globals OVC.
static mut TTF_DATA_PTR: i64 = 0;
static mut TTF_SCRATCH:  [i64; 200] = [0i64; 200];
static mut WOFF_SCRATCH: [i64; 256] = [0i64; 256];

// ── Demande de résolution en attente (DrvManSpec___SetResolution___) ─────────
// SetResolution N'APPLIQUE PAS le changement directement : seul kernel_runtime.rs
// (render_from_marep) possède le backbuffer/gop_ptr/w/h/stride réels et peut donc
// resynchroniser ces valeurs APRÈS le set_mode — un changement de mode appliqué
// depuis ici sans que la boucle de rendu ne s'en aperçoive laisserait le kernel
// écrire dans un framebuffer redimensionné avec l'ancienne géométrie (corruption
// d'affichage). Cette file d'attente à 1 élément est le point de rendez-vous.
static mut GOP_RESIZE_REQUEST: (i64, i64) = (0, 0);
static mut GOP_RESIZE_PENDING: bool = false;

/// Lu par kernel_runtime.rs à chaque frame — consomme (et efface) la demande de
/// résolution en attente posée par DrvManSpec___SetResolution___, `None` sinon.
pub fn gop_resize_take_pending() -> Option<(i64, i64)> {
    unsafe {
        if GOP_RESIZE_PENDING {
            GOP_RESIZE_PENDING = false;
            Some(GOP_RESIZE_REQUEST)
        } else {
            None
        }
    }
}

// ── Résultat du dernier HwBackdoorCall (DrvManSpec) ───────────────────────────
// [eax, ebx, ecx, edx] après l'instruction IN — voir hw_io_call() et l'arm
// "DrvManSpec___HwBackdoorCall___" plus bas. Purement mécanique (aucune
// connaissance de protocole ici), lu via HwBackdoorResultGet(0..3).
static mut HW_BACKDOOR_RESULT: [i64; 4] = [0i64; 4];

/// Échange brut de 4 registres 32 bits via une instruction x86 `IN` — port =
/// bits bas de `edx_in`, magic/commande/paramètre = eax_in/ecx_in/ebx_in (aucune
/// sémantique imposée ici, c'est au code Mara appelant de choisir ce que ces
/// registres représentent pour le protocole matériel visé).
///
/// `rbx` est réservé en interne par LLVM (pointeur de table globale en code
/// position-indépendant, y compris sur x86_64) — impossible de le nommer
/// directement dans `asm!` ("rbx is used internally by LLVM"). Contournement
/// standard : sauver/restaurer rbx manuellement via push/pop autour de
/// l'instruction, en passant par un registre banal pour ebx_in/ebx_out.
fn hw_io_call(eax_in: u32, ebx_in: u32, ecx_in: u32, edx_in: u32) -> (u32, u32, u32, u32) {
    let eax_out: u32;
    let ebx_out: u32;
    let ecx_out: u32;
    let edx_out: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov ebx, {ebx_in:e}",
            "in eax, dx",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            ebx_in  = in(reg) ebx_in,
            ebx_out = out(reg) ebx_out,
            inout("eax") eax_in => eax_out,
            inout("ecx") ecx_in => ecx_out,
            inout("edx") edx_in => edx_out,
            options(preserves_flags)
        );
    }
    (eax_out, ebx_out, ecx_out, edx_out)
}

// ── Registres généraux (DrvAPIInterCon***ScrollGet/Set***) ────────────────────
// Slots persistants indexés, même idiome que TTF_SCRATCH/WOFF_SCRATCH — sert de
// petit état inter-frames pour les vues marep (ex: TemplateView.mara), qui ne
// peuvent pas fiablement garder de state via des vars <ptr> de classe (voir
// LAPrevent.mara : "Seules les vars <string> persistent via class vars"). Usage
// typique : offsets de défilement vertical + état de glisser-déposer (ancre du
// pointeur au clic, région en cours de glissement) pour une liste donnée.
static mut SCROLL_SCRATCH: [i64; 64] = [0i64; 64];

// ── Menu contextuel (ShiLauncher, dock) ───────────────────────────────────────
// État minimal (ouvert/fermé, propriétaire, position, sous-menu déplié) — la liste
// d'items elle-même n'est PAS dupliquée ici : ContextMenu.mara la recalcule chaque
// frame depuis AppRegistryGetMenuItemCount/Label, comme le dock recalcule déjà sa
// liste d'apps depuis AppRegistryCount à chaque frame.
static mut MENU_OPEN: bool = false;
static mut MENU_OWNER_IDX: i32 = -1;
static mut MENU_X: i32 = 0;
static mut MENU_Y: i32 = 0;
static mut MENU_SUBMENU_IDX: i32 = -1;

// ── Menu contextuel (ShiLooker, couleur de dossier) — état SÉPARÉ du menu
// ci-dessus : ShiLauncher.marep (le dock) tourne en permanence en parallèle
// de n'importe quelle app et relit MENU_OPEN/MENU_OWNER_IDX à CHAQUE frame
// via ContextMenu.mara pour dessiner SON PROPRE menu — partager le même état
// entre le dock et FolderMenu.mara ferait que MENU_OWNER_IDX contiendrait
// tantôt un index d'app, tantôt un index de ligne de dossier, et les deux
// menus se dessineraient/interféreraient l'un avec l'autre au hasard des
// frames. D'où ce second jeu d'entiers, complètement indépendant.
static mut FOLDER_MENU_OPEN: bool = false;
static mut FOLDER_MENU_ROW: i32 = -1;

// ── Menu global in-app ShiLauncher — état SÉPARÉ du dock
// Affiche TOUS les apps pinned avec leurs losanges et dock_menu_items.
// Utilise son propre état pour ne pas interférer avec ContextMenu.mara.
static mut GLOBAL_MENU_OPEN: bool = false;
static mut GLOBAL_MENU_X: i32 = 0;
static mut GLOBAL_MENU_Y: i32 = 0;
// Sous-menu flottant (ex: "System power" > Reboot/Sleep screen/Shutdown/Standby,
// Figma 900:88) — index de l'app pinned propriétaire (position dans la liste
// AppRegistryGetPinnedIndex, PAS l'index registre brut) + index de l'item dans
// les dock_menu_items de CETTE app, et ancre écran où dessiner la carte flottante.
// -1/-1 = aucun sous-menu ouvert. État séparé de MENU_SUBMENU_IDX (ContextMenu,
// une seule app) car GlobalMenu itère plusieurs apps simultanément.
static mut GLOBAL_MENU_SUBMENU_APP_IDX: i32 = -1;
static mut GLOBAL_MENU_SUBMENU_ITEM_IDX: i32 = -1;
static mut GLOBAL_MENU_SUBMENU_X: i32 = 0;
static mut GLOBAL_MENU_SUBMENU_Y: i32 = 0;

// ── Mode "contexte" de GlobalMenu — remplace FolderMenu.mara/toute future
// carte contextuelle dédiée : un composant (fichier, dossier, disque monté,
// etc.) ouvre GlobalMenu avec SA PROPRE liste d'items ("Label1|Label2", même
// syntaxe `|` que dock_menu_items — voir app_registry.rs, mais SANS support
// de sous-menu ici : ces menus contextuels sont des listes plates) au lieu de
// la liste des apps épinglées. `ctx_id` est une donnée libre que l'appelant
// choisit et se réattribue lui-même au clic (ex: index de ligne dans
// DISK_DIR_LISTING) — le noyau ne l'interprète jamais, il le renvoie tel quel.
// Items déjà découpés et nul-terminés au moment de l'ouverture (Mara ne sait
// pas splitter une chaîne — voir README §4.11) ; vide = mode normal (apps
// épinglées, inchangé).
static mut GLOBAL_MENU_CTX_ITEMS: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
static mut GLOBAL_MENU_CTX_ID: i32 = -1;
// Retour de clic — même pattern que WindowManGetLaunchArg/LaunchArgGen : le
// label cliqué + une génération incrémentée à chaque nouveau clic, pour que
// l'appelant (ShiLooker...) ne traite un clic qu'UNE fois en le comparant à
// une valeur stockée en SCROLL_SCRATCH (voir README §2.8/§2.9).
static mut GLOBAL_MENU_CLICKED_LABEL: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
static mut GLOBAL_MENU_CLICKED_CTX_ID: i32 = -1;
static mut GLOBAL_MENU_CLICKED_GEN: i32 = 0;

// ── Sélecteur de dossier de capture (ShiCamera) — état COMPLÈTEMENT SÉPARÉ
// de FOLDER_MENU_* (qui est pour la couleur des dossiers, pas leur navigation)
// et de MENU_* (qui est pour le dock). Le picker a : propre bool ouvert/fermé,
// propres ancres X/Y, ET son propre curseur de navigation (CAPTURE_PICKER_PATH)
// — NE PAS réutiliser DISK_BROWSE_PATH, qui est le curseur persistant de
// l'onglet Disque (rightView==3). Le partager casserait la navigation du Disque
// dès que le picker naviguerait ailleurs pendant qu'il est ouvert.
static mut CAPTURE_PICKER_OPEN: bool = false;
static mut CAPTURE_PICKER_X: i32 = 0;
static mut CAPTURE_PICKER_Y: i32 = 0;
static mut CAPTURE_PICKER_PATH: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
static mut FOLDER_MENU_X: i32 = 0;
static mut FOLDER_MENU_Y: i32 = 0;

// ── Disque virtuel SRFS (pour SRFSMan.slul) ───────────────────────────────────
// Superblock SRFS v2 minimal : magic 'SRF2', blockSize=32768, rootBlock=3.
// SRFSMan.slul vérifie ce magic puis monte SDC:\.
// Le contenu réel (fichiers) est servi par le cache SRFS (srfs_find).
static SRFS_DISK_IMAGE: [u8; 512] = {
    let mut b = [0u8; 512];
    // Magic 'SRF2' = 0x53524632 big-endian
    b[0] = 0x53; b[1] = 0x52; b[2] = 0x46; b[3] = 0x32;
    // Version 0x00020000 big-endian
    b[4] = 0x00; b[5] = 0x02; b[6] = 0x00; b[7] = 0x00;
    // Block size 32768 = 0x00008000 big-endian
    b[8]  = 0x00; b[9]  = 0x00; b[10] = 0x80; b[11] = 0x00;
    // Total blocks = 256
    b[12] = 0x00; b[13] = 0x00; b[14] = 0x01; b[15] = 0x00;
    // Free blocks = 250
    b[16] = 0x00; b[17] = 0x00; b[18] = 0x00; b[19] = 0xFA;
    // Reserved fields (28, 36, 44, 52, 60) → 1, 2, 3, 32, 4
    b[31] = 0x01; b[39] = 0x02; b[47] = 0x03;
    b[55] = 0x20; b[63] = 0x04;
    // Root block = 3 at offset 68
    b[71] = 0x03;
    // Flags = 7 at offset 112
    b[115] = 0x07;
    b
};

// ── Disque virtuel NTFS (pour NTFSMan.slul) ───────────────────────────────────
// Volume NTFS minimal mais spec-conforme : secteur de boot (BPB : 512 o/secteur,
// 8 secteurs/cluster → cluster 4096 o, $MFT au LCN 4, records de 1024 o),
// $MFT (record 0, $DATA non-résident décrivant son propre run [LCN4..6)),
// répertoire racine (record 5, $INDEX_ROOT avec une entrée "HELLO.TXT" → record 6)
// et un fichier de test (record 6, $DATA résident = "Bonjour NTFS!\n").
// usaCount=1 partout → NTFSMft.ApplyFixup n'a rien à corriger (pas besoin de
// simuler la substitution de fin de secteur pour cette image de test).
static NTFS_DISK_IMAGE: [u8; 24576] = {
    let mut b = [0u8; 24576];

    // ── Secteur de boot ──────────────────────────────────────────────────
    b[3] = 0x4E; b[4] = 0x54; b[5] = 0x46; b[6] = 0x53;  // OEM "NTFS"
    b[7] = 0x20; b[8] = 0x20; b[9] = 0x20; b[10] = 0x20; // "    "
    b[11] = 0x00; b[12] = 0x02;                          // bytesPerSector = 512
    b[13] = 0x08;                                        // sectorsPerCluster = 8 (cluster 4096)
    b[48] = 0x04;                                        // $MFT LCN = 4 (offset 48, 64-bit LE)
    b[64] = 0xF6;                                        // clustersPerMftRecord = -10 -> 1024 o
    b[510] = 0x55; b[511] = 0xAA;

    // MFT_BASE = LCN4 * 4096 = 16384. $MFT contigu sur 2 clusters (LCN4..6),
    // donc offset physique = MFT_BASE + recordId*1024 pour les records 0..7.
    const R0: usize = 16384;
    const R5: usize = 16384 + 5 * 1024;
    const R6: usize = 16384 + 6 * 1024;

    // ── Record 0 : $MFT (se décrit lui-même) ────────────────────────────
    b[R0]=0x46; b[R0+1]=0x49; b[R0+2]=0x4C; b[R0+3]=0x45;  // 'FILE'
    b[R0+4]=0x2A;                                           // usaOffset=42
    b[R0+6]=0x01;                                           // usaCount=1
    b[R0+16]=0x01;                                          // seq=1
    b[R0+18]=0x01;                                          // hardLink=1
    b[R0+20]=0x38;                                          // firstAttrOffset=56
    b[R0+22]=0x01;                                          // flags=1 (en cours d'utilisation)
    b[R0+24]=0x80;                                          // usedSize=128
    b[R0+28]=0x00; b[R0+29]=0x04;                           // allocSize=1024
    b[R0+40]=0x02;                                          // nextAttrId=2
    b[R0+42]=0x01;                                          // USA[0] (non utilisé, usaCount<=1)
    // $DATA non-résident à +56 (header 64 o + runlist 4 o = 68 o)
    b[R0+56]=0x80;                                          // type=$DATA
    b[R0+60]=0x44;                                          // length=68
    b[R0+64]=0x01;                                          // nonResident=1
    b[R0+80]=0x01;                                          // endVCN=1 (2 clusters : VCN0,1)
    b[R0+88]=0x40;                                          // runsOffset=64 (rel. attr)
    b[R0+96]=0x00; b[R0+97]=0x20;                           // allocatedSize=8192
    b[R0+104]=0x00; b[R0+105]=0x20;                         // realSize=8192
    b[R0+112]=0x00; b[R0+113]=0x20;                         // initializedSize=8192
    // runlist @ +120 : header 0x11 (1 o longueur, 1 o LCN), longueur=2, delta LCN=+4
    b[R0+120]=0x11; b[R0+121]=0x02; b[R0+122]=0x04; b[R0+123]=0x00;
    // marqueur de fin d'attributs @ +124
    b[R0+124]=0xFF; b[R0+125]=0xFF; b[R0+126]=0xFF; b[R0+127]=0xFF;

    // ── Record 5 : répertoire racine ─────────────────────────────────────
    b[R5]=0x46; b[R5+1]=0x49; b[R5+2]=0x4C; b[R5+3]=0x45;  // 'FILE'
    b[R5+4]=0x2A;                                           // usaOffset=42
    b[R5+6]=0x01;                                           // usaCount=1
    b[R5+16]=0x01; b[R5+18]=0x01;                           // seq=1, hardLink=1
    b[R5+20]=0x38;                                          // firstAttrOffset=56
    b[R5+22]=0x03;                                          // flags=3 (en cours + répertoire)
    b[R5+24]=0xE8;                                          // usedSize=232
    b[R5+28]=0x00; b[R5+29]=0x04;                           // allocSize=1024
    b[R5+40]=0x02;                                          // nextAttrId=2
    b[R5+42]=0x01;                                          // USA[0]
    // $INDEX_ROOT résident à +56 (header 24 o + valeur 148 o = 172 o)
    b[R5+56]=0x90;                                          // type=$INDEX_ROOT
    b[R5+60]=0xAC;                                          // length=172
    b[R5+72]=0x94;                                          // valueLength=148
    b[R5+76]=0x18;                                          // valueOffset=24
    // valeur @ +80 : type indexé $FILE_NAME (0x30), collation=1, 4096 o/index record
    b[R5+80]=0x30;
    b[R5+84]=0x01;
    b[R5+88]=0x00; b[R5+89]=0x10;                           // 0x1000 = 4096
    b[R5+92]=0x01;                                          // clustersPerIndexRecord
    // Index Header @ +96 (= valeur+16)
    b[R5+96]=0x10;                                          // firstEntryOffset (rel.) = 16
    b[R5+100]=0x84;                                         // totalSize (rel.) = 132
    b[R5+104]=0x84;                                         // allocSize (rel.) = 132
    // Entrée 1 "HELLO.TXT" @ +112 (100 o) -> MFT record 6
    b[R5+112]=0x06;                                         // fileRef = 6
    b[R5+120]=0x64;                                         // entryLength=100
    b[R5+122]=0x54;                                         // streamLength=84
    // $FILE_NAME @ +128
    b[R5+128]=0x05;                                         // parentRef = 5 (racine)
    b[R5+168]=0x00; b[R5+169]=0x04;                         // allocSize=1024
    b[R5+176]=0x0E;                                         // realSize=14 ("Bonjour NTFS!\n")
    b[R5+192]=0x09;                                         // filenameLen=9
    b[R5+193]=0x01;                                         // namespace=Win32
    // "HELLO.TXT" en UTF-16LE @ +194
    b[R5+194]=0x48; b[R5+196]=0x45; b[R5+198]=0x4C; b[R5+200]=0x4C; b[R5+202]=0x4F;
    b[R5+204]=0x2E; b[R5+206]=0x54; b[R5+208]=0x58; b[R5+210]=0x54;
    // Entrée 2 (terminateur, "last entry") @ +212 (16 o)
    b[R5+220]=0x10;                                         // entryLength=16
    b[R5+224]=0x02;                                         // flags=isLast
    // marqueur de fin d'attributs @ +228
    b[R5+228]=0xFF; b[R5+229]=0xFF; b[R5+230]=0xFF; b[R5+231]=0xFF;

    // ── Record 6 : fichier "HELLO.TXT" ───────────────────────────────────
    b[R6]=0x46; b[R6+1]=0x49; b[R6+2]=0x4C; b[R6+3]=0x45;  // 'FILE'
    b[R6+4]=0x2A;                                           // usaOffset=42
    b[R6+6]=0x01;                                           // usaCount=1
    b[R6+16]=0x01; b[R6+18]=0x01;                           // seq=1, hardLink=1
    b[R6+20]=0x38;                                          // firstAttrOffset=56
    b[R6+22]=0x01;                                          // flags=1 (fichier en cours d'utilisation)
    b[R6+24]=0x62;                                          // usedSize=98
    b[R6+28]=0x00; b[R6+29]=0x04;                           // allocSize=1024
    b[R6+40]=0x02;                                          // nextAttrId=2
    b[R6+42]=0x01;                                          // USA[0]
    // $DATA résident @ +56 (header 24 o + valeur 14 o = 38 o)
    b[R6+56]=0x80;                                          // type=$DATA
    b[R6+60]=0x26;                                          // length=38
    b[R6+72]=0x0E;                                          // valueLength=14
    b[R6+76]=0x18;                                          // valueOffset=24
    // contenu @ +80 : "Bonjour NTFS!\n"
    b[R6+80]=0x42; b[R6+81]=0x6F; b[R6+82]=0x6E; b[R6+83]=0x6A; b[R6+84]=0x6F;
    b[R6+85]=0x75; b[R6+86]=0x72; b[R6+87]=0x20; b[R6+88]=0x4E; b[R6+89]=0x54;
    b[R6+90]=0x46; b[R6+91]=0x53; b[R6+92]=0x21; b[R6+93]=0x0A;
    // marqueur de fin d'attributs @ +94
    b[R6+94]=0xFF; b[R6+95]=0xFF; b[R6+96]=0xFF; b[R6+97]=0xFF;

    b
};

/// Sélecteur de disque actif : 0 = SRFS (SDC:), 1 = NTFS (voir NTFSMan.slul).
/// Positionné par `DrvManSpec***UefiLocateDisk***` (argument optionnel) —
/// chaque driver appelle UefiLocateDisk avec son propre id avant de lire,
/// donc l'exécution séquentielle des drivers au boot (slul_loader) suffit
/// à garantir la bonne cible sans avoir besoin de threader un handle
/// explicite à travers chaque appel DiskRead.
static mut ACTIVE_DISK: u8 = 0;

/// Table de montage (lettre → id disque), remplie par `MountPointRegister`.
/// Lettre stockée nul-terminée (même convention que `RegEntry::name_c` dans
/// app_registry.rs) pour que `MountTableGetLetter` renvoie un pointeur stable
/// consommable directement par StrLen/StrCharAt côté Mara. Exposée en lecture
/// via `DrvAPIInterCon***MountTable{Count,GetLetter,GetDiskId}***` (ShiLooker
/// affiche la liste réelle des disques montés). Pas encore consommée pour
/// router FSGetSize/FSRead (mécanisme séparé, voir SRFS_CACHE).
static mut MOUNT_TABLE: Vec<(Vec<u8>, u8)> = Vec::new();

/// Volumes UEFI physiques réellement détectés au boot (disk_id >= 2 — voir
/// disk_volumes.rs), en PLUS de SDC(0)/A(1) qui restent simulés et inchangés.
/// `(label, handle_index)` : label pour l'affichage, handle_index pour rouvrir
/// CE volume précis via disk_volumes::list_dir_on_volume. Lecture seule (pas
/// de create/format sur ces volumes-là pour l'instant).
static mut PHYSICAL_VOLUMES: Vec<(alloc::string::String, usize)> = Vec::new();

/// Publie les volumes physiques détectés au boot (appelé une fois depuis
/// kernel_runtime.rs, juste après disk_volumes::scan_physical_volumes) et les
/// monte automatiquement dans MOUNT_TABLE avec disk_id = 2, 3, 4...
pub fn publish_physical_volumes(vols: alloc::vec::Vec<crate::disk_volumes::PhysicalVolume>) {
    unsafe {
        PHYSICAL_VOLUMES.clear();
        for (i, v) in vols.into_iter().enumerate() {
            let disk_id = (2 + i) as u8;
            PHYSICAL_VOLUMES.push((v.label, v.handle_index));
            let mut letter_c = alloc::format!("PHYS{}:\\", i).into_bytes();
            letter_c.push(0);
            MOUNT_TABLE.push((letter_c, disk_id));
        }
    }
}

/// Nombre d'entrées dans la table de montage. Appelé par
/// `DrvAPIInterCon***MountTableCount***`.
pub fn mount_table_count() -> i64 {
    unsafe { MOUNT_TABLE.len() as i64 }
}

/// Pointeur nul-terminé vers la lettre de montage `i` (ex "A:\\"), ou 0 si
/// hors bornes. Appelé par `DrvAPIInterCon***MountTableGetLetter***`.
pub fn mount_table_letter_ptr(i: usize) -> i64 {
    unsafe { MOUNT_TABLE.get(i).map(|(letter, _)| letter.as_ptr() as i64).unwrap_or(0) }
}

/// Id disque (0=SRFS, 1=NTFS) de l'entrée `i`, ou -1 si hors bornes. Appelé
/// par `DrvAPIInterCon***MountTableGetDiskId***`.
pub fn mount_table_disk_id(i: usize) -> i64 {
    unsafe { MOUNT_TABLE.get(i).map(|(_, id)| *id as i64).unwrap_or(-1) }
}

/// Libellé friendly UNE SEULE LIGNE "Slura Drive Core (SDC:\)" / "Slura NTFS
/// Data (A:\)" — construit ICI en Rust (concaténation nom+lettre non fiable
/// côté Mara, voir mémoire projet). Lettre gardée TELLE QUE stockée dans
/// MOUNT_TABLE (avec le "\" final, ex "SDC:\\") — c'est le format explicitement
/// demandé ("Slura Drive Core (SDC:\)"), pas le format compact "(SDC:)" utilisé
/// avant cette révision.
///
/// Les deux noms sont de VRAIS libellés attribués (comme un volume label posé
/// par `mkfs`/`format` — légitime, pas une fabrication), PAS une marque OEM
/// matérielle : ni SDC ni le volume NTFS embarqué (`NTFS_DISK_IMAGE`, un tableau
/// statique compilé de 2 records MFT seulement — pas de record $Volume/attribut
/// $VOLUME_NAME réel dedans) ne sont adossés à un vrai périphérique UEFI
/// Block I/O avec une identité fabricant/modèle interrogeable (voir commentaire
/// de DISK_FORMATTED_SESSION) — aucune chaîne "marque OEM" ne peut donc être
/// honnêtement lue depuis du matériel réel ici ; le nom attribué EST le repli,
/// comme il le serait sur un disque réel jamais nommé par son fabricant.
static mut MOUNT_LABEL_BUF: [u8; 64] = [0u8; 64];

pub fn mount_table_label_ptr(i: usize) -> i64 {
    let entry = unsafe { MOUNT_TABLE.get(i) };
    let Some((letter, disk_id)) = entry else { return 0; };
    let letter_trimmed = core::str::from_utf8(letter)
        .unwrap_or("?")
        .trim_end_matches('\0');
    // disk_id 0/1 = SDC/NTFS simulés (noms fixes existants) ; disk_id >= 2 =
    // volume physique réellement détecté au boot (voir PHYSICAL_VOLUMES).
    let name: alloc::string::String = if *disk_id == 0 {
        "Slura Drive Core".into()
    } else if *disk_id == 1 {
        "Slura NTFS Data".into()
    } else {
        let phys_idx = (*disk_id as usize).saturating_sub(2);
        unsafe { PHYSICAL_VOLUMES.get(phys_idx).map(|(label, _)| label.clone()) }
            .unwrap_or_else(|| "Physical Disk".into())
    };
    let label = alloc::format!("{} ({})", name, letter_trimmed);
    let bytes = label.as_bytes();
    unsafe {
        let n = bytes.len().min(MOUNT_LABEL_BUF.len() - 1);
        MOUNT_LABEL_BUF[..n].copy_from_slice(&bytes[..n]);
        MOUNT_LABEL_BUF[n] = 0;
        MOUNT_LABEL_BUF.as_ptr() as i64
    }
}

// ── SluWWANMan : signal cellulaire — ÉTAT RÉEL, pas de placeholder ──────────
// `scan_for_wwan_modem` (pci.rs) énumère réellement les devices PCI (lecture
// seule, même mécanisme éprouvé que scan_for_xhci) à la recherche d'un modem
// WWAN (classe PCI 02:80), appelé une fois au boot depuis kernel_runtime.rs
// juste après le scan xHCI. `WWAN_DETECTED` reflète ce résultat RÉEL — sur une
// VM QEMU/VMware sans passthrough WWAN, il sera honnêtement `false` (pas de
// barres, pas de type réseau simulé), exactement comme un vrai OS le
// rapporterait sur cette machine. `WWAN_CONNECTED` ne peut être vrai que si
// `WWAN_DETECTED` l'est — le signal/type ne sont affichés QUE si du matériel a
// réellement été trouvé.
//
// ⚠️ Limite assumée : un modem détecté (classe PCI 02:80 présente) ne donne
// PAS accès à son niveau de signal réel — ça nécessiterait de parler le
// protocole du modem (AT/QMI/MBIM), hors scope ici. Si détecté, le niveau de
// signal reste à 0 ("détecté mais niveau inconnu") plutôt que d'inventer une
// valeur — seul `WWAN_DETECTED`/`WWAN_CONNECTED` sont garantis réels.
// Type réseau encodé i32 0..9 : 0=GPRS 1=EDGE 2=3G 3=HSPA 4=HSPA+ 5=4G 6=4G+ 7=5G 8=5G+ 9=5Ge.
static mut WWAN_DETECTED: bool = false;
static mut WWAN_SIGNAL_LEVEL: i32 = 0;
static mut WWAN_NETWORK_TYPE: i32 = 0;
static mut WWAN_CONNECTED: bool = false;

pub fn wwan_get_signal_level() -> i64 { unsafe { WWAN_SIGNAL_LEVEL as i64 } }
pub fn wwan_get_network_type() -> i64 { unsafe { WWAN_NETWORK_TYPE as i64 } }
pub fn wwan_is_connected() -> i64 { unsafe { WWAN_CONNECTED as i64 } }
pub fn wwan_is_detected() -> i64 { unsafe { WWAN_DETECTED as i64 } }
pub fn wwan_set_network_type(t: i32) -> i64 {
    if t < 0 || t > 9 { return -1; }
    unsafe { WWAN_NETWORK_TYPE = t; }
    0
}

/// Appelé UNE fois au boot par kernel_runtime.rs juste après
/// `pci::scan_for_wwan_modem` — traduit le résultat RÉEL de la détection
/// matérielle en l'état exposé à Mara. Ne devine jamais de niveau de signal :
/// `found=true` ne fait passer `WWAN_CONNECTED` à vrai que parce qu'un device
/// PCI classe 02:80 existe réellement, pas parce qu'une valeur est simulée.
pub fn wwan_set_detected(found: bool) {
    unsafe {
        WWAN_DETECTED = found;
        WWAN_CONNECTED = found;
    }
    serial_log(alloc::format!(
        "[WWAN] detection materielle au boot : {}\r\n",
        if found { "modem PCI 02:80 trouve" } else { "aucun modem — etat honnetement non connecte" }
    ).as_bytes());
}

// ── SluVMTools : pointeur absolu + auto-adaptation résolution — ÉTAT RÉEL ──
// Même philosophie que WWAN_DETECTED ci-dessus : reflète ce que
// vmware_backdoor.rs (backdoor VMware/QEMU, port 0x5658) a réellement négocié
// au boot dans kernel_runtime.rs, jamais un placeholder. Sur bare-metal ou un
// hyperviseur sans ce backdoor, `VMTOOLS_PRESENT` reste honnêtement `false` —
// SluVMTools.marep l'affiche tel quel plutôt que de prétendre être actif.
static mut VMTOOLS_PRESENT:            bool = false;
static mut VMTOOLS_ABSPOINTER_ENABLED: bool = false;
static mut VMTOOLS_RESIZE_COUNT:       i32  = 0;

pub fn vmtools_is_present() -> i64 { unsafe { VMTOOLS_PRESENT as i64 } }
pub fn vmtools_abspointer_enabled() -> i64 { unsafe { VMTOOLS_ABSPOINTER_ENABLED as i64 } }
pub fn vmtools_get_resize_count() -> i64 { unsafe { VMTOOLS_RESIZE_COUNT as i64 } }

/// Appelé UNE fois au boot par kernel_runtime.rs juste après la négociation
/// du backdoor (vmware_backdoor::backdoor_available/abspointer_enable).
pub fn vmtools_set_detected(present: bool, abspointer_enabled: bool) {
    unsafe {
        VMTOOLS_PRESENT = present;
        VMTOOLS_ABSPOINTER_ENABLED = abspointer_enabled;
    }
}

/// Appelé par kernel_runtime.rs à chaque fois que la résolution GOP est
/// effectivement rebasculée en cours de session (fenêtre hôte redimensionnée).
pub fn vmtools_note_resize() {
    unsafe { VMTOOLS_RESIZE_COUNT = VMTOOLS_RESIZE_COUNT.saturating_add(1); }
}

// ── SluPwMan : actions d'alimentation RÉELLES (ACPI Spec 6.4 §7, UEFI Runtime
// Services ResetSystem) ──────────────────────────────────────────────────────
// Redémarrer/Éteindre : `RuntimeServices::reset()` — mécanisme UEFI standard,
// géré par le firmware (transition ACPI \_S5 réelle pour l'extinction). Le
// pointeur vers les Runtime Services est capturé UNE fois au boot
// (kernel_runtime.rs, via `power_init`) et reste valide toute la session car
// ce noyau n'appelle jamais ExitBootServices (voir commentaire plus haut) —
// la table système n'est donc jamais réadressée en mémoire virtuelle.
//
// Mettre en veille (S3) : PAS géré par ResetSystem (qui ne connaît que
// Cold/Warm/Shutdown/PlatformSpecific, jamais "sleep" — S3 est une transition
// d'état ACPI différente, pas un reset). Implémenté via écriture directe du
// registre PM1_CNT (bits SLP_TYP + SLP_EN), avec les valeurs SLP_TYPa/b
// trouvées réellement dans le DSDT via `acpi::scan_power_management` (voir ce
// fichier pour le détail — recherche bornée de l'objet `\_S3`, PAS un
// interpréteur AML complet). Si l'un des éléments nécessaires manque (FADT
// sans PM1a exploitable, `\_S3` introuvable, GAS en System Memory non géré),
// la mise en veille est honnêtement indisponible (`PowerSleepSupported` rend
// 0) plutôt que de deviner des valeurs et risquer un blocage matériel.
static mut RUNTIME_SERVICES_PTR: *const uefi::table::runtime::RuntimeServices = core::ptr::null();
static mut POWER_MGMT: Option<crate::acpi::PowerMgmt> = None;

/// Appelé UNE fois au boot par kernel_runtime.rs, juste après
/// `acpi::scan_acpi_tables` — capture le pointeur Runtime Services (toujours
/// disponible, indépendant de l'ACPI) et le résultat (potentiellement `None`,
/// honnêtement) de la découverte des registres de mise en veille.
pub fn power_init(rt: *const uefi::table::runtime::RuntimeServices, pm: Option<crate::acpi::PowerMgmt>) {
    unsafe {
        RUNTIME_SERVICES_PTR = rt;
        let supported = pm.is_some();
        POWER_MGMT = pm;
        serial_log(alloc::format!(
            "[POWER] Runtime Services captures — mise en veille S3 {}\r\n",
            if supported { "disponible (\\_S3 trouve dans le DSDT)" } else { "indisponible (voir logs [ACPI] ci-dessus)" }
        ).as_bytes());
    }
}

/// Écrit un octet sur un port I/O x86_64 (`out`). Utilisé uniquement pour
/// SMI_CMD (activation du mode ACPI, rarement nécessaire sous UEFI natif où
/// SCI_EN est déjà à 1).
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

/// Lit un mot 16 bits sur un port I/O x86_64 (`in`) — PM1_CNT fait
/// PM1_CNT_LEN octets (2 le plus souvent) ; on lit/écrit toujours 16 bits,
/// suffisant pour couvrir SLP_TYP (bits 10-12) + SLP_EN (bit 13).
unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    core::arch::asm!("in ax, dx", in("dx") port, out("ax") val, options(nomem, nostack, preserves_flags));
    val
}

unsafe fn outw(port: u16, val: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags));
}

pub fn power_restart() -> i64 {
    let ptr = unsafe { RUNTIME_SERVICES_PTR };
    if ptr.is_null() {
        serial_log(b"[POWER] Redemarrage demande mais Runtime Services non captures\r\n");
        return -1;
    }
    serial_log(b"[POWER] Redemarrage (UEFI ResetSystem, EfiResetWarm)\r\n");
    unsafe { (*ptr).reset(uefi::table::runtime::ResetType::WARM, uefi::Status::SUCCESS, None) }
}

pub fn power_shutdown() -> i64 {
    let ptr = unsafe { RUNTIME_SERVICES_PTR };
    if ptr.is_null() {
        serial_log(b"[POWER] Extinction demandee mais Runtime Services non captures\r\n");
        return -1;
    }
    serial_log(b"[POWER] Extinction (UEFI ResetSystem, EfiResetShutdown - vraie transition ACPI S5)\r\n");
    unsafe { (*ptr).reset(uefi::table::runtime::ResetType::SHUTDOWN, uefi::Status::SUCCESS, None) }
}

pub fn power_sleep_supported() -> i64 {
    unsafe { POWER_MGMT.is_some() as i64 }
}

/// Déclenche une vraie transition ACPI S3 (RAM auto-rafraîchie, CPU arrêté) —
/// écrit SLP_TYPa<<10 | SLP_EN(bit13) dans PM1a_CNT ; si PM1b existe, même
/// séquence dessus AVANT PM1a (ordre recommandé par la spec pour que SLP_EN
/// déclenche l'entrée en veille une fois les deux blocs préparés). Ne modifie
/// jamais les autres bits déjà présents dans PM1_CNT (lecture puis
/// modification ciblée, pas d'écrasement).
pub fn power_sleep() -> i64 {
    let pm = unsafe { POWER_MGMT.clone() };
    let Some(pm) = pm else {
        serial_log(b"[POWER] Mise en veille demandee mais indisponible (voir logs [ACPI])\r\n");
        return -1;
    };
    serial_log(b"[POWER] Mise en veille S3 (ecriture PM1_CNT reelle)\r\n");
    unsafe {
        if pm.smi_cmd_port != 0 {
            let cur = inw(pm.pm1a_cnt_port);
            if cur & 1 == 0 { outb(pm.smi_cmd_port, pm.acpi_enable_val); }
        }
        const SLP_TYP_SHIFT: u16 = 10;
        const SLP_EN: u16 = 1 << 13;
        if pm.pm1b_cnt_port != 0 {
            let curb = inw(pm.pm1b_cnt_port);
            let clearedb = curb & !(0b111 << SLP_TYP_SHIFT);
            outw(pm.pm1b_cnt_port, clearedb | (pm.slp_typ_b << SLP_TYP_SHIFT));
        }
        let cura = inw(pm.pm1a_cnt_port);
        let clareda = cura & !(0b111 << SLP_TYP_SHIFT);
        outw(pm.pm1a_cnt_port, clareda | (pm.slp_typ_a << SLP_TYP_SHIFT));
        if pm.pm1b_cnt_port != 0 {
            let curb2 = inw(pm.pm1b_cnt_port);
            outw(pm.pm1b_cnt_port, curb2 | SLP_EN);
        }
        let cura2 = inw(pm.pm1a_cnt_port);
        outw(pm.pm1a_cnt_port, cura2 | SLP_EN);
    }
    // Si l'écriture a réellement fonctionné, le CPU s'arrête ici (S3) et cette
    // fonction ne "retourne" qu'au réveil (le firmware relance l'exécution
    // depuis le vecteur de reset — cette valeur de retour n'est donc en
    // pratique observable QUE si la transition a échoué silencieusement).
    0
}

// ── SluDskMan : format/mount/unmount honnêtes (voir plan) ───────────────────
// Aucune écriture disque réelle n'existe dans ce noyau (DiskWrite est un no-op,
// SRFS_DISK_IMAGE/NTFS_DISK_IMAGE sont des tableaux statiques compilés, pas des
// fichiers) — formater resterait donc un no-op honnête (documenté) plutôt que de
// simuler un vrai formatage. Mount/unmount sont réels : ils mutent la même
// MOUNT_TABLE que ShiLooker affiche déjà, mais restent SESSION-ONLY (reset au
// reboot, comme tout le reste de cet état noyau) et n'affectent aucun routage de
// fichier réel (rien ne gate ImageLoad/FontLoad/SRFS_CACHE sur MOUNT_TABLE).
static mut DISK_FORMATTED_SESSION: [bool; 2] = [false, false];

/// Marque le disque `disk_id` (0=SRFS, 1=NTFS) comme formaté pour cette session
/// uniquement — ne touche jamais SRFS_DISK_IMAGE/NTFS_DISK_IMAGE (état partagé,
/// le muter serait un effet de bord dangereux). Retourne -1 si id invalide.
pub fn disk_format(disk_id: i32) -> i64 {
    if disk_id < 0 || disk_id > 1 { return -1; }
    unsafe { DISK_FORMATTED_SESSION[disk_id as usize] = true; }
    serial_log(alloc::format!(
        "[DISK] Format disque {} — marque formate (session uniquement, non persiste au reboot)\r\n", disk_id
    ).as_bytes());
    0
}

pub fn disk_is_formatted_session(disk_id: i32) -> i64 {
    if disk_id < 0 || disk_id > 1 { return 0; }
    unsafe { DISK_FORMATTED_SESSION[disk_id as usize] as i64 }
}

fn disk_id_to_default_letter(disk_id: i32) -> &'static str {
    match disk_id { 1 => "A:\\", _ => "SDC:\\" }
}

/// Monte le disque `disk_id` s'il ne l'est pas déjà (pousse dans MOUNT_TABLE, même
/// mécanisme que MountPointRegister). Idempotent : renvoie 1 si déjà monté, 0 si
/// nouvellement monté, -1 si id invalide.
pub fn disk_mount(disk_id: i32) -> i64 {
    if disk_id < 0 || disk_id > 1 { return -1; }
    unsafe {
        if MOUNT_TABLE.iter().any(|(_, id)| *id == disk_id as u8) { return 1; }
        let mut letter_c = disk_id_to_default_letter(disk_id).as_bytes().to_vec();
        letter_c.push(0);
        MOUNT_TABLE.push((letter_c, disk_id as u8));
    }
    serial_log(alloc::format!("[DISK] DiskMount({}) OK\r\n", disk_id).as_bytes());
    0
}

/// Démonte le disque `disk_id` (retire son entrée de MOUNT_TABLE) — AFFICHAGE
/// SEULEMENT : rien ne route réellement les lectures fichier via MOUNT_TABLE
/// aujourd'hui, donc ça n'empêche aucune autre app de continuer à lire SDC:/A:.
/// Retourne -1 si aucune entrée ne correspondait.
pub fn disk_unmount(disk_id: i32) -> i64 {
    if disk_id < 0 || disk_id > 1 { return -1; }
    let before = unsafe { MOUNT_TABLE.len() };
    unsafe { MOUNT_TABLE.retain(|(_, id)| *id != disk_id as u8); }
    if unsafe { MOUNT_TABLE.len() } == before { return -1; }
    serial_log(alloc::format!("[DISK] DiskUnmount({}) OK (affichage seulement)\r\n", disk_id).as_bytes());
    0
}

// ── Navigation dossiers (ShiLooker, onglet Disks) ────────────────────────────
// Chemin courant de navigation, nul-terminé (même convention que RegEntry.name_c).
// Les "dossiers" sont une convention UI par-dessus SRFS_CACHE (entrées à 0 octet
// dont la clé finit par '/'), pas une vraie notion noyau — voir DiskCacheListDir.
static mut DISK_BROWSE_PATH: Vec<u8> = Vec::new();

pub fn disk_browse_get_path() -> i64 {
    unsafe {
        if DISK_BROWSE_PATH.is_empty() { DISK_BROWSE_PATH.push(0); }
        DISK_BROWSE_PATH.as_ptr() as i64
    }
}

pub fn disk_browse_reset(root: &str) {
    let mut s = alloc::string::String::from(root);
    if !s.ends_with('/') { s.push('/'); }
    let mut v = s.into_bytes();
    v.push(0);
    unsafe { DISK_BROWSE_PATH = v; }
}

/// Reset la navigation vers la racine du disque `disk_id`, quel qu'il soit —
/// construit le bon préfixe ("SDC:", "A:", ou "PHYSn:") côté Rust puisque Mara
/// n'a aucune concaténation de chaîne fiable (voir README §4.11). disk_id >= 2
/// = volume physique réel (voir disk_volumes.rs) : le préfixe "PHYSn:" est
/// reconnu par disk_cache_dir_rebuild pour router vers list_dir_on_volume.
pub fn disk_browse_reset_for_disk_id(disk_id: i32) {
    let root: alloc::string::String = match disk_id {
        0 => "SDC:".into(),
        1 => "A:".into(),
        n if n >= 2 => alloc::format!("PHYS{}:", n - 2),
        _ => "SDC:".into(),
    };
    disk_browse_reset(&root);
}

pub fn disk_browse_navigate_into(name: &str) {
    unsafe {
        if DISK_BROWSE_PATH.is_empty() { DISK_BROWSE_PATH.push(0); }
        DISK_BROWSE_PATH.pop(); // retire le \0 final
        DISK_BROWSE_PATH.extend_from_slice(name.as_bytes());
        if !name.ends_with('/') { DISK_BROWSE_PATH.push(b'/'); }
        DISK_BROWSE_PATH.push(0);
    }
}

pub fn disk_browse_navigate_up() {
    unsafe {
        if DISK_BROWSE_PATH.len() <= 1 { return; }
        DISK_BROWSE_PATH.pop(); // \0
        if DISK_BROWSE_PATH.last() == Some(&b'/') { DISK_BROWSE_PATH.pop(); } // slash de fin courant
        while let Some(&b) = DISK_BROWSE_PATH.last() {
            if b == b'/' { break; }
            DISK_BROWSE_PATH.pop();
        }
        DISK_BROWSE_PATH.push(0);
    }
}

// ── Sélecteur de dossier de capture (ShiCamera) — curseur de navigation isolé
// Des fonctions identiques à disk_browse_*, mais opérant sur CAPTURE_PICKER_PATH
// plutôt que DISK_BROWSE_PATH (règle §9.7 : jamais partager d'état entre UI).
pub fn capture_picker_browse_get_path() -> i64 {
    unsafe {
        if CAPTURE_PICKER_PATH.is_empty() { CAPTURE_PICKER_PATH.push(0); }
        CAPTURE_PICKER_PATH.as_ptr() as i64
    }
}

pub fn capture_picker_browse_reset(root: &str) {
    let mut s = alloc::string::String::from(root);
    if !s.ends_with('/') { s.push('/'); }
    let mut v = s.into_bytes();
    v.push(0);
    unsafe { CAPTURE_PICKER_PATH = v; }
}

pub fn capture_picker_browse_navigate_into(name: &str) {
    unsafe {
        if CAPTURE_PICKER_PATH.is_empty() { CAPTURE_PICKER_PATH.push(0); }
        CAPTURE_PICKER_PATH.pop(); // retire le \0 final
        CAPTURE_PICKER_PATH.extend_from_slice(name.as_bytes());
        if !name.ends_with('/') { CAPTURE_PICKER_PATH.push(b'/'); }
        CAPTURE_PICKER_PATH.push(0);
    }
}

pub fn capture_picker_browse_navigate_up() {
    unsafe {
        if CAPTURE_PICKER_PATH.len() <= 1 { return; }
        CAPTURE_PICKER_PATH.pop(); // \0
        if CAPTURE_PICKER_PATH.last() == Some(&b'/') { CAPTURE_PICKER_PATH.pop(); } // slash de fin courant
        while let Some(&b) = CAPTURE_PICKER_PATH.last() {
            if b == b'/' { break; }
            CAPTURE_PICKER_PATH.pop();
        }
        CAPTURE_PICKER_PATH.push(0);
    }
}

// ── Champ de texte générique (nom de fichier/dossier — aucune primitive de saisie
// texte n'existait avant : KeyGetCode ne donne qu'UNE touche par frame, et la
// concaténation <string>+<i32> Mara compile sans garantie d'exécution réelle côté
// interpréteur OVC, voir mémoire projet) ────────────────────────────────────────
static mut TEXT_FIELD_BUF: Vec<u8> = Vec::new();

pub fn text_field_append_char(code: i32) -> i64 {
    // Imprimable ASCII uniquement (32..=126) — ignore le reste (touches de contrôle
    // hors backspace, qui a son propre FFI).
    if code < 32 || code > 126 { return -1; }
    unsafe {
        if TEXT_FIELD_BUF.is_empty() { TEXT_FIELD_BUF.push(0); }
        if TEXT_FIELD_BUF.len() >= 64 { return -1; } // 63 car + \0
        TEXT_FIELD_BUF.pop();
        TEXT_FIELD_BUF.push(code as u8);
        TEXT_FIELD_BUF.push(0);
    }
    0
}

pub fn text_field_backspace() -> i64 {
    unsafe {
        if TEXT_FIELD_BUF.len() <= 1 { return 0; }
        TEXT_FIELD_BUF.pop(); // \0
        TEXT_FIELD_BUF.pop(); // dernier caractère
        TEXT_FIELD_BUF.push(0);
    }
    0
}

pub fn text_field_clear() -> i64 {
    unsafe { TEXT_FIELD_BUF.clear(); TEXT_FIELD_BUF.push(0); }
    0
}

pub fn text_field_get_ptr() -> i64 {
    unsafe {
        if TEXT_FIELD_BUF.is_empty() { TEXT_FIELD_BUF.push(0); }
        TEXT_FIELD_BUF.as_ptr() as i64
    }
}

/// Construit un buffer BMP 24bpp minimal (w×h, couleur unie argb) en RAM et
/// retourne un pointeur vers ses octets — évite de manipuler les octets d'en-tête
/// à la main en Mara via PtrWrite8At en boucle. Le pointeur reste valide tant que
/// le Vec sous-jacent n'est pas libéré : consommé immédiatement par l'appelant
/// (CaWriteFile) donc pas de problème de durée de vie.
pub fn bmp_blank_buffer(w: i32, h: i32, argb: i32) -> alloc::vec::Vec<u8> {
    let w = w.clamp(1, 256) as u32;
    let h = h.clamp(1, 256) as u32;
    let row_bytes = ((w * 3 + 3) / 4) * 4; // aligné 4 octets
    let pixel_data_size = row_bytes * h;
    let file_size = 54 + pixel_data_size;
    let r = ((argb >> 16) & 0xFF) as u8;
    let g = ((argb >> 8) & 0xFF) as u8;
    let b = (argb & 0xFF) as u8;

    let mut buf = alloc::vec::Vec::with_capacity(file_size as usize);
    // BITMAPFILEHEADER (14 octets)
    buf.extend_from_slice(b"BM");
    buf.extend_from_slice(&file_size.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // réservé
    buf.extend_from_slice(&54u32.to_le_bytes()); // offset pixels
    // BITMAPINFOHEADER (40 octets)
    buf.extend_from_slice(&40u32.to_le_bytes());
    buf.extend_from_slice(&(w as i32).to_le_bytes());
    buf.extend_from_slice(&(h as i32).to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());  // plans
    buf.extend_from_slice(&24u16.to_le_bytes()); // bpp
    buf.extend_from_slice(&0u32.to_le_bytes());  // compression (BI_RGB)
    buf.extend_from_slice(&pixel_data_size.to_le_bytes());
    buf.extend_from_slice(&2835i32.to_le_bytes()); // ppm X (~72dpi)
    buf.extend_from_slice(&2835i32.to_le_bytes()); // ppm Y
    buf.extend_from_slice(&0u32.to_le_bytes());    // couleurs palette
    buf.extend_from_slice(&0u32.to_le_bytes());    // couleurs importantes
    // Pixels (bas→haut, BGR, padding par ligne)
    let pad = (row_bytes - w * 3) as usize;
    for _ in 0..h {
        for _ in 0..w {
            buf.push(b);
            buf.push(g);
            buf.push(r);
        }
        for _ in 0..pad { buf.push(0); }
    }
    buf
}

// Listing du "dossier" courant (préfixe de chemin) — reconstruit à chaque appel
// de DiskCacheDirCount (même idiome que AppRegistryCount/GetName : un Count()
// qui prépare l'état, puis des GetName(i) indexés, pas de string \n-joined à
// parser côté Mara qui n'a aucune primitive de découpage de chaîne). Deux
// sources fusionnées pour SDC: (1) le VRAI contenu de la partition ESP hôte
// (srfs_uefi_list_dir, lecture réelle) et (2) SRFS_CACHE pour les
// fichiers/dossiers créés cette session (DiskBrowseCreateEntry n'écrit que sur
// le cache RAM, jamais sur le disque réel — sans ce merge, un dossier tout
// juste créé n'apparaîtrait pas dans la liste malgré la lecture réelle).
static mut DISK_DIR_LISTING: Vec<Vec<u8>> = Vec::new();

pub fn disk_cache_dir_rebuild(prefix: &str) -> i64 {
    use uefi::table::{Boot, SystemTable};
    let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();

    if prefix.to_ascii_uppercase().starts_with("SDC:") {
        let st_raw = unsafe { UEFI_ST_PTR };
        if !st_raw.is_null() {
            if let Some(real_names) = unsafe { srfs_uefi_list_dir(st_raw, prefix) } {
                names.extend(real_names);
            }
        }
    } else if let Some(phys_rest) = prefix.strip_prefix("PHYS").filter(|_| prefix.to_ascii_uppercase().starts_with("PHYS")) {
        // Volume physique réel (disk_id >= 2, voir disk_volumes.rs) : lecture
        // seule, aucun merge SRFS_CACHE (pas de création de fichier dessus).
        if let Some((idx_str, sub_path)) = phys_rest.split_once(':') {
            if let Ok(phys_idx) = idx_str.parse::<usize>() {
                let handle_index = unsafe { PHYSICAL_VOLUMES.get(phys_idx).map(|(_, h)| *h) };
                if let Some(handle_index) = handle_index {
                    let st_raw = unsafe { UEFI_ST_PTR };
                    if !st_raw.is_null() {
                        if let Some(mut st) = unsafe { SystemTable::<Boot>::from_ptr(st_raw) } {
                            if let Some(img) = unsafe { uefi::Handle::from_ptr(UEFI_IMG_HANDLE as *mut core::ffi::c_void) } {
                                let rel = sub_path.trim_start_matches('/');
                                if let Some(real_names) = crate::disk_volumes::list_dir_on_volume(&mut st, img, handle_index, rel) {
                                    names.extend(real_names);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    unsafe {
        for slot in SRFS_CACHE.iter() {
            if let Some((k, _)) = slot {
                if let Some(rest) = k.strip_prefix(prefix) {
                    if rest.is_empty() { continue; }
                    let seg = match rest.find('/') {
                        Some(pos) => &rest[..=pos], // garde le '/' final = sous-dossier
                        None => rest,
                    };
                    if !names.iter().any(|n| n == seg) { names.push(seg.to_string()); }
                }
            }
        }
    }
    let listing: alloc::vec::Vec<alloc::vec::Vec<u8>> = names.into_iter().map(|n| {
        let mut v = n.into_bytes();
        v.push(0);
        v
    }).collect();
    let count = listing.len() as i64;
    unsafe { DISK_DIR_LISTING = listing; }
    count
}

pub fn disk_cache_dir_get_name(i: usize) -> i64 {
    unsafe { DISK_DIR_LISTING.get(i).map(|v| v.as_ptr() as i64).unwrap_or(0) }
}

/// Crée une entrée (dossier ou fichier) dans le "dossier" courant de navigation
/// (DISK_BROWSE_PATH) avec le nom actuellement dans TEXT_FIELD_BUF — toute la
/// construction du chemin (concaténation dossier+nom+extension) se fait ICI en
/// Rust plutôt qu'en Mara, où la concaténation <string>+<string> n'a AUCUNE
/// garantie d'exécution réelle côté interpréteur OVC (voir commentaire sur
/// TEXT_FIELD_BUF/DISK_BROWSE_PATH). kind: 0=dossier, 1=.txt, 2=.md, 3=.bmp.
/// Retourne 0 si succès, -1 si le nom ou le dossier courant est vide/invalide.
pub fn disk_browse_create_entry(kind: i32) -> i64 {
    let name = unsafe {
        if TEXT_FIELD_BUF.len() <= 1 { return -1; }
        match core::str::from_utf8(&TEXT_FIELD_BUF[..TEXT_FIELD_BUF.len() - 1]) {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    if name.is_empty() { return -1; }
    let base = unsafe {
        if DISK_BROWSE_PATH.len() <= 1 { return -1; }
        match core::str::from_utf8(&DISK_BROWSE_PATH[..DISK_BROWSE_PATH.len() - 1]) {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    match kind {
        0 => { let path = alloc::format!("{}{}/", base, name); srfs_write_chain_file(&path, &[]); }
        1 => { let path = alloc::format!("{}{}.txt", base, name); srfs_write_chain_file(&path, &[]); }
        2 => { let path = alloc::format!("{}{}.md", base, name); srfs_write_chain_file(&path, &[]); }
        3 => {
            let path = alloc::format!("{}{}.bmp", base, name);
            let bytes = bmp_blank_buffer(16, 16, 0xFFB9B9B9u32 as i32);
            srfs_write_chain_file(&path, &bytes);
        }
        _ => return -1,
    }
    unsafe { TEXT_FIELD_BUF.clear(); TEXT_FIELD_BUF.push(0); }
    0
}

/// Couleur ARGB personnalisée d'un dossier — clé = chemin complet (dossier
/// parent + nom, mêmes deux pointeurs que DiskBrowseNavigateInto/CreateEntry
/// reçoit séparément : la concaténation se fait ICI en Rust, jamais côté Mara,
/// voir le commentaire sur disk_browse_create_entry). Table plate, pas de
/// limite de taille arbitraire (le nombre de dossiers réellement parcourus
/// dans une session reste petit). Couleur par défaut si jamais définie :
/// 0xFFE0E0E0 (gris clair, même teinte que les tuiles disque d'origine).
pub const DEFAULT_FOLDER_COLOR: u32 = 0xFFE0E0E0;
static mut FOLDER_COLORS: Vec<(alloc::string::String, u32)> = Vec::new();

fn folder_color_key(base_ptr: i64, name_ptr: i64) -> Option<alloc::string::String> {
    if base_ptr == 0 || name_ptr == 0 { return None; }
    let base = unsafe { read_cstr(base_ptr as *const u8) };
    let name = unsafe { read_cstr(name_ptr as *const u8) };
    if base.is_empty() || name.is_empty() { return None; }
    Some(alloc::format!("{}{}", base, name))
}

pub fn folder_color_get(base_ptr: i64, name_ptr: i64) -> i64 {
    let key = match folder_color_key(base_ptr, name_ptr) { Some(k) => k, None => return DEFAULT_FOLDER_COLOR as i64 };
    unsafe {
        match FOLDER_COLORS.iter().find(|(k, _)| *k == key) {
            Some((_, c)) => *c as i64,
            None => DEFAULT_FOLDER_COLOR as i64,
        }
    }
}

pub fn folder_color_set(base_ptr: i64, name_ptr: i64, argb: i32) -> i64 {
    let key = match folder_color_key(base_ptr, name_ptr) { Some(k) => k, None => return -1 };
    unsafe {
        match FOLDER_COLORS.iter_mut().find(|(k, _)| *k == key) {
            Some((_, c)) => { *c = argb as u32; }
            None => { FOLDER_COLORS.push((key, argb as u32)); }
        }
    }
    0
}

/// Retourne un pointeur vers l'image disque actuellement sélectionnée
/// (ACTIVE_DISK). Appelé par `DrvManSpec***UefiLocateDisk***`.
pub fn srfs_disk_handle() -> i64 {
    unsafe {
        match ACTIVE_DISK {
            1 => NTFS_DISK_IMAGE.as_ptr() as i64,
            _ => SRFS_DISK_IMAGE.as_ptr() as i64,
        }
    }
}

/// Lit `size` octets depuis le disque virtuel actuellement sélectionné
/// (ACTIVE_DISK) à l'offset `offset`. Appelé par `DrvManSpec***DiskRead***`.
pub fn srfs_disk_read(offset: usize, dst: *mut u8, size: usize) -> i64 {
    if dst.is_null() { return 0; }
    let (src, len) = unsafe {
        match ACTIVE_DISK {
            1 => (NTFS_DISK_IMAGE.as_ptr(), NTFS_DISK_IMAGE.len()),
            _ => (SRFS_DISK_IMAGE.as_ptr(), SRFS_DISK_IMAGE.len()),
        }
    };
    let avail = len.saturating_sub(offset);
    let n = size.min(avail);
    if n > 0 {
        unsafe { core::ptr::copy_nonoverlapping(src.add(offset), dst, n); }
    }
    // Au-delà de l'image (fin de disque), on remplit de zéros (blocs vides)
    if size > n {
        unsafe { core::ptr::write_bytes(dst.add(n), 0, size - n); }
    }
    size as i64  // toujours retourner size demandé
}

// ── Compteurs GPU (diagnostic) ────────────────────────────────────────────────
static mut GPU_FILLS:  u32 = 0;
static mut GPU_RECTS:  u32 = 0;
static mut GPU_TEXTS:  u32 = 0;

static mut GPU_OPACITY:    u32 = 255;
static mut GPU_BLEND_MODE: u32 = 0;
static mut CLIP_STACK: [(i32,i32,i32,i32,i32); 8] = [(0,0,0,0,0); 8];
static mut CLIP_DEPTH: usize = 0;
// Matrice de transformation 2D affine (fixed-point ×10000).  Identité par défaut.
// [a, b, c, d, tx, ty]  →  x' = a*x/10000 + c*y/10000 + tx
//                           y' = b*x/10000 + d*y/10000 + ty
static mut GPU_TRANSFORM: [i32; 6] = [10000, 0, 0, 10000, 0, 0];
static mut GPU_TRANSFORM_ACTIVE: bool = false;

// ── Cache masque alpha (GpuCaptureMask / GpuApplyAlphaMask) ──────────────────
// Chaque slot : (x, y, w, h, pixel_data_ARGB) — handle = index+1
static mut MASK_CACHE: [Option<(i32, i32, i32, i32, Vec<u8>)>; 4] = [None, None, None, None];
// ── Cache SVG chargés (SvgLoad / SvgDraw / SvgFree) ──────────────────────────
static mut SVG_CACHE: [Option<Vec<u8>>; 8] = [None, None, None, None, None, None, None, None];

// ── Curseurs Slura natifs (.sluc statique / .slun animé) ─────────────────────
// Format texte maison, cohérent avec le reste du projet (OVC/Maraset/RAbstract-
// allowing sont aussi du texte) : quelques lignes d'en-tête clé:valeur, puis une
// ou plusieurs frames au sous-ensemble SVG déjà supporté par svg_render (mêmes
// éléments que vec5.svg etc.), séparées par une ligne "@frame" pour les .slun.
//
// # Slura Cursor v1              (.sluc — statique)
// hotspot: 12,8
// size: 32,32
// <svg viewBox="0 0 32 32"> ... </svg>
//
// # Slura Cursor Anim v1         (.slun — animé : loading/busy/boot)
// hotspot: 16,16
// size: 32,32
// frame-ms: 83
// <svg viewBox="0 0 32 32"> ... </svg>
// @frame
// <svg viewBox="0 0 32 32"> ... </svg>
struct CursorAsset {
    hotspot_x: i32,
    hotspot_y: i32,
    width:     i32,
    height:    i32,
    /// 0 = statique (une seule frame). >0 = durée d'une frame en ms.
    frame_ms:  i32,
    frames:    Vec<String>,
}
static mut CURSOR_CACHE: [Option<CursorAsset>; 4] = [None, None, None, None];
/// Compteur de frames — avancé une fois par frame rendue (reset_gpu_counters,
/// appelé une fois par tick ~16ms par render_from_marep). Sert à choisir la
/// frame courante des curseurs animés sans dépendre d'une horloge murale.
static mut CURSOR_TICK: u64 = 0;

/// Parse un .sluc/.slun : en-tête clé:valeur puis corps découpé en frames sur
/// les lignes "@frame" (une seule frame implicite si absent, cas .sluc statique).
fn parse_cursor(text: &str) -> Option<CursorAsset> {
    let mut hotspot_x = 0i32;
    let mut hotspot_y = 0i32;
    let mut width  = 32i32;
    let mut height = 32i32;
    let mut frame_ms = 0i32;

    let mut lines = text.lines();
    let mut body_lines: Vec<&str> = Vec::new();
    for line in &mut lines {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }
        if let Some(v) = t.strip_prefix("hotspot:") {
            let mut p = v.split(',');
            hotspot_x = p.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            hotspot_y = p.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        } else if let Some(v) = t.strip_prefix("size:") {
            let mut p = v.split(',');
            width  = p.next().and_then(|s| s.trim().parse().ok()).unwrap_or(32);
            height = p.next().and_then(|s| s.trim().parse().ok()).unwrap_or(32);
        } else if let Some(v) = t.strip_prefix("frame-ms:") {
            frame_ms = v.trim().parse().unwrap_or(0);
        } else {
            // Première ligne qui n'est pas de l'en-tête reconnu : début du corps.
            body_lines.push(line);
            break;
        }
    }
    body_lines.extend(lines);

    let mut frames: Vec<String> = Vec::new();
    let mut current = String::new();
    for line in body_lines {
        if line.trim() == "@frame" {
            if !current.trim().is_empty() { frames.push(current.clone()); }
            current.clear();
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }
    if !current.trim().is_empty() { frames.push(current); }
    if frames.is_empty() { return None; }

    Some(CursorAsset { hotspot_x, hotspot_y, width, height, frame_ms, frames })
}

/// Taille standard d'un curseur, façon Windows (flèche par défaut à 100%) —
/// tout .sluc/.slun chargé est ramené à cette taille, quelle que soit sa
/// résolution native d'origine.
const STANDARD_CURSOR_SIZE: i32 = 32;

/// Moyenne alpha-pondérée de la zone [x0,x1)×[y0,y1) d'une grille ARGB dense.
/// Pondérer par alpha évite d'assombrir les bords avec la couleur de fond
/// transparente (mêmes maths que le pipeline de conversion PNG hors-ligne).
fn average_region(grid: &[u32], src_w: i32, x0: i32, x1: i32, y0: i32, y1: i32) -> (u32, u32, u32, u32) {
    let (mut rs, mut gs, mut bs, mut as_, mut n) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for yy in y0..y1 {
        for xx in x0..x1 {
            let c = grid[(yy * src_w + xx) as usize];
            let a = (c >> 24) & 0xFF; let r = (c >> 16) & 0xFF; let g = (c >> 8) & 0xFF; let b = c & 0xFF;
            rs += r as u64 * a as u64; gs += g as u64 * a as u64; bs += b as u64 * a as u64;
            as_ += a as u64; n += 1;
        }
    }
    if as_ == 0 { return (0, 0, 0, 0); }
    ((rs / as_) as u32, (gs / as_) as u32, (bs / as_) as u32, (as_ / n.max(1)) as u32)
}

/// Ré-échantillonne (moyenne de zone) une frame composée de <rect> pixel-exacts
/// (format émis par notre propre pipeline de conversion PNG→.sluc) de src×src
/// vers dst×dst, ré-encodés en <rect> RLE horizontaux. Retourne None si la frame
/// ne contient aucun <rect> exploitable — contenu vectoriel (circle/polygon/path),
/// laissé à sa taille native : il se redimensionne correctement via le mécanisme
/// SVG générique (sx/sy), contrairement à des rects de 1px qui tronquent à 0.
fn resample_rect_frame(svg: &str, src_w: i32, src_h: i32, dst: i32) -> Option<String> {
    if src_w <= 0 || src_h <= 0 || dst <= 0 { return None; }
    let mut grid: Vec<u32> = alloc::vec![0u32; (src_w * src_h) as usize];
    let mut found_rect = false;

    let mut pos = 0usize;
    while let Some(lt) = svg[pos..].find('<') {
        let abs = pos + lt;
        let gt = svg[abs..].find('>').map(|g| abs + g + 1).unwrap_or(svg.len());
        let tag = &svg[abs..gt];
        if tag.starts_with("<rect") {
            found_rect = true;
            let x = svg_num(svg_attr(tag, "x")) / 1000;
            let y = svg_num(svg_attr(tag, "y")) / 1000;
            let w = svg_num(svg_attr(tag, "width")) / 1000;
            let h = svg_num(svg_attr(tag, "height")) / 1000;
            let color = svg_color(svg_attr(tag, "fill"));
            for py in y..(y + h) {
                if py < 0 || py >= src_h { continue; }
                for px in x..(x + w) {
                    if px < 0 || px >= src_w { continue; }
                    grid[(py * src_w + px) as usize] = color;
                }
            }
        }
        pos = gt;
        if pos >= svg.len() { break; }
    }
    if !found_rect { return None; }

    let map_range = |i: i32, src: i32| -> (i32, i32) {
        let a0 = i * src / dst;
        let num = (i + 1) * src;
        let mut a1 = num / dst;
        if num % dst != 0 { a1 += 1; }
        (a0, a1.max(a0 + 1).min(src))
    };

    let mut out = String::new();
    out.push_str(&alloc::format!("<svg viewBox=\"0 0 {} {}\">\n", dst, dst));
    for dy in 0..dst {
        let (sy0, sy1) = map_range(dy, src_h);
        let mut dx = 0i32;
        while dx < dst {
            let (sx0, sx1) = map_range(dx, src_w);
            let (r, g, b, a) = average_region(&grid, src_w, sx0, sx1, sy0, sy1);
            let mut run = 1i32;
            loop {
                let ndx = dx + run;
                if ndx >= dst { break; }
                let (nsx0, nsx1) = map_range(ndx, src_w);
                if average_region(&grid, src_w, nsx0, nsx1, sy0, sy1) != (r, g, b, a) { break; }
                run += 1;
            }
            if a > 0 {
                out.push_str(&alloc::format!(
                    "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"1\" fill=\"#{:02X}{:02X}{:02X}{:02X}\"/>\n",
                    dx, dy, run, r, g, b, a));
            }
            dx += run;
        }
    }
    out.push_str("</svg>\n");
    Some(out)
}

static SIN_Q1: [i16; 91] = [
       0,   17,   35,   52,   70,   87,  105,  122,  139,  156,
     174,  191,  208,  225,  242,  259,  276,  292,  309,  326,
     342,  358,  375,  391,  407,  423,  438,  454,  469,  485,
     500,  515,  530,  545,  559,  574,  588,  602,  616,  629,
     643,  656,  669,  682,  695,  707,  719,  731,  743,  755,
     766,  777,  788,  799,  809,  819,  829,  839,  848,  857,
     866,  875,  883,  891,  899,  906,  914,  921,  927,  934,
     940,  946,  951,  956,  961,  966,  970,  974,  978,  982,
     985,  988,  990,  993,  995,  997,  998,  999, 1000, 1000, 1000,
];

fn sin_i(deg: i32) -> i32 {
    let d = ((deg % 360) + 360) % 360;
    if d <= 90      {  SIN_Q1[d as usize] as i32 }
    else if d <= 180 {  SIN_Q1[(180-d) as usize] as i32 }
    else if d <= 270 { -(SIN_Q1[(d-180) as usize] as i32) }
    else             { -(SIN_Q1[(360-d) as usize] as i32) }
}
#[inline] fn cos_i(deg: i32) -> i32 { sin_i(deg + 90) }

fn isqrt(n: u32) -> u32 {
    if n == 0 { return 0; }
    let mut r = n; let mut last = u32::MAX;
    while r < last { last = r; r = (r + n / r) / 2; }
    last
}

#[inline]
unsafe fn gpu_write_pixel(fb: *mut u32, idx: usize, sr: u32, sg: u32, sb: u32, sa: u32) {
    let eff_a = sa * GPU_OPACITY / 255;
    if eff_a == 0 { return; }
    if eff_a >= 255 && GPU_BLEND_MODE == 0 {
        fb.add(idx).write_volatile(0xFF000000 | (sr << 16) | (sg << 8) | sb);
        return;
    }
    let dst = fb.add(idx).read_volatile();
    let db = (dst & 0xFF) as u32; let dg = ((dst >> 8) & 0xFF) as u32; let dr = ((dst >> 16) & 0xFF) as u32;
    let ia = 255u32.saturating_sub(eff_a);
    // Helpers blend mode — travail en i32 pour les formules signées
    let blend = |s: u32, d: u32| -> u32 {
        let (s, d) = (s as i32, d as i32);
        let r: i32 = match GPU_BLEND_MODE {
            1 => s * d / 255,                              // Multiply
            2 => 255 - (255 - s) * (255 - d) / 255,       // Screen
            3 => if d < 128 { 2*s*d/255 } else { 255 - 2*(255-s)*(255-d)/255 }, // Overlay
            4 => s.min(d),                                 // Darken
            5 => s.max(d),                                 // Lighten
            6 => if s >= 255 { 255 } else { (d * 255 / (255 - s)).min(255) }, // Color Dodge
            7 => if s <= 0   { 0   } else { (255 - ((255-d)*255/s)).max(0) }, // Color Burn
            8 => if s < 128 { 2*s*d/255 } else { 255 - 2*(255-s)*(255-d)/255 }, // Hard Light
            9 => {                                         // Soft Light (Pegtop formula)
                let d2 = d * d / 255;
                if s < 128 { d - (255-2*s)*(d-d2)/255 } else { d + (2*s-255)*(4*d/255*(4*d/255+1)*(d-255)+255*d/255)/255 }
            },
            10 => (s - d).abs(),                           // Difference
            11 => s + d - 2*s*d/255,                       // Exclusion
            _ => s,                                        // fallback (utilisé dans Normal ci-dessous)
        };
        r.max(0).min(255) as u32
    };
    let (nr, ng, nb) = match GPU_BLEND_MODE {
        0 => ((sr*eff_a+dr*ia)/255, (sg*eff_a+dg*ia)/255, (sb*eff_a+db*ia)/255), // Normal
        _ => {
            let br = blend(sr, dr); let bg2 = blend(sg, dg); let bb = blend(sb, db);
            (br*eff_a/255+dr*ia/255, bg2*eff_a/255+dg*ia/255, bb*eff_a/255+db*ia/255)
        },
    };
    fb.add(idx).write_volatile(0xFF000000|(nr.min(255)<<16)|(ng.min(255)<<8)|nb.min(255));
}

/// Applique la transformation 2D courante à un point (x, y) → (x', y').
#[inline]
/// Échantillonne (r,g,b,a) dans une image RGBA avec moyenne de bloc quand on
/// RÉDUIT — l'échantillonnage nearest décime les glyphes (icônes en pointillés)
/// dès que l'image source est plus grande que la zone de destination.
/// Moyenne PRÉMULTIPLIÉE par l'alpha : sans ça les pixels transparents (RGB=0)
/// assombrissent les bords des glyphes.
#[inline]
unsafe fn img_sample_box(pp: *const u8, iw: u32, ih: u32, lx: i32, ly: i32, dw: i32, dh: i32) -> (u32, u32, u32, u32) {
    let dw = dw.max(1); let dh = dh.max(1);
    let kx = (iw as i32 / dw).clamp(1, 12);
    let ky = (ih as i32 / dh).clamp(1, 12);
    let sx0 = (lx as i64 * iw as i64 / dw as i64) as i32;
    let sy0 = (ly as i64 * ih as i64 / dh as i64) as i32;
    let (mut r, mut g, mut b, mut a, mut n) = (0u32, 0u32, 0u32, 0u32, 0u32);
    for oy in 0..ky {
        let sy = (sy0 + oy).clamp(0, ih as i32 - 1) as usize;
        for ox in 0..kx {
            let sx = (sx0 + ox).clamp(0, iw as i32 - 1) as usize;
            let o = (sy * iw as usize + sx) * 4;
            let pa = *pp.add(o + 3) as u32;
            r += *pp.add(o) as u32 * pa;
            g += *pp.add(o + 1) as u32 * pa;
            b += *pp.add(o + 2) as u32 * pa;
            a += pa;
            n += 1;
        }
    }
    if n == 0 || a == 0 { return (0, 0, 0, 0); }
    (r / a, g / a, b / a, a / n)
}

unsafe fn gpu_transform_point(x: i32, y: i32) -> (i32, i32) {
    if !GPU_TRANSFORM_ACTIVE { return (x, y); }
    let t = &GPU_TRANSFORM;
    let xp = t[0]*x/10000 + t[2]*y/10000 + t[4];
    let yp = t[1]*x/10000 + t[3]*y/10000 + t[5];
    (xp, yp)
}

fn box_blur_region(fb: *mut u32, stride: i32, x: i32, y: i32, w: i32, h: i32, r: i32) {
    if w <= 0 || h <= 0 || r <= 0 { return; }
    let total = (w * h) as usize;
    if total > 512 * 512 { return; }
    let mut buf: alloc::vec::Vec<u32> = alloc::vec::Vec::with_capacity(total);
    for py in 0..h { for px in 0..w { buf.push(unsafe { fb.add(((y+py)*stride+x+px) as usize).read_volatile() }); } }
    for _ in 0..3 {
        let src = buf.clone();
        for py in 0..h as usize { for px in 0..w as usize {
            let x0=(px as i32-r).max(0) as usize; let x1=(px as i32+r).min(w-1) as usize; let cnt=(x1-x0+1) as u32;
            let (mut sr,mut sg,mut sb)=(0u32,0u32,0u32);
            for sx in x0..=x1 { let c=src[py*w as usize+sx]; sr+=(c>>16)&0xFF; sg+=(c>>8)&0xFF; sb+=c&0xFF; }
            buf[py*w as usize+px]=0xFF000000|((sr/cnt)<<16)|((sg/cnt)<<8)|(sb/cnt);
        }}
    }
    for _ in 0..3 {
        let src = buf.clone();
        for py in 0..h as usize { for px in 0..w as usize {
            let y0=(py as i32-r).max(0) as usize; let y1=(py as i32+r).min(h-1) as usize; let cnt=(y1-y0+1) as u32;
            let (mut sr,mut sg,mut sb)=(0u32,0u32,0u32);
            for sy in y0..=y1 { let c=src[sy*w as usize+px]; sr+=(c>>16)&0xFF; sg+=(c>>8)&0xFF; sb+=c&0xFF; }
            buf[py*w as usize+px]=0xFF000000|((sr/cnt)<<16)|((sg/cnt)<<8)|(sb/cnt);
        }}
    }
    for py in 0..h { for px in 0..w { unsafe { fb.add(((y+py)*stride+x+px) as usize).write_volatile(buf[(py*w+px) as usize]); } } }
}

/// Flou d'arrière-plan découpé selon un rectangle arrondi tourné (transformation active).
/// Même box blur 3-pass que box_blur_region, mais appliqué sur la bbox destination du rect
/// tourné (coins transformés vers l'avant) et écrit UNIQUEMENT sur les pixels dont la
/// transformation inverse retombe dans le rectangle arrondi source — le flou lit ses voisins
/// normalement (pas d'artefact de bord), mais ne "fuit" pas hors de la silhouette tournée.
fn box_blur_region_masked_rotated(
    fb: *mut u32, stride: i32, sw: i32, sh: i32,
    x: i32, y: i32, w: i32, h: i32, radius: i32,
    t: [i32; 6], blur_r: i32,
) {
    if w <= 0 || h <= 0 || blur_r <= 0 { return; }
    let (ta, tb, tc, td, ttx, tty) = (t[0], t[1], t[2], t[3], t[4], t[5]);
    let corners = [(x, y), (x + w, y), (x, y + h), (x + w, y + h)];
    let mut min_fx = i32::MAX; let mut max_fx = i32::MIN;
    let mut min_fy = i32::MAX; let mut max_fy = i32::MIN;
    for &(cx, cy) in corners.iter() {
        let fx = ta * cx / 10000 + tc * cy / 10000 + ttx;
        let fy = tb * cx / 10000 + td * cy / 10000 + tty;
        if fx < min_fx { min_fx = fx; } if fx > max_fx { max_fx = fx; }
        if fy < min_fy { min_fy = fy; } if fy > max_fy { max_fy = fy; }
    }
    min_fx = min_fx.max(0); max_fx = max_fx.min(sw - 1);
    min_fy = min_fy.max(0); max_fy = max_fy.min(sh - 1);
    let bw = max_fx - min_fx + 1;
    let bh = max_fy - min_fy + 1;
    if bw <= 0 || bh <= 0 { return; }
    let total = (bw * bh) as usize;
    if total > 512 * 512 { return; }
    let mut buf: alloc::vec::Vec<u32> = alloc::vec::Vec::with_capacity(total);
    for py in 0..bh { for px in 0..bw {
        buf.push(unsafe { fb.add(((min_fy + py) * stride + min_fx + px) as usize).read_volatile() });
    }}
    for _ in 0..3 {
        let src = buf.clone();
        for py in 0..bh as usize { for px in 0..bw as usize {
            let x0 = (px as i32 - blur_r).max(0) as usize; let x1 = (px as i32 + blur_r).min(bw - 1) as usize; let cnt = (x1 - x0 + 1) as u32;
            let (mut sr, mut sg, mut sb) = (0u32, 0u32, 0u32);
            for sx in x0..=x1 { let c = src[py * bw as usize + sx]; sr += (c >> 16) & 0xFF; sg += (c >> 8) & 0xFF; sb += c & 0xFF; }
            buf[py * bw as usize + px] = 0xFF000000 | ((sr / cnt) << 16) | ((sg / cnt) << 8) | (sb / cnt);
        }}
    }
    for _ in 0..3 {
        let src = buf.clone();
        for py in 0..bh as usize { for px in 0..bw as usize {
            let y0 = (py as i32 - blur_r).max(0) as usize; let y1 = (py as i32 + blur_r).min(bh - 1) as usize; let cnt = (y1 - y0 + 1) as u32;
            let (mut sr, mut sg, mut sb) = (0u32, 0u32, 0u32);
            for sy in y0..=y1 { let c = src[sy * bw as usize + px]; sr += (c >> 16) & 0xFF; sg += (c >> 8) & 0xFF; sb += c & 0xFF; }
            buf[py * bw as usize + px] = 0xFF000000 | ((sr / cnt) << 16) | ((sg / cnt) << 8) | (sb / cnt);
        }}
    }
    let (ta64, tb64, tc64, td64) = (ta as i64, tb as i64, tc as i64, td as i64);
    let det = ta64 * td64 - tc64 * tb64;
    if det == 0 { return; }
    let r2 = radius * radius;
    for py in 0..bh {
        for px in 0..bw {
            let fx = min_fx + px; let fy = min_fy + py;
            let dx = (fx - ttx) as i64;
            let dy = (fy - tty) as i64;
            let lx = ((td64 * dx - tc64 * dy) * 10000 / det) as i32 - x;
            let ly = ((-tb64 * dx + ta64 * dy) * 10000 / det) as i32 - y;
            if lx < 0 || lx >= w || ly < 0 || ly >= h { continue; }
            if radius > 0 {
                let el = radius - lx; let er = lx - (w - radius) + 1;
                let cdx = if el > 0 { el } else if er > 0 { er } else { 0 };
                let et = radius - ly; let eb = ly - (h - radius) + 1;
                let cdy = if et > 0 { et } else if eb > 0 { eb } else { 0 };
                if cdx > 0 && cdy > 0 && cdx * cdx + cdy * cdy > r2 { continue; }
            }
            let idx = (fy * stride + fx) as usize;
            unsafe { fb.add(idx).write_volatile(buf[(py * bw + px) as usize]); }
        }
    }
}

pub fn reset_gpu_counters() {
    unsafe { GPU_FILLS = 0; GPU_RECTS = 0; GPU_TEXTS = 0; CURSOR_TICK += 1; }
}

/// Remet à zéro l'état GPU process-wide (opacité, blend mode, transformation
/// 2D, pile de clip). Ces `static mut` (ligne ~529) sont partagés par TOUS les
/// appels `exec_marep` — jusqu'ici sans conséquence puisqu'un seul appel avait
/// lieu par tick ; à appeler avant CHAQUE appel `exec_marep` dès qu'un 2e
/// `.marep` tourne dans le même tick (plan bureau à fenêtres, jalon 1 étape 3),
/// pour qu'un `Set*` sans `Reset*` côté Mara dans une app ne fuite pas vers
/// l'autre. Ne protège pas un plantage à mi-`Render`, avant son propre
/// `GpuReset*` interne — risque documenté séparément (mémoire projet).
pub fn reset_gpu_state() {
    unsafe {
        GPU_OPACITY = 255;
        GPU_BLEND_MODE = 0;
        GPU_TRANSFORM = [10000, 0, 0, 10000, 0, 0];
        GPU_TRANSFORM_ACTIVE = false;
        CLIP_DEPTH = 0;
    }
}
pub fn gpu_counters() -> (u32, u32, u32) {
    unsafe { (GPU_FILLS, GPU_RECTS, GPU_TEXTS) }
}

// ── Helpers SVG minimal ───────────────────────────────────────────────────────

/// Cherche `attr="value"` ou `attr='value'` dans un tag XML et retourne la valeur.
fn svg_attr<'a>(tag: &'a str, attr: &str) -> &'a str {
    let mut pos = 0usize;
    while let Some(i) = tag[pos..].find(attr) {
        let abs = pos + i;
        // Vérifier qu'il s'agit bien de cet attribut (précédé d'espace ou de début)
        let before = if abs == 0 { b' ' } else { tag.as_bytes()[abs - 1] };
        if !before.is_ascii_alphanumeric() && before != b'-' {
            let after = abs + attr.len();
            if after < tag.len() && (tag.as_bytes()[after] == b'=' || tag.as_bytes()[after] == b' ') {
                let eq = tag[after..].find('=').map(|e| after + e).unwrap_or(tag.len());
                if eq + 1 < tag.len() {
                    let q = tag.as_bytes()[eq + 1];
                    if q == b'"' || q == b'\'' {
                        let start = eq + 2;
                        if let Some(end) = tag[start..].find(q as char) {
                            return &tag[start..start + end];
                        }
                    }
                }
            }
        }
        pos = abs + 1;
    }
    ""
}

/// Parse une couleur SVG (#RRGGBB, #RGB, rgb(r,g,b)) → 0xAARRGGBB (A=255) ou 0.
fn svg_color(s: &str) -> u32 {
    let s = s.trim();
    if s.is_empty() || s == "none" || s == "transparent" { return 0; }
    if s.starts_with('#') {
        let h = &s[1..];
        if h.len() == 6 {
            let v = u32::from_str_radix(h, 16).unwrap_or(0);
            return 0xFF000000 | v;
        }
        if h.len() == 3 {
            let rb = h.as_bytes();
            let r = u8::from_str_radix(core::str::from_utf8(&[rb[0],rb[0]]).unwrap_or("0"), 16).unwrap_or(0);
            let g = u8::from_str_radix(core::str::from_utf8(&[rb[1],rb[1]]).unwrap_or("0"), 16).unwrap_or(0);
            let b = u8::from_str_radix(core::str::from_utf8(&[rb[2],rb[2]]).unwrap_or("0"), 16).unwrap_or(0);
            return 0xFF000000 | ((r as u32) << 16) | ((g as u32) << 8) | b as u32;
        }
        // #RRGGBBAA — extension non-standard SVG mais nécessaire pour reproduire
        // fidèlement (pixel-perfect, alpha inclus) un PNG source dans un .sluc/.slun ;
        // sans elle, tout canal alpha partiel (bords anti-aliasés, ombre floue)
        // retombe sur le défaut opaque noir de svg_color (cf. plus bas).
        if h.len() == 8 {
            let v = u32::from_str_radix(h, 16).unwrap_or(0);
            let a = v & 0xFF;
            return (a << 24) | (v >> 8);
        }
    }
    if s.starts_with("rgb(") && s.ends_with(')') {
        let inner = &s[4..s.len()-1];
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() == 3 {
            let r = parts[0].trim().parse::<u32>().unwrap_or(0).min(255);
            let g = parts[1].trim().parse::<u32>().unwrap_or(0).min(255);
            let b = parts[2].trim().parse::<u32>().unwrap_or(0).min(255);
            return 0xFF000000 | (r << 16) | (g << 8) | b;
        }
    }
    // Couleurs nommées essentielles
    match s {
        "black"   => 0xFF000000, "white"  => 0xFFFFFFFF,
        "red"     => 0xFFFF0000, "green"  => 0xFF008000,
        "blue"    => 0xFF0000FF, "yellow" => 0xFFFFFF00,
        "cyan"    => 0xFF00FFFF, "magenta"=> 0xFFFF00FF,
        "gray"    => 0xFF808080, "grey"   => 0xFF808080,
        "orange"  => 0xFFFFA500, "purple" => 0xFF800080,
        _         => 0xFF000000,
    }
}

/// Parse un nombre flottant textuel → millièmes entiers (1.5 → 1500).
fn svg_num(s: &str) -> i32 {
    let s = s.trim();
    if s.is_empty() { return 0; }
    let (sign, s) = if s.starts_with('-') { (-1i32, &s[1..]) } else { (1, s) };
    // Notation scientifique (exports Figma : "2.00272e-05") — mantisse + exposant.
    let (s, exp) = match s.find(|c| c == 'e' || c == 'E') {
        Some(p) => (&s[..p], s[p+1..].parse::<i32>().unwrap_or(0)),
        None => (s, 0),
    };
    let dot = s.find('.').unwrap_or(s.len());
    let int_part: i32 = s[..dot].parse().unwrap_or(0);
    let frac_str = if dot < s.len() { &s[dot+1..] } else { "" };
    let frac: i32 = match frac_str.len() {
        0 => 0,
        1 => frac_str.parse::<i32>().unwrap_or(0) * 100,
        2 => frac_str.parse::<i32>().unwrap_or(0) * 10,
        _ => frac_str[..3].parse().unwrap_or(0),
    };
    let mut val = sign * (int_part * 1000 + frac);
    let mut e = exp;
    while e > 0 && val.abs() < i32::MAX / 10 { val *= 10; e -= 1; }
    while e < 0 && val != 0 { val /= 10; e += 1; }
    val
}

/// Dessine un segment en CAPSULE (bouts ronds + anti-aliasing au bord).
/// Les exports Figma utilisent stroke-linecap="round" : l'ancien tampon carré
/// de Bresenham donnait des bouts carrés sur toutes les barres/pilules
/// (soulignés de titres, accents de tuiles) et des joints crénelés sur les
/// contours de paths. Rendu par distance au segment, fixed-point 1/8 px.
fn svg_draw_line(fb: *mut u32, stride: i32, width: i32, height: i32,
                 x0: i32, y0: i32, x1: i32, y1: i32, color: u32, wt: i32) {
    if color == 0 || wt <= 0 { return; }
    let base_alpha = (color >> 24) & 0xFF;
    if base_alpha == 0 { return; }
    let sr = (color >> 16) & 0xFF; let sg = (color >> 8) & 0xFF; let sb = color & 0xFF;
    const F: i64 = 8;                       // 1/8 px
    let hw8 = (wt as i64 * F) / 2;          // demi-largeur
    let (ax8, ay8) = (x0 as i64 * F, y0 as i64 * F);
    let (dx8, dy8) = ((x1 - x0) as i64 * F, (y1 - y0) as i64 * F);
    let len2 = dx8 * dx8 + dy8 * dy8;
    let pad = wt / 2 + 2;
    let bx0 = (x0.min(x1) - pad).max(0);
    let bx1 = (x0.max(x1) + pad).min(width - 1);
    let by0 = (y0.min(y1) - pad).max(0);
    let by1 = (y0.max(y1) + pad).min(height - 1);
    let r_in  = (hw8 - F / 2).max(0);       // plein en deçà
    let r_out = hw8 + F / 2;                // transparent au-delà
    for py in by0..=by1 {
        for px in bx0..=bx1 {
            let vx = px as i64 * F + F / 2 - ax8;
            let vy = py as i64 * F + F / 2 - ay8;
            // Point le plus proche sur le segment (t borné à [0,1])
            let (nx, ny) = if len2 == 0 { (0i64, 0i64) } else {
                let t = (vx * dx8 + vy * dy8).clamp(0, len2);
                (dx8 * t / len2, dy8 * t / len2)
            };
            let ddx = vx - nx; let ddy = vy - ny;
            let d2 = (ddx * ddx + ddy * ddy) as u64;
            if d2 > (r_out * r_out) as u64 { continue; }
            // AA linéaire sur la couronne [r_in, r_out]
            let alpha = if d2 <= (r_in * r_in) as u64 { base_alpha } else {
                let d = isqrt(d2 as u32) as i64;
                (base_alpha as i64 * (r_out - d).max(0) / (r_out - r_in).max(1)) as u32
            };
            if alpha == 0 { continue; }
            let ia = 255 - alpha;
            let di = (py * stride + px) as usize;
            let dst = unsafe { fb.add(di).read_volatile() };
            let db = (dst & 0xFF) as u32; let dg = ((dst >> 8) & 0xFF) as u32; let dr = ((dst >> 16) & 0xFF) as u32;
            let nr = (sr * alpha + dr * ia) / 255; let ng = (sg * alpha + dg * ia) / 255; let nb = (sb * alpha + db * ia) / 255;
            unsafe { fb.add(di).write_volatile(0xFF000000 | (nr << 16) | (ng << 8) | nb); }
        }
    }
}

/// Dessine un cercle rempli (fill) et/ou contour (stroke) à l'écran.
fn svg_draw_circle(fb: *mut u32, stride: i32, width: i32, height: i32,
                   cx: i32, cy: i32, r: i32, fill: u32, stroke: u32, wt: i32) {
    let r2 = r * r;
    let out_r = r + wt; let out_r2 = out_r * out_r;
    let in_r  = (r - wt).max(0); let in_r2 = in_r * in_r;
    for py in (cy - out_r)..=(cy + out_r) {
        if py < 0 || py >= height { continue; }
        for px in (cx - out_r)..=(cx + out_r) {
            if px < 0 || px >= width { continue; }
            let dx2 = (px - cx) * (px - cx); let dy2 = (py - cy) * (py - cy);
            let d2 = dx2 + dy2;
            let color = if d2 <= in_r2 { fill }
                        else if d2 <= r2 { fill }
                        else if d2 <= out_r2 && stroke != 0 { stroke }
                        else { 0 };
            if color == 0 { continue; }
            let alpha = (color >> 24) & 0xFF; if alpha == 0 { continue; }
            let ia = 255 - alpha;
            let sr = (color >> 16) & 0xFF; let sg = (color >> 8) & 0xFF; let sb = color & 0xFF;
            let di = (py * stride + px) as usize;
            let dst = unsafe { fb.add(di).read_volatile() };
            let db = (dst & 0xFF) as u32; let dg = ((dst >> 8) & 0xFF) as u32; let dr = ((dst >> 16) & 0xFF) as u32;
            let nr = (sr * alpha + dr * ia) / 255; let ng = (sg * alpha + dg * ia) / 255; let nb = (sb * alpha + db * ia) / 255;
            unsafe { fb.add(di).write_volatile(0xFF000000 | (nr << 16) | (ng << 8) | nb); }
        }
    }
}

/// Rend un tag SVG unique vers le framebuffer, coordonnées déjà en pixels écran.
/// ox/oy = offset, sx/sy = facteur d'échelle en millièmes (1000 = 1:1).
// ── Defs SVG (exports Figma) : dégradés, patterns image, images base64 ───────
// Figma exporte les barres en stroke url(#linearGradient), et les icônes/formes
// texturées en fill url(#pattern) → <use href="#image"> → <image base64 PNG>.
// Sans résolution de ces refs, svg_color retombait sur du noir opaque (barres
// noires) ou rien du tout (formes invisibles).
struct SvgDefs {
    gradients: Vec<(String, u32)>,       // id → couleur moyenne ARGB des stops
    patterns:  Vec<(String, usize)>,     // id → index dans images
    images:    Vec<(u32, u32, Vec<u8>)>, // (w, h, RGBA décodé)
}

enum SvgPaint { None, Color(u32), Pattern(usize) }

/// Multiplie le canal alpha d'une couleur ARGB par milli/1000.
fn svg_scale_alpha(c: u32, milli: i32) -> u32 {
    if c == 0 { return 0; }
    let a = ((c >> 24) & 0xFF) as i32 * milli.clamp(0, 1000) / 1000;
    ((a as u32) << 24) | (c & 0x00FF_FFFF)
}

/// Attribut d'opacité en millièmes (absent → 1000).
fn svg_opacity(tag: &str, attr: &str) -> i32 {
    let o = svg_attr(tag, attr);
    if o.is_empty() { 1000 } else { svg_num(o).clamp(0, 1000) }
}

fn svg_paint(s: &str, defs: &SvgDefs) -> SvgPaint {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("url(#") {
        let id = rest.trim_end_matches(')').trim();
        for (gid, c) in defs.gradients.iter() {
            if gid == id { return SvgPaint::Color(*c); }
        }
        for (pid, img) in defs.patterns.iter() {
            if pid == id { return SvgPaint::Pattern(*img); }
        }
        return SvgPaint::None;
    }
    let c = svg_color(s);
    if c == 0 { SvgPaint::None } else { SvgPaint::Color(c) }
}

fn b64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> i32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as i32,
            b'a'..=b'z' => (c - b'a') as i32 + 26,
            b'0'..=b'9' => (c - b'0') as i32 + 52,
            b'+' => 62, b'/' => 63, b'=' => -1, _ => -2,
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut nbits = 0u32;
    for &c in s.as_bytes() {
        let v = val(c);
        if v == -2 { continue; }  // espaces/retours ligne
        if v == -1 { break; }     // padding '='
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 { nbits -= 8; out.push((acc >> nbits) as u8); }
    }
    out
}

/// Scanne les <defs> d'un SVG : dégradés (→ couleur moyenne), patterns et images.
fn svg_scan_defs(text: &str) -> SvgDefs {
    let mut gradients: Vec<(String, u32)> = Vec::new();
    let mut patterns_raw: Vec<(String, String)> = Vec::new(); // pid → image id
    let mut images_raw: Vec<(String, u32, u32, Vec<u8>)> = Vec::new();
    let mut cur_grad: Option<(String, Vec<u32>)> = None;
    let mut cur_pattern: Option<String> = None;
    let mut pos = 0usize;
    while let Some(lt) = text[pos..].find('<') {
        let abs = pos + lt;
        let gt = text[abs..].find('>').map(|g| abs + g + 1).unwrap_or(text.len());
        let tag = &text[abs..gt];
        pos = gt;
        let inner = tag.trim_start_matches('<');
        if inner.starts_with("linearGradient") || inner.starts_with("radialGradient") {
            cur_grad = Some((svg_attr(tag, "id").to_string(), Vec::new()));
        } else if inner.starts_with("/linearGradient") || inner.starts_with("/radialGradient") {
            if let Some((id, stops)) = cur_grad.take() {
                if !stops.is_empty() {
                    let n = stops.len() as u32;
                    let (mut a, mut r, mut g, mut b) = (0u32, 0u32, 0u32, 0u32);
                    for c in stops.iter() {
                        a += (c >> 24) & 0xFF; r += (c >> 16) & 0xFF;
                        g += (c >> 8) & 0xFF;  b += c & 0xFF;
                    }
                    gradients.push((id, ((a / n) << 24) | ((r / n) << 16) | ((g / n) << 8) | (b / n)));
                }
            }
        } else if inner.starts_with("stop") {
            if let Some((_, ref mut stops)) = cur_grad {
                let mut c = svg_color(svg_attr(tag, "stop-color"));
                if c == 0 { c = 0xFF000000; }
                let so = svg_attr(tag, "stop-opacity");
                if !so.is_empty() { c = svg_scale_alpha(c, svg_num(so)); }
                stops.push(c);
            }
        } else if inner.starts_with("pattern") {
            cur_pattern = Some(svg_attr(tag, "id").to_string());
        } else if inner.starts_with("/pattern") {
            cur_pattern = None;
        } else if inner.starts_with("use") {
            if let Some(ref pid) = cur_pattern {
                let h = svg_attr(tag, "xlink:href");
                let href = if h.is_empty() { svg_attr(tag, "href") } else { h };
                patterns_raw.push((pid.clone(), href.trim_start_matches('#').to_string()));
            }
        } else if inner.starts_with("image") {
            let id = svg_attr(tag, "id").to_string();
            let h = svg_attr(tag, "xlink:href");
            let href = if h.is_empty() { svg_attr(tag, "href") } else { h };
            if let Some(b64) = href.strip_prefix("data:image/png;base64,") {
                let bytes = b64_decode(b64);
                if let Some((iw, ih, rgba)) = png_decode_rgba(&bytes) {
                    images_raw.push((id, iw, ih, rgba));
                }
            }
        }
    }
    let mut defs = SvgDefs { gradients, patterns: Vec::new(), images: Vec::new() };
    for (pid, img_id) in patterns_raw {
        if let Some(pos_img) = images_raw.iter().position(|(id, _, _, _)| *id == img_id) {
            // L'image est déplacée à la demande dans defs.images (une seule référence)
            let (_, iw, ih, rgba) = images_raw[pos_img].clone();
            defs.patterns.push((pid, defs.images.len()));
            defs.images.push((iw, ih, rgba));
        }
    }
    defs
}

fn svg_render_element(fb: *mut u32, stride: i32, width: i32, height: i32,
                      tag: &str, ox: i32, oy: i32, sx: i32, sy: i32, defs: &SvgDefs) {
    let name_end = tag.find(|c: char| c.is_ascii_whitespace() || c == '/').unwrap_or(tag.len());
    let tag_name = tag[..name_end].trim_start_matches('<').trim();

    let sc = |v: i32, s: i32| -> i32 { v * s / 1000 };

    match tag_name {
        "rect" => {
            let x  = sc(svg_num(svg_attr(tag, "x"))     / 1000, sx) + ox;
            let y  = sc(svg_num(svg_attr(tag, "y"))     / 1000, sy) + oy;
            let w  = sc(svg_num(svg_attr(tag, "width")) / 1000, sx);
            let h  = sc(svg_num(svg_attr(tag, "height"))/ 1000, sy);
            let rx = svg_num(svg_attr(tag, "rx")) / 1000;
            let op = svg_opacity(tag, "opacity");
            let fill = match svg_paint(svg_attr(tag, "fill"), defs) {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "fill-opacity") / 1000),
                _ => 0,
            };
            let stroke = match svg_paint(svg_attr(tag, "stroke"), defs) {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "stroke-opacity") / 1000),
                _ => 0,
            };
            let swt    = ((svg_num(svg_attr(tag, "stroke-width")) * ((sx + sy) / 2) + 500000) / 1000000).max(if stroke != 0 { 1 } else { 0 });
            let r2 = rx * rx;
            if fill != 0 {
                let fa = (fill >> 24) & 0xFF; let ia = 255 - fa;
                let fr = (fill >> 16) & 0xFF; let fg = (fill >> 8) & 0xFF; let fb2 = fill & 0xFF;
                for py in 0..h { let fy = y + py; if fy < 0 || fy >= height { continue; }
                    for px in 0..w { let fx = x + px; if fx < 0 || fx >= width { continue; }
                        if rx > 0 {
                            let cdx = if px < rx { rx - px } else if px >= w - rx { px - (w - rx - 1) } else { 0 };
                            let cdy = if py < rx { rx - py } else if py >= h - rx { py - (h - rx - 1) } else { 0 };
                            if cdx > 0 && cdy > 0 && cdx*cdx + cdy*cdy > r2 { continue; }
                        }
                        let di = (fy * stride + fx) as usize;
                        let dst = unsafe { fb.add(di).read_volatile() };
                        let db = (dst & 0xFF) as u32; let dg = ((dst >> 8) & 0xFF) as u32; let dr = ((dst >> 16) & 0xFF) as u32;
                        let nr = (fr * fa + dr * ia) / 255; let ng_ = (fg * fa + dg * ia) / 255; let nb = (fb2 * fa + db * ia) / 255;
                        unsafe { fb.add(di).write_volatile(0xFF000000 | (nr << 16) | (ng_ << 8) | nb); }
                    }
                }
            }
            if stroke != 0 && swt > 0 {
                // 4 côtés
                for t in 0..swt {
                    for px in x..x+w { for off in [t, h-1-t] {
                        let fy = y + off; let fx = px;
                        if fx < 0 || fx >= width || fy < 0 || fy >= height { continue; }
                        let alpha = (stroke>>24)&0xFF; let ia = 255-alpha;
                        let sr = (stroke>>16)&0xFF; let sg = (stroke>>8)&0xFF; let sb = stroke&0xFF;
                        let di = (fy*stride+fx) as usize;
                        let dst = unsafe { fb.add(di).read_volatile() };
                        let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                        unsafe { fb.add(di).write_volatile(0xFF000000|((sr*alpha+dr*ia)/255<<16)|((sg*alpha+dg*ia)/255<<8)|(sb*alpha+db*ia)/255); }
                    }}
                    for py in y..y+h { for off in [t, w-1-t] {
                        let fy = py; let fx = x + off;
                        if fx < 0 || fx >= width || fy < 0 || fy >= height { continue; }
                        let alpha = (stroke>>24)&0xFF; let ia = 255-alpha;
                        let sr = (stroke>>16)&0xFF; let sg = (stroke>>8)&0xFF; let sb = stroke&0xFF;
                        let di = (fy*stride+fx) as usize;
                        let dst = unsafe { fb.add(di).read_volatile() };
                        let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                        unsafe { fb.add(di).write_volatile(0xFF000000|((sr*alpha+dr*ia)/255<<16)|((sg*alpha+dg*ia)/255<<8)|(sb*alpha+db*ia)/255); }
                    }}
                }
            }
        },
        "circle" => {
            let cx = sc(svg_num(svg_attr(tag, "cx")) / 1000, sx) + ox;
            let cy = sc(svg_num(svg_attr(tag, "cy")) / 1000, sy) + oy;
            let r  = sc(svg_num(svg_attr(tag, "r"))  / 1000, sx);
            let op = svg_opacity(tag, "opacity");
            let fill = match svg_paint(svg_attr(tag, "fill"), defs) {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "fill-opacity") / 1000),
                _ => 0,
            };
            let stroke = match svg_paint(svg_attr(tag, "stroke"), defs) {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "stroke-opacity") / 1000),
                _ => 0,
            };
            let swt    = ((svg_num(svg_attr(tag, "stroke-width")) * ((sx + sy) / 2) + 500000) / 1000000).max(if stroke != 0 { 1 } else { 0 });
            svg_draw_circle(fb, stride, width, height, cx, cy, r, fill, stroke, swt);
        },
        "ellipse" => {
            let ecx = sc(svg_num(svg_attr(tag, "cx")) / 1000, sx) + ox;
            let ecy = sc(svg_num(svg_attr(tag, "cy")) / 1000, sy) + oy;
            let erx = sc(svg_num(svg_attr(tag, "rx")) / 1000, sx);
            let ery = sc(svg_num(svg_attr(tag, "ry")) / 1000, sy);
            let op = svg_opacity(tag, "opacity");
            let fill = match svg_paint(svg_attr(tag, "fill"), defs) {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "fill-opacity") / 1000),
                _ => 0,
            };
            let stroke = match svg_paint(svg_attr(tag, "stroke"), defs) {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "stroke-opacity") / 1000),
                _ => 0,
            };
            let swt    = ((svg_num(svg_attr(tag, "stroke-width")) * ((sx + sy) / 2) + 500000) / 1000000).max(if stroke != 0 { 1 } else { 0 });
            // Rasterize ellipse via scan-line
            let out_rx = erx + swt; let out_ry = ery + swt;
            for py in (ecy - out_ry)..=(ecy + out_ry) {
                if py < 0 || py >= height { continue; }
                let dy = py - ecy;
                for px in (ecx - out_rx)..=(ecx + out_rx) {
                    if px < 0 || px >= width { continue; }
                    let dxx = px - ecx;
                    let in_fill   = if erx > 0 && ery > 0 { dxx*dxx*1000/erx/erx + dy*dy*1000/ery/ery <= 1000 } else { false };
                    let in_stroke = if out_rx > 0 && out_ry > 0 { dxx*dxx*1000/out_rx/out_rx + dy*dy*1000/out_ry/out_ry <= 1000 } else { false };
                    let color = if in_fill && fill != 0 { fill } else if in_stroke && !in_fill && stroke != 0 { stroke } else { 0 };
                    if color == 0 { continue; }
                    let alpha = (color>>24)&0xFF; let ia = 255-alpha;
                    let sr = (color>>16)&0xFF; let sg = (color>>8)&0xFF; let sb = color&0xFF;
                    let di = (py*stride+px) as usize;
                    let dst = unsafe { fb.add(di).read_volatile() };
                    let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                    unsafe { fb.add(di).write_volatile(0xFF000000|((sr*alpha+dr*ia)/255<<16)|((sg*alpha+dg*ia)/255<<8)|(sb*alpha+db*ia)/255); }
                }
            }
        },
        "line" => {
            let x0 = sc(svg_num(svg_attr(tag, "x1")) / 1000, sx) + ox;
            let y0 = sc(svg_num(svg_attr(tag, "y1")) / 1000, sy) + oy;
            let x1 = sc(svg_num(svg_attr(tag, "x2")) / 1000, sx) + ox;
            let y1 = sc(svg_num(svg_attr(tag, "y2")) / 1000, sy) + oy;
            let op = svg_opacity(tag, "opacity");
            let stroke = match svg_paint(svg_attr(tag, "stroke"), defs) {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "stroke-opacity") / 1000),
                _ => 0,
            };
            let swt    = ((svg_num(svg_attr(tag, "stroke-width")) * ((sx + sy) / 2) + 500000) / 1000000).max(1);
            svg_draw_line(fb, stride, width, height, x0, y0, x1, y1, stroke, swt);
        },
        "polygon" | "polyline" => {
            let pts_str = svg_attr(tag, "points");
            let op = svg_opacity(tag, "opacity");
            let stroke = match svg_paint(svg_attr(tag, "stroke"), defs) {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "stroke-opacity") / 1000),
                _ => 0,
            };
            let fill = if tag_name == "polygon" {
                match svg_paint(svg_attr(tag, "fill"), defs) {
                    SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "fill-opacity") / 1000),
                    _ => 0,
                }
            } else { 0 };
            let swt    = ((svg_num(svg_attr(tag, "stroke-width")) * ((sx + sy) / 2) + 500000) / 1000000).max(if stroke != 0 { 1 } else { 0 });
            // Parse "x1,y1 x2,y2 x3,y3 ..."
            let mut pts: Vec<(i32, i32)> = Vec::new();
            for pair in pts_str.split(|c: char| c == ' ' || c == '\n' || c == '\r') {
                let pair = pair.trim();
                if pair.is_empty() { continue; }
                let comma = pair.find(',').unwrap_or(pair.len());
                let px2 = sc(svg_num(&pair[..comma]) / 1000, sx) + ox;
                let py2 = sc(svg_num(if comma < pair.len() { &pair[comma+1..] } else { "0" }) / 1000, sy) + oy;
                pts.push((px2, py2));
            }
            // Fill via scanline (odd-even rule)
            if fill != 0 && pts.len() >= 3 {
                let min_y = pts.iter().map(|p| p.1).min().unwrap_or(0).max(0);
                let max_y = pts.iter().map(|p| p.1).max().unwrap_or(0).min(height-1);
                let fa = (fill>>24)&0xFF; let ia = 255-fa;
                let fr = (fill>>16)&0xFF; let fg2 = (fill>>8)&0xFF; let fb2 = fill&0xFF;
                for py in min_y..=max_y {
                    let mut xs: Vec<i32> = Vec::new();
                    let n = pts.len();
                    let mut j = n - 1;
                    for i in 0..n {
                        let (xi, yi) = pts[i]; let (xj, yj) = pts[j];
                        if (yi <= py && yj > py) || (yj <= py && yi > py) {
                            let denom = yj - yi;
                            if denom != 0 {
                                xs.push(xi + (py - yi) * (xj - xi) / denom);
                            }
                        }
                        j = i;
                    }
                    xs.sort_unstable();
                    let mut k = 0;
                    while k + 1 < xs.len() {
                        let x0c = xs[k].max(0); let x1c = xs[k+1].min(width-1);
                        for px in x0c..=x1c {
                            let di = (py*stride+px) as usize;
                            let dst = unsafe { fb.add(di).read_volatile() };
                            let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                            unsafe { fb.add(di).write_volatile(0xFF000000|((fr*fa+dr*ia)/255<<16)|((fg2*fa+dg*ia)/255<<8)|(fb2*fa+db*ia)/255); }
                        }
                        k += 2;
                    }
                }
            }
            // Stroke
            for i in 0..pts.len() {
                let (x0, y0) = pts[i];
                let (x1, y1) = pts[(i + 1) % pts.len()];
                if i + 1 < pts.len() || tag_name == "polygon" {
                    svg_draw_line(fb, stride, width, height, x0, y0, x1, y1, stroke, swt);
                }
            }
        },
        "path" => {
            // Parser complet : M/L/H/V/C/S/Q/T/A/Z (absolu + relatif), Béziers
            // aplatis en polylignes, FILL scanline even-odd multi-sous-chemins.
            // L'ancien parser ne faisait que du stroke M/L/H/V/Z : or Figma
            // exporte quasi tout en <path fill="..."> à courbes C — les cartes,
            // fonds arrondis et icônes pleines ne s'affichaient pas du tout.
            let d = svg_attr(tag, "d");
            let op = svg_opacity(tag, "opacity");
            let fill_paint = svg_paint(svg_attr(tag, "fill"), defs);
            let fill = match fill_paint {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "fill-opacity") / 1000),
                _ => 0,
            };
            let pattern_img = match fill_paint { SvgPaint::Pattern(i) => Some(i), _ => None };
            let stroke = match svg_paint(svg_attr(tag, "stroke"), defs) {
                SvgPaint::Color(c) => svg_scale_alpha(c, op * svg_opacity(tag, "stroke-opacity") / 1000),
                _ => 0,
            };
            let swt    = ((svg_num(svg_attr(tag, "stroke-width")) * ((sx + sy) / 2) + 500000) / 1000000).max(if stroke != 0 { 1 } else { 0 });
            if fill == 0 && stroke == 0 && pattern_img.is_none() { return; }
            let db = d.as_bytes();
            // Lit le prochain nombre (millièmes d'unité utilisateur) ou None si commande/fin.
            let next_num = |idx: &mut usize| -> Option<i32> {
                while *idx < db.len() && (db[*idx] == b',' || db[*idx].is_ascii_whitespace()) { *idx += 1; }
                if *idx >= db.len() || db[*idx].is_ascii_alphabetic() { return None; }
                let start = *idx;
                if db[*idx] == b'-' || db[*idx] == b'+' { *idx += 1; }
                while *idx < db.len() && (db[*idx].is_ascii_digit() || db[*idx] == b'.') { *idx += 1; }
                // Exposant scientifique ("2e-05") : à consommer ici sinon le 'e'
                // serait pris pour une commande de path et corromprait le parse.
                if *idx < db.len() && (db[*idx] == b'e' || db[*idx] == b'E') {
                    *idx += 1;
                    if *idx < db.len() && (db[*idx] == b'-' || db[*idx] == b'+') { *idx += 1; }
                    while *idx < db.len() && db[*idx].is_ascii_digit() { *idx += 1; }
                }
                if *idx == start { *idx += 1; return None; }
                Some(svg_num(core::str::from_utf8(&db[start..*idx]).unwrap_or("0")))
            };
            // Sous-chemins en espace utilisateur (millièmes) — convertis en px à la fin.
            let mut subpaths: Vec<Vec<(i32, i32)>> = Vec::new();
            let mut cur: Vec<(i32, i32)> = Vec::new();
            let (mut px_u, mut py_u) = (0i32, 0i32);   // point courant
            let (mut mx_u, mut my_u) = (0i32, 0i32);   // début du sous-chemin
            let (mut rcx, mut rcy)   = (0i32, 0i32);   // dernier contrôle (réflexion S/T)
            let mut prev_cmd = b' ';
            let mut cmd = b' ';
            let mut idx = 0usize;
            // Aplatis une cubique en 16 segments (Bernstein entier, i64 anti-overflow).
            let bez3 = |p0: (i32,i32), c1: (i32,i32), c2: (i32,i32), p3: (i32,i32), out: &mut Vec<(i32,i32)>| {
                const N: i64 = 16;
                for k in 1..=N {
                    let t = k; let u = N - k;
                    let x = (u*u*u*(p0.0 as i64) + 3*u*u*t*(c1.0 as i64) + 3*u*t*t*(c2.0 as i64) + t*t*t*(p3.0 as i64)) / (N*N*N);
                    let y = (u*u*u*(p0.1 as i64) + 3*u*u*t*(c1.1 as i64) + 3*u*t*t*(c2.1 as i64) + t*t*t*(p3.1 as i64)) / (N*N*N);
                    out.push((x as i32, y as i32));
                }
            };
            let bez2 = |p0: (i32,i32), c1: (i32,i32), p2: (i32,i32), out: &mut Vec<(i32,i32)>| {
                const N: i64 = 16;
                for k in 1..=N {
                    let t = k; let u = N - k;
                    let x = (u*u*(p0.0 as i64) + 2*u*t*(c1.0 as i64) + t*t*(p2.0 as i64)) / (N*N);
                    let y = (u*u*(p0.1 as i64) + 2*u*t*(c1.1 as i64) + t*t*(p2.1 as i64)) / (N*N);
                    out.push((x as i32, y as i32));
                }
            };
            while idx < db.len() {
                let c = db[idx];
                if c == b',' || c.is_ascii_whitespace() { idx += 1; continue; }
                if c.is_ascii_alphabetic() {
                    cmd = c; idx += 1;
                    if cmd == b'Z' || cmd == b'z' {
                        if cur.len() >= 2 {
                            cur.push((mx_u, my_u));
                            subpaths.push(core::mem::take(&mut cur));
                        } else { cur.clear(); }
                        px_u = mx_u; py_u = my_u;
                        prev_cmd = cmd;
                    }
                    continue;
                }
                let rel = cmd.is_ascii_lowercase();
                match cmd.to_ascii_uppercase() {
                    b'M' => {
                        let x = match next_num(&mut idx) { Some(v) => v, None => break };
                        let y = match next_num(&mut idx) { Some(v) => v, None => break };
                        if cur.len() >= 2 { subpaths.push(core::mem::take(&mut cur)); } else { cur.clear(); }
                        if rel { px_u += x; py_u += y; } else { px_u = x; py_u = y; }
                        mx_u = px_u; my_u = py_u;
                        cur.push((px_u, py_u));
                        // Paires suivantes d'un même M = lineto implicites
                        cmd = if rel { b'l' } else { b'L' };
                    }
                    b'L' => {
                        let x = match next_num(&mut idx) { Some(v) => v, None => break };
                        let y = match next_num(&mut idx) { Some(v) => v, None => break };
                        if rel { px_u += x; py_u += y; } else { px_u = x; py_u = y; }
                        cur.push((px_u, py_u));
                    }
                    b'H' => {
                        let x = match next_num(&mut idx) { Some(v) => v, None => break };
                        if rel { px_u += x; } else { px_u = x; }
                        cur.push((px_u, py_u));
                    }
                    b'V' => {
                        let y = match next_num(&mut idx) { Some(v) => v, None => break };
                        if rel { py_u += y; } else { py_u = y; }
                        cur.push((px_u, py_u));
                    }
                    b'C' => {
                        let n: [i32; 6] = {
                            let mut a = [0i32; 6];
                            let mut ok = true;
                            for v in a.iter_mut() { match next_num(&mut idx) { Some(x) => *v = x, None => { ok = false; break; } } }
                            if !ok { break; }
                            a
                        };
                        let base = if rel { (px_u, py_u) } else { (0, 0) };
                        let c1 = (base.0 + n[0], base.1 + n[1]);
                        let c2 = (base.0 + n[2], base.1 + n[3]);
                        let p3 = (base.0 + n[4], base.1 + n[5]);
                        bez3((px_u, py_u), c1, c2, p3, &mut cur);
                        rcx = c2.0; rcy = c2.1;
                        px_u = p3.0; py_u = p3.1;
                    }
                    b'S' => {
                        let n: [i32; 4] = {
                            let mut a = [0i32; 4];
                            let mut ok = true;
                            for v in a.iter_mut() { match next_num(&mut idx) { Some(x) => *v = x, None => { ok = false; break; } } }
                            if !ok { break; }
                            a
                        };
                        let pc = prev_cmd.to_ascii_uppercase();
                        let c1 = if pc == b'C' || pc == b'S' { (2*px_u - rcx, 2*py_u - rcy) } else { (px_u, py_u) };
                        let base = if rel { (px_u, py_u) } else { (0, 0) };
                        let c2 = (base.0 + n[0], base.1 + n[1]);
                        let p3 = (base.0 + n[2], base.1 + n[3]);
                        bez3((px_u, py_u), c1, c2, p3, &mut cur);
                        rcx = c2.0; rcy = c2.1;
                        px_u = p3.0; py_u = p3.1;
                    }
                    b'Q' => {
                        let n: [i32; 4] = {
                            let mut a = [0i32; 4];
                            let mut ok = true;
                            for v in a.iter_mut() { match next_num(&mut idx) { Some(x) => *v = x, None => { ok = false; break; } } }
                            if !ok { break; }
                            a
                        };
                        let base = if rel { (px_u, py_u) } else { (0, 0) };
                        let c1 = (base.0 + n[0], base.1 + n[1]);
                        let p2 = (base.0 + n[2], base.1 + n[3]);
                        bez2((px_u, py_u), c1, p2, &mut cur);
                        rcx = c1.0; rcy = c1.1;
                        px_u = p2.0; py_u = p2.1;
                    }
                    b'T' => {
                        let x = match next_num(&mut idx) { Some(v) => v, None => break };
                        let y = match next_num(&mut idx) { Some(v) => v, None => break };
                        let pc = prev_cmd.to_ascii_uppercase();
                        let c1 = if pc == b'Q' || pc == b'T' { (2*px_u - rcx, 2*py_u - rcy) } else { (px_u, py_u) };
                        let p2 = if rel { (px_u + x, py_u + y) } else { (x, y) };
                        bez2((px_u, py_u), c1, p2, &mut cur);
                        rcx = c1.0; rcy = c1.1;
                        px_u = p2.0; py_u = p2.1;
                    }
                    b'A' => {
                        // Arc elliptique approximé par un segment (suffisant pour les
                        // exports Figma qui n'en émettent presque jamais).
                        let n: [i32; 7] = {
                            let mut a = [0i32; 7];
                            let mut ok = true;
                            for v in a.iter_mut() { match next_num(&mut idx) { Some(x) => *v = x, None => { ok = false; break; } } }
                            if !ok { break; }
                            a
                        };
                        if rel { px_u += n[5]; py_u += n[6]; } else { px_u = n[5]; py_u = n[6]; }
                        cur.push((px_u, py_u));
                    }
                    _ => { idx += 1; }
                }
                prev_cmd = cmd;
            }
            if cur.len() >= 2 { subpaths.push(cur); }
            // Conversion espace utilisateur (millièmes) → pixels écran
            let to_px = |p: (i32, i32)| -> (i32, i32) {
                ((((p.0 as i64) * (sx as i64)) / 1_000_000) as i32 + ox,
                 (((p.1 as i64) * (sy as i64)) / 1_000_000) as i32 + oy)
            };
            let rings_flat: Vec<Vec<(i32, i32)>> = subpaths.iter()
                .map(|sp| sp.iter().map(|&p| to_px(p)).collect())
                .collect();
            // Bbox AVANT transformation — sert de repère objet pour les patterns
            // image (objectBoundingBox), même quand les anneaux sont ensuite tournés.
            let ub_x0 = rings_flat.iter().flat_map(|r| r.iter().map(|p| p.0)).min().unwrap_or(0);
            let ub_x1 = rings_flat.iter().flat_map(|r| r.iter().map(|p| p.0)).max().unwrap_or(0);
            let ub_y0 = rings_flat.iter().flat_map(|r| r.iter().map(|p| p.1)).min().unwrap_or(0);
            let ub_y1 = rings_flat.iter().flat_map(|r| r.iter().map(|p| p.1)).max().unwrap_or(0);
            let (ubw, ubh) = ((ub_x1 - ub_x0).max(1), (ub_y1 - ub_y0).max(1));
            // GpuSetTransform2D actif pendant SvgDraw : transformer les SOMMETS —
            // le scanline d'un polygone transformé reste couvrant (aucun trou),
            // contrairement à un mapping avant par pixel.
            let xf_active = unsafe { GPU_TRANSFORM_ACTIVE };
            let rings: Vec<Vec<(i32, i32)>> = if xf_active {
                rings_flat.iter()
                    .map(|r| r.iter().map(|&(px, py)| unsafe { gpu_transform_point(px, py) }).collect())
                    .collect()
            } else {
                rings_flat
            };
            // Fill scanline even-odd sur TOUS les sous-chemins à la fois (les trous
            // — anneaux intérieurs — comptent double et restent transparents).
            // Pattern image (fill="url(#pattern)") : le pattern Figma est en
            // objectBoundingBox → l'image couvre la bbox du path, échantillonnée
            // par pixel (c'est comme ça que Figma exporte les formes texturées).
            if (fill != 0 || pattern_img.is_some()) && !rings.is_empty() {
                let min_y = rings.iter().flat_map(|r| r.iter().map(|p| p.1)).min().unwrap_or(0).max(0);
                let max_y = rings.iter().flat_map(|r| r.iter().map(|p| p.1)).max().unwrap_or(0).min(height - 1);
                let fa = (fill>>24)&0xFF;
                let fr = (fill>>16)&0xFF; let fg2 = (fill>>8)&0xFF; let fb2 = fill&0xFF;
                for py in min_y..=max_y {
                    let mut xs: Vec<i32> = Vec::new();
                    for ring in rings.iter() {
                        let rn = ring.len();
                        if rn < 3 { continue; }
                        let mut j = rn - 1;
                        for i2 in 0..rn {
                            let (xi, yi) = ring[i2]; let (xj, yj) = ring[j];
                            if (yi <= py && yj > py) || (yj <= py && yi > py) {
                                let denom = yj - yi;
                                if denom != 0 { xs.push(xi + (py - yi) * (xj - xi) / denom); }
                            }
                            j = i2;
                        }
                    }
                    xs.sort_unstable();
                    let mut k = 0;
                    while k + 1 < xs.len() {
                        let x0c = xs[k].max(0); let x1c = xs[k+1].min(width-1);
                        for px in x0c..=x1c {
                            let (pa, pr, pg, pb) = if let Some(ii) = pattern_img {
                                let (iw, ih, ref rgba) = defs.images[ii];
                                // Repère objet : inverse de la transformation GPU si
                                // active, pattern mappé sur la bbox NON transformée,
                                // échantillonné en moyenne de bloc (anti-décimation).
                                let (ox2, oy2) = if xf_active {
                                    let t = unsafe { GPU_TRANSFORM };
                                    let (ta64, tb64, tc64, td64) =
                                        (t[0] as i64, t[1] as i64, t[2] as i64, t[3] as i64);
                                    let det = ta64 * td64 - tc64 * tb64;
                                    if det == 0 { (px, py) } else {
                                        let dx = (px - t[4]) as i64;
                                        let dy = (py - t[5]) as i64;
                                        (((td64 * dx - tc64 * dy) * 10000 / det) as i32,
                                         ((-tb64 * dx + ta64 * dy) * 10000 / det) as i32)
                                    }
                                } else { (px, py) };
                                let (r, g, b, a0) = unsafe {
                                    img_sample_box(rgba.as_ptr(), iw, ih,
                                        (ox2 - ub_x0).clamp(0, ubw - 1),
                                        (oy2 - ub_y0).clamp(0, ubh - 1),
                                        ubw, ubh)
                                };
                                let a = a0 * op.clamp(0, 1000) as u32 / 1000;
                                (a, r, g, b)
                            } else {
                                (fa, fr, fg2, fb2)
                            };
                            if pa == 0 { continue; }
                            let pia = 255 - pa;
                            let di = (py*stride+px) as usize;
                            let dst = unsafe { fb.add(di).read_volatile() };
                            let dbc=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                            unsafe { fb.add(di).write_volatile(0xFF000000|((pr*pa+dr*pia)/255<<16)|((pg*pa+dg*pia)/255<<8)|(pb*pa+dbc*pia)/255); }
                        }
                        k += 2;
                    }
                }
            }
            // Stroke le long de chaque sous-chemin (Z a déjà refermé les anneaux clos)
            if stroke != 0 && swt > 0 {
                for ring in rings.iter() {
                    for i2 in 0..ring.len().saturating_sub(1) {
                        let (x0, y0) = ring[i2]; let (x1, y1) = ring[i2 + 1];
                        svg_draw_line(fb, stride, width, height, x0, y0, x1, y1, stroke, swt);
                    }
                }
            }
        },
        _ => {}
    }
}

/// Rend un buffer SVG complet vers le framebuffer à (dst_x, dst_y, dst_w, dst_h).
fn svg_render(svg: &[u8], fb: *mut u32, stride: i32, width: i32, height: i32,
              dst_x: i32, dst_y: i32, dst_w: i32, dst_h: i32) {
    let text = match core::str::from_utf8(svg) { Ok(t) => t, Err(_) => return };
    // Extraire viewBox du tag <svg>
    let (vb_x, vb_y, vb_w, vb_h) = {
        let mut vx = 0i32; let mut vy = 0i32; let mut vw = dst_w; let mut vh = dst_h;
        if let Some(start) = text.find("<svg") {
            let end = text[start..].find('>').map(|e| start + e).unwrap_or(start + 200);
            let tag = &text[start..end];
            let vb = svg_attr(tag, "viewBox");
            if !vb.is_empty() {
                let nums: Vec<&str> = vb.split(|c: char| c == ' ' || c == ',').filter(|s| !s.is_empty()).collect();
                if nums.len() >= 4 {
                    vx = svg_num(nums[0]) / 1000; vy = svg_num(nums[1]) / 1000;
                    vw = svg_num(nums[2]) / 1000; vh = svg_num(nums[3]) / 1000;
                }
            }
            if vw == 0 {
                let w_s = svg_attr(tag, "width"); if !w_s.is_empty() { vw = svg_num(w_s) / 1000; }
            }
            if vh == 0 {
                let h_s = svg_attr(tag, "height"); if !h_s.is_empty() { vh = svg_num(h_s) / 1000; }
            }
        }
        if vw <= 0 { vw = 24; } if vh <= 0 { vh = 24; }
        (vx, vy, vw, vh)
    };
    // Facteurs d'échelle en millièmes
    let sx = if vb_w > 0 { dst_w * 1000 / vb_w } else { 1000 };
    let sy = if vb_h > 0 { dst_h * 1000 / vb_h } else { 1000 };
    let ox = dst_x - vb_x * sx / 1000;
    let oy = dst_y - vb_y * sy / 1000;
    // Résoudre les <defs> (dégradés, patterns image) avant le rendu des éléments
    let defs = svg_scan_defs(text);
    let mut in_defs = false;
    // Itérer sur les tags
    let mut pos = 0usize;
    while let Some(lt) = text[pos..].find('<') {
        let abs = pos + lt;
        let gt = text[abs..].find('>').map(|g| abs + g + 1).unwrap_or(text.len());
        let tag = &text[abs..gt];
        // Le contenu de <defs> (stops, patterns, rects de gradient…) ne se rend pas.
        if tag.starts_with("<defs") { in_defs = true; }
        if tag.starts_with("</defs") { in_defs = false; }
        // Sauter les commentaires, déclarations, balises fermantes
        if !in_defs && !tag.starts_with("</") && !tag.starts_with("<!--") && !tag.starts_with("<?") && !tag.starts_with("<svg") {
            svg_render_element(fb, stride, width, height, tag.trim_start_matches('<'), ox, oy, sx, sy, &defs);
        }
        pos = gt;
        if pos >= text.len() { break; }
    }
}

// ── Contexte

/// Contexte d'exécution pour un OVC — fourni par le kernel au moment du rendu.
/// La police 8×16 est embarquée dans ovc_exec (FONT8X16), pas dans la struct.
pub struct ExecCtx {
    pub fb:     *mut u32,
    pub width:  i32,
    pub height: i32,
    pub stride: i32,
    /// Octets TTF de brsonomasemibold.ttf — chargés depuis l'ESP par le kernel.
    /// Sert aux dispatchers DrvManSpec___FSGetSize___ / DrvManSpec___FSRead___.
    pub font:   *const u8,
    pub font_len: usize,
    /// Position courante du pointeur HID (EFI_SIMPLE_POINTER_PROTOCOL), en pixels
    /// écran réels — accumulée et bornée à [0,width)×[0,height) par le kernel à
    /// partir des déplacements relatifs remontés par le device (souris PS/2 ou USB,
    /// énumérés par le firmware via ACPI, peu importe le port physique).
    pub pointer_x:   i32,
    pub pointer_y:   i32,
    /// Bit 0 = bouton gauche, bit 1 = bouton droit (EFI_SIMPLE_POINTER_PROTOCOL.state.button).
    pub pointer_btn: i32,
    /// Dernière touche lue via EFI_SIMPLE_TEXT_INPUT_PROTOCOL (ConIn) : caractère
    /// Unicode si imprimable, sinon 0x10000 | ScanCode ; 0 si aucune touche en attente.
    pub key_code: i32,
}

unsafe impl Send for ExecCtx {}
unsafe impl Sync for ExecCtx {}

// ── Utilitaires de parsing ────────────────────────────────────────────────────

/// Extrait le nom du registre depuis `%name` ou `%name.suffix`.
fn reg_name(tok: &str) -> String {
    tok.trim_start_matches('%').to_string()
}

/// Résout un opérande complet (peut être une expression entière de LLVM IR).
/// Exemples :
///   "%20"                              → regs["20"]
///   "@0"                               → consts["0"]
///   "ptr nonnull inttoptr (i32 2 to ptr)"  → 2
///   "inttoptr (i64 1710638 to ptr)"    → 1710638
///   "ptr null"                         → 0
///   "42"                               → 42
fn resolve(tok: &str, regs: &Regs, consts: &BTreeMap<String, i64>) -> i64 {
    let tok = tok.trim().trim_end_matches(',');

    // Registre %name
    if tok.starts_with('%') {
        return regs_get(regs, reg_name(tok).as_str());
    }
    // Constante @name
    if tok.starts_with('@') {
        let k = tok.trim_start_matches('@').trim_end_matches(',');
        return *consts.get(k).unwrap_or(&0);
    }

    // inttoptr (iN N to ptr) — peut être précédé de "ptr nonnull" etc.
    if let Some(p) = tok.find("inttoptr (") {
        let rest = &tok[p + 10..];  // "i64 1710638 to ptr)" ou "i32 2 to ptr)"
        // Sauter le type (premier mot : i32/i64)
        let after_type = rest.find(' ').map(|i| &rest[i+1..]).unwrap_or(rest);
        let num_end = after_type.find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(after_type.len());
        return after_type[..num_end].parse().unwrap_or(0);
    }

    // "ptr null" ou "null"
    if tok == "null" || tok == "nullptr" || tok.ends_with(" null") { return 0; }

    // Dernier mot : peut être un registre %N, une constante @N, ou un entier.
    // Exemples : "ptr %9" → "%9" → regs["9"]
    //            "ptr nonnull @0" → "@0" → consts["0"]
    //            "i32 42" → "42" → 42
    let last = tok.split_whitespace().last().unwrap_or(tok);
    if last.starts_with('%') {
        return regs_get(regs, reg_name(last).as_str());
    }
    if last.starts_with('@') {
        let k = last.trim_start_matches('@').trim_end_matches(',');
        return *consts.get(k).unwrap_or(&0);
    }
    last.trim_end_matches(')').parse().unwrap_or(0)
}

/// Lit les arguments d'un `call` ou d'une `define` : `(ptr %a, i32 %b, …)`.
/// Retourne la liste des valeurs ou noms d'arguments.
fn parse_call_args(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let open  = match src.find('(') { Some(p) => p, None => return out };
    let close = match src.rfind(')') { Some(p) => p, None => return out };
    let inner = &src[open+1..close];

    // Découper sur les virgules HORS parenthèses imbriquées
    // (gère "ptr nonnull inttoptr (i32 2 to ptr)" comme un seul token)
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(inner[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    // Dernier argument
    let last_part = inner[start..].trim();
    if !last_part.is_empty() {
        out.push(last_part.to_string());
    }
    out
}

// ── Parsing des constantes de chaîne : @N = ... c"text\00" ───────────────────

fn parse_string_consts(ovc: &str) -> &'static BTreeMap<String, i64> {
    let key = ovc.as_ptr() as usize;
    // Discriminant = (pointeur, longueur) : tous les OVC ont le même header 32 octets
    // donc la signature n'est pas suffisante — la longueur distingue les modules.
    let len = ovc.len();
    unsafe {
        for &(k, kl, ptr) in CONSTS_CACHE.iter() {
            if k == key && kl == len && !ptr.is_null() { return &*ptr; }
        }
        // Non trouvé — parser et mettre en cache
        let mut map = BTreeMap::new();
        for line in ovc.lines() {
            let line = line.trim();
            if !line.starts_with('@') { continue; }
            let Some(eq) = line.find('=') else { continue };
            let name = line[1..eq].trim().to_string();
            let Some(cp) = line.find(" c\"") else { continue };
            let after = &line[cp+3..];
            let Some(ep) = after.find("\\00\"") else { continue };
            let s: &str = &after[..ep];
            // Décoder les escapes \xx → byte, stocker avec \0 final
            let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            let sb = s.as_bytes();
            let mut i = 0;
            while i < sb.len() {
                if sb[i] == b'\\' && i + 2 < sb.len() {
                    if let (Some(hi), Some(lo)) = (
                        (sb[i+1] as char).to_digit(16),
                        (sb[i+2] as char).to_digit(16)) {
                        bytes.push((hi * 16 + lo) as u8);
                        i += 3;
                        continue;
                    }
                }
                bytes.push(sb[i]); i += 1;
            }
            bytes.push(0u8);
            let boxed: alloc::boxed::Box<[u8]> = bytes.into_boxed_slice();
            let ptr_val = alloc::boxed::Box::into_raw(boxed) as *const u8 as i64;
            map.insert(name, ptr_val);
        }
        // Fuite justifiée : UEFI boot, max ~8 modules, chacun parsé une seule fois
        let boxed_map = alloc::boxed::Box::new(map);
        let map_ptr = alloc::boxed::Box::into_raw(boxed_map) as *const BTreeMap<String, i64>;
        for slot in CONSTS_CACHE.iter_mut() {
            if slot.0 == 0 { *slot = (key, len, map_ptr); break; }
        }
        &*map_ptr
    }
}

// ── Localisation d'une fonction ───────────────────────────────────────────────

/// Retourne le corps d'une fonction `define ... @name(...) { ... }`.
fn find_function<'a>(ovc: &'a str, name: &str) -> Option<&'a str> {
    let marker = alloc::format!("@{}(", name);
    let mut depth = 0i32;
    let mut start = None;
    for (i, c) in ovc.char_indices() {
        if start.is_none() {
            if ovc[i..].starts_with("define ") {
                // Vérifier que @name( est sur LA MÊME LIGNE (pas dans le reste du fichier)
                let line_end = ovc[i..].find('\n').map(|n| i + n).unwrap_or(ovc.len());
                if ovc[i..line_end].contains(marker.as_str()) {
                    start = Some(i);
                }
            }
        } else {
            if c == '{' { depth += 1; }
            if c == '}' {
                depth -= 1;
                if depth == 0 {
                    return Some(&ovc[start.unwrap()..i+1]);
                }
            }
        }
    }
    None
}

/// Extrait les noms de paramètres d'une définition de fonction.
fn parse_def_args(func: &str) -> Vec<String> {
    let first_line = func.lines().next().unwrap_or("");
    parse_call_args(first_line)
        .into_iter()
        .filter_map(|s| {
            // Chaque arg LLVM IR est du type "ptr %name", "i32 %name", "ptr nonnull %name"...
            // Extraire le token qui commence par '%' (le nom du registre).
            s.split_whitespace()
             .find(|w| w.starts_with('%'))
             .map(|w| w.trim_start_matches('%').trim_end_matches(',').to_string())
        })
        .collect()
}

// ── Parsing des blocs de base ─────────────────────────────────────────────────

fn parse_blocks(func: &str) -> &'static BTreeMap<String, Vec<String>> {
    // Cache par pointeur de texte de fonction — parsé UNE SEULE FOIS par fonction OVC
    let key_ovc  = func.as_ptr() as usize;
    let key_func = func.len();
    unsafe {
        for &(ko, kf, ptr) in BLOCKS_CACHE.iter() {
            if ko == key_ovc && kf == key_func && !ptr.is_null() { return &*ptr; }
        }
    }
    let mut blocks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cur = "entry".to_string();
    blocks.insert(cur.clone(), Vec::new());

    let mut switch_buf: Option<String> = None;
    for line in func.lines().skip(1) {
        let t = line.trim();
        if t.is_empty() || t == "{" || t == "}" { continue; }
        if t.starts_with(';') { continue; }

        // Fusionner les instructions switch multi-lignes "switch ... [ ... ]"
        if let Some(ref mut buf) = switch_buf {
            buf.push(' ');
            buf.push_str(t);
            if t == "]" || t.ends_with(']') {
                let done = buf.clone();
                switch_buf = None;
                if let Some(v) = blocks.get_mut(&cur) { v.push(done); }
            }
            continue;
        }
        if t.starts_with("switch ") {
            if t.ends_with(']') {
                if let Some(v) = blocks.get_mut(&cur) { v.push(t.to_string()); }
            } else {
                switch_buf = Some(t.to_string());
            }
            continue;
        }

        // Supprimer le commentaire de fin de ligne avant le test de label
        let t_nc = if let Some(sc) = t.find(';') { t[..sc].trim() } else { t };
        if !t_nc.starts_with('%') && !t_nc.starts_with("store")
            && !t_nc.starts_with("br") && !t_nc.starts_with("ret")
            && t_nc.ends_with(':')
        {
            let label = t_nc.trim_end_matches(':').trim().to_string();
            cur = label.clone();
            blocks.entry(cur.clone()).or_insert_with(Vec::new);
            continue;
        }
        if let Some(v) = blocks.get_mut(&cur) {
            v.push(t.to_string());
        }
    }
    // Fuite justifiée (UEFI boot) — chaque fonction parsée une seule fois
    unsafe {
        let boxed = alloc::boxed::Box::new(blocks);
        let ptr   = alloc::boxed::Box::into_raw(boxed) as *const BTreeMap<String, Vec<String>>;
        for slot in BLOCKS_CACHE.iter_mut() {
            if slot.0 == 0 { *slot = (key_ovc, key_func, ptr); break; }
        }
        &*ptr
    }
}

// ── Exécution ─────────────────

pub fn exec_fn(
    ovc:     &[u8],
    fn_name: &str,
    args:    &[i64],
    ctx:     &ExecCtx,
) -> i64 {
    let text = core::str::from_utf8(ovc).unwrap_or("");
    if !text.starts_with("# Vyft OVC v1.0") { return -1; }

    let consts  = parse_string_consts(text);
    let func    = match find_function(text, fn_name) { Some(f) => f, None => return -1 };
    let arg_names = parse_def_args(func);
    let blocks  = parse_blocks(func);

    let mut regs: Regs = Vec::new();
    let mut globals: Regs = Vec::new();

    for (i, a) in arg_names.iter().enumerate() {
        regs_set(&mut regs, &a, args.get(i).copied().unwrap_or(0));
    }

    run_blocks(&blocks, &consts, &mut globals, &mut regs, ctx, "entry")
}

/// Exécute plusieurs fonctions d'un même OVC en partageant les globals.
/// Utilisé pour HelloWorld() puis Create() qui lisent les mêmes variables module.
pub fn exec_module(ovc: &[u8], fns: &[(&str, &[i64])], ctx: &ExecCtx) -> i64 {
    let text = core::str::from_utf8(ovc).unwrap_or("");
    if !text.starts_with("# Vyft OVC v1.0") { return -1; }

    let consts  = parse_string_consts(text);
    let mut globals: Regs = Vec::new();
    let mut last = 0i64;

    for (fn_name, args) in fns {
        let func = match find_function(text, fn_name) { Some(f) => f, None => continue };
        let arg_names = parse_def_args(func);
        let blocks    = parse_blocks(func);
        let mut regs: Regs = Vec::new();
        for (i, a) in arg_names.iter().enumerate() {
            regs_set(&mut regs, &a, args.get(i).copied().unwrap_or(0));
        }
        last = run_blocks(&blocks, &consts, &mut globals, &mut regs, ctx, "entry");
    }
    last
}

/// Exécute un marep complet dynamiquement.
///
/// Le kernel ne connaît que `OEntry.ovc` + la fonction `OEntry()` —
/// point d'entrée universel de tout marep (comme `main()` en C).
/// Les autres OVC sont découverts et chargés via les appels cross-module.
///
/// Résolution des appels cross-module :
///   `@ModuleName___FuncName` → cherche `@FuncName` dans `ModuleName.ovc`
///   `@self___FuncName`       → cherche `@FuncName` dans tous les modules
///   `@std___core___self___ModuleName___FuncName` → normalise et résout
///
/// `modules`: liste de `(nom_module, bytes_ovc)` extraits du marep.
/// Écriture sur COM1 (0x3F8) — visible dans QEMU -serial stdio sans borrow conflict.
/// pub : aussi utilisé par kernel_runtime.rs pour les diagnostics HID (détection
/// souris/clavier), en dehors du contexte d'exécution OVC.
pub fn serial_log(msg: &[u8]) {
    for &b in msg {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") 0x3F8u16,
                in("al") b,
                options(nomem, nostack)
            );
        }
    }
    // Accumulé pour `flush_boot_log_to_esp` — voir BOOT_LOG_BUF. Plafonné pour
    // éviter une croissance non bornée si le boot tourne longtemps (ex. boucle
    // de rendu) ; largement suffisant pour couvrir toute la séquence de boot
    // jusqu'au chargement de ShiLauncher, la zone qui nous intéresse ici.
    unsafe {
        if BOOT_LOG_BUF.len() < 512 * 1024 {
            BOOT_LOG_BUF.extend_from_slice(msg);
        }
    }
}

/// Affiche `msg` DIRECTEMENT à l'écran (st.stdout(), la console UEFI déjà
/// visible avant même que le kernel ne touche au GOP) et marque une pause
/// courte pour laisser le temps de lire — utilisé UNIQUEMENT sur le chemin de
/// boot bare-metal entre "Loading ShiLauncher..." et le premier dessin GOP, où
/// l'écran devient noir sans qu'on sache pourquoi. Contrairement à serial_log
/// (port série, invisible sans câble UART) ou flush_boot_log_to_esp (fichier,
/// invisible sans reboot sur un autre OS), ce message apparaît là, sur l'écran
/// qui affiche déjà le firmware — donc observable sans aucun matériel/étape
/// supplémentaire. `stall_us` : microsecondes de pause après affichage (0 pour
/// ne pas attendre, ex. juste avant une étape qu'on soupçonne de planter).
pub fn screen_log(st: &mut uefi::table::SystemTable<uefi::table::Boot>, msg: &str, stall_us: usize) {
    use core::fmt::Write;
    let _ = st.stdout().write_str(msg);
    let _ = st.stdout().write_str("\r\n");
    serial_log(msg.as_bytes());
    serial_log(b"\r\n");
    if stall_us > 0 {
        st.boot_services().stall(stall_us);
    }
}

pub fn exec_marep(
    modules: &[(&str, &[u8])],  // [("OEntry", bytes), ("HelloWorld", bytes), ...]
    ctx:     &ExecCtx,
) -> i64 {
    serial_log(b"[OVC] exec_marep start\r\n");

    // Construire la table modules → texte OVC + consts
    let mut mod_texts: Vec<(&str, &str)> = Vec::new();
    let mut all_consts: BTreeMap<String, i64> = BTreeMap::new();

    for (name, bytes) in modules {
        let text = core::str::from_utf8(bytes).unwrap_or("");
        if text.starts_with("# Vyft OVC v1.0") {
            // Fusionner les constantes de chaque module dans un espace global
            // (préfixées par le module pour éviter les collisions)
            let c = parse_string_consts(text);
            for (k, v) in c.iter() {
                all_consts.insert(alloc::format!("{}::{}", name, k), *v);
                all_consts.entry(k.clone()).or_insert(*v);
            }
            mod_texts.push((name, text));
        }
    }

    // Globals partagés entre tous les modules
    let mut globals: Regs = Vec::new();

    serial_log(b"[OVC] constructors start\r\n");

    // Étape 1 : constructeurs des COMPOSANTS (pas OEntry)
    for (mod_name, mod_text) in &mod_texts {
        if mod_name.eq_ignore_ascii_case("OEntry") { continue; }
        let has_fn = find_function(mod_text, mod_name).is_some();
        if has_fn {
            exec_marep_fn(
                mod_name, mod_text, mod_name, &[],
                &all_consts, &mut globals, ctx, &mod_texts, 0,
            );
        }
    }

    serial_log(b"[OVC] OEntry start\r\n");

    // Étape 2 : OEntry() — point d'entrée universel
    let oentry_text = mod_texts.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("OEntry"))
        .map(|(_, t)| *t)
        .unwrap_or("");

    if oentry_text.is_empty() {
        serial_log(b"[OVC] OEntry NOT FOUND\r\n");
        return -1;
    }

    let ret = exec_marep_fn(
        "OEntry", oentry_text, "OEntry", &[],
        &all_consts, &mut globals, ctx, &mod_texts,
        0,
    );
    serial_log(b"[OVC] exec_marep done\r\n");
    ret
}

/// Exécute une fonction dans un module donné avec résolution cross-module.
/// IMPORTANT : chaque module utilise SES PROPRES consts numériques (@0, @1…).
/// Les globals nommés (@message, @bgColor…) sont partagés entre modules.
/// Ceci évite la collision des constantes numériques entre modules.
fn exec_marep_fn(
    mod_name:   &str,
    ovc_text:   &str,
    fn_name:    &str,
    args:       &[i64],
    _all_consts: &BTreeMap<String, i64>,
    globals:    &mut Regs,
    ctx:        &ExecCtx,
    modules:    &[(&str, &str)],
    depth:      u32,
) -> i64 {
    if depth > 32 { return 0; }

    // Log uniquement les fonctions publiques (pas les helpers internes _xxx)
    let is_public = !fn_name.starts_with('_');
    if is_public {
        serial_log(b"[FN] ");
        serial_log(mod_name.as_bytes());
        serial_log(b"::");
        serial_log(fn_name.as_bytes());
        serial_log(b"\r\n");
    }

    let local_consts = parse_string_consts(ovc_text);
    let func = match find_function(ovc_text, fn_name) {
        Some(f) => f,
        None    => {
            serial_log(b"[FN] NOT FOUND\r\n");
            return 0;
        }
    };
    let arg_names = parse_def_args(func);
    let blocks = parse_blocks(func);

    let mut regs: Regs = Vec::new();
    for (i, a) in arg_names.iter().enumerate() {
        regs_set(&mut regs, &a, args.get(i).copied().unwrap_or(0));
    }

    run_blocks_cross(
        &blocks, &local_consts, globals, &mut regs, ctx,
        "entry", mod_name, modules, depth,
    )
}

/// Mapping cycle de vie Maratine : event → méthode de composant.
/// `onCreate`  → `Create`   (LaPrevent appelle TemplateView::Create)
/// `onDestroy` → `Destroy`
/// `onPause`   → `Pause`
/// `onResume`  → `Resume`
fn maratine_lifecycle_fn(event: &str) -> &str {
    match event {
        "onCreate"  => "Create",
        "onDestroy" => "Destroy",
        "onPause"   => "Pause",
        "onResume"  => "Resume",
        other       => other,
    }
}

/// Normalise un nom de fonction cross-module.
/// `@std___core___self___LAPrevent___Launch` → (`LAPrevent`, `Launch`)
/// `@HelloWorld___Create`                   → (`HelloWorld`, `Create`)
/// `@self___onCreate`                       → (`self`, `Create`)  ← lifecycle mapping
fn resolve_cross_module_call(fname: &str) -> Option<(&str, &str)> {
    // Supprimer le préfixe std___core___self___
    let stripped = fname.strip_prefix("std___core___self___").unwrap_or(fname);

    // Chercher le dernier `___` (séparateur module___fonction)
    if let Some(pos) = stripped.rfind("___") {
        let module   = &stripped[..pos];
        let raw_fn   = &stripped[pos+3..];
        // Appliquer le mapping cycle de vie Maratine
        let function = maratine_lifecycle_fn(raw_fn);
        if !module.is_empty() && !function.is_empty() {
            return Some((module, function));
        }
    }
    None
}

/// Version cross-module de run_blocks.
fn run_blocks_cross(
    blocks:   &BTreeMap<String, Vec<String>>,
    consts:   &BTreeMap<String, i64>,
    globals:  &mut Regs,
    regs:     &mut Regs,
    ctx:      &ExecCtx,
    start:    &str,
    mod_name: &str,
    modules:  &[(&str, &str)],
    depth:    u32,
) -> i64 {
    let mut cur  = start.to_string();
    let mut prev = String::new();
    let mut iters = 0u32;

    loop {
        iters += 1;
        if iters > 200_000 { break; }

        let instrs = match blocks.get(&cur) {
            Some(v) => v.clone(),
            None    => break,
        };

        let prev_blk = prev.clone();
        prev = cur.clone();

        let mut jumped = false;
        for instr in &instrs {
            // Pour les appels de fonction, intercepter les appels cross-module
            let result = if instr.contains(" = ") && instr.contains("call ") {
                let eq = instr.find(" = ").unwrap();
                let dst = instr[1..eq].trim().to_string();
                let rhs_raw = instr[eq+3..].trim();
                let rhs = rhs_raw.trim_start_matches("tail ").trim_start_matches("musttail ");

                if rhs.starts_with("call ") || rhs.starts_with("call i") || rhs.starts_with("call (") {
                    // Extraire le nom de la fonction
                    if let Some(at_pos) = rhs.find('@') {
                        let after_at = &rhs[at_pos+1..];
                        let fn_end = after_at.find('(').unwrap_or(after_at.len());
                        let fname = &after_at[..fn_end];

                        // Tenter la résolution cross-module
                        let raw_args = parse_call_args(rhs);
                        let arg_vals: Vec<i64> = raw_args.iter().map(|a| resolve(a, regs, consts)).collect();

                        let call_result = if let Some((target_mod, target_fn)) = resolve_cross_module_call(fname) {
                            // Appel cross-module
                            let found = if target_mod.eq_ignore_ascii_case("self") {
                                // self → chercher dans tous les modules sauf le courant
                                modules.iter()
                                    .filter(|(n, _)| !n.eq_ignore_ascii_case(mod_name))
                                    .find(|(_, t)| find_function(t, target_fn).is_some())
                                    .map(|(n, t)| (*n, *t))
                            } else {
                                modules.iter()
                                    .find(|(n, _)| n.eq_ignore_ascii_case(target_mod))
                                    .map(|(n, t)| (*n, *t))
                            };

                            if let Some((found_mod, found_text)) = found {
                                // Log uniquement les appels cross-module publics
                                if !target_fn.starts_with('_') {
                                    serial_log(b"[CM] ");
                                    serial_log(found_mod.as_bytes());
                                    serial_log(b"::");
                                    serial_log(target_fn.as_bytes());
                                    serial_log(b"\r\n");
                                }
                                exec_marep_fn(
                                    found_mod, found_text, target_fn,
                                    &arg_vals, consts, globals, ctx, modules, depth + 1,
                                )
                            } else {
                                serial_log(b"[XM] miss ");
                                serial_log(target_fn.as_bytes());
                                serial_log(b" in ");
                                serial_log(target_mod.as_bytes());
                                serial_log(b"\r\n");
                                dispatch(fname, &arg_vals, consts, globals, ctx)
                            }
                        } else {
                            // Fast-paths pour _r8/_r16/_r32/_rtag de TtfParser
                            // (évite de re-parser TtfParser.ovc 34KB à chaque lecture)
                            let fast = match fname {
                                "_r8" => {
                                    let off = arg_vals.get(0).copied().unwrap_or(0);
                                    let ptr = unsafe { TTF_DATA_PTR } as *const u8;
                                    let sz  = unsafe { TTF_SCRATCH[100] } as i64;
                                    if ptr.is_null() || off < 0 || off >= sz { Some(0i64) }
                                    else { Some(unsafe { *ptr.add(off as usize) as i64 }) }
                                },
                                "_r16" => {
                                    let off = arg_vals.get(0).copied().unwrap_or(0);
                                    let ptr = unsafe { TTF_DATA_PTR } as *const u8;
                                    let sz  = unsafe { TTF_SCRATCH[100] } as i64;
                                    if ptr.is_null() || off < 0 || off + 1 >= sz { Some(0i64) }
                                    else { unsafe {
                                        let hi = *ptr.add(off as usize) as i64;
                                        let lo = *ptr.add(off as usize + 1) as i64;
                                        Some((hi << 8) | lo)
                                    }}
                                },
                                "_r32" | "_rtag" => {
                                    let off = arg_vals.get(0).copied().unwrap_or(0);
                                    let ptr = unsafe { TTF_DATA_PTR } as *const u8;
                                    let sz  = unsafe { TTF_SCRATCH[100] } as i64;
                                    if ptr.is_null() || off < 0 || off + 3 >= sz { Some(0i64) }
                                    else { unsafe {
                                        let b0 = *ptr.add(off as usize)     as i64;
                                        let b1 = *ptr.add(off as usize + 1) as i64;
                                        let b2 = *ptr.add(off as usize + 2) as i64;
                                        let b3 = *ptr.add(off as usize + 3) as i64;
                                        Some((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
                                    }}
                                },
                                _ => None,
                            };
                            if let Some(v) = fast { v } else {
                                // Pas de séparateur "___" → fonction interne du module courant
                                let self_text = modules.iter()
                                    .find(|(n, _)| n.eq_ignore_ascii_case(mod_name))
                                    .map(|(_, t)| *t);
                                if let Some(st) = self_text {
                                    if find_function(st, fname).is_some() {
                                        exec_marep_fn(
                                            mod_name, st, fname,
                                            &arg_vals, consts, globals, ctx, modules, depth + 1,
                                        )
                                    } else {
                                        dispatch(fname, &arg_vals, consts, globals, ctx)
                                    }
                                } else {
                                    dispatch(fname, &arg_vals, consts, globals, ctx)
                                }
                            }  // end if let Some(v) = fast
                        };

                        regs_set(regs, &dst, call_result);
                        RunResult::Ok
                    } else {
                        run_instr(instr, consts, globals, regs, ctx, &prev_blk)
                    }
                } else {
                    run_instr(instr, consts, globals, regs, ctx, &prev_blk)
                }
            } else {
                run_instr(instr, consts, globals, regs, ctx, &prev_blk)
            };

            match result {
                RunResult::Ok          => {},
                RunResult::Branch(lbl) => {
                    prev = cur.clone();
                    cur  = lbl;
                    jumped = true;
                    break;
                },
                RunResult::Return(v) => return v,
            }
        }
        if !jumped { break; }
    }
    0
}

fn run_blocks(
    blocks:  &BTreeMap<String, Vec<String>>,
    consts:  &BTreeMap<String, i64>,
    globals: &mut Regs,
    regs:    &mut Regs,
    ctx:     &ExecCtx,
    start:   &str,
) -> i64 {
    let mut cur  = start.to_string();
    let mut prev = String::new();
    let mut iters = 0u32;

    loop {
        iters += 1;
        if iters > 200_000 { break; }  // garde-fou boucle infinie

        let instrs = match blocks.get(&cur) {
            Some(v) => v.clone(),
            None    => break,
        };

        let prev_blk = prev.clone();
        prev = cur.clone();

        let mut jumped = false;
        for instr in &instrs {
            match run_instr(instr, consts, globals, regs, ctx, &prev_blk) {
                RunResult::Ok          => {},
                RunResult::Branch(lbl) => {
                    prev = cur.clone();
                    cur  = lbl;
                    jumped = true;
                    break;
                },
                RunResult::Return(v)   => return v,
            }
        }
        if !jumped { break; }
    }
    0
}

enum RunResult { Ok, Branch(String), Return(i64) }

fn run_instr(
    instr:   &str,
    consts:  &BTreeMap<String, i64>,
    globals: &mut Regs,
    regs:    &mut Regs,
    ctx:     &ExecCtx,
    prev:    &str,
) -> RunResult {
    let instr = instr.trim();
    if instr.is_empty() || instr.starts_with(';') { return RunResult::Ok; }

    // ── switch i32 %val, label %default [ i32 N, label %lbl ... ] ───────────
    if instr.starts_with("switch ") {
        let toks: Vec<&str> = instr.split_whitespace().collect();
        // toks[2] = value token (e.g. "%14"), toks[4] = default label (e.g. "%merge80")
        let val_tok     = toks.get(2).unwrap_or(&"0");
        let default_lbl = toks.get(4).unwrap_or(&"").trim_start_matches('%').to_string();
        let val = resolve(val_tok, regs, consts);
        let mut target = default_lbl;
        // Scan pairs: "i32 CONST, label %LBL"
        let mut i = 5usize;
        while i + 3 <= toks.len() {
            if toks[i] == "[" { i += 1; continue; }
            if toks[i] == "]" { break; }
            // "i32" CONST "label" "%LBL"
            if toks[i].starts_with("i") {
                let case_val: i64 = toks.get(i+1).unwrap_or(&"").trim_end_matches(',').parse().unwrap_or(i64::MAX);
                let case_lbl = toks.get(i+3).unwrap_or(&"").trim_start_matches('%').trim_end_matches(']');
                if val == case_val {
                    target = case_lbl.to_string();
                    break;
                }
                i += 4;
            } else { i += 1; }
        }
        return RunResult::Branch(target);
    }

    // ── br ───────────────────────────────────────────────────────────────────
    if instr.starts_with("br ") {
        let rest = &instr[3..];
        if rest.starts_with("label ") {
            let lbl = rest[6..].trim().trim_start_matches('%').to_string();
            return RunResult::Branch(lbl);
        }
        if rest.starts_with("i1 ") {
            let parts: Vec<&str> = rest.splitn(4, ',').collect();
            let cond_tok = parts[0].trim().strip_prefix("i1 ").unwrap_or("").trim();
            let cond = resolve(cond_tok, regs, consts) != 0;
            let true_lbl  = parts.get(1).unwrap_or(&"").trim().strip_prefix("label %").unwrap_or("").to_string();
            let false_lbl = parts.get(2).unwrap_or(&"").trim().strip_prefix("label %").unwrap_or("").to_string();
            let dest = if cond { true_lbl } else { false_lbl };
            return RunResult::Branch(dest);
        }
    }

    // ── ret ──────────────────────────────────────────────────────────────────
    if instr.starts_with("ret ") {
        let rest = instr[4..].trim();
        // "ret i32 0" / "ret i32 %N"
        let val_tok = rest.split_whitespace().last().unwrap_or("0");
        return RunResult::Return(resolve(val_tok, regs, consts));
    }

    // ── store ────────────────────────────────────────────────────────────────
    if instr.starts_with("store ") {
        // store ptr @const, ptr @global  |  store i1 true, ptr @global
        // store ptr %reg,   ptr @global
        let parts: Vec<&str> = instr.splitn(3, ',').collect();
        // Source : dernier token de parts[0]
        let src_tok  = parts[0].trim().split_whitespace().last().unwrap_or("0");
        // Destination : @global_name dans parts[1]
        let dest_part = parts.get(1).unwrap_or(&"").trim();
        let dest_tok = dest_part.split_whitespace().last().unwrap_or("").trim_end_matches(',');
        let dest_k   = dest_tok.trim_start_matches('@').to_string();
        let val = if src_tok == "true" { 1i64 }
                  else if src_tok == "false" { 0i64 }
                  else { resolve(src_tok, regs, consts) };
        regs_set(globals, &dest_k, val);
        return RunResult::Ok;
    }

    // ── load : %N = load type, ptr @global / ptr %reg ────────────────────────
    // load i1, ptr @bgColor  → globals["bgColor"]
    // load ptr, ptr @message → globals["message"]
    if instr.starts_with("load ") && instr.contains(" = ") {
        // handled in assignment block below — fall through
    }

    // ── assignment: %N = ... ──────────────────────────────────────────────────
    let Some(eq) = instr.find(" = ") else { return RunResult::Ok };
    let dst = instr[1..eq].trim().to_string();
    let rhs = instr[eq+3..].trim();

    // Supprime les qualificateurs call
    let rhs = rhs.trim_start_matches("tail ");
    let rhs = rhs.trim_start_matches("musttail ");

    let val: i64 = if rhs.starts_with("call ") || rhs.starts_with("call i")
                   || rhs.starts_with("call (")
    {
        // Extraire le nom de la fonction
        let fn_start = match rhs.find('@') { Some(p) => p, None => { regs_set(regs, &dst, 0); return RunResult::Ok; } };
        let after_at = &rhs[fn_start+1..];
        let fn_end = after_at.find('(').unwrap_or(after_at.len());
        let fname = &after_at[..fn_end];

        // Extraire les arguments
        let raw_args = parse_call_args(rhs);
        let arg_vals: Vec<i64> = raw_args.iter().map(|a| resolve(a, regs, consts)).collect();

        dispatch(fname, &arg_vals, consts, globals, ctx)
    }
    else if rhs.starts_with("phi ") {
        // phi i32 [ v1, %lbl1 ], [ v2, %lbl2 ]
        // Cherche la valeur associée au bloc précédent.
        // Si le prédécesseur n'est pas dans la phi (optimisation LLVM : le compilateur
        // peut fusionner des chemins), on retourne la valeur actuelle du registre de
        // destination — c'est le comportement attendu pour les phi de boucles.
        if let Some(v) = parse_phi_opt(rhs, prev, regs, consts) { v }
        else { regs_get(regs, &dst) }  // prédécesseur non trouvé → valeur inchangée
    }
    else if rhs.starts_with("load ") {
        // load i1, ptr @global  |  load ptr, ptr @global
        // → retourne globals["global"] ou regs si c'est un %reg
        let parts: Vec<&str> = rhs.splitn(3, ',').collect();
        let src = parts.get(1).map(|s| s.trim()).unwrap_or("");
        // dernier token = @global ou %reg
        let key = src.split_whitespace().last().unwrap_or("").trim_end_matches(',');
        if key.starts_with('@') {
            let k = key.trim_start_matches('@');
            regs_get(globals, k)
        } else if key.starts_with('%') {
            regs_get(regs, reg_name(key).as_str())
        } else {
            0
        }
    }
    else if rhs.starts_with("select ") {
        // select i1 %cond, ptr A, ptr B
        // A peut être "ptr inttoptr (i64 N to ptr)" → passer la CHAÎNE ENTIÈRE à resolve
        let parts: Vec<&str> = rhs.splitn(4, ',').collect();
        let cond_tok = parts[0].trim().split_whitespace().last().unwrap_or("0");
        let cond = resolve(cond_tok, regs, consts) != 0;
        // Passer la partie entière (pas juste le dernier mot) pour gérer inttoptr inline
        let a_part = parts.get(1).map(|s| s.trim()).unwrap_or("0");
        let b_part = parts.get(2).map(|s| s.trim()).unwrap_or("0");
        if cond { resolve(a_part, regs, consts) } else { resolve(b_part, regs, consts) }
    }
    else if rhs.starts_with("icmp ") {
        // icmp sgt/eq/ugt/samesign ...
        let parts: Vec<&str> = rhs.splitn(4, ' ').collect();
        let op = parts.get(1).unwrap_or(&"eq");
        let toks: Vec<&str> = rhs.split_whitespace().collect();
        // find the two value tokens (after type)
        let len = toks.len();
        let a_tok = if len >= 4 { toks[len-2] } else { "0" };
        let b_tok = if len >= 3 { toks[len-1] } else { "0" };
        let a = resolve(a_tok, regs, consts);
        let b = resolve(b_tok, regs, consts);
        match *op {
            "sgt"              => (a > b) as i64,
            "sge"              => (a >= b) as i64,
            "eq"               => (a == b) as i64,
            "ne"               => (a != b) as i64,
            "slt"              => (a < b) as i64,
            "sle"              => (a <= b) as i64,
            "ugt" | "samesign" => ((a as u64) > (b as u64)) as i64,
            "uge"              => ((a as u64) >= (b as u64)) as i64,
            "ult"              => ((a as u64) < (b as u64)) as i64,
            "ule"              => ((a as u64) <= (b as u64)) as i64,
            _                  => 0,
        }
    }
    else {
        // Opérations arithmétiques / casts
        let toks: Vec<&str> = rhs.split_whitespace().collect();
        // Pattern: "op [qualifiers] type %a, %b"  |  "op [qualifiers] type %a, N"
        if toks.len() < 2 { 0 }
        else {
            let op = toks[0];
            // Trouver les deux opérandes (dernier et avant-dernier token non-type)
            let (a_tok, b_tok) = extract_binop_args(&toks);
            let a = resolve(a_tok, regs, consts);
            let b = resolve(b_tok, regs, consts);
            match op {
                "add"   => a.wrapping_add(b),
                "sub"   => a.wrapping_sub(b),
                "mul"   => a.wrapping_mul(b),
                "sdiv"  => if b != 0 { a / b } else { 0 },
                "udiv"  => if b != 0 { (a as u64 / b as u64) as i64 } else { 0 },
                "srem"  => if b != 0 { a % b } else { 0 },
                "urem"  => if b != 0 { (a as u64 % b as u64) as i64 } else { 0 },
                "shl"   => a.wrapping_shl(b as u32),
                "ashr"  => a >> (b & 63),
                "lshr"  => ((a as u64) >> (b & 63)) as i64,
                "and"   => a & b,
                "or"    => a | b,
                "xor"   => a ^ b,
                // Casts : format "op [qualifiers] src_type VALUE to dst_type"
                // La valeur est le token JUSTE AVANT "to".
                // extract_binop_args prend les MAUVAIS tokens pour les casts
                // (ex. "inttoptr i64 %8 to ptr" → donne "to" et "ptr" au lieu de "%8").
                "zext" | "sext" | "trunc" | "inttoptr" | "ptrtoint" | "bitcast" => {
                    // Trouver "to" dans les tokens, la valeur est juste avant
                    if let Some(to_pos) = toks.iter().position(|&t| t == "to") {
                        if to_pos > 0 {
                            resolve(toks[to_pos - 1], regs, consts)
                        } else { 0 }
                    } else {
                        a // fallback
                    }
                },
                _ => 0,
            }
        }
    };

    regs_set(regs, &dst, val);
    RunResult::Ok
}

fn extract_binop_args<'a>(toks: &[&'a str]) -> (&'a str, &'a str) {
    // Cherche "op [flags...] type a, b"
    // Les flags sont : nuw, nsw, exact, nofree, etc.
    // On cherche le dernier token avant la virgule = a, et le dernier = b
    let len = toks.len();
    if len < 2 { return ("0", "0"); }
    let b_tok = toks[len-1].trim_end_matches(',');
    // 'a' est juste avant la virgule : cherche la virgule dans les tokens
    for i in (1..len-1).rev() {
        if toks[i].ends_with(',') {
            return (toks[i].trim_end_matches(','), b_tok);
        }
    }
    (toks[len-2].trim_end_matches(','), b_tok)
}

// Retourne Some(val) si le prédécesseur est trouvé, None sinon.
fn parse_phi_opt(rhs: &str, prev: &str, regs: &Regs, consts: &BTreeMap<String, i64>) -> Option<i64> {
    let mut pos = 0usize;
    while pos < rhs.len() {
        let Some(open) = rhs[pos..].find('[') else { break };
        let open_abs = pos + open;
        let Some(close) = rhs[open_abs..].find(']') else { break };
        let inner = &rhs[open_abs+1..open_abs+close];
        let parts: Vec<&str> = inner.split(',').collect();
        let val_tok = parts.first().map(|s| s.trim()).unwrap_or("0");
        let lbl_tok = parts.get(1).map(|s| s.trim().trim_start_matches('%')).unwrap_or("");
        if lbl_tok == prev {
            return Some(resolve(val_tok, regs, consts));
        }
        pos = open_abs + close + 1;
    }
    None
}
fn parse_phi(rhs: &str, prev: &str, regs: &Regs, consts: &BTreeMap<String, i64>) -> i64 {
    parse_phi_opt(rhs, prev, regs, consts).unwrap_or(0)
}

// ── Rendu texte ──────────────────────────────────────────────────────────────

/// Rendu bitmap 8×16 (FONT8X16) — fallback quand TTF non disponible.
unsafe fn draw_text_bitmap(
    x: i32, y: i32, tp: *const u8, fg: u32, bg: u32,
    fb: *mut u32, s: i32,
) {
    let font = FONT8X16.as_ptr();
    let mut cx = x;
    let mut ci = 0usize;
    loop {
        let ch = *tp.add(ci);
        if ch == 0 { break; }
        let glyph_off = (ch as usize) * 16;
        for row in 0..16i32 {
            let bits = *font.add(glyph_off + row as usize);
            for col in 0..8i32 {
                let on = (bits >> (7 - col)) & 1 != 0;
                let c = if on { fg } else { bg };
                let idx = ((y + row) * s + cx + col) as usize;
                fb.add(idx).write_volatile(c);
            }
        }
        cx += 8;
        ci += 1;
    }
}

/// Appelle une fonction OVC avec des arguments et retourne la valeur i64.
/// `extra_mods` : modules supplémentaires accessibles pour les appels cross-module
/// (ex. l'OVC lui-même pour les appels internes, GlyphRasterizer pour TtfParser).
fn exec_fn_raw_with_mods<'a>(
    ovc:        &'a [u8],
    mod_name:   &'a str,
    fn_name:    &str,
    args:       &[i64],
    ctx:        &ExecCtx,
    extra_mods: &[(&'a str, &'a str)],
) -> i64 {
    let text = core::str::from_utf8(ovc).unwrap_or("");
    if !text.starts_with("# Vyft OVC v1.0") { return 0; }
    let local_consts = parse_string_consts(text);
    let func = match find_function(text, fn_name) { Some(f) => f, None => return 0 };
    let arg_names = parse_def_args(func);
    let blocks = parse_blocks(func);
    let mut regs: Regs = Vec::new();
    for (i, a) in arg_names.iter().enumerate() {
        regs_set(&mut regs, &a, args.get(i).copied().unwrap_or(0));
    }
    let mut globals: Regs = Vec::new();
    // Construire la liste modules : le module courant + les modules extra
    let mut mods_vec: Vec<(&str, &str)> = alloc::vec::Vec::new();
    mods_vec.push((mod_name, text));
    for &(n, t) in extra_mods { mods_vec.push((n, t)); }
    run_blocks_cross(&blocks, &local_consts, &mut globals, &mut regs, ctx, "entry", mod_name, &mods_vec, 0)
}

fn exec_fn_raw(ovc: &[u8], fn_name: &str, args: &[i64], ctx: &ExecCtx) -> i64 {
    exec_fn_raw_with_mods(ovc, fn_name, fn_name, args, ctx, &[])
}

// Police effectivement chargée dans TtfParser (ptr + len du dernier Load réussi).
static mut TTF_LOADED_PTR: i64 = 0;
static mut TTF_LOADED_LEN: usize = 0;

/// (Re)joue TtfParser::Load si la police effective a changé. Le gate historique
/// `TTF_SCRATCH[104] == 0` ne rejouait JAMAIS le Load : au 1er frame la police
/// SRFS n'est pas encore montée (ctx.font_len retombe sur un fichier quelconque,
/// ex. 158 octets de Maraset.yaml) — le Load parsait n'importe quoi puis tous les
/// GetGlyphId rendaient 0 glyphe pour toujours (texte invisible sur le bureau).
fn ttf_ensure_loaded(ttf_bytes: &[u8], rast_text: &str, woff_text: &str, font_ptr: i64, ctx: &ExecCtx) {
    unsafe {
        if TTF_LOADED_PTR == font_ptr && TTF_LOADED_LEN == ctx.font_len && TTF_SCRATCH[104] != 0 {
            return;
        }
    }
    let load_mods: Vec<(&str, &str)> = if woff_text.starts_with("# Vyft OVC") {
        alloc::vec![("GlyphRasterizer", rast_text),
                    ("WoffReader", woff_text),
                    ("std___core___self___WoffReader", woff_text)]
    } else {
        alloc::vec![("GlyphRasterizer", rast_text)]
    };
    // Purge l'état d'un parse foireux (cmap offset bidon) avant de recharger.
    unsafe { TTF_SCRATCH[104] = 0; }
    exec_fn_raw_with_mods(ttf_bytes, "TtfParser", "Load", &[font_ptr, ctx.font_len as i64], ctx, &load_mods);
    unsafe {
        if TTF_SCRATCH[104] != 0 {
            TTF_LOADED_PTR = font_ptr;
            TTF_LOADED_LEN = ctx.font_len;
        }
    }
}

// ── Pipeline texte TTF partagé (GpuDrawTextFont / Align / Full) ──────────────
// Pose chaque glyphe sur la baseline COMMUNE de la ligne (y_top + ascent) avec
// ses offsets stb (xoff = side bearing, yoff = baseline → haut du bitmap) et
// avance de la vraie largeur hmtx + kerning. Sans ça, les glyphes étaient
// blittés haut-alignés à y et avancés de bmp_w+1 : texte qui « sautille »
// verticalement et espacement dépendant de la forme de chaque lettre.
struct TtfLine<'a> {
    ttf_bytes:  &'a [u8],
    rast_bytes: &'a [u8],
    ttf_mods:   &'a [(&'a str, &'a str)],
    rast_mods:  &'a [(&'a str, &'a str)],
    font_ptr:   i64,
    size:       i32,
    lsp:        i32,
}

/// Décode le prochain codepoint UTF-8 de tp[*i..end] et avance *i.
/// Sans ce décodage, « • » (U+2022) ou « ' » (U+2019) sortaient octet par
/// octet en glyphes Latin-1 (« â ¢ ») — texte non product-grade.
fn utf8_next(tp: *const u8, i: &mut usize, end: usize) -> u32 {
    let b0 = unsafe { *tp.add(*i) } as u32;
    *i += 1;
    if b0 < 0x80 { return b0; }
    let (need, mask) = if b0 >= 0xF0 { (3u32, 0x07u32) }
        else if b0 >= 0xE0 { (2, 0x0F) }
        else if b0 >= 0xC0 { (1, 0x1F) }
        else { return b0; };  // octet de continuation isolé → tel quel
    let mut cp = b0 & mask;
    for _ in 0..need {
        if *i >= end { break; }
        let b = unsafe { *tp.add(*i) } as u32;
        if b & 0xC0 != 0x80 { break; }
        cp = (cp << 6) | (b & 0x3F);
        *i += 1;
    }
    cp
}

/// Largeur en px de tp[start..end] (avances hmtx + kerning, sans rastériser).
/// Sert aux alignements centre/droite — remplace l'estimation n*size*0.6.
fn ttf_line_width(p: &TtfLine, ctx: &ExecCtx, tp: *const u8, start: usize, end: usize) -> i32 {
    let scale_k = unsafe { stb_scale_k(p.size) };
    let mut w = 0i32;
    let mut prev = 0i32;
    let mut i = start;
    while i < end {
        let cp = utf8_next(tp, &mut i, end);
        let gid = exec_fn_raw_with_mods(p.ttf_bytes, "TtfParser", "GetGlyphId",
            &[cp as i64], ctx, p.ttf_mods) as i32;
        if gid <= 0 { w += p.size / 2 + p.lsp; prev = 0; continue; }
        if prev > 0 { w += unsafe { stb_kern(prev, gid, scale_k) }; }
        let adv = unsafe { stb_advance(gid, scale_k) };
        w += if adv > 0 { adv } else { p.size / 2 } + p.lsp;
        prev = gid;
    }
    w
}

/// Rend tp[start..end] à partir de (x, y_top) — y_top = haut de ligne, la
/// baseline est déduite de l'ascent de la police. Retourne le cx final.
fn ttf_draw_line(
    p: &TtfLine, ctx: &ExecCtx, tp: *const u8, start: usize, end: usize,
    x: i32, y_top: i32, fg: i64, bg: i64,
) -> i32 {
    let scale_k  = unsafe { stb_scale_k(p.size) };
    let ascent   = unsafe { stb_ascent(scale_k) };
    let baseline = y_top + ascent;
    let fb_i64 = ctx.fb as i64;
    let stride_i64 = ctx.stride as i64;
    let mut cx = x;
    let mut prev = 0i32;
    let mut i = start;
    while i < end {
        let cp = utf8_next(tp, &mut i, end);
        let gid = exec_fn_raw_with_mods(p.ttf_bytes, "TtfParser", "GetGlyphId",
            &[cp as i64], ctx, p.ttf_mods) as i32;
        if gid <= 0 { cx += p.size / 2 + p.lsp; prev = 0; continue; }
        if prev > 0 { cx += unsafe { stb_kern(prev, gid, scale_k) }; }
        let adv = unsafe { stb_advance(gid, scale_k) };
        let glyf_off = exec_fn_raw_with_mods(p.ttf_bytes, "TtfParser", "GetGlyfOffset",
            &[gid as i64], ctx, p.ttf_mods);
        let mut bmp_w = 0i32;
        // glyf_off <= 0 (ex. espace : contour vide) → pas de bitmap, mais on
        // avance quand même de la vraie largeur hmtx.
        if glyf_off > 0 {
            let glyf_data = p.font_ptr.wrapping_add(glyf_off);
            ovc_arena_reset();
            let bitmap = exec_fn_raw_with_mods(p.rast_bytes, "GlyphRasterizer", "RasterizeGlyph",
                &[glyf_data, p.size as i64], ctx, p.rast_mods);
            if bitmap != 0 {
                let (bw, bh, xo, yo) = unsafe { (RAST_W as i32, RAST_H as i32, RAST_XOFF, RAST_YOFF) };
                bmp_w = bw;
                // ascent == 0 → métriques indisponibles : ancien rendu top-aligné.
                let (gx, gy) = if ascent > 0 { (cx + xo, baseline + yo) } else { (cx, y_top) };
                exec_fn_raw_with_mods(p.rast_bytes, "GlyphRasterizer", "DrawGlyphAt",
                    &[fb_i64, stride_i64, gx as i64, gy as i64, bitmap,
                      bw as i64, bh as i64, fg, bg], ctx, p.rast_mods);
            }
        }
        cx += if adv > 0 { adv } else if bmp_w > 0 { bmp_w + 1 } else { p.size / 2 };
        cx += p.lsp;
        prev = gid;
    }
    cx
}

// ── Bureau à fenêtres — accesseurs génériques RUNNING_APPS[i] ────────────────
// `args[0]` = index de fenêtre pour les deux ; `window_man_set` attend en plus
// `args[1]` = nouvelle valeur. Index hors bornes → no-op (0/valeur par défaut),
// jamais de panic — cohérent avec le reste du dispatch (tout builtin mal appelé
// depuis Maratine renvoie 0 plutôt que de faire planter le rendu).
fn window_man_get(args: &[i64], f: impl Fn(&crate::window_manager::RunningApp) -> i32) -> i64 {
    let Some(&i) = args.first() else { return 0; };
    unsafe { RUNNING_APPS.get(i as usize).map(|a| f(a) as i64).unwrap_or(0) }
}

fn window_man_set(args: &[i64], f: impl FnOnce(&mut crate::window_manager::RunningApp, i32)) -> i64 {
    if args.len() < 2 { return 0; }
    let i = args[0] as usize;
    let v = args[1] as i32;
    unsafe { if let Some(a) = RUNNING_APPS.get_mut(i) { f(a, v); } }
    0
}

// ── Dispatch des appels externes ──────────────────────────────────────────────

fn dispatch(
    fname:   &str,
    args:    &[i64],
    _consts: &BTreeMap<String, i64>,
    _globals:&Regs,
    ctx:     &ExecCtx,
) -> i64 {
    match fname {
        // ── DrvManSpec GOP ────────────────────────────────────────────────────
        "DrvManSpec___GopGetFrameBuffer___"     => ctx.fb as i64,
        "DrvManSpec___GopGetWidth___"           => ctx.width  as i64,
        "DrvManSpec___GopGetHeight___"          => ctx.height as i64,

        // ── DrvAPIInterCon Capture média (ShiCamera, ShiLooker) ───────────────
        // Photo = un vrai PNG (voir media_encode.rs), écrit sur l'ESP réel
        // (srfs_uefi_write — persiste, contrairement à SRFS_CACHE). Vidéo =
        // Start/CaptureFrame (appelé périodiquement par Mara pendant
        // l'enregistrement)/Stop, assemblées en un vrai AVI (BI_RGB, non
        // compressé — voir media_encode.rs pour l'honnêteté de ce choix).
        "DrvAPIInterCon___CaptureDirGet___" => capture_dir_get(),
        "DrvAPIInterCon___CaptureDirSet___" => {
            if !args.is_empty() && args[0] != 0 {
                let s = unsafe { read_cstr(args[0] as *const u8) };
                capture_dir_set(&s);
            }
            0
        },
        "DrvAPIInterCon___MediaCapturePhoto___" => {
            let w = ctx.width.max(0) as u32;
            let h = ctx.height.max(0) as u32;
            if w == 0 || h == 0 { return -1; }
            let rgba = capture_rgba(ctx);
            let png = crate::media_encode::png_encode(w, h, &rgba);
            let idx = unsafe { CAPTURE_COUNTER += 1; CAPTURE_COUNTER };
            let dir = unsafe { read_cstr(capture_dir_get() as *const u8) };
            let path = alloc::format!("{}/photo_{:04}.png", dir, idx);
            let ok = unsafe { srfs_uefi_write(UEFI_ST_PTR, &path, &png) };
            serial_log(alloc::format!(
                "[MEDIA] Photo '{}' ({} octets) -> {}\r\n", path, png.len(), ok
            ).as_bytes());
            if ok { 0 } else { -1 }
        },
        "DrvAPIInterCon___MediaVideoStart___" => {
            unsafe {
                VIDEO_FRAMES.clear();
                VIDEO_W = ctx.width;
                VIDEO_H = ctx.height;
            }
            0
        },
        "DrvAPIInterCon___MediaVideoCaptureFrame___" => unsafe {
            if VIDEO_FRAMES.len() >= MAX_VIDEO_FRAMES { return VIDEO_FRAMES.len() as i64; }
            if ctx.width != VIDEO_W || ctx.height != VIDEO_H { return VIDEO_FRAMES.len() as i64; }
            VIDEO_FRAMES.push(capture_bgr_bottomup(ctx));
            VIDEO_FRAMES.len() as i64
        },
        "DrvAPIInterCon___MediaVideoFrameCount___" => unsafe { VIDEO_FRAMES.len() as i64 },
        "DrvAPIInterCon___MediaVideoStop___" => {
            let (frames, w, h) = unsafe {
                (core::mem::take(&mut VIDEO_FRAMES), VIDEO_W, VIDEO_H)
            };
            if frames.is_empty() || w <= 0 || h <= 0 { return -1; }
            let frame_n = frames.len();
            let avi = crate::media_encode::avi_encode(w as u32, h as u32, 4, &frames);
            let idx = unsafe { CAPTURE_COUNTER += 1; CAPTURE_COUNTER };
            let dir = unsafe { read_cstr(capture_dir_get() as *const u8) };
            let path = alloc::format!("{}/video_{:04}.avi", dir, idx);
            let ok = unsafe { srfs_uefi_write(UEFI_ST_PTR, &path, &avi) };
            serial_log(alloc::format!(
                "[MEDIA] Video '{}' ({} frames, {} octets) -> {}\r\n", path, frame_n, avi.len(), ok
            ).as_bytes());
            if ok { 0 } else { -1 }
        },

        // ── DrvManSpec HID (SluHIIDMan.slul) — EFI_SIMPLE_POINTER_PROTOCOL +
        // EFI_SIMPLE_TEXT_INPUT_PROTOCOL, ouverts et pollés par le kernel dans
        // render_from_marep (mêmes protocoles standards que le firmware expose
        // pour tout port HID énuméré via ACPI, PS/2 ou USB). Init = simple accusé
        // de réception : l'ouverture matérielle réelle a lieu côté kernel, avant
        // que le premier frame ne soit exécuté.
        "DrvManSpec___KeyboardInit___" | "DrvManSpec___PointerInit___" => 0,
        "DrvManSpec___UefiPointerGetState___" => {
            (((ctx.pointer_x & 0xFFF) as i64) << 20)
                | (((ctx.pointer_y & 0xFFF) as i64) << 8)
                | ((ctx.pointer_btn & 0xFF) as i64)
        },
        "DrvManSpec___UefiReadKey___" => ctx.key_code as i64,
        "DrvManSpec___UefiPollKey___" => (ctx.key_code != 0) as i64,
        // Simple Text Input standard n'a pas de notion de "mode" — accusé de
        // réception uniquement (pas de fonctionnalité matérielle à fabriquer).
        "DrvManSpec___UefiSetKeyMode___" => 0,

        // ── DrvManSpec Block Device (SRFSMan.slul, NTFSMan.slul) ──────────────
        // Argument optionnel : id disque à activer (0=SRFS/SDC:, 1=NTFS).
        // Absence d'argument = ne change pas la sélection courante (compat.
        // avec les appels historiques à zéro argument).
        "DrvManSpec___UefiLocateDisk___" => {
            if args.len() >= 1 {
                unsafe { ACTIVE_DISK = args[0] as u8; }
            }
            srfs_disk_handle()
        },

        "DrvManSpec___DiskRead___" => {
            if args.len() >= 3 {
                let off  = args[0] as usize;
                let dst  = args[1] as *mut u8;
                let size = args[2] as usize;
                srfs_disk_read(off, dst, size)
            } else { 0 }
        },
        "DrvManSpec___DiskWrite___" => {
            // Écriture sur disque virtuel — no-op en phase UEFI
            if args.len() >= 3 { args[2] } else { 0 }
        },
        "DrvManSpec___MountPointRegister___" |
        "DrvAPIInterCon___MountPointRegister___" => {
            // args[0] = pointeur vers la lettre ("SDC:\\", "A:\\", ...),
            // args[1] = handle disque (non utilisé au-delà de la trace).
            let letter = if args.len() >= 1 && args[0] != 0 {
                let p = args[0] as *const u8;
                let mut len = 0usize;
                unsafe { while *p.add(len) != 0 && len < 64 { len += 1; } }
                unsafe { core::str::from_utf8(core::slice::from_raw_parts(p, len)).unwrap_or("?") }
            } else { "?" };
            let disk = unsafe { ACTIVE_DISK };
            let mut letter_c = letter.as_bytes().to_vec();
            letter_c.push(0);
            unsafe { MOUNT_TABLE.push((letter_c, disk)); }
            serial_log(alloc::format!("[MOUNT] {} -> disque {}\r\n", letter, disk).as_bytes());
            0
        },

        // ── SluWWANMan : signal cellulaire (voir commentaire de WWAN_DETECTED) ──
        "DrvAPIInterCon___WWANGetSignalLevel___" => wwan_get_signal_level(),
        "DrvAPIInterCon___WWANGetNetworkType___" => wwan_get_network_type(),
        "DrvAPIInterCon___WWANIsConnected___" => wwan_is_connected(),
        "DrvAPIInterCon___WWANIsDetected___" => wwan_is_detected(),
        "DrvAPIInterCon___WWANSetNetworkType___" => wwan_set_network_type(args.first().copied().unwrap_or(-1) as i32),

        // ── SluVMTools : backdoor VMware/QEMU (voir commentaire de VMTOOLS_PRESENT) ──
        "DrvAPIInterCon___VMToolsIsPresent___" => vmtools_is_present(),
        "DrvAPIInterCon___VMToolsAbsPointerEnabled___" => vmtools_abspointer_enabled(),
        "DrvAPIInterCon___VMToolsGetResizeCount___" => vmtools_get_resize_count(),

        // ── SluPwMan : actions d'alimentation réelles (voir commentaire de RUNTIME_SERVICES_PTR) ──
        "DrvAPIInterCon___PowerRestart___" => power_restart(),
        "DrvAPIInterCon___PowerShutdown___" => power_shutdown(),
        "DrvAPIInterCon___PowerSleep___" => power_sleep(),
        "DrvAPIInterCon___PowerSleepSupported___" => power_sleep_supported(),

        // ── SluDskMan : format/mount/unmount (voir commentaire de DISK_FORMATTED_SESSION) ──
        "DrvAPIInterCon___DiskFormat___" => disk_format(args.first().copied().unwrap_or(-1) as i32),
        "DrvAPIInterCon___DiskIsFormattedSession___" => disk_is_formatted_session(args.first().copied().unwrap_or(-1) as i32),
        "DrvAPIInterCon___DiskMount___" => disk_mount(args.first().copied().unwrap_or(-1) as i32),
        "DrvAPIInterCon___DiskUnmount___" => disk_unmount(args.first().copied().unwrap_or(-1) as i32),

        // ── Navigation dossiers (ShiLooker, onglet Disks) ──
        "DrvAPIInterCon___DiskBrowseGetPath___" => disk_browse_get_path(),
        "DrvAPIInterCon___DiskBrowseReset___" => {
            let root = if !args.is_empty() && args[0] != 0 { unsafe { read_cstr(args[0] as *const u8) } } else { "SDC:".into() };
            disk_browse_reset(&root);
            0
        },
        // Reset générique par disk_id (0=SDC, 1=A, 2+=volume physique réel) —
        // construit le bon préfixe côté Rust, voir disk_browse_reset_for_disk_id.
        "DrvAPIInterCon___DiskBrowseResetForDiskId___" => {
            disk_browse_reset_for_disk_id(args.first().copied().unwrap_or(0) as i32);
            0
        },
        "DrvAPIInterCon___DiskBrowseNavigateInto___" => {
            if args.is_empty() || args[0] == 0 { return -1; }
            let name = unsafe { read_cstr(args[0] as *const u8) };
            disk_browse_navigate_into(&name);
            0
        },
        "DrvAPIInterCon___DiskBrowseNavigateUp___" => { disk_browse_navigate_up(); 0 },
        // Crée un dossier/fichier dans le dossier courant, nom pris dans le champ de
        // texte (TextField*) — voir disk_browse_create_entry pour pourquoi la
        // concaténation de chemin se fait ici plutôt qu'en Mara.
        "DrvAPIInterCon___DiskBrowseCreateEntry___" => disk_browse_create_entry(args.first().copied().unwrap_or(-1) as i32),

        // ── Couleur personnalisable des dossiers (ShiLooker, menu contextuel) ──
        "DrvAPIInterCon___FolderColorGet___" => {
            let base = args.first().copied().unwrap_or(0);
            let name = args.get(1).copied().unwrap_or(0);
            folder_color_get(base, name)
        },
        "DrvAPIInterCon___FolderColorSet___" => {
            let base = args.first().copied().unwrap_or(0);
            let name = args.get(1).copied().unwrap_or(0);
            let argb = args.get(2).copied().unwrap_or(DEFAULT_FOLDER_COLOR as i64) as i32;
            folder_color_set(base, name, argb)
        },

        // ── Champ de texte générique (nom fichier/dossier) ──
        "DrvAPIInterCon___TextFieldAppendChar___" => text_field_append_char(args.first().copied().unwrap_or(0) as i32),
        "DrvAPIInterCon___TextFieldBackspace___" => text_field_backspace(),
        "DrvAPIInterCon___TextFieldClear___" => text_field_clear(),
        "DrvAPIInterCon___TextFieldGetPtr___" => text_field_get_ptr(),

        // ── Création de fichier .bmp minimal (header 24bpp + pixels unis) ──
        // args[0]=path_ptr args[1]=w args[2]=h args[3]=argb — construit le buffer
        // en RAM puis l'écrit directement via le même mécanisme que CaWriteFile
        // (SRFS_CACHE, seul chemin d'écriture réellement fonctionnel du noyau).
        "DrvAPIInterCon___DiskCreateBmpFile___" => {
            if args.len() >= 4 && args[0] != 0 {
                let path = unsafe { read_cstr(args[0] as *const u8) };
                let bytes = bmp_blank_buffer(args[1] as i32, args[2] as i32, args[3] as i32);
                srfs_write_chain_file(&path, &bytes);
                0
            } else { -1 }
        },
        "DrvManSpec___PtrWrite8At___" => {
            if args.len() >= 3 {
                let p   = args[0] as *mut u8;
                let off = args[1];
                let v   = args[2] as u8;
                if !p.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    unsafe { *p.add(off as usize) = v; }
                }
            }
            0
        },
        "DrvManSpec___PtrWrite32At___" => {
            if args.len() >= 3 {
                let p   = args[0] as *mut u8;
                let off = args[1];
                let val = args[2] as u32;
                if !p.is_null() && off >= 0 && off < 256 * 1024 * 1024 {
                    unsafe {
                        // écriture 4 octets little-endian (framebuffer BGRA)
                        core::ptr::write_unaligned(p.add(off as usize) as *mut u32, val);
                    }
                }
            }
            0
        },
        "DrvManSpec___WoffGetData___" => 0,
        "DrvManSpec___WoffScratchGet___" => {
            if args.len() >= 1 {
                let idx = args[0] as usize;
                if idx < 256 { unsafe { WOFF_SCRATCH[idx] } } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___WoffScratchSet___" => {
            if args.len() >= 2 {
                let idx = args[0] as usize;
                let val = args[1];
                if idx < 256 { unsafe { WOFF_SCRATCH[idx] = val; } }
            }
            0
        },

        // ── DrvAPIInterCon Registres généraux (scroll/drag persistants) ──────
        "DrvAPIInterCon___ScrollGet___" => {
            if args.len() >= 1 {
                let idx = args[0] as usize;
                if idx < 64 { unsafe { SCROLL_SCRATCH[idx] } } else { 0 }
            } else { 0 }
        },
        "DrvAPIInterCon___ScrollSet___" => {
            if args.len() >= 2 {
                let idx = args[0] as usize;
                let val = args[1];
                if idx < 64 { unsafe { SCROLL_SCRATCH[idx] = val; } }
            }
            0
        },

        // ── DrvAPIInterCon Menu contextuel (ShiLauncher, dock) ────────────────
        "DrvAPIInterCon___MenuOpen___" => {
            if args.len() >= 3 {
                unsafe {
                    MENU_OPEN = true;
                    MENU_OWNER_IDX = args[0] as i32;
                    MENU_X = args[1] as i32;
                    MENU_Y = args[2] as i32;
                    MENU_SUBMENU_IDX = -1;
                }
                serial_log(alloc::format!(
                    "[MENU] MenuOpen ownerIdx={} x={} y={}\r\n", args[0], args[1], args[2]
                ).as_bytes());
            }
            0
        },
        "DrvAPIInterCon___MenuClose___" => {
            unsafe { MENU_OPEN = false; MENU_OWNER_IDX = -1; MENU_SUBMENU_IDX = -1; }
            0
        },
        "DrvAPIInterCon___MenuIsOpen___" => unsafe { MENU_OPEN as i64 },
        "DrvAPIInterCon___MenuGetOwnerIdx___" => unsafe { MENU_OWNER_IDX as i64 },
        "DrvAPIInterCon___MenuGetX___" => unsafe { MENU_X as i64 },
        "DrvAPIInterCon___MenuGetY___" => unsafe { MENU_Y as i64 },
        "DrvAPIInterCon___MenuOpenSubmenu___" => {
            if let Some(&idx) = args.first() { unsafe { MENU_SUBMENU_IDX = idx as i32; } }
            0
        },
        "DrvAPIInterCon___MenuCloseSubmenu___" => { unsafe { MENU_SUBMENU_IDX = -1; } 0 },
        "DrvAPIInterCon___MenuGetOpenSubmenuIdx___" => unsafe { MENU_SUBMENU_IDX as i64 },

        // ── DrvAPIInterCon Menu contextuel (ShiLooker, couleur dossier) — état
        // dédié, voir commentaire sur FOLDER_MENU_OPEN. ──────────────────────
        "DrvAPIInterCon___FolderMenuOpen___" => {
            if args.len() >= 3 {
                unsafe {
                    FOLDER_MENU_OPEN = true;
                    FOLDER_MENU_ROW = args[0] as i32;
                    FOLDER_MENU_X = args[1] as i32;
                    FOLDER_MENU_Y = args[2] as i32;
                }
            }
            0
        },
        "DrvAPIInterCon___FolderMenuClose___" => {
            unsafe { FOLDER_MENU_OPEN = false; FOLDER_MENU_ROW = -1; }
            0
        },
        "DrvAPIInterCon___FolderMenuIsOpen___" => unsafe { FOLDER_MENU_OPEN as i64 },
        "DrvAPIInterCon___FolderMenuGetRow___" => unsafe { FOLDER_MENU_ROW as i64 },
        "DrvAPIInterCon___FolderMenuGetX___" => unsafe { FOLDER_MENU_X as i64 },
        "DrvAPIInterCon___FolderMenuGetY___" => unsafe { FOLDER_MENU_Y as i64 },

        // ── DrvAPIInterCon Menu global in-app ShiLauncher ─────────────────────
        "DrvAPIInterCon___MenuOpenGlobal___" => {
            if args.len() >= 2 {
                unsafe {
                    GLOBAL_MENU_OPEN = true;
                    GLOBAL_MENU_X = args[0] as i32;
                    GLOBAL_MENU_Y = args[1] as i32;
                    GLOBAL_MENU_CTX_ITEMS.clear(); // mode normal : liste des apps épinglées
                    GLOBAL_MENU_CTX_ID = -1;
                }
            }
            0
        },
        // Ouvre GlobalMenu en mode CONTEXTE : affiche `items` ("Label1|Label2",
        // liste plate SANS sous-menu) au lieu des apps épinglées — utilisé par
        // tout composant avec son propre menu contextuel (fichier, dossier,
        // disque monté...). `ctx_id` est une donnée libre renvoyée telle quelle
        // au clic (voir MenuGetGlobalClickedLabel/Gen/CtxId) — remplace
        // FolderMenu.mara et toute future carte contextuelle dédiée.
        "DrvAPIInterCon___MenuOpenGlobalWithItems___" => {
            if args.len() >= 4 && args[2] != 0 {
                let raw = unsafe { read_cstr(args[2] as *const u8) };
                let items: alloc::vec::Vec<alloc::vec::Vec<u8>> = raw
                    .split('|')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| { let mut v = s.as_bytes().to_vec(); v.push(0); v })
                    .collect();
                unsafe {
                    GLOBAL_MENU_OPEN = true;
                    GLOBAL_MENU_X = args[0] as i32;
                    GLOBAL_MENU_Y = args[1] as i32;
                    GLOBAL_MENU_CTX_ITEMS = items;
                    GLOBAL_MENU_CTX_ID = args[3] as i32;
                }
            }
            0
        },
        "DrvAPIInterCon___MenuCloseGlobal___" => {
            // Ferme aussi le sous-menu flottant (System power, etc.) — sinon
            // il resterait ouvert « fantôme » lors de la prochaine ouverture
            // du menu global, sans que son ancre/app propriétaire soit valide.
            unsafe {
                GLOBAL_MENU_OPEN = false;
                GLOBAL_MENU_SUBMENU_APP_IDX = -1;
                GLOBAL_MENU_SUBMENU_ITEM_IDX = -1;
                GLOBAL_MENU_CTX_ITEMS.clear();
                GLOBAL_MENU_CTX_ID = -1;
            }
            0
        },
        "DrvAPIInterCon___MenuIsOpenGlobal___" => unsafe { GLOBAL_MENU_OPEN as i64 },
        "DrvAPIInterCon___MenuGetGlobalX___" => unsafe { GLOBAL_MENU_X as i64 },
        "DrvAPIInterCon___MenuGetGlobalY___" => unsafe { GLOBAL_MENU_Y as i64 },
        // Mode contexte : actif si des items ont été fournis via
        // MenuOpenGlobalWithItems — GlobalMenu.mara lit ceci pour savoir s'il
        // doit lister les apps épinglées (0 item ctx) ou ces items précis.
        "DrvAPIInterCon___MenuGlobalIsCtxMode___" => unsafe { (!GLOBAL_MENU_CTX_ITEMS.is_empty()) as i64 },
        "DrvAPIInterCon___MenuGetGlobalCtxItemCount___" => unsafe { GLOBAL_MENU_CTX_ITEMS.len() as i64 },
        "DrvAPIInterCon___MenuGetGlobalCtxItemLabel___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { return 0; }
            unsafe { GLOBAL_MENU_CTX_ITEMS.get(i as usize).map(|v| v.as_ptr() as i64).unwrap_or(0) }
        },
        "DrvAPIInterCon___MenuGetGlobalCtxId___" => unsafe { GLOBAL_MENU_CTX_ID as i64 },
        // Enregistre le clic sur un item en mode contexte — GlobalMenu.mara
        // appelle ceci au lieu de MenuCloseGlobal seul, pour transmettre QUEL
        // label a été cliqué (même pattern que WindowManSetLaunchArg) : incrémente
        // la génération pour que l'appelant (ShiLooker...) ne le traite qu'une fois.
        "DrvAPIInterCon___MenuSetGlobalClicked___" => {
            if args.len() >= 1 && args[0] != 0 {
                let label = unsafe { read_cstr(args[0] as *const u8) };
                let mut label_c = label.into_bytes();
                label_c.push(0);
                unsafe {
                    GLOBAL_MENU_CLICKED_LABEL = label_c;
                    GLOBAL_MENU_CLICKED_CTX_ID = GLOBAL_MENU_CTX_ID;
                    GLOBAL_MENU_CLICKED_GEN += 1;
                }
            }
            0
        },
        "DrvAPIInterCon___MenuGetGlobalClickedLabel___" => unsafe {
            if GLOBAL_MENU_CLICKED_LABEL.is_empty() { 0 } else { GLOBAL_MENU_CLICKED_LABEL.as_ptr() as i64 }
        },
        "DrvAPIInterCon___MenuGetGlobalClickedCtxId___" => unsafe { GLOBAL_MENU_CLICKED_CTX_ID as i64 },
        "DrvAPIInterCon___MenuGetGlobalClickedGen___" => unsafe { GLOBAL_MENU_CLICKED_GEN as i64 },
        // Sous-menu flottant du menu global (ex: "System power" > Reboot/Sleep
        // screen/Shutdown/Standby) — voir commentaire de GLOBAL_MENU_SUBMENU_*.
        "DrvAPIInterCon___MenuOpenSubmenuGlobal___" => {
            if args.len() >= 4 {
                unsafe {
                    GLOBAL_MENU_SUBMENU_APP_IDX = args[0] as i32;
                    GLOBAL_MENU_SUBMENU_ITEM_IDX = args[1] as i32;
                    GLOBAL_MENU_SUBMENU_X = args[2] as i32;
                    GLOBAL_MENU_SUBMENU_Y = args[3] as i32;
                }
            }
            0
        },
        "DrvAPIInterCon___MenuCloseSubmenuGlobal___" => {
            unsafe { GLOBAL_MENU_SUBMENU_APP_IDX = -1; GLOBAL_MENU_SUBMENU_ITEM_IDX = -1; }
            0
        },
        "DrvAPIInterCon___MenuGetSubmenuGlobalAppIdx___" => unsafe { GLOBAL_MENU_SUBMENU_APP_IDX as i64 },
        "DrvAPIInterCon___MenuGetSubmenuGlobalItemIdx___" => unsafe { GLOBAL_MENU_SUBMENU_ITEM_IDX as i64 },
        "DrvAPIInterCon___MenuGetSubmenuGlobalX___" => unsafe { GLOBAL_MENU_SUBMENU_X as i64 },
        "DrvAPIInterCon___MenuGetSubmenuGlobalY___" => unsafe { GLOBAL_MENU_SUBMENU_Y as i64 },

        // ── DrvAPIInterCon AppRegistry (étendu pour menus) ─────────────────────
        // Menu global : itérer les apps pinned
        "DrvAPIInterCon___AppRegistryGetPinnedCount___" => crate::app_registry::registry_pinned_count(),
        "DrvAPIInterCon___AppRegistryGetPinnedIndex___" => {
            if let Some(&idx) = args.first() { return crate::app_registry::registry_pinned_index(idx as usize) }
            -1
        },

        // ── DrvAPIInterCon Sélecteur de dossier de capture (ShiCamera) ─────────
        // État isolé : propre curseur de navigation (CAPTURE_PICKER_PATH), jamais
        // partager DISK_BROWSE_PATH qui appartient à l'onglet Disque.
        "DrvAPIInterCon___CapturePickerOpen___" => {
            if args.len() >= 2 {
                unsafe {
                    CAPTURE_PICKER_OPEN = true;
                    CAPTURE_PICKER_X = args[0] as i32;
                    CAPTURE_PICKER_Y = args[1] as i32;
                }
            }
            0
        },
        "DrvAPIInterCon___CapturePickerClose___" => {
            unsafe { CAPTURE_PICKER_OPEN = false; }
            0
        },
        "DrvAPIInterCon___CapturePickerIsOpen___" => unsafe { CAPTURE_PICKER_OPEN as i64 },
        "DrvAPIInterCon___CapturePickerGetX___" => unsafe { CAPTURE_PICKER_X as i64 },
        "DrvAPIInterCon___CapturePickerGetY___" => unsafe { CAPTURE_PICKER_Y as i64 },
        "DrvAPIInterCon___CapturePickerBrowseGetPath___" => capture_picker_browse_get_path(),
        "DrvAPIInterCon___CapturePickerBrowseReset___" => {
            let root = if !args.is_empty() && args[0] != 0 {
                unsafe { read_cstr(args[0] as *const u8) }
            } else {
                "SDC:".into()
            };
            capture_picker_browse_reset(&root);
            0
        },
        "DrvAPIInterCon___CapturePickerBrowseNavigateInto___" => {
            if args.is_empty() || args[0] == 0 { return -1; }
            let name = unsafe { read_cstr(args[0] as *const u8) };
            capture_picker_browse_navigate_into(&name);
            0
        },
        "DrvAPIInterCon___CapturePickerBrowseNavigateUp___" => {
            capture_picker_browse_navigate_up();
            0
        },

        // ── DrvAPIInterCon Table de montage (disques réellement montés) ──────
        "DrvAPIInterCon___MountTableCount___" => mount_table_count(),
        "DrvAPIInterCon___MountTableGetLetter___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { 0 } else { mount_table_letter_ptr(i as usize) }
        },
        "DrvAPIInterCon___MountTableGetDiskId___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { -1 } else { mount_table_disk_id(i as usize) }
        },
        "DrvAPIInterCon___MountTableGetLabel___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { 0 } else { mount_table_label_ptr(i as usize) }
        },

        // ── DrvAPIInterCon Horloge système (UEFI GetTime réel) ───────────────
        "DrvAPIInterCon___ClockRefresh___" => clock_refresh() as i64,
        "DrvAPIInterCon___ClockGetTimeStr___" => clock_time_str_ptr(),
        "DrvAPIInterCon___ClockGetDateStr___" => clock_date_str_ptr(),

        // ── DrvManSpec TtfParser state ────────────────────────────────────────
        // TtfGetData/SetData : pointeur vers les bytes TTF en mémoire
        "DrvManSpec___TtfGetData___" => unsafe { TTF_DATA_PTR },
        "DrvManSpec___TtfSetData___" => {
            if args.len() >= 1 { unsafe { TTF_DATA_PTR = args[0]; } }
            0
        },
        // TtfScratchGet/Set : registres temporaires indexés (200 slots)
        // idx 100 = taille font, 101 = nb tables, 102-108 = offsets tables TTF,
        // 109 = unitsPerEm, 110-112 = hhea, 113 = locaFormat, 114 = numHMetrics
        "DrvManSpec___TtfScratchGet___" => {
            if args.len() >= 1 {
                let idx = args[0] as usize;
                if idx < 200 { unsafe { TTF_SCRATCH[idx] } } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___TtfScratchSet___" => {
            if args.len() >= 2 {
                let idx = args[0] as usize;
                let val = args[1];
                if idx < 200 { unsafe { TTF_SCRATCH[idx] = val; } }
            }
            0
        },

        // ── DrvManSpec Filesystem via cache SRFS (SRFSMan.slul) ──────────────
        // FSGetSize(path_ptr) → taille du fichier dans le cache SRFS
        // FSRead(path_ptr, buf, size) → copie les octets depuis le cache
        "DrvManSpec___FSGetSize___" => {
            let path_ptr = if args.len() >= 1 { args[0] } else { 0 };
            srfs_find(path_ptr).map(|d| d.len() as i64).unwrap_or(0)
        },
        "DrvManSpec___FSRead___" => {
            if args.len() >= 3 {
                if let Some(data) = srfs_find(args[0]) {
                    let dst = args[1] as *mut u8;
                    let req = args[2] as usize;
                    if !dst.is_null() {
                        let n = req.min(data.len());
                        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, n); }
                        return n as i64;
                    }
                }
            }
            0
        },

        // ── DrvManSpec Mémoire brute (TtfParser / GlyphRasterizer) ───────────
        // Limite de sécurité: offset > 16MB → accès invalide probable (offset négatif converti en usize énorme)
        "DrvManSpec___PtrReadI16At___" | "DrvManSpec___PtrRead16At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1];
                if !base.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    let o = off as usize;
                    unsafe {
                        let hi = *base.add(o)     as i64;
                        let lo = *base.add(o + 1) as i64;
                        (hi << 8) | lo
                    }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrReadU16At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1];
                if !base.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    let o = off as usize;
                    unsafe {
                        let hi = *base.add(o)     as i64;
                        let lo = *base.add(o + 1) as i64;
                        (hi << 8) | lo
                    }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrReadI32At___" | "DrvManSpec___PtrRead32At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1];
                if !base.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    // Lecture native-endian : cohérente avec PtrWrite32At (buffers internes OVC)
                    // TtfParser utilise _r32 fast-path (big-endian) pour les données font TTF
                    unsafe { core::ptr::read_unaligned(base.add(off as usize) as *const i32) as i64 }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrRead8At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1];
                if !base.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    unsafe { *base.add(off as usize) as i64 }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrAdd___" => {
            if args.len() >= 2 { args[0].wrapping_add(args[1]) } else { 0 }
        },

        // ── DrvManSpec Primitive matérielle générique : échange de 4 registres via
        // une instruction x86 IN sur un port I/O donné (mécanisme CPU brut, PAS lié
        // à un protocole précis). Args = [eax_in, ebx_in, ecx_in, edx_in] — le port
        // effectif lu est la valeur basse 16 bits d'edx_in (convention x86 standard :
        // seul DX adresse le port, EAX/EBX/ECX portent des données/paramètres selon
        // ce que le récepteur matériel en fait). Résultat (4 registres après
        // l'instruction) stocké dans HW_BACKDOOR_RESULT, lu ensuite via
        // HwBackdoorResultGet(0..3). Toute la logique protocole (constantes, séquence
        // d'activation, décodage paquet) vit côté Mara (SluHIIDMan.slul/HidImpl.mara)
        // — ce builtin ne connaît qu'un mécanisme CPU générique, jamais un vendor.
        "DrvManSpec___HwBackdoorCall___" => {
            if args.len() >= 4 {
                let (eax, ebx, ecx, edx) = hw_io_call(
                    args[0] as u32, args[1] as u32, args[2] as u32, args[3] as u32,
                );
                unsafe { HW_BACKDOOR_RESULT = [eax as i64, ebx as i64, ecx as i64, edx as i64]; }
            }
            0
        },
        // ── DrvManSpec Installation depuis un volume quelconque (Vmwaretool) ──
        // UefiProbeExists : lecture seule, essaie `path` (chemin ABSOLU depuis la
        // racine du volume, ex. "\Vmwaretool.marep") sur TOUS les filesystems
        // découverts (même mécanisme que srfs_uefi_read, qui ne présuppose déjà
        // aucun volume précis) — répond "oui" dès qu'UN volume (CD monté ou ESP)
        // contient ce chemin. UefiInstallFile lit `srcPath` (n'importe quel
        // volume, même mécanisme) et l'écrit RÉELLEMENT sur l'ESP à `dstPath`
        // (voir srfs_uefi_write) — persiste au reboot, contrairement à
        // CaWriteFile (SRFS_CACHE, RAM-only).
        "DrvManSpec___UefiProbeExists___" => {
            if args.len() >= 1 {
                let p = args[0] as *const u8;
                if !p.is_null() {
                    let path = unsafe { read_cstr(p) };
                    let found = unsafe { srfs_uefi_read(UEFI_ST_PTR, &path).is_some() };
                    serial_log(alloc::format!("[VMINSTALL] Probe '{}' -> {}\r\n", path, found).as_bytes());
                    return if found { 1 } else { 0 };
                }
            }
            0
        },
        "DrvManSpec___UefiInstallFile___" => {
            if args.len() >= 2 {
                let sp = args[0] as *const u8;
                let dp = args[1] as *const u8;
                if !sp.is_null() && !dp.is_null() {
                    let src_path = unsafe { read_cstr(sp) };
                    let dst_path = unsafe { read_cstr(dp) };
                    let read_result = unsafe { srfs_uefi_read(UEFI_ST_PTR, &src_path) };
                    serial_log(alloc::format!(
                        "[VMINSTALL] Read '{}' -> {:?} octets\r\n", src_path, read_result.as_ref().map(|d| d.len())
                    ).as_bytes());
                    if let Some(data) = read_result {
                        let write_ok = unsafe { srfs_uefi_write(UEFI_ST_PTR, &dst_path, &data) };
                        serial_log(alloc::format!(
                            "[VMINSTALL] Write '{}' ({} octets) -> {}\r\n", dst_path, data.len(), write_ok
                        ).as_bytes());
                        if write_ok {
                            return 0;
                        }
                    }
                }
            }
            -1
        },
        // ── DrvManSpec Détection de format (EncDecProcMan) ────────────────────
        // EncDecProbeFormat lit le fichier réel (SDC/NTFS via srfs_uefi_read,
        // même mécanisme que ImageLoad) et détecte son format par signature
        // binaire (format_detect.rs) — pas par extension de nom de fichier.
        // EncDecCanDecode renvoie honnêtement 2=décodage complet (image
        // affichable), 1=identification seule (conteneur reconnu, pas
        // d'échantillons extraits), 0=inconnu — voir media_encode.rs pour
        // pourquoi vidéo/audio réels ne sont pas dans la colonne "2" ici.
        "DrvManSpec___EncDecProbeFormat___" => {
            if args.len() >= 1 {
                let p = args[0] as *const u8;
                if !p.is_null() {
                    let path = unsafe { read_cstr(p) };
                    // "SDC:/path" → "SDC/slu64/path" (emplacement réel sur l'ESP) —
                    // même conversion que ImageLoad ; srfs_uefi_read attend un
                    // chemin déjà résolu, pas le préfixe Mara "SDC:".
                    let uefi_rel = if path.to_ascii_uppercase().starts_with("SDC:") {
                        let after = path[4..].trim_matches(|c: char| c == '/' || c == '\\');
                        alloc::format!("SDC/slu64/{}", after)
                    } else {
                        path.trim_start_matches(|c: char| c == '/' || c == '\\').to_string()
                    };
                    if let Some(data) = unsafe { srfs_uefi_read(UEFI_ST_PTR, &uefi_rel) } {
                        return crate::format_detect::detect_format(&data) as i64;
                    }
                }
            }
            crate::format_detect::FMT_UNKNOWN as i64
        },
        "DrvManSpec___EncDecCanDecode___" => {
            if args.len() >= 1 {
                crate::format_detect::decode_support(args[0] as i32) as i64
            } else { 0 }
        },
        "DrvManSpec___EncDecGetFormatName___" => {
            if args.len() >= 1 { encdec_format_name_ptr(args[0] as i32) } else { 0 }
        },
        "DrvManSpec___HwBackdoorResultGet___" => {
            if args.len() >= 1 {
                let idx = args[0] as usize;
                if idx < 4 { unsafe { HW_BACKDOOR_RESULT[idx] } } else { 0 }
            } else { 0 }
        },

        // ── DrvManSpec Résolution GOP dynamique ───────────────────────────────
        // WindowsResolution (GpuImpl.mara, SluGpu.slul) appelle SetResolution — voir
        // GOP_RESIZE_REQUEST ci-dessus pour pourquoi ça ne fait que poser une
        // demande. GopModeCount/GetW/GetH sont en lecture seule (sûrs immédiatement).
        "DrvManSpec___SetResolution___" => {
            if args.len() >= 2 {
                unsafe {
                    GOP_RESIZE_REQUEST = (args[0], args[1]);
                    GOP_RESIZE_PENDING = true;
                }
            }
            0
        },
        "DrvManSpec___GopModeCount___" => {
            unsafe { gop_mode_count(UEFI_ST_PTR) as i64 }
        },
        "DrvManSpec___GopModeGetW___" => {
            if args.len() >= 1 {
                unsafe { gop_mode_wh(UEFI_ST_PTR, args[0] as u32).map(|(w, _)| w as i64).unwrap_or(0) }
            } else { 0 }
        },
        "DrvManSpec___GopModeGetH___" => {
            if args.len() >= 1 {
                unsafe { gop_mode_wh(UEFI_ST_PTR, args[0] as u32).map(|(_, h)| h as i64).unwrap_or(0) }
            } else { 0 }
        },

        // ── DrvManSpec Police (TtfParser utilise ces primitives) ─────────────
        // UnitsPerEm est stocké dans un global partagé au moment du parse TTF.
        "DrvManSpec___FontGetUnitsPerEm___" => {
            // Valeur typique pour brsonomasemibold.ttf (1000 ou 2048)
            unsafe { FONT_UNITS_PER_EM as i64 }
        },
        "DrvManSpec___FontSetUnitsPerEm___" => {
            if args.len() >= 1 { unsafe { FONT_UNITS_PER_EM = args[0] as u32; } }
            0
        },
        // MathSafety : fonctions clamp (utilisées par GlyphRasterizer)
        "MathSafety___ClampI32___" => {
            if args.len() >= 3 {
                let v   = args[0];
                let min = args[1];
                let max = args[2];
                if v < min { min } else if v > max { max } else { v }
            } else { 0 }
        },
        "MathSafety___ClampU32___" => {
            if args.len() >= 3 {
                let v   = args[0] as u64;
                let min = args[1] as u64;
                let max = args[2] as u64;
                if v < min { min as i64 } else if v > max { max as i64 } else { v as i64 }
            } else { 0 }
        },

        "DrvManSpec___RastSetDims___" => {
            // Stocke les dimensions du raster en cours (width, height)
            if args.len() >= 2 {
                unsafe { RAST_W = args[0] as u32; RAST_H = args[1] as u32; }
            }
            0
        },
        "DrvManSpec___RastGetWidth___"  => unsafe { RAST_W as i64 },
        "DrvManSpec___RastGetHeight___" => unsafe { RAST_H as i64 },

        // ── Primitives natives stb_truetype (stb_font.obj) — relais des <stb_*___>
        // appelés par SluFontConf.slul. Le .slul reste l'orchestration ; ici on fournit
        // juste les primitives natives (le « pipeline stb » qui manquait au noyau).
        "stb_font_init___" => {
            let p = args.first().copied().unwrap_or(0) as *const u8;
            unsafe { stb_font_init(p) as i64 }
        },
        "stb_glyph_index___" => {
            let cp = args.first().copied().unwrap_or(0) as i32;
            unsafe { stb_glyph_index(cp) as i64 }
        },
        "stb_set_current_glyph___" => {
            let gi = args.first().copied().unwrap_or(0) as i32;
            unsafe { stb_set_current_glyph(gi); }
            0
        },
        "stb_get_current_glyph___" => unsafe { stb_get_current_glyph() as i64 },
        "stb_scale_k___" => {
            let px = args.first().copied().unwrap_or(0) as i32;
            unsafe { stb_scale_k(px) as i64 }
        },
        "stb_rasterize___" => {
            let gid = args.first().copied().unwrap_or(0) as i32;
            let sk  = args.get(1).copied().unwrap_or(0) as i32;
            let bmp = unsafe { stb_rasterize(gid, sk) };
            // Publie dimensions ET offsets baseline pour que le noyau (GpuDrawTextFont*)
            // puisse blitter chaque glyphe à sa vraie position typographique.
            unsafe {
                RAST_W = stb_bmp_w() as u32; RAST_H = stb_bmp_h() as u32;
                RAST_XOFF = stb_bmp_xoff(); RAST_YOFF = stb_bmp_yoff();
            }
            bmp as i64
        },
        "stb_bmp_w___"    => unsafe { stb_bmp_w() as i64 },
        "stb_bmp_h___"    => unsafe { stb_bmp_h() as i64 },
        "stb_bmp_yoff___" => unsafe { stb_bmp_yoff() as i64 },
        "stb_bmp_xoff___" => unsafe { stb_bmp_xoff() as i64 },
        "stb_advance___"  => {
            let gi = args.first().copied().unwrap_or(0) as i32;
            let sk = args.get(1).copied().unwrap_or(0) as i32;
            unsafe { stb_advance(gi, sk) as i64 }
        },
        "stb_ascent___"   => {
            let sk = args.first().copied().unwrap_or(0) as i32;
            unsafe { stb_ascent(sk) as i64 }
        },
        "stb_kern___"     => {
            let g1 = args.first().copied().unwrap_or(0) as i32;
            let g2 = args.get(1).copied().unwrap_or(0) as i32;
            let sk = args.get(2).copied().unwrap_or(0) as i32;
            unsafe { stb_kern(g1, g2, sk) as i64 }
        },

        // ── DrvManSpec Chaîne ─────────────────────────────────────────────────
        "DrvManSpec___StrLen___" => {
            if args.len() >= 1 {
                let p = args[0] as *const u8;
                if p.is_null() { return 0; }
                let mut n = 0usize;
                unsafe { while *p.add(n) != 0 { n += 1; } }
                n as i64
            } else { 0 }
        },
        "DrvManSpec___StrCharAt___" => {
            if args.len() >= 2 {
                let p = args[0] as *const u8;
                // Bornes explicites : `args[1] < 0` (ex. StrCharAt(p, StrLen(p)-1) sur
                // une chaîne vide → -1) caste en usize géant sans ce garde, produisant
                // un pointeur totalement hors-bornes — lecture mémoire non garantie qui
                // peut faire planter/redémarrer un système bare-metal (pas de MMU de
                // protection en UEFI). On scanne aussi jusqu'à l'index demandé pour
                // vérifier qu'aucun octet nul (fin de chaîne réelle) n'est rencontré
                // avant — un index au-delà de la vraie longueur est traité comme
                // hors-bornes plutôt que de lire au-delà du terminateur.
                if p.is_null() || args[1] < 0 { return 0; }
                let i = args[1] as usize;
                unsafe {
                    let mut n = 0usize;
                    while n <= i {
                        if *p.add(n) == 0 { return 0; }
                        n += 1;
                    }
                    *p.add(i) as i64
                }
            } else { 0 }
        },

        // Compare deux chaînes nul-terminées (bornées, aucune lecture hors
        // limites même sur une chaîne vide ou un pointeur null) — 1 si
        // identiques, 0 sinon. Utile pour router les actions du menu
        // contextuel (WindowManGetLaunchArg) sans dupliquer un parseur ad hoc.
        "DrvManSpec___StrEqual___" => {
            if args.len() < 2 { return 0; }
            let pa = args[0] as *const u8;
            let pb = args[1] as *const u8;
            if pa.is_null() || pb.is_null() { return 0; }
            unsafe {
                let mut i = 0usize;
                loop {
                    if i > 256 { return 0; } // borne dure — jamais de chaîne aussi longue ici
                    let ca = *pa.add(i);
                    let cb = *pb.add(i);
                    if ca != cb { return 0; }
                    if ca == 0 { return 1; } // les deux se terminent en même temps
                    i += 1;
                }
            }
        },

        // Compare deux chaînes nul-terminées (bornées, aucune lecture hors
        // limites même sur une chaîne vide ou un pointeur null) — 1 si
        // identiques, 0 sinon. Utile pour router les actions du menu
        // contextuel (WindowManGetLaunchArg) sans dupliquer un parseur ad hoc.
        "DrvManSpec___StrEqual___" => {
            if args.len() < 2 { return 0; }
            let pa = args[0] as *const u8;
            let pb = args[1] as *const u8;
            if pa.is_null() || pb.is_null() { return 0; }
            unsafe {
                let mut i = 0usize;
                loop {
                    if i > 256 { return 0; } // borne dure — jamais de chaîne aussi longue ici
                    let ca = *pa.add(i);
                    let cb = *pb.add(i);
                    if ca != cb { return 0; }
                    if ca == 0 { return 1; } // les deux se terminent en même temps
                    i += 1;
                }
            }
        },

        // ── MathSafety (GlyphRasterizer utilise ClampI32) ────────────────────
        "MathSafety___ClampI32___" => {
            if args.len() >= 3 {
                let v   = args[0] as i32;
                let lo  = args[1] as i32;
                let hi  = args[2] as i32;
                v.max(lo).min(hi) as i64
            } else { 0 }
        },

        // ── DrvAPIInterCon Mémoire (GlyphRasterizer utilise MemAlloc/Set) ────
        // Utilise l'arène statique OVC (512KB) au lieu du heap UEFI limité.
        "DrvAPIInterCon___MemAlloc___" => {
            if args.len() >= 1 {
                let size  = args[0] as usize;
                let align = if args.len() >= 3 { args[2] as usize } else { 8 };
                let align = align.max(1).next_power_of_two().min(64);
                let p = ovc_arena_alloc(size, align);
                p as i64
            } else { 0 }
        },
        "DrvAPIInterCon___MemFree___" => {
            // Note : on ne libère pas en UEFI boot (heap gérée par UEFI)
            0
        },
        "DrvAPIInterCon___MemSet___" => {
            if args.len() >= 3 {
                let p   = args[0] as *mut u8;
                let val = args[1] as u8;
                let sz  = args[2] as usize;
                if !p.is_null() { unsafe { core::ptr::write_bytes(p, val, sz); } }
            }
            0
        },
        "DrvAPIInterCon___MemCopy___" => {
            if args.len() >= 3 {
                let dst = args[0] as *mut u8;
                let src = args[1] as *const u8;
                let sz  = args[2] as usize;
                if !dst.is_null() && !src.is_null() {
                    unsafe { core::ptr::copy_nonoverlapping(src, dst, sz); }
                }
            }
            0
        },
        "DrvAPIInterCon___MemRead8___" => {
            if args.len() >= 2 {
                let p = args[0] as *const u8;
                let i = args[1] as usize;
                if !p.is_null() { unsafe { *p.add(i) as i64 } } else { 0 }
            } else { 0 }
        },
        "DrvAPIInterCon___MemWrite8___" => {
            if args.len() >= 3 {
                let p = args[0] as *mut u8;
                let i = args[1] as usize;
                let v = args[2] as u8;
                if !p.is_null() { unsafe { *p.add(i) = v; } }
            }
            0
        },
        "DrvAPIInterCon___MemWrite32___" | "DrvAPIInterCon___PtrWrite32At___" => {
            if args.len() >= 3 {
                let p   = args[0] as *mut u8;
                let off = args[1] as usize;
                let val = args[2] as u32;
                if !p.is_null() {
                    unsafe { *(p.add(off) as *mut u32) = val; }
                }
            }
            0
        },
        "DrvAPIInterCon___MemRead32___" => {
            if args.len() >= 2 {
                let p = args[0] as *const u8;
                let i = args[1] as usize;
                if !p.is_null() { unsafe { *(p.add(i) as *const u32) as i64 } } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___GopGetPixelsPerScanLine___" => ctx.stride as i64,
        "DrvManSpec___GetBitmapFont8x16___"     => FONT8X16.as_ptr() as i64,
        "DrvManSpec___GopCacheState___"         => 0,

        // (PtrWrite32At et PtrRead8At déjà définis ci-dessus avec bounds check)

        // StrLen(ptr) — null-terminated
        "DrvManSpec___StrLen___" => {
            if args.len() >= 1 {
                let p = args[0] as *const u8;
                if !p.is_null() {
                    let mut n = 0i64;
                    unsafe { while *p.add(n as usize) != 0 { n += 1; } }
                    return n;
                }
            }
            0
        },

        // StrCharAt(ptr, idx)
        "DrvManSpec___StrCharAt___" => {
            // Dupliqué de l'arm plus haut (inatteignable — le premier match gagne
            // dans un `match` Rust) — bornes appliquées ici aussi par cohérence,
            // voir le commentaire de la première occurrence.
            if args.len() >= 2 {
                let p = args[0] as *const u8;
                if p.is_null() || args[1] < 0 { return 0; }
                let idx = args[1] as usize;
                unsafe {
                    let mut n = 0usize;
                    while n <= idx {
                        if *p.add(n) == 0 { return 0; }
                        n += 1;
                    }
                    return *p.add(idx) as i64;
                }
            }
            0
        },

        // ── DrvAPIInterCon GPU — appelés depuis HelloWorld.ovc ───────────────
        // Ces fonctions sont le pont entre HelloSlura.marep et SluGpu.slul.

        "DrvAPIInterCon___GpuGetWidth___"  => ctx.width  as i64,
        "DrvAPIInterCon___GpuGetHeight___" => ctx.height as i64,

        // GpuFill(color_argb) — remplit tout le framebuffer (respecte GPU_OPACITY)
        "DrvAPIInterCon___GpuFill___" => {
            unsafe { GPU_FILLS += 1; }
            serial_log(b"[GPU] GpuFill\r\n");
            if args.len() >= 1 {
                let c  = args[0] as u32;
                let sr = (c >> 16) & 0xFF;
                let sg = (c >>  8) & 0xFF;
                let sb =  c        & 0xFF;
                let sa = (c >> 24) & 0xFF;
                let fb    = ctx.fb;
                let total = (ctx.stride * ctx.height) as usize;
                if !fb.is_null() {
                    for i in 0..total {
                        unsafe { gpu_write_pixel(fb, i, sr, sg, sb, sa); }
                    }
                }
            }
            0
        },

        // GpuDrawRect(x, y, w, h, color) — tous passés comme entiers (inttoptr)
        "DrvAPIInterCon___GpuDrawRect___" => {
            unsafe { GPU_RECTS += 1; }
            if args.len() >= 5 {
                let x  = args[0] as i32;
                let y  = args[1] as i32;
                let w  = args[2] as i32;
                let h  = args[3] as i32;
                let c  = args[4] as u32;
                let sr = (c >> 16) & 0xFF;
                let sg = (c >>  8) & 0xFF;
                let sb =  c        & 0xFF;
                let sa = (c >> 24) & 0xFF;
                let fb = ctx.fb;
                let s  = ctx.stride;
                let sw = ctx.width; let sh = ctx.height;
                if !fb.is_null() && w > 0 && h > 0 {
                    for row in 0..h {
                        for col in 0..w {
                            let (fx, fy) = unsafe { gpu_transform_point(x + col, y + row) };
                            if fx < 0 || fx >= sw || fy < 0 || fy >= sh { continue; }
                            let idx = (fy * s + fx) as usize;
                            unsafe { gpu_write_pixel(fb, idx, sr, sg, sb, sa); }
                        }
                    }
                }
            }
            0
        },

        // GpuDrawLine(x1, y1, x2, y2, color) — ligne droite simple (Bresenham)
        "DrvAPIInterCon___GpuDrawLine___" => {
            if args.len() >= 5 {
                let x1 = args[0] as i32;
                let y1 = args[1] as i32;
                let x2 = args[2] as i32;
                let y2 = args[3] as i32;
                let c  = args[4] as u32;
                let sr = (c >> 16) & 0xFF;
                let sg = (c >>  8) & 0xFF;
                let sb =  c        & 0xFF;
                let sa = (c >> 24) & 0xFF;
                let fb = ctx.fb;
                let s  = ctx.stride;
                let sw = ctx.width; let sh = ctx.height;
                if !fb.is_null() {
                    let dx = (x2 - x1).abs();
                    let dy = -(y2 - y1).abs();
                    let sx = if x1 < x2 { 1 } else { -1 };
                    let sy = if y1 < y2 { 1 } else { -1 };
                    let mut err = dx + dy;
                    let mut x = x1;
                    let mut y = y1;
                    loop {
                        let (fx, fy) = unsafe { gpu_transform_point(x, y) };
                        if fx >= 0 && fx < sw && fy >= 0 && fy < sh {
                            let idx = (fy * s + fx) as usize;
                            unsafe { gpu_write_pixel(fb, idx, sr, sg, sb, sa); }
                        }
                        if x == x2 && y == y2 { break; }
                        let e2 = 2 * err;
                        if e2 >= dy {
                            if x == x2 { break; }
                            err += dy;
                            x += sx;
                        }
                        if e2 <= dx {
                            if y == y2 { break; }
                            err += dx;
                            y += sy;
                        }
                    }
                }
            }
            0
        },

        // GpuDrawRoundedRectSolid(x, y, w, h, radius, color) — coins ronds, opaque
        "DrvAPIInterCon___GpuDrawRoundedRectSolid___" => {
            if args.len() >= 6 {
                let x      = args[0] as i32;
                let y      = args[1] as i32;
                let w      = args[2] as i32;
                let h      = args[3] as i32;
                let radius = args[4] as i32;
                let c      = args[5] as u32;
                let sr     = (c >> 16) & 0xFF;
                let sg     = (c >>  8) & 0xFF;
                let sb     =  c        & 0xFF;
                let sa     = 0xFF_u32; // Solid = opaque (GPU_OPACITY scale appliqué dans gpu_write_pixel)
                let fb     = ctx.fb;
                let s      = ctx.stride;
                let r2     = radius * radius;
                let sw = ctx.width; let sh = ctx.height;
                if !fb.is_null() && w > 0 && h > 0 {
                    for row in 0..h {
                        let et  = radius - row;
                        let eb  = row - (h - radius) + 1;
                        let cdy = if et > 0 { et } else if eb > 0 { eb } else { 0 };
                        for col in 0..w {
                            let el  = radius - col;
                            let er  = col - (w - radius) + 1;
                            let cdx = if el > 0 { el } else if er > 0 { er } else { 0 };
                            if cdx > 0 && cdy > 0 && cdx * cdx + cdy * cdy > r2 { continue; }
                            let (fx, fy) = unsafe { gpu_transform_point(x + col, y + row) };
                            if fx < 0 || fx >= sw || fy < 0 || fy >= sh { continue; }
                            let idx = (fy * s + fx) as usize;
                            unsafe { gpu_write_pixel(fb, idx, sr, sg, sb, sa); }
                        }
                    }
                }
            }
            0
        },

        // GpuDrawRoundedRectAlpha(x, y, w, h, radius, color_argb) — coins ronds + alpha blending
        "DrvAPIInterCon___GpuDrawRoundedRectAlpha___" => {
            if args.len() >= 6 {
                let x      = args[0] as i32;
                let y      = args[1] as i32;
                let w      = args[2] as i32;
                let h      = args[3] as i32;
                let radius = args[4] as i32;
                let c      = args[5] as u32;
                // GPU_OPACITY scale : alpha_effectif = color_alpha * GPU_OPACITY / 255
                let opa    = unsafe { GPU_OPACITY };
                let alpha  = ((c >> 24) & 0xFF) * opa / 255;
                let fb = ctx.fb;
                let s  = ctx.stride;
                let sw = ctx.width; let sh = ctx.height;
                if alpha > 0 && !fb.is_null() && w > 0 && h > 0 {
                    let r2 = radius * radius;
                    let sr = ((c >> 16) & 0xFF) as u32;
                    let sg = ((c >>  8) & 0xFF) as u32;
                    let sb = ( c        & 0xFF) as u32;
                    let ia = 255 - alpha;
                    if unsafe { GPU_TRANSFORM_ACTIVE } {
                        // Mapping arrière (rotation inverse) — le mapping avant (un pixel source →
                        // un pixel destination) laisse des trous en damier sur les rectangles tournés :
                        // une rotation déplace chaque pas source d'~1px destination dans une direction
                        // diagonale, et l'arrondi entier fait sauter certains pixels destination d'une
                        // ligne de balayage à l'autre. On parcourt ici les pixels de la bbox destination
                        // (coins du rect tourné vers l'avant) et on retrouve le pixel source par
                        // transformation inverse — couverture exhaustive, aucun trou possible.
                        let t = unsafe { GPU_TRANSFORM };
                        let (ta, tb, tc, td, ttx, tty) = (t[0], t[1], t[2], t[3], t[4], t[5]);
                        let corners = [(x, y), (x + w, y), (x, y + h), (x + w, y + h)];
                        let mut min_fx = i32::MAX; let mut max_fx = i32::MIN;
                        let mut min_fy = i32::MAX; let mut max_fy = i32::MIN;
                        for &(cx, cy) in corners.iter() {
                            let fx = ta * cx / 10000 + tc * cy / 10000 + ttx;
                            let fy = tb * cx / 10000 + td * cy / 10000 + tty;
                            if fx < min_fx { min_fx = fx; } if fx > max_fx { max_fx = fx; }
                            if fy < min_fy { min_fy = fy; } if fy > max_fy { max_fy = fy; }
                        }
                        min_fx = min_fx.max(0); max_fx = max_fx.min(sw - 1);
                        min_fy = min_fy.max(0); max_fy = max_fy.min(sh - 1);
                        let (ta64, tb64, tc64, td64) = (ta as i64, tb as i64, tc as i64, td as i64);
                        let det = ta64 * td64 - tc64 * tb64;
                        if det != 0 {
                            for fy in min_fy..=max_fy {
                                for fx in min_fx..=max_fx {
                                    let dx = (fx - ttx) as i64;
                                    let dy = (fy - tty) as i64;
                                    let lx = ((td64 * dx - tc64 * dy) * 10000 / det) as i32 - x;
                                    let ly = ((-tb64 * dx + ta64 * dy) * 10000 / det) as i32 - y;
                                    if lx < 0 || lx >= w || ly < 0 || ly >= h { continue; }
                                    if radius > 0 {
                                        let el = radius - lx; let er = lx - (w - radius) + 1;
                                        let cdx = if el > 0 { el } else if er > 0 { er } else { 0 };
                                        let et = radius - ly; let eb = ly - (h - radius) + 1;
                                        let cdy = if et > 0 { et } else if eb > 0 { eb } else { 0 };
                                        if cdx > 0 && cdy > 0 && cdx * cdx + cdy * cdy > r2 { continue; }
                                    }
                                    let idx = (fy * s + fx) as usize;
                                    let dst = unsafe { fb.add(idx).read_volatile() };
                                    let db  = (dst        & 0xFF) as u32;
                                    let dg  = ((dst >>  8) & 0xFF) as u32;
                                    let dr  = ((dst >> 16) & 0xFF) as u32;
                                    let nr  = (sr * alpha + dr * ia) / 255;
                                    let ng  = (sg * alpha + dg * ia) / 255;
                                    let nb  = (sb * alpha + db * ia) / 255;
                                    let blended: u32 = 0xFF000000 | (nr << 16) | (ng << 8) | nb;
                                    unsafe { fb.add(idx).write_volatile(blended); }
                                }
                            }
                        }
                    } else {
                        for row in 0..h {
                            let et  = radius - row;
                            let eb  = row - (h - radius) + 1;
                            let cdy = if et > 0 { et } else if eb > 0 { eb } else { 0 };
                            for col in 0..w {
                                let el  = radius - col;
                                let er  = col - (w - radius) + 1;
                                let cdx = if el > 0 { el } else if er > 0 { er } else { 0 };
                                if cdx > 0 && cdy > 0 && cdx * cdx + cdy * cdy > r2 { continue; }
                                let (fx, fy) = unsafe { gpu_transform_point(x + col, y + row) };
                                if fx < 0 || fx >= sw || fy < 0 || fy >= sh { continue; }
                                let idx = (fy * s + fx) as usize;
                                let dst = unsafe { fb.add(idx).read_volatile() };
                                let db  = (dst        & 0xFF) as u32;
                                let dg  = ((dst >>  8) & 0xFF) as u32;
                                let dr  = ((dst >> 16) & 0xFF) as u32;
                                let nr  = (sr * alpha + dr * ia) / 255;
                                let ng  = (sg * alpha + dg * ia) / 255;
                                let nb  = (sb * alpha + db * ia) / 255;
                                let blended: u32 = 0xFF000000 | (nr << 16) | (ng << 8) | nb;
                                unsafe { fb.add(idx).write_volatile(blended); }
                            }
                        }
                    }
                }
            }
            0
        },

        // GpuDrawText(x, y, text_ptr, fg, bg) — police 8×16 depuis FONT8X16
        "DrvAPIInterCon___GpuDrawText___" => {
            unsafe { GPU_TEXTS += 1; }
            serial_log(b"[GPU] GpuDrawText\r\n");
            if args.len() >= 5 {
                let x    = args[0] as i32;
                let y    = args[1] as i32;
                let tp   = args[2] as *const u8;
                let fg   = args[3] as u32;
                let bg   = args[4] as u32;
                let fb   = ctx.fb;
                let s    = ctx.stride;
                if !fb.is_null() && !tp.is_null() {
                    let font = FONT8X16.as_ptr();
                    let mut cx = x;
                    let mut ci = 0usize;
                    loop {
                        let ch = unsafe { *tp.add(ci) };
                        if ch == 0 { break; }
                        let glyph_off = (ch as usize) * 16;
                        for row in 0..16i32 {
                            let bits = unsafe { *font.add(glyph_off + row as usize) };
                            for col in 0..8i32 {
                                let on = (bits >> (7 - col)) & 1 != 0;
                                let c = if on { fg } else { bg };
                                let idx = ((y + row) * s + cx + col) as usize;
                                unsafe { fb.add(idx).write_volatile(c); }
                            }
                        }
                        cx += 8;
                        ci += 1;
                    }
                }
            }
            0
        },

        // DrvAPIInterCon***FontGetDefault*** — retourne le 1er font du cache SRFS
        "DrvAPIInterCon___FontGetDefault___" => {
            let (ptr, _) = srfs_font_ptr();
            ptr as i64
        },

        // DrvAPIInterCon***FontLoad*** — charge un font par chemin SRFS déclaré dans le marep.
        // Chemin déclaré dans HelloWorld.mara : "SDC:\\boot\\assets\\font\\..."
        // 1. Cherche dans le cache SRFS (si déjà chargé)
        // 2. Sinon, charge depuis l'ESP UEFI via le loader dynamique
        "DrvAPIInterCon___FontLoad___" => {
            if args.len() >= 1 {
                serial_log(b"[FontLoad] path_ptr=");
                    serial_log(b"\r\n");
                if args[0] == 0 {
                    serial_log(b"[FontLoad] path=0 constructor not run?\r\n");
                    return 0;
                }
                // Cache hit ?
                if let Some(data) = srfs_find(args[0]) {
                    serial_log(b"[FontLoad] cache hit\r\n");
                    return data.as_ptr() as i64;
                }
                // Chargement à la demande depuis l'ESP
                let ptr = srfs_load_on_demand(args[0]);
                if ptr == 0 { serial_log(b"[FONT] FontLoad: echec\r\n"); }
                ptr
            } else { 0 }
        },

        // GpuDrawTextFont(x, y, text, fg, bg, font, pixelSize)
        // Version avec police TTF — utilise TtfParser + GlyphRasterizer si disponibles,
        // sinon fallback sur FONT8X16.
        // GpuDrawTextFont : orchestration Rust → TtfParser.ovc + GlyphRasterizer.ovc
        // Les algorithmes de rendu restent dans SluFontConf.slul/base/
        "DrvAPIInterCon___GpuDrawTextFont___" => {
            unsafe { GPU_TEXTS += 1; }
            serial_log(b"[GPU] GpuDrawTextFont\r\n");
            if args.len() < 5 { serial_log(b"[D] args<5\r\n"); return 0; }
            let x        = args[0] as i32;
            let y        = args[1] as i32;
            let tp       = args[2] as *const u8;
            let fg       = args[3];
            let bg       = args[4];
            let font_ptr = if args.len() >= 6 { args[5] } else { 0 };
            let size     = if args.len() >= 7 { args[6] as i32 } else { 16 };

            // Logs détaillés : font_ptr, fg, bg, size, ctx.font_len
            serial_log(b" fl=");
            serial_log(&[(ctx.font_len % 1000) as u8 / 100 + b'0',
                          (ctx.font_len % 100)  as u8 / 10  + b'0',
                          (ctx.font_len % 10)   as u8        + b'0']);
            serial_log(b"\r\n");
            let fg_b = (fg as u32).to_be_bytes();
            serial_log(&fg_b);
            serial_log(b" bg=");
            let bg_b = (bg as u32).to_be_bytes();
            serial_log(&bg_b);
            serial_log(b"\r\n");

            if tp.is_null() || font_ptr == 0 { serial_log(b"[D] skip null\r\n"); return 0; }

            let ttf_bytes  = unsafe { FONT_TTF_OVC.as_deref()  }.unwrap_or(&[]);
            let rast_bytes = unsafe { FONT_RAST_OVC.as_deref() }.unwrap_or(&[]);
            let woff_bytes = unsafe { FONT_WOFF_OVC.as_deref() }.unwrap_or(&[]);
            if ttf_bytes.is_empty() || rast_bytes.is_empty() { return 0; }
            let ttf_text  = core::str::from_utf8(ttf_bytes).unwrap_or("");
            let rast_text = core::str::from_utf8(rast_bytes).unwrap_or("");
            let woff_text = core::str::from_utf8(woff_bytes).unwrap_or("");

            // ── Étape 1 : Load (rejoué si la police effective change) ────────
            ttf_ensure_loaded(ttf_bytes, rast_text, woff_text, font_ptr, ctx);

            let ttf_mods   = [("GlyphRasterizer", rast_text)];
            let rast_mods  = [("TtfParser", ttf_text)];

            // ── Étape 2 : rendu baseline + avance hmtx (pipeline partagé) ────
            let mut n = 0usize;
            unsafe { while *tp.add(n) != 0 { n += 1; } }
            let pipe = TtfLine {
                ttf_bytes, rast_bytes,
                ttf_mods: &ttf_mods, rast_mods: &rast_mods,
                font_ptr, size, lsp: 0,
            };
            ttf_draw_line(&pipe, ctx, tp, 0, n, x, y, fg, bg);
            serial_log(b"[FONT] rendered\r\n");
            0
        },

        // ImageLoad(path_ptr) — charge et décode un PNG RGBA depuis l'ESP UEFI.
        // Retourne un handle entier (1-based) ou 0 en cas d'erreur.
        // Chaque appel avec un path différent occupe un slot distinct dans IMAGE_CACHE.
        // NB: bypass SRFS_CACHE (8 slots) — les PNG bruts ne sont pas mis en cache
        // car ils sont immédiatement décodés dans IMAGE_CACHE (26 slots).
        "DrvAPIInterCon___ImageLoad___" => {
            if args.len() < 1 || args[0] == 0 { return 0; }
            serial_log(b"[IMG] ImageLoad\r\n");
            // Extraire le chemin depuis le pointeur de chaîne
            let path_ptr = args[0] as *const u8;
            let mut path_len = 0usize;
            unsafe { while *path_ptr.add(path_len) != 0 && path_len < 512 { path_len += 1; } }
            let rel = match core::str::from_utf8(unsafe { core::slice::from_raw_parts(path_ptr, path_len) }) {
                Ok(s) => s,
                Err(_) => { serial_log(b"[IMG] file not found\r\n"); return 0; }
            };
            serial_log(b"[IMG] path: ");
            serial_log(rel.as_bytes());
            serial_log(b"\r\n");
            // Charger les octets PNG bruts — SRFS_CACHE en fast-path, ESP direct sinon
            let raw_owned: alloc::vec::Vec<u8> = {
                if let Some(d) = srfs_find(args[0]) {
                    d.to_vec()
                } else {
                    // Lecture directe depuis l'ESP sans stocker dans SRFS_CACHE
                    // (évite le dépassement des 8 slots quand 26 images sont chargées)
                    let uefi_rel = if rel.to_ascii_uppercase().starts_with("SDC:") {
                        let after = rel[4..].trim_matches(|c: char| c == '/' || c == '\\');
                        alloc::format!("SDC/slu64/{}", after)
                    } else {
                        rel.trim_start_matches(|c: char| c == '/' || c == '\\').to_string()
                    };
                    let st_raw = unsafe { UEFI_ST_PTR };
                    if st_raw.is_null() { serial_log(b"[IMG] file not found\r\n"); return 0; }
                    match unsafe { srfs_uefi_read(st_raw, &uefi_rel) } {
                        Some(d) => d,
                        None => { serial_log(b"[IMG] file not found\r\n"); return 0; }
                    }
                }
            };
            serial_log(b"[IMG] decode\r\n");
            let decoded = png_decode_rgba(&raw_owned)
                .or_else(|| crate::image_decode::bmp_decode_rgba(&raw_owned))
                .or_else(|| crate::image_decode::gif_decode_rgba(&raw_owned));
            match decoded {
                Some((w, h, pixels)) => {
                    // Slot libre ou LRU eviction (8 slots max)
                    let idx = unsafe {
                        match IMAGE_CACHE.iter().position(|s| s.is_none()) {
                            Some(i) => i,
                            None => {
                                let mut oldest = 0usize;
                                for i in 1..8 { if IMAGE_CACHE_AGE[i] < IMAGE_CACHE_AGE[oldest] { oldest = i; } }
                                IMAGE_CACHE[oldest] = None;
                                oldest
                            }
                        }
                    };
                    unsafe {
                        IMAGE_CACHE_TICK = IMAGE_CACHE_TICK.wrapping_add(1);
                        IMAGE_CACHE_AGE[idx] = IMAGE_CACHE_TICK;
                        IMAGE_CACHE[idx] = Some((w, h, pixels));
                    }
                    serial_log(b"[IMG] decode OK\r\n");
                    (idx + 1) as i64
                }
                None => { serial_log(b"[IMG] decode fail\r\n"); 0 }
            }
        },

        // ImageDraw(handle, x, y, draw_w, draw_h) — blite l'image décodée sur le framebuffer.
        // draw_w/draw_h <= 0 → utilise la taille naturelle de l'image.
        // Les pixels transparents (alpha=0) sont sautés ; semi-transparents → alpha blending.
        "DrvAPIInterCon___ImageDraw___" => {
            if args.len() < 3 { return 0; }
            let handle = args[0] as usize;
            if handle == 0 || handle > 8 { return 0; }
            let dst_x = args[1] as i32;
            let dst_y = args[2] as i32;
            let dst_w = if args.len() >= 4 && args[3] > 0 { args[3] as u32 } else { 0 };
            let dst_h = if args.len() >= 5 && args[4] > 0 { args[4] as u32 } else { 0 };
            let fb = ctx.fb; let s = ctx.stride;
            let sw = ctx.width; let sh = ctx.height;
            if fb.is_null() { return 0; }
            let (img_w, img_h, pix_ptr) = unsafe {
                match IMAGE_CACHE[handle - 1] {
                    Some(ref e) => (e.0, e.1, e.2.as_ptr()),
                    None => { serial_log(b"[IMG] handle invalid\r\n"); return 0; }
                }
            };
            let draw_w = if dst_w > 0 { dst_w } else { img_w };
            let draw_h = if dst_h > 0 { dst_h } else { img_h };
            serial_log(b"[IMG] ImageDraw\r\n");
            if unsafe { GPU_TRANSFORM_ACTIVE } {
                // Mapping arrière (même approche que GpuDrawRoundedRectAlpha) : le blit
                // direct ci-dessous ignorait GPU_TRANSFORM — toutes les icônes « pivotées »
                // (étincelles du losange verre, contrôles fenêtre, curseur décoratif)
                // se dessinaient droites, à côté du design Figma.
                let t = unsafe { GPU_TRANSFORM };
                let (ta, tb, tc, td, ttx, tty) = (t[0], t[1], t[2], t[3], t[4], t[5]);
                let (w, h) = (draw_w as i32, draw_h as i32);
                let corners = [(dst_x, dst_y), (dst_x + w, dst_y), (dst_x, dst_y + h), (dst_x + w, dst_y + h)];
                let mut min_fx = i32::MAX; let mut max_fx = i32::MIN;
                let mut min_fy = i32::MAX; let mut max_fy = i32::MIN;
                for &(cx, cy) in corners.iter() {
                    let fx = ta * cx / 10000 + tc * cy / 10000 + ttx;
                    let fy = tb * cx / 10000 + td * cy / 10000 + tty;
                    if fx < min_fx { min_fx = fx; } if fx > max_fx { max_fx = fx; }
                    if fy < min_fy { min_fy = fy; } if fy > max_fy { max_fy = fy; }
                }
                min_fx = min_fx.max(0); max_fx = max_fx.min(sw - 1);
                min_fy = min_fy.max(0); max_fy = max_fy.min(sh - 1);
                let (ta64, tb64, tc64, td64) = (ta as i64, tb as i64, tc as i64, td as i64);
                let det = ta64 * td64 - tc64 * tb64;
                if det != 0 {
                    let opa = unsafe { GPU_OPACITY };
                    for fy in min_fy..=max_fy {
                        for fx in min_fx..=max_fx {
                            let dx = (fx - ttx) as i64;
                            let dy = (fy - tty) as i64;
                            let lx = ((td64 * dx - tc64 * dy) * 10000 / det) as i32 - dst_x;
                            let ly = ((-tb64 * dx + ta64 * dy) * 10000 / det) as i32 - dst_y;
                            if lx < 0 || lx >= w || ly < 0 || ly >= h { continue; }
                            let (r, g, bv, raw_a) = unsafe {
                                img_sample_box(pix_ptr, img_w, img_h, lx, ly, w, h)
                            };
                            let a = raw_a * opa / 255;
                            if a == 0 { continue; }
                            let di = (fy * s + fx) as usize;
                            if a == 255 {
                                unsafe { fb.add(di).write_volatile(0xFF000000 | (r << 16) | (g << 8) | bv); }
                            } else {
                                let dst = unsafe { fb.add(di).read_volatile() };
                                let db = (dst & 0xFF) as u32;
                                let dg = ((dst >> 8) & 0xFF) as u32;
                                let dr = ((dst >> 16) & 0xFF) as u32;
                                let ia = 255 - a;
                                let nr = (r * a + dr * ia) / 255;
                                let ng = (g * a + dg * ia) / 255;
                                let nb = (bv * a + db * ia) / 255;
                                unsafe { fb.add(di).write_volatile(0xFF000000 | (nr << 16) | (ng << 8) | nb); }
                            }
                        }
                    }
                }
                serial_log(b"[IMG] draw done\r\n");
                return 0;
            }
            // ── Fast-path grandes images (fond d'écran) : version pré-échantillonnée
            // en cache ARGB, blit direct — le box-sampling par pixel ne se paie
            // qu'UNE fois par (image, taille), plus jamais par frame.
            if (draw_w as i64) * (draw_h as i64) >= 65536 {
                let dw = draw_w as i32; let dh = draw_h as i32;
                let key = pix_ptr as usize;
                let mut src_ptr: *const u32 = core::ptr::null();
                unsafe {
                    for slot in SCALED_CACHE.iter() {
                        if let Some((k, w2, h2, ref v)) = slot {
                            if *k == key && *w2 == dw && *h2 == dh { src_ptr = v.as_ptr(); break; }
                        }
                    }
                    if src_ptr.is_null() {
                        let mut v: Vec<u32> = Vec::with_capacity((dw * dh) as usize);
                        for py in 0..dh {
                            for px in 0..dw {
                                let (r, g, b, a) = img_sample_box(pix_ptr, img_w, img_h, px, py, dw, dh);
                                v.push((a << 24) | (r << 16) | (g << 8) | b);
                            }
                        }
                        let slot = SCALED_NEXT % 2;
                        SCALED_NEXT = SCALED_NEXT.wrapping_add(1);
                        SCALED_CACHE[slot] = Some((key, dw, dh, v));
                        if let Some((_, _, _, ref v)) = SCALED_CACHE[slot] { src_ptr = v.as_ptr(); }
                    }
                }
                if !src_ptr.is_null() {
                    let opa = unsafe { GPU_OPACITY };
                    for py in 0..dh {
                        let fy = dst_y + py;
                        if fy < 0 || fy >= sh { continue; }
                        for px in 0..dw {
                            let fx = dst_x + px;
                            if fx < 0 || fx >= sw { continue; }
                            let cpx = unsafe { *src_ptr.add((py * dw + px) as usize) };
                            let a = (cpx >> 24) * opa / 255;
                            if a == 0 { continue; }
                            let di = (fy * s + fx) as usize;
                            if a == 255 {
                                unsafe { fb.add(di).write_volatile(0xFF000000 | (cpx & 0x00FF_FFFF)); }
                            } else {
                                let r = (cpx >> 16) & 0xFF; let g = (cpx >> 8) & 0xFF; let bv = cpx & 0xFF;
                                let dst = unsafe { fb.add(di).read_volatile() };
                                let db = dst & 0xFF; let dg = (dst >> 8) & 0xFF; let dr = (dst >> 16) & 0xFF;
                                let ia = 255 - a;
                                let nr = (r * a + dr * ia) / 255;
                                let ng = (g * a + dg * ia) / 255;
                                let nb = (bv * a + db * ia) / 255;
                                unsafe { fb.add(di).write_volatile(0xFF000000 | (nr << 16) | (ng << 8) | nb); }
                            }
                        }
                    }
                    serial_log(b"[IMG] draw done (scaled cache)\r\n");
                    return 0;
                }
            }
            for py in 0..draw_h as i32 {
                let fy = dst_y + py;
                if fy < 0 || fy >= sh { continue; }
                for px in 0..draw_w as i32 {
                    let fx = dst_x + px;
                    if fx < 0 || fx >= sw { continue; }
                    let (r, g, bv, raw_a) = unsafe {
                        img_sample_box(pix_ptr, img_w, img_h, px, py, draw_w as i32, draw_h as i32)
                    };
                    let opa = unsafe { GPU_OPACITY };
                    let a = raw_a * opa / 255;
                    let di = (fy * s + fx) as usize;
                    if a == 255 {
                        unsafe { fb.add(di).write_volatile(0xFF000000 | (r << 16) | (g << 8) | bv); }
                    } else if a > 0 {
                        let dst = unsafe { fb.add(di).read_volatile() };
                        let db = (dst & 0xFF) as u32;
                        let dg = ((dst >> 8) & 0xFF) as u32;
                        let dr = ((dst >> 16) & 0xFF) as u32;
                        let ia = 255 - a;
                        let nr = (r * a + dr * ia) / 255;
                        let ng = (g * a + dg * ia) / 255;
                        let nb = (bv * a + db * ia) / 255;
                        unsafe { fb.add(di).write_volatile(0xFF000000 | (nr << 16) | (ng << 8) | nb); }
                    }
                }
            }
            serial_log(b"[IMG] draw done\r\n");
            0
        },

        // ── GpuSetOpacity / GpuSetBlendMode ──────────────────────────────────
        "DrvAPIInterCon___GpuSetOpacity___" => {
            if args.len() >= 1 { unsafe { GPU_OPACITY = (args[0] as u32).min(255); } } 0
        },
        "DrvAPIInterCon___GpuSetBlendMode___" => {
            if args.len() >= 1 { unsafe { GPU_BLEND_MODE = args[0] as u32; } } 0
        },
        "DrvAPIInterCon___GpuResetOpacity___" => {
            unsafe { GPU_OPACITY = 255; } 0
        },
        "DrvAPIInterCon___GpuResetBlendMode___" => {
            unsafe { GPU_BLEND_MODE = 0; } 0
        },

        // ── GpuSetTransform2D(cos, sin, neg_sin, cos, pivot_x, pivot_y) ─────────
        // args 4/5 = pivot autour duquel la rotation est appliquée (pas une translation brute).
        // Conversion pivot → translation affine :
        //   tx = (px*(10000-cos) + py*sin) / 10000
        //   ty = (py*(10000-cos) - px*sin) / 10000
        "DrvAPIInterCon___GpuSetTransform2D___" => {
            serial_log(b"[MENU] GpuSetTransform2D\r\n");
            if args.len() >= 6 {
                let cos_ = args[0] as i32;
                let sin_ = args[1] as i32;
                let px   = args[4] as i32;
                let py   = args[5] as i32;
                let tx   = (px * (10000 - cos_) + py * sin_) / 10000;
                let ty   = (py * (10000 - cos_) - px * sin_) / 10000;
                unsafe {
                    GPU_TRANSFORM = [cos_, sin_, -sin_, cos_, tx, ty];
                    GPU_TRANSFORM_ACTIVE = true;
                }
            }
            0
        },
        "DrvAPIInterCon___GpuResetTransform___" => {
            unsafe {
                GPU_TRANSFORM = [10000, 0, 0, 10000, 0, 0];
                GPU_TRANSFORM_ACTIVE = false;
            }
            0
        },

        // ── GpuDrawRotatedImage(img, cx, cy, dw, dh, angleDeg) ───────────────
        "DrvAPIInterCon___GpuDrawRotatedImage___" => {
            if args.len() < 6 { return 0; }
            let handle = args[0] as usize;
            if handle == 0 || handle > 8 { return 0; }
            let cx = args[1] as i32; let cy = args[2] as i32;
            let dw = args[3] as i32; let dh = args[4] as i32;
            let ang = args[5] as i32;
            let fb = ctx.fb; let st = ctx.stride; let sw = ctx.width; let sh = ctx.height;
            if fb.is_null() || dw <= 0 || dh <= 0 { return 0; }
            let (iw, ih, pp) = unsafe {
                match IMAGE_CACHE[handle - 1] {
                    Some(ref e) => (e.0 as i32, e.1 as i32, e.2.as_ptr()),
                    None => return 0,
                }
            };
            let csa = cos_i(ang); let sna = sin_i(ang);
            let bw = (dw * csa.abs() + dh * sna.abs()) / 1000 + 2;
            let bh = (dw * sna.abs() + dh * csa.abs()) / 1000 + 2;
            for dy in 0..bh {
                let py = cy - bh/2 + dy; if py < 0 || py >= sh { continue; }
                let rly = py - cy;
                for dx in 0..bw {
                    let px = cx - bw/2 + dx; if px < 0 || px >= sw { continue; }
                    let rlx = px - cx;
                    let sx = ( rlx * csa + rly * sna) / 1000 + dw/2;
                    let sy = (-rlx * sna + rly * csa) / 1000 + dh/2;
                    if sx < 0 || sx >= dw || sy < 0 || sy >= dh { continue; }
                    let six = (sx as u64 * iw as u64 / dw as u64) as usize;
                    let siy = (sy as u64 * ih as u64 / dh as u64) as usize;
                    let so = (siy * iw as usize + six) * 4;
                    let r = unsafe { *pp.add(so) } as u32; let g = unsafe { *pp.add(so+1) } as u32;
                    let bv = unsafe { *pp.add(so+2) } as u32; let a = unsafe { *pp.add(so+3) } as u32;
                    unsafe { gpu_write_pixel(fb, (py * st + px) as usize, r, g, bv, a); }
                }
            }
            0
        },

        // ── Blur ─────────────────────────────────────────────────────────────
        "DrvAPIInterCon___GpuGaussianBlur___" => {
            if args.len() >= 5 {
                let fb = ctx.fb; let s = ctx.stride;
                if !fb.is_null() { box_blur_region(fb,s,args[0] as i32,args[1] as i32,args[2] as i32,args[3] as i32,(args[4] as i32).clamp(1,16)); }
            } 0
        },
        "DrvAPIInterCon___GpuBackgroundBlur___" => {
            serial_log(alloc::format!(
                "[MENU] GpuBackgroundBlur args={:?} fb_null={}\r\n", args, ctx.fb.is_null()
            ).as_bytes());
            if args.len() >= 6 {
                let fb = ctx.fb; let s = ctx.stride;
                let blur_r = (args[5] as i32).clamp(1, 16);
                if !fb.is_null() {
                    if unsafe { GPU_TRANSFORM_ACTIVE } {
                        // Transformation active (rotation) : flou découpé selon le rectangle arrondi
                        // tourné, cf. box_blur_region_masked_rotated — args[4] sert ici de rayon de
                        // coin pour le masque (ignoré côté rectangle plat ci-dessous).
                        let t = unsafe { GPU_TRANSFORM };
                        box_blur_region_masked_rotated(
                            fb, s, ctx.width, ctx.height,
                            args[0] as i32, args[1] as i32, args[2] as i32, args[3] as i32, args[4] as i32,
                            t, blur_r,
                        );
                    } else {
                        box_blur_region(fb, s, args[0] as i32, args[1] as i32, args[2] as i32, args[3] as i32, blur_r);
                    }
                }
            } 0
        },
        "DrvAPIInterCon___GpuProgressiveBlur___" => {
            if args.len() >= 7 {
                let fb = ctx.fb; let s = ctx.stride;
                let bx=args[0] as i32; let by_=args[1] as i32; let bw=args[2] as i32; let bh_=args[3] as i32;
                let r0=(args[4] as i32).clamp(0,16); let r1=(args[5] as i32).clamp(0,16); let ang=args[6] as i32;
                if !fb.is_null() && bw > 0 && bh_ > 0 {
                    let ac=cos_i(ang).abs(); let as_=sin_i(ang).abs();
                    for i in 0i32..4 {
                        let t = i*250;
                        let cr = ((r0*(1000-t)+r1*t)/1000).max(1);
                        let sx = bx + (bw*t*ac)/(4*1000); let sy = by_ + (bh_*t*as_)/(4*1000);
                        box_blur_region(fb,s,sx,sy,(bw/4).max(1),(bh_/4).max(1),cr);
                    }
                }
            } 0
        },

        // ── GpuDrawLinearGradient(x,y,w,h,r,angle,c1,p1,c2,p2,[stopCount]) ──
        "DrvAPIInterCon___GpuDrawLinearGradient___" => {
            if args.len() < 10 { return 0; }
            let gx=args[0] as i32; let gy=args[1] as i32; let gw=args[2] as i32; let gh=args[3] as i32;
            let gcr=args[4] as i32; let ang=args[5] as i32;
            let c1=args[6] as u32; let p1=args[7] as i32; let c2=args[8] as u32; let p2=args[9] as i32;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null() || gw<=0 || gh<=0 { return 0; }
            let cs=cos_i(ang); let sn=sin_i(ang);
            let (a1i,r1i,g1i,b1i)=((c1>>24)&0xFF,(c1>>16)&0xFF,(c1>>8)&0xFF,c1&0xFF);
            let (a2i,r2i,g2i,b2i)=((c2>>24)&0xFF,(c2>>16)&0xFF,(c2>>8)&0xFF,c2&0xFF);
            let (a1,r1,g1,b1)=(a1i as i32,r1i as i32,g1i as i32,b1i as i32);
            let (a2,r2,g2,b2)=(a2i as i32,r2i as i32,g2i as i32,b2i as i32);
            let hw=gw/2; let hh=gh/2;
            let mr=((gw*cs.abs()+gh*sn.abs())/1000).max(1);
            let range=(p2-p1).max(1);
            for py in 0..gh {
                let fy=gy+py; if fy<0||fy>=sh { continue; }
                let rly=py-hh;
                for px in 0..gw {
                    let fx=gx+px; if fx<0||fx>=sw { continue; }
                    if gcr>0 {
                        let cdx=if px<gcr{gcr-px}else if px>=gw-gcr{px-(gw-gcr-1)}else{0};
                        let cdy=if py<gcr{gcr-py}else if py>=gh-gcr{py-(gh-gcr-1)}else{0};
                        if cdx>0&&cdy>0&&cdx*cdx+cdy*cdy>gcr*gcr { continue; }
                    }
                    let rlx=px-hw;
                    let proj=(rlx*cs+rly*sn)/1000+mr/2;
                    let t=((proj*1000/mr)-p1).max(0).min(range)*1000/range;
                    let it=1000-t;
                    let nr=((r1*it+r2*t)/1000) as u32; let ng=((g1*it+g2*t)/1000) as u32;
                    let nb=((b1*it+b2*t)/1000) as u32; let na=((a1*it+a2*t)/1000) as u32;
                    unsafe { gpu_write_pixel(fb,(fy*s+fx) as usize,nr,ng,nb,na); }
                }
            }
            0
        },

        // ── GpuDrawCorrugated(x,y,w,h,r,color,folds,angleDeg) ────────────────
        // Surface PLISSÉE réaliste (carton ondulé, signature ShUI) : `folds` plis
        // parallèles calculés PAR PIXEL via une onde sinusoïdale (sin_i, même trig
        // entière ×1000 que GpuDrawLinearGradient) — pic (sin≥0) = zone la plus
        // claire du zigzag, creux (sin<0) = couleur normale légèrement assombrie
        // (ligne de pli). UNE SEULE teinte (`color`) : seule sa luminosité varie
        // selon la position dans le pli — pas un dégradé plat ni des bandes dures.
        "DrvAPIInterCon___GpuDrawCorrugated___" => {
            if args.len() < 8 { return 0; }
            let x=args[0] as i32; let y=args[1] as i32; let w=args[2] as i32; let h=args[3] as i32;
            let gcr=(args[4] as i32).max(0);
            let c=args[5] as u32;
            let folds=(args[6] as i32).max(1);
            let ang=args[7] as i32;
            // Alpha BRUT — pas de pré-multiplication par GPU_OPACITY : gpu_write_pixel() (appelé
            // plus bas) l'applique déjà (évite le bug de double-application découvert sur le dock).
            let alpha=(c>>24)&0xFF;
            let cr_=(c>>16)&0xFF; let cg_=(c>>8)&0xFF; let cb_=c&0xFF;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||alpha==0||w<=0||h<=0 { return 0; }
            let cs=cos_i(ang); let sn=sin_i(ang);
            let hw=w/2; let hh=h/2;
            let mr=((w*cs.abs()+h*sn.abs())/1000).max(1);
            let (ccx,ccy)=unsafe{gpu_transform_point(x+hw,y+hh)};
            let active=unsafe{GPU_TRANSFORM_ACTIVE};
            let t=unsafe{GPU_TRANSFORM};
            let det:i64=(t[0] as i64)*(t[3] as i64)-(t[1] as i64)*(t[2] as i64);
            // Contour du losange NON gauchi (pas de bulge) : le bord reste net et géométrique
            // (pointes nettes du losange) — un bulge sur le bord arrondissait la silhouette en
            // blob/cercle (rejeté : "reste losange comme avant, pas un rond"). L'effet 3D vient
            // uniquement du contraste clair/sombre du remplissage ci-dessous.
            let (bx0,bx1,by0,by1) = if active {
                let corners=[(x,y),(x+w,y),(x,y+h),(x+w,y+h)];
                let mut bx0=i32::MAX; let mut bx1=i32::MIN; let mut by0=i32::MAX; let mut by1=i32::MIN;
                for &(cxp,cyp) in corners.iter() {
                    let (fx,fy)=unsafe{gpu_transform_point(cxp,cyp)};
                    if fx<bx0{bx0=fx} if fx>bx1{bx1=fx}
                    if fy<by0{by0=fy} if fy>by1{by1=fy}
                }
                (bx0.max(0),bx1.min(sw-1),by0.max(0),by1.min(sh-1))
            } else {
                (x.max(0),(x+w-1).min(sw-1),y.max(0),(y+h-1).min(sh-1))
            };
            if bx1<bx0||by1<by0||det==0 { return 0; }
            for fy in by0..=by1 {
                for fx in bx0..=bx1 {
                    // MAPPAGE INVERSE (écran → local) : itérer la grille locale et projeter vers
                    // l'écran (mappage direct) laisse des trous en damier sous rotation non
                    // alignée sur la grille (vérifié : le fond d'écran, sans cet appel, est net —
                    // pas un artefact de capture). On itère ici la boîte englobante ÉCRAN et on
                    // retrouve le point local par transformation inverse : tout pixel écran est
                    // visité exactement une fois.
                    let (px,py) = if active {
                        let xprime=(fx-t[4]) as i64; let yprime=(fy-t[5]) as i64;
                        let lx=((t[3] as i64*xprime - t[2] as i64*yprime)*10000/det) as i32;
                        let ly=((-(t[1] as i64)*xprime + t[0] as i64*yprime)*10000/det) as i32;
                        (lx-x, ly-y)
                    } else {
                        (fx-x, fy-y)
                    };
                    if px<0||px>=w||py<0||py>=h { continue; }
                    if gcr>0 {
                        let cdx=if px<gcr{gcr-px}else if px>=w-gcr{px-(w-gcr-1)}else{0};
                        let cdy=if py<gcr{gcr-py}else if py>=h-gcr{py-(h-gcr-1)}else{0};
                        if cdx>0&&cdy>0&&cdx*cdx+cdy*cdy>gcr*gcr { continue; }
                    }
                    // Onde calculée en ESPACE ÉCRAN — la phase est échantillonnée directement sur
                    // (fx,fy), même technique de projection que GpuDrawLinearGradient.
                    let rlx=fx-ccx; let rly=fy-ccy;
                    let proj=(rlx*cs+rly*sn)/1000 + mr/2;
                    let phase_deg=(proj*360*folds)/mr;
                    let sv=sin_i(phase_deg); // -1000..1000 (sin_i normalise déjà les négatifs)
                    // Zébrure blanc/noir marquée sur la teinte unique (façon Floava, gardant la
                    // couleur du maraset) : courbes en PUISSANCE (cube/carré de sv, dérivée nulle
                    // en sv=0 des deux côtés — raccord lisse, sans coude visible), catch-light qui
                    // monte presque au blanc au sommet du pli, ombre qui descend presque au noir
                    // au creux.
                    let (mut nr,mut ng,mut nb) = if sv >= 0 {
                        let tt=((sv as i64).pow(3) * 150 / 1_000_000_000) as i32; // 0..150, cubique, vers le blanc
                        (((cr_ as i32)+tt).min(255) as u32, ((cg_ as i32)+tt).min(255) as u32, ((cb_ as i32)+tt).min(255) as u32)
                    } else {
                        let tt=(((-sv) as i64).pow(2) * 180 / 1_000_000) as i32; // 0..180, quadratique, vers le noir
                        (((cr_ as i32)-tt).max(0) as u32, ((cg_ as i32)-tt).max(0) as u32, ((cb_ as i32)-tt).max(0) as u32)
                    };
                    // Grain microscopique gris (hash déterministe par pixel écran, pas d'état à
                    // faire circuler) — GpuDrawNoisePatch n'est pas conscient de la rotation et
                    // déborderait du losange pivoté, donc intégré directement ici.
                    let mut gs=(fx as u32).wrapping_mul(374761393)^(fy as u32).wrapping_mul(668265263);
                    gs^=gs>>13; gs=gs.wrapping_mul(1274126177); gs^=gs>>16;
                    let gj=((gs&0xFF) as i32 - 128)*10/128; // -10..10
                    nr=((nr as i32)+gj).clamp(0,255) as u32;
                    ng=((ng as i32)+gj).clamp(0,255) as u32;
                    nb=((nb as i32)+gj).clamp(0,255) as u32;
                    let di=(fy*s+fx) as usize;
                    unsafe { gpu_write_pixel(fb, di, nr, ng, nb, alpha); }
                }
            }
            0
        },

        // ── GpuDrawRadialGradient(x,y,w,h,radius,c1,p1,c2,p2,num_stops) ──────
        "DrvAPIInterCon___GpuDrawRadialGradient___" => {
            if args.len() < 10 { return 0; }
            let gx=args[0] as i32; let gy=args[1] as i32; let gw=args[2] as i32; let gh=args[3] as i32;
            let mr=(args[4] as i32).max(1);
            let c1=args[5] as u32; let p1=args[6] as i32;
            let c2=args[7] as u32; let p2=args[8] as i32;
            let gcx=gx+gw/2; let gcy=gy+gh/2;
            let range=(p2-p1).max(1);
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||gw<=0||gh<=0 { return 0; }
            let (a1,r1,g1,b1)=((c1>>24)&0xFF,(c1>>16)&0xFF,(c1>>8)&0xFF,c1&0xFF);
            let (a2,r2,g2,b2)=((c2>>24)&0xFF,(c2>>16)&0xFF,(c2>>8)&0xFF,c2&0xFF);
            let (a1,r1,g1,b1)=(a1 as i32,r1 as i32,g1 as i32,b1 as i32);
            let (a2,r2,g2,b2)=(a2 as i32,r2 as i32,g2 as i32,b2 as i32);
            for py in 0..gh {
                let fy=gy+py; if fy<0||fy>=sh { continue; }
                for px in 0..gw {
                    let fx=gx+px; if fx<0||fx>=sw { continue; }
                    let dx=(fx-gcx) as i64; let dy=(fy-gcy) as i64;
                    let d=isqrt((dx*dx+dy*dy) as u32) as i32;
                    let t=((d*1000/mr)-p1).max(0).min(range)*1000/range;
                    let it=1000-t;
                    let nr=((r1*it+r2*t)/1000) as u32; let ng=((g1*it+g2*t)/1000) as u32;
                    let nb=((b1*it+b2*t)/1000) as u32; let na=((a1*it+a2*t)/1000) as u32;
                    unsafe { gpu_write_pixel(fb,(fy*s+fx) as usize,nr,ng,nb,na); }
                }
            }
            0
        },

        // GpuFlushRenderContext — retourne -1 en UEFI pour quitter la boucle
        // de rendu de LAPrevent après 1 frame (Render loop exit condition).
        // En OS runtime, ce serait 0 (flush réel du buffer).
        "DrvAPIInterCon___GpuFlushRenderContext___" => -1,

        // ── GpuDrawDropShadow(x,y,w,h,cr,offX,offY,blur,color) ──────────────
        "DrvAPIInterCon___GpuDrawDropShadow___" => {
            if args.len() < 9 { return 0; }
            let x=args[0] as i32; let y=args[1] as i32; let w=args[2] as i32; let h=args[3] as i32;
            let cr=args[4] as i32; let ox=args[5] as i32; let oy=args[6] as i32;
            let br=(args[7] as i32).clamp(0,16); let c=args[8] as u32;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null() || w<=0 || h<=0 { return 0; }
            // Ombre portée EXTÉRIEURE uniquement (SDF du rounded rect décalé, falloff
            // linéaire). L'ancien code remplissait tout le rect puis floutait : quand
            // l'élément au-dessus n'est pas opaque (ombre de fenêtre/barre frosted),
            // ça voilait l'écran entier — une drop shadow ne se voit qu'au bord.
            let sx=x+ox; let sy_=y+oy;
            let opa=unsafe{GPU_OPACITY};
            let base_alpha=((c>>24)&0xFF)*opa/255;
            let sr_=(c>>16)&0xFF; let sg_=(c>>8)&0xFF; let sb_=c&0xFF;
            if base_alpha==0 { return 0; }
            // Spread 2×blur et falloff QUADRATIQUE : le falloff linéaire sur 3×blur
            // laissait une bande sombre bien visible AU-DESSUS des tuiles (entre la
            // ligne accent et la tuile) — une vraie ombre gaussienne décalée vers le
            // bas est quasi invisible à 4px au-dessus du bord.
            let spread=(br*2).max(2);
            let hx=w/2; let hy=h/2;
            let cr=cr.max(0);
            for py in (sy_-spread)..(sy_+h+spread) {
                if py<0||py>=sh { continue; }
                for px in (sx-spread)..(sx+w+spread) {
                    if px<0||px>=sw { continue; }
                    // SDF du rounded rect : dist > 0 = extérieur de la forme
                    let qx=(px-sx-hx).abs()-hx+cr;
                    let qy=(py-sy_-hy).abs()-hy+cr;
                    let ext=isqrt((qx.max(0)*qx.max(0)+qy.max(0)*qy.max(0)) as u32) as i32;
                    let dist=ext+qx.max(qy).min(0)-cr;
                    if dist<=0 || dist>=spread { continue; }
                    let f=(spread-dist) as u32;
                    let alpha=base_alpha*f*f/(spread*spread) as u32;
                    if alpha==0 { continue; }
                    let ia=255-alpha;
                    let di=(py*s+px) as usize;
                    let dst=unsafe{fb.add(di).read_volatile()};
                    let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                    let nr=(sr_*alpha+dr*ia)/255; let ng=(sg_*alpha+dg*ia)/255; let nb=(sb_*alpha+db*ia)/255;
                    unsafe{fb.add(di).write_volatile(0xFF000000|(nr<<16)|(ng<<8)|nb);}
                }
            }
            0
        },

        // ── GpuDrawGlow(x,y,w,h,r,glowColor,glowRadius,intensity) ────────────
        // Lueur extérieure autour d'un rounded rect — additive src-over avec falloff linéaire.
        "DrvAPIInterCon___GpuDrawGlow___" => {
            if args.len() < 8 { return 0; }
            let x  = args[0] as i32; let y  = args[1] as i32;
            let w  = args[2] as i32; let h  = args[3] as i32;
            let r  = (args[4] as i32).max(0);
            let gc = args[5] as u32;
            let gr = (args[6] as i32).max(1);
            let intensity = (args[7] as u32).min(255);
            let fb = ctx.fb; let s = ctx.stride; let sw = ctx.width; let sh = ctx.height;
            if fb.is_null() || intensity == 0 || w <= 0 || h <= 0 { return 0; }
            let cr_ = (gc >> 16) & 0xFF;
            let cg_ = (gc >>  8) & 0xFF;
            let cb_ =  gc        & 0xFF;
            let hx = w / 2; let hy = h / 2;
            for py in (y - gr)..(y + h + gr) {
                if py < 0 || py >= sh { continue; }
                for px in (x - gr)..(x + w + gr) {
                    if px < 0 || px >= sw { continue; }
                    // SDF du rounded rect : dist > 0 = extérieur
                    let qx = (px - x - hx).abs() - hx + r;
                    let qy = (py - y - hy).abs() - hy + r;
                    let ext = isqrt((qx.max(0) * qx.max(0) + qy.max(0) * qy.max(0)) as u32) as i32;
                    let dist = ext + qx.max(qy).min(0) - r;
                    if dist <= 0 || dist > gr { continue; }
                    // Falloff linéaire : plein sur l'arête, nul à glowRadius
                    let a = (intensity * (gr - dist) as u32 / gr as u32).min(255);
                    if a == 0 { continue; }
                    let di = (py * s + px) as usize;
                    unsafe {
                        let dst = fb.add(di).read_volatile();
                        let db = (dst & 0xFF) as u32;
                        let dg = ((dst >> 8) & 0xFF) as u32;
                        let dr = ((dst >> 16) & 0xFF) as u32;
                        let ia = 255 - a;
                        let nr = (cr_ * a / 255 + dr * ia / 255).min(255);
                        let ng = (cg_ * a / 255 + dg * ia / 255).min(255);
                        let nb = (cb_ * a / 255 + db * ia / 255).min(255);
                        fb.add(di).write_volatile(0xFF000000 | (nr << 16) | (ng << 8) | nb);
                    }
                }
            }
            0
        },

        // ── Clip push/pop ─────────────────────────────────────────────────────
        "DrvAPIInterCon___GpuPushClip___" => {
            if args.len() >= 4 { unsafe {
                if CLIP_DEPTH < 8 {
                    CLIP_STACK[CLIP_DEPTH] = (
                        args[0] as i32, args[1] as i32, args[2] as i32, args[3] as i32,
                        if args.len() >= 5 { args[4] as i32 } else { 0 },
                    );
                    CLIP_DEPTH += 1;
                }
            }} 0
        },
        "DrvAPIInterCon___GpuPopClip___" => {
            unsafe { if CLIP_DEPTH > 0 { CLIP_DEPTH -= 1; } } 0
        },

        // ── GpuDrawRoundedRectFull(x,y,w,h,rTL,rTR,rBL,rBR,color) ───────────
        "DrvAPIInterCon___GpuDrawRoundedRectFull___" => {
            if args.len() < 9 { return 0; }
            let x=args[0] as i32; let y=args[1] as i32; let w=args[2] as i32; let h=args[3] as i32;
            let rtl=args[4] as i32; let rtr=args[5] as i32; let rbl=args[6] as i32; let rbr=args[7] as i32;
            let c=args[8] as u32;
            let opa=unsafe{GPU_OPACITY};
            let alpha=((c>>24)&0xFF)*opa/255;
            let sr_=(c>>16)&0xFF; let sg_=(c>>8)&0xFF; let sb_=c&0xFF;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||alpha==0||w<=0||h<=0 { return 0; }
            let ia=255-alpha;
            for py in 0..h {
                for px in 0..w {
                    let r=if py<h/2{if px<w/2{rtl}else{rtr}}else{if px<w/2{rbl}else{rbr}};
                    if r>0 {
                        let cdx=if px<r{r-px}else if px>=w-r{px-(w-r-1)}else{0};
                        let cdy=if py<r{r-py}else if py>=h-r{py-(h-r-1)}else{0};
                        if cdx>0&&cdy>0&&cdx*cdx+cdy*cdy>r*r { continue; }
                    }
                    let (fx,fy)=unsafe{gpu_transform_point(x+px,y+py)};
                    if fx<0||fx>=sw||fy<0||fy>=sh { continue; }
                    let di=(fy*s+fx) as usize;
                    // Opaque : écriture directe — la lecture-mélange coûtait ~2M
                    // d'accès mémoire par frame sur le fond plein écran du bureau.
                    if alpha==255 {
                        unsafe{fb.add(di).write_volatile(0xFF000000|(sr_<<16)|(sg_<<8)|sb_);}
                        continue;
                    }
                    let dst=unsafe{fb.add(di).read_volatile()};
                    let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                    let nr=(sr_*alpha+dr*ia)/255; let ng=(sg_*alpha+dg*ia)/255; let nb=(sb_*alpha+db*ia)/255;
                    unsafe{fb.add(di).write_volatile(0xFF000000|(nr<<16)|(ng<<8)|nb);}
                }
            }
            0
        },

        // ── GpuDrawEllipse(x,y,w,h,color) ────────────────────────────────────
        "DrvAPIInterCon___GpuDrawEllipse___" => {
            if args.len() < 5 { return 0; }
            let x=args[0] as i32; let y=args[1] as i32; let w=args[2] as i32; let h=args[3] as i32;
            let c=args[4] as u32;
            let opa=unsafe{GPU_OPACITY};
            let alpha=((c>>24)&0xFF)*opa/255;
            let sr_=(c>>16)&0xFF; let sg_=(c>>8)&0xFF; let sb_=c&0xFF;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||alpha==0||w<=0||h<=0 { return 0; }
            let ia=255-alpha; let w64=w as i64; let h64=h as i64;
            let wh2=w64*w64*h64*h64;
            for py in 0..h {
                let dy=2*py as i64-h64+1;
                for px in 0..w {
                    let dx=2*px as i64-w64+1;
                    if dx*dx*h64*h64+dy*dy*w64*w64 > wh2 { continue; }
                    let (fx,fy)=unsafe{gpu_transform_point(x+px,y+py)};
                    if fx<0||fx>=sw||fy<0||fy>=sh { continue; }
                    let di=(fy*s+fx) as usize;
                    let dst=unsafe{fb.add(di).read_volatile()};
                    let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                    let nr=(sr_*alpha+dr*ia)/255; let ng=(sg_*alpha+dg*ia)/255; let nb=(sb_*alpha+db*ia)/255;
                    unsafe{fb.add(di).write_volatile(0xFF000000|(nr<<16)|(ng<<8)|nb);}
                }
            }
            0
        },

        // ── Noise ─────────────────────────────────────────────────────────────
        "DrvAPIInterCon___GpuDrawNoisePatch___" => {
            if args.len() < 7 { return 0; }
            let nx=args[0] as i32; let ny=args[1] as i32; let nw=args[2] as i32; let nh=args[3] as i32;
            let nr_=args[4] as i32; let na=(args[5] as u32).min(255); let mut seed=args[6] as u32;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||nw<=0||nh<=0 { return 0; }
            let r2=nr_*nr_; let ia=255-na;
            for py in 0..nh {
                let fy=ny+py; if fy<0||fy>=sh { continue; }
                for px in 0..nw {
                    let fx=nx+px; if fx<0||fx>=sw { continue; }
                    if nr_>0 {
                        let cdx=if px<nr_{nr_-px}else if px>=nw-nr_{px-(nw-nr_-1)}else{0};
                        let cdy=if py<nr_{nr_-py}else if py>=nh-nr_{py-(nh-nr_-1)}else{0};
                        if cdx>0&&cdy>0&&cdx*cdx+cdy*cdy>r2 { continue; }
                    }
                    seed^=seed<<13; seed^=seed>>17; seed^=seed<<5;
                    let gray=(seed&0xFF) as u32;
                    let di=(fy*s+fx) as usize;
                    let dst=unsafe{fb.add(di).read_volatile()};
                    let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                    let nnr=(gray*na+dr*ia)/255; let nng=(gray*na+dg*ia)/255; let nnb=(gray*na+db*ia)/255;
                    unsafe{fb.add(di).write_volatile(0xFF000000|(nnr<<16)|(nng<<8)|nnb);}
                }
            }
            0
        },
        "DrvAPIInterCon___GpuDrawColoredNoise___" => {
            if args.len() < 8 { return 0; }
            let nx=args[0] as i32; let ny=args[1] as i32; let nw=args[2] as i32; let nh=args[3] as i32;
            let nr_=args[4] as i32; let na=(args[5] as u32).min(255); let mut seed=args[6] as u32; let hue=args[7] as u32;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||nw<=0||nh<=0 { return 0; }
            let r2=nr_*nr_; let ia=255-na;
            let (hr,hg,hb)=((hue>>16)&0xFF,(hue>>8)&0xFF,hue&0xFF);
            for py in 0..nh {
                let fy=ny+py; if fy<0||fy>=sh { continue; }
                for px in 0..nw {
                    let fx=nx+px; if fx<0||fx>=sw { continue; }
                    if nr_>0 {
                        let cdx=if px<nr_{nr_-px}else if px>=nw-nr_{px-(nw-nr_-1)}else{0};
                        let cdy=if py<nr_{nr_-py}else if py>=nh-nr_{py-(nh-nr_-1)}else{0};
                        if cdx>0&&cdy>0&&cdx*cdx+cdy*cdy>r2 { continue; }
                    }
                    seed^=seed<<13; seed^=seed>>17; seed^=seed<<5;
                    let n=(seed&0xFF) as u32;
                    let cr_=hr*n>>8; let cg_=hg*n>>8; let cb_=hb*n>>8;
                    let di=(fy*s+fx) as usize;
                    let dst=unsafe{fb.add(di).read_volatile()};
                    let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                    let nnr=(cr_*na+dr*ia)/255; let nng=(cg_*na+dg*ia)/255; let nnb=(cb_*na+db*ia)/255;
                    unsafe{fb.add(di).write_volatile(0xFF000000|(nnr<<16)|(nng<<8)|nnb);}
                }
            }
            0
        },

        // ── GpuDrawGrainNoise(x,y,w,h,radius,color,grain_size) ───────────────
        // hash = (px*1664525 ^ py*1013904223) & 0xFF  →  alpha = color_alpha * hash / 255
        "DrvAPIInterCon___GpuDrawGrainNoise___" => {
            if args.len() < 7 { return 0; }
            let x=args[0] as i32; let y=args[1] as i32; let w=args[2] as i32; let h=args[3] as i32;
            let cr=args[4] as i32; let c=args[5] as u32; let gs=(args[6] as i32).max(1);
            let opa=unsafe{GPU_OPACITY};
            let alpha=((c>>24)&0xFF)*opa/255; let sr_=(c>>16)&0xFF; let sg_=(c>>8)&0xFF; let sb_=c&0xFF;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||alpha==0||w<=0||h<=0 { return 0; }
            let r2=cr*cr;
            for py in 0..h {
                let fy=y+py; if fy<0||fy>=sh { continue; }
                for px in 0..w {
                    let fx=x+px; if fx<0||fx>=sw { continue; }
                    if cr>0 {
                        let cdx=if px<cr{cr-px}else if px>=w-cr{px-(w-cr-1)}else{0};
                        let cdy=if py<cr{cr-py}else if py>=h-cr{py-(h-cr-1)}else{0};
                        if cdx>0&&cdy>0&&cdx*cdx+cdy*cdy>r2 { continue; }
                    }
                    let gpx=(px/gs) as u32; let gpy=(py/gs) as u32;
                    let hash=(gpx.wrapping_mul(1664525)^gpy.wrapping_mul(1013904223))&0xFF;
                    let pa=alpha*hash/255; let ia=255-pa;
                    if pa==0 { continue; }
                    let di=(fy*s+fx) as usize;
                    let dst=unsafe{fb.add(di).read_volatile()};
                    let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                    let nr=(sr_*pa+dr*ia)/255; let ng=(sg_*pa+dg*ia)/255; let nb=(sb_*pa+db*ia)/255;
                    unsafe{fb.add(di).write_volatile(0xFF000000|(nr<<16)|(ng<<8)|nb);}
                }
            }
            0
        },

        // ── GpuDrawStroke(x,y,w,h,r,weight,align,color) ──────────────────────
        "DrvAPIInterCon___GpuDrawStroke___" => {
            if args.len() < 8 { return 0; }
            let rx=args[0] as i32; let ry=args[1] as i32; let rw=args[2] as i32; let rh=args[3] as i32;
            let wt=args[5] as i32; let aln=args[6] as i32; let c=args[7] as u32;
            let (bx,by_,bw,bh)=match aln{1=>(rx,ry,rw,rh),2=>(rx-wt,ry-wt,rw+2*wt,rh+2*wt),_=>(rx-wt/2,ry-wt/2,rw+wt,rh+wt)};
            let fa=(c>>24)&0xFF; let fr=(c>>16)&0xFF; let fgc=(c>>8)&0xFF; let fbc=c&0xFF;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||fa==0 { return 0; }
            let ia=255-fa;
            let mut draw_seg = |x0:i32,y0:i32,w0:i32,h0:i32| {
                for py in 0..h0 { let fy=y0+py; if fy<0||fy>=sh{continue;}
                    for px in 0..w0 { let fx=x0+px; if fx<0||fx>=sw{continue;}
                        let di=(fy*s+fx) as usize;
                        let dst=unsafe{fb.add(di).read_volatile()};
                        let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                        let nr=(fr*fa+dr*ia)/255; let ng=(fgc*fa+dg*ia)/255; let nb=(fbc*fa+db*ia)/255;
                        unsafe{fb.add(di).write_volatile(0xFF000000|(nr<<16)|(ng<<8)|nb);}
                    }
                }
            };
            draw_seg(bx,by_,bw,wt); draw_seg(bx,by_+bh-wt,bw,wt);
            draw_seg(bx,by_+wt,wt,bh-2*wt); draw_seg(bx+bw-wt,by_+wt,wt,bh-2*wt);
            0
        },
        "DrvAPIInterCon___GpuDrawDashedStroke___" => {
            if args.len() < 9 { return 0; }
            let sx=args[0] as i32; let sy_=args[1] as i32; let sw2=args[2] as i32; let sh2=args[3] as i32;
            let wt=args[5] as i32; let dash=args[6] as i32; let gap=args[7] as i32; let c=args[8] as u32;
            let fa=(c>>24)&0xFF; let fr=(c>>16)&0xFF; let fgc=(c>>8)&0xFF; let fbc=c&0xFF;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||fa==0 { return 0; }
            let ia=255-fa; let period=(dash+gap).max(1);
            for edge in 0..2i32 {
                let ey=if edge==0{sy_}else{sy_+sh2-wt};
                for px in 0..sw2 { if (px%period)>=dash{continue;}
                    for t in 0..wt { let fy=ey+t; if fy<0||fy>=sh{continue;}
                        let fx=sx+px; if fx<0||fx>=sw{continue;}
                        let di=(fy*s+fx) as usize;
                        let dst=unsafe{fb.add(di).read_volatile()};
                        let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                        unsafe{fb.add(di).write_volatile(0xFF000000|((fr*fa+dr*ia)/255<<16)|((fgc*fa+dg*ia)/255<<8)|(fbc*fa+db*ia)/255);}
                    }
                }
            }
            for edge in 0..2i32 {
                let ex=if edge==0{sx}else{sx+sw2-wt};
                for py in 0..sh2 { if (py%period)>=dash{continue;}
                    for t in 0..wt { let fx=ex+t; if fx<0||fx>=sw{continue;}
                        let fy=sy_+py; if fy<0||fy>=sh{continue;}
                        let di=(fy*s+fx) as usize;
                        let dst=unsafe{fb.add(di).read_volatile()};
                        let db=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr=((dst>>16)&0xFF) as u32;
                        unsafe{fb.add(di).write_volatile(0xFF000000|((fr*fa+dr*ia)/255<<16)|((fgc*fa+dg*ia)/255<<8)|(fbc*fa+db*ia)/255);}
                    }
                }
            }
            0
        },

        // ── GpuDrawInnerShadow(x,y,w,h,cr,offX,offY,blurR,color) ────────────
        "DrvAPIInterCon___GpuDrawInnerShadow___" => {
            if args.len() < 9 { return 0; }
            let x=args[0] as i32; let y=args[1] as i32; let w=args[2] as i32; let h=args[3] as i32;
            let _cr=args[4] as i32; let ox=args[5] as i32; let oy=args[6] as i32;
            let br=(args[7] as i32).max(1); let c=args[8] as u32;
            let sa=(c>>24)&0xFF; let sr=(c>>16)&0xFF; let sg=(c>>8)&0xFF; let sb=c&0xFF;
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null()||sa==0 { return 0; }
            for py in 0..h {
                let fy=y+py; if fy<0||fy>=sh { continue; }
                for px in 0..w {
                    let fx=x+px; if fx<0||fx>=sw { continue; }
                    // Distance minimale aux bords, modulée par l'offset d'ombre
                    let dl=(px-ox).max(0); let dt=(py-oy).max(0);
                    let dr_=((w-1-px)+ox).max(0); let db_=((h-1-py)+oy).max(0);
                    let dist=dl.min(dt).min(dr_).min(db_);
                    if dist>=br { continue; }
                    let t=((br-dist)*255/br).min(255) as u32;
                    let alpha=sa*t/255; if alpha==0 { continue; }
                    let ia=255-alpha;
                    let di=(fy*s+fx) as usize;
                    let dst=unsafe{fb.add(di).read_volatile()};
                    let db2=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr2=((dst>>16)&0xFF) as u32;
                    let nr=(sr*alpha+dr2*ia)/255; let ng=(sg*alpha+dg*ia)/255; let nb=(sb*alpha+db2*ia)/255;
                    unsafe{fb.add(di).write_volatile(0xFF000000|(nr<<16)|(ng<<8)|nb);}
                }
            }
            0
        },

        // ── GpuCaptureMask(x,y,w,h) → handle (1-based slot) ─────────────────
        "DrvAPIInterCon___GpuCaptureMask___" => {
            if args.len() < 4 { return 0; }
            let mx=args[0] as i32; let my=args[1] as i32; let mw=args[2] as i32; let mh=args[3] as i32;
            let fb=ctx.fb; let s=ctx.stride;
            if fb.is_null()||mw<=0||mh<=0 { return 0; }
            let mut pix: Vec<u8> = Vec::with_capacity((mw*mh*4) as usize);
            for py in 0..mh { for px in 0..mw {
                let idx=((my+py)*s+(mx+px)) as usize;
                let c=unsafe{fb.add(idx).read_volatile()};
                pix.push(((c>>16)&0xFF) as u8);
                pix.push(((c>>8)&0xFF) as u8);
                pix.push((c&0xFF) as u8);
                pix.push(255u8);
            }}
            // Stocker dans le premier slot libre ou recycler le slot 0
            let mut pix_opt = Some(pix);
            unsafe {
                for (i, slot) in MASK_CACHE.iter_mut().enumerate() {
                    if slot.is_none() {
                        *slot = Some((mx, my, mw, mh, pix_opt.take().unwrap()));
                        return (i + 1) as i64;
                    }
                }
                MASK_CACHE[0] = Some((mx, my, mw, mh, pix_opt.take().unwrap()));
            }
            1
        },

        // ── GpuApplyAlphaMask(handle) ─────────────────────────────────────────
        "DrvAPIInterCon___GpuApplyAlphaMask___" => {
            if args.len() < 1 || args[0] <= 0 { return 0; }
            let slot_idx = (args[0] as usize).wrapping_sub(1);
            if slot_idx >= 4 { return 0; }
            // Copier les métadonnées et pixels hors de l'emprunt statique
            let (mx, my, mw, mh, pix): (i32, i32, i32, i32, Vec<u8>) = unsafe {
                match &MASK_CACHE[slot_idx] {
                    Some(m) => (m.0, m.1, m.2, m.3, m.4.clone()),
                    None => return 0,
                }
            };
            let fb=ctx.fb; let s=ctx.stride; let sw=ctx.width; let sh=ctx.height;
            if fb.is_null() { return 0; }
            for py in 0..mh {
                let fy=my+py; if fy<0||fy>=sh { continue; }
                for px in 0..mw {
                    let fx=mx+px; if fx<0||fx>=sw { continue; }
                    let pi=((py*mw+px)*4) as usize;
                    if pi+2 >= pix.len() { continue; }
                    let mr=pix[pi] as u32; let mg=pix[pi+1] as u32; let mb=pix[pi+2] as u32;
                    // Luminance du pixel masque → coefficient d'opacité
                    let lum=(mr*299+mg*587+mb*114)/1000;
                    let di=(fy*s+fx) as usize;
                    let dst=unsafe{fb.add(di).read_volatile()};
                    let dr=((dst>>16)&0xFF)*lum/255;
                    let dg=((dst>>8)&0xFF)*lum/255;
                    let db=(dst&0xFF)*lum/255;
                    unsafe{fb.add(di).write_volatile(0xFF000000|(dr<<16)|(dg<<8)|db);}
                }
            }
            0
        },

        // ── GpuDrawGradientStroke(x,y,w,h,r,weight,stops_ptr,stopCount) ──────
        // Gradient linéaire de gauche (stops[0]) vers droite (stops[stopCount-1])
        // le long du périmètre de la bordure.
        "DrvAPIInterCon___GpuDrawGradientStroke___" => {
            if args.len() < 6 { return 0; }
            let x=args[0] as i32; let y=args[1] as i32; let w=args[2] as i32; let h=args[3] as i32;
            let _cr=args[4] as i32; let wt=(args[5] as i32).max(1);
            let stops_ptr=if args.len()>=7{args[6]}else{0};
            let stop_count=if args.len()>=8{args[7] as usize}else{2};
            let fb=ctx.fb; let s=ctx.stride; let sw2=ctx.width; let sh2=ctx.height;
            if fb.is_null()||w<=0||h<=0 { return 0; }
            // Lire les couleurs depuis le pointeur (i64[stopCount])
            let stops: Vec<u32> = if stops_ptr!=0 && stop_count>0 {
                let p=stops_ptr as *const i64;
                (0..stop_count.min(16)).map(|i| unsafe{*p.add(i)} as u32).collect()
            } else if args.len()>=8 {
                alloc::vec![args[6] as u32, args[7] as u32]
            } else {
                alloc::vec![0xFF888888, 0xFF444444]
            };
            let n=stops.len().max(1);
            // Interpoler couleur à la position t (0..=perim-1) dans la liste de stops
            let perim=2*(w+h);
            let lerp_stop = |t: i32| -> u32 {
                let pos=t*(n as i32-1)/perim.max(1);
                let pos=pos.max(0).min(n as i32-2) as usize;
                let frac=((t*(n as i32-1))%perim.max(1))*1000/perim.max(1);
                let c1=stops[pos]; let c2=stops[pos+1];
                let it=1000-frac as u32; let ft=frac as u32;
                let a=((c1>>24)&0xFF)*it/1000+((c2>>24)&0xFF)*ft/1000;
                let r=((c1>>16)&0xFF)*it/1000+((c2>>16)&0xFF)*ft/1000;
                let g=((c1>>8)&0xFF)*it/1000+((c2>>8)&0xFF)*ft/1000;
                let b=(c1&0xFF)*it/1000+(c2&0xFF)*ft/1000;
                (a<<24)|(r<<16)|(g<<8)|b
            };
            let draw_px = |fx:i32, fy:i32, col:u32| {
                if fx<0||fx>=sw2||fy<0||fy>=sh2 { return; }
                let alpha=(col>>24)&0xFF; if alpha==0 { return; }
                let ia=255-alpha;
                let sr=(col>>16)&0xFF; let sg=(col>>8)&0xFF; let sb=col&0xFF;
                let di=(fy*s+fx) as usize;
                let dst=unsafe{fb.add(di).read_volatile()};
                let db2=(dst&0xFF) as u32; let dg=((dst>>8)&0xFF) as u32; let dr2=((dst>>16)&0xFF) as u32;
                unsafe{fb.add(di).write_volatile(0xFF000000|((sr*alpha+dr2*ia)/255<<16)|((sg*alpha+dg*ia)/255<<8)|(sb*alpha+db2*ia)/255);}
            };
            let mut t=0i32;
            for px in 0..w   { let col=lerp_stop(t); for k in 0..wt { draw_px(x+px,y+k,col); } t+=1; }
            for py in 0..h   { let col=lerp_stop(t); for k in 0..wt { draw_px(x+w-wt+k,y+py,col); } t+=1; }
            for px in (0..w).rev() { let col=lerp_stop(t); for k in 0..wt { draw_px(x+px,y+h-wt+k,col); } t+=1; }
            for py in (0..h).rev() { let col=lerp_stop(t); for k in 0..wt { draw_px(x+k,y+py,col); } t+=1; }
            0
        },

        // ── GpuDrawFloavaBlob(x,y,w,h,r,color,phaseDeg) ──────────────────────
        // Losange « Floava » (état app fermée du dock) : squircle dont les
        // coordonnées sont GAUCHIES par deux sinusoïdes orthogonales (domain
        // warping) → silhouette ondulée organique « tortillée », ombrage DOUX
        // (produit de deux sinus — pas de rayures dures type corrugated), AA au
        // bord par SDF. `phaseDeg` anime lentement l'ondulation (tick*4).
        // Respecte GPU_TRANSFORM (mapping arrière) et GPU_OPACITY.
        "DrvAPIInterCon___GpuDrawFloavaBlob___" => {
            serial_log(alloc::format!("[MENU] GpuDrawFloavaBlob args_len={}\r\n", args.len()).as_bytes());
            if args.len() < 7 { return 0; }
            let x = args[0] as i32; let y = args[1] as i32;
            let w = (args[2] as i32).max(4); let h = (args[3] as i32).max(4);
            let r = (args[4] as i32).max(0);
            let c = args[5] as u32;
            let phase = args[6] as i32;
            let fb = ctx.fb; let s = ctx.stride;
            let sw2 = ctx.width; let sh2 = ctx.height;
            if fb.is_null() { return 0; }
            let opa = unsafe { GPU_OPACITY };
            let base_a = ((c >> 24) & 0xFF) * opa / 255;
            if base_a == 0 { return 0; }
            let (cr_, cg_, cb_) = ((c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF);
            // SILHOUETTE = carré-arrondi SANS segment plat : les côtés rectilignes
            // entre les coins « sentaient le carré » — bombé SUBTIL (w/24 ≈ 2px au
            // milieu du côté, profil quadratique, zéro aux coins), rayon PLEIN
            // conservé. phase < 0 = intérieur UNI + bruit (état déplié/ouvert),
            // phase >= 0 = légèrement replié (état fermé) — bruit dans les deux.
            let textured = phase >= 0;
            let bulge = (w / 24).max(1);
            let m = bulge + 2;                  // marge bbox (bombé + AA)
            // Évalue le blob en coordonnées locales : (alpha 0..255, luminosité ‰, gris bruit)
            let eval = |lx: i32, ly: i32| -> (u32, i32, u32) {
                let lyc = (2 * ly - h).abs().min(h);
                let lxc = (2 * lx - w).abs().min(w);
                let py_ = h - lyc; let px_ = w - lxc;
                let ex = (w / 2 - r) + (bulge * py_ * py_) / (h * h);
                let ey = (h / 2 - r) + (bulge * px_ * px_) / (w * w);
                let qx = (lx - w / 2).abs() - ex;
                let qy = (ly - h / 2).abs() - ey;
                let ext = isqrt((qx.max(0) * qx.max(0) + qy.max(0) * qy.max(0)) as u32) as i32;
                let dist = ext + qx.max(qy).min(0) - r;
                if dist > 1 { return (0, 1000, 0); }
                let a = if dist >= -1 { (base_a * ((1 - dist) as u32)) / 2 } else { base_a };
                // Ombrage MAT « coussin BOMBÉ » : dôme diffus (centre lumineux
                // décalé vers le haut +9 %, assombrissement progressif vers les
                // bords -8 %) qui donne du volume SANS toucher la silhouette,
                // + macro-plis discrets (±7 %, fermé seulement) et grain
                // pointillé granita. Pas de spéculaire : le dôme est un
                // dégradé large, ça reste mat.
                let dxc = lx - w / 2;
                let dyc = ly - (h * 3) / 8;     // centre du dôme à 37,5 % de haut
                let rr = ((w * w + h * h) / 8).max(1);
                let t = (((dxc * dxc + dyc * dyc) * 1000) / rr).min(1000);
                let dome = 90 - (t * 170) / 1000;                       // +90 → -80 ‰
                let mut bright = 1000 + dome;
                // BRUIT navbar gesture, MÊME RECETTE que GpuDrawNoisePatch :
                // mélange de chaque pixel vers un GRIS aléatoire 0..255 avec
                // alpha 64 (appliqué aux sites d'appel) — mais hash déterministe
                // en coordonnées LOCALES : il suit GPU_TRANSFORM et ne déborde
                // jamais du losange pivoté. FINALISEUR type Murmur obligatoire :
                // le simple xor de multiplications donnait des motifs corrélés
                // (mailles de tricot) au lieu d'un bruit blanc.
                let mut hsh = ((lx + 64) as u32).wrapping_mul(73856093)
                    ^ ((ly + 64) as u32).wrapping_mul(19349663);
                hsh ^= hsh >> 13; hsh = hsh.wrapping_mul(0x5bd1e995); hsh ^= hsh >> 15;
                let gray = hsh & 0xFF;
                if textured {
                    // App FERMÉE : LÉGÈREMENT replié sur lui-même — UNIQUEMENT
                    // les macro-plis doux (±7 %, produit de 2 sinus 2D : pas de
                    // bandes). AUCUNE rayure/cannelure (verdict user : « pas de
                    // rayure, des grains que je veux »). phase anime le repli.
                    let a1 = (ly * 360) / h + phase;
                    let a2 = (lx * 360) / w + phase * 2 + 120;
                    let macro_ = (sin_i(a1) * sin_i(a2 + 60)) / 1000;  // ±1000
                    bright += (macro_ * 70) / 1000;
                }
                (a.min(255), bright.min(1110), gray)
            };
            if unsafe { GPU_TRANSFORM_ACTIVE } {
                let t = unsafe { GPU_TRANSFORM };
                let (ta, tb, tc, td, ttx, tty) = (t[0], t[1], t[2], t[3], t[4], t[5]);
                let corners = [(x - m, y - m), (x + w + m, y - m), (x - m, y + h + m), (x + w + m, y + h + m)];
                let mut min_fx = i32::MAX; let mut max_fx = i32::MIN;
                let mut min_fy = i32::MAX; let mut max_fy = i32::MIN;
                for &(cx0, cy0) in corners.iter() {
                    let fx = ta * cx0 / 10000 + tc * cy0 / 10000 + ttx;
                    let fy = tb * cx0 / 10000 + td * cy0 / 10000 + tty;
                    if fx < min_fx { min_fx = fx; } if fx > max_fx { max_fx = fx; }
                    if fy < min_fy { min_fy = fy; } if fy > max_fy { max_fy = fy; }
                }
                min_fx = min_fx.max(0); max_fx = max_fx.min(sw2 - 1);
                min_fy = min_fy.max(0); max_fy = max_fy.min(sh2 - 1);
                let (ta64, tb64, tc64, td64) = (ta as i64, tb as i64, tc as i64, td as i64);
                let det = ta64 * td64 - tc64 * tb64;
                if det != 0 {
                    for fy in min_fy..=max_fy {
                        for fx in min_fx..=max_fx {
                            let dx = (fx - ttx) as i64;
                            let dy = (fy - tty) as i64;
                            let lx = ((td64 * dx - tc64 * dy) * 10000 / det) as i32 - x;
                            let ly = ((-tb64 * dx + ta64 * dy) * 10000 / det) as i32 - y;
                            if lx < -m || lx >= w + m || ly < -m || ly >= h + m { continue; }
                            let (a, bright, gray) = eval(lx, ly);
                            if a == 0 { continue; }
                            // Bruit navbar : mix vers le gris aléatoire, alpha 64/255.
                            let nr2 = ((cr_ as i32 * bright / 1000).clamp(0, 255) as u32 * 191 + gray * 64) / 255;
                            let ng2 = ((cg_ as i32 * bright / 1000).clamp(0, 255) as u32 * 191 + gray * 64) / 255;
                            let nb2 = ((cb_ as i32 * bright / 1000).clamp(0, 255) as u32 * 191 + gray * 64) / 255;
                            let ia = 255 - a;
                            let di = (fy * s + fx) as usize;
                            let dst = unsafe { fb.add(di).read_volatile() };
                            let db = (dst & 0xFF) as u32; let dg = ((dst >> 8) & 0xFF) as u32; let dr = ((dst >> 16) & 0xFF) as u32;
                            unsafe { fb.add(di).write_volatile(0xFF000000 | (((nr2*a+dr*ia)/255) << 16) | (((ng2*a+dg*ia)/255) << 8) | ((nb2*a+db*ia)/255)); }
                        }
                    }
                }
            } else {
                for ly in -m..(h + m) {
                    let fy = y + ly; if fy < 0 || fy >= sh2 { continue; }
                    for lx in -m..(w + m) {
                        let fx = x + lx; if fx < 0 || fx >= sw2 { continue; }
                        let (a, bright, gray) = eval(lx, ly);
                        if a == 0 { continue; }
                        // Bruit navbar : mix vers le gris aléatoire, alpha 64/255.
                        let nr2 = ((cr_ as i32 * bright / 1000).clamp(0, 255) as u32 * 191 + gray * 64) / 255;
                        let ng2 = ((cg_ as i32 * bright / 1000).clamp(0, 255) as u32 * 191 + gray * 64) / 255;
                        let nb2 = ((cb_ as i32 * bright / 1000).clamp(0, 255) as u32 * 191 + gray * 64) / 255;
                        let ia = 255 - a;
                        let di = (fy * s + fx) as usize;
                        let dst = unsafe { fb.add(di).read_volatile() };
                        let db = (dst & 0xFF) as u32; let dg = ((dst >> 8) & 0xFF) as u32; let dr = ((dst >> 16) & 0xFF) as u32;
                        unsafe { fb.add(di).write_volatile(0xFF000000 | (((nr2*a+dr*ia)/255) << 16) | (((ng2*a+dg*ia)/255) << 8) | ((nb2*a+db*ia)/255)); }
                    }
                }
            }
            0
        },

        // ── GpuDrawTextFontAlign(x,y,maxW,text,fg,bg,font,size,align) ────────
        // align: 0=left, 1=center, 2=right
        "DrvAPIInterCon___GpuDrawTextFontAlign___" => {
            if args.len() < 9 { return 0; }
            let base_x  = args[0] as i32;
            let y       = args[1] as i32;
            let max_w   = args[2] as i32;
            let tp      = args[3] as *const u8;
            let fg      = args[4];
            let bg      = args[5];
            let font_ptr= args[6];
            let size    = args[7] as i32;
            let align   = args[8] as i32;
            serial_log(alloc::format!(
                "[MENU] GpuDrawTextFontAlign x={} y={} maxW={} font_ptr={:#x} size={}\r\n",
                base_x, y, max_w, font_ptr, size
            ).as_bytes());
            if tp.is_null() || font_ptr == 0 { return 0; }
            let ttf_bytes  = unsafe { FONT_TTF_OVC.as_deref() }.unwrap_or(&[]);
            let rast_bytes = unsafe { FONT_RAST_OVC.as_deref() }.unwrap_or(&[]);
            let woff_bytes = unsafe { FONT_WOFF_OVC.as_deref() }.unwrap_or(&[]);
            if ttf_bytes.is_empty() || rast_bytes.is_empty() { return 0; }
            let ttf_text  = core::str::from_utf8(ttf_bytes).unwrap_or("");
            let rast_text = core::str::from_utf8(rast_bytes).unwrap_or("");
            let woff_text = core::str::from_utf8(woff_bytes).unwrap_or("");
            ttf_ensure_loaded(ttf_bytes, rast_text, woff_text, font_ptr, ctx);
            let ttf_mods=[("GlyphRasterizer", rast_text)];
            let rast_mods=[("TtfParser", ttf_text)];
            let mut n = 0usize;
            unsafe { while *tp.add(n) != 0 { n += 1; } }
            let pipe = TtfLine {
                ttf_bytes, rast_bytes,
                ttf_mods: &ttf_mods, rast_mods: &rast_mods,
                font_ptr, size, lsp: 0,
            };
            // Mesure RÉELLE (avances hmtx + kerning) pour l'alignement — l'estimation
            // n*size*0.6 décalait tous les textes centrés/alignés à droite.
            let text_w = ttf_line_width(&pipe, ctx, tp, 0, n);
            let x = match align {
                1 => base_x + (max_w - text_w) / 2,  // centre
                2 => base_x + max_w - text_w,        // droite
                _ => base_x,                         // gauche
            };
            ttf_draw_line(&pipe, ctx, tp, 0, n, x, y, fg, bg);
            0
        },

        // ── GpuDrawTextFontFull(x,y,text,fg,bg,font,size,letterSp,lineH,align,deco) ──
        // deco: bit0=underline, bit1=strikethrough
        "DrvAPIInterCon___GpuDrawTextFontFull___" => {
            if args.len() < 7 { return 0; }
            let base_x   = args[0] as i32;
            let base_y   = args[1] as i32;
            let tp       = args[2] as *const u8;
            let fg       = args[3];
            let bg       = args[4];
            let font_ptr = args[5];
            let size     = args[6] as i32;
            let lsp      = if args.len() >= 8  { args[7] as i32 } else { 0 };
            let line_h   = if args.len() >= 9  { args[8] as i32 } else { size + 4 };
            let align    = if args.len() >= 10 { args[9] as i32 } else { 0 };
            let deco     = if args.len() >= 11 { args[10] as u32 } else { 0 };
            if tp.is_null() || font_ptr == 0 { return 0; }
            let ttf_bytes  = unsafe { FONT_TTF_OVC.as_deref() }.unwrap_or(&[]);
            let rast_bytes = unsafe { FONT_RAST_OVC.as_deref() }.unwrap_or(&[]);
            let woff_bytes = unsafe { FONT_WOFF_OVC.as_deref() }.unwrap_or(&[]);
            if ttf_bytes.is_empty() || rast_bytes.is_empty() { return 0; }
            let ttf_text  = core::str::from_utf8(ttf_bytes).unwrap_or("");
            let rast_text = core::str::from_utf8(rast_bytes).unwrap_or("");
            let woff_text = core::str::from_utf8(woff_bytes).unwrap_or("");
            ttf_ensure_loaded(ttf_bytes, rast_text, woff_text, font_ptr, ctx);
            let fb_raw  = ctx.fb; let stride = ctx.stride;
            let scr_w   = ctx.width; let scr_h = ctx.height;
            let ttf_mods  = [("GlyphRasterizer", rast_text)];
            let rast_mods = [("TtfParser", ttf_text)];
            let pipe = TtfLine {
                ttf_bytes, rast_bytes,
                ttf_mods: &ttf_mods, rast_mods: &rast_mods,
                font_ptr, size, lsp,
            };
            // Découper en lignes sur \n
            let mut line_start = 0usize;
            let mut line_y = base_y;
            loop {
                // Trouver la fin de ligne
                let mut ci = line_start;
                loop {
                    let ch = unsafe { *tp.add(ci) };
                    if ch == 0 || ch == b'\n' { break; }
                    ci += 1;
                }
                let line_end = ci;
                // Mesure réelle (avances hmtx + kerning) pour l'alignement
                let line_w = ttf_line_width(&pipe, ctx, tp, line_start, line_end);
                let line_x = match align {
                    1 => base_x - line_w / 2,
                    2 => base_x - line_w,
                    _ => base_x,
                };
                let cx = ttf_draw_line(&pipe, ctx, tp, line_start, line_end, line_x, line_y, fg, bg);
                // Décorations
                if deco & 1 != 0 && !fb_raw.is_null() {
                    // Soulignement : ligne horizontale à line_y + size
                    let uy = line_y + size; let ux0 = line_x; let ux1 = cx;
                    if uy >= 0 && uy < scr_h {
                        let fc = fg as u32;
                        let fr=(fc>>16)&0xFF; let fgc=(fc>>8)&0xFF; let fbc=fc&0xFF;
                        for ux in ux0..ux1 { if ux>=0&&ux<scr_w {
                            unsafe { fb_raw.add((uy*stride+ux) as usize).write_volatile(0xFF000000|(fr<<16)|(fgc<<8)|fbc); }
                        }}
                    }
                }
                if deco & 2 != 0 && !fb_raw.is_null() {
                    // Barré : ligne à line_y + size/2
                    let sy2 = line_y + size / 2; let sx0 = line_x; let sx1 = cx;
                    if sy2 >= 0 && sy2 < scr_h {
                        let fc = fg as u32;
                        let fr=(fc>>16)&0xFF; let fgc=(fc>>8)&0xFF; let fbc=fc&0xFF;
                        for sux in sx0..sx1 { if sux>=0&&sux<scr_w {
                            unsafe { fb_raw.add((sy2*stride+sux) as usize).write_volatile(0xFF000000|(fr<<16)|(fgc<<8)|fbc); }
                        }}
                    }
                }
                let ch_end = unsafe { *tp.add(line_end) };
                if ch_end == 0 { break; }
                line_start = line_end + 1;
                line_y += line_h;
            }
            0
        },

        // ── SvgLoad(path_ptr) → handle (1-based) ─────────────────────────────
        "DrvAPIInterCon___SvgLoad___" => {
            if args.len() < 1 || args[0] == 0 { return 0; }
            let data_ptr = srfs_load_on_demand(args[0]);
            if data_ptr == 0 { return 0; }
            // Retrouver les octets dans SRFS_CACHE pour les copier dans SVG_CACHE
            let path_p = args[0] as *const u8;
            let mut plen = 0usize;
            unsafe { while *path_p.add(plen) != 0 { plen += 1; if plen > 512 { break; } } }
            let path_s = unsafe { core::str::from_utf8(core::slice::from_raw_parts(path_p, plen)).unwrap_or("") };
            let svg_bytes: Option<Vec<u8>> = unsafe {
                SRFS_CACHE.iter().find_map(|slot| {
                    if let Some((ref k, ref d)) = slot {
                        if keys_match(k.as_str(), path_s) { return Some(d.clone()); }
                    }
                    None
                })
            };
            let bytes = match svg_bytes { Some(b) => b, None => return 0 };
            unsafe {
                for (i, slot) in SVG_CACHE.iter_mut().enumerate() {
                    if slot.is_none() { *slot = Some(bytes); return (i + 1) as i64; }
                }
                // Recycler le slot 0
                SVG_CACHE[0] = Some(bytes);
                1
            }
        },

        // ── SvgDraw(handle,x,y,w,h) ──────────────────────────────────────────
        "DrvAPIInterCon___SvgDraw___" => {
            if args.len() < 5 || args[0] <= 0 { return 0; }
            let slot = (args[0] as usize).wrapping_sub(1);
            let svg_bytes: Option<&Vec<u8>> = unsafe { SVG_CACHE.get(slot).and_then(|s| s.as_ref()) };
            let bytes = match svg_bytes { Some(b) => b.as_slice(), None => return 0 };
            let dx = args[1] as i32; let dy = args[2] as i32;
            let dw = args[3] as i32; let dh = args[4] as i32;
            if dw <= 0 || dh <= 0 { return 0; }
            svg_render(bytes, ctx.fb, ctx.stride, ctx.width, ctx.height, dx, dy, dw, dh);
            0
        },

        // ── SvgFree(handle) ───────────────────────────────────────────────────
        "DrvAPIInterCon___SvgFree___" => {
            if args.len() >= 1 && args[0] > 0 {
                let slot = (args[0] as usize).wrapping_sub(1);
                if slot < 8 { unsafe { SVG_CACHE[slot] = None; } }
            }
            0
        },

        // ── CursorLoad(path_ptr) → handle (1-based) — charge un .sluc/.slun ──
        "DrvAPIInterCon___CursorLoad___" => {
            serial_log(b"[CURSOR] CursorLoad\r\n");
            if args.len() < 1 || args[0] == 0 { serial_log(b"[CURSOR] arg manquant\r\n"); return 0; }
            let data_ptr = srfs_load_on_demand(args[0]);
            if data_ptr == 0 { serial_log(b"[CURSOR] fichier non trouve\r\n"); return 0; }
            let path_p = args[0] as *const u8;
            let mut plen = 0usize;
            unsafe { while *path_p.add(plen) != 0 { plen += 1; if plen > 512 { break; } } }
            let path_s = unsafe { core::str::from_utf8(core::slice::from_raw_parts(path_p, plen)).unwrap_or("") };
            let raw: Option<Vec<u8>> = unsafe {
                SRFS_CACHE.iter().find_map(|slot| {
                    if let Some((ref k, ref d)) = slot {
                        if keys_match(k.as_str(), path_s) { return Some(d.clone()); }
                    }
                    None
                })
            };
            let bytes = match raw {
                Some(b) => b,
                None => { serial_log(b"[CURSOR] absent de SRFS_CACHE\r\n"); return 0; }
            };
            serial_log(alloc::format!("[CURSOR] {} octets lus\r\n", bytes.len()).as_bytes());
            let text = match core::str::from_utf8(&bytes) {
                Ok(t) => t,
                Err(_) => { serial_log(b"[CURSOR] UTF-8 invalide\r\n"); return 0; }
            };
            let mut asset = match parse_cursor(text) {
                Some(a) => a,
                None => { serial_log(b"[CURSOR] parse_cursor echoue (aucune frame)\r\n"); return 0; }
            };
            serial_log(alloc::format!(
                "[CURSOR] parse OK size={}x{} hotspot={},{} frames={}\r\n",
                asset.width, asset.height, asset.hotspot_x, asset.hotspot_y, asset.frames.len()
            ).as_bytes());
            // Ramène à la taille standard (façon Windows) quelle que soit la résolution
            // native de l'asset — un rect de 1px redimensionné au vol tronquerait à 0px
            // (bug déjà rencontré), donc on ré-échantillonne une fois ici, au chargement.
            if asset.width != STANDARD_CURSOR_SIZE || asset.height != STANDARD_CURSOR_SIZE {
                let (sw, sh) = (asset.width, asset.height);
                let mut resampled: Vec<String> = Vec::new();
                let mut ok = true;
                for f in asset.frames.iter() {
                    match resample_rect_frame(f, sw, sh, STANDARD_CURSOR_SIZE) {
                        Some(r) => resampled.push(r),
                        None => { ok = false; break; }
                    }
                }
                if ok {
                    asset.hotspot_x = asset.hotspot_x * STANDARD_CURSOR_SIZE / sw.max(1);
                    asset.hotspot_y = asset.hotspot_y * STANDARD_CURSOR_SIZE / sh.max(1);
                    asset.width  = STANDARD_CURSOR_SIZE;
                    asset.height = STANDARD_CURSOR_SIZE;
                    asset.frames = resampled;
                    serial_log(b"[CURSOR] resample OK vers taille standard\r\n");
                } else {
                    serial_log(b"[CURSOR] resample echoue\r\n");
                }
            }
            unsafe {
                for (i, slot) in CURSOR_CACHE.iter_mut().enumerate() {
                    if slot.is_none() {
                        serial_log(alloc::format!("[CURSOR] handle={}\r\n", i + 1).as_bytes());
                        *slot = Some(asset);
                        return (i + 1) as i64;
                    }
                }
                serial_log(b"[CURSOR] cache plein, recyclage slot 0 -> handle=1\r\n");
                CURSOR_CACHE[0] = Some(asset);
                1
            }
        },

        // ── CursorDraw(handle,x,y) — dessine à (x,y) écran, hotspot déduit.
        // Curseur animé (frame_ms > 0) : frame = (ticks*16ms / frame_ms) % nb_frames,
        // CURSOR_TICK avance une fois par frame rendue (cf. reset_gpu_counters).
        // CursorDraw(handle,x,y) dessine à la taille native du fichier ; l'appel
        // optionnel CursorDraw(handle,x,y,w,h) impose une taille (ex. responsive
        // sw/sh) — le hotspot est alors mis à l'échelle proportionnellement.
        "DrvAPIInterCon___CursorDraw___" => {
            if args.len() < 3 || args[0] <= 0 {
                serial_log(b"[CURSOR] Draw: handle invalide\r\n");
                return 0;
            }
            let slot = (args[0] as usize).wrapping_sub(1);
            let drawn = unsafe {
                match CURSOR_CACHE.get(slot).and_then(|s| s.as_ref()) {
                    Some(asset) => {
                        let frame_idx = if asset.frame_ms > 0 && asset.frames.len() > 1 {
                            let elapsed_ms = CURSOR_TICK.saturating_mul(16);
                            ((elapsed_ms / asset.frame_ms.max(1) as u64) as usize) % asset.frames.len()
                        } else { 0 };
                        let dw = if args.len() >= 5 && args[3] > 0 { args[3] as i32 } else { asset.width };
                        let dh = if args.len() >= 5 && args[4] > 0 { args[4] as i32 } else { asset.height };
                        let hx = if asset.width  > 0 { asset.hotspot_x * dw / asset.width  } else { 0 };
                        let hy = if asset.height > 0 { asset.hotspot_y * dh / asset.height } else { 0 };
                        let dx = args[1] as i32 - hx;
                        let dy = args[2] as i32 - hy;
                        Some((asset.frames[frame_idx].clone(), dx, dy, dw, dh))
                    }
                    None => None,
                }
            };
            match drawn {
                Some((svg_text, dx, dy, dw, dh)) => {
                    serial_log(alloc::format!(
                        "[CURSOR] Draw handle={} pos=({},{}) size={}x{} bytes_svg={}\r\n",
                        args[0], dx, dy, dw, dh, svg_text.len()
                    ).as_bytes());
                    svg_render(svg_text.as_bytes(), ctx.fb, ctx.stride, ctx.width, ctx.height, dx, dy, dw, dh);
                }
                None => {
                    serial_log(alloc::format!("[CURSOR] Draw handle={} : slot vide (pas charge)\r\n", args[0]).as_bytes());
                }
            }
            0
        },

        // ── CursorFree(handle) ────────────────────────────────────────────────
        "DrvAPIInterCon___CursorFree___" => {
            if args.len() >= 1 && args[0] > 0 {
                let slot = (args[0] as usize).wrapping_sub(1);
                if slot < 4 { unsafe { CURSOR_CACHE[slot] = None; } }
            }
            0
        },

        // ── TouchGetEvent() → 0 (pas de touch en UEFI boot) ──────────────────
        "DrvAPIInterCon___TouchGetEvent___" => 0,

        // ── Pointeur HID réel (EFI_SIMPLE_POINTER_PROTOCOL, polled par le kernel
        // chaque frame dans render_from_marep) — coordonnées en pixels écran réels.
        "DrvAPIInterCon___PointerGetX___"   => ctx.pointer_x as i64,
        "DrvAPIInterCon___PointerGetY___"   => ctx.pointer_y as i64,
        "DrvAPIInterCon___PointerGetBtn___" => {
            // DIAG : ne log QUE quand un bouton est réellement pressé (pas de spam par frame).
            // Confirme si l'état du bouton pointeur atteint bien la couche Maratine.
            if ctx.pointer_btn != 0 {
                serial_log(alloc::format!("[DIAG] PointerGetBtn = {}\r\n", ctx.pointer_btn).as_bytes());
            }
            ctx.pointer_btn as i64
        },

        // ── Clavier HID réel (EFI_SIMPLE_TEXT_INPUT_PROTOCOL / ConIn) ────────
        "DrvAPIInterCon___KeyGetCode___" => {
            // DIAG : ne log QUE quand une touche est reçue (Entree = 13).
            if ctx.key_code != 0 {
                serial_log(alloc::format!("[DIAG] KeyGetCode = {}\r\n", ctx.key_code).as_bytes());
            }
            ctx.key_code as i64
        },

        // ── Bureau à fenêtres — primitives bas niveau, pilotées depuis Maratine
        // (LAPrevent.mara/TemplateView.mara). RUNNING_APPS est la seule source de
        // vérité côté Rust ; la décision de déplacer/redimensionner/fermer/lancer
        // une fenêtre est entièrement décidée en Maratine à chaque frame.
        "DrvAPIInterCon___WindowManCount___" => unsafe { RUNNING_APPS.len() as i64 },

        "DrvAPIInterCon___WindowManGetX___" => window_man_get(args, |a| a.x),
        "DrvAPIInterCon___WindowManGetY___" => window_man_get(args, |a| a.y),
        "DrvAPIInterCon___WindowManGetW___" => window_man_get(args, |a| a.content_w),
        "DrvAPIInterCon___WindowManGetH___" => window_man_get(args, |a| a.content_h),
        // Tick d'ouverture de la fenêtre (CURSOR_TICK au lancement) — âge de la
        // fenêtre = GpuGetTick - GetOpenTick, pour les animations du dock.
        "DrvAPIInterCon___WindowManGetOpenTick___" => window_man_get(args, |a| a.opened_tick as i32),
        // Argument de lancement (WindowManLaunch(name, arg)) de la fenêtre i — pointeur
        // nul-terminé, "" (juste "\0") si aucun arg n'a été passé au lancement. Lu par
        // l'app cible une fois à son premier rendu (ex: item de menu "New Folder").
        "DrvAPIInterCon___WindowManGetLaunchArg___" => {
            let Some(&i) = args.first() else { return 0; };
            unsafe { RUNNING_APPS.get(i as usize).map(|a| a.launch_arg_c.as_ptr() as i64).unwrap_or(0) }
        },
        // Génération du launch_arg de la fenêtre i — incrémentée à chaque écriture
        // (lancement initial OU WindowManSetLaunchArg ci-dessous). L'app cible
        // compare cette valeur à la dernière génération traitée (stockée dans son
        // propre SCROLL_SCRATCH) pour savoir si un NOUVEL arg est arrivé, sans le
        // retraiter en boucle chaque frame (voir commentaire sur launch_arg_gen).
        "DrvAPIInterCon___WindowManGetLaunchArgGen___" => {
            let Some(&i) = args.first() else { return 0; };
            unsafe { RUNNING_APPS.get(i as usize).map(|a| a.launch_arg_gen as i64).unwrap_or(0) }
        },
        // Met à jour le launch_arg d'une fenêtre DÉJÀ OUVERTE (i = index existant,
        // typiquement WindowManFindByName(name) >= 0) SANS relancer l'app — sert
        // au menu contextuel du dock quand l'app ciblée tourne déjà : appeler
        // WindowManLaunch dans ce cas dupliquerait une seconde instance (aucune
        // déduplication par nom n'existe dans WindowManLaunch), au lieu de router
        // l'action vers la fenêtre existante.
        "DrvAPIInterCon___WindowManSetLaunchArg___" => {
            let Some(&i) = args.first() else { return -1; };
            let arg_ptr = args.get(1).copied().unwrap_or(0);
            let mut arg_c = if arg_ptr != 0 {
                unsafe { read_cstr(arg_ptr as *const u8) }.into_bytes()
            } else {
                alloc::vec::Vec::new()
            };
            arg_c.push(0);
            unsafe {
                let Some(app) = RUNNING_APPS.get_mut(i as usize) else { return -1; };
                app.launch_arg_c = arg_c;
                app.launch_arg_gen = app.launch_arg_gen.wrapping_add(1);
                if app.launch_arg_gen == 0 { app.launch_arg_gen = 1; } // jamais 0 (sentinelle "aucun arg encore vu")
            }
            0
        },
        // Tick de frame global (1 par frame rendue) + trig entière ×10000 —
        // de quoi animer GpuSetTransform2D depuis Maratine (rotations du dock).
        "DrvAPIInterCon___GpuGetTick___"  => unsafe { CURSOR_TICK as i64 },
        "DrvAPIInterCon___MathCos10k___" => {
            let deg = args.first().copied().unwrap_or(0) as i32;
            (cos_i(deg) * 10) as i64
        },
        "DrvAPIInterCon___MathSin10k___" => {
            let deg = args.first().copied().unwrap_or(0) as i32;
            (sin_i(deg) * 10) as i64
        },

        // Chrome de fenêtre (barre « Shi Windows ») : nom + icône d'app PAR fenêtre, résolus
        // depuis le registre via le nom de la fenêtre (RunningApp.name). Pointeurs null-terminés
        // stables (ceux du registre) → utilisables pour GpuDrawText / ImageLoad.
        "DrvAPIInterCon___WindowManGetName___" => {
            let Some(&i) = args.first() else { return 0; };
            let name = match unsafe { RUNNING_APPS.get(i as usize) } { Some(a) => a.name.clone(), None => return 0 };
            crate::app_registry::registry_name_icon_for(&name).0
        },
        "DrvAPIInterCon___WindowManGetIconPath___" => {
            let Some(&i) = args.first() else { return 0; };
            let name = match unsafe { RUNNING_APPS.get(i as usize) } { Some(a) => a.name.clone(), None => return 0 };
            crate::app_registry::registry_name_icon_for(&name).1
        },
        // Titre « AppName - CurrentScreen » de la fenêtre i (display_name du registre).
        "DrvAPIInterCon___WindowManGetTitle___" => {
            let Some(&i) = args.first() else { return 0; };
            let name = match unsafe { RUNNING_APPS.get(i as usize) } { Some(a) => a.name.clone(), None => return 0 };
            crate::app_registry::registry_display_ptr_for(&name)
        },
        // Couleur ARGB du losange (barre de titre) de la fenêtre i — donnée du Maraset.yaml
        // de l'app (diamond_color) via le registre, résolue par nom (comme GetTitle/GetIconPath).
        "DrvAPIInterCon___WindowManGetDiamondColor___" => {
            let Some(&i) = args.first() else { return crate::app_registry::DEFAULT_DIAMOND_COLOR as i64; };
            let name = match unsafe { RUNNING_APPS.get(i as usize) } {
                Some(a) => a.name.clone(),
                None => return crate::app_registry::DEFAULT_DIAMOND_COLOR as i64,
            };
            crate::app_registry::registry_diamond_color_for(&name)
        },

        "DrvAPIInterCon___WindowManSetX___" => window_man_set(args, |a, v| a.x = v),
        "DrvAPIInterCon___WindowManSetY___" => window_man_set(args, |a, v| a.y = v),
        "DrvAPIInterCon___WindowManSetW___" => window_man_set(args, |a, v| a.resize(v, a.content_h)),
        "DrvAPIInterCon___WindowManSetH___" => window_man_set(args, |a, v| a.resize(a.content_w, v)),

        "DrvAPIInterCon___WindowManClose___" => {
            if let Some(&i) = args.first() {
                let i = i as usize;
                unsafe {
                    if i < RUNNING_APPS.len() {
                        RUNNING_APPS.remove(i);
                        serial_log(alloc::format!("[WINMAN] fenetre {} FERMEE ({} restante(s))\r\n", i, RUNNING_APPS.len()).as_bytes());
                    }
                }
            }
            0
        },

        "DrvAPIInterCon___WindowManFindByName___" => {
            // DIAG placé AVANT le retour anticipé : confirme que la branche dock→lancement
            // est atteinte MÊME si le nom est nul (sinon symptôme silencieux : Entrée reçue,
            // aucun log, rien ne s'ouvre). arg0=0 => AppRegistryGetName a renvoyé nullptr.
            let arg0 = args.first().copied().unwrap_or(0);
            if args.is_empty() || args[0] == 0 {
                serial_log(alloc::format!("[DIAG] WindowManFindByName arg0={:#x} (NUL -> lancement tente mais nom introuvable)\r\n", arg0).as_bytes());
                return -1;
            }
            let name = unsafe { read_cstr(args[0] as *const u8) };
            let res = unsafe {
                RUNNING_APPS.iter().position(|a| a.name == name).map(|i| i as i64).unwrap_or(-1)
            };
            serial_log(alloc::format!("[DIAG] WindowManFindByName(\"{}\") -> {}\r\n", name, res).as_bytes());
            res
        },

        // ── Registre d'apps installées (dock dynamique, piloté par TemplateView.mara) ──
        // Le dock itère AppRegistryCount() et dessine AppRegistryGetIconPath(i) ; un clic
        // lance AppRegistryGetName(i). Une app absente du registre (non installée) n'a
        // aucune entrée — donc pas d'icône au dock, comme un vrai système.
        "DrvAPIInterCon___AppRegistryCount___" => crate::app_registry::registry_count(),
        "DrvAPIInterCon___AppRegistryGetName___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { return 0; }
            crate::app_registry::registry_name_ptr(i as usize)
        },
        "DrvAPIInterCon___AppRegistryGetIconPath___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { return 0; }
            crate::app_registry::registry_icon_ptr(i as usize)
        },
        // Couleur ARGB du losange (dock) — donnée du Maraset.yaml de l'app (diamond_color),
        // PAS codée en dur : ShiLauncher n'a plus besoin de reconnaître une app par son nom.
        "DrvAPIInterCon___AppRegistryGetDiamondColor___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { return crate::app_registry::DEFAULT_DIAMOND_COLOR as i64; }
            crate::app_registry::registry_diamond_color(i as usize)
        },

        // ── Épinglage dock (session-only, voir commentaire de publish_registry) ──
        "DrvAPIInterCon___AppRegistryGetPinned___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { return 0; }
            crate::app_registry::registry_get_pinned(i as usize)
        },
        "DrvAPIInterCon___AppRegistrySetPinned___" => {
            if args.len() < 2 || args[0] < 0 { return -1; }
            crate::app_registry::registry_set_pinned(args[0] as usize, args[1] != 0)
        },
        // ── Menu contextuel par app (dock_menu_items du Maraset.yaml) ──
        "DrvAPIInterCon___AppRegistryGetMenuItemCount___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { return 0; }
            let cnt = crate::app_registry::registry_menu_item_count(i as usize);
            serial_log(alloc::format!("[MENU] MenuItemCount ownerIdx={} -> {}\r\n", i, cnt).as_bytes());
            cnt
        },
        "DrvAPIInterCon___AppRegistryGetMenuItemLabel___" => {
            if args.len() < 2 || args[0] < 0 || args[1] < 0 { return 0; }
            serial_log(alloc::format!("[MENU] MenuItemLabel i={} j={}\r\n", args[0], args[1]).as_bytes());
            crate::app_registry::registry_menu_item_label_ptr(args[0] as usize, args[1] as usize)
        },
        "DrvAPIInterCon___AppRegistryGetMenuItemSubmenuCount___" => {
            if args.len() < 2 || args[0] < 0 || args[1] < 0 { return 0; }
            crate::app_registry::registry_menu_item_submenu_count(args[0] as usize, args[1] as usize)
        },
        "DrvAPIInterCon___AppRegistryGetMenuItemSubmenuLabel___" => {
            if args.len() < 3 || args[0] < 0 || args[1] < 0 || args[2] < 0 { return 0; }
            crate::app_registry::registry_menu_item_submenu_label_ptr(args[0] as usize, args[1] as usize, args[2] as usize)
        },

        // WindowManLaunch(nameStr) — charge \<nameStr>.marep à la racine ESP
        // (convention provisoire, cf. plan) via le même mécanisme UEFI_ST_PTR/
        // UEFI_IMG_HANDLE déjà utilisé par srfs_load_on_demand pour ImageLoad/
        // FontLoad. Position/taille par défaut arbitraires pour ce jalon (1
        // fenêtre à la fois) ; retourne l'index de la nouvelle fenêtre ou -1.
        "DrvAPIInterCon___WindowManLaunch___" => {
            if args.is_empty() || args[0] == 0 { return -1; }
            let name = unsafe { read_cstr(args[0] as *const u8) };
            // Second argument optionnel (pointeur string) — contexte de lancement lu par
            // l'app cible via WindowManGetLaunchArg (ex: item de menu contextuel "New
            // Folder" qui doit ouvrir directement le bon dialogue).
            let mut launch_arg_c = if args.len() >= 2 && args[1] != 0 {
                unsafe { read_cstr(args[1] as *const u8) }.into_bytes()
            } else {
                alloc::vec::Vec::new()
            };
            launch_arg_c.push(0);
            let st_raw = unsafe { UEFI_ST_PTR };
            if st_raw.is_null() {
                serial_log(b"[WINMAN] ST_PTR null, lancement impossible\r\n");
                return -1;
            }
            let (mut st, img) = unsafe {
                let st = match uefi::table::SystemTable::<uefi::table::Boot>::from_ptr(st_raw) {
                    Some(s) => s,
                    None => return -1,
                };
                let img = match uefi::Handle::from_ptr(UEFI_IMG_HANDLE as *mut core::ffi::c_void) {
                    Some(h) => h,
                    None => return -1,
                };
                (st, img)
            };
            let path_str = alloc::format!("\\{}.marep", name);
            let path_cstring = match uefi::CString16::try_from(path_str.as_str()) {
                Ok(p) => p,
                Err(_) => return -1,
            };
            match crate::bundle_loader::marep_loader::load_marep_modules(&mut st, img, &path_cstring) {
                Ok((app_name, modules)) => {
                    serial_log(alloc::format!("[WINMAN] lancement {} (nom fenetre={}) OK\r\n", app_name, name).as_bytes());
                    unsafe {
                        // Fenêtre nommée par le nom DEMANDÉ (name), pas par find_app_name
                        // (app_name) : garantit que WindowManFindByName(name) matche même
                        // pour une app sans .slasset (find_app_name renverrait "App").
                        let mut app = crate::window_manager::RunningApp::new(name.clone(), modules, 400, 300, 640, 480);
                        app.opened_tick = CURSOR_TICK;
                        app.launch_arg_c = launch_arg_c;
                        RUNNING_APPS.push(app);
                        let _ = app_name;
                        (RUNNING_APPS.len() - 1) as i64
                    }
                }
                Err(_) => {
                    serial_log(alloc::format!("[WINMAN] lancement {} echoue\r\n", name).as_bytes());
                    -1
                }
            }
        },

        // WindowManRenderAndComposite(i) — construit un ExecCtx pointé sur le
        // buffer propre de la fenêtre i (pointeur traduit en coordonnées locales
        // à partir du ctx de L'APPELANT, c'est-à-dire le bureau), exécute
        // exec_marep dessus (appel imbriqué — sans risque, cf. plan : mod_texts/
        // globals sont locaux à chaque appel), puis blitte le résultat dans le
        // framebuffer de l'appelant. reset_gpu_state() avant ET après : l'état
        // GPU (opacité/transform/clip) est process-wide, pas par-appel.
        "DrvAPIInterCon___WindowManRenderAndComposite___" => {
            let Some(&i) = args.first() else { return -1; };
            let i = i as usize;
            unsafe {
                let Some(app) = RUNNING_APPS.get_mut(i) else { return -1; };
                let inner_ctx = ExecCtx {
                    fb: app.buffer.as_mut_ptr(),
                    width:  app.content_w,
                    height: app.content_h,
                    stride: app.content_w,
                    font:     ctx.font,
                    font_len: ctx.font_len,
                    pointer_x: ctx.pointer_x - app.x,
                    pointer_y: ctx.pointer_y - app.y,
                    pointer_btn: ctx.pointer_btn,
                    key_code:    ctx.key_code,
                };
                // ── Throttle de rendu (réactivité souris) : l'exec_marep imbriqué
                // est LE coût dominant quand une fenêtre est ouverte (tout le
                // marep de l'app ré-interprété). On ne le rejoue que toutes les
                // 6 frames, ou immédiatement sur input (clic/touche — l'app doit
                // réagir) ou buffer sale (resize/ouverture) ; sinon on blitte le
                // dernier contenu tel quel — le bureau, le chrome et le curseur
                // restent fluides entre deux rendus du contenu.
                let now = CURSOR_TICK;
                let must_render = app.dirty
                    || now.saturating_sub(app.last_rendered_tick) >= 6
                    || ctx.key_code != 0
                    || ctx.pointer_btn != 0;
                if must_render {
                    reset_gpu_state();
                    let mod_refs = app.mod_refs();
                    let _ = exec_marep(&mod_refs, &inner_ctx);
                    app.last_rendered_tick = now;
                    app.dirty = false;
                }
                if !ctx.fb.is_null() {
                    let corner_r = args.get(1).copied().unwrap_or(0) as i32; // coins bas arrondis
                    let dst = core::slice::from_raw_parts_mut(ctx.fb, (ctx.stride * ctx.height).max(0) as usize);
                    app.blit_into(dst, ctx.stride, ctx.width, ctx.height, corner_r);
                }
                reset_gpu_state();
            }
            0
        },

        // MaratineKit UI — stubs (pas de RenderContext en UEFI boot)
        "MaratineKit___UI___TextLabel___New"        => 0,
        "MaratineKit___UI___TextLabel___SetAlign"   => 0,
        "MaratineKit___UI___TextLabel___SetFontSize"=> 0,
        "MaratineKit___RenderContext___New"         => 0,
        "MaratineKit___RenderContext___Attach"      => 0,
        "MaratineKit___RenderContext___Detach"      => 0,
        "MaratineKit___PIDActivity___ObtInfo"       => 0,
        // Compter les apps actives en cours d'exécution (dock ShiLauncher)
        "MaratineKit___PIDActivity___Count"        => unsafe { RUNNING_APPS.len() as i64 },
        "MaratineKit___AuthARoot"                   => 0,
        "MaratineKit___RenRootUI"                   => 0,
        "ObtProcess"                                => 0,
        "PAccess"                                   => 0,
        "gcc___archInfo___"                         => 0,

        // printf — no-op silencieux en UEFI
        "printf" => 0,

        // ── CryptoAssetSupport dispatchers (*.ca simple + bundle) ────────────
        // Écrire un fichier .ca dans SRFS (simple ou bundle JSON brut)
        // args[0]=path_ptr  args[1]=json_ptr_or_bytes
        "DrvAPIInterCon___CaWriteFile___" => {
            if args.len() >= 2 {
                let path_ptr = args[0] as *const u8;
                let json_ptr = args[1] as *const u8;
                if !path_ptr.is_null() && !json_ptr.is_null() {
                    let path_str = unsafe { read_cstr(path_ptr) };
                    let json_str = unsafe { read_cstr(json_ptr) };
                    srfs_write_chain_file(&path_str, json_str.as_bytes());
                }
            }
            0
        },

        // Lire un fichier .ca depuis SRFS vers un buffer alloué par l'appelant
        // (identique à FSRead mais dans le namespace Ca)
        "DrvAPIInterCon___CaReadFile___" => {
            if args.len() >= 3 {
                let path_ptr = args[0] as *const u8;
                let out_buf  = args[1] as *mut u8;
                let out_size = args[2] as usize;
                if !path_ptr.is_null() && !out_buf.is_null() {
                    let path_str = unsafe { read_cstr(path_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        let n = data.len().min(out_size);
                        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, n); }
                        return n as i64;
                    }
                }
            }
            -1
        },

        // Compter les fichiers .ca dans un répertoire SRFS
        // args[0]=dir_path_ptr → nombre de .ca trouvés dans le cache
        "DrvAPIInterCon___CaCountFiles___" => {
            let count = unsafe {
                SRFS_CACHE.iter()
                    .filter(|s| {
                        if let Some((k, _)) = s { k.ends_with(".ca") } else { false }
                    })
                    .count() as i64
            };
            count
        },

        // Lister les .ca (noms séparés par \n) dans un répertoire SRFS
        // args[0]=dir_path_ptr  args[1]=out_buf  args[2]=max_size
        "DrvAPIInterCon___CaListFiles___" => {
            if args.len() >= 3 {
                let out_buf  = args[1] as *mut u8;
                let out_size = args[2] as usize;
                if !out_buf.is_null() && out_size > 0 {
                    let mut listing = alloc::string::String::new();
                    unsafe {
                        for slot in SRFS_CACHE.iter() {
                            if let Some((k, _)) = slot {
                                if k.ends_with(".ca") {
                                    listing.push_str(k);
                                    listing.push('\n');
                                }
                            }
                        }
                    }
                    let bytes = listing.as_bytes();
                    let n = bytes.len().min(out_size - 1);
                    if n > 0 {
                        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, n); }
                        unsafe { *out_buf.add(n) = 0; }
                    }
                    return n as i64;
                }
            }
            -1
        },

        // ── Listing "dossier" pour ShiLooker (onglet Disks) — filtre SRFS_CACHE par
        // préfixe de chemin plutôt que par suffixe .ca (voir DiskCacheDirCount/GetName).
        "DrvAPIInterCon___DiskCacheDirCount___" => {
            let prefix = if !args.is_empty() && args[0] != 0 { unsafe { read_cstr(args[0] as *const u8) } } else { alloc::string::String::new() };
            disk_cache_dir_rebuild(&prefix)
        },
        "DrvAPIInterCon___DiskCacheDirGetName___" => {
            let i = args.first().copied().unwrap_or(-1);
            if i < 0 { return 0; }
            disk_cache_dir_get_name(i as usize)
        },

        // Vérifier si un buffer contient une substring (pour IsBundle)
        // args[0]=buf_ptr  args[1]=needle_ptr → 1 si trouvé, 0 sinon
        "DrvAPIInterCon___CaContains___" => {
            if args.len() >= 2 {
                let buf_ptr    = args[0] as *const u8;
                let needle_ptr = args[1] as *const u8;
                if !buf_ptr.is_null() && !needle_ptr.is_null() {
                    let buf_str    = unsafe { read_cstr(buf_ptr) };
                    let needle_str = unsafe { read_cstr(needle_ptr) };
                    return if buf_str.contains(needle_str.as_str()) { 1 } else { 0 };
                }
            }
            0
        },

        // Lire un champ de premier niveau dans un JSON .ca
        // args[0]=json_buf_ptr  args[1]=field_ptr → pointeur vers valeur (alloc), ou null
        "DrvAPIInterCon___CaReadField___" => {
            if args.len() >= 2 {
                let json_ptr  = args[0] as *const u8;
                let field_ptr = args[1] as *const u8;
                if !json_ptr.is_null() && !field_ptr.is_null() {
                    let json_str  = unsafe { read_cstr(json_ptr) };
                    let field_str = unsafe { read_cstr(field_ptr) };
                    let needle = alloc::format!("\"{}\":", field_str);
                    if let Some(pos) = json_str.find(&needle) {
                        let rest = json_str[pos + needle.len()..].trim_start();
                        let value = if rest.starts_with('"') {
                            // Valeur string : extraire entre guillemets
                            let inner = &rest[1..];
                            let end = inner.find('"').unwrap_or(inner.len());
                            inner[..end].to_string()
                        } else {
                            // Valeur numérique/bool
                            let end = rest.find(|c: char| c == ',' || c == '}' || c == '\n')
                                .unwrap_or(rest.len());
                            rest[..end].trim().to_string()
                        };
                        if !value.is_empty() {
                            let mut bytes = value.into_bytes();
                            bytes.push(0);
                            let boxed = bytes.into_boxed_slice();
                            return alloc::boxed::Box::into_raw(boxed) as *mut u8 as i64;
                        }
                    }
                }
            }
            0
        },

        // Extraire un sous-objet nested dans un bundle JSON
        // args[0]=json_buf_ptr  args[1]=parent_key_ptr  args[2]=child_key_ptr
        // Ex : CaExtractSubObject(buf, "contracts", "VEZproxy") → JSON de VEZproxy
        "DrvAPIInterCon___CaExtractSubObject___" => {
            if args.len() >= 3 {
                let json_ptr   = args[0] as *const u8;
                let parent_ptr = args[1] as *const u8;
                let child_ptr  = args[2] as *const u8;
                if !json_ptr.is_null() && !parent_ptr.is_null() && !child_ptr.is_null() {
                    let json_str   = unsafe { read_cstr(json_ptr) };
                    let parent_str = unsafe { read_cstr(parent_ptr) };
                    let child_str  = unsafe { read_cstr(child_ptr) };
                    // Trouver "parent":{ puis "child":{ ... }
                    let parent_key = alloc::format!("\"{}\":", parent_str);
                    let child_key  = alloc::format!("\"{}\":", child_str);
                    if let Some(p_pos) = json_str.find(&parent_key) {
                        let after_parent = &json_str[p_pos + parent_key.len()..];
                        if let Some(c_pos) = after_parent.find(&child_key) {
                            let after_child = &after_parent[c_pos + child_key.len()..].trim_start();
                            // Extraire l'objet JSON { ... } avec comptage de braces
                            if after_child.starts_with('{') {
                                let mut depth = 0usize;
                                let mut end   = 0usize;
                                for (i, c) in after_child.char_indices() {
                                    if c == '{' { depth += 1; }
                                    if c == '}' {
                                        depth -= 1;
                                        if depth == 0 { end = i + 1; break; }
                                    }
                                }
                                if end > 0 {
                                    let sub = after_child[..end].to_string();
                                    let mut bytes = sub.into_bytes();
                                    bytes.push(0);
                                    let boxed = bytes.into_boxed_slice();
                                    return alloc::boxed::Box::into_raw(boxed) as *mut u8 as i64;
                                }
                            }
                        }
                    }
                }
            }
            0
        },

        // Mettre à jour un champ de premier niveau dans un fichier .ca SRFS
        // args[0]=path_ptr  args[1]=field_ptr  args[2]=value_ptr
        "DrvAPIInterCon___CaUpdateField___" => {
            if args.len() >= 3 {
                let path_ptr  = args[0] as *const u8;
                let field_ptr = args[1] as *const u8;
                let val_ptr   = args[2] as *const u8;
                if !path_ptr.is_null() && !field_ptr.is_null() && !val_ptr.is_null() {
                    let path_str  = unsafe { read_cstr(path_ptr) };
                    let field_str = unsafe { read_cstr(field_ptr) };
                    let val_str   = unsafe { read_cstr(val_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        if let Ok(mut json_str) = alloc::string::String::from_utf8(data) {
                            let needle = alloc::format!("\"{}\":", field_str);
                            if let Some(pos) = json_str.find(&needle) {
                                let val_start = pos + needle.len();
                                let rest = json_str[val_start..].trim_start().to_string();
                                let val_end = rest.find(|c: char| c == ',' || c == '}')
                                    .unwrap_or(rest.len());
                                let old_val = &rest[..val_end];
                                let new_val = alloc::format!("\"{}\"", val_str);
                                json_str = json_str.replacen(old_val, &new_val, 1);
                                srfs_write_chain_file(&path_str, json_str.as_bytes());
                                return 0;
                            }
                        }
                    }
                }
            }
            -1
        },

        // Mettre à jour un champ nested contracts.<contract>.<field> dans un bundle
        // args[0]=path  args[1]=parent("contracts")  args[2]=contract_name  args[3]=field  args[4]=value
        "DrvAPIInterCon___CaUpdateNestedField___" => {
            if args.len() >= 5 {
                let path_ptr     = args[0] as *const u8;
                let contract_ptr = args[2] as *const u8;
                let field_ptr    = args[3] as *const u8;
                let val_ptr      = args[4] as *const u8;
                if !path_ptr.is_null() && !contract_ptr.is_null() && !field_ptr.is_null() && !val_ptr.is_null() {
                    let path_str     = unsafe { read_cstr(path_ptr) };
                    let contract_str = unsafe { read_cstr(contract_ptr) };
                    let field_str    = unsafe { read_cstr(field_ptr) };
                    let val_str      = unsafe { read_cstr(val_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        if let Ok(mut json_str) = alloc::string::String::from_utf8(data) {
                            // Trouver "contractName":{ ... "field":"old" ... }
                            let contract_key = alloc::format!("\"{}\":", contract_str);
                            let field_key    = alloc::format!("\"{}\":", field_str);
                            if let Some(c_pos) = json_str.find(&contract_key) {
                                let sub = &json_str[c_pos..];
                                if let Some(f_pos) = sub.find(&field_key) {
                                    let abs_pos  = c_pos + f_pos + field_key.len();
                                    let rest     = json_str[abs_pos..].trim_start().to_string();
                                    let val_end  = rest.find(|c: char| c == ',' || c == '}')
                                        .unwrap_or(rest.len());
                                    let old_val  = &rest[..val_end];
                                    let new_val  = alloc::format!("\"{}\"", val_str);
                                    json_str     = json_str.replacen(old_val, &new_val, 1);
                                    srfs_write_chain_file(&path_str, json_str.as_bytes());
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
            -1
        },

        // Ajouter une entrée à l'index SRFS (SDC:\env\.index)
        // args[0]=index_path_ptr  args[1]=entry_ptr ("NOM=VALEUR\n")
        "DrvAPIInterCon___EnvAppendIndex___" => {
            if args.len() >= 2 {
                let path_ptr  = args[0] as *const u8;
                let entry_ptr = args[1] as *const u8;
                if !path_ptr.is_null() && !entry_ptr.is_null() {
                    let path_str  = unsafe { read_cstr(path_ptr) };
                    let entry_str = unsafe { read_cstr(entry_ptr) };
                    let existing  = srfs_read_chain_file(&path_str)
                        .and_then(|d| alloc::string::String::from_utf8(d).ok())
                        .unwrap_or_default();
                    let new_index = alloc::format!("{}{}", existing, entry_str);
                    srfs_write_chain_file(&path_str, new_index.as_bytes());
                }
            }
            0
        },

        // Parser les entrées NOM=VALEUR\n d'un buffer d'index et les injecter
        // args[0]=buf_ptr  args[1]=buf_size → nombre de vars parsées
        "DrvAPIInterCon___EnvParseIndex___" => {
            if args.len() >= 2 {
                let buf_ptr  = args[0] as *const u8;
                let buf_size = args[1] as usize;
                if !buf_ptr.is_null() && buf_size > 0 {
                    let data  = unsafe { core::slice::from_raw_parts(buf_ptr, buf_size) };
                    let text  = core::str::from_utf8(data).unwrap_or("");
                    let count = text.lines()
                        .filter(|line| line.contains('='))
                        .count();
                    return count as i64;
                }
            }
            0
        },

        // LLVM intrinsics (utilisés par GlyphRasterizer pour smax/smin)
        "llvm.smax.i32" => if args.len() >= 2 { args[0].max(args[1]) } else { 0 },
        "llvm.smin.i32" => if args.len() >= 2 { args[0].min(args[1]) } else { 0 },
        "llvm.umax.i32" => if args.len() >= 2 { (args[0] as u64).max(args[1] as u64) as i64 } else { 0 },
        "llvm.umin.i32" => if args.len() >= 2 { (args[0] as u64).min(args[1] as u64) as i64 } else { 0 },

        // self___onDriverInit → appelé depuis APrevent::OnPowerOn
        "self___onDriverInit" => 0,

        // ── SluraChain Bridge (SluChainBridge.mara) ──────────────────────────
        // Pont SRFS ↔ vuc-platform : sérialise txns/calls en JSON dans SRFS.
        // vuc-platform (engine_platform.rs) les consomme en mode deferred.

        // Générer un ID unique pour une transaction/call (monotone, basé sur compteur)
        "DrvAPIInterCon___BlockchainGenTxId___" => {
            unsafe {
                static mut CHAIN_TX_COUNTER: u32 = 0;
                CHAIN_TX_COUNTER = CHAIN_TX_COUNTER.wrapping_add(1);
                CHAIN_TX_COUNTER as i64
            }
        },

        // Enqueue une transaction dans SRFS : SDC:\chain\pending_txs\<id>.json
        // args[0]=path_ptr args[1]=from_ptr args[2]=to_ptr args[3]=data_ptr args[4]=value args[5]=txId
        "DrvAPIInterCon___BlockchainQueueTx___" => {
            if args.len() >= 6 {
                let path_ptr = args[0] as *const u8;
                let to_ptr   = args[2] as *const u8;
                let data_ptr = args[3] as *const u8;
                let value    = args[4] as u64;
                let tx_id    = args[5] as u32;
                if !path_ptr.is_null() && !to_ptr.is_null() {
                    // Sérialiser en JSON minimaliste et écrire dans SRFS via srfs_write_chain_file
                    let to_str   = unsafe { read_cstr(to_ptr) };
                    let data_str = if data_ptr.is_null() { "0x".to_string() }
                                   else { unsafe { read_cstr(data_ptr) } };
                    let path_str = unsafe { read_cstr(path_ptr) };
                    let json = alloc::format!(
                        "{{\"type\":\"tx\",\"id\":{},\"to\":\"{}\",\"data\":\"{}\",\"value\":{}}}",
                        tx_id, to_str, data_str, value
                    );
                    srfs_write_chain_file(&path_str, json.as_bytes());

                    // ── PROD : exécution SYNCHRONE de la tx contre l'ABI .ca ──────────
                    // Charge le bundle .ca depuis l'ESP (UEFI_ST_PTR dispo pendant le bureau),
                    // résout le sélecteur (4 octets de calldata) → méthode, et écrit le reçu
                    // dans SRFS_CACHE au chemin que GetTxStatus/BlockchainReadMeta liront.
                    if let Some(ca) = unsafe { srfs_uefi_read(UEFI_ST_PTR, "SDC/slu64/assets/crypto/vezcurproxy.ca") } {
                        let receipt = crate::chain_ca::execute_tx(&ca, &to_str, &data_str, tx_id);
                        let rpath = alloc::format!("SDC:\\chain\\receipts\\{}.json", tx_id);
                        srfs_write_chain_file(&rpath, receipt.as_bytes());
                        serial_log(alloc::format!("[CHAIN] tx #{} executee via .ca -> recu ecrit\r\n", tx_id).as_bytes());
                    } else {
                        serial_log(b"[CHAIN] .ca introuvable, tx non executee\r\n");
                    }
                }
            }
            0
        },

        // Enqueue un eth_call en lecture seule : SDC:\chain\calls\<id>.req.json
        // args[0]=reqPath args[1]=contract args[2]=selector args[3]=args_data args[4]=callId
        "DrvAPIInterCon___BlockchainQueueCall___" => {
            if args.len() >= 5 {
                let path_ptr     = args[0] as *const u8;
                let contract_ptr = args[1] as *const u8;
                let sel_ptr      = args[2] as *const u8;
                let args_ptr     = args[3] as *const u8;
                let call_id      = args[4] as u32;
                if !path_ptr.is_null() && !contract_ptr.is_null() {
                    let path_str     = unsafe { read_cstr(path_ptr) };
                    let contract_str = unsafe { read_cstr(contract_ptr) };
                    let sel_str      = if sel_ptr.is_null()  { "0x".to_string() } else { unsafe { read_cstr(sel_ptr) } };
                    let args_str     = if args_ptr.is_null() { "0x".to_string() } else { unsafe { read_cstr(args_ptr) } };
                    let json = alloc::format!(
                        "{{\"type\":\"call\",\"id\":{},\"to\":\"{}\",\"selector\":\"{}\",\"args\":\"{}\"}}",
                        call_id, contract_str, sel_str, args_str
                    );
                    srfs_write_chain_file(&path_str, json.as_bytes());
                }
            }
            0
        },

        // Polling sur la réponse d'un call : SDC:\chain\calls\<id>.resp.json
        // args[0]=respPath args[1]=outBuf args[2]=outSize args[3]=timeout_ms
        // Retourne le nombre d'octets lus dans outBuf, ou -1 si timeout
        "DrvAPIInterCon___BlockchainPollResp___" => {
            if args.len() >= 4 {
                let path_ptr = args[0] as *const u8;
                let out_buf  = args[1] as *mut u8;
                let out_size = args[2] as usize;
                if !path_ptr.is_null() && !out_buf.is_null() && out_size > 0 {
                    let path_str = unsafe { read_cstr(path_ptr) };
                    // Lire depuis SRFS cache (mis à jour par vuc-platform)
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        let n = data.len().min(out_size);
                        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, n); }
                        return n as i64;
                    }
                }
            }
            -1
        },

        // Enqueue un déploiement de contrat : SDC:\chain\pending_txs\<id>.deploy.json
        // args[0]=queuePath args[1]=bytecodePath args[2]=ctorArgs args[3]=from args[4]=txId
        "DrvAPIInterCon___BlockchainQueueDeploy___" => {
            if args.len() >= 5 {
                let path_ptr     = args[0] as *const u8;
                let bc_path_ptr  = args[1] as *const u8;
                let ctor_ptr     = args[2] as *const u8;
                let from_ptr     = args[3] as *const u8;
                let tx_id        = args[4] as u32;
                if !path_ptr.is_null() && !bc_path_ptr.is_null() {
                    let path_str    = unsafe { read_cstr(path_ptr) };
                    let bc_path_str = unsafe { read_cstr(bc_path_ptr) };
                    let ctor_str    = if ctor_ptr.is_null()  { "0x".to_string() } else { unsafe { read_cstr(ctor_ptr) } };
                    let from_str    = if from_ptr.is_null()  { "0x0000000000000000000000000000000000000000".to_string() } else { unsafe { read_cstr(from_ptr) } };
                    let json = alloc::format!(
                        "{{\"type\":\"deploy\",\"id\":{},\"bytecodePath\":\"{}\",\"ctorArgs\":\"{}\",\"from\":\"{}\"}}",
                        tx_id, bc_path_str, ctor_str, from_str
                    );
                    srfs_write_chain_file(&path_str, json.as_bytes());
                }
            }
            0
        },

        // Lire la balance depuis SRFS : SDC:\chain\state\balances\<addr>.json
        // args[0]=statePath_ptr → retourne la balance (i32 simplifié) ou -1
        "DrvAPIInterCon___BlockchainReadBalance___" => {
            if args.len() >= 1 {
                let path_ptr = args[0] as *const u8;
                if !path_ptr.is_null() {
                    let path_str = unsafe { read_cstr(path_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        // Parse JSON minimaliste {"balance":12345}
                        if let Ok(s) = core::str::from_utf8(&data) {
                            if let Some(pos) = s.find("\"balance\":") {
                                let rest = &s[pos + 10..];
                                let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                                if let Ok(v) = rest[..end].parse::<i64>() {
                                    return v;
                                }
                            }
                        }
                    }
                }
            }
            -1
        },

        // Lire un champ JSON depuis un fichier SRFS de métadonnées
        // args[0]=path_ptr args[1]=field_ptr → valeur du champ (i32) ou -1
        "DrvAPIInterCon___BlockchainReadMeta___" => {
            if args.len() >= 2 {
                let path_ptr  = args[0] as *const u8;
                let field_ptr = args[1] as *const u8;
                if !path_ptr.is_null() && !field_ptr.is_null() {
                    let path_str  = unsafe { read_cstr(path_ptr) };
                    let field_str = unsafe { read_cstr(field_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        if let Ok(s) = core::str::from_utf8(&data) {
                            let needle = alloc::format!("\"{}\":", field_str);
                            if let Some(pos) = s.find(&needle) {
                                let rest = &s[pos + needle.len()..].trim_start();
                                let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                                if let Ok(v) = rest[..end].parse::<i64>() {
                                    return v;
                                }
                            }
                        }
                    }
                }
            }
            -1
        },

        _ => 0,
    }
}

// ── Helpers internes pour le bridge blockchain ────────────────────────────────

/// Lit une chaîne C nulle-terminée depuis un pointeur brut.
unsafe fn read_cstr(ptr: *const u8) -> alloc::string::String {
    let mut len = 0usize;
    while *ptr.add(len) != 0 && len < 512 { len += 1; }
    core::str::from_utf8(core::slice::from_raw_parts(ptr, len))
        .unwrap_or("")
        .to_string()
}

/// Écrit un fichier JSON dans la queue blockchain SRFS.
/// Cherche d'abord dans SRFS_CACHE un slot libre ; sinon enregistre directement.
fn srfs_write_chain_file(path: &str, data: &[u8]) {
    unsafe {
        for slot in SRFS_CACHE.iter_mut() {
            if slot.is_none() {
                *slot = Some((path.to_string(), data.to_vec()));
                return;
            }
        }
        // Cache plein : écraser le premier slot chain (pas de font/marep)
        for slot in SRFS_CACHE.iter_mut() {
            if let Some((ref k, _)) = slot {
                if k.contains("chain") {
                    *slot = Some((path.to_string(), data.to_vec()));
                    return;
                }
            }
        }
    }
    serial_log(b"[CHAIN] cache plein, tx perdue\r\n");
}

/// Lit un fichier de réponse blockchain depuis SRFS_CACHE.
fn srfs_read_chain_file(path: &str) -> Option<alloc::vec::Vec<u8>> {
    unsafe {
        for slot in SRFS_CACHE.iter() {
            if let Some((ref k, ref data)) = slot {
                if k == path {
                    return Some(data.clone());
                }
            }
        }
    }
    None
}

/// Auto-test du chemin d'exécution `.ca` (diagnostic boot). Simule ce qu'un marep fait via
/// SluChainBridge : charge le bundle `.ca`, exécute une tx `transfer` de démonstration,
/// écrit le reçu dans SRFS_CACHE, puis le relit par le MÊME chemin que `GetTxStatus` →
/// prouve le round-trip prod (tx → résolution ABI → reçu → status lisible par le marep).
pub fn chain_selftest() {
    let demo_data = "0xa9059cbb0000000000000000000000005aaeef00000000000000000000000000000064";
    let to = "0x53Ae54b11251D5003e9aA51422405bC35A2eF32D";
    let id: u32 = 9001;
    match unsafe { srfs_uefi_read(UEFI_ST_PTR, "SDC/slu64/assets/crypto/vezcurproxy.ca") } {
        Some(ca) => {
            let receipt = crate::chain_ca::execute_tx(&ca, to, demo_data, id);
            let rpath = alloc::format!("SDC:\\chain\\receipts\\{}.json", id);
            srfs_write_chain_file(&rpath, receipt.as_bytes());
            serial_log(alloc::format!("[CHAIN-TEST] recu: {}\r\n", receipt).as_bytes());
            if srfs_read_chain_file(&rpath).is_some() {
                serial_log(b"[CHAIN-TEST] relecture SRFS OK -> status lisible par le marep\r\n");
            }

            // ── Stablecoin VEZ en TEST : seed le solde balanceOf du gestionnaire ──
            // Le .ca déclare balanceOf (0x70a08231) ; on alloue un solde de démonstration
            // à l'adresse `owner` pour que BlockchainReadBalance/GetBalance le renvoie.
            if crate::chain_ca::has_balance_of(&ca) {
                if let Some(owner) = crate::chain_ca::owner_addr(&ca) {
                    let sym = crate::chain_ca::token_symbol(&ca);
                    let bal = crate::chain_ca::TEST_VEZ_BALANCE;
                    let bpath = alloc::format!("SDC:\\chain\\state\\balances\\{}.json", owner);
                    let bjson = alloc::format!("{{\"balance\":{},\"symbol\":\"{}\",\"test\":true}}", bal, sym);
                    srfs_write_chain_file(&bpath, bjson.as_bytes());
                    serial_log(alloc::format!("[CHAIN-TEST] stablecoin {} (test) solde balanceOf owner {} = {}\r\n", sym, owner, bal).as_bytes());
                }
            }
        }
        None => serial_log(b"[CHAIN-TEST] .ca introuvable\r\n"),
    }
}

// ── Bridge C-ABI pour vuc-platform (uefi-kernel feature) ─────────────────────
//
// vuc-platform appelle slura_mgc_register_executor() au démarrage.
// Ici on expose exec_module sous l'ABI C attendue.
//
// Signature : fn(bytecode: *const u8, len: usize, entry: *const u8) -> i32
// Enregistrement : kernel_runtime::platform_init() appelle
//   slura_mgc_register_executor(exec_module_raw)

/// Point d'entrée C-ABI de l'exécuteur OVC — enregistré dans vuc_platform.
///
/// `bytecode` : octets OVC (# Vyft OVC v1.0...)
/// `len`      : longueur du bytecode
/// `entry`    : nom de la fonction d'entrée null-terminated ("OEntry\0")
#[no_mangle]
pub unsafe extern "C" fn exec_module_raw(
    bytecode: *const u8,
    len:      usize,
    entry:    *const u8,
) -> i32 {
    if bytecode.is_null() || len == 0 { return -1; }
    let ovc = core::slice::from_raw_parts(bytecode, len);
    // Extraire le nom de la fonction
    let fn_name = if entry.is_null() {
        "OEntry"
    } else {
        let mut n = 0usize;
        while *entry.add(n) != 0 { n += 1; }
        core::str::from_utf8(core::slice::from_raw_parts(entry, n))
            .unwrap_or("OEntry")
    };
    // Contexte nul — l'appelant doit avoir initialisé via slura_mgc_set_ctx
    let ctx = ExecCtx { fb: core::ptr::null_mut(), width: 0, height: 0, stride: 0,
                        font: core::ptr::null(), font_len: 0,
                        pointer_x: 0, pointer_y: 0, pointer_btn: 0, key_code: 0 };
    exec_module(ovc, &[(fn_name, &[])], &ctx) as i32
}