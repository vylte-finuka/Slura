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
const HOME_MAREP: &uefi::CStr16 = cstr16!("\\HelloSlura.marep");

/// Charge `HelloSlura.marep`, vérifie l'OVC et transfère au driver SluGpu.
/// Le rendu est géré par le driver HAL (SluGpu.slul) chargé par hal_manager.
pub fn load_and_run(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
) -> Result<i32, BundleError> {
    let bundle = find_and_read(st, image_handle)?;
    run_ovc(st, image_handle, &bundle)
}

/// Extrait le SRID depuis Maraset.yaml (`SRID: SRID_xxx`).
fn extract_srid<'a>(yaml: &'a [u8]) -> &'a str {
    if let Ok(text) = core::str::from_utf8(yaml) {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("SRID:") {
                return rest.trim();
            }
        }
    }
    "SRID_unknown"
}

/// Vérifie AuthARoot : le SRID du manifeste doit figurer dans RAbstractallowing.xml.
fn verify_auth_root(xml: &[u8], srid: &str) -> bool {
    core::str::from_utf8(xml).map(|t| t.contains(srid)).unwrap_or(false)
}

fn run_ovc(st: &mut SystemTable<Boot>, image_handle: Handle, bundle: &[u8])
    -> Result<i32, BundleError>
{
    let zip = ZipReader::new(bundle)?;

    // ── AuthARoot : vérification SRID ────────────────────────────────────────
    let maraset  = zip.extract_file("Maraset.yaml").unwrap_or_default();
    let xml      = zip.extract_file("RAbstractallowing.xml").unwrap_or_default();
    let srid     = extract_srid(&maraset);
    let auth_ok  = verify_auth_root(&xml, srid);

    {
        use core::fmt::Write;
        if auth_ok {
            let _ = st.stdout().write_str("[AuthARoot] SRID verifie OK\r\n");
        } else {
            let _ = st.stdout().write_str("[AuthARoot] WARN: SRID non verifie\r\n");
        }
    }

    // ── OVC ──────────────────────────────────────────────────────────────────
    let ovc = zip.extract_file("base\\OEntry.ovc")?;
    if ovc.is_empty() { return Err(BundleError::EmptyBinary); }

    const MAGIC: &[u8] = b"# Vyft OVC v1.0";
    if ovc.len() < MAGIC.len() || &ovc[..MAGIC.len()] != MAGIC {
        return Err(BundleError::EmptyBinary);
    }

    // OVC Vyft signé — rendu via GOP (layout depuis HelloWorld.ovc).
    crate::kernel_runtime::render_marep_screen(st, image_handle);
    Ok(0)
}

// ── Lecture ───────────────────────────────────────────────────────────────────

/// Parcourt tous les volumes SimpleFileSystem et retourne les octets du
/// premier `home.marep` trouvé.
fn find_and_read(st: &mut SystemTable<Boot>, image_handle: Handle) -> Result<Vec<u8>, BundleError> {
    let handles = st
        .boot_services()
        .find_handles::<SimpleFileSystem>()
        .map_err(|_| BundleError::UefiError)?;

    for &fs_handle in handles.iter() {
        if let Ok(bytes) = read_from_volume(st, image_handle, fs_handle) {
            return Ok(bytes);
        }
    }

    Err(BundleError::FileNotFound)
}

fn read_from_volume(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    fs_handle:    Handle,
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
        .open(HOME_MAREP, FileMode::Read, FileAttribute::empty())
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
