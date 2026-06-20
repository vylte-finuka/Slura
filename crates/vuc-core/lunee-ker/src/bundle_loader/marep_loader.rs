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
        boot::{AllocateType, MemoryType},
        Boot, SystemTable,
    },
};

use super::{zip_reader::ZipReader, BundleError, FnOEntry};

/// Chemin de l'application de démarrage sur l'ESP.
const HOME_MAREP: &uefi::CStr16 = cstr16!("EFI\\SLURA\\HOME\\HelloSlura.marep");

/// Charge `home.marep`, mappe le code en mémoire exécutable et appelle
/// `OEntry`.  Cette fonction ne retourne que si `OEntry` retourne (anormal).
pub fn load_and_run(
    st:           &mut SystemTable<Boot>,
    _image_handle: Handle,
) -> Result<i32, BundleError> {
    let bundle = find_and_read(st)?;
    let entry  = map_executable(st, &bundle)?;

    // SAFETY: `entry` pointe sur un binaire PIC Maratine valide copié dans
    // des pages LOADER_CODE.  OEntry est à l'offset 0 avec C-ABI.
    let exit_code = unsafe { entry() };
    Ok(exit_code)
}

// ── Lecture ───────────────────────────────────────────────────────────────────

/// Parcourt tous les volumes SimpleFileSystem et retourne les octets du
/// premier `home.marep` trouvé.
fn find_and_read(st: &mut SystemTable<Boot>) -> Result<Vec<u8>, BundleError> {
    let handles = st
        .boot_services()
        .find_handles::<SimpleFileSystem>()
        .map_err(|_| BundleError::UefiError)?;

    for &fs_handle in handles.iter() {
        if let Ok(bytes) = read_from_volume(st, fs_handle) {
            return Ok(bytes);
        }
    }

    Err(BundleError::FileNotFound)
}

fn read_from_volume(
    st:        &mut SystemTable<Boot>,
    fs_handle: Handle,
) -> Result<Vec<u8>, BundleError> {
    let mut fs = st
        .boot_services()
        .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)
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
    st:     &mut SystemTable<Boot>,
    bundle: &[u8],
) -> Result<FnOEntry, BundleError> {
    let zip  = ZipReader::new(bundle)?;
    let code = zip.extract_file("native.bin")?;

    if code.is_empty() {
        return Err(BundleError::EmptyBinary);
    }

    // Nombre de pages 4 Kio nécessaires.
    let pages = (code.len() + 0xFFF) >> 12;

    let phys_addr = st
        .boot_services()
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_CODE, pages)
        .map_err(|_| BundleError::AllocationFailed)?;

    // Copie du binaire dans les pages allouées.
    // SAFETY: `phys_addr` est une adresse physique valide, alignée 4 Kio,
    // de taille `pages * 4096` octets, fournie par UEFI Boot Services.
    unsafe {
        core::ptr::copy_nonoverlapping(
            code.as_ptr(),
            phys_addr as *mut u8,
            code.len(),
        );
    }

    // Barrière compilateur : garantit que la copie précède le cast en FnOEntry.
    compiler_fence(Ordering::SeqCst);

    // SAFETY: OEntry est à l'offset 0 du binaire PIC avec signature C-ABI.
    let entry_fn: FnOEntry = unsafe {
        core::mem::transmute::<*const u8, FnOEntry>(phys_addr as *const u8)
    };

    Ok(entry_fn)
}
