//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — .slul driver loader ___
//
//! Charge les bundles drivers Maratine (`.slul`) depuis l'ESP et les
//! démarre via les protocoles UEFI `LoadImage` / `StartImage`.
//!
//! ## Cycle de vie d'un driver .slul
//! ```text
//! 1. Lire le fichier .slul  (SimpleFileSystem)
//! 2. Extraire native.efi    (ZipReader)
//! 3. UEFI LoadImage         → obtient un child Handle
//! 4. UEFI StartImage        → appelle OEntry du driver
//!    └─ OEntry enregistre ses protocoles UEFI puis retourne
//! ```
//!
//! ## Bundles tentés au démarrage
//! Le loader essaie, sur chaque volume SimpleFileSystem disponible,
//! la liste statique `DRIVER_BUNDLES`.  Les bundles absents sont
//! silencieusement ignorés.

extern crate alloc;
use alloc::vec::Vec;

use uefi::{
    cstr16, Handle,
    proto::media::{
        file::{File, FileAttribute, FileMode, FileType},
        fs::SimpleFileSystem,
    },
    table::{boot::LoadImageSource, Boot, SystemTable},
};

use super::{zip_reader::ZipReader, BundleError};

/// Chemins des bundles drivers à tenter, relatifs à la racine de chaque volume.
/// Ordre de chargement intentionnel : GPU d'abord (framebuffer), puis clavier/pointeur.
const DRIVER_BUNDLES: &[&uefi::CStr16] = &[
    cstr16!("EFI\\SLURA\\DRIVERS\\SluGpu.slul"),
    cstr16!("EFI\\SLURA\\DRIVERS\\SluKeyMouse.slul"),
];

/// Tente de charger tous les bundles `.slul` connus sur tous les volumes.
/// Retourne le nombre de drivers démarrés avec succès.
pub fn load_drivers(st: &mut SystemTable<Boot>, image_handle: Handle) -> usize {
    let mut started = 0usize;

    let handles = match st.boot_services().find_handles::<SimpleFileSystem>() {
        Ok(h) => h,
        Err(_) => return 0,
    };

    for &fs_handle in handles.iter() {
        for &bundle_path in DRIVER_BUNDLES {
            match try_load_one(st, image_handle, fs_handle, bundle_path) {
                Ok(()) => started += 1,
                Err(_) => {}
            }
        }
    }

    started
}

/// Tente de lire, extraire et démarrer un seul bundle `.slul`.
fn try_load_one(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    fs_handle:    Handle,
    path:         &uefi::CStr16,
) -> Result<(), BundleError> {
    let bytes = read_bundle(st, fs_handle, path)?;
    start_slul(st, image_handle, &bytes)
}

/// Lit l'intégralité d'un fichier bundle depuis un volume SimpleFileSystem.
fn read_bundle(
    st:        &mut SystemTable<Boot>,
    fs_handle: Handle,
    path:      &uefi::CStr16,
) -> Result<Vec<u8>, BundleError> {
    let mut fs = st
        .boot_services()
        .open_protocol_exclusive::<SimpleFileSystem>(fs_handle)
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

/// Extrait `native.efi` du ZIP et le passe à UEFI pour chargement.
fn start_slul(
    st:     &mut SystemTable<Boot>,
    parent: Handle,
    bundle: &[u8],
) -> Result<(), BundleError> {
    let zip        = ZipReader::new(bundle)?;
    let driver_efi = zip.extract_file("native.efi")?;

    if driver_efi.is_empty() {
        return Err(BundleError::EmptyBinary);
    }

    // Charge le PE32+ en mémoire ; UEFI valide l'en-tête et alloue les pages.
    let child = st
        .boot_services()
        .load_image(
            parent,
            LoadImageSource::FromBuffer { buffer: driver_efi, file_path: None },
        )
        .map_err(|_| BundleError::UefiError)?;

    // Lance le driver : appelle son entry-point, qui enregistre ses protocoles
    // UEFI puis retourne EFI_SUCCESS (ou une erreur).
    st.boot_services()
        .start_image(child)
        .map(|_| ())
        .map_err(|_| BundleError::UefiError)
}

/// Lit tout le contenu d'un `RegularFile` dans un `Vec<u8>`.
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
