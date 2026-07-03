//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — .slul driver loader ___

extern crate alloc;
use alloc::{borrow::ToOwned as _, vec::Vec};

use uefi::{
    cstr16, Handle,
    proto::media::{
        file::{File, FileAttribute, FileMode, FileType},
        fs::SimpleFileSystem,
    },
    table::{
        boot::{LoadImageSource, OpenProtocolAttributes, OpenProtocolParams},
        Boot, SystemTable,
    },
};

use super::{zip_reader::ZipReader, BundleError};

// Chemins absolus (leading \) — nécessaire pour les sous-dossiers sur QEMU FAT.
// Ordre de chargement intentionnel :
//   1. SluGpu       — framebuffer GOP disponible en premier
//   2. SluKeyMouse  — entrées clavier + pointeur
//   3. SRFSMan      — système de fichiers SDC:\ (avant SluFontConf qui en dépend)
//   4. SluFontConf  — rendu TTF/WOFF via DrvManSpec***FS***
//   5. SluEnvSys    — variables d'environnement système (timezone, locale, etc.)
//   6. CryptoAssetSupport — wallet, crypto, VezCur proxy
const DRIVER_BUNDLES: &[&uefi::CStr16] = &[
    cstr16!("\\sources\\SluGpu.slul"),
    cstr16!("\\sources\\SluKeyMouse.slul"),
    cstr16!("\\sources\\SRFSMan.slul"),
    cstr16!("\\sources\\SluFontConf.slul"),
    cstr16!("\\sources\\SluEnvSys.slul"),
    cstr16!("\\sources\\CryptoAssetSupport.slul"),
];

// Aucun chemin SRFS hardcodé ici.
// Les fichiers SRFS sont déclarés dans les marep (ex: HelloWorld.mara)
// et chargés dynamiquement par marep_loader via srfs_preload_from_ovc().

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

/// Pré-charge un fichier SRFS (ex: "SDC:\boot\assets\font\...") depuis l'ESP.
/// Appelé par marep_loader quand il détecte un chemin SDC:\ dans un OVC.
pub fn srfs_preload_file(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    srfs_path:    &'static str,
) {
    // Convertir "SDC:\path\to\file" → "\path\to\file" (UEFI path)
    let relative = if srfs_path.starts_with("SDC:\\") || srfs_path.starts_with("SDC:/") {
        &srfs_path[5..]
    } else { return; };

    // Construire le chemin UEFI en remplaçant \ par / puis en utilisant la version UCS-2
    // Via un buffer statique pré-alloué pour les chemins courants
    let handles = match st.boot_services().find_handles::<SimpleFileSystem>() {
        Ok(h) => h,
        Err(_) => return,
    };

    // Allouer un buffer UCS-2 pour le chemin UEFI
    let mut ucs2_buf = alloc::vec![0u16; relative.len() + 2];
    ucs2_buf[0] = b'\\' as u16;
    let mut i = 1usize;
    for b in relative.bytes() {
        ucs2_buf[i] = if b == b'\\' { b'\\' as u16 } else { b as u16 };
        i += 1;
    }
    ucs2_buf[i] = 0;

    let uefi_path = match uefi::CStr16::from_u16_with_nul(&ucs2_buf) {
        Ok(p) => p,
        Err(_) => return,
    };

    for &fs_handle in handles.iter() {
        if let Some(data) = read_file(st, image_handle, fs_handle, uefi_path) {
            crate::ovc_exec::srfs_register_file(srfs_path.to_owned(), data);
            return;
        }
    }
}

/// Lit un fichier depuis l'ESP et retourne ses octets.
fn read_file(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    fs_handle:    Handle,
    path:         &uefi::CStr16,
) -> Option<Vec<u8>> {
    let mut fs = unsafe {
        st.boot_services().open_protocol::<SimpleFileSystem>(
            OpenProtocolParams { handle: fs_handle, agent: image_handle, controller: None },
            OpenProtocolAttributes::GetProtocol,
        ).ok()?
    };
    let mut root = fs.open_volume().ok()?;
    let fh = root.open(path, FileMode::Read, FileAttribute::empty()).ok()?;
    let mut reg = match fh.into_type().ok()? {
        FileType::Regular(r) => r,
        _ => return None,
    };
    let mut info_buf = [0u8; 256];
    let info: &uefi::proto::media::file::FileInfo = reg.get_info(&mut info_buf).ok()?;
    let size = info.file_size() as usize;
    if size == 0 { return None; }
    let mut buf = alloc::vec![0u8; size];
    reg.read(&mut buf).ok()?;
    Some(buf)
}

fn try_load_one(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    fs_handle:    Handle,
    path:         &uefi::CStr16,
) -> Result<(), BundleError> {
    let bytes = read_bundle(st, image_handle, fs_handle, path)?;
    start_slul(st, image_handle, &bytes)?;
    Ok(())
}

fn read_bundle(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    fs_handle:    Handle,
    path:         &uefi::CStr16,
) -> Result<Vec<u8>, BundleError> {
    // GET_PROTOCOL : accès non-exclusif — évite l'échec si OVMF tient déjà le protocole.
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

/// Extrait le SRID depuis Maraset.yaml.
fn slul_srid(yaml: &[u8]) -> &str {
    if let Ok(text) = core::str::from_utf8(yaml) {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("SRID:") {
                return rest.trim();
            }
        }
    }
    "SRID_unknown"
}

/// Détecte si le bundle est SluGpu (contient GpuImpl.ovc).
fn is_slu_gpu(zip: &ZipReader) -> bool {
    !zip.extract_file("base/GpuImpl.ovc").unwrap_or_default().is_empty()
}

fn start_slul(
    st:     &mut SystemTable<Boot>,
    _parent: Handle,
    bundle: &[u8],
) -> Result<(), BundleError> {
    use core::fmt::Write;
    use crate::ovc_exec;

    let zip = ZipReader::new(bundle)?;

    // ── AuthARoot : vérification SRID ────────────────────────────────────────
    let maraset  = zip.extract_file("Maraset.yaml").unwrap_or_default();
    let xml      = zip.extract_file("RAbstractallowing.xml").unwrap_or_default();
    let srid     = slul_srid(&maraset);
    let auth_ok  = core::str::from_utf8(&xml).map(|t| t.contains(srid)).unwrap_or(false);

    if auth_ok {
        let _ = write!(st.stdout(), "[AuthARoot] Driver {} OK\r\n", srid);
    } else {
        let _ = write!(st.stdout(), "[AuthARoot] Driver {} WARN\r\n", srid);
    }

    // ── OVC OEntry : validation magic ─────────────────────────────────────────
    let ovc = zip.extract_file("base/OEntry.ovc")?;
    if ovc.is_empty() { return Err(BundleError::EmptyBinary); }
    const MAGIC: &[u8] = b"# Vyft OVC v1.0";
    if ovc.len() < MAGIC.len() || &ovc[..MAGIC.len()] != MAGIC {
        return Err(BundleError::EmptyBinary);
    }

    // ── APrevent.ovc : exécuter OnPowerOn(arch) via ovc_exec ─────────────────
    let aprevent = zip.extract_file("base/APrevent.ovc").unwrap_or_default();
    if !aprevent.is_empty() {
        // Contexte nul pour OnPowerOn (pas de GOP encore)
        let null_ctx = ovc_exec::ExecCtx {
            fb: core::ptr::null_mut(),
            width: 0, height: 0, stride: 0,
            font: core::ptr::null(), font_len: 0,
        };
        // arch = "x86_64" en pointeur de chaîne statique
        let arch_str = b"x86_64\0";
        let arch_ptr = arch_str.as_ptr() as i64;
        let _ = ovc_exec::exec_fn(&aprevent, "OnPowerOn", &[arch_ptr], &null_ctx);
        let _ = write!(st.stdout(), "[APrevent] OnPowerOn OK\r\n");
    }

    // ── SluGpu : stocker GpuImpl.ovc pour le rendu ───────────────────────────
    if is_slu_gpu(&zip) {
        let gpu_impl = zip.extract_file("base/GpuImpl.ovc").unwrap_or_default();
        crate::ovc_exec::register_gpu_ovc(gpu_impl);
        let _ = write!(st.stdout(), "[SluGpu] GpuImpl.ovc enregistre\r\n");
    }

    // ── SluFontConf : stocker TtfParser + GlyphRasterizer pour rendu TTF ────
    {
        let ttf  = zip.extract_file("base/TtfParser.ovc").unwrap_or_default();
        let rast = zip.extract_file("base/GlyphRasterizer.ovc").unwrap_or_default();
        let woff = zip.extract_file("base/WoffReader.ovc").unwrap_or_default();
        if !ttf.is_empty() && !rast.is_empty() {
            crate::ovc_exec::register_font_ovc(ttf, rast, woff);
            let _ = write!(st.stdout(), "[SluFontConf] TtfParser+GlyphRasterizer+WoffReader enregistres\r\n");
        }
    }

    Ok(())
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
    if buf.is_empty() { return Err(BundleError::EmptyBinary); }
    Ok(buf)
}
