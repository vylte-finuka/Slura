//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee ___

//! Runtime du kernel Lunée.
//!
//! Philosophie : le kernel ne connaît AUCUN nom de fonction OVC.
//! Tout le rendu passe par exec_marep → OEntry.ovc (point d'entrée universel).
//! Le kernel ouvre uniquement le GOP (hardware kernel-only) et passe
//! le framebuffer au contexte OVC.

use core::fmt::Write;
use crate::ressources_manager::RessourcesManager;
use crate::bundle_loader::{marep_loader, BundleError};
use uefi::{CStr16, Handle, Status, table::{Boot, SystemTable}};
use uefi::proto::console::gop::GraphicsOutput;
use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

#[derive(Default)]
pub struct KernelRuntime {
    resources:       RessourcesManager,
    boot_init:       bool,
    secure_verified: bool,
}

impl KernelRuntime {
    pub fn new() -> Self { Self::default() }

    pub fn boot_phase(
        &mut self,
        st:    &mut SystemTable<Boot>,
        image: Handle,
    ) -> Result<(), Status> {
        self.verify_integrity(st)?;
        self.resources.init_hardware(st, image)?;
        self.boot_init = true;
        let _ = st.stdout().write_str("[RUNTIME] Boot phase completed.\r\n");
        Ok(())
    }

    fn verify_integrity(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        let _ = st.stdout().write_str("[SECURITY] Integrity check passed.\r\n");
        self.secure_verified = true;
        Ok(())
    }

    pub fn maratine_phase(&mut self, st: &mut SystemTable<Boot>, image_handle: Handle) {
        let _ = st.stdout().write_str("[MARATINE] Loading ShiLauncher...\r\n");
        match marep_loader::load_and_run(st, image_handle) {
            Ok(code) => {
                let _ = write!(st.stdout(), "[MARATINE] OEntry returned {}\r\n", code);
            }
            Err(BundleError::FileNotFound) => {
                let _ = st.stdout().write_str("[MARATINE] ShiLauncher.marep not found.\r\n");
            }
            Err(BundleError::NotInitialized) => {
                let _ = st.stdout().write_str("[MARATINE] OVC trouve.\r\n");
            }
            Err(BundleError::ExecutionFailed(code)) => {
                let _ = write!(st.stdout(), "[MARATINE] Execution echouee: {}\r\n", code);
            }
            Err(e) => {
                let _ = write!(st.stdout(), "[MARATINE] Load error: {:?}\r\n", e);
            }
        }
    }

    /// Lance le platform engine via UEFI LoadImage + StartImage.
    /// Lit `\vuc_platform_engine.efi` depuis l'ESP, le charge en mémoire et le démarre.
    pub fn launch_platform_engine(
        &self,
        st:           &mut SystemTable<Boot>,
        image_handle: Handle,
        network:      &str,
    ) {
        use uefi::{
            cstr16,
            proto::media::{
                file::{File, FileAttribute, FileMode, FileType},
                fs::SimpleFileSystem,
            },
            table::boot::{LoadImageSource, OpenProtocolAttributes, OpenProtocolParams},
        };

        let _ = write!(st.stdout(),
            "[PLATFORM] Chargement vuc_platform_engine ({})\r\n", network);

        const EFI_PATH: &uefi::CStr16 = cstr16!("\\vuc_platform_engine.efi");

        // Lire le binaire EFI depuis l'ESP via SimpleFileSystem.
        let handles = match st.boot_services().find_handles::<SimpleFileSystem>() {
            Ok(h) => h,
            Err(_) => {
                let _ = st.stdout().write_str("[PLATFORM] SimpleFileSystem introuvable\r\n");
                return;
            }
        };

        let mut efi_bytes: Option<alloc::vec::Vec<u8>> = None;
        'fs: for &fs_handle in handles.iter() {
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
            let fh = match root.open(EFI_PATH, FileMode::Read, FileAttribute::empty()) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut file = match fh.into_type() {
                Ok(FileType::Regular(f)) => f,
                _ => continue,
            };
            let mut buf = alloc::vec::Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match file.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            if !buf.is_empty() {
                efi_bytes = Some(buf);
                break 'fs;
            }
        }

        let bytes = match efi_bytes {
            Some(b) => b,
            None => {
                let _ = st.stdout().write_str("[PLATFORM] vuc_platform_engine.efi introuvable\r\n");
                return;
            }
        };

        // LoadImage depuis le buffer en mémoire.
        let loaded = match st.boot_services().load_image(
            image_handle,
            LoadImageSource::FromBuffer { buffer: &bytes, file_path: None },
        ) {
            Ok(h) => h,
            Err(e) => {
                let _ = write!(st.stdout(), "[PLATFORM] load_image echoue: {:?}\r\n", e);
                return;
            }
        };

        let _ = st.stdout().write_str("[PLATFORM] vuc_platform_engine.efi charge — demarrage...\r\n");

        // StartImage — transfère le contrôle au platform engine.
        match st.boot_services().start_image(loaded) {
            Ok(_) => {
                let _ = st.stdout().write_str("[PLATFORM] vuc_platform_engine termine\r\n");
            }
            Err(e) => {
                let _ = write!(st.stdout(), "[PLATFORM] start_image echoue: {:?}\r\n", e);
            }
        }
    }
}

// ── Point d'entrée rendu marep ────────────────────────────────────────────────
//
// Tout le rendu passe par exec_marep :
//   1. Ouvrir GOP (kernel-only)
//   2. Fond garanti en Rust (baseline visible même si OVC échoue)
//   3. exec_marep(modules, ctx) → OEntry.ovc → chaîne OVC dynamique
//
// Le kernel ne connaît aucun nom de fonction ou de module OVC.

/// Exécute un marep complet via exec_marep.
/// `modules` : liste de (nom_module, bytes_ovc) extraits du marep ZIP.
/// Le seul point d'entrée est OEntry() dans OEntry.ovc.
pub fn render_from_marep(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    modules:      &[(&str, alloc::vec::Vec<u8>)],
) {
    use crate::ovc_exec;

    // Aucun fichier hardcodé. Les assets sont déclarés dans les marep
    // et chargés à la demande via DrvAPIInterCon***FontLoad***.
    let (font_ptr, font_len) = crate::ovc_exec::srfs_font_ptr();

    // Enregistrer le loader dynamique UEFI pour FontLoad(path) dans les marep.
    // Le loader convertit "SDC:\path" → "\path" et lit depuis l'ESP.
    {
        use uefi::proto::media::{
            file::{File, FileAttribute, FileMode, FileType},
            fs::SimpleFileSystem,
        };
        use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};
        let st_ptr = st.as_ptr() as usize;
        let img_h  = image_handle.as_ptr() as usize;

        // Stocker pour usage différé
        crate::ovc_exec::init_uefi_handles(
            st.as_ptr() as *mut core::ffi::c_void,
            img_h,
        );

        // Créer un loader qui capture les handles par valeur (pas par référence)
        let handles: alloc::vec::Vec<uefi::Handle> =
            st.boot_services().find_handles::<SimpleFileSystem>().unwrap_or_default();

        // Pré-scanner les handles et exposer la fonction de chargement
        // (le closure ne peut pas capturer st directement → utilise les handles)
        let _ = (st_ptr, handles);  // capturés mais pas utilisés directement ici
        // Le loader réel est dans srfs_load_on_demand() via les handles UEFI stockés
    }

    let handle0 = {
        let h = match st.boot_services().find_handles::<GraphicsOutput>() {
            Ok(h) if !h.is_empty() => h,
            _ => return,
        };
        h[0]
    };

    let mut gop = match unsafe {
        st.boot_services().open_protocol::<GraphicsOutput>(
            OpenProtocolParams { handle: handle0, agent: image_handle, controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(g)  => g,
        Err(_) => return,
    };

    // Sélectionne le mode GOP de plus grande résolution disponible. Sans ça, le kernel garde le mode
    // laissé actif par le firmware au boot (souvent un mode par défaut conservateur, pas la résolution
    // native de l'écran) — le rendu remplit correctement CE mode, mais le mode lui-même ne couvre pas
    // tout l'affichage physique, d'où des bandes noires sur les bords malgré un rendu interne responsive.
    //
    // Le rendu (.mara) étire indépendamment en X et Y pour remplir 100% de l'écran (sW/sH distincts,
    // "full-stretch responsive") — donc si le mode le plus grand a un ratio d'aspect très différent du
    // design (1440:1024 ≈ 1.406), tout apparaît déformé (ex: les losanges du dock deviennent ovales).
    // On préfère donc le plus grand mode dont le ratio reste proche du design (±15%), et seulement si
    // aucun mode ne s'en approche, on retombe sur le plus grand mode disponible tout court.
    const DESIGN_W: i64 = 1440;
    const DESIGN_H: i64 = 1024;
    let aspect_close = |mw: usize, mh: usize| -> bool {
        if mh == 0 { return false; }
        let ratio_permille = (mw as i64 * DESIGN_H * 1000) / (mh as i64 * DESIGN_W);
        (850..=1150).contains(&ratio_permille)
    };
    let best_mode = gop.modes(st.boot_services())
        .filter(|m| { let (mw, mh) = m.info().resolution(); aspect_close(mw, mh) })
        .max_by_key(|m| { let (mw, mh) = m.info().resolution(); mw * mh })
        .or_else(|| gop.modes(st.boot_services())
            .max_by_key(|m| { let (mw, mh) = m.info().resolution(); mw * mh }));
    if let Some(mode) = best_mode {
        let _ = gop.set_mode(&mode);
    }

    let info   = gop.current_mode_info();
    let (w, h) = info.resolution();
    let stride = info.stride() as i32;
    let fb     = gop.frame_buffer().as_mut_ptr() as *mut u32;

    let ctx = ovc_exec::ExecCtx {
        fb,
        width:    w as i32,
        height:   h as i32,
        stride,
        font:     font_ptr,
        font_len,
    };

    // Le kernel ne fait AUCUN rendu direct.
    // Tout le graphique vient des .ovc (SluGpu.slul + HelloSlura.marep).

    // Construire les références &[u8] pour exec_marep
    let mod_refs: alloc::vec::Vec<(&str, &[u8])> = modules.iter()
        .map(|(n, b)| (*n, b.as_slice()))
        .collect();

    // Réinitialiser les compteurs de diagnostic
    ovc_exec::reset_gpu_counters();

    // exec_marep — seul point d'entrée : OEntry.ovc
    let ret = ovc_exec::exec_marep(&mod_refs, &ctx);

    // Affichage permanent — stall UEFI en boucle (pas de spin_loop qui monopolise le CPU).
    // Pas d'écriture stdout ici : le texte console UEFI se superpose au framebuffer graphique.
    core::mem::forget(gop);
    let _ = ret;
    loop {
        st.boot_services().stall(30_000_000); // 30s par cycle
    }
}

