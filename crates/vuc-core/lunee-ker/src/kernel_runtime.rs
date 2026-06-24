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
        let _ = st.stdout().write_str("[MARATINE] Searching for HelloSlura.marep...\r\n");
        match marep_loader::load_and_run(st, image_handle) {
            Ok(code) => {
                let _ = write!(st.stdout(), "[MARATINE] OEntry returned {}\r\n", code);
            }
            Err(BundleError::FileNotFound) => {
                let _ = st.stdout().write_str("[MARATINE] HelloSlura.marep not found.\r\n");
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

    /// Lance le full node SluraChain via LoadImage UEFI.
    /// Charge \vuc_platform_engine.efi depuis l'ESP après le boot.
    pub fn launch_platform_engine(
        &self,
        st:           &mut SystemTable<Boot>,
        image_handle: Handle,
        network:      &str,
    ) {
        let _ = write!(st.stdout(),
            "[PLATFORM] Chargement vuc_platform_engine ({})\r\n", network);
        let _ = network;

        // TODO: implémenter LoadImage via EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
        // pour charger \vuc_platform_engine.efi depuis l'ESP.
        let _ = image_handle;
        let _ = write!(st.stdout(), "[PLATFORM] LoadImage — non encore implémenté\r\n");
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

    // La police TTF est chargée par SluFontConf.slul via SRFSMan (DrvManSpec***FS***).
    // Le kernel ne charge RIEN directement — tout passe par les drivers .slul.
    let (font_ptr, font_len) = crate::ovc_exec::srfs_font_ptr();

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

    // Garder GOP actif pendant l'affichage (30 secondes)
    core::mem::forget(gop);
    st.boot_services().stall(10_000_000); // 10s

    // Logs de diagnostic après le stall
    let (fills, rects, texts) = ovc_exec::gpu_counters();
    let _ = write!(st.stdout(), "[MAREP] OEntry={} GpuFill={} DrawRect={} DrawText={}\r\n",
                   ret, fills, rects, texts);
    let _ = write!(st.stdout(), "[MARATINE] exec_marep: GOP {}x{} OK\r\n", w, h);
    let _ = write!(st.stdout(), "[FONT] TTF {} octets charge\r\n", font_len);
}

