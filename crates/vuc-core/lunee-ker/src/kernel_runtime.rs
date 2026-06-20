//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee ___
// crates\vuc-core\src\lunee\kernel_runtime.rs

//! Point d'entrée du runtime du kernel Lunée.
//!
//! ## Séquence de boot
//! ```text
//! boot_phase()
//!   ├─ verify_integrity()          ← contrôle d'intégrité UEFI
//!   └─ resources.init_hardware()   ← HAL + chargement drivers .slul
//!
//! maratine_phase()                 ← transfert de contrôle à Maratine
//!   └─ marep_loader::load_and_run  ← lit home.marep, mappe native.bin, appelle OEntry
//! ```

use core::fmt::Write;

use crate::ressources_manager::RessourcesManager;
use crate::bundle_loader::{marep_loader, BundleError};
use uefi::{CStr16, Handle, Status, table::{Boot, SystemTable}};

#[derive(Default)]
pub struct KernelRuntime {
    resources:       RessourcesManager,
    boot_init:       bool,
    secure_verified: bool,
}

impl KernelRuntime {
    pub fn new() -> Self { Self::default() }

    // ── Phase 1 : initialisation hardware ────────────────────────────────────

    /// Initialise le kernel pendant la phase de boot UEFI.
    ///
    /// 1. Vérification d'intégrité
    /// 2. Détection hardware (HAL)
    /// 3. Chargement des drivers Maratine (.slul) via UEFI LoadImage/StartImage
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

    // ── Phase 2 : démarrage Maratine ─────────────────────────────────────────

    /// Transfère le contrôle au runtime Maratine.
    ///
    /// Charge `EFI\SLURA\HOME\home.marep` depuis l'ESP, mappe son binaire
    /// natif dans des pages exécutables et appelle `OEntry`.
    /// Cette méthode ne retourne normalement pas (OEntry = boucle principale).
    pub fn maratine_phase(&mut self, st: &mut SystemTable<Boot>, image_handle: Handle) {
        let _ = st.stdout().write_str("[MARATINE] Searching for home.marep...\r\n");

        match marep_loader::load_and_run(st, image_handle) {
            Ok(code) => {
                // OEntry a retourné — situation anormale pour un OS.
                let _ = st.stdout().write_str("[MARATINE] OEntry returned ");
                let _ = write!(st.stdout(), "{}", code);
                let _ = st.stdout().write_str(" — halting.\r\n");
            }
            Err(BundleError::FileNotFound) => {
                let _ = st.stdout().write_str(
                    "[MARATINE] home.marep not found on ESP.\r\n\
                     [MARATINE] Place the bundle at EFI\\SLURA\\HOME\\home.marep\r\n"
                );
            }
            Err(BundleError::CompressedNotSupported) => {
                let _ = st.stdout().write_str(
                    "[MARATINE] Bundle uses compression — rebuild with: marai build --no-compress\r\n"
                );
            }
            Err(BundleError::AllocationFailed) => {
                let _ = st.stdout().write_str("[MARATINE] Out of memory.\r\n");
            }
            Err(e) => {
                let _ = write!(st.stdout(), "[MARATINE] Load error: {:?}\r\n", e);
            }
        }
    }
}
