//___  Vyft Ltd __  (c) 2026  ___  All Rights Reserved  ___
// ___ Kernel core named Lunee ___
// This file is part of the Slura Lunee's kernel project, licensed under the MIT License.
// See LICENSE file in the project root for full license information.
// crates\vuc-core\src\lunee\hal_manager.rs

//! HAL (Hardware Abstraction Layer) du kernel Lunee.
//! ------------------------------------------------
//! Ce module expose une API **synchrone** (pour le moment) qui
//! détecte, charge et gère les drivers matériels.  
//! Il est volontairement minimal : les implémentations réelles
//! seront ajoutées dans les sous‑modules `hal_*` (PCI, ACPI, …).

use core::fmt::Write;
use uefi::prelude::*;
use uefi::proto::console::text::Output;
use uefi::{Handle, Status};

// Backend de détection CPU séparé par dossier d'architecture — même principe
// que slr_clk_bt/x64/amd64 vs slr_clk_bt/arm64/aarch64 côté bootloader :
// amd64.rs (CPUID x86_64) / arm64.rs (MRS sur les ID_AA64*_EL1 AArch64).
#[cfg_attr(target_arch = "x86_64", path = "hal_manager/amd64.rs")]
#[cfg_attr(target_arch = "aarch64", path = "hal_manager/arm64.rs")]
mod cpu_features;
use cpu_features::{cpuid, query_cpu_features};

/// Configuration d’un device.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub use_legacy_hal: bool,
    pub wantbe_deactivate: bool,
    pub wantbe_activate: bool,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            use_legacy_hal: false,
            wantbe_deactivate: false,
            wantbe_activate: true,
        }
    }
}

/// Informations d’un device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_version: u32,
    pub device_name: heapless::String<64>,
    pub device_authors: heapless::Vec<heapless::String<32>, 8>,
    pub devices_location: heapless::String<64>,
    pub device_description: heapless::String<128>,
    pub device_is_available: bool,
    pub device_capacities: heapless::Vec<heapless::String<32>, 8>,
    pub devices_logevent: heapless::Vec<heapless::String<64>, 16>,
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self {
            device_version: 0,
            device_name: heapless::String::new(),
            device_authors: heapless::Vec::new(),
            devices_location: heapless::String::new(),
            device_description: heapless::String::new(),
            device_is_available: false,
            device_capacities: heapless::Vec::new(),
            devices_logevent: heapless::Vec::new(),
        }
    }
}

/* --------------------------------------------------------------------- */
/*  Structure principale du HAL                                          */
/* --------------------------------------------------------------------- */
#[derive(Debug, Default, Clone)]
pub struct HalManager {
    pub device_config: DeviceConfig,
    pub device_info: DeviceInfo,
    pub device_state: bool,
}

impl HalManager {
    pub fn new() -> Self { Self::default() }

    fn log_device_event(&mut self, msg: &str) {
        // On utilise la console UEFI (stdout) via `SystemTable` lorsqu’on a besoin d’afficher.
        // Cette fonction sera appelée depuis `manage_device` qui possède déjà `SystemTable`.
        let _ = msg;
    }

    /// API publique : détecte le hardware, charge les drivers et met à jour les champs d’état.
    pub fn manage_device(
        &mut self,
        st:           &mut SystemTable<Boot>,
        image_handle: Handle,
    ) -> uefi::Result<()> {
        // Le plus tôt possible dans le boot, avant tout `find_handles`/`open_protocol`
        // (GOP, HID, PciIo) fait par ce kernel : force le firmware à connecter tous
        // les drivers de bus disponibles. Sur QEMU/VMware tout est déjà préconnecté
        // au boot (find_handles voit tout sans ça) ; sur du matériel réel, un firmware
        // OEM peut ne binder que le strict nécessaire au chemin de boot et laisser
        // l'écran, la souris/clavier ou le xHCI non connectés. Voir pci.rs pour le
        // détail — même fonction, appelée ici une seule fois pour couvrir tous les
        // usages ultérieurs de find_handles dans le kernel.
        crate::pci::connect_all_controllers(st);

        if self.detect_devices() {
            self.device_state = true;
            self.log(st, "Hardware detected and initialized successfully.");
        } else {
            self.log(st, "No compatible hardware found.");
        }
        self.load_drivers(st, image_handle)?;
        Ok(())
    }

    // -----------------------------------------------------------------
    //  Détection du hardware – prise en compte de la virtualisation,
    //  des jeux d’instructions modernes/legacy et des protections.
    // -----------------------------------------------------------------
    fn detect_devices(&self) -> bool {
        let features = query_cpu_features();
        // Exemple très simplifié : on accepte tout CPU qui possède AVX.
        (features & cpuid::SSE3_BIT) != 0 || (features & cpuid::AVX_BIT) != 0
    }

    // -----------------------------------------------------------------
    //  Chargement des drivers – version factice (écrit sur stdout)
    // -----------------------------------------------------------------
    fn load_drivers(&self, st: &mut SystemTable<Boot>, image_handle: Handle) -> uefi::Result<()> {
        use crate::bundle_loader::slul_loader;
        let count = slul_loader::load_drivers(st, image_handle);
        self.log(st, if count > 0 { "[HAL] Maratine drivers loaded." } else { "[HAL] No .slul drivers found." });
        Ok(())
    }

    // -----------------------------------------------------------------
    //  Helper d’affichage via la console UEFI
    // -----------------------------------------------------------------
    fn log(&self, st: &mut SystemTable<Boot>, msg: &str) {
        let _ = st.stdout().write_str(msg);
        let _ = st.stdout().write_str("\r\n");
    }
}