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

use core::{arch::x86_64::{__cpuid, __cpuid_count}, fmt::Write};
use uefi::prelude::*;
use uefi::proto::console::text::Output;
use uefi::{Handle, Status};

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
/*  Masques de bits CPUID – extensions AMD64 / Intel                     */
/* --------------------------------------------------------------------- */
mod cpuid {
    pub const SSE3_BIT:      u32 = 1 << 0;
    pub const SSSE3_BIT:     u32 = 1 << 9;
    pub const SSE41_BIT:     u32 = 1 << 19;
    pub const SSE42_BIT:     u32 = 1 << 20;
    pub const AES_BIT:       u32 = 1 << 25;
    pub const AVX_BIT:       u32 = 1 << 28;
    pub const FMA_BIT:       u32 = 1 << 12;
    pub const RDRAND_BIT:    u32 = 1 << 30;
    pub const VMX_BIT:       u32 = 1 << 5;

    pub const AVX2_BIT:      u32 = 1 << 5;
    pub const BMI1_BIT:      u32 = 1 << 3;
    pub const BMI2_BIT:      u32 = 1 << 8;
    pub const ADX_BIT:       u32 = 1 << 19;
    pub const SHA_BIT:       u32 = 1 << 29;
    pub const SMEP_BIT:      u32 = 1 << 7;
    pub const SMAP_BIT7:     u32 = 1 << 20;
    pub const MPX_BIT:       u32 = 1 << 14;
    pub const CET_SS_BIT:    u32 = 1 << 7;

    pub const SSE4A_BIT:     u32 = 1 << 6;
    pub const XOP_BIT:       u32 = 1 << 11;
    pub const FMA4_BIT:      u32 = 1 << 16;
    pub const SVM_BIT:       u32 = 1 << 2;
    pub const ABM_BIT:       u32 = 1 << 5;
    pub const TBM_BIT:       u32 = 1 << 21;
    pub const LZCNT_BIT:     u32 = 1 << 31;
    pub const SYSCALL_BIT:   u32 = 1 << 11;
    pub const NX_BIT:        u32 = 1 << 20;
    pub const RDTSCP_BIT:    u32 = 1 << 27;
    pub const POPCNT_BIT:    u32 = 1 << 23;
}

/* --------------------------------------------------------------------- */
/*  Fonction utilitaire – retourne un bit‑field décrivant les extensions AMD64 */
/* --------------------------------------------------------------------- */
fn query_cpu_features() -> u32 {
    let max_basic = unsafe { __cpuid(0).eax };
    let mut features: u32 = 0;

    if max_basic >= 1 {
        let cpuid1 = unsafe { __cpuid(1) };
        let ecx = cpuid1.ecx;
        if (ecx & cpuid::SSE3_BIT) != 0 { features |= cpuid::SSE3_BIT; }
        if (ecx & cpuid::SSSE3_BIT) != 0 { features |= cpuid::SSSE3_BIT; }
        if (ecx & cpuid::SSE41_BIT) != 0 { features |= cpuid::SSE41_BIT; }
        if (ecx & cpuid::SSE42_BIT) != 0 { features |= cpuid::SSE42_BIT; }
        if (ecx & cpuid::AES_BIT) != 0 { features |= cpuid::AES_BIT; }
        if (ecx & cpuid::AVX_BIT) != 0 { features |= cpuid::AVX_BIT; }
        if (ecx & cpuid::FMA_BIT) != 0 { features |= cpuid::FMA_BIT; }
        if (ecx & cpuid::RDRAND_BIT) != 0 { features |= cpuid::RDRAND_BIT; }
        if (ecx & cpuid::VMX_BIT) != 0 { features |= cpuid::VMX_BIT; }
    }

    if max_basic >= 7 {
        let cpuid7 = unsafe { __cpuid_count(7, 0) };
        let ebx = cpuid7.ebx;
        let ecx = cpuid7.ecx;
        if (ebx & cpuid::AVX2_BIT) != 0 { features |= cpuid::AVX2_BIT; }
        if (ebx & cpuid::BMI1_BIT) != 0 { features |= cpuid::BMI1_BIT; }
        if (ebx & cpuid::BMI2_BIT) != 0 { features |= cpuid::BMI2_BIT; }
        if (ebx & cpuid::ADX_BIT) != 0 { features |= cpuid::ADX_BIT; }
        if (ebx & cpuid::SHA_BIT) != 0 { features |= cpuid::SHA_BIT; }
        if (ebx & cpuid::SMEP_BIT) != 0 { features |= cpuid::SMEP_BIT; }
        if (ebx & cpuid::SMAP_BIT7) != 0 { features |= cpuid::SMAP_BIT7; }
        if (ebx & cpuid::MPX_BIT) != 0 { features |= cpuid::MPX_BIT; }
        if (ecx & cpuid::CET_SS_BIT) != 0 { features |= cpuid::CET_SS_BIT; }
    }

    let max_extended = unsafe { __cpuid(0x8000_0000).eax };
    if max_extended >= 0x8000_0001 {
        let cpuid_ext = unsafe { __cpuid(0x8000_0001) };
        let ecx = cpuid_ext.ecx;
        if (ecx & cpuid::SSE4A_BIT) != 0 { features |= cpuid::SSE4A_BIT; }
        if (ecx & cpuid::XOP_BIT) != 0 { features |= cpuid::XOP_BIT; }
        if (ecx & cpuid::FMA4_BIT) != 0 { features |= cpuid::FMA4_BIT; }
        if (ecx & cpuid::SVM_BIT) != 0 { features |= cpuid::SVM_BIT; }
        if (ecx & cpuid::ABM_BIT) != 0 { features |= cpuid::ABM_BIT; }
        if (ecx & cpuid::TBM_BIT) != 0 { features |= cpuid::TBM_BIT; }
        if (ecx & cpuid::LZCNT_BIT) != 0 { features |= cpuid::LZCNT_BIT; }
        if (ecx & cpuid::SYSCALL_BIT) != 0 { features |= cpuid::SYSCALL_BIT; }
        if (ecx & cpuid::NX_BIT) != 0 { features |= cpuid::NX_BIT; }
        if (ecx & cpuid::RDTSCP_BIT) != 0 { features |= cpuid::RDTSCP_BIT; }
        if (ecx & cpuid::POPCNT_BIT) != 0 { features |= cpuid::POPCNT_BIT; }
    }

    features
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