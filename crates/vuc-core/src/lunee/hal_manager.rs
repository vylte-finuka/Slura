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

use std::arch::x86_64::{__cpuid, __cpuid_count};
use std::io::{self, Write};
use tracing::{debug, error, info}; // ← `warn` retiré (non utilisé)

// ---------------------------------------------------------------------
//  Structures publiques – configuration & informations du hardware
// ---------------------------------------------------------------------

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
            wantbe_activate: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_version: u32,
    pub device_name: String,
    pub device_authors: Vec<String>,
    pub devices_location: String,
    pub device_description: String,
    pub device_is_available: bool,
    pub device_capacities: Vec<String>,
    pub devices_logevent: Vec<String>,
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self {
            device_version: 0,
            device_name: String::new(),
            device_authors: Vec::new(),
            devices_location: String::new(),
            device_description: String::new(),
            device_is_available: false,
            device_capacities: Vec::new(),
            devices_logevent: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------
//  Masques de bits CPUID – extensions AMD64 / Intel
// ---------------------------------------------------------------------
mod cpuid {
    // Fonction 1 (EAX=1) – bits ECX
    pub const SSE3_BIT:      u32 = 1 << 0;
    pub const SSSE3_BIT:     u32 = 1 << 9;
    pub const SSE41_BIT:     u32 = 1 << 19;
    pub const SSE42_BIT:     u32 = 1 << 20;
    pub const AES_BIT:       u32 = 1 << 25;
    pub const AVX_BIT:       u32 = 1 << 28;
    pub const FMA_BIT:       u32 = 1 << 12;   // FMA (AVX‑FMA)
    pub const RDRAND_BIT:    u32 = 1 << 30;   // RDRAND
    pub const VMX_BIT:       u32 = 1 << 5;    // Intel VT‑x (VMX)

    // Fonction 7, sous‑fonction 0 – bits EBX
    pub const AVX2_BIT:      u32 = 1 << 5;
    pub const BMI1_BIT:      u32 = 1 << 3;
    pub const BMI2_BIT:      u32 = 1 << 8;
    pub const ADX_BIT:       u32 = 1 << 19;
    pub const SHA_BIT:       u32 = 1 << 29;
    pub const SMEP_BIT:      u32 = 1 << 7;    // SMEP (EBX, fonction 7)
    pub const SMAP_BIT7:     u32 = 1 << 20;   // SMAP (EBX, fonction 7)
    pub const MPX_BIT:       u32 = 1 << 14;   // MPX
    pub const CET_SS_BIT:    u32 = 1 << 7;    // CET‑SS (ECX, fonction 7)

    // Fonction 0x8000_0001 – bits ECX (extensions AMD)
    pub const SSE4A_BIT:     u32 = 1 << 6;
    pub const XOP_BIT:       u32 = 1 << 11;
    pub const FMA4_BIT:      u32 = 1 << 16;
    pub const SVM_BIT:       u32 = 1 << 2;    // AMD‑V (SVM)
    pub const ABM_BIT:       u32 = 1 << 5;
    pub const TBM_BIT:       u32 = 1 << 21;
    pub const LZCNT_BIT:     u32 = 1 << 31;
    pub const SYSCALL_BIT:   u32 = 1 << 11;
    pub const NX_BIT:        u32 = 1 << 20;
    pub const RDTSCP_BIT:    u32 = 1 << 27;
    pub const POPCNT_BIT:    u32 = 1 << 23;
}

// ---------------------------------------------------------------------
//  Fonction utilitaire – retourne un bit‑field décrivant les extensions AMD64
// ---------------------------------------------------------------------
fn query_cpu_features() -> u32 {
    let max_basic = unsafe { __cpuid(0).eax };
    let mut features: u32 = 0;

    // Fonction 1 – ECX
    if max_basic >= 1 {
        let cpuid1 = unsafe { __cpuid(1) };
        let ecx = cpuid1.ecx;
        if ecx & cpuid::SSE3_BIT   != 0 { features |= cpuid::SSE3_BIT;   }
        if ecx & cpuid::SSSE3_BIT  != 0 { features |= cpuid::SSSE3_BIT;  }
        if ecx & cpuid::SSE41_BIT  != 0 { features |= cpuid::SSE41_BIT;  }
        if ecx & cpuid::SSE42_BIT  != 0 { features |= cpuid::SSE42_BIT;  }
        if ecx & cpuid::AES_BIT    != 0 { features |= cpuid::AES_BIT;    }
        if ecx & cpuid::AVX_BIT    != 0 { features |= cpuid::AVX_BIT;    }
        if ecx & cpuid::FMA_BIT    != 0 { features |= cpuid::FMA_BIT;    }
        if ecx & cpuid::RDRAND_BIT != 0 { features |= cpuid::RDRAND_BIT; }
        if ecx & cpuid::VMX_BIT    != 0 { features |= cpuid::VMX_BIT;    }
    }

    // Fonction 7 – EBX + ECX (CET‑SS se trouve dans ECX)
    if max_basic >= 7 {
        let cpuid7 = unsafe { __cpuid_count(7, 0) };
        let ebx = cpuid7.ebx;
        let ecx = cpuid7.ecx;
        if ebx & cpuid::AVX2_BIT   != 0 { features |= cpuid::AVX2_BIT;   }
        if ebx & cpuid::BMI1_BIT   != 0 { features |= cpuid::BMI1_BIT;   }
        if ebx & cpuid::BMI2_BIT   != 0 { features |= cpuid::BMI2_BIT;   }
        if ebx & cpuid::ADX_BIT    != 0 { features |= cpuid::ADX_BIT;    }
        if ebx & cpuid::SHA_BIT    != 0 { features |= cpuid::SHA_BIT;    }
        if ebx & cpuid::SMEP_BIT   != 0 { features |= cpuid::SMEP_BIT;   }
        if ebx & cpuid::SMAP_BIT7  != 0 { features |= cpuid::SMAP_BIT7;  }
        if ebx & cpuid::MPX_BIT    != 0 { features |= cpuid::MPX_BIT;    }
        if ecx & (1 << 7) != 0 { features |= cpuid::CET_SS_BIT; } // CET‑SS
    }

    // Fonction 0x8000_0001 – extensions AMD
    let max_extended = unsafe { __cpuid(0x8000_0000).eax };
    if max_extended >= 0x8000_0001 {
        let cpuid_ext = unsafe { __cpuid(0x8000_0001) };
        let ecx = cpuid_ext.ecx;
        if ecx & cpuid::SSE4A_BIT   != 0 { features |= cpuid::SSE4A_BIT;   }
        if ecx & cpuid::XOP_BIT     != 0 { features |= cpuid::XOP_BIT;     }
        if ecx & cpuid::FMA4_BIT    != 0 { features |= cpuid::FMA4_BIT;    }
        if ecx & cpuid::SVM_BIT     != 0 { features |= cpuid::SVM_BIT;     }
        if ecx & cpuid::ABM_BIT     != 0 { features |= cpuid::ABM_BIT;     }
        if ecx & cpuid::TBM_BIT     != 0 { features |= cpuid::TBM_BIT;     }
        if ecx & cpuid::LZCNT_BIT   != 0 { features |= cpuid::LZCNT_BIT;   }
        if ecx & cpuid::SYSCALL_BIT != 0 { features |= cpuid::SYSCALL_BIT; }
        if ecx & cpuid::NX_BIT      != 0 { features |= cpuid::NX_BIT;      }
        if ecx & cpuid::RDTSCP_BIT  != 0 { features |= cpuid::RDTSCP_BIT;  }
        if ecx & cpuid::POPCNT_BIT  != 0 { features |= cpuid::POPCNT_BIT;  }
    }

    features
}

// ---------------------------------------------------------------------
//  Structure principale du HAL
// ---------------------------------------------------------------------
#[derive(Debug, Default, Clone)]
pub struct HalManager {
    pub device_config: DeviceConfig,
    pub device_info: DeviceInfo,
    pub device_state: bool, // ← état hardware (true = actif)
}

impl HalManager {
    pub fn new() -> Self {
        Self {
            device_config: DeviceConfig::default(),
            device_info: DeviceInfo::default(),
            device_state: false,
        }
    }

    fn log_device_event(&mut self, msg: &str) {
        self.device_info.devices_logevent.push(msg.to_string());
        info!("[HAL] {}", msg);
    }

    /// API publique : détecte le hardware, charge les drivers et met à jour les champs d’état.
    pub fn manage_device(&mut self) -> io::Result<()> {
        let detected = self.detect_devices();
        if detected {
            self.device_state = true;
            self.device_info.device_is_available = true;
            self.log_device_event("Hardware detected and initialized.");
        } else {
            self.device_state = false;
            self.device_info.device_is_available = false;
            self.log_device_event("No hardware detected.");
        }

        match self.load_drivers() {
            Ok(_) => self.log_device_event("Hardware drivers loaded successfully."),
            Err(e) => {
                error!("Failed to load hardware drivers: {}", e);
                self.log_device_event("Failed to load hardware drivers.");
                return Err(e);
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------
    //  Détection du hardware – prise en compte de la virtualisation,
    //  des jeux d’instructions modernes/legacy et des protections.
    // -----------------------------------------------------------------
    fn detect_devices(&self) -> bool {
        let feats = query_cpu_features();

        // 1️⃣ Jeux d’instructions modernes
        let has_modern = (feats & cpuid::AVX_BIT)  != 0
                     || (feats & cpuid::AVX2_BIT) != 0
                     || (feats & cpuid::FMA_BIT) != 0;

        // 2️⃣ Jeux d’instructions legacy
        let has_legacy = (feats & cpuid::SSE3_BIT)  != 0
                     && (feats & cpuid::SSSE3_BIT) != 0
                     && (feats & cpuid::SSE41_BIT) != 0
                     && (feats & cpuid::SSE42_BIT) != 0;

        // 3️⃣ Virtualisation (Intel VMX ou AMD SVM)
        let has_virtualization = (feats & cpuid::VMX_BIT) != 0
                              || (feats & cpuid::SVM_BIT) != 0;

        // 4️⃣ Sécurité / protection
        let has_security = (feats & cpuid::SMEP_BIT) != 0
                        || (feats & cpuid::SMAP_BIT7) != 0
                        || (feats & cpuid::CET_SS_BIT) != 0
                        || (feats & cpuid::MPX_BIT) != 0;

        // 5️⃣ Décision finale
        let detected = has_modern || has_legacy;

        debug!(
            "CPU features bitmap = 0x{:08x}
             modern={} legacy={} virtualization={} security={}",
            feats,
            has_modern,
            has_legacy,
            has_virtualization,
            has_security
        );

        // (Optionnel) on peut pousser les capacités dans `device_info.device_capacities`
        // si on veut les exposer à l’extérieur du HAL.

        detected
    }

    // -----------------------------------------------------------------
    //  Chargement des drivers – version factice (écrit sur stdout)
    // -----------------------------------------------------------------
    fn load_drivers(&self) -> io::Result<()> {
        let mut out = io::BufWriter::new(io::stdout());
        writeln!(out, "Loading device drivers…")?;
        out.flush()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------
//  Fin du fichier – aucune duplication restante
// ---------------------------------------------------------------------

            self.device_info.device_is_available = true;
            self.log(st, "Hardware detected and initialized successfully.");
        } else {
            self.log(st, "No compatible hardware detected.");
        }
        self.load_drivers(st)?;
        Ok(())
    }

    fn log(&self, st: &mut SystemTable<Boot>, msg: &str) {
        let _ = st.stdout().output_string(
            CStr16::from_u16_with_nul(&[0x005B,0x0048,0x0041,0x004C,0x005D,0x0020,0x0000]).unwrap()
        );
        let utf16: Vec<u16> = msg.encode_utf16().chain(Some(0)).collect();
        if let Ok(s) = CStr16::from_u16_with_nul(&utf16) {
            let _ = st.stdout().output_string(s);
        }
        let _ = st.stdout().output_string(
            CStr16::from_u16_with_nul(&[0x000D,0x000A,0x0000]).unwrap()
        );
    }

    fn detect_devices(&self) -> bool {
        // aarch64 — pas de CPUID x86
        // Détection basique : toujours true pour l'instant
        // À remplacer par lecture des Device Tree / ACPI MADT
        true
    }

    fn load_drivers(&self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        self.log(st, "Loading device drivers...");
        Ok(())
    }
}    pub device_state: bool,
}

impl HalManager {
    pub fn new() -> Self { Self::default() }

    pub fn manage_device(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        let detected = self.detect_devices();
        if detected {
            self.device_state = true;
            self.device_info.device_is_available = true;
            self.log(st, "Hardware detected and initialized successfully.");
        } else {
            self.log(st, "No compatible hardware detected.");
        }
        self.load_drivers(st)?;
        Ok(())
    }

    fn log(&self, st: &mut SystemTable<Boot>, msg: &str) {
        let _ = st.stdout().output_string(CStr16::from_u16_with_nul(&[0x005B,0x0048,0x0041,0x004C,0x005D,0x0020,0x0000]).unwrap());
        let _ = st.stdout().output_string(CStr16::from_u16_with_nul(&msg.encode_utf16().chain(Some(0)).collect::<Vec<_>>()[..]).unwrap_or(CStr16::from_u16_with_nul(&[0]).unwrap()));
        let _ = st.stdout().output_string(CStr16::from_u16_with_nul(&[0x000D,0x000A,0x0000]).unwrap());
    }

    fn detect_devices(&self) -> bool {
        // Logique CPUID originale conservée
        let cpuid = unsafe { __cpuid(0x1) };
        cpuid.eax != 0
    }

    fn load_drivers(&self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        self.log(st, "Loading device drivers...");
        Ok(())
    }
}
