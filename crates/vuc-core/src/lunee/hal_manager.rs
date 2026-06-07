//___  Vyft Ltd __  (c) 2026  ___  All Rights Reserved  ___
// ___ Kernel core named Lunee ___
// crates\vuc-core\src\lunee\hal_manager.rs

//! HAL (Hardware Abstraction Layer) du kernel Lunee.

use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::CStr16;

#[derive(Debug, Clone, Default)]
pub struct DeviceConfig {
    pub use_legacy_hal: bool,
    pub wantbe_deactivate: bool,
    pub wantbe_activate: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub device_is_available: bool,
}

#[derive(Debug, Default, Clone)]
pub struct HalManager {
    pub device_config: DeviceConfig,
    pub device_info: DeviceInfo,
    pub device_state: bool,
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
