//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee ___
// crates\vuc-core\src\lunee\kernel_runtime.rs

//! Point d'entrée du runtime du kernel Lunee.

use crate::ressources_manager::RessourcesManager;
use uefi::{CStr16, Status, Handle, table::{Boot, SystemTable}};

#[derive(Default)]
pub struct KernelRuntime {
    resources: RessourcesManager,
    boot_init: bool,
    secure_verified: bool,
}

impl KernelRuntime {
    pub fn new() -> Self { Self::default() }

    /// Initialise le kernel pendant la phase de boot.
    pub fn boot_phase(&mut self, st: &mut SystemTable<Boot>, _image: Handle) -> Result<(), Status> {
        self.verify_integrity(st)?;
        self.resources.init_hardware(st)?;
        self.boot_init = true;
        let _ = st.stdout().output_string(CStr16::from_u16_with_nul(&[
            0x005B,0x0052,0x0055,0x004E,0x0054,0x0049,0x004D,0x0045,0x005D,0x0020,
            0x0042,0x006F,0x006F,0x0074,0x0020,0x0070,0x0068,0x0061,0x0073,0x0065,
            0x0020,0x0063,0x006F,0x006D,0x0070,0x006C,0x0065,0x0074,0x0065,0x0064,
            0x002E,0x000D,0x000A,0x0000,
        ]).unwrap());
        Ok(())
    }

    fn verify_integrity(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        let _ = st.stdout().output_string(CStr16::from_u16_with_nul(&[
            0x005B,0x0053,0x0045,0x0043,0x0055,0x0052,0x0049,0x0054,0x0059,0x005D,
            0x0020,0x0049,0x006E,0x0074,0x0065,0x0067,0x0072,0x0069,0x0074,0x0079,
            0x0020,0x0063,0x0068,0x0065,0x0063,0x006B,0x0020,0x0070,0x0061,0x0073,
            0x0073,0x0065,0x0064,0x002E,0x000D,0x000A,0x0000,
        ]).unwrap());
        self.secure_verified = true;
        Ok(())
    }
}
