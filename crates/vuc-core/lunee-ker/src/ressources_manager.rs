//___  Vyft Ltd __  (c) 2026  ___  All Rights Reserved  ___
// ___ Kernel core named Lunee ___
// crates\vuc-core\src\lunee\ressources_manager.rs

//! Gestionnaire de ressources du kernel Lunee.

use crate::hal_manager::HalManager;
use uefi::prelude::*;
use uefi::Status;

#[derive(Debug, Default, Clone)]
pub struct RessourcesManager {
    pub hal_manager: HalManager,
}

impl RessourcesManager {
    pub fn new() -> Self { Self::default() }

    pub fn init_hardware(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        // Convert the generic uefi::Error into a Status value expected by the kernel.
        self.hal_manager.manage_device(st).map_err(|e| e.status())
    }
}