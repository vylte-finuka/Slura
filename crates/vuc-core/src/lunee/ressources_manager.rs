//___  Vyft Ltd __  (c) 2026  ___  All Rights Reserved  ___
// ___ Kernel core named Lunee ___
// This file is part of the Slura Lunee's kernel project, licensed under the MIT License.
// See LICENSE file in the project root for full license information.
// crates\vuc-core\src\lunee\ressources_manager.rs

//! Gestionnaire de ressources du kernel Lunee.
//! Il regroupe les vues (ROM, RAM, GPU, …) ainsi que le **HAL**.

#![no_std]

use crate::lunee::hal_manager::HalManager;
use uefi::prelude::*;
use uefi::Status;

#[derive(Debug, Default, Clone)]
pub struct RessourcesManager {
    pub hal_manager: HalManager,
}

impl RessourcesManager {
    pub fn new() -> Self { Self::default() }

    pub fn init_hardware(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        self.hal_manager.manage_device(st)
    }
}