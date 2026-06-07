// Pas de #![no_std] ici — c'est géré par lib.rs
// Pas de #[entry] ici — c'est un module, pas un binaire

extern crate alloc;

pub mod kernel_runtime;
pub mod ressources_manager;
pub mod hal_manager;

pub use kernel_runtime::KernelRuntime;
pub use ressources_manager::RessourcesManager;
pub use hal_manager::HalManager;

use uefi::prelude::*;
use uefi::CStr16;
