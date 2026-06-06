//___  Vyft Ltd __  (c) 2026  ___  All Rights Reserved  ___
// ___ Kernel core named Lunee ___
// This file is part of the Slura Lunee's kernel project, licensed under the MIT License.
// See LICENSE file in the project root for full license information.
// crates\vuc-core\src\lunee\ressources_manager.rs

//! Gestionnaire de ressources du kernel Lunee.
//! Il regroupe les vues (ROM, RAM, GPU, …) ainsi que le **HAL**.

use crate::lunee::hal_manager::HalManager;
use tracing::{debug, error, info};

/// Point d’entrée du gestionnaire de ressources.
#[derive(Debug, Clone)]
pub struct RessourcesManager {
    pub rom_overview: Option<RomOverview>,
    pub ram_overview: Option<RamOverview>,
    pub vram_overview: Option<VramOverview>,
    pub oam_overview: Option<OamOverview>,
    pub cpu_overview_list: CpuOverviewList,
    pub gpu_overview_list: GpuOverviewList,
    pub apu_overview_list: ApuOverviewList,
    pub npu_overview_list: NpuOverviewList,
    pub hal_manager: HalManager,               // <-- HAL intégré
}

impl RessourcesManager {
    /// Crée une nouvelle instance avec toutes les sous‑structures vides.
    pub fn new() -> Self {
        Self {
            rom_overview: None,
            ram_overview: None,
            vram_overview: None,
            oam_overview: None,
            cpu_overview_list: CpuOverviewList::new(),
            gpu_overview_list: GpuOverviewList::new(),
            apu_overview_list: ApuOverviewList::new(),
            npu_overview_list: NpuOverviewList::new(),
            hal_manager: HalManager::new(),
        }
    }

    /// Initialise le matériel via le HAL.  
    /// Retourne `Result<(), std::io::Error>` afin que le kernel puisse réagir.
    pub async fn init_hardware(&mut self) -> std::io::Result<()> {
        debug!("RessourcesManager::init_hardware – start");
        // Le HAL n’est pas async aujourd’hui, mais on le place dans un `async`
        // block pour garder la signature future‑proof.
        self.hal_manager.manage_device()?;
        info!("Hardware initialisation completed");
        Ok(())
    }

    // -----------------------------------------------------------------
    // Méthodes supplémentaires (exemple de mise à jour d’une vue) …
    // -----------------------------------------------------------------
}

/* --------------------------------------------------------------------- */
/*  Déclarations des structures de vue (ROM, RAM, GPU, …) – gardées     */
/*  inchangées pour la compilation (implémentations futures).          */
/* --------------------------------------------------------------------- */

#[derive(Debug, Default, Clone)]
pub struct RomOverview { /* … */ }

#[derive(Debug, Default, Clone)]
pub struct RamOverview { /* … */ }

#[derive(Debug, Default, Clone)]
pub struct VramOverview { /* … */ }

#[derive(Debug, Default, Clone)]
pub struct OamOverview { /* … */ }

#[derive(Debug, Default, Clone)]
pub struct CpuOverviewList {
    // Exemple d’implémentation minimale
    cpus: Vec<CpuOverview>,
}
impl CpuOverviewList {
    pub fn new() -> Self { Self { cpus: Vec::new() } }
}

#[derive(Debug, Default, Clone)]
pub struct GpuOverviewList {
    gpus: Vec<GpuOverview>,
}
impl GpuOverviewList {
    pub fn new() -> Self { Self { gpus: Vec::new() } }
}

#[derive(Debug, Default, Clone)]
pub struct ApuOverviewList {
    apus: Vec<ApuOverview>,
}
impl ApuOverviewList {
    pub fn new() -> Self { Self { apus: Vec::new() } }
}

#[derive(Debug, Default, Clone)]
pub struct NpuOverviewList {
    npus: Vec<NpuOverview>,
}
impl NpuOverviewList {
    pub fn new() -> Self { Self { npus: Vec::new() } }
}

/* --------------------------------------------------------------------- */
/*  Structures de description (CPU, GPU, …) – placeholders              */
/* --------------------------------------------------------------------- */

#[derive(Debug, Default, Clone)]
pub struct CpuOverview { /* … */ }

#[derive(Debug, Default, Clone)]
pub struct GpuOverview { /* … */ }

#[derive(Debug, Default, Clone)]
pub struct ApuOverview { /* … */ }

#[derive(Debug, Default, Clone)]
pub struct NpuOverview { /* … */ }