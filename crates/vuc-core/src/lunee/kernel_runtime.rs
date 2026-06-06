//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee ___
// This file is part of the Slura Lunee's kernel project, licensed under the MIT License.
// See LICENSE file in the project root for full license information.
// crates\vuc-core\src\lunee\kernel_runtime.rs

//! Point d’entrée du runtime du kernel Lunee, avec les trois passes (boot, loading, checker)
//! et la gestion des ressources matérielles via le HAL.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

use crate::lunee::ressources_manager::RessourcesManager;

/// Point d’entrée du runtime du kernel Lunee.
pub struct KernelRuntime {
    pass_boot:    PassBoot,
    pass_loading: PassLoading,
    pass_checker: PassChecker,
    resources:    RessourcesManager,   // <-- HAL intégré via RessourcesManager
}

impl KernelRuntime {
    /// Crée une nouvelle instance du runtime avec les trois passes initialisées.
    pub fn new() -> Self {
        Self {
            pass_boot: PassBoot::default(),
            pass_loading: PassLoading::default(),
            pass_checker: PassChecker::default(),
            resources: RessourcesManager::new(),
        }
    }

    /// Boot du kernel : initialise le matériel via le HAL puis prépare le loader / le checker.
    pub async fn boot(&mut self, ready: Arc<Notify>) {
        // -------------------------------------------------
        // 1️⃣  Initialisation du hardware (HAL)
        // -------------------------------------------------
        if let Err(e) = self.resources.init_hardware().await {
            eprintln!("Hardware initialisation failed: {}", e);
            // En production on pourrait décider de redémarrer ou d’entrer
            // en mode de secours.  Ici on continue pour garder le demo‑flow.
        }

        // Lecture des options de démarrage depuis le FFI
        unsafe {
            if !load_options.is_null() {
                // Convertir le C‑string en Vec<u8>
                let mut len = 0usize;
                while *load_options.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(load_options, len);
                self.pass_boot.boot_options = Some(slice.to_vec());
            }
        }

        // -------------------------------------------------
        // 2️⃣  Suite du boot (loader & checker)
        // -------------------------------------------------
        println!(
            "Booting Lunee Kernel with config: {:?}",
            self.pass_boot.boot_config
        );
        self.pass_boot.boot_init = true;
        self.pass_boot.boot_lunee_loader = Some(LuneeLoader {
            loader_name: "LuneeLoader v1.0".to_string(),
            loader_version: "1.0".to_string(),
            loader_supported_formats: vec!["ELF".to_string(), "PE".to_string()],
        });
        self.pass_boot.boot_lunee_checker = Some(LuneeChecker {
            checker_name: "LuneeChecker v1.0".to_string(),
            checker_version: "1.0".to_string(),
            checker_supported_formats: vec!["ELF".to_string(), "PE".to_string()],
        });

        // -------------------------------------------------
        // 3️⃣  Signal aux autres tâches que le checker est prêt
        // -------------------------------------------------
        ready.notify_waiters();
    }

    /// Vérifie l’intégrité du kernel après que le boot ait signalé la disponibilité du checker.
    pub async fn check(&mut self, ready: Arc<Notify>) {
        ready.notified().await;

        if let Some(checker) = &self.pass_boot.boot_lunee_checker {
            println!("Checking Lunee Kernel with checker: {:?}", checker);
            self.pass_checker.checker_active = true;
        } else {
            println!("No checker available for Lunee Kernel.");
        }
    }
}

/* -------------------------------------------------------------------------- */
/*  Entrée du programme – runtime Tokio multithread (production)               */
/* -------------------------------------------------------------------------- */

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // Un `Notify` partagé entre les deux tâches.
    let ready = Arc::new(Notify::new());

    // L’état du runtime doit être partagé mutuellement entre les deux tâches.
    let runtime = Arc::new(Mutex::new(KernelRuntime::new()));

    // -------------------------------------------------
    // Tâche 1 – boot du kernel
    // -------------------------------------------------
    let ready_boot = ready.clone();
    let rt_boot = runtime.clone();
    let boot_handle = tokio::spawn(async move {
        let mut guard = rt_boot.lock().await;
        guard.boot(ready_boot).await;
    });

    // -------------------------------------------------
    // Tâche 2 – vérification (check) du kernel
    // -------------------------------------------------
    let ready_check = ready.clone();
    let rt_check = runtime.clone();
    let check_handle = tokio::spawn(async move {
        let mut guard = rt_check.lock().await;
        guard.check(ready_check).await;
    });

    // Attente de la fin des deux tâches
    let _ = tokio::join!(boot_handle, check_handle);
}

/* -------------------------------------------------------------------------- */
/*  Passes (Boot / Loading / Checker) – chaque passe possède son propre état   */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Default, Clone)]
struct PassBoot {
    boot_config:          BootConfig,
    boot_init:            bool,
    boot_lunee_loader:    Option<LuneeLoader>,
    boot_lunee_checker:   Option<LuneeChecker>,
    boot_options:         Option<Vec<u8>>,   // ← nouveau champ
}

#[derive(Debug, Default, Clone)]
struct PassLoading {
    loading_queue:          Vec<ProcessProgram>,
    loading_active:         bool,
    loading_lunee_loader:   Option<LuneeLoader>,
}

#[derive(Debug, Default, Clone)]
struct PassChecker {
    checker_queue:          Vec<ProcessProgram>,
    checker_active:         bool,
    checker_lunee_checker:  Option<LuneeChecker>,
    check_program:          Option<ProcessProgram>,
}

/* -------------------------------------------------------------------------- */
/*  Configuration d’amorçage                                                   */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone)]
struct BootConfig {
    boot_mode:            BootMode,
    boot_timeout:         u64,
    boot_arch:            BootArch,
    boot_secure_mode:     bool,
    driver_managed_support: bool,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            boot_mode:            BootMode::Normal,
            boot_timeout:         30_000,
            boot_arch:            BootArch::X86_64,
            boot_secure_mode:     false,
            driver_managed_support: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BootMode {
    Normal,
    Safe,
    Recovery,
}

#[derive(Debug, Clone, Copy)]
enum BootArch {
    X86_64,
    ARM64,
    RiscV,
}

/* -------------------------------------------------------------------------- */
/*  Loader / Checker – métadonnées descriptives                               */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone)]
struct LuneeLoader {
    loader_name:               String,
    loader_version:            String,
    loader_supported_formats:  Vec<String>,
}

#[derive(Debug, Clone)]
struct LuneeChecker {
    checker_name:               String,
    checker_version:            String,
    checker_supported_formats:  Vec<String>,
}

/* -------------------------------------------------------------------------- */
/*  Représentation d’un programme à charger / vérifier                         */
/* -------------------------------------------------------------------------- */

#[derive(Debug, Clone)]
struct ProcessProgram {
    program_name:    String,
    program_version: String,
    program_pid:     u32,
    program_format:  String,
    program_data:    Vec<u8>,
}

/* -------------------------------------------------------------------------- */
/*  Implémentation Debug personnalisée (facultative)                           */
/* -------------------------------------------------------------------------- */

impl Debug for KernelRuntime {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("KernelRuntime")
            .field("pass_boot", &self.pass_boot)
            .field("pass_loading", &self.pass_loading)
            .field("pass_checker", &self.pass_checker)
            .field("resources", &self.resources)
            .finish()
    }
}

