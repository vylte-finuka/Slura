//___  Vyft Ltd __  (c) 2026  ___
// ___ EFI Manager for AMD64 UEFI ___
// This file is part of the SLR Clock project, licensed under the MIT License.
// See LICENSE file in the project root for full license information.
// slr_clk_bt\x64\amd64\efi_manager.cpp

//___ Part of support EFI booting ___

#include "efi_manager.h"
#include <cstdio>
#include <cstdlib>

// ---------------------------------------------------------------------
//  Définitions des symboles attendus par le linker.
//  Dans une version finale ces symboles proviendraient du code Rust
//  (ffi.rs).  Pour que la chaîne de compilation fonctionne immédiatement,
//  on fournit ici des implémentations factices : le chargeur Rust sera
//  réellement lié plus tard, mais le linker trouve bien les symboles.
// ---------------------------------------------------------------------
extern "C" {
    // Entrée du kernel Rust – version factice qui renvoie simplement true.
    // La version réelle sera fournie par le crate Rust (ffi.rs) lors du
    // linking complet du projet.
    bool RustEfiEntry(void* ImageHandle, void* SystemTable, void* LoadOptions) {
        // Le vrai pointeur sera stocké dans le symbole du namespace ci‑dessous.
        // Cette implémentation factice ne fait rien d’autre que retourner true.
        return true;
    }
}

// Le symbole attendu par le code C++ est `slr_clk_bt::load_options`.
// Nous le définissons ici afin que le linker le trouve.
namespace slr_clk_bt {
    void* load_options = nullptr;
}

namespace slr_clk_bt
{
    /* ----------------------------------------------------------------- */
    /*  Symboles exportés – visibles depuis l’asm (tables uniquement)   */
    /* ----------------------------------------------------------------- */
    void* EfiManager::efi_system_table    = nullptr;
    void* EfiManager::efi_boot_services   = nullptr;
    void* EfiManager::efi_runtime_services= nullptr;

    /* ----------------------------------------------------------------- */
    EfiManager::EfiManager() = default;

    EfiManager::~EfiManager()
    {
        Shutdown();
    }

    /* ----------------------------------------------------------------- */
    bool EfiManager::Initialize(void* ImageHandle, void* SystemTable)
    {
        m_image_handle = ImageHandle;
        m_system_table = SystemTable;

        // -------------------------------------------------
        // Récupération des tables UEFI (offsets standard)
        // -------------------------------------------------
        const std::uintptr_t* sys = static_cast<std::uintptr_t*>(SystemTable);
        efi_system_table    = const_cast<void*>(static_cast<const void*>(sys));
        efi_boot_services   = reinterpret_cast<void*>(sys[0x64/sizeof(std::uintptr_t)]);
        efi_runtime_services= reinterpret_cast<void*>(sys[0x5C/sizeof(std::uintptr_t)]);

        // -------------------------------------------------
        // Désactivation du watchdog (SetWatchdogTimer)
        // -------------------------------------------------
        using SetWatchdogFn = std::uint64_t(*)(std::uint64_t, std::uint64_t,
                                               std::uint64_t, void*);
        SetWatchdogFn set_watchdog = reinterpret_cast<SetWatchdogFn>(
                static_cast<std::uintptr_t*>(efi_boot_services)[0x38/sizeof(std::uintptr_t)] );
        set_watchdog(0, 0, 0, nullptr);   // 0 = désactiver

        // -------------------------------------------------
        // Passage des options de démarrage au kernel Rust
        // -------------------------------------------------
        extern void* load_options;               // symbole exporté par ffi.rs
        void* load_opts = load_options;          // pointeur vers la chaîne d’options

        // -------------------------------------------------
        // Appel direct du kernel Rust
        // -------------------------------------------------
        return RustEfiEntry(ImageHandle, SystemTable, load_opts);
    }

    /* ----------------------------------------------------------------- */
    void EfiManager::Shutdown()
    {
        // Aucun nettoyage spécial requis – le firmware libère les ressources.
    }
}

/* --------------------------------------------------------------------- */
/*  Point d’entrée appelé depuis l’asm – crée un EfiManager et lance
    l’initialisation du kernel Rust.                                      */
/* --------------------------------------------------------------------- */
extern "C" bool EfiInitialize(void* ImageHandle, void* SystemTable)
{
    slr_clk_bt::EfiManager manager;
    return manager.Initialize(ImageHandle, SystemTable);
}

// Aucun prototype supplémentaire n’est nécessaire ici ; le prototype correct
// provient de `efi_manager.h`. Le symbole `load_options` est déclaré comme
// `extern` plus haut dans la fonction `Initialize`.
