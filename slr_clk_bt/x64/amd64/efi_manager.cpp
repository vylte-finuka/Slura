//___  Vyft Ltd __  (c) 2026  ___
// ___ EFI Manager for AMD64 UEFI ___
// This file is part of the SLR Clock project, licensed under the MIT License.
// See LICENSE file in the project root for full license information.
// slr_clk_bt\x64\amd64\efi_manager.cpp

//___ Part of support EFI booting ___

//___ EFI Manager pour Lunée (BootX-like) ___
#include "efi_manager.h"

extern "C" {
    bool RustEfiEntry(void* ImageHandle, void* SystemTable, void* LoadOptions);
}

namespace slr_clk_bt {
    void* load_options = nullptr;
}

// ---------------------------------------------------------------------------
// Implémentation des symboles exportés par le bootloader.
// ---------------------------------------------------------------------------

// Expose les symboles C attendus par l'assembleur.
extern "C" {
    void* efi_system_table = nullptr;
    void* efi_boot_services = nullptr;
    void* efi_runtime_services = nullptr;
}

// Constructeur / destructeur – aucune logique particulière pour le moment.
slr_clk_bt::EfiManager::EfiManager() = default;
slr_clk_bt::EfiManager::~EfiManager() = default;

bool slr_clk_bt::EfiManager::Initialize(void* ImageHandle, void* SystemTable)
{
    // Conserver les pointeurs UEFI essentiels pour un usage futur.
    m_image_handle = ImageHandle;
    m_system_table = SystemTable;

    // Le tableau de services de démarrage se trouve à l'offset 0x60 du SystemTable.
    // Cette adresse est définie par la spécification UEFI.
    // Mettre à jour les symboles C visibles depuis l'assembleur.
    ::efi_system_table = SystemTable;
    // Les pointeurs vers les tables de services sont à des offsets fixes dans le SystemTable.
    // Utilisation de reinterpret_cast sur un pointeur d'octet pour éviter l'interdiction de static_cast.
    ::efi_boot_services = *reinterpret_cast<void**>(reinterpret_cast<std::uint8_t*>(SystemTable) + 0x60);
    ::efi_runtime_services = *reinterpret_cast<void**>(reinterpret_cast<std::uint8_t*>(SystemTable) + 0x70);

    // Conserver les options de charge si elles existent (pas encore utilisées).
    slr_clk_bt::load_options = nullptr; // TODO: récupérer les LoadOptions réelles.

    // Déléguer l'initialisation au kernel Rust.
    return RustEfiEntry(ImageHandle, SystemTable, nullptr);
}

void slr_clk_bt::EfiManager::Shutdown()
{
    // Aucun nettoyage spécifique requis pour le moment.
}

extern "C" bool EfiInitialize(void* ImageHandle, void* SystemTable)
{
    // Crée une instance locale du gestionnaire et lance l'initialisation.
    slr_clk_bt::EfiManager manager;
    return manager.Initialize(ImageHandle, SystemTable);
}