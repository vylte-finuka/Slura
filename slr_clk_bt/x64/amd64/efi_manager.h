//___  Vyft Ltd __  (c) 2026  ___  All Rights Reserved  ___
// ___ EFI Manager for AMD64 UEFI ___
// This file is part of the SLR Clock project, licensed under the MIT License.
// See LICENSE file in the project root for full license information.

#pragma once

#include <cstddef> // std::size_t, std::nullptr_t, …
#include <cstdint>   // std::uint*_t, std::int*_t, …
#include <type_traits>   // std::is_same, std::remove_reference, …
#include <utility>       // std::move, std::forward, …
#include <cstring>       // std::memcpy, std::memset (si besoin futur)

// ------------------------------------------------------------
//  Déclaration du namespace du projet
// ------------------------------------------------------------
namespace slr_clk_bt
{
    // Point d’entrée du kernel Rust (exposé via FFI). Trois arguments : ImageHandle, SystemTable et LoadOptions.
    extern "C" bool RustEfiEntry(void* ImageHandle, void* SystemTable, void* LoadOptions);

    // --------------------------------------------------------
    //  Classe principale qui encapsule les services UEFI
    // --------------------------------------------------------
    class EfiManager
    {
    public:
        EfiManager();
        ~EfiManager();

        // Initialise le service UEFI et lance le kernel Rust
        bool Initialize(void* ImageHandle, void* SystemTable);
        void Shutdown();

        // Symboles exportés pour le chargeur UEFI (déjà exportés par l’asm)
        static void* efi_system_table;
        static void* efi_boot_services;
        static void* efi_runtime_services;
    private:
        void* m_image_handle = nullptr;
        void* m_system_table = nullptr;
        // Les champs inutilisés ont été retirés pour éviter les warnings.
    };
}

// ------------------------------------------------------------
//  Point d’entrée appelé depuis l’asm – il crée simplement un
//  EfiManager et délègue l’initialisation au kernel Rust.
// ------------------------------------------------------------
extern "C" bool EfiInitialize(void* ImageHandle, void* SystemTable);
