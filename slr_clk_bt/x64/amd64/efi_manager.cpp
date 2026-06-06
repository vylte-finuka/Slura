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

extern "C" bool EfiInitialize(void* ImageHandle, void* SystemTable)
{
    slr_clk_bt::load_options = nullptr; // À remplir plus tard

    // Appel direct au kernel Lunée
    return RustEfiEntry(ImageHandle, SystemTable, nullptr);
}