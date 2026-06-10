// ---------------------------------------------------------------
// Programme d’hôte qui simule le firmware UEFI et appelle
// EfiInitialize (votre point d’entrée EFI).
// ---------------------------------------------------------------
#include "efi_manager.h"
#include <cstdio>
#include <cstdint>
#include <cstring>

// -----------------------------------------------------------------
// Structure minimale de EFI_TABLE_HEADER (seulement le champ
// Signature qui est vérifié dans votre asm)
// -----------------------------------------------------------------
struct EFI_TABLE_HEADER {
    uint64_t Signature;   // 0x20494249 = "IBI"
    uint32_t Revision;
    uint32_t HeaderSize;
    uint32_t CRC32;
    uint32_t Reserved;
};

// -----------------------------------------------------------------
// Structure très simplifiée de EFI_SYSTEM_TABLE.
// Seuls les champs réellement lus par votre code sont présents.
// -----------------------------------------------------------------
struct FAKE_EFI_SYSTEM_TABLE {
    EFI_TABLE_HEADER Hdr;          // offset 0x00
    void* FirmwareVendor;          // offset 0x18 (ignoré)
    uint32_t FirmwareRevision;     // offset 0x20 (ignoré)
    void* ConsoleInHandle;         // offset 0x24 (ignoré)
    void* ConIn;                   // offset 0x28 (ignoré)
    void* ConsoleOutHandle;        // offset 0x2C (ignoré)
    void* ConOut;                  // offset 0x30 (ignoré)
    void* StandardErrorHandle;     // offset 0x34 (ignoré)
    void* StdErr;                  // offset 0x38 (ignoré)
    void* RuntimeServices;         // offset 0x40  <-- utilisé (offset 0x5C dans votre asm)
    void* BootServices;            // offset 0x48  <-- utilisé (offset 0x64 dans votre asm)
    void* NumberOfTableEntries;    // offset 0x50 (ignoré)
    void* ConfigurationTable;      // offset 0x58 (ignoré)
    void* LoadOptions;             // offset 0x60  <-- utilisé (offset 0x20 dans votre asm)
    uint32_t LoadOptionsSize;      // offset 0x68 (ignoré)
    void* ImageHandle;             // offset 0x6C (ignoré)
};

// -----------------------------------------------------------------
// Implémentation très simple d’un service BootServices.
// Nous ne fournissons que l’entrée SetWatchdogTimer (offset 0x38
// dans la table BootServices).  Le reste du tableau est rempli de
// zéros.
// -----------------------------------------------------------------
struct FAKE_BOOT_SERVICES {
    void* RaiseTPL;                // 0x00
    void* RestoreTPL;              // 0x08
    void* AllocatePages;           // 0x10
    void* FreePages;               // 0x18
    void* GetMemoryMap;            // 0x20
    void* AllocatePool;            // 0x28
    void* FreePool;                // 0x30
    void* CreateEvent;             // 0x38 <-- SetWatchdogTimer (nous le remplaçons)
    // le reste n’est pas nécessaire pour le test
};

// -----------------------------------------------------------------
// Fonction factice SetWatchdogTimer – on ne fait rien, on renvoie 0.
// -----------------------------------------------------------------
extern "C" uint64_t __stdcall FakeSetWatchdogTimer(
    uint64_t Disable,
    uint64_t Timeout,
    uint64_t WatchdogCode,
    void*   Data)
{
    (void)Disable; (void)Timeout; (void)WatchdogCode; (void)Data;
    printf("[FakeSetWatchdogTimer] called – watchdog disabled\n");
    return 0;               // EFI_SUCCESS
}

// -----------------------------------------------------------------
// Point d’entrée du programme d’hôte
// -----------------------------------------------------------------
int main()
{
    // -------------------------------------------------------------
    // 1️⃣  Construire la table EFI minimale
    // -------------------------------------------------------------
    FAKE_EFI_SYSTEM_TABLE sys{};
    sys.Hdr.Signature = 0x20494249ULL;          // "IBI"
    sys.RuntimeServices = reinterpret_cast<void*>(0xDEADBEEF); // valeur factice
    sys.BootServices    = reinterpret_cast<void*>(new FAKE_BOOT_SERVICES());

    // On place notre fonction factice à l’offset 0x38 du tableau BootServices
    auto* bs = reinterpret_cast<FAKE_BOOT_SERVICES*>(sys.BootServices);
    std::memset(bs, 0, sizeof(*bs));
    bs->CreateEvent = reinterpret_cast<void*>(&FakeSetWatchdogTimer);

    // -------------------------------------------------------------
    // 2️⃣  LoadOptions (facultatif – on met simplement nullptr)
    // -------------------------------------------------------------
    sys.LoadOptions = nullptr;

    // -------------------------------------------------------------
    // 3️⃣  Appel du point d’entrée EFI de votre projet
    // -------------------------------------------------------------
    printf("[host] Appel de EfiInitialize …\n");
    bool ok = EfiInitialize(nullptr, &sys);

    // -------------------------------------------------------------
    // 4️⃣  Résultat
    // -------------------------------------------------------------
    if (ok) {
        printf("[host] EfiInitialize a retourné true → kernel Rust invoqué\n");
    } else {
        printf("[host] EfiInitialize a retourné false → échec du démarrage\n");
    }

    // Nettoyage (déallocation du faux BootServices)
    delete bs;
    return ok ? 0 : 1;
}