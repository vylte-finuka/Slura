/**
 * boot_selector.cpp — BOOTX64.EFI — Sélecteur de démarrage Slura OS
 * ====================================================================
 * Vyft Ltd — 2026
 *
 * Approche :
 *   1. Lire slr_clk_bt.efi en mémoire via EFI_LOADED_IMAGE + SimpleFileSystem
 *      (même volume que BOOTX64.EFI → pas de recherche réseau / timeout)
 *   2. LoadImage depuis buffer mémoire
 *   3. StartImage
 */

// ── Types UEFI freestanding ───────────────────────────────────────────────────
typedef unsigned char           UINT8;
typedef unsigned short          UINT16;
typedef unsigned int            UINT32;
typedef unsigned long long      UINT64;
typedef long long               INT64;
typedef UINT64                  UINTN;
typedef wchar_t                 CHAR16;
typedef void*                   EFI_HANDLE;
typedef UINT64                  EFI_STATUS;
typedef UINT8                   BOOLEAN;

#define EFI_SUCCESS    ((EFI_STATUS)0)
#define EFI_NOT_FOUND  ((EFI_STATUS)(0x800000000000000EULL))
#define NULL_HANDLE    ((EFI_HANDLE)nullptr)

#define EFI_FILE_MODE_READ 0x0000000000000001ULL
#define EFI_FILE_READ_ONLY 0x0000000000000001ULL

struct EFI_GUID {
    UINT32 Data1; UINT16 Data2; UINT16 Data3; UINT8 Data4[8];
};

// ── GUIDs ─────────────────────────────────────────────────────────────────────
// EFI_LOADED_IMAGE_PROTOCOL_GUID
static const EFI_GUID gLoadedImageGuid = {
    0x5B1B31A1, 0x9562, 0x11D2,
    {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}
};
// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID
static const EFI_GUID gSimpleFileSystemGuid = {
    0x0964E5B22, 0x6459, 0x11D2,
    {0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}
};
// EFI_FILE_INFO_ID
static const EFI_GUID gFileInfoGuid = {
    0x09576E92, 0x6D3F, 0x11D2,
    {0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}
};

// ── Simple Text Output ────────────────────────────────────────────────────────
struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void*       Reset;
    EFI_STATUS  (*OutputString)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL*, const CHAR16*);
    void*       TestString;
    void*       QueryMode;
    void*       SetMode;
    void*       SetAttribute;
    EFI_STATUS  (*ClearScreen)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL*);
    void*       SetCursorPosition;
    void*       EnableCursor;
    void*       Mode;
};

// ── Simple Text Input ─────────────────────────────────────────────────────────
struct EFI_INPUT_KEY { UINT16 ScanCode; CHAR16 UnicodeChar; };
struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
    void*      Reset;
    EFI_STATUS (*ReadKeyStroke)(EFI_SIMPLE_TEXT_INPUT_PROTOCOL*, EFI_INPUT_KEY*);
};

// ── Device Path ───────────────────────────────────────────────────────────────
struct EFI_DEVICE_PATH_PROTOCOL { UINT8 Type; UINT8 SubType; UINT8 Length[2]; };

// ── File Protocol ─────────────────────────────────────────────────────────────
struct EFI_FILE_PROTOCOL {
    UINT64      Revision;
    EFI_STATUS  (*Open)(EFI_FILE_PROTOCOL* This, EFI_FILE_PROTOCOL** NewHandle,
                        CHAR16* FileName, UINT64 OpenMode, UINT64 Attributes);
    EFI_STATUS  (*Close)(EFI_FILE_PROTOCOL* This);
    void*       Delete;
    EFI_STATUS  (*Read)(EFI_FILE_PROTOCOL* This, UINTN* BufferSize, void* Buffer);
    void*       Write;
    void*       GetPosition;
    void*       SetPosition;
    EFI_STATUS  (*GetInfo)(EFI_FILE_PROTOCOL* This, const EFI_GUID* InfoType,
                           UINTN* BufferSize, void* Buffer);
};

// EFI_FILE_INFO (taille fixe + nom de fichier variable — on prend large)
struct EFI_FILE_INFO {
    UINT64 Size;        // taille de la structure
    UINT64 FileSize;    // taille du fichier
    UINT64 PhysicalSize;
    UINT8  _times[48];  // 3 × EFI_TIME (16 bytes each)
    UINT64 Attribute;
    CHAR16 FileName[4]; // variable, on remplit ensuite
};

// ── Simple File System Protocol ───────────────────────────────────────────────
struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
    UINT64      Revision;
    EFI_STATUS  (*OpenVolume)(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* This,
                              EFI_FILE_PROTOCOL** Root);
};

// ── Loaded Image Protocol ─────────────────────────────────────────────────────
struct EFI_LOADED_IMAGE_PROTOCOL {
    UINT32                    Revision;
    EFI_HANDLE                ParentHandle;
    void*                     SystemTable;
    EFI_HANDLE                DeviceHandle;   // ← le handle du volume
    EFI_DEVICE_PATH_PROTOCOL* FilePath;
    void*                     Reserved;
    UINT32                    LoadOptionsSize;
    void*                     LoadOptions;
    void*                     ImageBase;
    UINT64                    ImageSize;
    UINT32                    ImageCodeType;
    UINT32                    ImageDataType;
    void*                     Unload;
};

// ── Boot Services ─────────────────────────────────────────────────────────────
struct EFI_BOOT_SERVICES {
    UINT8       _hdr[24];
    void*       RaiseTPL;
    void*       RestoreTPL;
    void*       AllocatePages;
    void*       FreePages;
    void*       GetMemoryMap;
    EFI_STATUS  (*AllocatePool)(UINT32 PoolType, UINTN Size, void** Buffer);
    EFI_STATUS  (*FreePool)(void* Buffer);
    void*       CreateEvent;
    void*       SetTimer;
    void*       WaitForEvent;
    void*       SignalEvent;
    void*       CloseEvent;
    void*       CheckEvent;
    void*       InstallProtocolInterface;
    void*       ReinstallProtocolInterface;
    void*       UninstallProtocolInterface;
    EFI_STATUS  (*HandleProtocol)(EFI_HANDLE Handle, const EFI_GUID* Protocol,
                                  void** Interface);
    void*       Reserved;
    void*       RegisterProtocolNotify;
    void*       LocateHandle;
    void*       LocateDevicePath;
    void*       InstallConfigurationTable;
    EFI_STATUS  (*LoadImage)(BOOLEAN BootPolicy, EFI_HANDLE Parent,
                             EFI_DEVICE_PATH_PROTOCOL* Path,
                             void* Src, UINTN SrcSize, EFI_HANDLE* Out);
    EFI_STATUS  (*StartImage)(EFI_HANDLE ImageHandle, UINTN* ExitDataSize,
                              CHAR16** ExitData);
    void*       Exit;
    void*       UnloadImage;
    void*       ExitBootServices;
    void*       GetNextMonotonicCount;
    EFI_STATUS  (*Stall)(UINTN Microseconds);
    void*       SetWatchdogTimer;
};

// ── System Table ──────────────────────────────────────────────────────────────
struct EFI_SYSTEM_TABLE {
    UINT8                            _hdr[24];
    CHAR16*                          FirmwareVendor;
    UINT32                           FirmwareRevision;
    EFI_HANDLE                       ConsoleInHandle;
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL*  ConIn;
    EFI_HANDLE                       ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* ConOut;
    EFI_HANDLE                       StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* StdErr;
    void*                            RuntimeServices;
    EFI_BOOT_SERVICES*               BootServices;
};

// ── Helpers ───────────────────────────────────────────────────────────────────
static void print(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* con, const CHAR16* s) {
    con->OutputString(con, s);
}

static UINTN wlen(const CHAR16* s) {
    UINTN n = 0; while (s[n]) ++n; return n;
}

// ── Chaînes ───────────────────────────────────────────────────────────────────
static const CHAR16 MSG_TITLE[]  = L"\r\n  === Slura OS Boot Selector ===\r\n\r\n";
static const CHAR16 MSG_OPT[]    = L"  [ENTREE]  Slura OS  (slr_clk_bt.efi)\r\n";
static const CHAR16 MSG_PROMPT[] = L"\r\n  Appuyez sur une touche pour demarrer...\r\n";
static const CHAR16 MSG_LOAD[]   = L"\r\n  Lecture de slr_clk_bt.efi...\r\n";
static const CHAR16 MSG_START[]  = L"  Demarrage Lunee kernel...\r\n";
static const CHAR16 MSG_ERR[]    = L"\r\n  [ERREUR] Impossible de charger slr_clk_bt.efi\r\n";
static const CHAR16 SLR_NAME[]   = L"slr_clk_bt.efi";

// ── Point d'entrée ────────────────────────────────────────────────────────────
extern "C" EFI_STATUS efi_selector_main(EFI_HANDLE image_handle,
                                         EFI_SYSTEM_TABLE* st) {
    auto* con = st->ConOut;
    auto* cin = st->ConIn;
    auto* bs  = st->BootServices;

    con->ClearScreen(con);
    print(con, MSG_TITLE);
    print(con, MSG_OPT);
    print(con, MSG_PROMPT);

    // ── Attendre une touche ────────────────────────────────────────────────────
    while (true) {
        EFI_INPUT_KEY key{0, L'\0'};
        if (cin->ReadKeyStroke(cin, &key) == EFI_SUCCESS) break;
        bs->Stall(50000);
    }

    print(con, MSG_LOAD);

    // ── 1. Obtenir le handle du volume via EFI_LOADED_IMAGE_PROTOCOL ──────────
    EFI_LOADED_IMAGE_PROTOCOL* loaded = nullptr;
    EFI_STATUS s = bs->HandleProtocol(image_handle, &gLoadedImageGuid,
                                       reinterpret_cast<void**>(&loaded));
    if (s != EFI_SUCCESS || !loaded) { print(con, MSG_ERR); bs->Stall(3000000); return s; }

    EFI_HANDLE dev = loaded->DeviceHandle;

    // ── 2. Ouvrir SimpleFileSystem sur ce volume ───────────────────────────────
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* fs = nullptr;
    s = bs->HandleProtocol(dev, &gSimpleFileSystemGuid,
                           reinterpret_cast<void**>(&fs));
    if (s != EFI_SUCCESS || !fs) { print(con, MSG_ERR); bs->Stall(3000000); return s; }

    EFI_FILE_PROTOCOL* root = nullptr;
    s = fs->OpenVolume(fs, &root);
    if (s != EFI_SUCCESS || !root) { print(con, MSG_ERR); bs->Stall(3000000); return s; }

    // ── 3. Ouvrir slr_clk_bt.efi ──────────────────────────────────────────────
    EFI_FILE_PROTOCOL* file = nullptr;
    s = root->Open(root, &file,
                   const_cast<CHAR16*>(SLR_NAME),
                   EFI_FILE_MODE_READ, 0);
    if (s != EFI_SUCCESS || !file) { print(con, MSG_ERR); bs->Stall(3000000); return s; }

    // ── 4. Lire la taille du fichier via GetInfo ───────────────────────────────
    UINT8   info_buf[sizeof(EFI_FILE_INFO) + 128] = {};
    UINTN   info_size = sizeof(info_buf);
    s = file->GetInfo(file, &gFileInfoGuid, &info_size, info_buf);
    if (s != EFI_SUCCESS) { print(con, MSG_ERR); bs->Stall(3000000); return s; }

    UINTN file_size = reinterpret_cast<EFI_FILE_INFO*>(info_buf)->FileSize;
    if (file_size == 0) { print(con, MSG_ERR); bs->Stall(3000000); return EFI_NOT_FOUND; }

    // ── 5. Allouer un buffer et lire le fichier ────────────────────────────────
    void* buf = nullptr;
    s = bs->AllocatePool(2 /*EfiLoaderData*/, file_size, &buf);
    if (s != EFI_SUCCESS || !buf) { print(con, MSG_ERR); bs->Stall(3000000); return s; }

    UINTN read_size = file_size;
    s = file->Read(file, &read_size, buf);
    file->Close(file);
    root->Close(root);
    if (s != EFI_SUCCESS || read_size != file_size) {
        bs->FreePool(buf);
        print(con, MSG_ERR); bs->Stall(3000000); return s;
    }

    // ── 6. LoadImage depuis le buffer mémoire ─────────────────────────────────
    EFI_HANDLE child = nullptr;
    s = bs->LoadImage(0 /*BootPolicy=false*/,
                      image_handle,
                      nullptr,           // pas de device path
                      buf, file_size,
                      &child);
    bs->FreePool(buf);
    if (s != EFI_SUCCESS) { print(con, MSG_ERR); bs->Stall(3000000); return s; }

    print(con, MSG_START);

    // ── 7. StartImage → Lunée kernel ──────────────────────────────────────────
    UINTN  exit_size = 0;
    CHAR16* exit_data = nullptr;
    return bs->StartImage(child, &exit_size, &exit_data);
}
