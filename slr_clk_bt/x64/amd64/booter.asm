;=====================================================================
; booter.asm – Bootloader UEFI (PE/COFF) – Vyft Ltd
;=====================================================================
; SPDX‑License‑Identifier: MIT
;=====================================================================

; -------------------------------------------------
; 1️⃣ En‑tête DOS (MZ) – obligatoire pour UEFI
; -------------------------------------------------
db 0x4D, 0x5A                     ; "MZ"
times 0x3C-2 db 0                 ; padding jusqu’à e_lfanew
dd _pe_header                     ; e_lfanew → offset du header PE

; -------------------------------------------------
; 2️⃣ Header PE
; -------------------------------------------------
_pe_header:
    db "PE", 0, 0                 ; Signature PE
    dw 0x8664                     ; Machine = AMD64
    dw 0x0003                     ; NumberOfSections = 3 (.text, .data, .reloc)
    dd 0                          ; TimeDateStamp
    dd 0                          ; PointerToSymbolTable
    dd 0                          ; NumberOfSymbols
    dw 0x00E0                     ; SizeOfOptionalHeader (224 bytes)
    dw 0x0022                     ; Characteristics = Executable | 32‑bit word

; -------------------------------------------------
; 3️⃣ Optional Header (PE32+)
; -------------------------------------------------
    dw 0x020B                     ; Magic = PE32+
    db 0x0E                       ; MajorLinkerVersion (arbitraire)
    db 0x00                       ; MinorLinkerVersion
    dd 0x00001000                 ; SizeOfCode
    dd 0x00001000                 ; SizeOfInitializedData
    dd 0x00000000                 ; SizeOfUninitializedData
    dd _efi_entry                 ; AddressOfEntryPoint (dans .text)
    dd 0x00001000                 ; BaseOfCode
    dd 0x00002000                 ; BaseOfData
    dq 0x0000000000400000         ; ImageBase (< 1 GiB requis)
    dd 0x00001000                 ; SectionAlignment
    dd 0x00000200                 ; FileAlignment
    dw 0x0000                     ; MajorOperatingSystemVersion
    dw 0x0000                     ; MinorOperatingSystemVersion
    dw 0x0000                     ; MajorImageVersion
    dw 0x0000                     ; MinorImageVersion
    dw 0x0000                     ; MajorSubsystemVersion
    dw 0x000A                     ; MinorSubsystemVersion = 10 (UEFI)
    dd 0x00000000                 ; Win32VersionValue
    dd 0x00003000                 ; SizeOfImage (≈ 12 KiB)
    dd 0x00000200                 ; SizeOfHeaders
    dd 0x00000000                 ; CheckSum
    dw 0x000A                     ; Subsystem = UEFI Application
    dw 0x0000                     ; DllCharacteristics
    dq 0x0000000000100000         ; SizeOfStackReserve
    dq 0x0000000000001000         ; SizeOfStackCommit
    dq 0x0000000000100000         ; SizeOfHeapReserve
    dq 0x0000000000001000         ; SizeOfHeapCommit
    dd 0x00000000                 ; LoaderFlags
    dd 0x00000000                 ; NumberOfRvaAndSizes
    ; DataDirectory (16 entrées) – on les laisse à zéro
    times 16*8 dd 0

; -------------------------------------------------
; 4️⃣ Section Table (3 sections)
; -------------------------------------------------
;   Name      VirtualSize  VirtualAddress  SizeOfRawData  PointerToRawData  Relocs  LineNums  Flags
section_header_text:
    db ".text",0,0,0
    dd $ - _text_start            ; VirtualSize (taille réelle)
    dd 0x00001000                 ; VirtualAddress (début .text)
    dd $ - _text_start            ; SizeOfRawData
    dd _text_start - $$           ; PointerToRawData (offset dans le fichier)
    dd 0,0,0
    dw 0x60000020                 ; Characteristics = MEM_EXECUTE | MEM_READ | CNT_CODE

section_header_data:
    db ".data",0,0,0
    dd $ - _data_start
    dd 0x00002000
    dd $ - _data_start
    dd _data_start - $$
    dd 0,0,0
    dw 0xC0000040                 ; MEM_READ | MEM_WRITE | CNT_INITIALIZED_DATA

section_header_reloc:
    db ".reloc",0,0,0
    dd $ - _reloc_start
    dd 0x00003000
    dd $ - _reloc_start
    dd _reloc_start - $$
    dd 0,0,0
    dw 0x42000040                 ; MEM_DISCARDABLE | CNT_INITIALIZED_DATA

; -------------------------------------------------
; 5️⃣ SECTION .text  (code exécutable)
; -------------------------------------------------
section .text
global efi_system_table
global efi_boot_services
global efi_runtime_services
global RustEfiEntry          ; point d’entrée appelé depuis le C++ wrapper

; -----------------------------------------------------------------
; 5.1 Export des pointeurs UEFI (visibles depuis le code C++)
; -----------------------------------------------------------------
efi_system_table      dq 0
efi_boot_services     dq 0
efi_runtime_services  dq 0

; -----------------------------------------------------------------
; 5.2 Point d’entrée réel (appelé par le firmware)
; -----------------------------------------------------------------
_efi_entry:
    ; RDI = ImageHandle, RSI = SystemTable (convention Microsoft x64)
    ; UEFI spécifie RCX = ImageHandle, RDX = SystemTable
    mov rcx, rdi
    mov rdx, rsi

    ; -------------------------------------------------
    ; Magic marker – indique à GDB où l’image est chargée
    ; -------------------------------------------------
    MAGIC_ADDR    EQU 0x500                ; adresse RAM libre (page 0)
    MAGIC_VALUE   EQU 0xDEADBEEF

    lea rax, [_text_start]            ; rax = base de l’image en mémoire

    ; Écriture du marker (4 bytes) + adresse 64 bits (2 dwords)
    mov dword [MAGIC_ADDR], MAGIC_VALUE
    mov dword [MAGIC_ADDR+4], eax      ; partie basse de l’adresse
    mov dword [MAGIC_ADDR+8], edx      ; partie haute (0 sur x86‑64)

    ; -------------------------------------------------
    ; Export des pointeurs pour le code C++
    ; -------------------------------------------------
    mov [efi_system_table], rdx                     ; SystemTable*
    mov rax, [rdx + 0x64]                           ; BootServices*  (offset 0x64)
    mov [efi_boot_services], rax
    mov rax, [rdx + 0x5C]                           ; RuntimeServices* (offset 0x5C)
    mov [efi_runtime_services], rax
    ; -------------------------------------------------
    ; Vérification de la signature SystemTable (IBI)
    ; -------------------------------------------------
    mov rax, [rdx]                      ; SystemTable->Hdr.Signature
    cmp eax, 0x20494249                 ; "IBI" (little‑endian)
    jne .fatal_error

    ; -------------------------------------------------
    ; Désactivation du watchdog (SetWatchdogTimer)
    ; -------------------------------------------------
    mov rax, [efi_boot_services]        ; BootServices*
    xor rcx, rcx                        ; Disable = 0
    xor rdx, rdx                        ; Timeout = 0
    xor r8,  r8                         ; WatchdogCode = 0
    xor r9,  r9                         ; Data = NULL
    mov rax, [rax + 0x38]               ; SetWatchdogTimer (offset 0x38)
    call rax

    ; -------------------------------------------------
    ; Récupération du pointeur LoadOptions (offset 0x20 dans EFI_SYSTEM_TABLE)
    ; -------------------------------------------------
    mov rax, [rdx + 0x20]          ; rdx = SystemTable, LoadOptions pointer
    mov [load_options], rax

    ; -------------------------------------------------
    ; Appel du kernel Rust (RustEfiEntry)
    ; -------------------------------------------------
    ; Convention Microsoft x64 : RCX, RDX, R8, R9 sont les 4 premiers args.
    ; Nous passons ImageHandle (RCX) et SystemTable (RDX), les deux autres = 0.
    xor r8, r8
    xor r9, r9
    call RustEfiEntry

    ; Si le kernel retourne (cela ne doit pas arriver) on boucle.
    hlt
    jmp $

; -----------------------------------------------------------------
; 5.3 Gestion d’erreur (affichage texte simple en mémoire vidéo)
; -----------------------------------------------------------------
.fatal_error:
    mov byte [0xB8000], 'E'
    mov byte [0xB8002], 'R'
    mov byte [0xB8004], 'R'
    hlt
    jmp .fatal_error

; -------------------------------------------------
; 5️⃣ SECTION .text  (code exécutable)
; -------------------------------------------------
section .text
align 16
PrintString:
    ; RCX = adresse du texte (null‑terminated)
    ; RDI = adresse du framebuffer (0xB8000) – texte couleur 16‑bits
    push rsi
    push rdx
    mov rdi, 0xB8000          ; base vidéo texte (mode texte 80×25)
    mov rsi, rcx              ; pointeur source
.print_loop:
    lodsb                     ; AL = *RSI, RSI++
    test al, al
    jz .done
    mov ah, 0x07              ; attribut gris clair sur noir
    stosw                     ; écrit le caractère + attribut
    jmp .print_loop
.done:
    pop rdx
    pop rsi
    ret

; -------------------------------------------------
; 6️⃣ SECTION .data (variables globales)
; -------------------------------------------------
section .data
align 8
scratch_space dq 0          ; 8 bytes pour stockage temporaire TSC
load_options dq 0          ; pointeur vers la chaîne LoadOptions (null‑terminated)

; -------------------------------------------------
; 7️⃣ SECTION .reloc (table de relocations)
; -------------------------------------------------
section .reloc
    ; Relocation de base : IMAGE_REL_BASED_DIR64 (type 10) pour _efi_entry
    dd 0x00001000               ; VirtualAddress = début .text
    dd 0x00000018               ; SizeOfBlock = 24 bytes (3 relocs de 8 bytes)
    dw 0x000A, 0x0000           ; TYPE=IMAGE_REL_BASED_DIR64, Offset=0x0000 (_efi_entry)
    dw 0x000A, 0x0008           ; TYPE=IMAGE_REL_BASED_DIR64, Offset=0x0008 (efi_system_table)
    dw 0x000A, 0x0010           ; TYPE=IMAGE_REL_BASED_DIR64, Offset=0x0010 (efi_boot_services)
    dw 0x0000, 0x0000           ; padding
    ; Terminator
    dd 0,0

; -------------------------------------------------
; 8️⃣ FIN du fichier
; -------------------------------------------------
section .rodata
err_msg db "BOOT FAILURE – SEE VIDEO MEMORY",0