;=====================================================================
; booter.asm – Bootloader UEFI pour Slura Lunée (Production)
;=====================================================================

; -------------------------------------------------
; 1. En-tête DOS (MZ)
; -------------------------------------------------
    db 0x4D, 0x5A
    times 0x3C-2 db 0
    dd _pe_header

_pe_header:
    db "PE", 0, 0
    dw 0x8664
    dw 2                              ; 2 sections (.text + .data)
    dd 0, 0, 0
    dw 0x00F0
    dw 0x0022

    dw 0x020B                         ; PE32+
    db 2, 0
    dd 0x1000, 0x1000, 0
    dd _efi_entry
    dd 0x1000, 0x2000
    dq 0x400000
    dd 0x1000, 0x200
    dw 0, 0, 0, 0, 0, 0xA
    dd 0x3000
    dd 0x200
    dd 0
    dw 0xA                            ; UEFI Application
    dw 0
    dq 0x100000, 0x1000
    dq 0x100000, 0x1000
    dd 0, 0
    times 16*8 dd 0

; Section Table
    db ".text",0,0,0
    dd text_end - text_start
    dd 0x1000
    dd text_end - text_start
    dd text_start - $$
    dd 0,0,0
    dd 0x60000020

    db ".data",0,0,0
    dd data_end - data_start
    dd 0x2000
    dd data_end - data_start
    dd data_start - $$
    dd 0,0,0
    dd 0xC0000040

; SECTION .text
section .text
text_start:

global _efi_entry
global RustEfiEntry
global EfiInitialize

_efi_entry:
    mov [efi_system_table], rdx

    ; Désactiver watchdog
    mov rax, [rdx + 0x60]
    mov rax, [rax + 0x38]
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call rax

    ; Appel au wrapper
    mov rcx, rdi
    mov rdx, rsi
    call EfiInitialize

    hlt
    jmp $

efi_system_table     dq 0

text_end:

; SECTION .data
section .data
data_start:
    align 8
load_options dq 0
data_end: